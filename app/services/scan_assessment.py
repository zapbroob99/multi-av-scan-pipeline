"""Verdict, detection-coverage, and decision resolution for a scan.

Extracted from ``app.main`` so both the FastAPI app and the standalone ICAP
server share the exact same decision logic without importing the web app.
"""

from __future__ import annotations

import json

from app.database import list_engine_results
from app.models import EngineResultRecord, ScanRecord
from app.services.decisions import ScanDecision, decide_scan_action
from app.services.engine_registry import detection_engine_names
from app.services.profile_policy import apply_profile_policy, archive_handling
from app.services.scoring import calculate_risk
from app.services.service_clients import parse_profile_snapshot, required_detection_engine_names


def detection_engine_results(
    results: list[EngineResultRecord],
    *,
    required_names: list[str] | None = None,
) -> list[EngineResultRecord]:
    if required_names is not None:
        required = {name.casefold() for name in required_names}
        return [
            result
            for result in results
            if result.engine_name.casefold() in required
        ]
    return [
        result
        for result in results
        if result.engine_name.lower() != "static metadata"
    ]


def engine_result_map(
    results: list[EngineResultRecord],
) -> dict[str, EngineResultRecord]:
    return {result.engine_name.lower(): result for result in results}


def engine_policy_action(result: EngineResultRecord) -> str | None:
    """Read an adapter's normalized policy action, when it provides one."""
    if not result.details_json:
        return None
    try:
        details = json.loads(result.details_json)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(details, dict):
        return None
    decision = details.get("decision")
    if not isinstance(decision, dict):
        return None
    action = decision.get("action")
    return str(action) if action in {"allow", "review", "block"} else None


def engine_policy_reason(result: EngineResultRecord) -> str | None:
    """Read the human-facing reason supplied by an adapter policy decision."""
    if not result.details_json:
        return None
    try:
        details = json.loads(result.details_json)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(details, dict):
        return None
    decision = details.get("decision")
    if not isinstance(decision, dict):
        return None
    reason = decision.get("reason")
    return str(reason).strip() if reason else None


def engine_policy_review_reasons(
    results: list[EngineResultRecord],
    *,
    source: str = "manual",
) -> list[str]:
    """Return review policy signals separately from execution coverage."""
    reasons: list[str] = []
    for result in results:
        if result.status != "completed" or engine_policy_action(result) != "review":
            continue
        if source.strip().lower() == "manual":
            try:
                details = json.loads(result.details_json)
            except (TypeError, json.JSONDecodeError):
                details = {}
            if (
                isinstance(details, dict)
                and details.get("source") == "virustotal"
                and details.get("status") in {"unknown", "undetected", "stale"}
            ):
                # VirusTotal is enrichment for manual file scans. Preserve the
                # strict review decision in technical details/Scan Hash, but do
                # not let a zero-signal reputation result override local AV.
                continue
        reason = engine_policy_reason(result)
        reasons.append(
            f"{result.engine_name}: {reason}"
            if reason
            else f"{result.engine_name} requires review under its configured policy."
        )
    return reasons


def detection_summary(
    results: list[EngineResultRecord],
    *,
    source: str = "manual",
    scan: ScanRecord | None = None,
    required_names: list[str] | None = None,
) -> tuple[int, int]:
    scoped = scan is not None or required_names is not None
    required_names = required_names if required_names is not None else (
        required_detection_engine_names(scan)
        if scan is not None
        else detection_engine_names(source=source)
    )
    detection_results = detection_engine_results(
        results,
        required_names=required_names if scoped else None,
    )
    detected = sum(
        1
        for result in detection_results
        if result.status == "completed" and result.detected
    )
    return detected, max(len(detection_results), len(required_names))


def required_engine_coverage(
    results: list[EngineResultRecord],
    *,
    source: str = "manual",
    scan: ScanRecord | None = None,
    required_names: list[str] | None = None,
) -> tuple[int, int, list[str]]:
    result_map = engine_result_map(results)
    unavailable = []
    ran = 0
    required_engines = required_names if required_names is not None else (
        required_detection_engine_names(scan)
        if scan is not None
        else detection_engine_names(source=source)
    )

    for engine_name in required_engines:
        result = result_map.get(engine_name.lower())
        if result is None:
            unavailable.append(f"{engine_name} missing")
            continue

        if result.status == "completed":
            ran += 1
            continue

        unavailable.append(f"{engine_name} {result.status}")

    return ran, len(required_engines), unavailable


def scan_decision(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
    *,
    risk_score: int | None = None,
    verdict: str | None = None,
    required_names: list[str] | None = None,
) -> ScanDecision:
    assessment = calculate_risk(engine_results)
    effective_score = risk_score if risk_score is not None else scan.risk_score
    effective_verdict = verdict if verdict is not None else scan.verdict
    if effective_score is None:
        effective_score = assessment.score
    if effective_verdict == "pending":
        effective_verdict = assessment.verdict
    detected_count, detection_total = detection_summary(
        engine_results, source=scan.source, scan=scan, required_names=required_names
    )
    _, _, coverage_unavailable = required_engine_coverage(
        engine_results, source=scan.source, scan=scan, required_names=required_names
    )
    policy_review_reasons = engine_policy_review_reasons(
        engine_results, source=scan.source
    )
    decision = decide_scan_action(
        scan_status=scan.status,
        verdict=effective_verdict,
        risk_score=effective_score,
        detected_engines=detected_count,
        detection_engines=detection_total,
        unavailable_engines=coverage_unavailable,
        policy_review_reasons=policy_review_reasons,
    )
    # The client's frozen profile policy can only make this stricter.
    return apply_profile_policy(decision, parse_profile_snapshot(scan), scan_role=scan.scan_role)


def resolve_scan_decision(scan: ScanRecord) -> ScanDecision:
    """Load a scan's engine results and compute its final decision."""
    return scan_decision(scan, list_engine_results(scan.id))


def every_member_is_scanned(scan: ScanRecord) -> bool:
    """Whether this archive is judged on all of its members (scan_members)."""
    if scan.batch_id is None or scan.scan_role != "container":
        return False
    return archive_handling(parse_profile_snapshot(scan)) == "scan_members"


def archive_decision(container: ScanRecord, *, connection=None, decision=None) -> ScanDecision:
    """Resolve the archive in the caller's snapshot, or open one for ICAP.

    Bounded readers can catch ArchiveDecisionUnavailable and suppress decisions.
    ICAP explicitly blocks unassessable archives, even under fail-open transport.
    """
    from app import database as db
    from app.services import archive_assessment

    if connection is not None:
        return archive_assessment.read(connection, container, decision)
    try:
        with db.connect() as connection:
            connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
            archive_assessment.apply_read_budget(connection)
            current = db.get_scan(container.id, connection=connection)
            if current is None or (current.source, current.service_client_id) != (container.source, container.service_client_id):
                raise archive_assessment.ArchiveDecisionUnavailable('Archive decision unavailable: scan is missing or ownership changed.')
            results = db.list_engine_results(current.id, connection=connection)
            base = scan_decision(current, results)
            if not every_member_is_scanned(current):
                return base
            return archive_assessment.read(connection, current, base)
    except archive_assessment.ArchiveDecisionUnavailable as exc:
        return _archive_block('archive_unassessed', str(exc), [])


def combine_archive_decisions(decision: ScanDecision, expected: int,
                              members: list[tuple[str, str, ScanDecision | None]]) -> ScanDecision:
    """Pure aggregation shared by ICAP, reports and integration projections."""
    if decision.action in {'wait', 'block'}:
        return decision
    if any(status not in {'completed', 'failed'} for status, _, _ in members):
        return ScanDecision(action='wait', label='Wait', tone='neutral', confidence='low',
                            policy='archive_members_in_progress', reason='Archive members are still being scanned.',
                            reasons=['Archive members are still being scanned.'])
    if len(members) != expected:
        reason = (f'Only {len(members)} of the archive\'s {expected} members were registered for scanning.'
                  if len(members) < expected else 'The registered member count differs from the inspected archive.')
        return _archive_block('archive_incomplete', reason, [])
    blocked, unscanned, review = [], [], []
    for status, name, member_decision in members:
        if status == 'failed' or member_decision is None:
            unscanned.append(f'{name}: the member could not be scanned.')
        elif member_decision.action == 'block':
            blocked.append(f'{name}: {member_decision.reason}')
        elif member_decision.action != 'allow':
            review.append(f'{name}: {member_decision.reason}')
    if blocked:
        return _archive_block('archive_member_blocked', f'Archive member {blocked[0]}', blocked + unscanned)
    if unscanned:
        return _archive_block('archive_member_unscanned', f'Archive member {unscanned[0]}', unscanned)
    if review:
        return ScanDecision(action='review', label='Review', tone='warning', confidence='medium',
                            policy='archive_member_review', reason=f'Archive member {review[0]}',
                            reasons=[f'Archive member {item}' for item in review[:20]])
    if decision.action != 'allow':
        return decision
    return ScanDecision(action='allow', label='Allow', tone='success', confidence='high',
                        policy='archive_full_coverage',
                        reason='The archive and all inspected members allow with complete required coverage.',
                        reasons=['The archive and all inspected members allow with complete required coverage.'])


def _archive_block(policy: str, reason: str, members: list[str]) -> ScanDecision:
    # The first member is usually the reason itself; list it once.
    reasons = list(dict.fromkeys([reason, *(f"Archive member {item}" for item in members[:20])]))
    if len(members) > 20:
        reasons.append(f"{len(members) - 20} more members are not listed.")
    return ScanDecision(action="block", label="Block", tone="danger", confidence="high", policy=policy,
                        reason=reason, reasons=reasons)
