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
from app.services.scoring import calculate_risk
from app.services.service_clients import required_detection_engine_names


def detection_engine_results(
    results: list[EngineResultRecord],
) -> list[EngineResultRecord]:
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
) -> tuple[int, int]:
    detection_results = detection_engine_results(results)
    detected = sum(
        1
        for result in detection_results
        if result.status == "completed" and result.detected
    )
    required_names = (
        required_detection_engine_names(scan)
        if scan is not None
        else detection_engine_names(source=source)
    )
    return detected, max(len(detection_results), len(required_names))


def required_engine_coverage(
    results: list[EngineResultRecord],
    *,
    source: str = "manual",
    scan: ScanRecord | None = None,
) -> tuple[int, int, list[str]]:
    result_map = engine_result_map(results)
    unavailable = []
    ran = 0
    required_engines = (
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
) -> ScanDecision:
    assessment = calculate_risk(engine_results)
    effective_score = risk_score if risk_score is not None else scan.risk_score
    effective_verdict = verdict if verdict is not None else scan.verdict
    if effective_score is None:
        effective_score = assessment.score
    if effective_verdict == "pending":
        effective_verdict = assessment.verdict
    detected_count, detection_total = detection_summary(
        engine_results, source=scan.source, scan=scan
    )
    _, _, coverage_unavailable = required_engine_coverage(
        engine_results, source=scan.source, scan=scan
    )
    policy_review_reasons = engine_policy_review_reasons(
        engine_results, source=scan.source
    )
    return decide_scan_action(
        scan_status=scan.status,
        verdict=effective_verdict,
        risk_score=effective_score,
        detected_engines=detected_count,
        detection_engines=detection_total,
        unavailable_engines=coverage_unavailable,
        policy_review_reasons=policy_review_reasons,
    )


def resolve_scan_decision(scan: ScanRecord) -> ScanDecision:
    """Load a scan's engine results and compute its final decision."""
    return scan_decision(scan, list_engine_results(scan.id))
