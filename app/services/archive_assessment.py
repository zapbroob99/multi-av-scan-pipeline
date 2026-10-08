"""Bounded archive decisions from one database snapshot, without raw engine output."""
from dataclasses import replace
import json

from app import database as db
from app.services.browser_db_budget import apply_read_budget
from app.services.decisions import ScanDecision
from app.services.service_clients import required_detection_engine_names

MAX_MEMBERS = 5000
MAX_RESULTS = 20000
SOURCE_LIMIT = 2 * 1024 * 1024
POLICY_LIMIT = 65536


class ArchiveDecisionUnavailable(ValueError):
    """Incomplete admission or invalid recorded policy; never use a partial decision."""


def _object(value: str) -> dict:
    try:
        parsed = json.loads(value or '{}')
        if not isinstance(parsed, dict):
            raise ValueError
        return parsed
    except (ValueError, TypeError, RecursionError):
        raise ArchiveDecisionUnavailable('Archive decision unavailable: recorded policy is invalid.') from None


def read(connection, container, decision: ScanDecision) -> ScanDecision:
    from app.services.scan_assessment import combine_archive_decisions, scan_decision

    if decision.action in {'wait', 'block'}:
        return decision
    apply_read_budget(connection)
    snapshot = _object(container.profile_snapshot_json)
    if decision.policy == 'exception_allow':
        # The exception names this archive itself: what is inside does not change it.
        return decision
    inspection = snapshot.get('archive_inspection')
    expected = inspection.get('members') if isinstance(inspection, dict) else None
    if type(expected) is not int or expected < 0 or inspection.get('violation_total') != 0:
        raise ArchiveDecisionUnavailable('Archive decision unavailable: successful inspection is missing.')
    if expected > MAX_MEMBERS:
        raise ArchiveDecisionUnavailable('Archive decision unavailable: member limit exceeded.')
    batch = connection.execute('SELECT source, service_client_id FROM scan_batches WHERE id = ?',
                               (container.batch_id,)).fetchone()
    if batch is None or batch['source'] != container.source or batch['service_client_id'] != container.service_client_id:
        raise ArchiveDecisionUnavailable('Archive decision unavailable: inconsistent batch ownership.')
    # Admit metadata first. Do not filter foreign members out and accidentally
    # treat the remaining subset as the complete archive.
    rows = connection.execute('''SELECT id, source, service_client_id, parent_scan_id, scan_role,
        status, verdict, risk_score, attempt_count, SUBSTR(relative_path, 1, 513) AS relative_path
        FROM scan_jobs WHERE batch_id = ? ORDER BY id LIMIT ?''',
        (container.batch_id, MAX_MEMBERS + 2)).fetchall()
    if len(rows) > MAX_MEMBERS + 1:
        raise ArchiveDecisionUnavailable('Archive decision unavailable: member limit exceeded.')
    by_id = {row['id']: row for row in rows}
    if container.id not in by_id or any(row['source'] != container.source or
            row['service_client_id'] != container.service_client_id for row in rows):
        raise ArchiveDecisionUnavailable('Archive decision unavailable: inconsistent member ownership.')
    members = [row for row in rows if row['id'] != container.id]
    # Every member must belong to this root, including nested members. Cycles,
    # orphan records and a second container cannot supply missing coverage.
    rooted = {container.id}
    for member in members:
        cursor = member
        seen = set()
        while cursor['id'] not in rooted:
            if cursor['id'] in seen or cursor['scan_role'] != 'child' or cursor['parent_scan_id'] not in by_id:
                raise ArchiveDecisionUnavailable('Archive decision unavailable: invalid member ancestry.')
            seen.add(cursor['id'])
            cursor = by_id[cursor['parent_scan_id']]
        rooted.update(seen)
    if any(row['status'] not in {'completed', 'failed'} for row in members):
        return combine_archive_decisions(decision, expected, [(row['status'], '', None) for row in members])
    if len(members) != expected:
        return combine_archive_decisions(decision, expected, [(row['status'], '', None) for row in members])
    # Preflight all policy bytes and results before hydration. Raw output,
    # findings, sample bytes and storage paths are never selected.
    length = "OCTET_LENGTH(COALESCE({field}, ''))" if db.using_postgres() else "LENGTH(CAST(COALESCE({field}, '') AS BLOB))"
    snapshots = connection.execute(f'''SELECT COALESCE(SUM({length.format(field='profile_snapshot_json')}), 0) AS bytes
        FROM scan_jobs WHERE batch_id = ?''', (container.batch_id,)).fetchone()
    size = connection.execute(f'''SELECT COUNT(*) AS n,
        COALESCE(SUM({length.format(field='r.details_json')} + {length.format(field='r.engine_name')}), 0) AS bytes,
        COALESCE(MAX({length.format(field='r.details_json')}), 0) AS largest
        FROM engine_results r JOIN scan_jobs j ON j.id = r.scan_job_id
        WHERE j.batch_id = ?''', (container.batch_id,)).fetchone()
    if size['n'] > MAX_RESULTS or size['bytes'] + snapshots['bytes'] > SOURCE_LIMIT or size['largest'] > POLICY_LIMIT:
        raise ArchiveDecisionUnavailable('Archive decision unavailable: recorded policy exceeds the reader limit.')
    policies = {row['id']: row['profile_snapshot_json'] for row in connection.execute(
        'SELECT id, profile_snapshot_json FROM scan_jobs WHERE batch_id = ?', (container.batch_id,)).fetchall()}
    results = connection.execute('''SELECT r.id, r.scan_job_id, r.engine_name,
        NULL AS engine_version, NULL AS signature_version, r.status, r.detected,
        NULL AS signature, r.severity, r.confidence, '' AS raw_output,
        NULL AS error_message, r.duration_ms, r.created_at, r.details_json, '[]' AS findings_json
        FROM engine_results r JOIN scan_jobs j ON j.id = r.scan_job_id
        WHERE j.batch_id = ? ORDER BY r.id''', (container.batch_id,)).fetchall()
    grouped = {}
    for row in results:
        _object(row['details_json'])
        grouped.setdefault(row['scan_job_id'], []).append(db.row_to_engine_result_record(row))
    decisions = []
    for row in members:
        policy = _object(policies[row['id']])
        if not isinstance(policy.get('engines'), list):
            raise ArchiveDecisionUnavailable('Archive decision unavailable: accepted member routing is missing.')
        member = replace(container, **dict(row), profile_snapshot_json=policies[row['id']])
        result = scan_decision(member, grouped.get(member.id, []),
                               required_names=required_detection_engine_names(member, jobs=[]))
        decisions.append((member.status, (member.relative_path or f'Scan {member.id}')[:512], result))
    return combine_archive_decisions(decision, expected, decisions)
