"""Bounded, session-facing report projections with server-selected source scope. No adapter execution."""
from dataclasses import asdict
import json
import os

from fastapi import HTTPException
from pydantic import BaseModel

from app import database as db
from app.services.scan_assessment import detection_summary, required_engine_coverage, scan_decision
from app.services.service_clients import required_detection_engine_names, parse_profile_snapshot
from app.services.browser_db_budget import apply_read_budget

MAX_ENGINES = 256
POLICY_LIMIT = 65536
TEXT_LIMIT = 16384
SNAPSHOT_LIMIT = 262144
FULL_OUTPUT_LIMIT = 2 * 1024 * 1024
RAW_OUTPUT_DEFAULT_LIMIT = 32 * 1024 * 1024
RAW_OUTPUT_MAX_LIMIT = 256 * 1024 * 1024


def raw_output_limit() -> int:
    raw = os.getenv('MASP_UI_RAW_OUTPUT_LIMIT', str(RAW_OUTPUT_DEFAULT_LIMIT)).strip()
    try:
        value = int(raw)
    except ValueError:
        return RAW_OUTPUT_DEFAULT_LIMIT
    # Never below the JSON reader's ceiling: this download exists to serve what
    # the JSON reader already refuses.
    return max(FULL_OUTPUT_LIMIT, min(value, RAW_OUTPUT_MAX_LIMIT))


class EngineSummary(BaseModel):
    result_id: int | None
    name: str
    required: bool
    status: str
    detected: bool
    signature: str | None
    error: str | None
    duration_ms: int | None


class DecisionSummary(BaseModel):
    action: str
    label: str
    tone: str
    confidence: str
    policy: str
    reason: str
    reasons: list[str]


class ScanReport(BaseModel):
    source: str = 'manual'
    service_client_id: int | None = None
    id: int
    filename: str
    sha256: str
    size_bytes: int
    case_name: str
    note: str
    status: str
    risk_score: int | None
    risk_level: str
    attempt_count: int
    job_revision: int = 0
    created_at: str
    completed_at: str | None
    last_error: str | None
    batch_id: int | None
    parent_scan_id: int | None
    detected_engines: int
    required_engines: int
    completed_engines: int
    unavailable: list[str]
    coverage_basis: str
    decision: DecisionSummary | None
    warning: str | None
    engines: list[EngineSummary]


class TechnicalDetails(BaseModel):
    result_id: int
    raw_output: str
    details_json: str
    findings_json: str
    truncated: list[str]


class FullTechnicalDetails(BaseModel):
    scan_id: int
    result_id: int
    engine_name: str
    attempt_count: int
    raw_output: str
    details_json: str
    findings_json: str


def source_clause(automation: bool) -> str:
    # Server-selected scope only; never accept SQL or source sets from the caller's request.
    return "j.source IN ('api', 'icap')" if automation else "j.source = 'manual'"


def full_technical_details(scan_id: int, result_id: int, *, automation: bool = False) -> FullTechnicalDetails:
    # Size admission and hydration must see the same result, including when a
    # retry deletes it concurrently. No deployment/sample metadata is selected.
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        fields = ('engine_name', 'raw_output', 'details_json', 'findings_json')
        byte_length = ('OCTET_LENGTH(COALESCE(r.{field}, \'\'))' if db.using_postgres()
                       else 'LENGTH(CAST(COALESCE(r.{field}, \'\') AS BLOB))')
        size_terms = ' + '.join(byte_length.format(field=field) for field in fields)
        source = f"FROM engine_results r JOIN scan_jobs j ON j.id = r.scan_job_id WHERE r.id = ? AND j.id = ? AND {source_clause(automation)}"
        size = connection.execute(f'SELECT {size_terms} AS source_bytes {source}', (result_id, scan_id)).fetchone()
        if size is None:
            raise HTTPException(404, 'Automation scan result not found.' if automation else 'Manual scan result not found.')
        if int(size['source_bytes']) > FULL_OUTPUT_LIMIT:
            raise HTTPException(413, 'Full engine output exceeds the 2 MiB browser source limit. Use the legacy report.')
        row = connection.execute(f'''SELECT j.id AS scan_id, r.id AS result_id, j.attempt_count,
            r.engine_name, r.raw_output, r.details_json, r.findings_json {source}''', (result_id, scan_id)).fetchone()
        payload = FullTechnicalDetails(scan_id=row['scan_id'], result_id=row['result_id'],
            attempt_count=row['attempt_count'], **{field: row[field] or '' for field in fields})
    # JSON control-character escaping may exceed the source size considerably.
    if len(payload.model_dump_json().encode('utf-8')) > FULL_OUTPUT_LIMIT:
        raise HTTPException(413, 'Full engine output exceeds the 2 MiB browser response limit. Use the legacy report.')
    return payload


def raw_output(scan_id: int, result_id: int, *, automation: bool = False) -> tuple[str, str]:
    """Serve one engine's raw output as plain text, outside the JSON envelope.

    The typed full-detail reader refuses above 2 MiB because JSON escaping of
    scanner output can multiply its size and React would hold the whole string.
    Plain text has neither cost, so this is the browser path for output the JSON
    reader rejects; legacy stays unnecessary. It is still explicitly bounded:
    legacy rendered every result inline with no ceiling at all.
    """
    limit = raw_output_limit()
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        byte_length = ("OCTET_LENGTH(COALESCE(r.raw_output, ''))" if db.using_postgres()
                       else "LENGTH(CAST(COALESCE(r.raw_output, '') AS BLOB))")
        source = (f"FROM engine_results r JOIN scan_jobs j ON j.id = r.scan_job_id "
                  f"WHERE r.id = ? AND j.id = ? AND {source_clause(automation)}")
        size = connection.execute(f'SELECT {byte_length} AS source_bytes {source}', (result_id, scan_id)).fetchone()
        if size is None:
            raise HTTPException(404, 'Automation scan result not found.' if automation else 'Manual scan result not found.')
        if int(size['source_bytes']) > limit:
            raise HTTPException(413, f'Engine output exceeds the {limit} byte download limit configured for this deployment.')
        row = connection.execute(f'SELECT r.raw_output {source}', (result_id, scan_id)).fetchone()
    # Filename is built from validated integers only; no sample or engine name
    # reaches the Content-Disposition header.
    return f'masp-scan-{scan_id}-result-{result_id}-output.txt', row['raw_output'] or ''


def report(scan_id: int, *, automation: bool = False) -> ScanReport:
    with db.connect() as connection:
        # Keep state, attempt, jobs and results in one snapshot without locking
        # worker rows. PostgreSQL's default READ COMMITTED is not sufficient.
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        row = connection.execute(f'''SELECT j.id, j.sample_id, SUBSTR(j.case_name, 1, 200) AS case_name,
            j.priority, SUBSTR(j.note, 1, 4000) AS note, j.source, j.status, j.verdict, j.risk_score,
            j.created_at, j.started_at, j.completed_at, j.failed_at, j.attempt_count,
            SUBSTR(j.last_error, 1, 2048) AS last_error, j.batch_id, j.parent_scan_id,
            j.scan_role, NULL AS relative_path, j.service_client_id, j.scan_profile_id,
            SUBSTR(j.profile_snapshot_json, 1, ?) AS profile_snapshot_json,
            SUBSTR(s.original_filename, 1, 512) AS original_filename,
            '' AS stored_filename, '' AS storage_path, s.content_type, s.size_bytes, s.md5, s.sha1, s.sha256
            FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
            WHERE j.id = ? AND {source_clause(automation)} ''', (SNAPSHOT_LIMIT + 1, scan_id)).fetchone()
        if row is None:
            raise HTTPException(404, 'Automation scan not found.' if automation else 'Manual scan not found.')
        scan = db.row_to_scan_record(row)
        if len(scan.profile_snapshot_json) > SNAPSHOT_LIMIT:
            raise HTTPException(413, 'Large routing snapshot: open the legacy report.')
        job_rows = connection.execute('''SELECT id, scan_job_id, engine_instance_id, engine_key, engine_name,
            status, NULL AS worker_id, claimed_at, started_at, finished_at, lease_expires_at,
            attempt_count, NULL AS last_error, created_at, updated_at
            FROM scan_engine_jobs WHERE scan_job_id = ? ORDER BY id LIMIT ?''',
                                      (scan_id, MAX_ENGINES + 1)).fetchall()
        rows = connection.execute('''SELECT id, scan_job_id, engine_name, NULL AS engine_version, NULL AS signature_version,
            status, detected, SUBSTR(signature, 1, 1024) AS signature, severity, confidence,
            '' AS raw_output, SUBSTR(error_message, 1, 2048) AS error_message, duration_ms,
            created_at, SUBSTR(details_json, 1, ?) AS details_json, '[]' AS findings_json
            FROM engine_results WHERE scan_job_id = ? ORDER BY id LIMIT ?''',
            (POLICY_LIMIT + 1, scan_id, MAX_ENGINES + 1)).fetchall()
        if len(rows) > MAX_ENGINES or len(job_rows) > MAX_ENGINES:
            raise HTTPException(413, 'Large report: open the legacy report for the complete engine set.')
        jobs = [db.row_to_scan_engine_job_record(row) for row in job_rows]
        required = required_detection_engine_names(scan, jobs=jobs)
        coverage_basis = 'routing_snapshot' if isinstance(parse_profile_snapshot(scan).get('engines'), list) else 'engine_jobs' if jobs else 'legacy_configuration'
        if len(required) > MAX_ENGINES:
            raise HTTPException(413, 'Large routing snapshot: open the legacy report.')
        results = [db.row_to_engine_result_record(row) for row in rows]
    ran, total, unavailable = required_engine_coverage(results, scan=scan, required_names=required)
    detected, _ = detection_summary(results, scan=scan, required_names=required)
    policy_complete = True
    for result in results:
        try:
            details = json.loads(result.details_json or '{}')
            if len(result.details_json) > POLICY_LIMIT or not isinstance(details, dict):
                policy_complete = False
        except (ValueError, TypeError, RecursionError):
            policy_complete = False
    # Never invent an allow/review decision from truncated policy input. The
    # complete legacy report remains available when the compact reader cannot
    # reproduce the existing decision faithfully.
    decision = scan_decision(scan, results, required_names=required) if policy_complete else None
    decision_payload = asdict(decision) if decision else None
    if decision_payload:
        decision_payload['reason'] = decision_payload['reason'][:2048]
        decision_payload['reasons'] = [reason[:2048] for reason in decision_payload['reasons'][:32]]
    required_keys = {name.casefold() for name in required}
    summaries = [EngineSummary(result_id=r.id, name=r.engine_name, required=r.engine_name.casefold() in required_keys,
        status=r.status, detected=r.detected and r.status == 'completed', signature=r.signature,
        error=r.error_message, duration_ms=r.duration_ms) for r in results]
    seen = {r.engine_name.casefold() for r in results}
    for name in required:
        if name.casefold() not in seen:
            summaries.append(EngineSummary(result_id=None, name=name, required=True,
                status='missing', detected=False, signature=None, error=None, duration_ms=None))
            seen.add(name.casefold())
    return ScanReport(source=scan.source, service_client_id=scan.service_client_id, id=scan.id, filename=scan.original_filename[:512], sha256=scan.sha256,
        size_bytes=scan.size_bytes, case_name=scan.case_name[:200], note=scan.note[:4000], status=scan.status,
        risk_score=scan.risk_score, risk_level=scan.verdict, attempt_count=scan.attempt_count,
        job_revision=max((job.id for job in jobs), default=0),
        created_at=scan.created_at, completed_at=scan.completed_at, last_error=(scan.last_error or '')[:2048] or None,
        batch_id=scan.batch_id, parent_scan_id=scan.parent_scan_id, detected_engines=detected,
        required_engines=total, completed_engines=ran, unavailable=[value[:2048] for value in unavailable],
        coverage_basis=coverage_basis,
        decision=DecisionSummary(**decision_payload) if decision_payload else None,
        warning=None if policy_complete else 'Decision unavailable: policy details exceed the compact reader limit or are invalid. Open the legacy report.',
        engines=summaries)


def technical_details(scan_id: int, result_id: int, *, automation: bool = False) -> TechnicalDetails:
    with db.connect() as connection:
        apply_read_budget(connection)
        row = connection.execute(f'''SELECT r.id,
            SUBSTR(r.raw_output, 1, ?) AS raw_output, SUBSTR(r.details_json, 1, ?) AS details_json,
            SUBSTR(r.findings_json, 1, ?) AS findings_json
            FROM engine_results r JOIN scan_jobs j ON j.id = r.scan_job_id
            WHERE r.id = ? AND j.id = ? AND {source_clause(automation)} ''',
            (TEXT_LIMIT + 1, TEXT_LIMIT + 1, TEXT_LIMIT + 1, result_id, scan_id)).fetchone()
    if row is None:
        raise HTTPException(404, 'Automation scan result not found.' if automation else 'Manual scan result not found.')
    values = {key: row[key] or '' for key in ('raw_output', 'details_json', 'findings_json')}
    return TechnicalDetails(result_id=row['id'], **{key: value[:TEXT_LIMIT] for key, value in values.items()},
        truncated=[key for key, value in values.items() if len(value) > TEXT_LIMIT])
