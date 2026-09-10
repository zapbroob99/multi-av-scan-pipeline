"""Manual browser operations; reuse the queue and bounded report boundary."""
import csv
import io
import json
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app import database as db
from app.services.cleanup import delete_sample_file
from app.services.engine_registry import adapter_definition
from app.services.reports import build_scan_report_payload, create_scan_report_csv
from app.services.service_clients import (
    engines_for_scan,
    parse_profile_snapshot,
    required_detection_engine_names,
)
from app.services import scan_report_read
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms

EXPORT_LIMIT = 2 * 1024 * 1024
FULL_EXPORT_SOURCE_LIMIT = 2 * 1024 * 1024
MAX_EXPORT_ENGINES = 256
DASHBOARD_DELETE_ROLES = frozenset({'standalone', 'container'})
EXPORT_SCOPE = 'Manual scan summary only. Bounded text previews; no raw output, findings or archive children. Use the separate bounded full export for complete result data.'


class SummaryExport(BaseModel):
    filename: str
    media_type: Literal['application/json', 'text/csv']
    content: str


class RetryAccepted(BaseModel):
    scan_id: int
    status: Literal['accepted'] = 'accepted'


class ScanDeleted(BaseModel):
    scan_id: int
    status: Literal['deleted'] = 'deleted'
    sample_removed: bool


class BulkDeleteCandidate(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

    scan_id: int = Field(ge=1, le=9007199254740991)
    attempt: int = Field(ge=0, le=2147483647)
    job_revision: int = Field(ge=0, le=9007199254740991)


class BulkDeleteBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

    scans: list[BulkDeleteCandidate] = Field(min_length=1, max_length=20)


class BulkDeleteResult(BaseModel):
    requested_count: int
    deleted_ids: list[int]
    blocked_ids: list[int]
    cleanup_failed_ids: list[int]


def manual_scan(scan_id: int):
    scan = db.get_scan(scan_id)
    if scan is None or scan.source != 'manual':
        raise HTTPException(404, 'Manual scan not found.')
    return scan


def retry(scan_id: int, attempt: int, job_revision: int) -> RetryAccepted:
    scan = manual_scan(scan_id)
    engines = engines_for_scan(scan)
    if not engines:
        raise HTTPException(409, 'No eligible engines. Existing results have been preserved.')
    if not db.retry_scan_job(scan_id, source='manual', expected_attempt=attempt, engines=engines,
                             expected_job_revision=job_revision,
                             lock_timeout_ms=write_lock_timeout_ms()):
        raise HTTPException(409, 'Scan changed or is active. Refresh before retrying.')
    return RetryAccepted(scan_id=scan_id)


def delete(scan_id: int, attempt: int, job_revision: int, *,
           allowed_scan_roles: frozenset[str] | None = None) -> ScanDeleted:
    manual_scan(scan_id)
    scan = db.delete_scan(scan_id, source='manual', expected_attempt=attempt, protect_children=True,
                          allowed_scan_roles=allowed_scan_roles,
                          expected_job_revision=job_revision,
                          lock_timeout_ms=write_lock_timeout_ms())
    if scan is None:
        raise HTTPException(409, 'Deletion blocked: scan changed, is active, has registered children, shares a sample or has undelivered notifications. Refresh the report.')
    # Database deletion commits first. A filesystem failure must not suggest
    # that the scan record still exists or encourage replay of the mutation.
    try:
        removed = delete_sample_file(scan)
    except OSError:
        removed = False
    return ScanDeleted(scan_id=scan_id, sample_removed=removed)


def bulk_delete(candidates: list[BulkDeleteCandidate]) -> BulkDeleteResult:
    ids = [candidate.scan_id for candidate in candidates]
    if len(set(ids)) != len(ids):
        raise HTTPException(422, 'Each selected scan may appear only once.')
    deleted_ids: list[int] = []
    blocked_ids: list[int] = []
    cleanup_failed_ids: list[int] = []
    for candidate in candidates:
        try:
            # The locked delete rechecks this Dashboard-only role boundary along
            # with source, attempt, job revision and all existing protections.
            result = delete(candidate.scan_id, candidate.attempt, candidate.job_revision,
                            allowed_scan_roles=DASHBOARD_DELETE_ROLES)
        except HTTPException as exc:
            if exc.status_code not in {404, 409}:
                raise
            blocked_ids.append(candidate.scan_id)
            continue
        deleted_ids.append(candidate.scan_id)
        if not result.sample_removed:
            cleanup_failed_ids.append(candidate.scan_id)
    return BulkDeleteResult(requested_count=len(candidates), deleted_ids=deleted_ids,
                            blocked_ids=blocked_ids, cleanup_failed_ids=cleanup_failed_ids)


def summary_export(scan_id: int, format: Literal['json', 'csv']) -> SummaryExport:
    report = scan_report_read.report(scan_id)
    payload = {'schema_version': 1, 'scope': EXPORT_SCOPE, 'report': report.model_dump(mode='json')}
    if format == 'json':
        content = json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        output = io.StringIO(newline='')
        writer = csv.writer(output)
        writer.writerow(['field', 'value'])

        def emit(path, value):
            if isinstance(value, dict) and value:
                for key, item in value.items():
                    emit(f'{path}.{key}' if path else key, item)
            elif isinstance(value, list) and value:
                for index, item in enumerate(value):
                    emit(f'{path}[{index}]', item)
            else:
                # Force all untrusted strings to spreadsheet text, including
                # leading whitespace/control characters before a formula.
                cell = "'" + value if isinstance(value, str) else json.dumps(value)
                writer.writerow([path, cell])

        emit('', payload)
        content = output.getvalue()
    if len(content.encode('utf-8')) > EXPORT_LIMIT:
        raise HTTPException(413, 'Summary export exceeds 2 MiB. Use the legacy report.')
    return SummaryExport(filename=f'masp-scan-{scan_id}-summary.{format}',
                         media_type='application/json' if format == 'json' else 'text/csv', content=content)


def _full_export_rows(scan_id: int):
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        row = connection.execute('''SELECT j.id, j.sample_id, j.case_name, j.priority, j.note, j.source,
            j.batch_id, j.parent_scan_id, j.relative_path, j.scan_role, j.service_client_id,
            j.scan_profile_id, SUBSTR(j.profile_snapshot_json, 1, ?) AS profile_snapshot_json,
            j.status, j.verdict, j.risk_score, j.created_at, j.started_at, j.completed_at,
            j.failed_at, j.attempt_count, j.last_error, s.original_filename,
            '' AS stored_filename, '' AS storage_path, s.content_type, s.size_bytes,
            s.md5, s.sha1, s.sha256
            FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
            WHERE j.id = ? AND j.source = 'manual' ''',
            (scan_report_read.SNAPSHOT_LIMIT + 1, scan_id)).fetchone()
        if row is None:
            raise HTTPException(404, 'Manual scan not found.')
        scan = db.row_to_scan_record(row)
        if len(scan.profile_snapshot_json) > scan_report_read.SNAPSHOT_LIMIT:
            raise HTTPException(413, 'Full export routing snapshot exceeds the browser limit. Use the legacy export.')
        byte_length = ("OCTET_LENGTH(COALESCE({field}, ''))" if db.using_postgres()
                       else "LENGTH(CAST(COALESCE({field}, '') AS BLOB))")
        fields = ('engine_name', 'engine_version', 'signature_version', 'signature', 'raw_output',
                  'error_message', 'details_json', 'findings_json')
        size_terms = ' + '.join(byte_length.format(field=field) for field in fields)
        preflight = connection.execute(f'''SELECT COUNT(*) AS result_count,
            COALESCE(SUM({size_terms}), 0) AS source_bytes
            FROM engine_results WHERE scan_job_id = ?''', (scan_id,)).fetchone()
        if int(preflight['result_count']) > MAX_EXPORT_ENGINES:
            raise HTTPException(413, 'Full export has too many engine results. Use the legacy export.')
        if int(preflight['source_bytes']) > FULL_EXPORT_SOURCE_LIMIT:
            raise HTTPException(413, 'Full export engine output exceeds the 2 MiB browser source limit. Use the legacy export.')
        result_rows = connection.execute('''SELECT id, scan_job_id, engine_name, engine_version,
            signature_version, status, detected, signature, severity, confidence, raw_output,
            error_message, duration_ms, details_json, findings_json, created_at
            FROM engine_results WHERE scan_job_id = ? ORDER BY created_at ASC, id ASC''',
            (scan_id,)).fetchall()
        job_rows = connection.execute('''SELECT id, scan_job_id, engine_instance_id, engine_key,
            engine_name, status, NULL AS worker_id, claimed_at, started_at, finished_at,
            lease_expires_at, attempt_count, NULL AS last_error, created_at, updated_at
            FROM scan_engine_jobs WHERE scan_job_id = ? ORDER BY id LIMIT ?''',
            (scan_id, MAX_EXPORT_ENGINES + 1)).fetchall()
        if len(job_rows) > MAX_EXPORT_ENGINES:
            raise HTTPException(413, 'Full export has too many engine jobs. Use the legacy export.')
        jobs = [db.row_to_scan_engine_job_record(job) for job in job_rows]
        snapshot = parse_profile_snapshot(scan)
        if isinstance(snapshot.get('engines'), list) or jobs:
            required = required_detection_engine_names(scan, jobs=jobs)
        else:
            instances = connection.execute('''SELECT adapter_key, display_name FROM engine_instances
                WHERE enabled ORDER BY id''').fetchall()
            required = []
            for instance in instances:
                try:
                    detection = adapter_definition(str(instance['adapter_key'])).detection
                except KeyError:
                    detection = True
                if detection:
                    required.append(str(instance['display_name']))
        results = [db.row_to_engine_result_record(result) for result in result_rows]
    policy_complete = True
    for result in results:
        try:
            policy_complete = policy_complete and isinstance(json.loads(result.details_json or '{}'), dict)
        except (ValueError, TypeError, RecursionError):
            policy_complete = False
    return scan, results, required, policy_complete


def full_export(scan_id: int, format: Literal['json', 'csv']) -> SummaryExport:
    scan, results, required, policy_complete = _full_export_rows(scan_id)
    payload = build_scan_report_payload(
        scan, results, required_names=required, decision_available=policy_complete
    )
    if not policy_complete:
        payload['decision_warning'] = 'Decision unavailable: engine policy details are invalid.'
    content = (json.dumps(payload, ensure_ascii=False, indent=2) if format == 'json'
               else create_scan_report_csv(scan, results, payload))
    if len(content.encode('utf-8')) > EXPORT_LIMIT:
        raise HTTPException(413, 'Full export exceeds 2 MiB. Use the legacy export.')
    return SummaryExport(filename=f'masp-scan-{scan_id}-full.{format}',
                         media_type='application/json' if format == 'json' else 'text/csv', content=content)
