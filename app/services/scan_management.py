"""Browser operations sharing queue protections; manual by default."""
from contextlib import nullcontext
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
           allowed_scan_roles: frozenset[str] | None = None, automation: bool = False) -> ScanDeleted:
    if automation:
        current = db.get_scan(scan_id)
        if current is None or current.source not in {'api', 'icap'}:
            raise HTTPException(404, 'Automation scan not found.')
    else:
        current = manual_scan(scan_id)
    scan = db.delete_scan(scan_id, source=current.source, expected_attempt=attempt, protect_children=True,
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


def bulk_delete(candidates: list[BulkDeleteCandidate], *, automation: bool = False) -> BulkDeleteResult:
    ids = [candidate.scan_id for candidate in candidates]
    if len(set(ids)) != len(ids):
        raise HTTPException(422, 'Each selected scan may appear only once.')
    deleted_ids: list[int] = []
    blocked_ids: list[int] = []
    cleanup_failed_ids: list[int] = []
    for candidate in candidates:
        try:
            # The locked delete rechecks this top-level history role boundary along
            # with source, attempt, job revision and all existing protections.
            result = delete(candidate.scan_id, candidate.attempt, candidate.job_revision,
                            allowed_scan_roles=DASHBOARD_DELETE_ROLES, automation=automation)
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


def summary_export(scan_id: int, format: Literal['json', 'csv'], *, automation: bool = False) -> SummaryExport:
    report = scan_report_read.report(scan_id, automation=automation)
    payload = {'schema_version': 1, 'scope': EXPORT_SCOPE.replace('Manual', 'Automation') if automation else EXPORT_SCOPE, 'report': report.model_dump(mode='json')}
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
        raise HTTPException(413, 'Summary export exceeds 2 MiB. Open the report or download individual engine outputs from the report instead.')
    return SummaryExport(filename=f'masp-scan-{scan_id}-summary.{format}',
                         media_type='application/json' if format == 'json' else 'text/csv', content=content)


def _full_export_rows(scan_id: int, *, automation: bool = False, connection=None):
    owned = connection is None
    with (db.connect() if owned else nullcontext(connection)) as connection:
        if owned:
            connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        row = connection.execute(f'''SELECT j.id, j.sample_id, j.case_name, j.priority, j.note, j.source,
            j.batch_id, j.parent_scan_id, j.relative_path, j.scan_role, j.service_client_id,
            j.scan_profile_id, SUBSTR(j.profile_snapshot_json, 1, ?) AS profile_snapshot_json,
            j.status, j.verdict, j.risk_score, j.created_at, j.started_at, j.completed_at,
            j.failed_at, j.attempt_count, j.last_error, s.original_filename,
            '' AS stored_filename, '' AS storage_path, s.content_type, s.size_bytes,
            s.md5, s.sha1, s.sha256
            FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
            WHERE j.id = ? AND {scan_report_read.source_clause(automation)} ''',
            (scan_report_read.SNAPSHOT_LIMIT + 1, scan_id)).fetchone()
        if row is None:
            raise HTTPException(404, 'Automation scan not found.' if automation else 'Manual scan not found.')
        scan = db.row_to_scan_record(row)
        if len(scan.profile_snapshot_json) > scan_report_read.SNAPSHOT_LIMIT:
            raise HTTPException(413, 'Full export routing snapshot exceeds the browser limit, so no full export is available for this scan.')
        byte_length = ("OCTET_LENGTH(COALESCE({field}, ''))" if db.using_postgres()
                       else "LENGTH(CAST(COALESCE({field}, '') AS BLOB))")
        fields = ('engine_name', 'engine_version', 'signature_version', 'signature', 'raw_output',
                  'error_message', 'details_json', 'findings_json')
        size_terms = ' + '.join(byte_length.format(field=field) for field in fields)
        preflight = connection.execute(f'''SELECT COUNT(*) AS result_count,
            COALESCE(SUM({size_terms}), 0) AS source_bytes
            FROM engine_results WHERE scan_job_id = ?''', (scan_id,)).fetchone()
        if int(preflight['result_count']) > MAX_EXPORT_ENGINES:
            raise HTTPException(413, 'Full export has more engine results than the browser export supports. Download individual engine outputs from the report instead.')
        if int(preflight['source_bytes']) > FULL_EXPORT_SOURCE_LIMIT:
            raise HTTPException(413, 'Full export engine output exceeds the 2 MiB browser source limit. Download individual engine outputs from the report instead.')
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
            raise HTTPException(413, 'Full export has more engine jobs than the browser export supports. Download individual engine outputs from the report instead.')
        jobs = [db.row_to_scan_engine_job_record(job) for job in job_rows]
        snapshot = parse_profile_snapshot(scan)
        if isinstance(snapshot.get('engines'), list) or jobs:
            required = required_detection_engine_names(scan, jobs=jobs)
        elif automation:
            # Do not reconstruct historical automation coverage using today's global
            # or profile routing; a bounded coherent snapshot is unavailable.
            raise HTTPException(413, 'Historical automation routing has no snapshot or engine jobs, so its coverage cannot be reconstructed and no full export is available. The report and summary export remain available.')
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


def full_export(scan_id: int, format: Literal['json', 'csv'], *, automation: bool = False) -> SummaryExport:
    scan, results, required, policy_complete = _full_export_rows(scan_id, automation=automation)
    payload = build_scan_report_payload(
        scan, results, required_names=required, decision_available=policy_complete
    )
    if not policy_complete:
        payload['decision_warning'] = 'Decision unavailable: engine policy details are invalid.'
    content = (json.dumps(payload, ensure_ascii=False, indent=2) if format == 'json'
               else create_scan_report_csv(scan, results, payload))
    if len(content.encode('utf-8')) > EXPORT_LIMIT:
        raise HTTPException(413, 'Full export exceeds 2 MiB. Download individual engine outputs from the report instead.')
    return SummaryExport(filename=f'masp-scan-{scan_id}-full.{format}',
                         media_type='application/json' if format == 'json' else 'text/csv', content=content)


PRINT_OUTPUT_LIMIT = 8192
MAX_PRINT_FINDINGS = 200
PRINT_EVIDENCE_LIMIT = 512


class PrintFinding(BaseModel):
    engine: str
    severity: str
    finding: str
    title: str
    matched_evidence: list[str]
    classification: list[str]


class PrintEngine(BaseModel):
    engine_name: str
    status: str
    detected: bool
    severity: str
    confidence: int
    signature: str | None
    duration_ms: int | None
    error_message: str | None
    raw_output: str
    output_truncated: bool


class PrintSummary(BaseModel):
    verdict: str
    risk_score: int | None
    assessment_reasons: list[str]
    detection_label: str
    detection_detail: str
    detected_engines: list[str]
    coverage_label: str
    coverage_detail: str
    coverage_ran: int
    coverage_total: int
    coverage_unavailable: list[str]


class PrintableReport(BaseModel):
    scan_id: int
    source: str
    filename: str
    case_name: str
    note: str
    status: str
    content_type: str
    size_bytes: int
    sha256: str
    attempt_count: int
    created_at: str
    completed_at: str | None
    generated_at: str
    summary: PrintSummary
    decision: scan_report_read.DecisionSummary | None
    decision_warning: str | None
    findings: list[PrintFinding]
    findings_truncated: bool
    engines: list[PrintEngine]


def _bounded_text_list(values: object, limit: int = PRINT_EVIDENCE_LIMIT, count: int = 16) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value)[:limit] for value in values[:count]]


def printable_report(scan_id: int, *, automation: bool = False) -> PrintableReport:
    """Print-oriented projection of the bounded full-export snapshot.

    Legacy `/scans/{id}/report` embedded every engine's raw output with no
    ceiling and no source scope, so an oversized result could render an
    unbounded page and a manual URL could display an automation scan. This
    reuses the export admission and server-selected scope instead, and bounds
    each engine preview; complete output stays behind the per-result reads.
    """
    scan, results, required, policy_complete = _full_export_rows(scan_id, automation=automation)
    payload = build_scan_report_payload(scan, results, required_names=required,
                                        decision_available=policy_complete)
    summary = payload['summary']
    detection, coverage, assessment = summary['detection'], summary['coverage'], summary['assessment']
    decision_payload = summary['decision']
    if decision_payload:
        decision_payload = dict(decision_payload)
        decision_payload['reason'] = str(decision_payload['reason'])[:2048]
        decision_payload['reasons'] = [str(reason)[:2048] for reason in decision_payload['reasons'][:32]]
    raw_findings = payload['findings'] if isinstance(payload['findings'], list) else []
    findings = [PrintFinding(engine=str(item['engine'])[:512], severity=str(item['severity'])[:64],
        finding=str(item['finding'])[:512], title=str(item['title'])[:512],
        matched_evidence=_bounded_text_list(item['matched_evidence']),
        classification=_bounded_text_list(item['classification']))
        for item in raw_findings[:MAX_PRINT_FINDINGS]]
    engines = [PrintEngine(engine_name=result.engine_name[:512], status=result.status,
        detected=result.detected and result.status == 'completed', severity=result.severity,
        confidence=result.confidence, signature=(result.signature or None) and result.signature[:1024],
        duration_ms=result.duration_ms, error_message=(result.error_message or None) and result.error_message[:2048],
        raw_output=(result.raw_output or '')[:PRINT_OUTPUT_LIMIT],
        output_truncated=len(result.raw_output or '') > PRINT_OUTPUT_LIMIT) for result in results]
    report = PrintableReport(scan_id=scan.id, source=scan.source, filename=scan.original_filename[:512],
        case_name=scan.case_name[:200], note=scan.note[:4000], status=scan.status,
        content_type=scan.content_type[:255], size_bytes=scan.size_bytes, sha256=scan.sha256,
        attempt_count=scan.attempt_count, created_at=scan.created_at, completed_at=scan.completed_at,
        generated_at=str(payload['generated_at']),
        summary=PrintSummary(verdict=str(assessment['verdict']), risk_score=assessment['score'],
            assessment_reasons=_bounded_text_list(assessment['reasons'], 2048, 32),
            detection_label=str(detection['label'])[:512], detection_detail=str(detection['detail'])[:2048],
            detected_engines=_bounded_text_list(detection['detected_engines']),
            coverage_label=str(coverage['label'])[:512], coverage_detail=str(coverage['detail'])[:2048],
            coverage_ran=int(coverage['ran']), coverage_total=int(coverage['total']),
            coverage_unavailable=_bounded_text_list(coverage['unavailable'], 2048, 32)),
        decision=scan_report_read.DecisionSummary(**decision_payload) if decision_payload else None,
        decision_warning=None if policy_complete else
            'Decision unavailable: engine policy details are invalid or exceed the reader limit. Review each engine\'s recorded details and output.',
        findings=findings, findings_truncated=len(raw_findings) > MAX_PRINT_FINDINGS, engines=engines)
    if len(report.model_dump_json().encode('utf-8')) > EXPORT_LIMIT:
        raise HTTPException(413, 'Printable report exceeds the 2 MiB browser response limit. Download the full export instead.')
    return report
