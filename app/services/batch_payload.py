"""Complete small-batch public JSON previews; never truncate contract members."""
import json
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ValidationError

from app import database as db
from app.services.api_payloads import build_batch_summary_payload, build_scan_summary_payload, public_scan_report_payload
from app.services.api_schemas import BatchStatusResponse, BatchResultResponse
from app.services.browser_db_budget import apply_read_budget
from app.services.reports import build_scan_report_payload
from app.services.scan_intake import scan_is_terminal
from app.services.scan_management import _full_export_rows, EXPORT_LIMIT

MAX_MEMBERS = 20


class BatchPreview(BaseModel):
    batch_id: int
    content: str


def preview(batch_id: int, kind: Literal['status', 'result'], base_url: str) -> BatchPreview:
    def links(resource, identifier):
        status = f'{base_url.rstrip("/")}/api/v1/{resource}/{identifier}'
        return {'status': status, 'result': status + '/result'}

    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        row = connection.execute('''SELECT id, source, service_client_id,
            SUBSTR(original_filename, 1, 1025) AS original_filename,
            archive_mode, status, total_items, queued_items, running_items,
            completed_items, failed_items, malicious_items, skipped_items,
            '{}' AS metadata_json, NULL AS last_error, created_at, updated_at, completed_at
            FROM scan_batches WHERE id = ? AND source IN ('api', 'icap')''', (batch_id,)).fetchone()
        if row is None:
            raise HTTPException(404, 'Automation batch not found.')
        batch = db.row_to_scan_batch_record(row)
        if len(batch.original_filename) > 1024:
            raise HTTPException(413, 'Batch filename exceeds the browser JSON limit.')
        members = connection.execute('''SELECT id, source, service_client_id FROM scan_jobs
            WHERE batch_id = ? ORDER BY created_at, id LIMIT ?''', (batch_id, MAX_MEMBERS + 1)).fetchall()
        if len(members) > MAX_MEMBERS:
            raise HTTPException(413, 'Batch JSON supports at most 20 registered scans. Use the paginated batch overview.')
        if any(member['source'] != batch.source or member['service_client_id'] != batch.service_client_id for member in members):
            raise HTTPException(409, 'Batch membership has inconsistent source or ownership.')
        ids = [member['id'] for member in members]
        placeholders = ','.join('?' for _ in ids)
        scans = []
        if ids:
            # Public status needs no engine blobs, routing snapshots or operator text.
            rows = connection.execute(f'''SELECT j.id, j.sample_id, '' AS case_name,
                j.priority, '' AS note, j.source, j.batch_id, j.parent_scan_id,
                SUBSTR(j.relative_path, 1, 4097) AS relative_path, j.scan_role,
                j.status, j.verdict, j.risk_score, j.created_at, j.started_at, j.completed_at,
                j.failed_at, j.attempt_count, NULL AS last_error,
                SUBSTR(s.original_filename, 1, 1025) AS original_filename,
                '' AS stored_filename, '' AS storage_path, s.content_type, s.size_bytes,
                s.md5, s.sha1, s.sha256
                FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
                WHERE j.id IN ({placeholders}) ORDER BY j.created_at, j.id''', tuple(ids)).fetchall()
            scans = [db.row_to_scan_record(row) for row in rows]
            if len(scans) != len(ids):
                raise HTTPException(409, 'Batch contains unavailable sample records.')
            if any(len(scan.original_filename) > 1024 or len(scan.relative_path or '') > 4096 for scan in scans):
                raise HTTPException(413, 'Batch member metadata exceeds the browser JSON limit.')
        ready = batch.status == 'completed'
        if kind == 'result' and (not ready or any(not scan_is_terminal(scan) for scan in scans)):
            raise HTTPException(409, 'Batch result is not ready. Refresh after processing finishes.')
        entries = []
        if kind == 'result' and ids:
            # Admit the entire result set before hydrating any engine blob. The
            # aggregate ceiling is for the batch, not twenty independent 2 MiB reads.
            byte_length = "OCTET_LENGTH(COALESCE({field}, ''))" if db.using_postgres() else "LENGTH(CAST(COALESCE({field}, '') AS BLOB))"
            fields = ('engine_name', 'engine_version', 'signature_version', 'signature', 'raw_output', 'error_message', 'details_json', 'findings_json')
            terms = ' + '.join(byte_length.format(field=field) for field in fields)
            size = connection.execute(f'''SELECT COUNT(*) AS n, COALESCE(SUM({terms}), 0) AS bytes
                FROM engine_results WHERE scan_job_id IN ({placeholders})''', tuple(ids)).fetchone()
            snapshots = connection.execute(f'''SELECT COALESCE(SUM({byte_length.format(field='profile_snapshot_json')}), 0) AS bytes
                FROM scan_jobs WHERE id IN ({placeholders})''', tuple(ids)).fetchone()
            jobs = connection.execute(f'SELECT COUNT(*) AS n FROM scan_engine_jobs WHERE scan_job_id IN ({placeholders})', tuple(ids)).fetchone()
            if size['n'] > 256 or jobs['n'] > 256 or size['bytes'] + snapshots['bytes'] > EXPORT_LIMIT:
                raise HTTPException(413, 'Batch result exceeds the aggregate engine/source limit. Open individual reports.')
            for member in scans:
                scan, results, required, valid_policy = _full_export_rows(member.id, automation=True, connection=connection)
                if not valid_policy:
                    raise HTTPException(409, 'Batch result unavailable: a member has invalid policy details.')
                report = build_scan_report_payload(scan, results, required_names=required)
                entries.append({'id': scan.id, 'role': scan.scan_role, 'parent_scan_id': scan.parent_scan_id,
                                'relative_path': scan.relative_path,
                                'result': public_scan_report_payload(report, build_scan_summary_payload(scan)),
                                'links': links('scans', scan.id)})
        elif kind == 'status':
            entries = [{**build_scan_summary_payload(scan), 'result_ready': scan_is_terminal(scan),
                        'links': links('scans', scan.id)} for scan in scans]
        payload = {'completed': ready, 'result_ready': ready,
                   'batch': build_batch_summary_payload(batch, scans, links('batches', batch.id)),
                   'scans': entries, 'links': links('batches', batch.id)}
    try:
        (BatchResultResponse if kind == 'result' else BatchStatusResponse).model_validate(payload)
    except ValidationError:
        raise HTTPException(409, 'Stored batch cannot satisfy the integration JSON contract.') from None
    output = BatchPreview(batch_id=batch.id, content=json.dumps(payload, ensure_ascii=False, indent=2))
    if len(output.model_dump_json().encode('utf-8')) > EXPORT_LIMIT:
        raise HTTPException(413, 'Batch JSON exceeds the 2 MiB browser response limit.')
    return output
