"""Bounded, session-only previews of public scan JSON contracts."""
import json
from dataclasses import asdict

from fastapi import HTTPException
from pydantic import BaseModel, ValidationError

from app.services.api_payloads import build_scan_summary_payload, create_api_scan_result_payload
from app.services.api_schemas import ScanResultResponse
from app.services.reports import build_scan_report_payload
from app.services.scan_intake import scan_is_terminal
from app.services.scan_management import _full_export_rows, EXPORT_LIMIT
from app import database as db
from app.services import scan_policy
from app.services.api_payloads import create_api_scan_status_payload
from app.services.api_schemas import ScanStatusResponse
from app.services.browser_db_budget import apply_read_budget
from app.services.engine_registry import engine_allowed_for_source
from app.services.service_clients import parse_profile_snapshot, _file_capable
from app.services.scan_assessment import scan_decision


class ResultPreview(BaseModel):
    scan_id: int
    content: str


def _expected_engines(connection, scan) -> int:
    # Match the public status field's current eligibility of accepted instances.
    # This is not required detection coverage, which uses recorded names below.
    entries = parse_profile_snapshot(scan).get('engines')
    if not isinstance(entries, list):
        raise HTTPException(413, 'Status JSON requires an accepted routing snapshot.')
    if len(entries) > 256:
        raise HTTPException(413, 'Status routing exceeds the browser engine limit.')
    identifiers = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            identifier = int(entry['id'])
        except (KeyError, TypeError, ValueError, OverflowError):
            continue
        if not -(2 ** 63) <= identifier < 2 ** 63:
            raise HTTPException(409, 'Stored routing contains an unsupported engine ID.')
        identifiers.add(identifier)
    if not identifiers:
        return 0
    placeholders = ','.join('?' for _ in identifiers)
    rows = connection.execute(f'''SELECT id, adapter_key, enabled,
        '' AS display_name, '{{}}' AS config_json, '' AS created_at, '' AS updated_at
        FROM engine_instances WHERE id IN ({placeholders}) AND enabled''',
        tuple(identifiers)).fetchall()
    engines = [db.row_to_engine_instance_record(row) for row in rows]
    return sum(engine_allowed_for_source(engine, scan.source) and _file_capable(engine)
               for engine in engines)


def status_preview(scan_id: int, base_url: str) -> ResultPreview:
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        scan, results, required, policy_complete = _full_export_rows(
            scan_id, automation=True, connection=connection)
        if not policy_complete:
            raise HTTPException(409, 'Status JSON unavailable: engine policy details are invalid.')
        expected = _expected_engines(connection, scan)
        ready = scan_is_terminal(scan)
        poll_seconds = None
        if not ready:
            setting = connection.execute('SELECT SUBSTR(value, 1, 1025) AS value FROM app_settings WHERE key = ?',
                                         ('scan_policy.api_retry_after_seconds',)).fetchone()
            raw = setting['value'] if setting else None
            if raw is not None and len(raw) > 1024:
                raise HTTPException(413, 'Polling policy exceeds the browser limit.')
            poll_seconds = scan_policy.resolve_raw('api_retry_after_seconds', raw)
        metrics = db.get_queue_metrics(connection=connection)
        position = db.get_scan_queue_position(scan.id, connection=connection)
    status_url = f'{base_url.rstrip("/")}/api/v1/scans/{scan.id}'
    payload = create_api_scan_status_payload(
        result_ready=ready, recommended_poll_seconds=poll_seconds,
        decision_payload=asdict(scan_decision(scan, results, required_names=required)),
        scan_payload=build_scan_summary_payload(scan), queue_metrics=metrics,
        queue_position=position, expected_engines=expected, results=results,
        links={'status': status_url, 'result': status_url + '/result'})
    if scan.batch_id is not None:
        batch_url = f'{base_url.rstrip("/")}/api/v1/batches/{scan.batch_id}'
        payload['batch_links'] = {'status': batch_url, 'result': batch_url + '/result'}
    try:
        ScanStatusResponse.model_validate(payload)
    except ValidationError:
        raise HTTPException(409, 'Stored status cannot satisfy the integration JSON contract.') from None
    preview = ResultPreview(scan_id=scan.id, content=json.dumps(payload, ensure_ascii=False, indent=2))
    if len(preview.model_dump_json().encode('utf-8')) > EXPORT_LIMIT:
        raise HTTPException(413, 'Status JSON exceeds the 2 MiB browser response limit.')
    return preview


def result_preview(scan_id: int, base_url: str) -> ResultPreview:
    # Same coherent preflight and hydration as exports, including recorded routing.
    scan, results, required, policy_complete = _full_export_rows(scan_id, automation=True)
    if not scan_is_terminal(scan):
        raise HTTPException(409, 'Result is not ready. Refresh after the scan finishes.')
    if not policy_complete:
        raise HTTPException(409, 'Result JSON unavailable: engine policy details are invalid.')
    report = build_scan_report_payload(scan, results, required_names=required)

    def links(resource, identifier):
        status = f'{base_url.rstrip("/")}/api/v1/{resource}/{identifier}'
        return {'status': status, 'result': status + '/result'}

    payload = create_api_scan_result_payload(
        report_payload=report, scan_payload=build_scan_summary_payload(scan),
        completed=True, result_ready=True, decision_payload=report['summary']['decision'],
        links=links('scans', scan.id),
    )
    if scan.batch_id is not None:
        payload['batch_links'] = links('batches', scan.batch_id)
    try:
        ScanResultResponse.model_validate(payload)
    except ValidationError:
        # Never echo stored data in validation errors or invent a valid decision.
        raise HTTPException(409, 'Stored result cannot satisfy the integration JSON contract.') from None
    preview = ResultPreview(scan_id=scan.id, content=json.dumps(payload, ensure_ascii=False, indent=2))
    if len(preview.model_dump_json().encode('utf-8')) > EXPORT_LIMIT:
        raise HTTPException(413, 'Result JSON exceeds the 2 MiB browser response limit.')
    return preview
