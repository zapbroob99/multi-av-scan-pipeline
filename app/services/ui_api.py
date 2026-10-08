"""Session-authenticated browser API. No HTML or integration bearer credentials."""

from dataclasses import asdict
import hashlib
import hmac
from datetime import datetime
import json
import time
from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, Path, Query, Request, Response, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from app import database as db
from app.services import auth
from app.services import login_throttle
from app.services import date_range
from app.services import dashboard_read
from app.services import scan_report_read
from app.services import archive_read
from app.services import batch_read
from app.services import scan_management
from app.services import automation_payload
from app.services import batch_payload
from app.services import worker_admin
from app.services import queue_read
from app.services import system_read
from app.services import retention_admin
from app.services import scan_policy_admin
from app.services import hash_console
from app.services import client_admin
from app.services import client_readiness
from app.services import profile_admin
from app.services import client_storage_admin
from app.services import credential_admin
from app.services import ledger_read
from app.services import user_admin
from app.services import audit_read
from app.services import hash_list_admin
from app.services import scan_exceptions
from app.services import intake_read
from app.services import intake_admin
from app.services import health_read
from app.services import delivery_read
from app.services import support_bundle
from app.services import about_read
from app.services import notification_read
from app.services import storage_admin
from app.services import storage_read
from app.services import account
from app.services.ingest import store_upload, configured_upload_max_bytes, UploadTooLargeError
from app.services.ldap_auth import ldap_enabled
from app.services.scan_intake import enqueue_scan_from_stored_sample, NoEligibleEnginesError, DEFAULT_ARCHIVE_MODE
from app.services.upload_admission import bounded_upload, upload_body_limit
from app.services.audit import set_audit_context
from app.services.engine_registry import (
    ADAPTERS, adapter_capabilities, add_engine, configured_engines,
    engine_config, remove_engine, test_engine_connection, enabled_engines, EngineCapabilityProfile,
)
from app.services.engine_setup import engine_setup_from_form
from app.services.secret_store import SecretStoreError
from app.services.virustotal import clear_virustotal_cache
from app.services.worker_runtime import get_worker_status
from app.services.worker_health import health_interval_seconds
from app.services.worker_scheduling import eligible_worker_node_ids_for_engine_instance
from app.services.yara_rules import list_yara_rules, save_yara_rule, toggle_yara_rule, delete_yara_rule


PREFIX = "/api/ui/v1"
BODY_LIMIT = 128 * 1024


def csrf_token(session: str) -> str:
    return hmac.new(session.encode(), b"masp-browser-csrf-v1", hashlib.sha256).hexdigest()


def browser_user(request: Request):
    user = auth.current_user(request)
    if user is None:
        raise HTTPException(401, "Sign in to MASP to continue.")
    return user


class BrowserRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def checked(request: Request):
            login = self.path == PREFIX + "/session/login"
            # The sign-in screen reads this before any session exists.
            login_options = request.method == "GET" and self.path == PREFIX + "/session/options"
            upload = self.path == PREFIX + "/scans" and request.method == "POST"
            if not login and not login_options:
                user = await run_in_threadpool(browser_user, request)
                request.state.ui_user = user
                dashboard_read_allowed = request.method == "GET" and self.path in {
                    PREFIX + "/dashboard/summary", PREFIX + "/dashboard/scans",
                    PREFIX + "/api-ledger", PREFIX + "/api-ledger/clients",
                    PREFIX + "/api-ledger/scans/{scan_id}",
                    PREFIX + "/api-ledger/scans/{scan_id}/children",
                    PREFIX + "/api-ledger/scans/{scan_id}/summary-export",
                    PREFIX + "/api-ledger/scans/{scan_id}/export",
                    PREFIX + "/api-ledger/scans/{scan_id}/result-json",
                    PREFIX + "/api-ledger/scans/{scan_id}/status-json",
                    PREFIX + "/api-ledger/scans/{scan_id}/results/{result_id}",
                    PREFIX + "/api-ledger/scans/{scan_id}/results/{result_id}/full",
                    PREFIX + "/api-ledger/scans/{scan_id}/results/{result_id}/output",
                    PREFIX + "/api-ledger/scans/{scan_id}/print",
                    PREFIX + "/api-ledger/batches/{batch_id}",
                    PREFIX + "/api-ledger/batches/{batch_id}/json",
                    PREFIX + "/api-ledger/batches/{batch_id}/download",
                    PREFIX + "/scans/options",
                    PREFIX + "/scans/{scan_id}", PREFIX + "/scans/{scan_id}/results/{result_id}",
                    PREFIX + "/scans/{scan_id}/results/{result_id}/full",
                    PREFIX + "/scans/{scan_id}/results/{result_id}/output",
                    PREFIX + "/scans/{scan_id}/print",
                    PREFIX + "/scans/{scan_id}/children",
                    PREFIX + "/scans/{scan_id}/summary-export",
                    PREFIX + "/scans/{scan_id}/export",
                    PREFIX + "/batches/{batch_id}",
                }
                retry_allowed = request.method == 'POST' and self.path == PREFIX + '/scans/{scan_id}/retry'
                hash_allowed = (request.method == 'GET' and self.path == PREFIX + '/hash-scan/options') or (request.method == 'POST' and self.path == PREFIX + '/hash-scan')
                account_allowed = (request.method == 'GET' and self.path == PREFIX + '/account') or (request.method == 'POST' and self.path == PREFIX + '/account/password')
                about_allowed = request.method == 'GET' and self.path == PREFIX + '/about'
                notifications_allowed = (request.method == 'GET' and self.path == PREFIX + '/notifications') or (
                    request.method == 'POST' and self.path in {PREFIX + '/notifications/read', PREFIX + '/notifications/clear'})
                # Folder Scanning results are readable like the dashboards; managing locations is admin work.
                storage_read_allowed = request.method == 'GET' and self.path in {
                    PREFIX + '/storage/overview', PREFIX + '/storage/locations/{location_id}',
                    PREFIX + '/storage/locations/{location_id}/objects', PREFIX + '/storage/findings',
                }
                if not self.path.startswith(PREFIX + "/session") and not dashboard_read_allowed and not upload and not retry_allowed and not hash_allowed and not account_allowed and not about_allowed and not notifications_allowed and not storage_read_allowed and user.role != "admin":
                    raise HTTPException(403, "Admin permission is required.")
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                origin = str(request.base_url).rstrip("/")
                if request.headers.get("origin") != origin or request.headers.get("x-masp-ui") != "1":
                    raise HTTPException(403, "Same-origin browser request required.")
                if not login and not hmac.compare_digest(
                    request.headers.get("x-csrf-token", "").encode(),
                    csrf_token(request.cookies.get(auth.SESSION_COOKIE, "")).encode(),
                ):
                    raise HTTPException(403, "Invalid CSRF token. Refresh your session.")
                if not upload:
                    body = bytearray()
                    async for chunk in request.stream():
                        if len(body) + len(chunk) > BODY_LIMIT:
                            raise HTTPException(413, "Browser API body exceeds 128 KiB.")
                        body.extend(chunk)
                    request._body = bytes(body)
            try:
                if upload:
                    async def multipart_handler(request: Request):
                        async with request.form(max_files=1, max_fields=3, max_part_size=16384) as form:
                            if any(key not in {'sample', 'case_name', 'priority', 'note'} or len(form.getlist(key)) != 1 for key in form):
                                raise HTTPException(422, "Unexpected or duplicate upload fields.")
                            return await handler(request)
                    response = await bounded_upload(request, multipart_handler)
                else:
                    response = await handler(request)
            except RequestValidationError as exc:
                # Do not echo input dictionaries containing passwords or API keys.
                raise HTTPException(422, "Invalid request fields.") from exc
            except db.IntegrityViolation as exc:
                detail = "Scan submission conflicts with existing data." if upload else "Engine configuration conflicts with existing data."
                raise HTTPException(409, detail) from exc
            except (ValueError, SecretStoreError) as exc:
                raise HTTPException(422, str(exc)) from exc
            except FileNotFoundError as exc:
                raise HTTPException(404, "Rule not found.") from exc
            except db.DatabaseOperationalError as exc:
                if db.is_postgres_budget_error(exc):
                    raise HTTPException(503, "Browser database work exceeded its time budget. Refine the request or retry after current work settles.") from exc
                raise
            response.headers["Cache-Control"] = "no-store"
            return response

        return checked


class ErrorPayload(BaseModel):
    detail: str


router = APIRouter(prefix=PREFIX, tags=["Browser console"], route_class=BrowserRoute,
    responses={status: {"model": ErrorPayload} for status in (400, 401, 403, 404, 409, 413, 422, 503)})


class SubmissionOptions(BaseModel):
    file_max_bytes: int | None
    body_max_bytes: int
    enabled_engine_count: int
    archive_mode: str


@router.get('/api-ledger', response_model=ledger_read.LedgerPage)
def browser_api_ledger(limit: int = Query(default=20, ge=1, le=100),
    before: int | None = Query(default=None, ge=1, le=9007199254740991),
    q: str = Query(default='', max_length=200),
    source: Literal['all', 'api', 'icap'] = 'all',
    status: Literal['all', 'active', 'queued', 'running', 'finalizing', 'completed', 'partial', 'failed', 'skipped'] = 'all',
    risk: Literal['all', 'pending', 'info', 'metadata_only', 'low', 'medium', 'high', 'critical', 'not_allowed'] = 'all',
    client_id: int | None = Query(default=None, ge=1, le=9007199254740991), unassigned: bool = False,
    created_after: datetime | None = None, created_before: datetime | None = None,
):
    if client_id is not None and unassigned:
        raise HTTPException(422, 'Choose either a client ID or unassigned records.')
    created_after, created_before = date_range.validated(created_after, created_before)
    return ledger_read.page(limit=limit, before=before, query=q, source=source, status=status,
                            risk=risk, client_id=client_id, unassigned=unassigned,
                            created_after=created_after, created_before=created_before)


@router.get('/api-ledger/clients', response_model=ledger_read.LedgerClients)
def browser_api_ledger_clients():
    return ledger_read.clients()


class SubmissionAccepted(BaseModel):
    scan_id: int
    status: Literal["accepted"] = "accepted"
    report_url: str


@router.get("/scans/options", response_model=SubmissionOptions)
def submission_options():
    return SubmissionOptions(file_max_bytes=configured_upload_max_bytes(), body_max_bytes=upload_body_limit(),
        enabled_engine_count=len(enabled_engines(source="manual")), archive_mode=DEFAULT_ARCHIVE_MODE)


@router.get('/scans/{scan_id}', response_model=scan_report_read.ScanReport)
def read_scan_report(scan_id: int = Path(ge=1, le=9007199254740991)):
    return scan_report_read.report(scan_id)


@router.get('/scans/{scan_id}/children', response_model=archive_read.ArchivePage)
def read_archive_children(scan_id: int = Path(ge=1, le=9007199254740991),
    limit: int = Query(default=20, ge=1, le=100), after: int | None = Query(default=None, ge=1, le=9007199254740991),
    attempt: int | None = Query(default=None, ge=0, le=2147483647), q: str = Query(default='', max_length=200),
    status: Literal['all', 'active', 'queued', 'running', 'finalizing', 'completed', 'partial', 'failed', 'skipped'] = 'all',
):
    if after is not None and attempt is None:
        raise HTTPException(422, 'Archive pagination requires the parent attempt from the first page.')
    return archive_read.children(scan_id, limit=limit, after=after, attempt=attempt, query=q, status=status)


@router.get('/api-ledger/scans/{scan_id}/children', response_model=archive_read.ArchivePage)
def read_automation_archive_children(scan_id: int = Path(ge=1, le=9007199254740991),
    limit: int = Query(default=20, ge=1, le=100), after: int | None = Query(default=None, ge=1, le=9007199254740991),
    attempt: int | None = Query(default=None, ge=0, le=2147483647), q: str = Query(default='', max_length=200),
    status: Literal['all', 'active', 'queued', 'running', 'finalizing', 'completed', 'partial', 'failed', 'skipped'] = 'all',
):
    if after is not None and attempt is None:
        raise HTTPException(422, 'Archive pagination requires the parent attempt from the first page.')
    return archive_read.children(scan_id, limit=limit, after=after, attempt=attempt, query=q, status=status, automation=True)


@router.get('/scans/{scan_id}/results/{result_id}', response_model=scan_report_read.TechnicalDetails)
def read_scan_technical_details(scan_id: int = Path(ge=1, le=9007199254740991),
                                result_id: int = Path(ge=1, le=9007199254740991)):
    return scan_report_read.technical_details(scan_id, result_id)


@router.get('/scans/{scan_id}/results/{result_id}/full', response_model=scan_report_read.FullTechnicalDetails)
def read_full_engine_output(scan_id: int = Path(ge=1, le=9007199254740991),
                            result_id: int = Path(ge=1, le=9007199254740991)):
    return scan_report_read.full_technical_details(scan_id, result_id)


@router.get('/batches/{batch_id}', response_model=batch_read.BatchPage)
def read_manual_batch(
    batch_id: int = Path(ge=1, le=9007199254740991),
    limit: int = Query(default=20, ge=1, le=100),
    after_id: int | None = Query(default=None, ge=1, le=9007199254740991),
    after_created: str | None = Query(default=None, min_length=1, max_length=64),
):
    if (after_id is None) != (after_created is None):
        raise HTTPException(422, 'Batch pagination requires both cursor fields from the previous page.')
    return batch_read.page(batch_id, limit=limit, after_id=after_id, after_created=after_created)


@router.get('/api-ledger/batches/{batch_id}/json', response_model=batch_payload.BatchPreview)
def automation_batch_json(request: Request, batch_id: int = Path(ge=1, le=9007199254740991),
                          kind: Literal['status', 'result'] = 'status'):
    return batch_payload.preview(batch_id, kind, str(request.base_url))


@router.get('/users', response_model=user_admin.UserPage)
def browser_users(after: int | None = Query(default=None, ge=1, le=9007199254740991)):
    return user_admin.page(after)


@router.post('/users', response_model=user_admin.UserCreated, status_code=201)
def browser_create_user(request: Request, body: user_admin.CreateUserBody):
    set_audit_context(request, action='user.create', target_type='user', actor=request.state.ui_user,
                      details={'username': body.username.strip(), 'role': body.role})
    result = user_admin.create(body)
    set_audit_context(request, target_id=result.user_id)
    return result


@router.put('/users/{user_id}', status_code=204)
def browser_update_user(request: Request, body: user_admin.UpdateUserBody,
                        user_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='user.update', target_type='user', target_id=user_id,
                      actor=request.state.ui_user, details={'role': body.role, 'credentials_replaced': body.password is not None})
    user_admin.manage(request.state.ui_user.id, user_id, expected_revision=body.expected_revision,
                       role=body.role, password=body.password.get_secret_value() if body.password is not None else None)


@router.delete('/users/{user_id}', status_code=204)
def browser_delete_user(request: Request, body: user_admin.UserFence,
                        user_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='user.delete', target_type='user', target_id=user_id, actor=request.state.ui_user)
    user_admin.manage(request.state.ui_user.id, user_id, expected_revision=body.expected_revision, delete=True)


# PlainTextResponse would also declare the router's error responses as text, but
# an HTTPException still returns JSON. Restate them so the contract stays honest.
OUTPUT_ERRORS = {status: {'model': ErrorPayload,
                          'content': {'application/json': {'schema': {'$ref': '#/components/schemas/ErrorPayload'}}}}
                 for status in (400, 401, 403, 404, 409, 413, 422, 503)}


def _output_response(filename: str, content: str) -> PlainTextResponse:
    return PlainTextResponse(content, media_type='text/plain; charset=utf-8',
                             headers={'Content-Disposition': f'attachment; filename="{filename}"'})


# The document conforms to the public integration contract and is validated in
# full before it is served; it is a download, so it carries no typed envelope.
BATCH_DOWNLOAD_RESPONSES = OUTPUT_ERRORS | {
    200: {'content': {'application/json': {'schema': {'type': 'object'}}},
          'description': 'Complete public batch contract as a downloadable document'}}


@router.get('/api-ledger/batches/{batch_id}/download', responses=BATCH_DOWNLOAD_RESPONSES, response_model=None)
def automation_batch_download(request: Request, batch_id: int = Path(ge=1, le=9007199254740991),
                              kind: Literal['status', 'result'] = 'status'):
    filename, content = batch_payload.download(batch_id, kind, str(request.base_url))
    return Response(content, media_type='application/json',
                    headers={'Content-Disposition': f'attachment; filename="{filename}"'})


@router.get('/scans/{scan_id}/print', response_model=scan_management.PrintableReport)
def manual_printable_report(scan_id: int = Path(ge=1, le=9007199254740991)):
    return scan_management.printable_report(scan_id)


@router.get('/api-ledger/scans/{scan_id}/print', response_model=scan_management.PrintableReport)
def automation_printable_report(scan_id: int = Path(ge=1, le=9007199254740991)):
    return scan_management.printable_report(scan_id, automation=True)


@router.get('/scans/{scan_id}/results/{result_id}/output', response_class=PlainTextResponse, responses=OUTPUT_ERRORS)
def manual_result_output(scan_id: int = Path(ge=1, le=9007199254740991),
                         result_id: int = Path(ge=1, le=9007199254740991)):
    return _output_response(*scan_report_read.raw_output(scan_id, result_id))


@router.get('/api-ledger/scans/{scan_id}/results/{result_id}/output', response_class=PlainTextResponse, responses=OUTPUT_ERRORS)
def automation_result_output(scan_id: int = Path(ge=1, le=9007199254740991),
                             result_id: int = Path(ge=1, le=9007199254740991)):
    return _output_response(*scan_report_read.raw_output(scan_id, result_id, automation=True))


@router.get('/audit', response_model=audit_read.AuditPage)
def browser_audit(limit: int = Query(default=20, ge=1, le=100),
                  before: int | None = Query(default=None, ge=1, le=9007199254740991),
                  q: str = Query(default='', max_length=200),
                  outcome: Literal['all', 'success', 'failure', 'denied'] = 'all',
                  created_after: datetime | None = None, created_before: datetime | None = None):
    created_after, created_before = date_range.validated(created_after, created_before)
    return audit_read.page(limit=limit, before=before, query=q, outcome=outcome,
                           created_after=created_after, created_before=created_before)


@router.get('/system/intake', response_model=intake_read.IntakeOverview)
def browser_intake_overview():
    return intake_read.overview()


@router.post('/system/intake/{submission_id}/retry', status_code=204)
def browser_retry_intake(submission_id: int = Path(ge=1, le=9007199254740991)):
    intake_admin.retry_failed_submission(submission_id)
    return Response(status_code=204)


@router.post('/system/intake/rejections/dismiss', status_code=204)
def browser_dismiss_rejection(body: intake_admin.RejectionDismissal):
    intake_admin.dismiss_rejection(body)
    return Response(status_code=204)


def engine_payloads() -> list[dict]:
    status, records = get_worker_status(), db.list_engine_node_health()
    bindings, pools = db.list_engine_instance_worker_pool_bindings(), db.list_worker_pools()
    return [engine_payload(e, status, records, bindings, pools) for e in configured_engines() if e.adapter_key in ADAPTERS]


def system_health(payloads: list[dict]) -> health_read.HealthReport:
    # The Engines screen's verdicts, so a check never contradicts that screen.
    return health_read.report([health_read.EngineState(name=p['display_name'], adapter_key=p['adapter_key'],
                                                       state=p['health']['state'], detail=p['health']['detail'])
                               for p in payloads])


@router.get('/system/health', response_model=health_read.HealthReport)
def browser_system_health():
    return system_health(engine_payloads())


@router.post('/system/support-bundle', response_model=support_bundle.SupportBundle)
def browser_support_bundle(request: Request):
    # A POST so the export lands in the audit trail; it changes nothing.
    set_audit_context(request, action='system.support_bundle', target_type='system', actor=request.state.ui_user)
    payloads = engine_payloads()
    # Engine configuration can hold hosts and paths but never secrets in clear; it is still left out.
    engines = [{key: payload[key] for key in ('id', 'adapter_key', 'display_name', 'enabled', 'pool_id', 'health')}
               for payload in payloads]
    return support_bundle.build(system_health(payloads), engines)


@router.get('/system/delivery', response_model=delivery_read.DeliveryOverview)
def browser_delivery_overview():
    return delivery_read.overview()


@router.post('/system/notifications/retry', response_model=delivery_read.RetryNow)
def browser_retry_notifications():
    return delivery_read.retry_notifications_now()


@router.get('/hash-list', response_model=hash_list_admin.HashListPage)
def browser_hash_list(limit: int = Query(default=20, ge=1, le=100),
                      before: int | None = Query(default=None, ge=1, le=9007199254740991),
                      q: str = Query(default='', max_length=200),
                      kind: Literal['all', 'block', 'allow'] = 'all'):
    return hash_list_admin.page(limit=limit, before=before, kind=kind, query=q)


@router.post('/hash-list', response_model=hash_list_admin.HashesAdded, status_code=201)
def browser_add_hashes(request: Request, body: hash_list_admin.AddHashesBody):
    user = request.state.ui_user
    details = {'list_kind': body.list_kind, 'submitted': len(body.hashes)}
    set_audit_context(request, action='hash_list.add', target_type='hash_list', actor=user, details=details)
    result = hash_list_admin.add(body, user.username)
    set_audit_context(request, details={**details, 'added': result.added, 'existing': len(result.existing)})
    return result


@router.delete('/hash-list/{entry_id}', status_code=204)
def browser_remove_hash(request: Request, entry_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='hash_list.remove', target_type='hash_list_entry',
                      target_id=entry_id, actor=request.state.ui_user)
    hash_list_admin.remove(entry_id)


@router.get('/exceptions', response_model=scan_exceptions.ExceptionPage)
def browser_exceptions(limit: int = Query(default=20, ge=1, le=100),
                       before: int | None = Query(default=None, ge=1, le=9007199254740991),
                       state: Literal['all', 'active', 'expired', 'revoked'] = 'active',
                       q: str = Query(default='', max_length=200)):
    return scan_exceptions.page(limit=limit, before=before, state=state, query=q)


@router.post('/exceptions', response_model=scan_exceptions.ExceptionCreated, status_code=201)
def browser_add_exception(request: Request, body: scan_exceptions.ExceptionCreate):
    user = request.state.ui_user
    set_audit_context(request, action='exception.create', target_type='scan_exception', actor=user,
                      details={'sha256': body.sha256, 'client_id': body.service_client_id, 'reason': body.reason,
                               'expires_in_days': body.expires_in_days})
    try:
        created = scan_exceptions.create(body, user.username)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    set_audit_context(request, target_id=created)
    return scan_exceptions.ExceptionCreated(id=created)


@router.post('/exceptions/{exception_id}/revoke', status_code=204)
def browser_revoke_exception(request: Request, exception_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='exception.revoke', target_type='scan_exception', target_id=exception_id,
                      actor=request.state.ui_user)
    if not scan_exceptions.revoke(exception_id, request.state.ui_user.username):
        raise HTTPException(409, 'The exception is missing or already revoked. Refresh the list.')
    return Response(status_code=204)


@router.get('/storage/overview', response_model=storage_read.StorageOverview)
def browser_storage_overview():
    return storage_read.overview()


@router.get('/storage/options', response_model=storage_admin.StorageOptions)
def browser_storage_options():
    return storage_admin.options()


@router.post('/storage/locations', response_model=storage_admin.LocationCreated, status_code=201)
def browser_create_storage_location(request: Request, body: storage_admin.LocationCreate):
    user = request.state.ui_user
    set_audit_context(request, action='storage_location.create', target_type='storage_location', actor=user,
                      details={'backend_key': body.backend_key, 'service_client_id': body.service_client_id})
    created = storage_admin.create(body, user.username)
    set_audit_context(request, target_id=created.id)
    return created


@router.get('/storage/locations/{location_id}', response_model=storage_read.LocationDetail)
def browser_storage_location(location_id: int = Path(ge=1, le=9007199254740991)):
    return storage_read.location(location_id)


@router.put('/storage/locations/{location_id}', status_code=204)
def browser_update_storage_location(request: Request, body: storage_admin.LocationUpdate,
                                    location_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='storage_location.update', target_type='storage_location',
                      target_id=location_id, actor=request.state.ui_user, details={'enabled': body.enabled})
    storage_admin.update(location_id, body)
    return Response(status_code=204)


@router.get('/storage/locations/{location_id}/objects', response_model=storage_read.ObjectPage)
def browser_storage_objects(location_id: int = Path(ge=1, le=9007199254740991),
                            limit: int = Query(default=20, ge=1, le=100),
                            before: int | None = Query(default=None, ge=1, le=9007199254740991),
                            state: Literal['all', 'waiting', 'changed', 'light_passed', 'light_detected', 'allowed',
                                           'full_pending', 'unreadable', 'removed'] = 'all',
                            q: str = Query(default='', max_length=200)):
    return storage_read.objects(location_id, limit=limit, before=before, state=state, query=q)


@router.get('/storage/findings', response_model=storage_read.FindingPage)
def browser_storage_findings(limit: int = Query(default=20, ge=1, le=100),
                             before: int | None = Query(default=None, ge=1, le=9007199254740991),
                             location_id: int | None = Query(default=None, ge=1, le=9007199254740991),
                             kind: Literal['all', 'rule_block', 'type_policy', 'type_mismatch', 'archive_policy',
                                           'hash_block'] = 'all',
                             detected: Literal['all', 'detected', 'not_detected'] = 'all'):
    return storage_read.findings(limit=limit, before=before, location_id=location_id, kind=kind,
                                 detected=detected)


@router.get('/notifications', response_model=notification_read.Notifications)
def browser_notifications(request: Request):
    return notification_read.read(request.state.ui_user.id)


@router.post('/notifications/read', status_code=204)
def browser_mark_notifications_read(request: Request, body: notification_read.ThroughDetection):
    notification_read.mark_read(request.state.ui_user.id, body)
    return Response(status_code=204)


@router.post('/notifications/clear', status_code=204)
def browser_clear_notifications(request: Request, body: notification_read.ThroughDetection):
    notification_read.clear(request.state.ui_user.id, body)
    return Response(status_code=204)


@router.get('/about', response_model=about_read.AboutPayload)
def browser_about(request: Request):
    return about_read.snapshot(admin=request.state.ui_user.role == 'admin')


@router.get('/api-ledger/scans/{scan_id}', response_model=scan_report_read.ScanReport)
def automation_report(scan_id: int = Path(ge=1, le=9007199254740991)):
    return scan_report_read.report(scan_id, automation=True)


@router.get('/api-ledger/scans/{scan_id}/status-json', response_model=automation_payload.ResultPreview)
def automation_status_json(request: Request, scan_id: int = Path(ge=1, le=9007199254740991)):
    return automation_payload.status_preview(scan_id, str(request.base_url))


@router.get('/api-ledger/scans/{scan_id}/result-json', response_model=automation_payload.ResultPreview)
def automation_result_json(request: Request, scan_id: int = Path(ge=1, le=9007199254740991)):
    return automation_payload.result_preview(scan_id, str(request.base_url))


@router.get('/api-ledger/scans/{scan_id}/summary-export', response_model=scan_management.SummaryExport)
def automation_summary_export(scan_id: int = Path(ge=1, le=9007199254740991), format: Literal['json', 'csv'] = 'json'):
    return scan_management.summary_export(scan_id, format, automation=True)


@router.get('/api-ledger/scans/{scan_id}/export', response_model=scan_management.SummaryExport)
def automation_full_export(scan_id: int = Path(ge=1, le=9007199254740991), format: Literal['json', 'csv'] = 'json'):
    return scan_management.full_export(scan_id, format, automation=True)


@router.get('/api-ledger/scans/{scan_id}/results/{result_id}', response_model=scan_report_read.TechnicalDetails)
def automation_technical(scan_id: int = Path(ge=1, le=9007199254740991), result_id: int = Path(ge=1, le=9007199254740991)):
    return scan_report_read.technical_details(scan_id, result_id, automation=True)


@router.get('/api-ledger/scans/{scan_id}/results/{result_id}/full', response_model=scan_report_read.FullTechnicalDetails)
def automation_full_output(scan_id: int = Path(ge=1, le=9007199254740991), result_id: int = Path(ge=1, le=9007199254740991)):
    return scan_report_read.full_technical_details(scan_id, result_id, automation=True)


@router.get('/api-ledger/batches/{batch_id}', response_model=batch_read.BatchPage)
def automation_batch(batch_id: int = Path(ge=1, le=9007199254740991),
    limit: int = Query(default=20, ge=1, le=100),
    after_id: int | None = Query(default=None, ge=1, le=9007199254740991),
    after_created: str | None = Query(default=None, min_length=1, max_length=64),
):
    if (after_id is None) != (after_created is None):
        raise HTTPException(422, 'Batch pagination requires both cursor fields from the previous page.')
    return batch_read.page(batch_id, limit=limit, after_id=after_id, after_created=after_created, automation=True)


@router.post("/scans", response_model=SubmissionAccepted, status_code=202)
async def submit_scan(
    request: Request, response: Response,
    sample: UploadFile = File(...),
    case_name: str = Form(default="Unassigned", max_length=200),
    priority: Literal["Normal", "High", "Low"] = Form(default="Normal"),
    note: str = Form(default="", max_length=4000),
):
    if not sample.filename:
        raise HTTPException(422, "Select one sample file.")
    # Same storage, source-specific engine selection and transactional intake as
    # the legacy UI. No worker execution or orchestration wait in the HTTP request.
    try:
        stored = await store_upload(sample)
        scan = await run_in_threadpool(enqueue_scan_from_stored_sample, stored,
            case_name=case_name, priority=priority, note=note, source="manual",
            archive_mode=DEFAULT_ARCHIVE_MODE)
    except UploadTooLargeError as exc:
        raise HTTPException(413, str(exc)) from exc
    except NoEligibleEnginesError as exc:
        raise HTTPException(503, "No eligible scan engines are available. Check Engines before submitting again.") from exc
    set_audit_context(request, action="scan.submit", target_type="scan", target_id=scan.id,
        actor=request.state.ui_user, details={"source": "manual"})
    response.headers['Location'] = f'/scans/{scan.id}'
    return SubmissionAccepted(scan_id=scan.id, report_url=f'/scans/{scan.id}')


@router.get("/dashboard/summary", response_model=dashboard_read.DashboardSummary)
def dashboard_summary():
    return dashboard_read.summary()


@router.get("/dashboard/scans", response_model=dashboard_read.ScanPage)
def dashboard_scans(
    limit: int = Query(default=20, ge=1, le=100),
    before: int | None = Query(default=None, ge=1, le=9007199254740991),
    q: str = Query(default="", max_length=200),
    status: Literal["all", "active", "queued", "running", "finalizing", "completed", "partial", "failed"] = "all",
    risk: Literal["all", "pending", "info", "metadata_only", "low", "medium", "high", "critical"] = "all",
    detection: Literal["all", "detected", "undetected"] = "all",
    created_after: datetime | None = None,
    created_before: datetime | None = None,
):
    created_after, created_before = date_range.validated(created_after, created_before)
    return dashboard_read.scan_page(limit=limit, before=before, query=q, status=status, risk=risk,
                                    detection=detection, created_after=created_after,
                                    created_before=created_before)


class StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class WorkerIdentityBody(StrictBody):
    node_id: str = Field(min_length=1, max_length=128)


@router.get('/system/queue', response_model=queue_read.ActiveQueuePage)
def read_active_queue(limit: int = Query(default=20, ge=1, le=100),
                       after: int | None = Query(default=None, ge=1, le=9007199254740991)):
    return queue_read.page(limit=limit, after=after)


@router.get('/system/summary', response_model=system_read.SystemSummary)
def read_system_summary():
    return system_read.summary()


@router.get('/scan-policy', response_model=scan_policy_admin.ScanPolicySnapshot)
def read_browser_scan_policy():
    return scan_policy_admin.read()


@router.get('/service-clients', response_model=client_admin.ServiceClientPage)
def read_browser_service_clients(limit: int = Query(default=20, ge=1, le=100),
                                after: int | None = Query(default=None, ge=1, le=9007199254740991),
                                q: str = Query(default='', max_length=100)):
    return client_admin.page(limit, after, q)


@router.get('/service-clients/create-options', response_model=credential_admin.ClientCreateOptions)
def browser_client_create_options():
    return credential_admin.options()


@router.post('/service-clients', response_model=credential_admin.ClientCreated, status_code=201)
def browser_create_client(request: Request, body: credential_admin.ClientCreateBody):
    set_audit_context(request, action='service_client.create', target_type='service_client', actor=request.state.ui_user)
    result = credential_admin.create_client(body)
    set_audit_context(request, target_id=result.client_id)
    return result


@router.get('/service-clients/{client_id}/credentials', response_model=credential_admin.CredentialPage)
def browser_credentials(client_id: int = Path(ge=1, le=9007199254740991), after: int | None = Query(default=None, ge=1, le=9007199254740991)):
    return credential_admin.page(client_id, after)


@router.post('/service-clients/{client_id}/credentials', response_model=credential_admin.CredentialCreated, status_code=201)
def browser_create_credential(request: Request, body: credential_admin.CredentialBody, client_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='api_credential.create', target_type='service_client', target_id=client_id, actor=request.state.ui_user)
    return credential_admin.create_credential(client_id, body)


@router.post('/service-clients/{client_id}/credentials/{credential_id}/revoke', status_code=204)
def browser_revoke_credential(request: Request, client_id: int = Path(ge=1, le=9007199254740991), credential_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='api_credential.revoke', target_type='api_credential', target_id=credential_id, actor=request.state.ui_user)
    credential_admin.revoke(client_id, credential_id)
    return Response(status_code=204)


@router.get('/service-clients/{client_id}/readiness', response_model=client_readiness.ClientReadiness)
def browser_client_readiness(request: Request, client_id: int = Path(ge=1, le=9007199254740991)):
    return client_readiness.readiness(client_id, str(request.base_url))


@router.get('/service-clients/{client_id}/profiles', response_model=profile_admin.ClientProfiles)
def read_browser_profiles(client_id: int = Path(ge=1, le=9007199254740991),
                          after: int | None = Query(default=None, ge=1, le=9007199254740991)):
    return profile_admin.page(client_id, after)


@router.put('/service-clients/{client_id}/profiles/{profile_id}/engines', status_code=204)
def save_browser_profile(request: Request, body: profile_admin.ProfileRoutingBody,
                          client_id: int = Path(ge=1, le=9007199254740991), profile_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='scan_profile.engines_update', target_type='scan_profile', target_id=profile_id, actor=request.state.ui_user)
    profile_admin.save(client_id, profile_id, body)
    set_audit_context(request, details={'client_id': client_id, 'engine_ids': body.engine_ids})
    return Response(status_code=204)


@router.post('/service-clients/{client_id}/profiles', response_model=profile_admin.ProfileCreated, status_code=201)
def create_browser_profile(request: Request, body: profile_admin.ProfileCreateBody,
                           client_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='scan_profile.create', target_type='service_client', target_id=client_id, actor=request.state.ui_user)
    return profile_admin.create(client_id, body)


@router.get('/service-clients/{client_id}/storage', response_model=client_storage_admin.ClientStorageAccess)
def read_browser_client_storage(client_id: int = Path(ge=1, le=9007199254740991)):
    return client_storage_admin.read(client_id)


@router.put('/service-clients/{client_id}/storage', status_code=204)
def save_browser_client_storage(request: Request, body: client_storage_admin.StorageAccessUpdate,
                                client_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='service_client.storage.update', target_type='service_client',
                      target_id=client_id, actor=request.state.ui_user)
    client_storage_admin.save(client_id, body)
    return Response(status_code=204)


@router.put('/service-clients/{client_id}/profiles/{profile_id}', status_code=204)
def update_browser_profile(request: Request, body: profile_admin.ProfileUpdateBody,
                           client_id: int = Path(ge=1, le=9007199254740991), profile_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='scan_profile.update', target_type='scan_profile', target_id=profile_id, actor=request.state.ui_user)
    profile_admin.manage(client_id, profile_id, body, 'update')
    return Response(status_code=204)


@router.put('/service-clients/{client_id}/profiles/{profile_id}/default', status_code=204)
def default_browser_profile(request: Request, body: profile_admin.ProfileDefaultBody,
                            client_id: int = Path(ge=1, le=9007199254740991), profile_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='scan_profile.default', target_type='scan_profile', target_id=profile_id, actor=request.state.ui_user)
    profile_admin.manage(client_id, profile_id, body, 'default')
    return Response(status_code=204)


@router.put('/service-clients/{client_id}/profiles/{profile_id}/policy', status_code=204)
def policy_browser_profile(request: Request, body: profile_admin.ProfileRulesBody,
                           client_id: int = Path(ge=1, le=9007199254740991), profile_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='scan_profile.policy_update', target_type='scan_profile', target_id=profile_id, actor=request.state.ui_user)
    profile_admin.save_rules(client_id, profile_id, body)
    set_audit_context(request, details={'client_id': client_id, 'rules': body.rules.model_dump(mode='json')})
    return Response(status_code=204)


@router.delete('/service-clients/{client_id}/profiles/{profile_id}', status_code=204)
def delete_browser_profile(request: Request, body: profile_admin.ProfileFence,
                           client_id: int = Path(ge=1, le=9007199254740991), profile_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='scan_profile.delete', target_type='scan_profile', target_id=profile_id, actor=request.state.ui_user)
    profile_admin.manage(client_id, profile_id, body, 'delete')
    return Response(status_code=204)


@router.put('/service-clients/{client_id}', status_code=204)
def update_browser_service_client(request: Request, body: client_admin.ServiceClientUpdate,
                                  client_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='service_client.update', target_type='service_client',
                      target_id=client_id, actor=request.state.ui_user)
    client_admin.update(client_id, body)
    set_audit_context(request, details={'enabled': body.enabled})
    return Response(status_code=204)


@router.get('/hash-scan/options', response_model=hash_console.HashLookupOptions)
def read_hash_lookup_options():
    return hash_console.options()


@router.post('/hash-scan', response_model=hash_console.HashLookupResult)
def browser_hash_lookup(request: Request, body: hash_console.HashLookupBody):
    set_audit_context(request, action='hash_scan.lookup', target_type='hash', actor=request.state.ui_user)
    result = hash_console.lookup(body)
    set_audit_context(request, details={'action': result.action, 'engine_count': len(result.results)})
    return result


@router.put('/scan-policy', status_code=204)
def save_browser_scan_policy(request: Request, body: scan_policy_admin.ScanPolicyBody):
    set_audit_context(request, action='scan_policy.update', target_type='scan_policy', actor=request.state.ui_user)
    resolved = scan_policy_admin.save(body)
    set_audit_context(request, details={'settings': resolved})
    return Response(status_code=204)


@router.get('/system/retention', response_model=retention_admin.RetentionPage)
def read_retention_candidates(after: int | None = Query(default=None, ge=1, le=9007199254740991)):
    return retention_admin.preview(after)


@router.post('/system/retention/run', response_model=scan_management.BulkDeleteResult)
def run_browser_retention(request: Request, body: retention_admin.RetentionRunBody):
    set_audit_context(request, action='retention.run', target_type='scan', actor=request.state.ui_user,
                      details={'requested_ids': [item.scan_id for item in body.scans]})
    result = retention_admin.run(body)
    set_audit_context(request, details=result.model_dump())
    system_read._summary_cache = system_read._metrics_cache = None
    dashboard_read._summary_cache = None
    return result


@router.get('/system/engine-metrics', response_model=system_read.EngineMetricPage)
def read_engine_metrics(limit: int = Query(default=20, ge=1, le=100),
                        after: int | None = Query(default=None, ge=1, le=9007199254740991)):
    return system_read.metrics(limit=limit, after=after)


class PoolCreateBody(StrictBody):
    name: str = Field(min_length=1, max_length=100)
    selector: str = Field(min_length=1, max_length=4096)


class PoolUpdateBody(PoolCreateBody):
    enabled: bool


class PoolSaved(BaseModel):
    id: int


def browser_pool_values(body: PoolCreateBody) -> tuple[str, str]:
    try:
        name, selector = worker_admin.normalized_pool_form(body.name, body.selector)
    except RecursionError as exc:
        raise HTTPException(422, 'Worker pool selector is too deeply nested.') from exc
    if selector == '{}' or len(selector) > 4096:
        raise HTTPException(422, 'Supply a non-empty selector within 4096 serialized characters.')
    return name, selector


@router.get('/system/pools', response_model=worker_admin.PoolPage)
def read_worker_pools(limit: int = Query(default=20, ge=1, le=100),
                      after: int | None = Query(default=None, ge=1, le=9007199254740991),
                      q: str = Query(default='', max_length=100)):
    return worker_admin.pool_page(limit=limit, after=after, query=q)


@router.post('/system/pools', response_model=PoolSaved, status_code=201)
def create_browser_pool(request: Request, body: PoolCreateBody):
    name, selector = browser_pool_values(body)
    pool_id = db.create_worker_pool(name, selector)
    set_audit_context(request, action='worker_pool.create', target_type='worker_pool',
        target_id=pool_id, actor=request.state.ui_user)
    return PoolSaved(id=pool_id)


@router.put('/system/pools/{pool_id}', response_model=PoolSaved)
def update_browser_pool(request: Request, body: PoolUpdateBody, pool_id: int = Path(ge=1, le=9007199254740991)):
    name, selector = browser_pool_values(body)
    if not db.update_worker_pool(pool_id, name=name, selector_json=selector, enabled=body.enabled):
        raise HTTPException(404, 'Worker pool not found.')
    set_audit_context(request, action='worker_pool.update', target_type='worker_pool',
        target_id=pool_id, actor=request.state.ui_user)
    return PoolSaved(id=pool_id)


@router.delete('/system/pools/{pool_id}', status_code=204)
def delete_browser_pool(request: Request, pool_id: int = Path(ge=1, le=9007199254740991)):
    try:
        deleted = db.delete_worker_pool(pool_id)
    except (ValueError, *db.IntegrityViolation) as exc:
        raise HTTPException(409, 'Pool is still assigned or changed concurrently. Refresh and remove engine assignments first.') from exc
    except db.DatabaseOperationalError as exc:
        if getattr(exc, 'sqlstate', None) == '23503':
            raise HTTPException(409, 'Pool acquired an engine assignment. Refresh and remove assignments first.') from exc
        raise
    if not deleted:
        raise HTTPException(404, 'Worker pool not found.')
    set_audit_context(request, action='worker_pool.delete', target_type='worker_pool',
        target_id=pool_id, actor=request.state.ui_user)
    return Response(status_code=204)


class WorkerLifecycleBody(WorkerIdentityBody):
    lifecycle_state: Literal['active', 'draining', 'disabled']


class WorkerLifecycleSaved(BaseModel):
    node_id: str
    lifecycle_state: str


class WorkerCredentialsRevoked(BaseModel):
    node_id: str
    revoked_count: int


@router.get('/system/workers', response_model=worker_admin.WorkerPage)
def read_system_workers(limit: int = Query(default=20, ge=1, le=100),
                        after: str | None = Query(default=None, min_length=1, max_length=128),
                        q: str = Query(default='', max_length=100)):
    return worker_admin.page(limit=limit, after=after, query=q)


@router.post('/system/workers/lifecycle', response_model=WorkerLifecycleSaved)
def change_worker_lifecycle(request: Request, body: WorkerLifecycleBody):
    if not db.update_worker_node_lifecycle(body.node_id, body.lifecycle_state):
        raise HTTPException(404, 'Worker node not found.')
    set_audit_context(request, action='worker.lifecycle.update', target_type='worker_node',
        target_id=body.node_id, actor=request.state.ui_user, details={'lifecycle_state': body.lifecycle_state})
    return WorkerLifecycleSaved(node_id=body.node_id, lifecycle_state=body.lifecycle_state)


@router.post('/system/workers/credentials/revoke', response_model=WorkerCredentialsRevoked)
def revoke_worker_credentials(request: Request, body: WorkerIdentityBody):
    revoked = db.revoke_worker_agent_credentials(body.node_id)
    if revoked == 0:
        raise HTTPException(409, 'No active agent credential found. Refresh the worker list.')
    set_audit_context(request, action='worker.credential.revoke', target_type='worker_node',
        target_id=body.node_id, actor=request.state.ui_user, details={'revoked_count': revoked})
    return WorkerCredentialsRevoked(node_id=body.node_id, revoked_count=revoked)


class ScanAttemptBody(StrictBody):
    attempt: int = Field(ge=0, le=2147483647)
    job_revision: int = Field(ge=0, le=9007199254740991)


@router.get('/scans/{scan_id}/summary-export', response_model=scan_management.SummaryExport)
def export_scan_summary(scan_id: int = Path(ge=1, le=9007199254740991),
                        format: Literal['json', 'csv'] = 'json'):
    return scan_management.summary_export(scan_id, format)


@router.get('/scans/{scan_id}/export', response_model=scan_management.SummaryExport)
def export_scan_full(scan_id: int = Path(ge=1, le=9007199254740991),
                     format: Literal['json', 'csv'] = 'json'):
    return scan_management.full_export(scan_id, format)


@router.post('/scans/{scan_id}/retry', response_model=scan_management.RetryAccepted, status_code=202)
def retry_manual_scan(request: Request, body: ScanAttemptBody, scan_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='scan.retry', target_type='scan', target_id=scan_id,
                      actor=request.state.ui_user, details={'expected_attempt': body.attempt})
    return scan_management.retry(scan_id, body.attempt, body.job_revision)


@router.delete('/scans/{scan_id}', response_model=scan_management.ScanDeleted)
def delete_manual_scan(request: Request, body: ScanAttemptBody, scan_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='scan.delete', target_type='scan', target_id=scan_id,
                      actor=request.state.ui_user, details={'expected_attempt': body.attempt})
    result = scan_management.delete(scan_id, body.attempt, body.job_revision)
    set_audit_context(request, details={'expected_attempt': body.attempt, 'sample_removed': result.sample_removed})
    return result


@router.delete('/api-ledger/scans/{scan_id}', response_model=scan_management.ScanDeleted)
def delete_automation_scan(request: Request, body: ScanAttemptBody, scan_id: int = Path(ge=1, le=9007199254740991)):
    set_audit_context(request, action='scan.delete', target_type='scan', target_id=scan_id, actor=request.state.ui_user)
    result = scan_management.delete(scan_id, body.attempt, body.job_revision, automation=True)
    set_audit_context(request, details={'sample_removed': result.sample_removed})
    return result


@router.delete('/api-ledger/scans', response_model=scan_management.BulkDeleteResult)
def bulk_delete_automation_scans(request: Request, body: scan_management.BulkDeleteBody):
    result = scan_management.bulk_delete(body.scans, automation=True)
    set_audit_context(request, action='scan.bulk_delete', target_type='scan',
        actor=request.state.ui_user, details={
            'requested_count': result.requested_count,
            'deleted_count': len(result.deleted_ids),
            'blocked_count': len(result.blocked_ids),
            'cleanup_failed_count': len(result.cleanup_failed_ids),
        })
    return result

@router.delete('/scans', response_model=scan_management.BulkDeleteResult)
def bulk_delete_manual_scans(request: Request, body: scan_management.BulkDeleteBody):
    result = scan_management.bulk_delete(body.scans)
    set_audit_context(request, action='scan.bulk_delete', target_type='scan',
        actor=request.state.ui_user, details={
            'requested_count': result.requested_count,
            'deleted_count': len(result.deleted_ids),
            'blocked_count': len(result.blocked_ids),
            'cleanup_failed_count': len(result.cleanup_failed_ids),
        })
    return result


class LoginBody(StrictBody):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=4096)


class ConfigBody(StrictBody):
    config: dict[str, str]


class CreateBody(ConfigBody):
    adapter_key: str
    display_name: str = Field(min_length=1, max_length=128)


class EnabledBody(StrictBody):
    enabled: bool


class PlacementBody(StrictBody):
    pool_id: int | None


class RuleBody(StrictBody):
    filename: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=100000)


class UserPayload(BaseModel):
    id: int
    username: str
    role: str


class SessionPayload(BaseModel):
    user: UserPayload
    csrf_token: str


class HealthPayload(BaseModel):
    state: Literal["unknown", "disabled", "healthy", "failed", "unavailable", "running", "pending", "stale"]
    ok: bool
    detail: str
    checked_at: int | None


class EnginePayload(BaseModel):
    id: int
    adapter_key: str
    display_name: str
    enabled: bool
    config: dict[str, str]
    has_secret: bool
    pool_id: int | None
    health: HealthPayload


class FieldPayload(BaseModel):
    key: str
    label: str
    field_type: str
    required: bool
    default: str
    secret: bool
    help_text: str
    choices: list[str]


class AdapterPayload(BaseModel):
    key: str
    label: str
    description: str
    support_state: str
    capabilities: EngineCapabilityProfile
    fields: list[FieldPayload]


class PoolPayload(BaseModel):
    id: int
    name: str
    enabled: bool


class InventoryPayload(BaseModel):
    adapters: list[AdapterPayload]
    engines: list[EnginePayload]
    pools: list[PoolPayload]


class InstanceSaved(BaseModel):
    id: int


class InstanceEnabled(InstanceSaved):
    enabled: bool


class RulePayload(BaseModel):
    name: str
    base_name: str
    enabled: bool
    size_bytes: int
    modified_at: int


class RulesPayload(BaseModel):
    rules: list[RulePayload]


class RuleSaved(BaseModel):
    name: str


def session_payload(user, token: str):
    return {"user": {"id": user.id, "username": user.username, "role": user.role},
            "csrf_token": csrf_token(token)}


@router.get("/session", response_model=SessionPayload)
def session(request: Request):
    return session_payload(request.state.ui_user, request.cookies[auth.SESSION_COOKIE])


@router.get('/account', response_model=account.AccountPayload)
def own_account(request: Request):
    user = request.state.ui_user
    return account.AccountPayload(user_id=user.id, username=user.username[:128],
                                  role=user.role, auth_source=user.auth_source)


@router.post('/account/password', status_code=204)
def change_own_password(request: Request, body: account.PasswordChangeBody, response: Response):
    user = request.state.ui_user
    set_audit_context(request, action='user.password_change', target_type='user', target_id=user.id, actor=user)
    account.change_password(user, body.current_password.get_secret_value(),
                            body.new_password.get_secret_value(), body.confirm_password.get_secret_value())
    response.delete_cookie(auth.SESSION_COOKIE, path='/')


class LoginOptions(BaseModel):
    directory_login_enabled: bool


@router.get("/session/options", response_model=LoginOptions)
def login_options():
    # Legacy parity: the retired login page announced directory sign-in to
    # anyone, so this unauthenticated read reveals nothing new.
    return LoginOptions(directory_login_enabled=ldap_enabled())


@router.post("/session/login", response_model=SessionPayload)
def sign_in(request: Request, body: LoginBody, response: Response):
    address = request.client.host if request.client is not None else None
    # Checked before any password or directory check; the answer does not
    # depend on whether the username exists.
    wait = login_throttle.locked_for(body.username, address)
    if wait:
        raise HTTPException(429, login_throttle.message(wait), headers={"Retry-After": str(wait)})
    result = auth.login(body.username, body.password)
    if result is None:
        login_throttle.record_failure(body.username, address)
        raise HTTPException(401, "Invalid username or password.")
    login_throttle.record_success(body.username)
    set_audit_context(request, action="auth.login", actor=result.user,
                      target_type="user", target_id=result.user.id)
    response.set_cookie(auth.SESSION_COOKIE, result.session_token, httponly=True,
                        secure=auth.session_cookie_secure(request), samesite="lax", path="/",
                        max_age=auth.SESSION_TTL_SECONDS)
    return session_payload(result.user, result.session_token)


@router.post("/session/logout", status_code=204)
def sign_out(request: Request, response: Response):
    auth.logout(request.cookies.get(auth.SESSION_COOKIE))
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    set_audit_context(request, action="auth.logout", target_type="user", target_id=request.state.ui_user.id)


CHOICES = {
    "mode": ["clamd", "cli"], "execution_mode": ["powershell", "mpcmdrun"],
    "default_scan_type": ["custom", "quick", "full"], "mismatch_action": ["report", "detect"],
}


def catalog():
    result = []
    for definition in ADAPTERS.values():
        fields = [asdict(field) for field in definition.config_fields]
        if definition.key == "clamav":
            fields.insert(0, {"key": "mode", "label": "Connection mode", "field_type": "text",
                              "default": "clamd", "secret": False,
                              "help_text": "clamd: the ClamAV service over the network (normal). Command line: clamscan on the worker."})
        for field in fields:
            field["choices"] = CHOICES.get(field["key"],
                ["true", "false"] if field["field_type"] == "checkbox" else [])
            field["required"] = True
        result.append({"key": definition.key, "label": definition.label,
                       "description": definition.description, "support_state": definition.support_state,
                       "capabilities": asdict(adapter_capabilities(definition.key)), "fields": fields})
    return result


def instance_or_404(instance_id: int):
    instance = db.get_engine_instance_by_id(instance_id)
    if instance is None or instance.adapter_key not in ADAPTERS:
        raise HTTPException(404, "Engine instance not found.")
    return instance


def engine_payload(instance, worker_status, records, bindings, pools=None):
    fields = {field.key for field in ADAPTERS[instance.adapter_key].config_fields if not field.secret}
    fields.add("mode")
    config = engine_config(instance)
    health = {"state": "unknown", "ok": False, "detail": "No current connection test result.", "checked_at": None}
    if not instance.enabled:
        health.update(state="disabled", detail="Engine instance is disabled.")
    elif instance.adapter_key == "static_metadata":
        health.update(state="healthy", ok=True, detail="Built-in metadata analyzer.")
    elif instance.adapter_key == "hash_list":
        # Runs inside MASP against its own database; there is no service to check.
        health.update(state="healthy", ok=True, detail="Built-in institution hash list.")
    elif adapter_capabilities(instance.adapter_key).deployment == "worker":
        eligible = eligible_worker_node_ids_for_engine_instance(worker_status, instance, bindings=bindings, pools=pools)
        reports = [r for r in records if r.engine_instance_id == instance.id and r.node_id in eligible]
        if not eligible:
            health.update(state="unavailable", detail="No active worker matches this adapter and pool placement.")
        elif any(r.check_worker_id for r in reports):
            health.update(state="running", detail="A worker is checking the saved configuration.")
        elif any(r.last_checked_at is None for r in reports) or not reports:
            health.update(state="pending", detail="Waiting for a worker check; online does not mean healthy.")
        else:
            failures = [r for r in reports if not r.ok]
            record = max(failures or reports, key=lambda r: r.last_checked_at or 0)
            health.update(state="healthy" if record.ok else "failed", ok=record.ok,
                          detail=f"{record.node_id}: {record.detail}", checked_at=record.last_checked_at)
            if any(time.time() - (r.last_checked_at or 0) > max(300, 2 * health_interval_seconds()) for r in reports):
                health.update(state="stale", ok=False, detail="A worker health report has expired. Request a new check.")
    return {"id": instance.id, "adapter_key": instance.adapter_key, "display_name": instance.display_name,
            "enabled": instance.enabled, "config": {k: v for k, v in config.items() if k in fields},
            "has_secret": bool(config.get("api_key_encrypted")),
            "pool_id": bindings.get(instance.id), "health": health}


@router.get("/engines", response_model=InventoryPayload)
def engines():
    # Fetch inventory/health once for this response; never execute vendor probes on GET.
    status, records = get_worker_status(), db.list_engine_node_health()
    bindings = db.list_engine_instance_worker_pool_bindings()
    pools = db.list_worker_pools()
    return {"adapters": catalog(), "engines": [engine_payload(e, status, records, bindings, pools) for e in configured_engines()],
            "pools": [{"id": p.id, "name": p.name, "enabled": p.enabled} for p in pools]}


def validated_config(adapter_key, name, submitted, existing=None):
    if adapter_key not in ADAPTERS:
        raise HTTPException(404, "Unknown adapter.")
    keys = {field.key for field in ADAPTERS[adapter_key].config_fields}
    if adapter_key == "clamav":
        keys.add("mode")
    if set(submitted) - keys:
        raise ValueError("Unknown adapter configuration fields.")
    form = {f"{adapter_key}_{key}": value for key, value in submitted.items()}
    form["engine_display_name"] = name
    return engine_setup_from_form(adapter_key, form, existing_config=existing)[1]


@router.post("/engines", status_code=201, response_model=InstanceSaved)
def create_engine(request: Request, body: CreateBody):
    config = validated_config(body.adapter_key, body.display_name, body.config)
    if not adapter_capabilities(body.adapter_key).allows_multiple_instances:
        if any(e.adapter_key == body.adapter_key for e in configured_engines()):
            raise HTTPException(409, "This adapter already has an instance.")
    instance_id = add_engine(body.adapter_key, display_name=body.display_name, config=config)
    set_audit_context(request, action="engine.add", target_type="engine", target_id=instance_id)
    return {"id": instance_id}


@router.put("/engines/{instance_id}/config", response_model=InstanceSaved)
def configure_engine(instance_id: int, request: Request, body: ConfigBody):
    instance = instance_or_404(instance_id)
    config = validated_config(instance.adapter_key, instance.display_name, body.config, engine_config(instance))
    if not db.update_engine_instance_by_id(instance_id, config_json=json.dumps(config, sort_keys=True)):
        raise HTTPException(404, "Engine instance no longer exists.")
    if instance.adapter_key == "virustotal":
        clear_virustotal_cache()
    set_audit_context(request, action="engine.configure", target_type="engine", target_id=instance_id)
    return {"id": instance_id}


@router.put("/engines/{instance_id}/enabled", response_model=InstanceEnabled)
def enable_engine(instance_id: int, request: Request, body: EnabledBody):
    instance_or_404(instance_id)
    if not db.update_engine_instance_by_id(instance_id, enabled=body.enabled):
        raise HTTPException(404, "Engine instance no longer exists.")
    set_audit_context(request, action="engine.toggle", target_type="engine", target_id=instance_id,
                      details={"enabled": body.enabled})
    return {"id": instance_id, "enabled": body.enabled}


@router.delete("/engines/{instance_id}", status_code=204)
def delete_engine(instance_id: int, request: Request):
    instance = instance_or_404(instance_id)
    remove_engine(instance.adapter_key, instance_id)
    set_audit_context(request, action="engine.delete", target_type="engine", target_id=instance_id)


@router.put("/engines/{instance_id}/placement", response_model=InstanceSaved)
def placement(instance_id: int, request: Request, body: PlacementBody):
    instance_or_404(instance_id)
    db.set_engine_instance_worker_pool(instance_id, body.pool_id)
    db.request_engine_node_health_check(instance_id)
    set_audit_context(request, action="engine.placement", target_type="engine", target_id=instance_id)
    return {"id": instance_id}


@router.post("/engines/{instance_id}/checks", response_model=HealthPayload,
    responses={202: {"model": HealthPayload, "description": "Worker check requested; not a successful connection."}})
def check_engine(instance_id: int, request: Request, response: Response):
    instance = instance_or_404(instance_id)
    if not instance.enabled:
        raise HTTPException(409, "Enable the engine before requesting a check.")
    set_audit_context(request, action="engine.test", target_type="engine", target_id=instance_id)
    if adapter_capabilities(instance.adapter_key).deployment == "worker":
        db.request_engine_node_health_check(instance_id)
        response.status_code = 202
        return engine_payload(instance, get_worker_status(), db.list_engine_node_health(), db.list_engine_instance_worker_pool_bindings())["health"]
    result = test_engine_connection(instance)
    return {"state": "healthy" if result.get("ok") else "failed", "ok": bool(result.get("ok")),
            "detail": str(result.get("detail", "Check returned no detail.")), "checked_at": int(time.time())}


def require_yara(instance_id):
    if instance_or_404(instance_id).adapter_key != "yara":
        raise HTTPException(409, "This instance does not support YARA rules.")


@router.get("/engines/{instance_id}/rules", response_model=RulesPayload)
def rules(instance_id: int):
    require_yara(instance_id)
    return {"rules": list_yara_rules()}


@router.post("/engines/{instance_id}/rules", status_code=201, response_model=RuleSaved)
def upload_rule(instance_id: int, body: RuleBody, request: Request):
    require_yara(instance_id)
    saved = save_yara_rule(body.filename, body.content.encode("utf-8"))
    db.request_engine_node_health_check(instance_id)
    set_audit_context(request, action="engine.rules.save", target_type="engine", target_id=instance_id)
    return {"name": saved.name}


@router.post("/engines/{instance_id}/rules/{name}/toggle", response_model=RuleSaved)
def toggle_rule(instance_id: int, name: str, request: Request):
    require_yara(instance_id)
    result = toggle_yara_rule(name)
    db.request_engine_node_health_check(instance_id)
    set_audit_context(request, action="engine.rules.toggle", target_type="engine", target_id=instance_id)
    return {"name": result.name}


@router.delete("/engines/{instance_id}/rules/{name}", status_code=204)
def delete_rule(instance_id: int, name: str, request: Request):
    require_yara(instance_id)
    delete_yara_rule(name)
    db.request_engine_node_health_check(instance_id)
    set_audit_context(request, action="engine.rules.delete", target_type="engine", target_id=instance_id)
