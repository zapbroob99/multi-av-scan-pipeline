"""Session-authenticated browser API. No HTML or integration bearer credentials."""

from dataclasses import asdict
import hashlib
import hmac
import json
import time
from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, Path, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from app import database as db
from app.services import auth
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
from app.services import profile_admin
from app.services import credential_admin
from app.services import ledger_read
from app.services import user_admin
from app.services import account
from app.services.ingest import store_upload, configured_upload_max_bytes, UploadTooLargeError
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
            upload = self.path == PREFIX + "/scans" and request.method == "POST"
            if not login:
                user = await run_in_threadpool(browser_user, request)
                request.state.ui_user = user
                dashboard_read_allowed = request.method == "GET" and self.path in {
                    PREFIX + "/dashboard/summary", PREFIX + "/dashboard/scans",
                    PREFIX + "/api-ledger",
                    PREFIX + "/api-ledger/scans/{scan_id}",
                    PREFIX + "/api-ledger/scans/{scan_id}/children",
                    PREFIX + "/api-ledger/scans/{scan_id}/summary-export",
                    PREFIX + "/api-ledger/scans/{scan_id}/export",
                    PREFIX + "/api-ledger/scans/{scan_id}/result-json",
                    PREFIX + "/api-ledger/scans/{scan_id}/status-json",
                    PREFIX + "/api-ledger/scans/{scan_id}/results/{result_id}",
                    PREFIX + "/api-ledger/scans/{scan_id}/results/{result_id}/full",
                    PREFIX + "/api-ledger/batches/{batch_id}",
                    PREFIX + "/api-ledger/batches/{batch_id}/json",
                    PREFIX + "/scans/options",
                    PREFIX + "/scans/{scan_id}", PREFIX + "/scans/{scan_id}/results/{result_id}",
                    PREFIX + "/scans/{scan_id}/results/{result_id}/full",
                    PREFIX + "/scans/{scan_id}/children",
                    PREFIX + "/scans/{scan_id}/summary-export",
                    PREFIX + "/scans/{scan_id}/export",
                    PREFIX + "/batches/{batch_id}",
                }
                retry_allowed = request.method == 'POST' and self.path == PREFIX + '/scans/{scan_id}/retry'
                hash_allowed = (request.method == 'GET' and self.path == PREFIX + '/hash-scan/options') or (request.method == 'POST' and self.path == PREFIX + '/hash-scan')
                account_allowed = (request.method == 'GET' and self.path == PREFIX + '/account') or (request.method == 'POST' and self.path == PREFIX + '/account/password')
                if not self.path.startswith(PREFIX + "/session") and not dashboard_read_allowed and not upload and not retry_allowed and not hash_allowed and not account_allowed and user.role != "admin":
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
    risk: Literal['all', 'pending', 'info', 'metadata_only', 'low', 'medium', 'high', 'critical'] = 'all',
    client_id: int | None = Query(default=None, ge=1, le=9007199254740991), unassigned: bool = False,
):
    if client_id is not None and unassigned:
        raise HTTPException(422, 'Choose either a client ID or unassigned records.')
    return ledger_read.page(limit=limit, before=before, query=q, source=source, status=status,
                            risk=risk, client_id=client_id, unassigned=unassigned)


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
    risk: Literal["all", "pending", "info", "low", "medium", "high", "critical"] = "all",
):
    return dashboard_read.scan_page(limit=limit, before=before, query=q, status=status, risk=risk)


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
                                after: int | None = Query(default=None, ge=1, le=9007199254740991)):
    return client_admin.page(limit, after)


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
                      after: int | None = Query(default=None, ge=1, le=9007199254740991)):
    return worker_admin.pool_page(limit=limit, after=after)


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
                        after: str | None = Query(default=None, min_length=1, max_length=128)):
    return worker_admin.page(limit=limit, after=after)


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


@router.post("/session/login", response_model=SessionPayload)
def sign_in(request: Request, body: LoginBody, response: Response):
    result = auth.login(body.username, body.password)
    if result is None:
        raise HTTPException(401, "Invalid username or password.")
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
    "default_scan_type": ["custom", "quick", "full"],
}


def catalog():
    result = []
    for definition in ADAPTERS.values():
        fields = [asdict(field) for field in definition.config_fields]
        if definition.key == "clamav":
            fields.insert(0, {"key": "mode", "label": "Connection mode", "field_type": "text",
                              "default": "clamd", "secret": False, "help_text": "Choose explicitly."})
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
