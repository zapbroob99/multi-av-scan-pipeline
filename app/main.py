"""MASP application: integration API, browser API and the served console.

The server-rendered browser UI was retired in favour of the console under
/console/. Its former paths redirect there so bookmarks keep working.
"""
import logging
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, Security, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPBearer
from starlette.concurrency import run_in_threadpool

from app import APP_VERSION
from app.database import (
    find_deferred_scan_submission,
    create_deferred_scan_submission,
    get_scan,
    get_deferred_scan_submission,
    get_scan_batch,
    get_scan_queue_position,
    get_queue_metrics,
    init_db,
    list_engine_results,
    list_recent_scans,
    list_scan_batch_scans,
    refresh_scan_batch_counts,
    update_scan_assessment,
)
from app.models import (
    ACTIVE_SCAN_STATUSES,
    ApiClientIdentity,
    EngineInstanceRecord,
    EngineResultRecord,
    DeferredScanRecord,
    ScanBatchRecord,
    ScanRecord,
)
from app.services.auth import (
    api_client_identity,
    current_user,
    require_api_token,
    seed_default_users,
)
from app.services.audit import append_http_audit_event, request_id_for, should_audit_request
from app.services.decisions import ScanDecision
from app.services import api_schemas
from app.services import metrics
from app.services.engine_registry import (
    adapter_definition,
    enabled_hash_engines,
    run_hash_engine,
    seed_default_engines,
)
from app.services.ingest import UploadTooLargeError, store_upload
from app.services.deferred_storage import (
    DeferredSourceError,
    backend_allowed_for_client,
    configured_backend_keys,
    max_deferred_source_bytes,
    validate_object_id,
)
from app.services.hash_scanning import HashEngineError, HashEngineRun, build_hash_scan_payload
from app.services import scan_policy
from app.services.scan_intake import (
    DEFAULT_ARCHIVE_MODE,
    NoEligibleEnginesError,
    enqueue_scan_from_stored_sample,
    scan_is_terminal,
    wait_for_terminal_scan,
)
from app.services.scan_assessment import scan_decision
from app.services.api_payloads import (
    create_api_scan_result_payload,
    create_api_scan_status_payload,
    public_scan_report_payload,
)
from app.services.reports import build_scan_report_payload as build_shared_scan_report_payload
from app.services.scoring import calculate_risk
from app.services.worker_control import router as worker_control_router
from app.services.virustotal import InvalidSha256Error, normalize_sha256
from app.services.service_clients import (
    engines_for_scan,
    identity_can_access_batch,
    identity_can_access_scan,
    profile_snapshot_json,
    resolve_profile_routing,
    seed_legacy_service_client,
)
from app.services.upload_admission import UploadAdmissionRoute
from app.services.ui_api import router as ui_router
from app.services.console_static import router as console_router


app = FastAPI(
    title="MASP",
    description=(
        "Multi AV Scan Pipeline: self-hosted orchestration layer for file scanning engines, "
        "normalization, risk scoring, and analyst reports."
    ),
    version=APP_VERSION,
)
logger = logging.getLogger(__name__)
app.router.route_class = UploadAdmissionRoute

SUPPORTED_ARCHIVE_MODES = {"container", "lazy_extract_on_detection"}

init_db()
seed_default_users()
seed_default_engines()
seed_legacy_service_client()

app.include_router(worker_control_router)
app.include_router(ui_router)
app.include_router(console_router)


@app.middleware("http")
async def audit_http_requests(request: Request, call_next):
    request.state.audit_request_id = request_id_for(request)
    audited = should_audit_request(request)
    session_user = None
    if audited:
        try:
            # Snapshot before the handler so logout remains attributable after
            # its session row has been revoked.
            session_user = await run_in_threadpool(current_user, request)
        except Exception:
            logger.exception("Unable to resolve audit actor")

    try:
        response = await call_next(request)
    except Exception as exc:
        if audited:
            try:
                await run_in_threadpool(
                    append_http_audit_event,
                    request,
                    status_code=500,
                    session_user=session_user,
                    error_type=type(exc).__name__,
                )
            except Exception:
                logger.exception("Unable to append failed-request audit event")
        raise

    response.headers["X-Request-ID"] = request.state.audit_request_id
    if request.url.path.startswith("/api/ui/v1/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
    if audited:
        try:
            await run_in_threadpool(
                append_http_audit_event,
                request,
                status_code=response.status_code,
                session_user=session_user,
            )
        except Exception:
            # Phase-one audit is best effort and must not make an otherwise
            # successful operation appear to have failed.
            logger.exception("Unable to append HTTP audit event")
    return response


def configured_api_max_wait_seconds() -> int:
    return scan_policy.resolve_int("api_max_wait_seconds")


def configured_api_retry_after_seconds() -> int:
    return scan_policy.resolve_int("api_retry_after_seconds")


def normalized_api_wait_seconds(requested_wait_seconds: int) -> int:
    return max(0, min(requested_wait_seconds, configured_api_max_wait_seconds()))


def normalized_archive_mode(requested_archive_mode: str) -> str:
    archive_mode = requested_archive_mode.strip().lower() or DEFAULT_ARCHIVE_MODE
    aliases = {
        "lazy": "lazy_extract_on_detection",
        "lazy_extract": "lazy_extract_on_detection",
    }
    archive_mode = aliases.get(archive_mode, archive_mode)
    if archive_mode not in SUPPORTED_ARCHIVE_MODES:
        supported = ", ".join(sorted(SUPPORTED_ARCHIVE_MODES))
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported archive_mode '{requested_archive_mode}'. Supported values: {supported}.",
        )
    return archive_mode


# Documentation-only security scheme: surfaces the bearer requirement in the
# OpenAPI schema. Enforcement stays in require_api_token (auto_error=False, so
# this dependency never rejects a request itself).
API_BEARER_SCHEME = HTTPBearer(
    auto_error=False,
    scheme_name="bearerAuth",
    description="Static API token issued by the MASP operator.",
)


API_ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    401: {
        "model": api_schemas.ApiErrorResponse,
        "description": "Missing or invalid bearer token.",
    },
    503: {
        "model": api_schemas.ApiErrorResponse,
        "description": "API token authentication is not configured on the server.",
    },
}


# Public API links are the vendor-facing security boundary: only the
# machine-readable status/result URLs are exposed. The operator-UI ("ui") link
# is intentionally omitted so the public payload never leaks an internal
# console URL. Operator previews under /api-ledger render this same sanitized
# payload; full internal detail lives on the /scans/{id} detail page and the
# JSON/CSV exports, which use build_scan_report_payload (unchanged).
def api_scan_links(request: Request, scan_id: int) -> dict[str, str]:
    return {
        "status": str(request.url_for("api_scan_status", scan_id=scan_id)),
        "result": str(request.url_for("api_scan_result", scan_id=scan_id)),
    }


def api_batch_links(request: Request, batch_id: int) -> dict[str, str]:
    return {
        "status": str(request.url_for("api_batch_status", batch_id=batch_id)),
        "result": str(request.url_for("api_batch_result", batch_id=batch_id)),
    }


def build_scan_summary_payload(scan: ScanRecord) -> dict[str, object]:
    from app.services.api_payloads import build_scan_summary_payload as public_summary
    return public_summary(scan)


def scan_batch_is_terminal(batch: ScanBatchRecord) -> bool:
    return batch.status == "completed"


def build_scan_batch_summary_payload(
    request: Request, batch: ScanBatchRecord, scans: list[ScanRecord],
) -> dict[str, object]:
    from app.services.api_payloads import build_batch_summary_payload
    return build_batch_summary_payload(batch, scans, api_batch_links(request, batch.id))


def build_scan_batch_status_payload(
    request: Request,
    batch: ScanBatchRecord,
    scans: list[ScanRecord],
) -> dict[str, object]:
    return {
        "completed": scan_batch_is_terminal(batch),
        "result_ready": scan_batch_is_terminal(batch),
        "batch": build_scan_batch_summary_payload(request, batch, scans),
        "scans": [
            {
                **build_scan_summary_payload(scan),
                "result_ready": scan_is_terminal(scan),
                "links": api_scan_links(request, scan.id),
            }
            for scan in scans
        ],
        "links": api_batch_links(request, batch.id),
    }


def build_scan_batch_result_payload(
    request: Request,
    batch: ScanBatchRecord,
    scans: list[ScanRecord],
) -> dict[str, object]:
    return {
        "completed": scan_batch_is_terminal(batch),
        "result_ready": scan_batch_is_terminal(batch),
        "batch": build_scan_batch_summary_payload(request, batch, scans),
        "scans": [
            {
                "id": scan.id,
                "role": scan.scan_role,
                "parent_scan_id": scan.parent_scan_id,
                "relative_path": scan.relative_path,
                # Vendor-safe projection of the full report (drops raw_output,
                # engine details, path-bearing evidence, internal fields).
                "result": public_scan_report_payload(
                    build_scan_report_payload(scan, list_engine_results(scan.id)),
                    build_scan_summary_payload(scan),
                ),
                "links": api_scan_links(request, scan.id),
            }
            for scan in scans
        ],
        "links": api_batch_links(request, batch.id),
    }


def scan_decision_payload(decision: ScanDecision) -> dict[str, object]:
    return {
        "action": decision.action,
        "label": decision.label,
        "tone": decision.tone,
        "confidence": decision.confidence,
        "policy": decision.policy,
        "reason": decision.reason,
        "reasons": decision.reasons,
    }


def build_api_scan_status_payload(
    request: Request,
    scan: ScanRecord,
    engine_results: list[EngineResultRecord] | None = None,
) -> dict[str, object]:
    results = engine_results if engine_results is not None else list_engine_results(scan.id)
    queue_metrics = get_queue_metrics()
    queue_position = get_scan_queue_position(scan.id)
    result_ready = scan_is_terminal(scan)
    decision = scan_decision(scan, results)
    payload = create_api_scan_status_payload(
        result_ready=result_ready,
        recommended_poll_seconds=None if result_ready else configured_api_retry_after_seconds(),
        decision_payload=scan_decision_payload(decision),
        scan_payload=build_scan_summary_payload(scan),
        queue_metrics=queue_metrics,
        queue_position=queue_position,
        expected_engines=len(engines_for_scan(scan)),
        results=results,
        links=api_scan_links(request, scan.id),
    )
    if scan.batch_id is not None:
        payload["batch_links"] = api_batch_links(request, scan.batch_id)
    return payload


def build_api_scan_result_payload(
    request: Request,
    scan: ScanRecord,
    engine_results: list[EngineResultRecord] | None = None,
) -> dict[str, object]:
    results = engine_results if engine_results is not None else list_engine_results(scan.id)
    report_payload = build_scan_report_payload(scan, results)
    result_ready = scan_is_terminal(scan)
    payload = create_api_scan_result_payload(
        report_payload=report_payload,
        scan_payload=build_scan_summary_payload(scan),
        completed=result_ready,
        result_ready=result_ready,
        decision_payload=report_payload["summary"]["decision"],
        links=api_scan_links(request, scan.id),
    )
    if scan.batch_id is not None:
        payload["batch_links"] = api_batch_links(request, scan.batch_id)
    return payload


def deferred_scan_payload(
    request: Request, record: DeferredScanRecord, *, duplicate: bool = False
) -> dict[str, object]:
    links = {
        "status": str(
            request.url_for("api_deferred_scan_status", submission_id=record.id)
        )
    }
    if record.scan_job_id is not None:
        links.update(api_scan_links(request, record.scan_job_id))
    if record.status == "pending":
        detail = "Deferred object accepted; MASP will fetch and scan it independently."
    elif record.status == "claimed":
        detail = "Deferred object is being fetched and verified by MASP."
    elif record.status == "queued":
        detail = "Deferred object was fetched and queued for engine scanning."
    elif record.status == "failed":
        detail = "Deferred object intake failed before a scan could be queued."
    elif record.status == "completed":
        detail = "Deferred scan completed."
    else:
        detail = "Deferred submission status loaded."
    return {
        "accepted": True,
        "duplicate": duplicate,
        "submission_id": record.id,
        "client_request_id": record.client_request_id,
        "status": record.status,
        "scan_id": record.scan_job_id,
        "detail": detail,
        "attempts": record.attempt_count,
        "available_at": record.available_at,
        "last_error": record.last_error if record.status == "failed" else None,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "links": links,
    }


async def enqueue_scan_from_upload(
    sample: UploadFile,
    *,
    case_name: str,
    priority: str,
    note: str,
    source: str,
    archive_mode: str = DEFAULT_ARCHIVE_MODE,
    api_identity: ApiClientIdentity | None = None,
    requested_profile_id: int | None = None,
) -> ScanRecord:
    if not sample.filename:
        raise HTTPException(status_code=400, detail="A file must be selected.")

    effective_archive_mode = normalized_archive_mode(archive_mode)
    selected_engines = None
    service_client_id = None
    scan_profile_id = None
    snapshot = '{}'
    if api_identity is not None:
        try:
            api_identity, selected_engines = await run_in_threadpool(resolve_profile_routing,
                api_identity, requested_profile_id, source=source)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc
        service_client_id = api_identity.client.id
        scan_profile_id = api_identity.profile.id
        snapshot = await run_in_threadpool(profile_snapshot_json, api_identity, selected_engines)
    try:
        stored_sample = await store_upload(sample)
    except UploadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc

    try:
        return await run_in_threadpool(enqueue_scan_from_stored_sample,
            stored_sample,
            case_name=case_name,
            priority=priority,
            note=note,
            source=source,
            archive_mode=effective_archive_mode,
            engines=selected_engines,
            service_client_id=service_client_id,
            scan_profile_id=scan_profile_id,
            profile_snapshot_json=snapshot,
        )
    except NoEligibleEnginesError as exc:
        raise HTTPException(
            status_code=503,
            detail="No eligible scan engines are available for this submission source.",
        ) from exc


def build_scan_report_payload(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
) -> dict[str, object]:
    return build_shared_scan_report_payload(scan, engine_results)


def backfill_missing_assessments(limit: int = 250) -> None:
    for scan in list_recent_scans(limit=limit):
        if scan.risk_score is not None:
            continue
        if scan.status in ACTIVE_SCAN_STATUSES:
            continue

        engine_results = list_engine_results(scan.id)
        assessment = calculate_risk(engine_results)
        update_scan_assessment(scan.id, assessment.verdict, assessment.score)


backfill_missing_assessments()


@app.get(
    "/health",
    summary="Service liveness probe",
    responses={200: {"model": api_schemas.HealthResponse, "description": "Service is up."}},
)
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get(
    "/metrics",
    summary="Prometheus metrics",
    description=(
        "Queue depth and latency, worker liveness, and per-engine result counts in "
        "the Prometheus text exposition format. Requires the API bearer token; "
        "Prometheus sends it with the scrape config's bearer_token option."
    ),
    dependencies=[Security(API_BEARER_SCHEME)],
    responses={
        200: {"description": "Metrics in Prometheus text exposition format."},
        404: {"description": "Metrics are disabled (MASP_METRICS_ENABLED=0)."},
        **API_ERROR_RESPONSES,
    },
)
def metrics_endpoint(request: Request) -> Response:
    # Authenticated, unlike /health: the payload reports scan volumes and
    # detection counts, which is operational detail about the institution's
    # traffic rather than a liveness signal.
    if not metrics.metrics_enabled():
        raise HTTPException(status_code=404, detail="Metrics are disabled.")
    require_api_token(request)
    return Response(
        content=metrics.render_metrics(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


def execute_hash_scan(
    sha256: str,
    engines: list[EngineInstanceRecord],
) -> list[HashEngineRun]:
    return [
        HashEngineRun(
            engine=engine,
            support_state=adapter_definition(engine.adapter_key).support_state,
            execution=run_hash_engine(engine, sha256),
        )
        for engine in engines
    ]


@app.post(
    "/api/v1/scans",
    summary="Submit a file scan",
    description="Accepts a sample upload, creates a scan job, and optionally waits for completion. Optional profile_id selects an enabled profile owned by the authenticated client; omission uses its default.",
    dependencies=[Security(API_BEARER_SCHEME)],
    responses={
        200: {
            "model": api_schemas.ScanSubmitCompletedResponse,
            "description": "Scan reached a terminal state within the wait window; embeds the final result.",
        },
        202: {
            "model": api_schemas.ScanSubmitAcceptedResponse,
            "description": "Scan accepted and still processing. Poll the Location URL; Retry-After is set.",
        },
        400: {
            "model": api_schemas.ApiErrorResponse,
            "description": "No file supplied, or an unsupported archive_mode value.",
        },
        413: {
            "model": api_schemas.ApiErrorResponse,
            "description": "Upload exceeds the configured size limit.",
        },
        404: {"model": api_schemas.ApiErrorResponse, "description": "Selected scan profile is unavailable for this client."},
        **API_ERROR_RESPONSES,
    },
)
async def api_create_scan(
    request: Request,
    profile_id: Annotated[int | None, Form(ge=1, le=2147483647, description="Own enabled scan profile ID. Omit to use the client's default.")] = None,
    sample: UploadFile = File(...),
    case_name: str = Form("Unassigned"),
    priority: str = Form("Normal"),
    note: str = Form(""),
    archive_mode: str = Form(DEFAULT_ARCHIVE_MODE),
    wait_seconds: int = Form(0),
) -> JSONResponse:
    await run_in_threadpool(require_api_token, request)
    identity = api_client_identity(request)
    scan = await enqueue_scan_from_upload(
        sample,
        case_name=case_name,
        priority=priority,
        note=note,
        source="api",
        archive_mode=archive_mode,
        api_identity=identity,
        requested_profile_id=profile_id,
    )
    applied_wait_seconds = await run_in_threadpool(normalized_api_wait_seconds, wait_seconds)
    current_scan = await wait_for_terminal_scan(scan.id, applied_wait_seconds)
    if current_scan is None:
        raise HTTPException(status_code=500, detail="Scan could not be loaded.")

    headers = {"Location": str(request.url_for("api_scan_status", scan_id=scan.id))}
    status_payload = await run_in_threadpool(build_api_scan_status_payload, request, current_scan)
    status_payload["accepted"] = True
    status_payload["wait_seconds_applied"] = applied_wait_seconds

    if scan_is_terminal(current_scan):
        status_payload["detail"] = "Scan completed within the requested wait window."
        status_payload["result"] = await run_in_threadpool(build_api_scan_result_payload, request, current_scan)
        return JSONResponse(status_payload, status_code=200, headers=headers)

    headers["Retry-After"] = str(await run_in_threadpool(configured_api_retry_after_seconds))
    status_payload["detail"] = "Scan accepted and still processing."
    return JSONResponse(status_payload, status_code=202, headers=headers)


@app.post(
    "/api/v1/deferred-scans",
    name="api_create_deferred_scan",
    summary="Submit a deferred object scan",
    description=(
        "Durably accepts a reference to an object in a deployment-approved storage "
        "backend. A separate intake worker fetches the object later; the caller never "
        "waits for file transfer or antivirus execution."
    ),
    dependencies=[Security(API_BEARER_SCHEME)],
    responses={
        202: {"model": api_schemas.DeferredScanSubmitResponse},
        400: {"model": api_schemas.ApiErrorResponse},
        404: {"model": api_schemas.ApiErrorResponse, "description": "Selected scan profile is unavailable for this client."},
        409: {"model": api_schemas.ApiErrorResponse},
        **API_ERROR_RESPONSES,
    },
)
def api_create_deferred_scan(
    request: Request, body: api_schemas.DeferredScanSubmitRequest
) -> JSONResponse:
    require_api_token(request)
    identity = api_client_identity(request)
    client_request_id = body.client_request_id.strip()
    backend_key = body.backend_key.strip().lower()
    try:
        object_id = validate_object_id(body.object_id)
    except DeferredSourceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    expected_sha256 = None
    if body.expected_sha256:
        try:
            expected_sha256 = normalize_sha256(body.expected_sha256)
        except InvalidSha256Error as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    archive_mode = normalized_archive_mode(body.archive_mode)
    # Answer a retry from the accepted record before touching live routing. The
    # work already runs against a frozen snapshot, so re-resolving the profile
    # here only made a byte-identical retry fail once an operator edited
    # configuration, and a removed profile made it unanswerable at all. What the
    # client asserted is still compared, so a genuinely different request for the
    # same id remains a conflict.
    existing = find_deferred_scan_submission(identity.client.id, client_request_id)
    if existing is not None:
        asserted = (existing.backend_key, existing.object_id, existing.expected_size_bytes,
                    existing.expected_sha256, existing.archive_mode, existing.requested_profile_id)
        if asserted != (backend_key, object_id, body.expected_size_bytes,
                        expected_sha256, archive_mode, body.profile_id):
            raise HTTPException(
                status_code=409,
                detail="client_request_id already exists with a different deferred payload.",
            )
        return JSONResponse(
            deferred_scan_payload(request, existing, duplicate=True),
            status_code=202,
            headers={"Location": str(request.url_for("api_deferred_scan_status", submission_id=existing.id))},
        )
    try:
        available_backends = configured_backend_keys()
    except DeferredSourceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if backend_key not in available_backends:
        raise HTTPException(
            status_code=400,
            detail=f"Deferred storage backend {backend_key!r} is not configured.",
        )
    try:
        backend_allowed = backend_allowed_for_client(
            backend_key, identity.client.client_key, object_id
        )
    except DeferredSourceError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not backend_allowed:
        raise HTTPException(
            status_code=403,
            detail="This service client is not allowed to use that storage backend.",
        )
    try:
        max_bytes = max_deferred_source_bytes()
    except DeferredSourceError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if (
        max_bytes
        and body.expected_size_bytes is not None
        and body.expected_size_bytes > max_bytes
    ):
        raise HTTPException(
            status_code=413,
            detail="Deferred object exceeds MASP_DEFERRED_MAX_BYTES.",
        )
    try:
        identity, engines = resolve_profile_routing(identity, body.profile_id, source='api')
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    if not engines:
        raise HTTPException(
            status_code=503,
            detail="No eligible engines are assigned to this client's deferred scan profile.",
        )
    snapshot = profile_snapshot_json(
        identity,
        engines,
        delivery_mode="security_events_only",
        client_request_id=client_request_id,
    )
    try:
        record, created = create_deferred_scan_submission(
            service_client_id=identity.client.id,
            scan_profile_id=identity.profile.id,
            requested_profile_id=body.profile_id,
            client_request_id=client_request_id,
            backend_key=backend_key,
            object_id=object_id,
            original_filename=body.original_filename.strip(),
            content_type=body.content_type.strip() or "application/octet-stream",
            expected_size_bytes=body.expected_size_bytes,
            expected_sha256=expected_sha256,
            archive_mode=archive_mode,
            case_name=body.case_name.strip() or "Unassigned",
            priority=body.priority.strip() or "Normal",
            note=body.note.strip(),
            profile_snapshot_json=snapshot,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    payload = deferred_scan_payload(request, record, duplicate=not created)
    headers = {
        "Location": str(
            request.url_for("api_deferred_scan_status", submission_id=record.id)
        )
    }
    return JSONResponse(payload, status_code=202, headers=headers)


@app.get(
    "/api/v1/deferred-scans/{submission_id}",
    name="api_deferred_scan_status",
    summary="Fetch deferred scan status",
    dependencies=[Security(API_BEARER_SCHEME)],
    responses={
        200: {"model": api_schemas.DeferredScanSubmitResponse},
        404: {"model": api_schemas.ApiErrorResponse},
        **API_ERROR_RESPONSES,
    },
)
def api_deferred_scan_status(request: Request, submission_id: int) -> JSONResponse:
    require_api_token(request)
    identity = api_client_identity(request)
    record = get_deferred_scan_submission(submission_id)
    if record is None or record.service_client_id != identity.client.id:
        raise HTTPException(status_code=404, detail="Deferred scan not found.")
    return JSONResponse(deferred_scan_payload(request, record))


@app.get(
    "/api/v1/scans/{scan_id}",
    name="api_scan_status",
    summary="Fetch scan status",
    description="Returns queue state, engine progress, and links for a previously submitted scan.",
    dependencies=[Security(API_BEARER_SCHEME)],
    responses={
        200: {
            "model": api_schemas.ScanStatusResponse,
            "description": "Current scan status; result_ready indicates whether the result endpoint is available.",
        },
        404: {"model": api_schemas.ApiErrorResponse, "description": "Scan not found."},
        **API_ERROR_RESPONSES,
    },
)
def api_scan_status(request: Request, scan_id: int) -> JSONResponse:
    require_api_token(request)
    identity = api_client_identity(request)
    scan = get_scan(scan_id)
    # The public API only exposes scans submitted through the API. ICAP/manual
    # scans are hidden (404, not 403) so an API token cannot enumerate or read
    # them. Matches the source guard on the batch endpoints.
    if scan is None or not identity_can_access_scan(identity, scan):
        raise HTTPException(status_code=404, detail="Scan not found.")
    return JSONResponse(build_api_scan_status_payload(request, scan))


@app.get(
    "/api/v1/scans/{scan_id}/result",
    name="api_scan_result",
    summary="Fetch final scan result",
    description="Returns the normalized result payload after a scan reaches a terminal state.",
    dependencies=[Security(API_BEARER_SCHEME)],
    responses={
        200: {
            "model": api_schemas.ScanResultResponse,
            "description": "Normalized final result for a terminal scan.",
        },
        409: {
            "model": api_schemas.ScanResultNotReadyResponse,
            "description": "Scan is not terminal yet; body carries current status and Retry-After is set.",
        },
        404: {"model": api_schemas.ApiErrorResponse, "description": "Scan not found."},
        **API_ERROR_RESPONSES,
    },
)
def api_scan_result(request: Request, scan_id: int) -> JSONResponse:
    require_api_token(request)
    identity = api_client_identity(request)
    scan = get_scan(scan_id)
    # Public API exposes API-sourced scans only; ICAP/manual scans return 404.
    if scan is None or not identity_can_access_scan(identity, scan):
        raise HTTPException(status_code=404, detail="Scan not found.")
    if not scan_is_terminal(scan):
        payload = build_api_scan_status_payload(request, scan)
        payload["detail"] = "Scan result is not ready yet."
        return JSONResponse(
            payload,
            status_code=409,
            headers={"Retry-After": str(configured_api_retry_after_seconds())},
        )
    return JSONResponse(build_api_scan_result_payload(request, scan))


@app.get(
    "/api/v1/batches/{batch_id}",
    name="api_batch_status",
    summary="Fetch batch status",
    description="Returns batch-level queue state and per-scan status for an archive-backed API submission.",
    dependencies=[Security(API_BEARER_SCHEME)],
    responses={
        200: {
            "model": api_schemas.BatchStatusResponse,
            "description": "Current batch status with per-scan summaries.",
        },
        404: {"model": api_schemas.ApiErrorResponse, "description": "Batch not found."},
        **API_ERROR_RESPONSES,
    },
)
def api_batch_status(request: Request, batch_id: int) -> JSONResponse:
    require_api_token(request)
    identity = api_client_identity(request)
    refresh_scan_batch_counts(batch_id)
    batch = get_scan_batch(batch_id)
    if batch is None or not identity_can_access_batch(identity, batch):
        raise HTTPException(status_code=404, detail="Batch not found.")
    scans = list_scan_batch_scans(batch_id, limit=5000)
    return JSONResponse(build_scan_batch_status_payload(request, batch, scans))


@app.get(
    "/api/v1/batches/{batch_id}/result",
    name="api_batch_result",
    summary="Fetch final batch result",
    description="Returns per-scan normalized results for a completed archive-backed API submission.",
    dependencies=[Security(API_BEARER_SCHEME)],
    responses={
        200: {
            "model": api_schemas.BatchResultResponse,
            "description": "Per-scan normalized results for a terminal batch.",
        },
        409: {
            "model": api_schemas.BatchResultNotReadyResponse,
            "description": "Batch is not terminal yet; body carries current status and Retry-After is set.",
        },
        404: {"model": api_schemas.ApiErrorResponse, "description": "Batch not found."},
        **API_ERROR_RESPONSES,
    },
)
def api_batch_result(request: Request, batch_id: int) -> JSONResponse:
    require_api_token(request)
    identity = api_client_identity(request)
    refresh_scan_batch_counts(batch_id)
    batch = get_scan_batch(batch_id)
    if batch is None or not identity_can_access_batch(identity, batch):
        raise HTTPException(status_code=404, detail="Batch not found.")
    scans = list_scan_batch_scans(batch_id, limit=5000)
    if not scan_batch_is_terminal(batch):
        payload = build_scan_batch_status_payload(request, batch, scans)
        payload["detail"] = "Batch result is not ready yet."
        return JSONResponse(
            payload,
            status_code=409,
            headers={"Retry-After": str(configured_api_retry_after_seconds())},
        )
    return JSONResponse(build_scan_batch_result_payload(request, batch, scans))


@app.get(
    "/api/v1/hashes/{sha256}",
    name="api_hash_lookup",
    summary="Look up SHA-256 reputation",
    description=(
        "Sends only the supplied SHA-256 digest to enabled non-metered hash-capable "
        "engines and returns normalized per-engine results. MASP never uploads file "
        "content or invokes quota-consuming engines from this API endpoint."
        " Optional profile_id selects an enabled profile owned by the authenticated client; omission uses its default."
    ),
    dependencies=[Security(API_BEARER_SCHEME)],
    responses={
        200: {
            "model": api_schemas.HashScanResponse,
            "description": "Aggregated decision and normalized per-engine reputation results.",
        },
        400: {
            "model": api_schemas.ApiErrorResponse,
            "description": "The path value is not a valid SHA-256 digest.",
        },
        502: {
            "model": api_schemas.ApiErrorResponse,
            "description": "An enabled hash engine was unreachable or returned an invalid response.",
        },
        404: {"model": api_schemas.ApiErrorResponse, "description": "Selected scan profile is unavailable for this client."},
        **API_ERROR_RESPONSES,
        503: {
            "model": api_schemas.ApiErrorResponse,
            "description": (
                "API authentication is not configured, no eligible non-metered hash "
                "engine is enabled, or an eligible upstream engine is unavailable."
            ),
        },
    },
)
def api_hash_lookup(request: Request, sha256: str,
                    profile_id: Annotated[int | None, Query(ge=1, le=2147483647)] = None) -> JSONResponse:
    require_api_token(request)
    identity = api_client_identity(request)
    try:
        normalized_sha256 = normalize_sha256(sha256)
    except InvalidSha256Error as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if identity.legacy_credential and profile_id is None:
        engines = enabled_hash_engines(source='api')
    else:
        try:
            identity, engines = resolve_profile_routing(identity, profile_id, source='api', hash_lookup=True)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc
    if not engines:
        raise HTTPException(
            status_code=503,
            detail="No non-metered hash-capable engine is available for API use.",
        )
    try:
        runs = execute_hash_scan(normalized_sha256, engines)
    except HashEngineError as exc:
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
        raise HTTPException(
            status_code=exc.status_code,
            detail=str(exc),
            headers=headers,
        ) from exc
    payload = build_hash_scan_payload(normalized_sha256, runs)
    print(
        f"[hash-scan] {normalized_sha256[:12]}...: "
        f"{payload['decision']['action']} ({len(runs)} engine(s))",
        flush=True,
    )
    return JSONResponse(payload)


# Former server-rendered pages. The HTML UI is retired; each GET path it served
# redirects to the console screen that replaced it so bookmarks and old links
# keep working. Legacy form POSTs are gone and answer 404/405.
LEGACY_REDIRECTS = {
    "/": "/console/dashboard",
    "/login": "/console/",
    "/scans/new": "/console/scans/new",
    "/api-ledger": "/console/api-ledger",
    "/system": "/console/system/overview",
    "/engines": "/console/engines",
    "/users": "/console/users",
    "/service-clients": "/console/service-clients",
    "/audit": "/console/audit",
    "/account": "/console/account",
    "/about": "/console/about",
    "/hash-scan": "/console/hash-scan",
    "/scan-policy": "/console/scan-policy",
}


def _legacy_redirect(target: str):
    def redirect() -> RedirectResponse:
        return RedirectResponse(target, status_code=301)
    return redirect


for _path, _target in LEGACY_REDIRECTS.items():
    app.add_api_route(_path, _legacy_redirect(_target), methods=["GET"], include_in_schema=False)


@app.get("/scans/{scan_id}", include_in_schema=False)
@app.get("/scans/{scan_id}/report", include_in_schema=False)
@app.get("/scans/{scan_id}/export.json", include_in_schema=False)
@app.get("/scans/{scan_id}/export.csv", include_in_schema=False)
def legacy_scan_redirect(request: Request, scan_id: int) -> RedirectResponse:
    # Legacy report paths served every source; the console keeps manual and
    # automation reports apart. Only a signed-in operator learns which one a
    # scan is, so an anonymous request cannot probe scan sources by ID.
    suffix = request.url.path.rsplit("/", 1)[-1]
    page = {"report": "/print", "export.json": "/manage", "export.csv": "/manage"}.get(suffix, "")
    base = "/console/scans"
    if current_user(request) is not None:
        scan = get_scan(scan_id)
        if scan is not None and scan.source != "manual":
            base = "/console/api-ledger/scans"
    return RedirectResponse(f"{base}/{scan_id}{page}", status_code=302)


@app.get("/batches/{batch_id}", include_in_schema=False)
def legacy_batch_redirect(batch_id: int) -> RedirectResponse:
    return RedirectResponse(f"/console/batches/{batch_id}", status_code=301)


@app.get("/api-ledger/scans/{scan_id}/{kind}", include_in_schema=False)
@app.get("/api-ledger/batches/{batch_id}/{kind}", include_in_schema=False)
def legacy_ledger_json_redirect(request: Request, kind: str, scan_id: int | None = None,
                                batch_id: int | None = None) -> RedirectResponse:
    if kind not in {"status", "result"}:
        raise HTTPException(404)
    resource = f"scans/{scan_id}" if scan_id is not None else f"batches/{batch_id}"
    return RedirectResponse(f"/console/api-ledger/{resource}/{kind}-json", status_code=301)


@app.get("/api-ledger/batches/{batch_id}", include_in_schema=False)
def legacy_ledger_batch_redirect(batch_id: int) -> RedirectResponse:
    return RedirectResponse(f"/console/api-ledger/batches/{batch_id}", status_code=301)
