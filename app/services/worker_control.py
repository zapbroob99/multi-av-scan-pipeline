from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from fastapi import APIRouter, HTTPException, Request, Response, Security
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from app.database import (
    authenticate_worker_agent_credential,
    claim_due_engine_node_health,
    claim_next_scan_engine_job,
    commit_engine_job_result_if_owned,
    commit_engine_node_health_if_owned,
    create_worker_agent_credential,
    ensure_engine_node_health_rows,
    get_engine_instance_by_id,
    get_scan,
    get_scan_engine_job,
    get_worker_node,
    mark_scan_engine_job_running,
    mark_scan_running,
    record_engine_node_scan_success,
    renew_scan_engine_job_lease,
    upsert_worker_node_heartbeat,
)
from app.models import EngineResultInput, WorkerAgentCredentialRecord
from app.services.audit import set_audit_context
from app.services.auth import bearer_token_from_request
from app.services.engine_registry import adapter_definition, enabled_engines, runtime_config
from app.services.worker_scheduling import eligible_engine_instance_ids_for_node
from app.services.sample_paths import resolve_sample_path


WORKER_BEARER_SCHEME = HTTPBearer(
    scheme_name="WorkerAgentBearer",
    description=(
        "Enrollment bootstrap token for /enroll; node-bound agent token for all "
        "other worker-control operations."
    ),
)
router = APIRouter(
    prefix="/api/v1/worker-control",
    tags=["worker control"],
    dependencies=[Security(WORKER_BEARER_SCHEME)],
)


class ControlModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkerIdentityPayload(ControlModel):
    node_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    display_name: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=64)
    agent_version: str = Field(min_length=1, max_length=64)
    labels: dict[str, str] = Field(default_factory=dict)
    capacity: int = Field(default=1, ge=1, le=1024)
    engine_keys: list[str] = Field(default_factory=list, max_length=64)
    process_id: int = Field(default=0, ge=0)


class WorkerHeartbeatPayload(WorkerIdentityPayload):
    runtime_state: str = Field(default="idle", min_length=1, max_length=64)
    active_scan_id: int | None = Field(default=None, ge=1)


class WorkerProcessPayload(ControlModel):
    process_id: int = Field(ge=1)
    lease_seconds: int = Field(default=120, ge=30, le=3600)


class WorkerLeasePayload(WorkerProcessPayload):
    attempt_generation: int = Field(ge=1)


class WorkerEngineResultPayload(WorkerLeasePayload):
    status: str = Field(min_length=1, max_length=64)
    detected: bool
    severity: str = Field(min_length=1, max_length=32)
    confidence: int = Field(ge=0, le=100)
    signature: str | None = Field(default=None, max_length=4096)
    raw_output: str = Field(default="", max_length=1_000_000)
    duration_ms: int = Field(ge=0, le=86_400_000)
    error_message: str | None = Field(default=None, max_length=16_384)
    engine_version: str | None = Field(default=None, max_length=512)
    signature_version: str | None = Field(default=None, max_length=2048)
    details: dict[str, object] = Field(default_factory=dict)
    findings: list[dict[str, object]] = Field(default_factory=list, max_length=10_000)


class WorkerHealthClaimPayload(WorkerProcessPayload):
    interval_seconds: int = Field(default=60, ge=15, le=86_400)


class WorkerHealthResultPayload(ControlModel):
    process_id: int = Field(ge=1)
    check_generation: int = Field(ge=1)
    ok: bool
    health_status: str = Field(min_length=1, max_length=128)
    detail: str = Field(default="", max_length=16_384)
    product_version: str | None = Field(default=None, max_length=512)
    engine_version: str | None = Field(default=None, max_length=512)
    signature_version: str | None = Field(default=None, max_length=2048)
    service_state: str | None = Field(default=None, max_length=128)
    storage_readable: bool | None = None
    storage_writable: bool | None = None
    details: dict[str, object] = Field(default_factory=dict)


def _flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _require_secure_transport(request: Request) -> None:
    if _flag("MASP_WORKER_CONTROL_REQUIRE_HTTPS") and request.url.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="Worker control requires HTTPS.",
        )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _require_enrollment_token(request: Request) -> None:
    configured = os.getenv("MASP_WORKER_ENROLLMENT_TOKEN", "").strip()
    if not configured:
        raise HTTPException(
            status_code=503,
            detail="Worker enrollment is not configured.",
        )
    provided = bearer_token_from_request(request)
    if provided is None or not hmac.compare_digest(provided, configured):
        raise HTTPException(
            status_code=401,
            detail="Valid worker enrollment token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_worker_agent(request: Request) -> WorkerAgentCredentialRecord:
    _require_secure_transport(request)
    provided = bearer_token_from_request(request)
    credential = (
        None
        if provided is None
        else authenticate_worker_agent_credential(_token_hash(provided))
    )
    if credential is None:
        raise HTTPException(
            status_code=401,
            detail="Valid worker agent token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credential


def _normalized_identity(payload: WorkerIdentityPayload) -> dict[str, object]:
    labels = {
        str(key).strip()[:128]: str(value).strip()[:512]
        for key, value in payload.labels.items()
        if str(key).strip()
    }
    engine_keys = sorted(
        {
            str(value).strip()[:128]
            for value in payload.engine_keys
            if str(value).strip()
        }
    )
    return {
        "display_name": payload.display_name.strip(),
        "hostname": payload.hostname.strip(),
        "platform": payload.platform.strip().lower(),
        "agent_version": payload.agent_version.strip(),
        "labels_json": json.dumps(labels, sort_keys=True),
        "capacity": payload.capacity,
        "advertised_engine_keys_json": json.dumps(engine_keys),
    }


def _worker_id(node_id: str, process_id: int) -> str:
    return f"{node_id}:{process_id}"


def _node_engine_keys(node_id: str) -> set[str]:
    node = get_worker_node(node_id)
    if node is None:
        return set()
    try:
        parsed = json.loads(node.advertised_engine_keys_json)
    except json.JSONDecodeError:
        return set()
    return {str(value) for value in parsed} if isinstance(parsed, list) else set()


def _engine_payload(instance_id: int) -> dict[str, object]:
    instance = get_engine_instance_by_id(instance_id)
    if instance is None or not instance.enabled:
        raise HTTPException(status_code=409, detail="Engine instance is no longer enabled.")
    materialized = runtime_config(instance)
    secret_keys = {
        field.key
        for field in adapter_definition(instance.adapter_key).config_fields
        if field.secret
    }
    config = {
        str(key): value
        for key, value in materialized.items()
        if str(key) not in secret_keys
    }
    return {
        "id": instance.id,
        "adapter_key": instance.adapter_key,
        "display_name": instance.display_name,
        # Runtime defaults are materialized by the server so a remote worker
        # never consults a local MASP database. Secret fields are omitted; a
        # future secret-reference transport will handle adapters that need one.
        "config": config,
        "omitted_secret_keys": sorted(secret_keys),
    }


@router.post("/enroll", status_code=201)
def enroll_worker(request: Request, payload: WorkerIdentityPayload) -> dict[str, object]:
    _require_secure_transport(request)
    _require_enrollment_token(request)
    identity = _normalized_identity(payload)
    upsert_worker_node_heartbeat(
        node_id=payload.node_id,
        **identity,
        runtime_state="enrolled",
        active_scan_id=None,
        process_id=payload.process_id,
        last_heartbeat_at=int(time.time()),
    )
    token = f"masp_wa_{secrets.token_urlsafe(36)}"
    expires_at: int | None = None
    configured_days = os.getenv("MASP_WORKER_AGENT_TOKEN_TTL_DAYS", "").strip()
    if configured_days:
        try:
            expires_at = int(time.time()) + max(1, int(configured_days)) * 86_400
        except ValueError:
            raise HTTPException(
                status_code=500,
                detail="MASP_WORKER_AGENT_TOKEN_TTL_DAYS must be an integer.",
            )
    credential = create_worker_agent_credential(
        node_id=payload.node_id,
        token_hash=_token_hash(token),
        token_prefix=token[:16],
        expires_at=expires_at,
        revoke_existing=True,
    )
    set_audit_context(
        request,
        action="worker.enroll",
        target_type="worker_node",
        target_id=payload.node_id,
        details={"credential_id": credential.id, "rotated_existing": True},
    )
    return {
        "node_id": payload.node_id,
        "agent_token": token,
        "token_prefix": credential.token_prefix,
        "expires_at": expires_at,
        "detail": "Store the agent token now; MASP will not display it again.",
    }


@router.post("/heartbeat")
def worker_heartbeat(request: Request, payload: WorkerHeartbeatPayload) -> dict[str, object]:
    credential = require_worker_agent(request)
    if payload.node_id != credential.node_id:
        raise HTTPException(status_code=403, detail="Agent token belongs to another node.")
    identity = _normalized_identity(payload)
    node = upsert_worker_node_heartbeat(
        node_id=credential.node_id,
        **identity,
        runtime_state=payload.runtime_state,
        active_scan_id=payload.active_scan_id,
        process_id=payload.process_id,
        last_heartbeat_at=int(time.time()),
    )
    return {
        "accepted": True,
        "node_id": node.node_id,
        "lifecycle_state": node.lifecycle_state,
        "server_time": int(time.time()),
    }


@router.post("/jobs/claim", response_model=None)
def claim_worker_job(
    request: Request,
    payload: WorkerProcessPayload,
) -> Response | dict[str, object]:
    credential = require_worker_agent(request)
    engine_keys = _node_engine_keys(credential.node_id)
    eligible_ids = eligible_engine_instance_ids_for_node(credential.node_id, engine_keys)
    job = claim_next_scan_engine_job(
        engine_keys,
        _worker_id(credential.node_id, payload.process_id),
        worker_node_id=credential.node_id,
        eligible_engine_instance_ids=eligible_ids,
        lease_seconds=payload.lease_seconds,
    )
    if job is None:
        return Response(status_code=204)
    if job.engine_instance_id is None:
        raise HTTPException(status_code=409, detail="Claimed job has no engine instance.")
    if not mark_scan_engine_job_running(
        job.id,
        _worker_id(credential.node_id, payload.process_id),
        lease_seconds=payload.lease_seconds,
        attempt_generation=job.attempt_count,
    ):
        raise HTTPException(status_code=409, detail="Job ownership was lost before dispatch.")
    scan = get_scan(job.scan_job_id)
    if scan is None:
        raise HTTPException(status_code=409, detail="Claimed scan no longer exists.")
    mark_scan_running(scan.id)
    return {
        "job": {
            "id": job.id,
            "scan_id": job.scan_job_id,
            "attempt_generation": job.attempt_count,
            "lease_seconds": payload.lease_seconds,
        },
        "engine": _engine_payload(job.engine_instance_id),
        "sample": {
            "original_filename": scan.original_filename,
            "stored_filename": scan.stored_filename,
            "content_type": scan.content_type,
            "size_bytes": scan.size_bytes,
            "md5": scan.md5,
            "sha1": scan.sha1,
            "sha256": scan.sha256,
            "download_path": f"/api/v1/worker-control/jobs/{job.id}/sample",
        },
        "scan": {
            "source": scan.source,
            "role": scan.scan_role,
            "relative_path": scan.relative_path,
        },
    }


@router.post("/jobs/{job_id}/sample", response_class=FileResponse)
def download_worker_job_sample(
    request: Request,
    job_id: int,
    payload: WorkerLeasePayload,
) -> FileResponse:
    credential = require_worker_agent(request)
    worker_id = _worker_id(credential.node_id, payload.process_id)
    job = get_scan_engine_job(job_id)
    if (
        job is None
        or job.worker_id != worker_id
        or job.attempt_count != payload.attempt_generation
        or job.status != "running"
    ):
        raise HTTPException(status_code=409, detail="Sample ownership was lost.")
    if not renew_scan_engine_job_lease(
        job_id,
        worker_id,
        payload.attempt_generation,
        payload.lease_seconds,
    ):
        raise HTTPException(status_code=409, detail="Sample ownership was lost.")
    scan = get_scan(job.scan_job_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan sample not found.")
    sample_path = resolve_sample_path(scan)
    if not sample_path.is_file():
        raise HTTPException(status_code=404, detail="Scan sample file not found.")
    return FileResponse(
        sample_path,
        media_type="application/octet-stream",
        filename=scan.original_filename,
        headers={
            "X-MASP-SHA256": scan.sha256,
            "X-MASP-Size": str(scan.size_bytes),
            "Cache-Control": "no-store",
        },
    )


@router.post("/jobs/{job_id}/lease")
def renew_worker_job(
    request: Request,
    job_id: int,
    payload: WorkerLeasePayload,
) -> dict[str, object]:
    credential = require_worker_agent(request)
    renewed = renew_scan_engine_job_lease(
        job_id,
        _worker_id(credential.node_id, payload.process_id),
        payload.attempt_generation,
        payload.lease_seconds,
    )
    if not renewed:
        raise HTTPException(status_code=409, detail="Job lease ownership was lost.")
    return {"renewed": True, "job_id": job_id}


@router.post("/jobs/{job_id}/result")
def submit_worker_job_result(
    request: Request,
    job_id: int,
    payload: WorkerEngineResultPayload,
) -> dict[str, object]:
    credential = require_worker_agent(request)
    job = get_scan_engine_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Engine job not found.")
    result = EngineResultInput(
        engine_name=job.engine_name,
        status=payload.status,
        detected=payload.detected,
        severity=payload.severity,
        confidence=payload.confidence,
        signature=payload.signature,
        raw_output=payload.raw_output,
        duration_ms=payload.duration_ms,
        error_message=payload.error_message,
        engine_version=payload.engine_version,
        signature_version=payload.signature_version,
        details_json=json.dumps(payload.details, sort_keys=True, default=str),
        findings_json=json.dumps(payload.findings, sort_keys=True, default=str),
    )
    committed = commit_engine_job_result_if_owned(
        job_id=job_id,
        worker_id=_worker_id(credential.node_id, payload.process_id),
        attempt_generation=payload.attempt_generation,
        result=result,
        terminal_status=(
            payload.status
            if payload.status in {"completed", "failed", "skipped"}
            else "completed"
        ),
        last_error=payload.error_message,
    )
    if not committed:
        raise HTTPException(status_code=409, detail="Job result ownership was lost.")
    if payload.status == "completed" and job.engine_instance_id is not None:
        record_engine_node_scan_success(
            credential.node_id,
            job.engine_instance_id,
            engine_version=payload.engine_version,
            signature_version=payload.signature_version,
        )
    scan = get_scan(job.scan_job_id)
    finalized = False
    if scan is not None:
        # Keep finalization server-side: the agent does not need database access
        # and cannot mutate archive/scoring state outside this fenced endpoint.
        from app.workers.scan_worker import finalize_scan_if_complete

        finalized = finalize_scan_if_complete(scan, enabled_engines(source=scan.source))
    return {"committed": True, "job_id": job_id, "scan_finalized": finalized}


@router.post("/health/claim", response_model=None)
def claim_worker_health(
    request: Request,
    payload: WorkerHealthClaimPayload,
) -> Response | dict[str, object]:
    credential = require_worker_agent(request)
    engine_keys = _node_engine_keys(credential.node_id)
    eligible_ids = eligible_engine_instance_ids_for_node(credential.node_id, engine_keys)
    if not eligible_ids:
        return Response(status_code=204)
    ensure_engine_node_health_rows(credential.node_id, eligible_ids)
    worker_id = _worker_id(credential.node_id, payload.process_id)
    claim = claim_due_engine_node_health(
        credential.node_id,
        worker_id,
        eligible_ids,
        interval_seconds=payload.interval_seconds,
        lease_seconds=payload.lease_seconds,
    )
    if claim is None:
        return Response(status_code=204)
    return {
        "engine": _engine_payload(claim.engine_instance_id),
        "check_generation": claim.check_generation,
        "lease_seconds": payload.lease_seconds,
    }


@router.post("/health/{engine_instance_id}/result")
def submit_worker_health(
    request: Request,
    engine_instance_id: int,
    payload: WorkerHealthResultPayload,
) -> dict[str, object]:
    credential = require_worker_agent(request)
    committed = commit_engine_node_health_if_owned(
        node_id=credential.node_id,
        engine_instance_id=engine_instance_id,
        worker_id=_worker_id(credential.node_id, payload.process_id),
        check_generation=payload.check_generation,
        ok=payload.ok,
        health_status=payload.health_status,
        detail=payload.detail,
        product_version=payload.product_version,
        engine_version=payload.engine_version,
        signature_version=payload.signature_version,
        service_state=payload.service_state,
        storage_readable=payload.storage_readable,
        storage_writable=payload.storage_writable,
        details_json=json.dumps(payload.details, sort_keys=True, default=str),
    )
    if not committed:
        raise HTTPException(status_code=409, detail="Health-check ownership was lost.")
    return {"committed": True, "engine_instance_id": engine_instance_id}
