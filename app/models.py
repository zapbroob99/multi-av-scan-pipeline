from dataclasses import dataclass


# A scan is "active" (non-terminal, still in progress) in exactly these states.
# 'finalizing' is the brief owned window between all engine jobs finishing and
# the scan being marked completed. Treated identically to running everywhere a
# scan is considered in progress (polling, decisions=wait, active filters, queue
# metrics, retry guards, UI refresh).
ACTIVE_SCAN_STATUSES = frozenset({"queued", "running", "finalizing"})

# Terminal (settled) scan states. Terminal is NOT forever: retry_scan_job moves
# a completed/failed scan back to queued, after which it can reach 'finalizing'
# again and re-promote archive-child files to the same deterministic paths. A
# terminal status read in isolation therefore never proves that no child file is
# about to appear; orphan-sample cleanup re-confirms terminal-and-unreferenced
# under the parent's row lock (database.remove_orphan_child_sample) at the
# moment of deletion, which is what actually excludes a concurrent retry or
# finalizer.
TERMINAL_SCAN_STATUSES = frozenset({"completed", "failed"})


@dataclass(frozen=True)
class StoredSample:
    original_filename: str
    stored_filename: str
    storage_path: str
    content_type: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str


@dataclass(frozen=True)
class ScanRecord:
    id: int
    sample_id: int
    case_name: str
    priority: str
    note: str
    source: str
    status: str
    verdict: str
    risk_score: int | None
    created_at: str
    started_at: str | None
    completed_at: str | None
    failed_at: str | None
    attempt_count: int
    last_error: str | None
    original_filename: str
    stored_filename: str
    storage_path: str
    content_type: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    batch_id: int | None = None
    parent_scan_id: int | None = None
    relative_path: str | None = None
    scan_role: str = "standalone"


@dataclass(frozen=True)
class ScanBatchRecord:
    id: int
    source: str
    original_filename: str
    archive_mode: str
    status: str
    total_items: int
    queued_items: int
    running_items: int
    completed_items: int
    failed_items: int
    malicious_items: int
    skipped_items: int
    metadata_json: str
    created_at: str
    updated_at: str
    completed_at: str | None
    last_error: str | None


@dataclass(frozen=True)
class EngineResultInput:
    engine_name: str
    status: str
    detected: bool
    severity: str
    confidence: int
    signature: str | None
    raw_output: str
    duration_ms: int
    error_message: str | None = None
    engine_version: str | None = None
    signature_version: str | None = None
    details_json: str = "{}"
    findings_json: str = "[]"


@dataclass(frozen=True)
class EngineResultRecord:
    id: int
    scan_job_id: int
    engine_name: str
    engine_version: str | None
    signature_version: str | None
    status: str
    detected: bool
    signature: str | None
    severity: str
    confidence: int
    raw_output: str
    error_message: str | None
    duration_ms: int
    created_at: str
    details_json: str
    findings_json: str


@dataclass(frozen=True)
class ScanWorkerEventRecord:
    id: int
    scan_job_id: int
    event_name: str
    worker_id: str
    worker_engine_keys: str
    engine_name: str | None
    duration_ms: int | None
    details_json: str
    created_at: str


@dataclass(frozen=True)
class ScanEngineJobRecord:
    id: int
    scan_job_id: int
    engine_instance_id: int | None
    engine_key: str
    engine_name: str
    status: str
    worker_id: str | None
    claimed_at: str | None
    started_at: str | None
    finished_at: str | None
    lease_expires_at: int | None
    attempt_count: int
    last_error: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class EngineInstanceRecord:
    id: int
    adapter_key: str
    display_name: str
    enabled: bool
    config_json: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class WorkerNodeRecord:
    node_id: str
    display_name: str
    hostname: str
    platform: str
    agent_version: str
    labels_json: str
    capacity: int
    advertised_engine_keys_json: str
    lifecycle_state: str
    runtime_state: str
    active_scan_id: int | None
    process_id: int | None
    last_heartbeat_at: int
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class WorkerAgentCredentialRecord:
    id: int
    node_id: str
    token_hash: str
    token_prefix: str
    created_at: str
    last_used_at: int | None
    expires_at: int | None
    revoked_at: int | None


@dataclass(frozen=True)
class WorkerPoolRecord:
    id: int
    name: str
    selector_json: str
    enabled: bool
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class EngineNodeHealthRecord:
    node_id: str
    engine_instance_id: int
    status: str
    ok: bool
    health_status: str
    detail: str
    product_version: str | None
    engine_version: str | None
    signature_version: str | None
    service_state: str | None
    storage_readable: bool | None
    storage_writable: bool | None
    consecutive_failures: int
    last_checked_at: int | None
    last_success_at: int | None
    last_scan_success_at: int | None
    details_json: str
    check_worker_id: str | None
    check_generation: int
    check_lease_expires_at: int | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class UserRecord:
    id: int
    username: str
    password_hash: str
    role: str
    created_at: str
    updated_at: str
    auth_source: str = "local"
    external_id: str | None = None
    display_name: str | None = None
    last_login_at: str | None = None


@dataclass(frozen=True)
class AuditEventRecord:
    id: int
    created_at: str
    actor_type: str
    actor_id: str | None
    actor_name: str | None
    action: str
    target_type: str
    target_id: str | None
    outcome: str
    source_ip: str | None
    request_id: str
    details_json: str
