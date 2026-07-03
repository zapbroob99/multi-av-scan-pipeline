from dataclasses import dataclass


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
class EngineInstanceRecord:
    id: int
    adapter_key: str
    display_name: str
    enabled: bool
    config_json: str
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
