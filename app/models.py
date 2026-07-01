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
    completed_at: str | None
    original_filename: str
    stored_filename: str
    storage_path: str
    content_type: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
