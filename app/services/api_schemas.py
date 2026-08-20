"""Pydantic contract models for the public REST API (`/api/v1/...`).

These models are the single source of truth for the vendor-facing API
contract and describe the **public-safe** projection produced by
``app.services.api_payloads`` (raw engine output, engine detail/evidence,
worker telemetry, storage paths, internal IDs, and operator URLs are
deliberately absent — see that module).

Two roles:

1. OpenAPI documentation: the API endpoints reference these models via
   ``responses={...}`` so the generated schema carries real, typed response
   bodies for client generation. The endpoints keep returning ``JSONResponse``
   directly, so runtime behavior is unchanged.
2. Drift guard: tests validate real builder payloads and the shipped vendor
   examples against these models. ``extra="forbid"`` means any new/renamed
   field breaks the drift test instead of silently leaking into the contract.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


DecisionAction = Literal["allow", "block", "review", "wait"]
DecisionTone = Literal["success", "danger", "warning", "neutral"]
DecisionConfidence = Literal["low", "medium", "high"]
DecisionPolicy = Literal[
    "clean_full_coverage",
    "malware_detected",
    "elevated_risk",
    "partial_coverage",
    "metadata_only",
    "scan_failed",
    "scan_in_progress",
]


class ContractModel(BaseModel):
    """Base for all contract models: unknown fields are a contract break."""

    model_config = ConfigDict(extra="forbid")


class DecisionPayload(ContractModel):
    action: DecisionAction
    label: str
    tone: DecisionTone
    confidence: DecisionConfidence
    policy: DecisionPolicy
    reason: str
    reasons: list[str]


class LinksPayload(ContractModel):
    status: str
    result: str


class HashesPayload(ContractModel):
    md5: str
    sha1: str
    sha256: str


class VirusTotalDecisionPayload(ContractModel):
    action: Literal["allow", "block", "review"]
    reason: str


class VirusTotalStatsPayload(ContractModel):
    malicious: int
    suspicious: int
    undetected: int
    harmless: int
    timeout: int
    failure: int
    type_unsupported: int
    confirmed_timeout: int
    total: int


class VirusTotalPolicyPayload(ContractModel):
    malicious_threshold: int
    allow_undetected: bool
    max_age_days: int


class VirusTotalEnginePayload(ContractModel):
    key: Literal["virustotal"]
    name: str
    support_state: str


class VirusTotalHashResponse(ContractModel):
    """``GET /api/v1/hashes/{sha256}`` body.

    ``unknown`` and ``undetected`` are intentionally distinct. Unknown means
    VirusTotal has no usable report; undetected means a report exists but no
    engine in its latest statistics flagged the file.
    """

    hash: str
    algorithm: Literal["sha256"]
    source: Literal["virustotal"]
    found: bool
    status: Literal["malicious", "suspicious", "undetected", "stale", "unknown"]
    detail: str
    decision: VirusTotalDecisionPayload
    stats: VirusTotalStatsPayload | None
    last_analysis_date: str | None
    permalink: str | None
    cached: bool
    policy: VirusTotalPolicyPayload
    engine: VirusTotalEnginePayload


class HashEngineIdentityPayload(ContractModel):
    key: str
    name: str
    support_state: str


class HashEngineResultPayload(ContractModel):
    engine: HashEngineIdentityPayload
    status: str
    found: bool
    decision: VirusTotalDecisionPayload
    duration_ms: int
    data: dict[str, object]


class HashEngineCountsPayload(ContractModel):
    expected: int
    completed: int
    failed: int


class HashScanResponse(ContractModel):
    """Engine-neutral ``GET /api/v1/hashes/{sha256}`` response."""

    hash: str
    algorithm: Literal["sha256"]
    decision: VirusTotalDecisionPayload
    engines: HashEngineCountsPayload
    results: list[HashEngineResultPayload]


class TimingPayload(ContractModel):
    queue_wait_ms: int | None
    processing_duration_ms: int | None
    total_duration_ms: int | None
    age_ms: int | None
    processing_age_ms: int | None


class ScanBatchRef(ContractModel):
    id: int | None
    parent_scan_id: int | None
    relative_path: str | None
    role: str


class ScanSummaryPayload(ContractModel):
    """Public-safe scan block, shared by status and result payloads."""

    id: int
    filename: str
    status: str
    verdict: str
    risk_score: int | None
    created_at: str
    started_at: str | None
    completed_at: str | None
    failed_at: str | None
    content_type: str
    size_bytes: int
    batch: ScanBatchRef
    timing: TimingPayload
    hashes: HashesPayload


class QueuePayload(ContractModel):
    queued: int
    running: int
    active: int
    completed: int
    failed: int
    total: int
    position: int | None


class EnginesPayload(ContractModel):
    expected: int
    reported: int
    completed: int
    failed: int
    skipped: int
    detections: int


class EngineResultBrief(ContractModel):
    engine_name: str
    status: str
    detected: bool
    duration_ms: int


class ScanStatusResponse(ContractModel):
    """``GET /api/v1/scans/{scan_id}`` body."""

    completed: bool
    result_ready: bool
    recommended_poll_seconds: int | None
    decision: DecisionPayload
    scan: ScanSummaryPayload
    queue: QueuePayload
    engines: EnginesPayload
    engine_results: list[EngineResultBrief]
    links: LinksPayload
    batch_links: LinksPayload | None = None


class DetectionSummaryPayload(ContractModel):
    label: str
    detail: str
    detected_engines: list[str]


class CoverageSummaryPayload(ContractModel):
    label: str
    detail: str
    ran: int
    total: int
    unavailable: list[str]


class AssessmentSummaryPayload(ContractModel):
    score: int
    verdict: str
    reasons: list[str]


class ReportSummaryPayload(ContractModel):
    detection: DetectionSummaryPayload
    coverage: CoverageSummaryPayload
    assessment: AssessmentSummaryPayload
    decision: DecisionPayload


class FindingRowPayload(ContractModel):
    """Public-safe finding summary (no path-bearing evidence)."""

    engine: str
    title: str
    finding: str
    severity: str
    confidence: int
    action: str
    classification: list[str]


class EngineResultFull(ContractModel):
    """Public-safe engine result.

    No raw_output / details / error text, and no version fields
    (signature_version can carry an internal rules-directory path).
    """

    engine_name: str
    status: str
    detected: bool
    signature: str | None
    severity: str
    confidence: int
    duration_ms: int


class ScanReportPayload(ContractModel):
    """Normalized result body (also nested per-scan in batch results)."""

    generated_at: str
    scan: ScanSummaryPayload
    summary: ReportSummaryPayload
    findings: list[FindingRowPayload]
    engine_results: list[EngineResultFull]


class ScanResultResponse(ScanReportPayload):
    """``GET /api/v1/scans/{scan_id}/result`` body (terminal scan)."""

    completed: bool
    result_ready: bool
    decision: DecisionPayload
    links: LinksPayload
    batch_links: LinksPayload | None = None


class ScanResultNotReadyResponse(ScanStatusResponse):
    """``GET /api/v1/scans/{scan_id}/result`` 409 body (scan not terminal)."""

    detail: str


class ScanSubmitAcceptedResponse(ScanStatusResponse):
    """``POST /api/v1/scans`` 202 body (scan still processing)."""

    accepted: bool
    wait_seconds_applied: int
    detail: str


class ScanSubmitCompletedResponse(ScanSubmitAcceptedResponse):
    """``POST /api/v1/scans`` 200 body (terminal within the wait window)."""

    result: ScanResultResponse


class BatchCountsPayload(ContractModel):
    total_items: int
    queued_items: int
    running_items: int
    completed_items: int
    failed_items: int
    malicious_items: int
    skipped_items: int
    child_items: int


class BatchSummaryPayload(ContractModel):
    id: int
    source: str
    original_filename: str
    archive_mode: str
    status: str
    counts: BatchCountsPayload
    container_scan_id: int | None
    created_at: str
    updated_at: str
    completed_at: str | None
    completed: bool
    links: LinksPayload


class BatchScanStatusEntry(ScanSummaryPayload):
    result_ready: bool
    links: LinksPayload


class BatchStatusResponse(ContractModel):
    """``GET /api/v1/batches/{batch_id}`` body."""

    completed: bool
    result_ready: bool
    batch: BatchSummaryPayload
    scans: list[BatchScanStatusEntry]
    links: LinksPayload


class BatchResultScanEntry(ContractModel):
    id: int
    role: str
    parent_scan_id: int | None
    relative_path: str | None
    result: ScanReportPayload
    links: LinksPayload


class BatchResultResponse(ContractModel):
    """``GET /api/v1/batches/{batch_id}/result`` body (terminal batch)."""

    completed: bool
    result_ready: bool
    batch: BatchSummaryPayload
    scans: list[BatchResultScanEntry]
    links: LinksPayload


class BatchResultNotReadyResponse(BatchStatusResponse):
    """``GET /api/v1/batches/{batch_id}/result`` 409 body."""

    detail: str


class HealthResponse(ContractModel):
    status: str


class ApiErrorResponse(ContractModel):
    """FastAPI ``HTTPException`` body (400, 401, 404, 413, 503)."""

    detail: str
