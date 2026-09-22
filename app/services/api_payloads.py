"""Public REST API serialization (`/api/v1/...`).

These builders produce the vendor-facing, **public-safe** projection of a scan.
The `/api/v1` surface is the external integration boundary, so the payloads
here are an explicit allowlist: they never carry engine raw output,
engine-specific detail/evidence (which can embed internal filesystem paths),
worker/orchestration telemetry, storage paths, internal stored filenames, or
operator-console URLs.

Full internal detail is unchanged elsewhere: the operator scan-detail page and
the JSON/CSV exports use ``build_scan_report_payload`` /
``create_scan_report_payload`` (in ``app.services.reports``), and the raw
engine output remains in the database. Only the public API projection is
reduced here.

The contract models in ``app.services.api_schemas`` mirror these shapes with
``extra="forbid"``; a drift test validates real builder output (and the
shipped vendor examples) against them, so any new field added here without a
matching model/allowlist review breaks the test.
"""

from __future__ import annotations

from typing import Any

from app.models import EngineResultRecord, ScanRecord, ScanBatchRecord
from app.services.timing import build_scan_timing_payload


def public_engine_result_brief(result: EngineResultRecord) -> dict[str, object]:
    """Status-payload engine entry: progress only, no detail."""
    return {
        "engine_name": result.engine_name,
        "status": result.status,
        "detected": result.detected,
        "duration_ms": result.duration_ms,
    }


def _public_engine_result_full(entry: dict[str, Any]) -> dict[str, object]:
    """Result-payload engine entry: verdict-relevant fields only.

    Drops raw_output, engine-specific ``details``, engine-level ``findings``
    (which carry path-bearing evidence), ``error_message`` (can leak internal
    paths), internal timestamps, and the version fields (``signature_version``
    can carry an internal rules-directory path, e.g. YARA).
    """
    return {
        "engine_name": entry["engine_name"],
        "status": entry["status"],
        "detected": entry["detected"],
        "signature": entry.get("signature"),
        "severity": entry["severity"],
        "confidence": entry["confidence"],
        "duration_ms": entry["duration_ms"],
    }


def _public_finding(entry: dict[str, Any]) -> dict[str, object]:
    """Finding summary: no ``matched_evidence``/``evidence`` (path-bearing)."""
    return {
        "engine": entry["engine"],
        "title": entry["title"],
        "finding": entry["finding"],
        "severity": entry["severity"],
        "confidence": entry["confidence"],
        "action": entry["action"],
        "classification": list(entry.get("classification", [])),
    }


def public_scan_report_payload(
    report_payload: dict[str, Any],
    scan_payload: dict[str, object],
) -> dict[str, object]:
    """Project a full scan report onto the vendor-safe result body.

    ``scan_payload`` is the already-sanitized scan summary
    (``build_scan_summary_payload``), reused so the scan block is identical to
    the status payload. ``summary`` (detection/coverage/assessment/decision)
    is MASP-generated text and is safe as-is.
    """
    return {
        "generated_at": report_payload["generated_at"],
        "scan": scan_payload,
        "summary": report_payload["summary"],
        "findings": [_public_finding(finding) for finding in report_payload["findings"]],
        "engine_results": [
            _public_engine_result_full(result) for result in report_payload["engine_results"]
        ],
    }


def create_api_scan_status_payload(
    *,
    result_ready: bool,
    recommended_poll_seconds: int | None,
    decision_payload: dict[str, object],
    scan_payload: dict[str, object],
    queue_metrics: dict[str, int],
    queue_position: int | None,
    expected_engines: int,
    results: list[EngineResultRecord],
    links: dict[str, str],
) -> dict[str, object]:
    return {
        "completed": result_ready,
        "result_ready": result_ready,
        "recommended_poll_seconds": recommended_poll_seconds,
        "decision": decision_payload,
        "scan": scan_payload,
        "queue": {
            **queue_metrics,
            "position": queue_position,
        },
        "engines": {
            "expected": expected_engines,
            "reported": len(results),
            "completed": sum(1 for result in results if result.status == "completed"),
            "failed": sum(1 for result in results if result.status == "failed"),
            "skipped": sum(1 for result in results if result.status == "skipped"),
            "detections": sum(1 for result in results if result.detected),
        },
        "engine_results": [public_engine_result_brief(result) for result in results],
        "links": links,
    }


def create_api_scan_result_payload(
    *,
    report_payload: dict[str, Any],
    scan_payload: dict[str, object],
    completed: bool,
    result_ready: bool,
    decision_payload: dict[str, object],
    links: dict[str, str],
) -> dict[str, object]:
    payload = public_scan_report_payload(report_payload, scan_payload)
    payload["completed"] = completed
    payload["result_ready"] = result_ready
    payload["decision"] = decision_payload
    payload["links"] = links
    return payload


def build_scan_summary_payload(scan: ScanRecord) -> dict[str, object]:
    # Vendor-safe projection: internal identifiers (sample_id), operator-only
    # bookkeeping (attempt_count, last_error) and free-form operator text
    # (case_name, priority, note, source) are deliberately omitted from the
    # public API. storage_path / stored_filename are never included here.
    return {
        "id": scan.id,
        "filename": scan.original_filename,
        "status": scan.status,
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "failed_at": scan.failed_at,
        "content_type": scan.content_type,
        "size_bytes": scan.size_bytes,
        "batch": {
            "id": scan.batch_id,
            "parent_scan_id": scan.parent_scan_id,
            "relative_path": scan.relative_path,
            "role": scan.scan_role,
        },
        "timing": build_scan_timing_payload(scan),
        "hashes": {
            "md5": scan.md5,
            "sha1": scan.sha1,
            "sha256": scan.sha256,
        },
    }


def build_batch_summary_payload(
    batch: ScanBatchRecord,
    scans: list[ScanRecord],
    links: dict[str, str],
) -> dict[str, object]:
    container_scan = next((scan for scan in scans if scan.scan_role == "container"), None)
    child_count = sum(1 for scan in scans if scan.scan_role == "child")
    return {
        "id": batch.id,
        "source": batch.source,
        "original_filename": batch.original_filename,
        "archive_mode": batch.archive_mode,
        "status": batch.status,
        "counts": {
            "total_items": batch.total_items,
            "queued_items": batch.queued_items,
            "running_items": batch.running_items,
            "completed_items": batch.completed_items,
            "failed_items": batch.failed_items,
            "malicious_items": batch.malicious_items,
            "skipped_items": batch.skipped_items,
            "child_items": child_count,
        },
        "container_scan_id": None if container_scan is None else container_scan.id,
        # Free-form batch metadata and operator error text are omitted from the
        # public API: metadata may carry internal extraction detail and
        # last_error may leak internal paths/messages.
        "created_at": batch.created_at,
        "updated_at": batch.updated_at,
        "completed_at": batch.completed_at,
        "completed": batch.status == "completed",
        "links": links,
    }
