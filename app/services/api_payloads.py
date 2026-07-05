from __future__ import annotations

from typing import Any

from app.models import ScanRecord


def create_api_scan_status_payload(
    *,
    scan: ScanRecord,
    result_ready: bool,
    recommended_poll_seconds: int | None,
    decision_payload: dict[str, object],
    scan_payload: dict[str, object],
    queue_metrics: dict[str, int],
    queue_position: int | None,
    expected_engines: int,
    results: list[Any],
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
        "links": links,
    }


def create_api_scan_result_payload(
    *,
    report_payload: dict[str, object],
    completed: bool,
    result_ready: bool,
    decision_payload: dict[str, object],
    links: dict[str, str],
) -> dict[str, object]:
    payload = dict(report_payload)
    payload["completed"] = completed
    payload["result_ready"] = result_ready
    payload["decision"] = decision_payload
    payload["links"] = links
    return payload
