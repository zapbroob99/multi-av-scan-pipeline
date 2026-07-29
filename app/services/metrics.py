"""Prometheus text-format metrics for MASP.

Why this exists: the ICAP gateway is fail-closed, so a MASP outage does not
degrade quietly -- it blocks uploads for real users. The platform therefore has
to be observable from outside, and "is the process up" is not enough. A worker
can be running while claiming nothing, and a queue can be deep because traffic
is heavy or because nothing is draining it. The metrics below are chosen so a
monitoring system can tell those apart:

  * queue depth AND the age of the oldest waiting scan (depth alone is
    ambiguous; age is what distinguishes busy from stalled),
  * worker liveness as a count of online workers, not a single boolean, so
    losing one worker of several is visible,
  * per-engine result counts, so a single broken engine is caught before it
    drags every scan into partial coverage.

Output is the Prometheus text exposition format, which every mainstream
monitoring stack ingests. No third-party client library is used: the format is
a few lines of text, and avoiding the dependency keeps the runtime surface of a
malware-handling service small.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from app.database import (
    get_oldest_active_scan_timestamps,
    get_queue_metrics,
    list_engine_result_metrics,
)
from app.services.timing import parse_timestamp
from app.services.worker_runtime import get_worker_status, worker_stale_seconds


def metrics_enabled() -> bool:
    """Whether ``/metrics`` is served. Read per call so tests can toggle it."""
    return os.getenv("MASP_METRICS_ENABLED", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _escape_label_value(value: str) -> str:
    """Escape a label value per the Prometheus exposition format."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _metric_lines(
    name: str,
    help_text: str,
    metric_type: str,
    samples: list[tuple[dict[str, str], float | int]],
) -> list[str]:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {metric_type}"]
    for labels, value in samples:
        if labels:
            rendered = ",".join(
                f'{key}="{_escape_label_value(str(val))}"' for key, val in sorted(labels.items())
            )
            lines.append(f"{name}{{{rendered}}} {value}")
        else:
            lines.append(f"{name} {value}")
    return lines


def _age_seconds(timestamp: str | None, now: datetime) -> float:
    """Age of a stored timestamp in seconds, clamped at zero.

    Returns 0 for a missing timestamp: an empty queue has no waiting scan, and
    reporting 0 rather than omitting the series keeps alert rules simple (they
    can always compare against a threshold instead of handling absent data).
    """
    parsed = parse_timestamp(timestamp)
    if parsed is None:
        return 0.0
    return max(0.0, (now - parsed).total_seconds())


def render_metrics(now: datetime | None = None) -> str:
    """Build the full Prometheus exposition payload."""
    current_time = now or datetime.now(timezone.utc)
    queue = get_queue_metrics()
    oldest = get_oldest_active_scan_timestamps()
    worker_status = get_worker_status()

    lines: list[str] = []

    lines += _metric_lines(
        "masp_scans_total",
        "Scan jobs by lifecycle status.",
        "gauge",
        [
            ({"status": "queued"}, queue["queued"]),
            ({"status": "running"}, queue["running"]),
            ({"status": "completed"}, queue["completed"]),
            ({"status": "failed"}, queue["failed"]),
        ],
    )
    lines += _metric_lines(
        "masp_scan_queue_depth",
        "Scans queued or running (not yet terminal).",
        "gauge",
        [({}, queue["active"])],
    )
    lines += _metric_lines(
        "masp_scan_oldest_queued_age_seconds",
        "Age of the oldest scan still waiting to start; 0 when none are queued.",
        "gauge",
        [({}, round(_age_seconds(oldest["oldest_queued_at"], current_time), 3))],
    )
    lines += _metric_lines(
        "masp_scan_oldest_running_age_seconds",
        "Age of the oldest scan still in progress; 0 when none are running.",
        "gauge",
        [({}, round(_age_seconds(oldest["oldest_running_at"], current_time), 3))],
    )

    online_count = int(worker_status.get("online_count", 0) or 0)
    lines += _metric_lines(
        "masp_workers_online",
        "Workers that sent a heartbeat within the stale threshold.",
        "gauge",
        [({}, online_count)],
    )
    lines += _metric_lines(
        "masp_worker_heartbeat_stale_after_seconds",
        "Seconds without a heartbeat after which a worker counts as offline.",
        "gauge",
        [({}, worker_stale_seconds())],
    )
    age_seconds = worker_status.get("age_seconds")
    lines += _metric_lines(
        "masp_worker_heartbeat_age_seconds",
        "Age of the freshest worker heartbeat; -1 when no worker is online.",
        "gauge",
        [({}, int(age_seconds) if age_seconds is not None else -1)],
    )

    engine_samples: list[tuple[dict[str, str], float | int]] = []
    detection_samples: list[tuple[dict[str, str], float | int]] = []
    for row in list_engine_result_metrics():
        engine = str(row.get("engine_name") or "unknown")
        for status in ("completed", "failed", "skipped"):
            engine_samples.append(
                ({"engine": engine, "status": status}, int(row.get(f"{status}_results") or 0))
            )
        detection_samples.append(({"engine": engine}, int(row.get("detections") or 0)))
    lines += _metric_lines(
        "masp_engine_results_total",
        "Engine results by engine and status.",
        "gauge",
        engine_samples,
    )
    lines += _metric_lines(
        "masp_engine_detections_total",
        "Detections reported by each engine.",
        "gauge",
        detection_samples,
    )

    return "\n".join(lines) + "\n"
