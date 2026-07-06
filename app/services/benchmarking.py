from __future__ import annotations

from dataclasses import asdict, dataclass
from statistics import mean
from typing import Any


@dataclass(frozen=True)
class BenchmarkRun:
    request_index: int
    scan_id: int | None
    accepted: bool
    completed: bool
    submit_duration_ms: int
    queue_wait_ms: int | None
    processing_duration_ms: int | None
    total_duration_ms: int | None
    polls: int
    queue_position: int | None
    final_status: str
    final_verdict: str | None
    decision_action: str | None
    expected_engines: int | None
    reported_engines: int | None
    completed_engines: int | None
    failed_engines: int | None
    skipped_engines: int | None
    detections: int | None
    error: str | None = None


def percentile(values: list[int], percentile_rank: float) -> int | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    normalized_rank = min(max(percentile_rank, 0.0), 1.0)
    index = round((len(values) - 1) * normalized_rank)
    return values[index]


def summarize_benchmark(
    runs: list[BenchmarkRun],
    *,
    base_url: str,
    sample_name: str,
    sample_size_bytes: int,
    requested_runs: int,
    concurrency: int,
    poll_interval_seconds: float,
    wait_seconds: int,
    benchmark_duration_ms: int,
) -> dict[str, Any]:
    submit_durations = sorted(run.submit_duration_ms for run in runs)
    completed_runs = [run for run in runs if run.completed]
    errored_runs = [run for run in runs if run.error]
    total_durations = sorted(
        run.total_duration_ms for run in runs if run.total_duration_ms is not None
    )
    queue_wait_durations = sorted(
        run.queue_wait_ms for run in completed_runs if run.queue_wait_ms is not None
    )
    processing_durations = sorted(
        run.processing_duration_ms
        for run in completed_runs
        if run.processing_duration_ms is not None
    )

    expected_engine_values = [
        run.expected_engines for run in completed_runs if run.expected_engines is not None
    ]
    reported_engine_values = [
        run.reported_engines for run in completed_runs if run.reported_engines is not None
    ]
    skipped_engine_values = [
        run.skipped_engines for run in completed_runs if run.skipped_engines is not None
    ]

    return {
        "meta": {
            "base_url": base_url,
            "sample_name": sample_name,
            "sample_size_bytes": sample_size_bytes,
            "requested_runs": requested_runs,
            "concurrency": concurrency,
            "poll_interval_seconds": poll_interval_seconds,
            "wait_seconds": wait_seconds,
            "benchmark_duration_ms": benchmark_duration_ms,
        },
        "summary": {
            "submitted": len(runs),
            "completed": len(completed_runs),
            "errored": len(errored_runs),
            "accepted": sum(1 for run in runs if run.accepted),
            "terminal_statuses": count_values(run.final_status for run in runs),
            "decision_actions": count_values(
                run.decision_action for run in runs if run.decision_action
            ),
            "verdicts": count_values(run.final_verdict for run in runs if run.final_verdict),
        },
        "latency_ms": {
            "submit_avg": safe_average(submit_durations),
            "submit_p50": percentile(submit_durations, 0.50),
            "submit_p95": percentile(submit_durations, 0.95),
            "submit_p99": percentile(submit_durations, 0.99),
            "queue_wait_avg": safe_average(queue_wait_durations),
            "queue_wait_p50": percentile(queue_wait_durations, 0.50),
            "queue_wait_p95": percentile(queue_wait_durations, 0.95),
            "queue_wait_p99": percentile(queue_wait_durations, 0.99),
            "processing_avg": safe_average(processing_durations),
            "processing_p50": percentile(processing_durations, 0.50),
            "processing_p95": percentile(processing_durations, 0.95),
            "processing_p99": percentile(processing_durations, 0.99),
            "total_avg": safe_average(total_durations),
            "total_p50": percentile(total_durations, 0.50),
            "total_p95": percentile(total_durations, 0.95),
            "total_p99": percentile(total_durations, 0.99),
        },
        "engines": {
            "expected_avg": safe_average(expected_engine_values),
            "reported_avg": safe_average(reported_engine_values),
            "skipped_avg": safe_average(skipped_engine_values),
            "partial_runs": sum(
                1
                for run in completed_runs
                if run.expected_engines is not None
                and run.reported_engines is not None
                and run.reported_engines < run.expected_engines
            ),
        },
        "runs": [asdict(run) for run in runs],
    }


def safe_average(values: list[int]) -> float | None:
    if not values:
        return None
    return round(mean(values), 2)


def count_values(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return counts
