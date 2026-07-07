from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib import error, request

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.benchmarking import BenchmarkRun, summarize_benchmark


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark MASP scan API using the real submit and poll workflow."
    )
    parser.add_argument("--base-url", required=True, help="Example: http://localhost:8000")
    parser.add_argument("--token", required=True, help="Bearer token for MASP API")
    parser.add_argument("--sample", required=True, help="Path to the sample file")
    parser.add_argument("--requests", type=int, default=10, help="Total scan submissions")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Maximum parallel HTTP requests during submit and poll phases",
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=0,
        help="wait_seconds sent to POST /api/v1/scans",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Seconds between status polls for unfinished scans",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Maximum total seconds to wait for all scans to finish",
    )
    parser.add_argument("--priority", default="Normal", help="Priority field for scan job")
    parser.add_argument(
        "--case-prefix",
        default="BENCH",
        help="Prefix for generated case names, example BENCH",
    )
    parser.add_argument(
        "--note",
        default="benchmark run",
        help="Note field attached to submitted scan jobs",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional path to write the full JSON benchmark report",
    )
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=60,
        help="Per-request HTTP timeout in seconds",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sample_path = Path(args.sample).expanduser().resolve()
    if not sample_path.is_file():
        print(f"Sample file not found: {sample_path}", file=sys.stderr)
        return 1
    if args.requests <= 0:
        print("--requests must be greater than 0", file=sys.stderr)
        return 1
    if args.concurrency <= 0:
        print("--concurrency must be greater than 0", file=sys.stderr)
        return 1
    if args.poll_interval <= 0:
        print("--poll-interval must be greater than 0", file=sys.stderr)
        return 1

    sample_bytes = sample_path.read_bytes()
    sample_name = sample_path.name
    content_type = mimetypes.guess_type(sample_name)[0] or "application/octet-stream"
    started_at = time.perf_counter()

    print(
        f"Submitting {args.requests} scans with concurrency {args.concurrency} "
        f"against {args.base_url.rstrip('/')}"
    )

    runs = submit_scans(
        base_url=args.base_url,
        token=args.token,
        sample_name=sample_name,
        sample_bytes=sample_bytes,
        content_type=content_type,
        total_requests=args.requests,
        concurrency=args.concurrency,
        wait_seconds=args.wait_seconds,
        case_prefix=args.case_prefix,
        priority=args.priority,
        note=args.note,
        request_timeout=args.request_timeout,
    )

    pending_runs = [run for run in runs if run.scan_id is not None and not run.completed]
    if pending_runs:
        print(f"Polling {len(pending_runs)} pending scans until completion or timeout...")
        completed_updates = poll_until_terminal(
            base_url=args.base_url,
            token=args.token,
            runs=pending_runs,
            concurrency=args.concurrency,
            poll_interval_seconds=args.poll_interval,
            deadline=time.perf_counter() + args.timeout,
            request_timeout=args.request_timeout,
        )
        runs = merge_run_updates(runs, completed_updates)

    benchmark_duration_ms = int((time.perf_counter() - started_at) * 1000)
    summary = summarize_benchmark(
        runs,
        base_url=args.base_url.rstrip("/"),
        sample_name=sample_name,
        sample_size_bytes=len(sample_bytes),
        requested_runs=args.requests,
        concurrency=args.concurrency,
        poll_interval_seconds=args.poll_interval,
        wait_seconds=args.wait_seconds,
        benchmark_duration_ms=benchmark_duration_ms,
    )

    print_summary(summary)
    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Full JSON report written to {output_path}")

    return 0


def submit_scans(
    *,
    base_url: str,
    token: str,
    sample_name: str,
    sample_bytes: bytes,
    content_type: str,
    total_requests: int,
    concurrency: int,
    wait_seconds: int,
    case_prefix: str,
    priority: str,
    note: str,
    request_timeout: int,
) -> list[BenchmarkRun]:
    runs: list[BenchmarkRun] = []
    submit_url = base_url.rstrip("/") + "/api/v1/scans"
    worker_count = min(concurrency, total_requests)

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                submit_single_scan,
                submit_url=submit_url,
                token=token,
                sample_name=sample_name,
                sample_bytes=sample_bytes,
                content_type=content_type,
                request_index=request_index,
                wait_seconds=wait_seconds,
                case_name=f"{case_prefix}-{request_index:04d}",
                priority=priority,
                note=note,
                request_timeout=request_timeout,
            ): request_index
            for request_index in range(1, total_requests + 1)
        }

        for future in as_completed(futures):
            runs.append(future.result())

    runs.sort(key=lambda run: run.request_index)
    return runs


def submit_single_scan(
    *,
    submit_url: str,
    token: str,
    sample_name: str,
    sample_bytes: bytes,
    content_type: str,
    request_index: int,
    wait_seconds: int,
    case_name: str,
    priority: str,
    note: str,
    request_timeout: int,
) -> BenchmarkRun:
    fields = {
        "case_name": case_name,
        "priority": priority,
        "note": note,
        "wait_seconds": str(wait_seconds),
    }
    body, multipart_content_type = build_multipart_body(
        fields=fields,
        file_field_name="sample",
        file_name=sample_name,
        file_bytes=sample_bytes,
        file_content_type=content_type,
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": multipart_content_type,
        "Accept": "application/json",
    }

    started_at = time.perf_counter()
    try:
        status_code, payload, _response_headers = request_json(
            method="POST",
            url=submit_url,
            headers=headers,
            body=body,
            timeout=request_timeout,
        )
    except RuntimeError as exc:
        elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        return BenchmarkRun(
            request_index=request_index,
            scan_id=None,
            accepted=False,
            completed=False,
            submit_duration_ms=elapsed_ms,
            queue_wait_ms=None,
            processing_duration_ms=None,
            total_duration_ms=None,
            polls=0,
            queue_position=None,
            final_status="submit_failed",
            final_verdict=None,
            decision_action=None,
            expected_engines=None,
            reported_engines=None,
            completed_engines=None,
            failed_engines=None,
            skipped_engines=None,
            detections=None,
            error=str(exc),
        )

    elapsed_ms = int((time.perf_counter() - started_at) * 1000)
    return run_from_payload(
        request_index=request_index,
        payload=payload,
        submit_duration_ms=elapsed_ms,
        queue_wait_ms=None,
        processing_duration_ms=None,
        total_duration_ms=elapsed_ms if bool(payload.get("completed")) else None,
        polls=0,
        fallback_status=f"http_{status_code}",
    )


def poll_until_terminal(
    *,
    base_url: str,
    token: str,
    runs: list[BenchmarkRun],
    concurrency: int,
    poll_interval_seconds: float,
    deadline: float,
    request_timeout: int,
) -> dict[int, BenchmarkRun]:
    status_base_url = base_url.rstrip("/") + "/api/v1/scans/"
    pending = {run.request_index: run for run in runs if run.scan_id is not None}
    terminal_runs: dict[int, BenchmarkRun] = {}

    with ThreadPoolExecutor(max_workers=min(concurrency, len(pending))) as executor:
        while pending and time.perf_counter() < deadline:
            futures = {
                executor.submit(
                    poll_single_scan,
                    status_url=status_base_url + str(run.scan_id),
                    token=token,
                    previous_run=run,
                    request_timeout=request_timeout,
                ): request_index
                for request_index, run in pending.items()
            }

            next_pending: dict[int, BenchmarkRun] = {}
            for future in as_completed(futures):
                updated_run = future.result()
                if updated_run.completed:
                    terminal_runs[updated_run.request_index] = updated_run
                else:
                    next_pending[updated_run.request_index] = updated_run

            pending = next_pending
            if pending and time.perf_counter() < deadline:
                time.sleep(poll_interval_seconds)

    timeout_ms = None
    for request_index, run in pending.items():
        timeout_ms = run.total_duration_ms
        terminal_runs[request_index] = BenchmarkRun(
            request_index=run.request_index,
            scan_id=run.scan_id,
            accepted=run.accepted,
            completed=False,
            submit_duration_ms=run.submit_duration_ms,
            queue_wait_ms=run.queue_wait_ms,
            processing_duration_ms=run.processing_duration_ms,
            total_duration_ms=timeout_ms,
            polls=run.polls,
            queue_position=run.queue_position,
            final_status="timeout",
            final_verdict=run.final_verdict,
            decision_action=run.decision_action,
            expected_engines=run.expected_engines,
            reported_engines=run.reported_engines,
            completed_engines=run.completed_engines,
            failed_engines=run.failed_engines,
            skipped_engines=run.skipped_engines,
            detections=run.detections,
            engine_durations_ms=run.engine_durations_ms,
            worker_event_durations_ms=run.worker_event_durations_ms,
            error="Benchmark timeout reached before terminal scan state.",
        )

    return terminal_runs


def poll_single_scan(
    *,
    status_url: str,
    token: str,
    previous_run: BenchmarkRun,
    request_timeout: int,
) -> BenchmarkRun:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    try:
        _status_code, payload, _response_headers = request_json(
            method="GET",
            url=status_url,
            headers=headers,
            body=None,
            timeout=request_timeout,
        )
    except RuntimeError as exc:
        return BenchmarkRun(
            request_index=previous_run.request_index,
            scan_id=previous_run.scan_id,
            accepted=previous_run.accepted,
            completed=False,
            submit_duration_ms=previous_run.submit_duration_ms,
            queue_wait_ms=previous_run.queue_wait_ms,
            processing_duration_ms=previous_run.processing_duration_ms,
            total_duration_ms=previous_run.total_duration_ms,
            polls=previous_run.polls + 1,
            queue_position=previous_run.queue_position,
            final_status="poll_failed",
            final_verdict=previous_run.final_verdict,
            decision_action=previous_run.decision_action,
            expected_engines=previous_run.expected_engines,
            reported_engines=previous_run.reported_engines,
            completed_engines=previous_run.completed_engines,
            failed_engines=previous_run.failed_engines,
            skipped_engines=previous_run.skipped_engines,
            detections=previous_run.detections,
            engine_durations_ms=previous_run.engine_durations_ms,
            worker_event_durations_ms=previous_run.worker_event_durations_ms,
            error=str(exc),
        )

    total_duration_ms = previous_run.submit_duration_ms
    scan_payload = payload.get("scan")
    if isinstance(scan_payload, dict):
        created_at = scan_payload.get("created_at")
        completed_at = scan_payload.get("completed_at") or scan_payload.get("failed_at")
        total_duration_ms = derive_duration_ms(created_at, completed_at)
    if total_duration_ms is None:
        total_duration_ms = previous_run.total_duration_ms

    updated_run = run_from_payload(
        request_index=previous_run.request_index,
        payload=payload,
        submit_duration_ms=previous_run.submit_duration_ms,
        queue_wait_ms=previous_run.queue_wait_ms,
        processing_duration_ms=previous_run.processing_duration_ms,
        total_duration_ms=total_duration_ms,
        polls=previous_run.polls + 1,
        fallback_status="running",
    )
    if updated_run.scan_id is None:
        return BenchmarkRun(
            request_index=previous_run.request_index,
            scan_id=previous_run.scan_id,
            accepted=previous_run.accepted,
            completed=False,
            submit_duration_ms=previous_run.submit_duration_ms,
            queue_wait_ms=previous_run.queue_wait_ms,
            processing_duration_ms=previous_run.processing_duration_ms,
            total_duration_ms=previous_run.total_duration_ms,
            polls=previous_run.polls + 1,
            queue_position=previous_run.queue_position,
            final_status="poll_invalid",
            final_verdict=previous_run.final_verdict,
            decision_action=previous_run.decision_action,
            expected_engines=previous_run.expected_engines,
            reported_engines=previous_run.reported_engines,
            completed_engines=previous_run.completed_engines,
            failed_engines=previous_run.failed_engines,
            skipped_engines=previous_run.skipped_engines,
            detections=previous_run.detections,
            engine_durations_ms=previous_run.engine_durations_ms,
            worker_event_durations_ms=previous_run.worker_event_durations_ms,
            error="Status payload did not include a scan id.",
        )
    return updated_run


def run_from_payload(
    *,
    request_index: int,
    payload: dict[str, Any],
    submit_duration_ms: int,
    queue_wait_ms: int | None,
    processing_duration_ms: int | None,
    total_duration_ms: int | None,
    polls: int,
    fallback_status: str,
) -> BenchmarkRun:
    scan_payload = payload.get("scan")
    queue_payload = payload.get("queue")
    engines_payload = payload.get("engines")
    decision_payload = payload.get("decision")

    scan_id = None
    final_status = fallback_status
    final_verdict = None
    if isinstance(scan_payload, dict):
        scan_id = safe_int(scan_payload.get("id"))
        final_status = str(scan_payload.get("status") or fallback_status)
        final_verdict = optional_string(scan_payload.get("verdict"))
        timing_payload = scan_payload.get("timing")
        if isinstance(timing_payload, dict):
            queue_wait_ms = safe_int(timing_payload.get("queue_wait_ms"))
            processing_duration_ms = safe_int(
                timing_payload.get("processing_duration_ms")
            )
            total_duration_ms = safe_int(timing_payload.get("total_duration_ms")) or total_duration_ms

    queue_position = None
    if isinstance(queue_payload, dict):
        queue_position = safe_int(queue_payload.get("position"))

    decision_action = None
    if isinstance(decision_payload, dict):
        decision_action = optional_string(decision_payload.get("action"))

    expected_engines = None
    reported_engines = None
    completed_engines = None
    failed_engines = None
    skipped_engines = None
    detections = None
    if isinstance(engines_payload, dict):
        expected_engines = safe_int(engines_payload.get("expected"))
        reported_engines = safe_int(engines_payload.get("reported"))
        completed_engines = safe_int(engines_payload.get("completed"))
        failed_engines = safe_int(engines_payload.get("failed"))
        skipped_engines = safe_int(engines_payload.get("skipped"))
        detections = safe_int(engines_payload.get("detections"))
    engine_durations_ms = extract_engine_durations(payload.get("engine_results"))
    worker_event_durations_ms = extract_worker_event_durations(payload.get("worker_events"))

    return BenchmarkRun(
        request_index=request_index,
        scan_id=scan_id,
        accepted=bool(payload.get("accepted", True)),
        completed=bool(payload.get("completed")),
        submit_duration_ms=submit_duration_ms,
        queue_wait_ms=queue_wait_ms,
        processing_duration_ms=processing_duration_ms,
        total_duration_ms=total_duration_ms,
        polls=polls,
        queue_position=queue_position,
        final_status=final_status,
        final_verdict=final_verdict,
        decision_action=decision_action,
        expected_engines=expected_engines,
        reported_engines=reported_engines,
        completed_engines=completed_engines,
        failed_engines=failed_engines,
        skipped_engines=skipped_engines,
        detections=detections,
        engine_durations_ms=engine_durations_ms,
        worker_event_durations_ms=worker_event_durations_ms,
        error=optional_string(payload.get("detail")) if scan_id is None else None,
    )


def extract_engine_durations(value: Any) -> dict[str, int]:
    if not isinstance(value, list):
        return {}
    durations: dict[str, int] = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        if optional_string(item.get("status")) == "skipped":
            continue
        engine_name = optional_string(item.get("engine_name"))
        duration_ms = safe_int(item.get("duration_ms"))
        if engine_name is None or duration_ms is None:
            continue
        durations[engine_name] = duration_ms
    return durations


def extract_worker_event_durations(value: Any) -> dict[str, int]:
    if not isinstance(value, list):
        return {}
    durations: dict[str, int] = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        event_name = optional_string(item.get("event_name"))
        duration_ms = safe_int(item.get("duration_ms"))
        if event_name is None or duration_ms is None:
            continue
        engine_name = optional_string(item.get("engine_name"))
        key = f"{event_name}:{engine_name}" if engine_name else event_name
        durations[key] = durations.get(key, 0) + duration_ms
    return durations


def merge_run_updates(
    original_runs: list[BenchmarkRun],
    updated_runs: dict[int, BenchmarkRun],
) -> list[BenchmarkRun]:
    return [updated_runs.get(run.request_index, run) for run in original_runs]


def request_json(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: int,
) -> tuple[int, dict[str, Any], Any]:
    http_request = request.Request(url=url, data=body, headers=headers, method=method)
    try:
        with request.urlopen(http_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return response.status, payload, response.headers
    except error.HTTPError as exc:
        try:
            body_text = exc.read().decode("utf-8")
        except Exception:
            body_text = ""
        detail = body_text.strip() or exc.reason
        raise RuntimeError(f"{method} {url} returned HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc


def build_multipart_body(
    *,
    fields: dict[str, str],
    file_field_name: str,
    file_name: str,
    file_bytes: bytes,
    file_content_type: str,
) -> tuple[bytes, str]:
    boundary = f"masp-benchmark-{uuid.uuid4().hex}"
    chunks: list[bytes] = []

    for field_name, field_value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode("utf-8"),
                f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'.encode(
                    "utf-8"
                ),
                field_value.encode("utf-8"),
                b"\r\n",
            ]
        )

    chunks.extend(
        [
            f"--{boundary}\r\n".encode("utf-8"),
            (
                f'Content-Disposition: form-data; name="{file_field_name}"; '
                f'filename="{file_name}"\r\n'
            ).encode("utf-8"),
            f"Content-Type: {file_content_type}\r\n\r\n".encode("utf-8"),
            file_bytes,
            b"\r\n",
            f"--{boundary}--\r\n".encode("utf-8"),
        ]
    )
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def derive_duration_ms(created_at: Any, completed_at: Any) -> int | None:
    if not created_at or not completed_at:
        return None
    try:
        created_epoch = iso_to_epoch(str(created_at))
        completed_epoch = iso_to_epoch(str(completed_at))
    except ValueError:
        return None
    return max(0, int((completed_epoch - created_epoch) * 1000))


def iso_to_epoch(value: str) -> float:
    normalized = value.replace("Z", "+00:00")
    if " " in normalized and "T" not in normalized:
        normalized = normalized.replace(" ", "T", 1)
    from datetime import datetime

    return datetime.fromisoformat(normalized).timestamp()


def safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def print_summary(summary: dict[str, Any]) -> None:
    meta = summary["meta"]
    aggregate = summary["summary"]
    latency = summary["latency_ms"]
    engines = summary["engines"]

    print("")
    print("Benchmark summary")
    print(f"Sample: {meta['sample_name']} ({meta['sample_size_bytes']} bytes)")
    print(
        f"Submitted: {aggregate['submitted']} | Completed: {aggregate['completed']} | "
        f"Errored: {aggregate['errored']}"
    )
    print(
        f"Submit latency avg/p95/p99: {format_ms(latency['submit_avg'])} / "
        f"{format_ms(latency['submit_p95'])} / {format_ms(latency['submit_p99'])}"
    )
    print(
        f"Queue wait avg/p95/p99: {format_ms(latency['queue_wait_avg'])} / "
        f"{format_ms(latency['queue_wait_p95'])} / {format_ms(latency['queue_wait_p99'])}"
    )
    print(
        f"Processing avg/p95/p99: {format_ms(latency['processing_avg'])} / "
        f"{format_ms(latency['processing_p95'])} / {format_ms(latency['processing_p99'])}"
    )
    print(
        f"Total latency avg/p95/p99: {format_ms(latency['total_avg'])} / "
        f"{format_ms(latency['total_p95'])} / {format_ms(latency['total_p99'])}"
    )
    print(
        f"Partial runs: {engines['partial_runs']} | Expected engines avg: "
        f"{format_number(engines['expected_avg'])} | Reported avg: "
        f"{format_number(engines['reported_avg'])}"
    )
    print(f"Statuses: {json.dumps(aggregate['terminal_statuses'], sort_keys=True)}")
    print(f"Decisions: {json.dumps(aggregate['decision_actions'], sort_keys=True)}")
    print(f"Verdicts: {json.dumps(aggregate['verdicts'], sort_keys=True)}")
    engine_timings = summary.get("engine_timings_ms")
    if isinstance(engine_timings, dict) and engine_timings:
        print("Engine duration avg/p95/p99:")
        for engine_name, timing in sorted(engine_timings.items()):
            if not isinstance(timing, dict):
                continue
            print(
                f"  {engine_name}: {format_ms(timing.get('avg'))} / "
                f"{format_ms(timing.get('p95'))} / {format_ms(timing.get('p99'))}"
            )
    worker_timings = summary.get("worker_timing_ms")
    if isinstance(worker_timings, dict) and worker_timings:
        print("Worker event duration avg/p95/p99:")
        for event_name, timing in sorted(worker_timings.items()):
            if not isinstance(timing, dict):
                continue
            print(
                f"  {event_name}: {format_ms(timing.get('avg'))} / "
                f"{format_ms(timing.get('p95'))} / {format_ms(timing.get('p99'))}"
            )


def format_ms(value: Any) -> str:
    if value is None:
        return "-"
    numeric = float(value)
    if numeric < 1000:
        return f"{round(numeric, 2)} ms"
    return f"{round(numeric / 1000, 2)} s"


def format_number(value: Any) -> str:
    if value is None:
        return "-"
    return str(round(float(value), 2))


if __name__ == "__main__":
    raise SystemExit(main())
