"""Benchmark the MASP ICAP gateway with real REQMOD connections.

ICAP is inherently synchronous (the client holds the connection open for the
verdict), so this measures the same thing the size-capped REST sync pattern
does: how many concurrent connections the gateway can hold before latency or
the fail-closed timeout policy starts biting.

Example (PowerShell):
    .venv\\Scripts\\python.exe tools\\benchmark_icap.py --host 127.0.0.1 --port 1344 --sample .\\README.md --requests 50 --concurrency 10
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.benchmarking import percentile, safe_average

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
MAX_RESPONSE_HEAD_BYTES = 64 * 1024


@dataclass(frozen=True)
class IcapBenchRun:
    request_index: int
    verdict: str  # allow | block | error | timeout
    duration_ms: int
    error: str | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark the MASP ICAP gateway.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1344)
    parser.add_argument("--service", default="masp")
    parser.add_argument("--requests", type=int, default=20, help="Total REQMOD connections")
    parser.add_argument(
        "--concurrency", type=int, default=5, help="Maximum parallel connections"
    )
    parser.add_argument("--sample", default="", help="Path to the sample file to send")
    parser.add_argument(
        "--eicar", action="store_true", help="Send the EICAR test string instead of --sample"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Per-connection socket timeout in seconds",
    )
    parser.add_argument("--output", default="", help="Optional path to write a JSON report")
    return parser.parse_args()


def build_reqmod(host: str, port: int, service: str, filename: str, body: bytes) -> bytes:
    http_hdr = (
        f"PUT /{filename} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode()
    chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body) if body else b"0\r\n\r\n"
    encapsulated = f"req-hdr=0, req-body={len(http_hdr)}".encode()
    head = (
        f"REQMOD icap://{host}:{port}/{service} ICAP/1.0\r\n"
        f"Host: {host}:{port}\r\nAllow: 204\r\n"
    ).encode() + b"Encapsulated: " + encapsulated + b"\r\n\r\n"
    return head + http_hdr + chunked


def read_icap_response_head(sock: socket.socket) -> bytes:
    """Read through the ICAP header terminator, without waiting for keep-alive EOF.

    The benchmark only needs the ICAP status line to classify a verdict. The
    gateway deliberately keeps connections alive, so waiting for EOF or a
    follow-up socket timeout adds idle time to both measured latency and the
    client's occupied concurrency slot.
    """
    response = bytearray()
    while b"\r\n\r\n" not in response:
        try:
            chunk = sock.recv(4096)
        except socket.timeout as exc:
            if response:
                raise OSError("ICAP response headers timed out before completion") from exc
            raise
        if not chunk:
            break
        response.extend(chunk)
        if len(response) > MAX_RESPONSE_HEAD_BYTES:
            raise OSError("ICAP response headers exceed 64 KiB")
    return bytes(response)


def classify_icap_response(response: bytes) -> tuple[str, str | None]:
    if not response:
        return "timeout", None
    if b"\r\n\r\n" not in response:
        return "error", "ICAP response ended before headers completed"
    if response.startswith(b"ICAP/1.0 204"):
        return "allow", None
    if response.startswith(b"ICAP/1.0 200"):
        return "block", None
    status_line = response.split(b"\r\n", 1)[0].decode(errors="replace") or "<no response>"
    return "error", status_line


def send_reqmod(
    *,
    host: str,
    port: int,
    service: str,
    filename: str,
    body: bytes,
    request_index: int,
    timeout: float,
) -> IcapBenchRun:
    message = build_reqmod(host, port, service, filename, body)
    started_at = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(message)
            sock.settimeout(timeout)
            response = read_icap_response_head(sock)
    except socket.timeout:
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        return IcapBenchRun(request_index, "timeout", duration_ms)
    except OSError as exc:
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        return IcapBenchRun(request_index, "error", duration_ms, error=str(exc))

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    verdict, error = classify_icap_response(response)
    return IcapBenchRun(request_index, verdict, duration_ms, error=error)


def run_benchmark(
    *,
    host: str,
    port: int,
    service: str,
    filename: str,
    body: bytes,
    total_requests: int,
    concurrency: int,
    timeout: float,
) -> list[IcapBenchRun]:
    runs: list[IcapBenchRun] = []
    worker_count = min(concurrency, total_requests)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                send_reqmod,
                host=host,
                port=port,
                service=service,
                filename=filename,
                body=body,
                request_index=request_index,
                timeout=timeout,
            ): request_index
            for request_index in range(1, total_requests + 1)
        }
        for future in as_completed(futures):
            runs.append(future.result())
    runs.sort(key=lambda run: run.request_index)
    return runs


def summarize(runs: list[IcapBenchRun], *, benchmark_duration_ms: int) -> dict:
    durations = sorted(run.duration_ms for run in runs)
    by_verdict = {"allow": 0, "block": 0, "error": 0, "timeout": 0}
    for run in runs:
        by_verdict[run.verdict] = by_verdict.get(run.verdict, 0) + 1

    return {
        "summary": {
            "submitted": len(runs),
            "allow": by_verdict["allow"],
            "block": by_verdict["block"],
            "error": by_verdict["error"],
            "timeout": by_verdict["timeout"],
            "success_rate": round(
                (by_verdict["allow"] + by_verdict["block"]) / len(runs), 4
            )
            if runs
            else 0.0,
            "benchmark_duration_ms": benchmark_duration_ms,
        },
        "latency_ms": {
            "avg": safe_average(durations),
            "p50": percentile(durations, 0.50),
            "p95": percentile(durations, 0.95),
            "p99": percentile(durations, 0.99),
            "min": durations[0] if durations else None,
            "max": durations[-1] if durations else None,
        },
        "runs": [asdict(run) for run in runs],
    }


def print_summary(summary: dict) -> None:
    s = summary["summary"]
    latency = summary["latency_ms"]
    print()
    print(f"Submitted:          {s['submitted']}")
    print(f"Allow (204):        {s['allow']}")
    print(f"Block (200):        {s['block']}")
    print(f"Errors:             {s['error']}")
    print(f"Timeouts:           {s['timeout']}")
    print(f"Success rate:       {s['success_rate'] * 100:.1f}% (allow+block / submitted)")
    print(f"Benchmark duration: {s['benchmark_duration_ms']} ms")
    print()
    print("Latency (ms):", {k: latency[k] for k in ("avg", "p50", "p95", "p99", "min", "max")})


def main() -> int:
    args = parse_args()
    if args.requests <= 0:
        print("--requests must be greater than 0", file=sys.stderr)
        return 1
    if args.concurrency <= 0:
        print("--concurrency must be greater than 0", file=sys.stderr)
        return 1

    if args.eicar:
        filename, body = "eicar.com", EICAR
    elif args.sample:
        sample_path = Path(args.sample).expanduser().resolve()
        if not sample_path.is_file():
            print(f"Sample file not found: {sample_path}", file=sys.stderr)
            return 1
        filename, body = sample_path.name, sample_path.read_bytes()
    else:
        filename, body = "clean.txt", b"a clean harmless benchmark file\n"

    print(
        f"Sending {args.requests} REQMOD connections with concurrency "
        f"{args.concurrency} to icap://{args.host}:{args.port}/{args.service} "
        f"[{filename}, {len(body)} bytes]"
    )

    started_at = time.perf_counter()
    runs = run_benchmark(
        host=args.host,
        port=args.port,
        service=args.service,
        filename=filename,
        body=body,
        total_requests=args.requests,
        concurrency=args.concurrency,
        timeout=args.timeout,
    )
    benchmark_duration_ms = int((time.perf_counter() - started_at) * 1000)

    summary = summarize(runs, benchmark_duration_ms=benchmark_duration_ms)
    print_summary(summary)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Full JSON report written to {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
