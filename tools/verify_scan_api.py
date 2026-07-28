"""Acceptance verification for the MASP scan REST API integration.

Standalone, stdlib-only, and safe to ship to the integrating vendor: it
talks to MASP exclusively through the documented public REST contract
(see docs/integrations/API_SCAN_GATEWAY.md). It deliberately does NOT import
MASP application code, so the same file works from inside this repository
and from the distributed integration package.

Scenarios:
  - health probe
  - auth rejection (missing and malformed bearer token)
  - clean-file submission completes with decision.action == "allow"
  - asynchronous flow: wait_seconds=0 -> 202 + Location, result 409 while
    pending, polling until result_ready, then the final result payload
  - optional --eicar: EICAR test string is detected and blocked
  - optional --archive: ZIP submission exposes working batch endpoints
  - optional --expect-max-bytes N: an (N+1)-byte upload is rejected with 413

Engine coverage is validated generically (expected == reported == completed,
failed == 0, skipped == 0) so the tool keeps working when the MASP operator
adds engines. Use --require-engine (repeatable) to additionally require
specific engines by name.

The bearer token is read from --token or the MASP_API_TOKEN environment
variable and is never echoed to stdout, stderr, or report files.

Exit code 0 = all executed checks passed; 1 = at least one check failed.

SECURITY NOTE about --eicar: the EICAR string is the industry-standard
harmless antivirus test file (see eicar.org). This tool assembles it in
memory from fragments and uploads it directly, so no EICAR file is written
to disk on the client. Endpoint protection on the machine running this tool
may still react to the network upload; run it only where your security team
expects antivirus test traffic.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
import uuid
import zipfile
from pathlib import Path
from urllib import error, request


# Assembled from fragments so this file itself never contains the contiguous
# EICAR signature (which endpoint protection could quarantine).
EICAR_PARTS = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
    "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
    "!$H+H*",
)


def eicar_bytes() -> bytes:
    return "".join(EICAR_PARTS).encode("ascii")


class CheckFailure(AssertionError):
    pass


class Reporter:
    def __init__(self) -> None:
        self.results: list[dict[str, str]] = []

    def record(self, name: str, status: str, detail: str = "") -> None:
        self.results.append({"check": name, "status": status, "detail": detail})
        marker = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP"}[status]
        line = f"[{marker}] {name}"
        if detail:
            line += f" — {detail}"
        print(line)

    @property
    def failed(self) -> bool:
        return any(result["status"] == "FAIL" for result in self.results)


class ApiClient:
    def __init__(self, base_url: str, token: str, request_timeout: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.request_timeout = request_timeout

    def call(
        self,
        method: str,
        path_or_url: str,
        *,
        body: bytes | None = None,
        content_type: str | None = None,
        auth: str | None = "bearer",
    ) -> tuple[int, dict[str, str], dict]:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base_url}{path_or_url}"
        headers = {"Accept": "application/json"}
        if auth == "bearer":
            headers["Authorization"] = f"Bearer {self.token}"
        elif auth == "malformed":
            headers["Authorization"] = "Basic invalid-scheme"
        if content_type:
            headers["Content-Type"] = content_type
        req = request.Request(url, data=body, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=self.request_timeout) as response:
                payload = json.loads(response.read() or b"{}")
                return response.status, {k.lower(): v for k, v in response.headers.items()}, payload
        except error.HTTPError as exc:
            raw = exc.read() or b"{}"
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = {"raw": raw.decode("utf-8", "replace")}
            return exc.code, {k.lower(): v for k, v in exc.headers.items()}, payload

    def submit(
        self,
        filename: str,
        data: bytes,
        *,
        wait_seconds: int,
        note: str,
    ) -> tuple[int, dict[str, str], dict]:
        fields = {
            "case_name": "API-VERIFY",
            "priority": "Normal",
            "note": note,
            "wait_seconds": str(wait_seconds),
        }
        boundary = f"masp-verify-{uuid.uuid4().hex}"
        chunks: list[bytes] = []
        for field_name, field_value in fields.items():
            chunks.extend(
                [
                    f"--{boundary}\r\n".encode("utf-8"),
                    f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'.encode("utf-8"),
                    field_value.encode("utf-8"),
                    b"\r\n",
                ]
            )
        chunks.extend(
            [
                f"--{boundary}\r\n".encode("utf-8"),
                f'Content-Disposition: form-data; name="sample"; filename="{filename}"\r\n'.encode("utf-8"),
                b"Content-Type: application/octet-stream\r\n\r\n",
                data,
                b"\r\n",
                f"--{boundary}--\r\n".encode("utf-8"),
            ]
        )
        return self.call(
            "POST",
            "/api/v1/scans",
            body=b"".join(chunks),
            content_type=f"multipart/form-data; boundary={boundary}",
        )


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def normalize_engine_name(name: str) -> str:
    return "".join(char for char in name.lower() if char.isalnum())


def assert_full_coverage(payload: dict, required_engines: list[str], context: str) -> None:
    engines = payload.get("engines") or {}
    expected = engines.get("expected")
    reported = engines.get("reported")
    completed = engines.get("completed")
    expect(
        expected is not None and expected > 0,
        f"{context}: engines.expected missing or zero ({expected!r})",
    )
    expect(
        expected == reported == completed,
        f"{context}: expected={expected} reported={reported} completed={completed} must all match",
    )
    expect(engines.get("failed") == 0, f"{context}: engines.failed={engines.get('failed')} (want 0)")
    expect(engines.get("skipped") == 0, f"{context}: engines.skipped={engines.get('skipped')} (want 0)")

    results = payload.get("engine_results") or []
    for result in results:
        expect(
            result.get("status") == "completed",
            f"{context}: engine {result.get('engine_name')!r} status={result.get('status')!r} (want completed)",
        )
    present = {normalize_engine_name(str(result.get("engine_name", ""))) for result in results}
    for required in required_engines:
        expect(
            normalize_engine_name(required) in present,
            f"{context}: required engine {required!r} missing from engine_results {sorted(present)}",
        )


def poll_until_ready(
    client: ApiClient,
    status_url: str,
    *,
    poll_interval: float,
    total_timeout: float,
) -> dict:
    deadline = time.monotonic() + total_timeout
    while True:
        status, _, payload = client.call("GET", status_url)
        expect(status == 200, f"status poll returned HTTP {status}")
        if payload.get("result_ready"):
            return payload
        expect(
            time.monotonic() < deadline,
            f"scan did not reach a terminal state within {total_timeout:.0f}s "
            f"(status={payload.get('scan', {}).get('status')!r})",
        )
        time.sleep(poll_interval)


def capture(capture_dir: Path | None, name: str, payload: object) -> None:
    if capture_dir is None:
        return
    capture_dir.mkdir(parents=True, exist_ok=True)
    path = capture_dir / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run_checks(args: argparse.Namespace, client: ApiClient, reporter: Reporter) -> None:
    capture_dir = Path(args.capture_dir) if args.capture_dir else None
    required_engines: list[str] = args.require_engine or []

    def check(name: str, func) -> None:
        try:
            detail = func()
        except CheckFailure as exc:
            reporter.record(name, "FAIL", str(exc))
        except Exception as exc:  # communication/parse errors are failures too
            reporter.record(name, "FAIL", f"unexpected error: {exc}")
        else:
            reporter.record(name, "PASS", detail or "")

    # 1. Health probe (unauthenticated by contract).
    def health() -> str:
        status, _, payload = client.call("GET", "/health", auth=None)
        expect(status == 200, f"GET /health returned HTTP {status}")
        expect(payload.get("status") == "ok", f"unexpected health body: {payload}")
        capture(capture_dir, "health-200", payload)
        return "GET /health -> 200 ok"

    check("health", health)

    # 2. Missing bearer token is rejected.
    def auth_missing() -> str:
        status, headers, payload = client.call("GET", "/api/v1/scans/999999", auth=None)
        expect(status == 401, f"expected 401 without token, got {status}")
        expect(headers.get("www-authenticate") == "Bearer", "WWW-Authenticate: Bearer header missing")
        capture(capture_dir, "auth-missing-401", payload)
        return "401 + WWW-Authenticate: Bearer"

    check("auth-missing-token", auth_missing)

    # 3. Malformed Authorization scheme is rejected.
    def auth_malformed() -> str:
        status, headers, _ = client.call("GET", "/api/v1/scans/999999", auth="malformed")
        expect(status == 401, f"expected 401 for malformed scheme, got {status}")
        expect(headers.get("www-authenticate") == "Bearer", "WWW-Authenticate: Bearer header missing")
        return "401 for non-Bearer Authorization"

    check("auth-malformed-token", auth_malformed)

    # 4. Clean file completes with decision allow and full engine coverage.
    def clean_allow() -> str:
        data = f"MASP API verification clean sample {uuid.uuid4().hex}\n".encode("ascii")
        status, headers, payload = client.submit(
            "api-verify-clean.txt", data, wait_seconds=args.wait_seconds, note="api verify clean"
        )
        expect(status in (200, 202), f"submit returned HTTP {status}")
        expect(payload.get("accepted") is True, "accepted flag missing/false")
        location = headers.get("location")
        expect(bool(location), "Location header missing")
        if status == 202:
            payload = poll_until_ready(
                client, location, poll_interval=args.poll_interval, total_timeout=args.total_timeout
            )
        else:
            capture(capture_dir, "submit-clean-200", payload)
        assert_full_coverage(payload, required_engines, "clean scan")
        decision = (payload.get("decision") or {}).get("action")
        expect(decision == "allow", f"clean file decision={decision!r} (want allow)")
        result_url = (payload.get("links") or {}).get("result")
        expect(bool(result_url), "links.result missing")
        res_status, _, result_payload = client.call("GET", result_url)
        expect(res_status == 200, f"result endpoint returned HTTP {res_status}")
        expect(result_payload.get("result_ready") is True, "result_ready is not true")
        expect(
            (result_payload.get("decision") or {}).get("action") == "allow",
            "result decision is not allow",
        )
        capture(capture_dir, "result-clean-200", result_payload)
        return f"decision=allow with full coverage (HTTP {status} submit)"

    check("clean-file-allow", clean_allow)

    # 5. Asynchronous flow: 202 + polling + 409 while pending.
    def async_polling() -> str:
        data = f"MASP API verification async sample {uuid.uuid4().hex}\n".encode("ascii")
        status, headers, payload = client.submit(
            "api-verify-async.txt", data, wait_seconds=0, note="api verify async"
        )
        expect(status == 202, f"wait_seconds=0 submit returned HTTP {status} (want 202)")
        expect(payload.get("accepted") is True, "accepted flag missing/false")
        expect(payload.get("result_ready") is False, "202 body claims result_ready")
        location = headers.get("location")
        expect(bool(location), "Location header missing on 202")
        expect(bool(headers.get("retry-after")), "Retry-After header missing on 202")
        capture(capture_dir, "submit-async-202", payload)

        result_url = (payload.get("links") or {}).get("result")
        expect(bool(result_url), "links.result missing on 202 body")
        early_status, early_headers, early_payload = client.call("GET", result_url)
        not_ready_note = ""
        if early_status == 409:
            expect(
                bool(early_headers.get("retry-after")),
                "409 result response is missing Retry-After",
            )
            expect(early_payload.get("result_ready") is False, "409 body claims result_ready")
            capture(capture_dir, "result-pending-409", early_payload)
            not_ready_note = ", 409-while-pending confirmed"
        else:
            expect(
                early_status == 200,
                f"early result fetch returned HTTP {early_status} (want 409 or 200)",
            )
            not_ready_note = ", scan finished before the 409 probe (409 path not exercised)"

        final_payload = poll_until_ready(
            client, location, poll_interval=args.poll_interval, total_timeout=args.total_timeout
        )
        capture(capture_dir, "status-ready-200", final_payload)
        assert_full_coverage(final_payload, required_engines, "async scan")
        expect(
            (final_payload.get("decision") or {}).get("action") == "allow",
            "async clean scan decision is not allow",
        )
        res_status, _, result_payload = client.call("GET", result_url)
        expect(res_status == 200, f"final result fetch returned HTTP {res_status}")
        expect(result_payload.get("result_ready") is True, "final result_ready is not true")
        return f"202 -> poll -> result_ready{not_ready_note}"

    check("async-202-polling", async_polling)

    # 6. EICAR detection (optional).
    def eicar_block() -> str:
        status, headers, payload = client.submit(
            "api-verify-eicar.com", eicar_bytes(), wait_seconds=args.wait_seconds, note="api verify eicar"
        )
        expect(status in (200, 202), f"EICAR submit returned HTTP {status}")
        if status == 202:
            payload = poll_until_ready(
                client,
                headers.get("location", ""),
                poll_interval=args.poll_interval,
                total_timeout=args.total_timeout,
            )
        assert_full_coverage(payload, required_engines, "eicar scan")
        engines = payload.get("engines") or {}
        expect(
            engines.get("detections", 0) >= 1,
            f"EICAR produced no detections (engines={engines})",
        )
        decision = (payload.get("decision") or {}).get("action")
        expect(decision == "block", f"EICAR decision={decision!r} (want block)")
        result_url = (payload.get("links") or {}).get("result")
        res_status, _, result_payload = client.call("GET", result_url)
        expect(res_status == 200, f"EICAR result endpoint returned HTTP {res_status}")
        expect(
            (result_payload.get("decision") or {}).get("action") == "block",
            "EICAR result decision is not block",
        )
        capture(capture_dir, "result-eicar-200", result_payload)
        detections = engines.get("detections")
        return f"decision=block with {detections} detection(s)"

    if args.eicar:
        check("eicar-block", eicar_block)
    else:
        reporter.record("eicar-block", "SKIP", "enable with --eicar")

    # 7. Archive/batch contract (optional).
    def archive_batch() -> str:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("docs/readme.txt", f"clean archive member {uuid.uuid4().hex}\n")
            archive.writestr("docs/notes.txt", "second clean member\n")
        status, headers, payload = client.submit(
            "api-verify-archive.zip", buffer.getvalue(), wait_seconds=args.wait_seconds, note="api verify archive"
        )
        expect(status in (200, 202), f"archive submit returned HTTP {status}")
        if status == 202:
            payload = poll_until_ready(
                client,
                headers.get("location", ""),
                poll_interval=args.poll_interval,
                total_timeout=args.total_timeout,
            )
        batch_links = payload.get("batch_links") or {}
        expect(bool(batch_links.get("status")), "batch_links.status missing for archive submission")
        batch_status_code, _, batch_payload = client.call("GET", batch_links["status"])
        expect(batch_status_code == 200, f"batch status returned HTTP {batch_status_code}")
        expect("batch" in batch_payload and "scans" in batch_payload, "batch status body incomplete")
        capture(capture_dir, "batch-status-200", batch_payload)

        deadline = time.monotonic() + args.total_timeout
        while not batch_payload.get("result_ready"):
            expect(time.monotonic() < deadline, "batch did not complete in time")
            time.sleep(args.poll_interval)
            batch_status_code, _, batch_payload = client.call("GET", batch_links["status"])
            expect(batch_status_code == 200, f"batch status returned HTTP {batch_status_code}")

        batch_result_code, _, batch_result = client.call("GET", batch_links["result"])
        expect(batch_result_code == 200, f"batch result returned HTTP {batch_result_code}")
        expect(bool(batch_result.get("scans")), "batch result carries no scans")
        capture(capture_dir, "batch-result-200", batch_result)
        return f"batch endpoints OK ({len(batch_result.get('scans', []))} scan(s) in batch)"

    if args.archive:
        check("archive-batch", archive_batch)
    else:
        reporter.record("archive-batch", "SKIP", "enable with --archive")

    # 8. Upload size cap (optional; requires the server to enforce a limit).
    def oversize_rejected() -> str:
        oversize = args.expect_max_bytes + 1
        status, _, payload = client.submit(
            "api-verify-oversize.bin", b"\0" * oversize, wait_seconds=0, note="api verify oversize"
        )
        expect(status == 413, f"{oversize}-byte upload returned HTTP {status} (want 413)")
        capture(capture_dir, "upload-oversize-413", payload)
        return f"{oversize}-byte upload rejected with 413"

    if args.expect_max_bytes:
        check("upload-413", oversize_rejected)
    else:
        reporter.record("upload-413", "SKIP", "enable with --expect-max-bytes <configured limit>")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify the MASP scan REST API integration contract end to end."
    )
    parser.add_argument("--base-url", required=True, help="Example: https://masp.example.internal")
    parser.add_argument(
        "--token",
        default="",
        help="Bearer token; falls back to the MASP_API_TOKEN environment variable",
    )
    parser.add_argument("--eicar", action="store_true", help="Run the EICAR detection/block scenario")
    parser.add_argument("--archive", action="store_true", help="Run the ZIP/batch endpoint scenario")
    parser.add_argument(
        "--expect-max-bytes",
        type=int,
        default=0,
        help="Server-side MASP_UPLOAD_MAX_BYTES value; enables the 413 scenario",
    )
    parser.add_argument(
        "--require-engine",
        action="append",
        default=None,
        metavar="NAME",
        help="Require this engine to appear in engine_results (repeatable)",
    )
    parser.add_argument("--wait-seconds", type=int, default=30, help="wait_seconds for synchronous submissions")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Seconds between status polls")
    parser.add_argument("--total-timeout", type=float, default=180.0, help="Max seconds to wait per scan")
    parser.add_argument("--request-timeout", type=int, default=60, help="Per-request HTTP timeout in seconds")
    parser.add_argument(
        "--capture-dir",
        default="",
        help="Directory to write captured response JSON (token is never written)",
    )
    parser.add_argument(
        "--report",
        default="",
        help="Optional path for a JSON report of check outcomes (token is never written)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    token = args.token or os.environ.get("MASP_API_TOKEN", "")
    if not token:
        print("No token given: pass --token or set MASP_API_TOKEN.", file=sys.stderr)
        return 1

    client = ApiClient(args.base_url, token, args.request_timeout)
    reporter = Reporter()
    run_checks(args, client, reporter)

    passed = sum(1 for result in reporter.results if result["status"] == "PASS")
    failed = sum(1 for result in reporter.results if result["status"] == "FAIL")
    skipped = sum(1 for result in reporter.results if result["status"] == "SKIP")
    print(f"\nSummary: {passed} passed, {failed} failed, {skipped} skipped")

    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(
                {
                    "base_url": args.base_url,
                    "results": reporter.results,
                    "summary": {"passed": passed, "failed": failed, "skipped": skipped},
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"Report written to {report_path}")

    return 1 if reporter.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
