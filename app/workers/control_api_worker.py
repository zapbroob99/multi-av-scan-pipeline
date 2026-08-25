from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import ssl
import tempfile
import threading
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from app.models import EngineInstanceRecord, EngineResultInput, ScanRecord
from app.services.engine_registry import (
    adapter_capabilities,
    engine_health,
    run_engine,
)
from app.services.worker_capabilities import worker_engine_keys
from app.services.worker_runtime import (
    current_worker_node_id,
    worker_node_capacity,
    worker_node_labels,
    worker_poll_seconds,
)


class WorkerControlError(RuntimeError):
    pass


def control_url() -> str:
    value = os.getenv("MASP_WORKER_CONTROL_URL", "").strip().rstrip("/")
    if not value:
        raise WorkerControlError("MASP_WORKER_CONTROL_URL is required.")
    parsed = urlparse(value)
    allow_http = os.getenv(
        "MASP_WORKER_CONTROL_ALLOW_INSECURE_HTTP", "0"
    ).strip().lower() in {"1", "true", "yes", "on"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and allow_http):
        raise WorkerControlError(
            "Worker control URL must use HTTPS. Set "
            "MASP_WORKER_CONTROL_ALLOW_INSECURE_HTTP=1 only for local development."
        )
    return value


def agent_token() -> str:
    token_file = os.getenv("MASP_WORKER_AGENT_TOKEN_FILE", "").strip()
    if token_file:
        try:
            return Path(token_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise WorkerControlError(f"Unable to read worker token file: {exc}") from exc
    token = os.getenv("MASP_WORKER_AGENT_TOKEN", "").strip()
    if not token:
        raise WorkerControlError(
            "MASP_WORKER_AGENT_TOKEN or MASP_WORKER_AGENT_TOKEN_FILE is required."
        )
    return token


def ssl_context() -> ssl.SSLContext | None:
    ca_file = os.getenv("MASP_WORKER_CONTROL_CA_FILE", "").strip()
    return ssl.create_default_context(cafile=ca_file or None)


class WorkerControlClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.context = ssl_context() if self.base_url.startswith("https://") else None

    def _url(self, path: str) -> str:
        """Resolve API-relative and origin-relative paths without changing origin."""
        resolved = urljoin(self.base_url, path)
        base = urlparse(self.base_url)
        target = urlparse(resolved)

        def origin(parsed) -> tuple[str, str | None, int | None]:
            default_port = 443 if parsed.scheme == "https" else 80
            return parsed.scheme, parsed.hostname, parsed.port or default_port

        try:
            base_origin = origin(base)
            target_origin = origin(target)
        except ValueError as exc:
            raise WorkerControlError("Control API operation URL is invalid.") from exc
        if (
            not path
            or target.username is not None
            or target.password is not None
            or target_origin != base_origin
        ):
            raise WorkerControlError(
                "Control API operation URL must remain on the configured origin."
            )
        return resolved

    def _request(
        self,
        path: str,
        payload: dict[str, object],
        *,
        token: str | None = None,
    ):
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = Request(
            self._url(path),
            data=data,
            method="POST",
            headers={
                "Authorization": f"Bearer {token or self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "MASP-Worker-Agent/0.1",
            },
        )
        try:
            return urlopen(request, timeout=60, context=self.context)
        except HTTPError as exc:
            detail = exc.reason
            try:
                body = json.loads(exc.read().decode("utf-8"))
                detail = body.get("detail") or detail
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                pass
            raise WorkerControlError(f"Control API returned {exc.code}: {detail}") from exc
        except URLError as exc:
            raise WorkerControlError(f"Control API is unreachable: {exc.reason}") from exc

    def post_json(
        self,
        path: str,
        payload: dict[str, object],
        *,
        token: str | None = None,
    ) -> dict[str, object] | None:
        with self._request(path, payload, token=token) as response:
            if response.status == 204:
                return None
            try:
                parsed = json.loads(response.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise WorkerControlError("Control API returned invalid JSON.") from exc
        if not isinstance(parsed, dict):
            raise WorkerControlError("Control API returned an unexpected payload.")
        return parsed

    def download_sample(
        self,
        path: str,
        payload: dict[str, object],
        *,
        expected_sha256: str,
        expected_size: int,
        filename: str,
    ) -> Path:
        suffix = Path(filename).suffix[:32]
        digest = hashlib.sha256()
        size = 0
        handle = tempfile.NamedTemporaryFile(
            prefix="masp-agent-", suffix=suffix, delete=False
        )
        target = Path(handle.name)
        try:
            with handle, self._request(path, payload) as response:
                header_hash = response.headers.get("X-MASP-SHA256", "").lower()
                if header_hash and header_hash != expected_sha256.lower():
                    raise WorkerControlError("Server sample hash header does not match claim.")
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > expected_size:
                        raise WorkerControlError("Downloaded sample exceeded its declared size.")
                    digest.update(chunk)
                    handle.write(chunk)
            if size != expected_size:
                raise WorkerControlError(
                    f"Downloaded sample size mismatch: expected {expected_size}, got {size}."
                )
            if digest.hexdigest().lower() != expected_sha256.lower():
                raise WorkerControlError("Downloaded sample SHA-256 verification failed.")
            return target
        except Exception:
            target.unlink(missing_ok=True)
            raise


def identity_payload(*, process_id: int, runtime_state: str | None = None,
                     active_scan_id: int | None = None) -> dict[str, object]:
    hostname = socket.gethostname()
    payload: dict[str, object] = {
        "node_id": current_worker_node_id(),
        "display_name": os.getenv("MASP_WORKER_NODE_NAME", "").strip() or hostname,
        "hostname": hostname,
        "platform": platform.system().lower() or "unknown",
        "agent_version": os.getenv("MASP_WORKER_AGENT_VERSION", "0.1.0").strip()
        or "unknown",
        "labels": worker_node_labels(),
        "capacity": worker_node_capacity(),
        "engine_keys": sorted(worker_engine_keys()),
        "process_id": process_id,
    }
    if runtime_state is not None:
        payload["runtime_state"] = runtime_state
        payload["active_scan_id"] = active_scan_id
    return payload


def _dict(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise WorkerControlError(f"Claim omitted {label} metadata.")
    return value


def engine_from_claim(payload: dict[str, object]) -> EngineInstanceRecord:
    engine = _dict(payload.get("engine"), "engine")
    return EngineInstanceRecord(
        id=int(engine["id"]),
        adapter_key=str(engine["adapter_key"]),
        display_name=str(engine["display_name"]),
        enabled=True,
        config_json=json.dumps(_dict(engine.get("config", {}), "engine config")),
        created_at="",
        updated_at="",
    )


def scan_from_claim(payload: dict[str, object], local_path: Path) -> ScanRecord:
    job = _dict(payload.get("job"), "job")
    sample = _dict(payload.get("sample"), "sample")
    scan = _dict(payload.get("scan"), "scan")
    return ScanRecord(
        id=int(job["scan_id"]),
        sample_id=0,
        case_name="Remote worker",
        priority="Normal",
        note="",
        source=str(scan.get("source") or "manual"),
        status="running",
        verdict="pending",
        risk_score=None,
        created_at="",
        started_at=None,
        completed_at=None,
        failed_at=None,
        attempt_count=1,
        last_error=None,
        original_filename=str(sample["original_filename"]),
        stored_filename=local_path.name,
        storage_path=str(local_path),
        content_type=str(sample.get("content_type") or "application/octet-stream"),
        size_bytes=int(sample["size_bytes"]),
        md5=str(sample["md5"]),
        sha1=str(sample["sha1"]),
        sha256=str(sample["sha256"]),
        relative_path=(None if scan.get("relative_path") is None else str(scan["relative_path"])),
        scan_role=str(scan.get("role") or "standalone"),
    )


def result_payload(
    process_id: int,
    generation: int,
    lease_seconds: int,
    result: EngineResultInput,
) -> dict[str, object]:
    try:
        details = json.loads(result.details_json)
    except json.JSONDecodeError:
        details = {"raw_details": result.details_json}
    try:
        findings = json.loads(result.findings_json)
    except json.JSONDecodeError:
        findings = []
    return {
        "process_id": process_id,
        "attempt_generation": generation,
        "lease_seconds": lease_seconds,
        "status": result.status,
        "detected": result.detected,
        "severity": result.severity,
        "confidence": result.confidence,
        "signature": result.signature,
        "raw_output": result.raw_output,
        "duration_ms": result.duration_ms,
        "error_message": result.error_message,
        "engine_version": result.engine_version,
        "signature_version": result.signature_version,
        "details": details if isinstance(details, dict) else {},
        "findings": findings if isinstance(findings, list) else [],
    }


def run_claim(client: WorkerControlClient, claim: dict[str, object], process_id: int) -> None:
    job = _dict(claim.get("job"), "job")
    sample = _dict(claim.get("sample"), "sample")
    job_id = int(job["id"])
    generation = int(job["attempt_generation"])
    lease_seconds = int(job["lease_seconds"])
    ownership = {
        "process_id": process_id,
        "attempt_generation": generation,
        "lease_seconds": lease_seconds,
    }
    local_path = client.download_sample(
        str(sample["download_path"]),
        ownership,
        expected_sha256=str(sample["sha256"]),
        expected_size=int(sample["size_bytes"]),
        filename=str(sample["original_filename"]),
    )
    stop = threading.Event()

    def renew() -> None:
        while not stop.wait(max(5.0, lease_seconds / 3.0)):
            try:
                client.post_json(f"jobs/{job_id}/lease", ownership)
            except WorkerControlError as exc:
                print(f"Worker lease renewal stopped: {exc}", flush=True)
                return

    renewer = threading.Thread(target=renew, name=f"control-lease-{job_id}", daemon=True)
    renewer.start()
    try:
        engine = engine_from_claim(claim)
        scan = scan_from_claim(claim, local_path)
        print(f"Running {engine.display_name} for remote scan job {scan.id}", flush=True)
        result = run_engine(engine, scan)
    except Exception as exc:
        result = EngineResultInput(
            engine_name=str(_dict(claim.get("engine"), "engine").get("display_name") or "Unknown"),
            status="failed",
            detected=False,
            severity="info",
            confidence=0,
            signature=None,
            raw_output=f"Remote worker adapter failed: {type(exc).__name__}: {exc}",
            duration_ms=0,
            error_message=str(exc),
        )
    finally:
        stop.set()
        renewer.join()
        local_path.unlink(missing_ok=True)
    client.post_json(
        f"jobs/{job_id}/result",
        result_payload(process_id, generation, lease_seconds, result),
    )


def run_health_claim(
    client: WorkerControlClient,
    claim: dict[str, object],
    process_id: int,
) -> None:
    engine = engine_from_claim(claim)
    try:
        probe = engine_health(engine)
    except Exception as exc:
        probe = {
            "ok": False,
            "status": "unexpected",
            "detail": f"Health check raised {type(exc).__name__}: {exc}",
        }
    client.post_json(
        f"health/{engine.id}/result",
        {
            "process_id": process_id,
            "check_generation": int(claim["check_generation"]),
            "ok": bool(probe.get("ok")),
            "health_status": str(probe.get("status") or "unknown"),
            "detail": str(probe.get("detail") or "No health detail was returned."),
            "product_version": probe.get("product_version"),
            "engine_version": probe.get("engine_version"),
            "signature_version": probe.get("signature_version"),
            "service_state": probe.get("service_state"),
            # Remote agents receive samples through the authenticated download
            # endpoint, so central shared-storage access is intentionally N/A.
            "storage_readable": None,
            "storage_writable": None,
            "details": {
                "adapter_key": engine.adapter_key,
                "probe": probe,
                "sample_delivery": "control_api_download",
                "supports_file_upload": adapter_capabilities(
                    engine.adapter_key
                ).supports_file_upload,
            },
        },
    )


def enroll() -> str:
    enrollment_token = os.getenv("MASP_WORKER_ENROLLMENT_TOKEN", "").strip()
    if not enrollment_token:
        raise WorkerControlError("MASP_WORKER_ENROLLMENT_TOKEN is required for enrollment.")
    process_id = os.getpid()
    client = WorkerControlClient(control_url(), enrollment_token)
    response = client.post_json(
        "enroll", identity_payload(process_id=process_id), token=enrollment_token
    )
    if response is None or not response.get("agent_token"):
        raise WorkerControlError("Enrollment did not return an agent token.")
    return str(response["agent_token"])


def _wait(stop_event: threading.Event, seconds: float) -> bool:
    """Wait interruptibly; return True when service shutdown was requested."""
    return stop_event.wait(max(0.0, seconds))


def run_forever(stop_event: threading.Event | None = None) -> None:
    stop = stop_event or threading.Event()
    client = WorkerControlClient(control_url(), agent_token())
    process_id = os.getpid()
    poll_seconds = worker_poll_seconds()
    print(
        "MASP control API worker started "
        f"(node: {current_worker_node_id()}, engines: "
        f"{', '.join(sorted(worker_engine_keys())) or 'none'})",
        flush=True,
    )
    while not stop.is_set():
        try:
            client.post_json(
                "heartbeat",
                identity_payload(process_id=process_id, runtime_state="idle"),
            )
            health = client.post_json(
                "health/claim",
                {
                    "process_id": process_id,
                    "lease_seconds": 1200,
                    "interval_seconds": 60,
                },
            )
            if health is not None:
                run_health_claim(client, health, process_id)
            claim = client.post_json(
                "jobs/claim", {"process_id": process_id, "lease_seconds": 1200}
            )
            if claim is None:
                _wait(stop, poll_seconds)
                continue
            scan_id = int(_dict(claim.get("job"), "job")["scan_id"])
            client.post_json(
                "heartbeat",
                identity_payload(
                    process_id=process_id,
                    runtime_state="running",
                    active_scan_id=scan_id,
                ),
            )
            run_claim(client, claim, process_id)
        except WorkerControlError as exc:
            print(f"Worker control error, retrying: {exc}", flush=True)
            _wait(stop, poll_seconds)
    try:
        client.post_json(
            "heartbeat",
            identity_payload(process_id=process_id, runtime_state="stopping"),
        )
    except WorkerControlError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="MASP HTTPS worker agent")
    parser.add_argument(
        "--enroll",
        action="store_true",
        help="Enroll this node and print the one-time agent token.",
    )
    args = parser.parse_args()
    if args.enroll:
        print(enroll())
        return
    run_forever()


if __name__ == "__main__":
    main()
