import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
from time import perf_counter, sleep

from app.models import EngineResultInput, ScanRecord
from app.services.findings import evidence_object, normalized_finding
from app.services.sample_paths import resolve_sample_path, sample_path_error


ENGINE_NAME = "ClamAV"
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_CLAMD_PORT = 3310
DEFAULT_CLAMD_READY_TIMEOUT_SECONDS = 30
DEFAULT_CLAMD_RETRY_INTERVAL_SECONDS = 1.0
DEFAULT_MAX_FILE_SIZE_BYTES = 0
STREAM_CHUNK_SIZE = 1024 * 1024
CLAMD_LIMIT_HINT = (
    "clamd closed the scan stream. Check StreamMaxLength, MaxFileSize, "
    "MaxScanSize, and timeout settings for large samples."
)
# clamd enforces its own size caps (StreamMaxLength / MaxFileSize), configured on
# the clamav container and defaulting to 64M. They are invisible to this process
# unless the same values are also passed to the app and worker, which is what
# these variables are for. Without them, raising only the adapter cap lets a file
# through routing, reach clamd, and be rejected there -- surfacing as an opaque
# engine failure instead of a deliberate skip.
CLAMD_SIZE_LIMIT_ENV_VARS = ("MASP_CLAMD_STREAM_MAX_LENGTH", "MASP_CLAMD_MAX_FILE_SIZE")
DEFAULT_CLAMD_SIZE_LIMIT = "64M"
SIZE_SUFFIX_MULTIPLIERS = {"k": 1024, "m": 1024**2, "g": 1024**3}


def parse_size_bytes(value: str) -> int:
    """Parse a clamd-style size ("64M", "1G", "1048576") into bytes.

    Returns 0 for anything unparseable or non-positive, which callers read as
    "no limit configured" -- the same convention the adapter cap uses.
    """
    text = (value or "").strip().lower()
    if not text:
        return 0
    multiplier = 1
    if text[-1] in SIZE_SUFFIX_MULTIPLIERS:
        multiplier = SIZE_SUFFIX_MULTIPLIERS[text[-1]]
        text = text[:-1].strip()
    try:
        parsed = int(float(text) * multiplier)
    except ValueError:
        return 0
    return parsed if parsed > 0 else 0


def clamd_size_limit_bytes() -> int:
    """The smallest size cap clamd itself will enforce, in bytes (0 = unknown)."""
    limits = [
        parse_size_bytes(env_or_setting(var, f"clamav.{var.lower()}", DEFAULT_CLAMD_SIZE_LIMIT))
        for var in CLAMD_SIZE_LIMIT_ENV_VARS
    ]
    positive = [limit for limit in limits if limit > 0]
    return min(positive) if positive else 0


def effective_max_file_size(adapter_cap_bytes: int, clamd_cap_bytes: int) -> tuple[int, str]:
    """Combine the adapter cap and clamd's own cap into the binding limit.

    0 means "no limit" on either side, so the effective cap is the smallest
    positive one. Returns the limit and which layer produced it, so the skip
    reason can tell an operator *which* setting to raise -- the confusion FU-2
    was about.
    """
    candidates = [
        (adapter_cap_bytes, "adapter max_file_size_bytes"),
        (clamd_cap_bytes, "clamd StreamMaxLength/MaxFileSize"),
    ]
    positive = [(limit, source) for limit, source in candidates if limit > 0]
    if not positive:
        return 0, "unlimited"
    return min(positive, key=lambda item: item[0])


def get_clamav_config(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | int | float | bool]:
    override = config_override or {}
    clamd_host = setting_value(
        override,
        "host",
        env_or_setting("MASP_CLAMD_HOST", "clamav.host", ""),
    ).strip()
    if clamd_host:
        adapter_cap = setting_int(
            override,
            "max_file_size_bytes",
            env_or_setting(
                "MASP_CLAMAV_MAX_FILE_SIZE_BYTES",
                "clamav.max_file_size_bytes",
                str(DEFAULT_MAX_FILE_SIZE_BYTES),
            ),
            DEFAULT_MAX_FILE_SIZE_BYTES,
        )
        clamd_cap = clamd_size_limit_bytes()
        effective_cap, effective_source = effective_max_file_size(adapter_cap, clamd_cap)
        return {
            "mode": "clamd",
            "host": clamd_host,
            "port": setting_int(
                override,
                "port",
                env_or_setting("MASP_CLAMD_PORT", "clamav.port", str(DEFAULT_CLAMD_PORT)),
                DEFAULT_CLAMD_PORT,
            ),
            "timeout_seconds": setting_int(
                override,
                "timeout_seconds",
                env_or_setting(
                    "MASP_CLAMD_TIMEOUT_SECONDS",
                    "clamav.timeout_seconds",
                    str(DEFAULT_TIMEOUT_SECONDS),
                ),
                DEFAULT_TIMEOUT_SECONDS,
            ),
            "ready_timeout_seconds": setting_int(
                override,
                "ready_timeout_seconds",
                env_or_setting(
                    "MASP_CLAMD_READY_TIMEOUT_SECONDS",
                    "clamav.ready_timeout_seconds",
                    str(DEFAULT_CLAMD_READY_TIMEOUT_SECONDS),
                ),
                DEFAULT_CLAMD_READY_TIMEOUT_SECONDS,
            ),
            "retry_interval_seconds": setting_float(
                override,
                "retry_interval_seconds",
                env_or_setting(
                    "MASP_CLAMD_RETRY_INTERVAL_SECONDS",
                    "clamav.retry_interval_seconds",
                    str(DEFAULT_CLAMD_RETRY_INTERVAL_SECONDS),
                ),
                DEFAULT_CLAMD_RETRY_INTERVAL_SECONDS,
            ),
            "max_file_size_bytes": adapter_cap,
            # The limit routing must actually enforce: the adapter cap alone lets
            # a file reach clamd only to be rejected there. Reported alongside
            # its source so a skip can name the setting that needs raising.
            "effective_max_file_size_bytes": effective_cap,
            "effective_max_file_size_source": effective_source,
            "clamd_max_file_size_bytes": clamd_cap,
            "enabled": True,
        }

    command = setting_value(
        override,
        "command",
        env_or_setting("MASP_CLAMAV_COMMAND", "clamav.command", "clamscan"),
    )
    return {
        "mode": "cli",
        "command": command,
        "timeout_seconds": setting_int(
            override,
            "timeout_seconds",
            env_or_setting(
                "MASP_CLAMAV_TIMEOUT_SECONDS",
                "clamav.timeout_seconds",
                str(DEFAULT_TIMEOUT_SECONDS),
            ),
            DEFAULT_TIMEOUT_SECONDS,
        ),
        "max_file_size_bytes": setting_int(
            override,
            "max_file_size_bytes",
            env_or_setting(
                "MASP_CLAMAV_MAX_FILE_SIZE_BYTES",
                "clamav.max_file_size_bytes",
                str(DEFAULT_MAX_FILE_SIZE_BYTES),
            ),
            DEFAULT_MAX_FILE_SIZE_BYTES,
        ),
        "enabled": shutil.which(command) is not None,
    }


def check_clamav_health(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | bool]:
    config = get_clamav_config(config_override)
    if config["mode"] == "clamd":
        host = str(config["host"])
        port = int(config["port"])
        timeout = int(config["timeout_seconds"])
        try:
            response = ping_clamd(host, port, timeout)
        except (OSError, TimeoutError, socket.timeout) as exc:
            return {
                "ok": False,
                "status": "unreachable",
                "detail": f"Could not connect to clamd at {host}:{port}: {exc}",
            }

        return {
            "ok": response == "PONG",
            "status": "reachable" if response == "PONG" else "unexpected",
            "detail": f"clamd responded with {response!r}",
        }

    command = str(config["command"])
    path = shutil.which(command)
    if path is None:
        return {
            "ok": False,
            "status": "not configured",
            "detail": f"{command} was not found on PATH.",
        }

    return {
        "ok": True,
        "status": "available",
        "detail": f"{command} found at {path}.",
    }


def run_clamav_engine(
    scan: ScanRecord,
    config_override: dict[str, str] | None = None,
) -> EngineResultInput:
    config = get_clamav_config(config_override)
    if config["mode"] == "clamd":
        return run_clamd_scan(
            scan,
            str(config["host"]),
            int(config["port"]),
            int(config["timeout_seconds"]),
            int(config["ready_timeout_seconds"]),
            float(config["retry_interval_seconds"]),
        )
    return run_cli_scan(scan, str(config["command"]), int(config["timeout_seconds"]))


def run_clamd_scan(
    scan: ScanRecord,
    host: str,
    port: int,
    timeout: int,
    ready_timeout: int,
    retry_interval: float,
) -> EngineResultInput:
    started_at = perf_counter()

    sample_path = resolve_sample_path(scan)
    if not sample_path.is_file():
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=sample_path_error(scan, sample_path),
            error_message="Stored sample file is missing.",
            duration_ms=elapsed_ms(started_at),
            engine_version="clamd",
            details=clamav_details("clamd", scan, host=host, port=port, timeout=timeout),
        )

    try:
        raw_response = scan_with_clamd_when_ready(
            sample_path,
            host,
            port,
            timeout,
            ready_timeout,
            retry_interval,
        )
    except (BrokenPipeError, ConnectionResetError) as exc:
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=str(exc),
            error_message=CLAMD_LIMIT_HINT,
            duration_ms=elapsed_ms(started_at),
            engine_version="clamd",
            details=clamav_details(
                "clamd",
                scan,
                host=host,
                port=port,
                timeout=timeout,
                ready_timeout=ready_timeout,
                error=str(exc),
                hint="large_sample_stream_interrupted",
            ),
        )
    except (TimeoutError, socket.timeout) as exc:
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=str(exc),
            error_message=f"ClamAV timed out after {timeout} seconds.",
            duration_ms=elapsed_ms(started_at),
            engine_version="clamd",
            details=clamav_details(
                "clamd",
                scan,
                host=host,
                port=port,
                timeout=timeout,
                ready_timeout=ready_timeout,
                error=str(exc),
                hint="scan_timeout",
            ),
        )
    except OSError as exc:
        return build_result(
            status="skipped",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=str(exc),
            error_message=f"Could not connect to clamd at {host}:{port}.",
            duration_ms=elapsed_ms(started_at),
            engine_version="clamd",
            details=clamav_details(
                "clamd",
                scan,
                host=host,
                port=port,
                timeout=timeout,
                ready_timeout=ready_timeout,
                error=str(exc),
            ),
        )

    signature = parse_clamd_signature(raw_response)
    if raw_response.endswith(" OK"):
        return build_result(
            status="completed",
            detected=False,
            signature=None,
            severity="info",
            confidence=100,
            raw_output=raw_response,
            error_message=None,
            duration_ms=elapsed_ms(started_at),
            engine_version="clamd",
            details=clamav_details(
                "clamd",
                scan,
                host=host,
                port=port,
                timeout=timeout,
                response=raw_response,
            ),
        )

    if raw_response.endswith(" FOUND"):
        return build_result(
            status="completed",
            detected=True,
            signature=signature,
            severity="high",
            confidence=90,
            raw_output=raw_response,
            error_message=None,
            duration_ms=elapsed_ms(started_at),
            engine_version="clamd",
            details=clamav_details(
                "clamd",
                scan,
                host=host,
                port=port,
                timeout=timeout,
                response=raw_response,
                signature=signature,
            ),
            findings=clamav_findings(signature, raw_response),
        )

    if "size limit exceeded" in raw_response.lower():
        # clamd refused the sample for its own size cap. That is not an engine
        # malfunction -- it is this engine declining to scan -- so it is recorded
        # as a skip with the limit named, not as an opaque failure. Reaching here
        # at all means the pre-flight effective limit did not match clamd's real
        # configuration (see effective_max_file_size); the message says so, since
        # the fix is a configuration change, not a retry. Coverage is unaffected:
        # scoring counts skipped and failed alike as missing coverage, so the
        # scan still lands on "review" rather than a clean allow.
        return build_result(
            status="skipped",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=raw_response,
            error_message=(
                "Sample exceeds clamd's own size limit (StreamMaxLength/MaxFileSize). "
                "Raise it on the clamav service and mirror the value in "
                "MASP_CLAMD_STREAM_MAX_LENGTH / MASP_CLAMD_MAX_FILE_SIZE so the "
                "scan is skipped before streaming."
            ),
            duration_ms=elapsed_ms(started_at),
            engine_version="clamd",
            details=clamav_details(
                "clamd",
                scan,
                host=host,
                port=port,
                timeout=timeout,
                response=raw_response,
                hint="exceeds_clamd_size_limit",
            ),
        )

    if raw_response.endswith(" ERROR"):
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=raw_response,
            error_message=CLAMD_LIMIT_HINT,
            duration_ms=elapsed_ms(started_at),
            engine_version="clamd",
            details=clamav_details(
                "clamd",
                scan,
                host=host,
                port=port,
                timeout=timeout,
                response=raw_response,
                hint="large_sample_limit_or_stream_error",
            ),
        )

    return build_result(
        status="failed",
        detected=False,
        signature=None,
        severity="info",
        confidence=0,
        raw_output=raw_response,
        error_message="clamd returned an unrecognized response.",
        duration_ms=elapsed_ms(started_at),
        engine_version="clamd",
        details=clamav_details(
            "clamd",
            scan,
            host=host,
            port=port,
            timeout=timeout,
            response=raw_response,
        ),
    )


def run_cli_scan(scan: ScanRecord, command: str, timeout: int) -> EngineResultInput:
    started_at = perf_counter()

    if shutil.which(command) is None:
        return build_result(
            status="skipped",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=f"{command} was not found on PATH.",
            error_message="ClamAV is not installed or not configured.",
            duration_ms=elapsed_ms(started_at),
            engine_version="clamscan",
            details=clamav_details("cli", scan, command=command, timeout=timeout),
        )

    sample_path = resolve_sample_path(scan)
    if not sample_path.is_file():
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=sample_path_error(scan, sample_path),
            error_message="Stored sample file is missing.",
            duration_ms=elapsed_ms(started_at),
            engine_version="clamscan",
            details=clamav_details("cli", scan, command=command, timeout=timeout),
        )

    try:
        completed = subprocess.run(
            [command, "--no-summary", str(sample_path)],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=(exc.stdout or "") + (exc.stderr or ""),
            error_message=f"ClamAV timed out after {timeout} seconds.",
            duration_ms=elapsed_ms(started_at),
            engine_version="clamscan",
            details=clamav_details(
                "cli",
                scan,
                command=command,
                timeout=timeout,
                error="timeout",
            ),
        )
    except OSError as exc:
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=str(exc),
            error_message="ClamAV could not be executed.",
            duration_ms=elapsed_ms(started_at),
            engine_version="clamscan",
            details=clamav_details(
                "cli",
                scan,
                command=command,
                timeout=timeout,
                error=str(exc),
            ),
        )

    raw_output = "\n".join(
        part for part in [completed.stdout.strip(), completed.stderr.strip()] if part
    )
    signature = parse_signature(raw_output)

    if completed.returncode == 0:
        return build_result(
            status="completed",
            detected=False,
            signature=None,
            severity="info",
            confidence=100,
            raw_output=raw_output or "No threats found.",
            error_message=None,
            duration_ms=elapsed_ms(started_at),
            engine_version="clamscan",
            details=clamav_details(
                "cli",
                scan,
                command=command,
                timeout=timeout,
                returncode=completed.returncode,
                output=raw_output or "No threats found.",
            ),
        )

    if completed.returncode == 1:
        return build_result(
            status="completed",
            detected=True,
            signature=signature,
            severity="high",
            confidence=90,
            raw_output=raw_output,
            error_message=None,
            duration_ms=elapsed_ms(started_at),
            engine_version="clamscan",
            details=clamav_details(
                "cli",
                scan,
                command=command,
                timeout=timeout,
                returncode=completed.returncode,
                output=raw_output,
                signature=signature,
            ),
            findings=clamav_findings(signature, raw_output),
        )

    return build_result(
        status="failed",
        detected=False,
        signature=None,
        severity="info",
        confidence=0,
        raw_output=raw_output,
        error_message=f"ClamAV exited with code {completed.returncode}.",
        duration_ms=elapsed_ms(started_at),
        engine_version="clamscan",
        details=clamav_details(
            "cli",
            scan,
            command=command,
            timeout=timeout,
            returncode=completed.returncode,
            output=raw_output,
        ),
    )


def scan_with_clamd(sample_path: Path, host: str, port: int, timeout: int) -> str:
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(b"zINSTREAM\0")

        try:
            with sample_path.open("rb") as sample:
                while chunk := sample.read(STREAM_CHUNK_SIZE):
                    connection.sendall(struct.pack("!I", len(chunk)))
                    connection.sendall(chunk)

            connection.sendall(struct.pack("!I", 0))
        except (BrokenPipeError, ConnectionResetError) as exc:
            response = receive_clamd_response(
                connection,
                timeout_seconds=1.0,
                ignore_timeout=True,
            )
            if response:
                return response
            raise

        return receive_clamd_response(connection, timeout_seconds=float(timeout))


def receive_clamd_response(
    connection: socket.socket,
    timeout_seconds: float,
    ignore_timeout: bool = False,
) -> str:
    previous_timeout = connection.gettimeout()
    chunks = []
    try:
        connection.settimeout(timeout_seconds)
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    except (TimeoutError, socket.timeout):
        if not ignore_timeout:
            raise
        pass
    finally:
        connection.settimeout(previous_timeout)

    return b"".join(chunks).decode("utf-8", errors="replace").strip("\x00\r\n ")


def scan_with_clamd_when_ready(
    sample_path: Path,
    host: str,
    port: int,
    timeout: int,
    ready_timeout: int,
    retry_interval: float,
) -> str:
    started_at = perf_counter()
    last_error: OSError | TimeoutError | socket.timeout | None = None

    while True:
        try:
            return scan_with_clamd(sample_path, host, port, timeout)
        except (OSError, TimeoutError, socket.timeout) as exc:
            last_error = exc
            elapsed = perf_counter() - started_at
            if elapsed >= ready_timeout or not is_retryable_clamd_connection_error(exc):
                raise
            sleep(max(0.1, min(retry_interval, ready_timeout - elapsed)))

    if last_error is not None:
        raise last_error
    raise RuntimeError("clamd scan did not produce a result.")


def is_retryable_clamd_connection_error(exc: BaseException) -> bool:
    if isinstance(exc, (ConnectionRefusedError, TimeoutError, socket.timeout)):
        return True
    if isinstance(exc, OSError):
        return exc.errno in {
            111,  # Linux ECONNREFUSED
            10061,  # Windows WSAECONNREFUSED
        }
    return False


def ping_clamd(host: str, port: int, timeout: int) -> str:
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(b"zPING\0")
        response = connection.recv(4096)
    return response.decode("utf-8", errors="replace").strip("\x00\r\n ")


def parse_signature(raw_output: str) -> str | None:
    for line in raw_output.splitlines():
        if line.endswith(" FOUND"):
            _, _, finding = line.partition(": ")
            return finding.removesuffix(" FOUND").strip() or None
    return None


def parse_clamd_signature(raw_response: str) -> str | None:
    _, _, finding = raw_response.partition(": ")
    if not finding:
        return None
    return finding.removesuffix(" FOUND").strip() or None


def build_result(
    status: str,
    detected: bool,
    signature: str | None,
    severity: str,
    confidence: int,
    raw_output: str,
    error_message: str | None,
    duration_ms: int,
    engine_version: str | None,
    details: dict[str, object] | None = None,
    findings: list[dict[str, object]] | None = None,
) -> EngineResultInput:
    return EngineResultInput(
        engine_name=ENGINE_NAME,
        engine_version=engine_version,
        signature_version=None,
        status=status,
        detected=detected,
        signature=signature,
        severity=severity,
        confidence=confidence,
        raw_output=raw_output,
        error_message=error_message,
        duration_ms=duration_ms,
        details_json=json.dumps(details or {}, sort_keys=True),
        findings_json=json.dumps(findings or [], sort_keys=True),
    )


def clamav_details(
    mode: str,
    scan: ScanRecord,
    **extra: object,
) -> dict[str, object]:
    details: dict[str, object] = {
        "adapter": "clamav",
        "mode": mode,
        "sample": {
            "filename": scan.original_filename,
            "sha256": scan.sha256,
            "size_bytes": scan.size_bytes,
        },
    }
    details.update({key: value for key, value in extra.items() if value is not None})
    return details


def clamav_findings(
    signature: str | None,
    raw_output: str,
) -> list[dict[str, object]]:
    if not signature:
        return []
    return [
        normalized_finding(
            title=signature,
            finding_type="antivirus_signature",
            source=ENGINE_NAME,
            severity="high",
            confidence=90,
            action="detected",
            category=clamav_signature_category(signature),
            tags=["av", "signature"],
            evidence={
                "objects": [
                    evidence_object(
                        kind="signature",
                        value=signature,
                        metadata={"raw_response": raw_output},
                    )
                ],
                "raw_response": raw_output,
            },
            vendor_details={
                "signature": signature,
                "raw_response": raw_output,
            },
        )
    ]


def clamav_signature_category(signature: str) -> str:
    lowered = signature.lower()
    if "eicar" in lowered:
        return "test_file"
    if "phish" in lowered:
        return "phishing"
    if "trojan" in lowered:
        return "trojan"
    return "malware"


def elapsed_ms(started_at: float) -> int:
    return max(1, int((perf_counter() - started_at) * 1000))


def engine_setting(key: str, fallback: str) -> str:
    from app.database import get_setting

    value = get_setting(key, fallback)
    return fallback if value is None else value


def env_or_setting(env_key: str, setting_key: str, fallback: str) -> str:
    value = os.getenv(env_key)
    if value is not None:
        return value
    return engine_setting(setting_key, fallback)


def engine_setting_int(key: str, fallback: str, default: int) -> int:
    try:
        return int(engine_setting(key, fallback))
    except ValueError:
        return default


def setting_value(config_override: dict[str, str], key: str, fallback: str) -> str:
    """Resolve one setting, treating a blank override as "not configured".

    A present-but-empty value used to win over the fallback, which silently
    disabled features rather than falling back: saving the engine config form
    while the clamd host came from ``MASP_CLAMD_HOST`` persisted ``host=""``,
    and an empty host drops this engine into ``clamscan`` CLI mode -- a binary
    the app image does not contain, so every ClamAV scan failed. No setting here
    (host, command, executable paths, scan type) has a meaningful empty value,
    so blank now means unset for all of them.
    """
    value = config_override.get(key)
    if value is None or not value.strip():
        return fallback
    return value


def setting_int(
    config_override: dict[str, str],
    key: str,
    fallback: str,
    default: int,
) -> int:
    try:
        return int(setting_value(config_override, key, fallback))
    except ValueError:
        return default


def setting_float(
    config_override: dict[str, str],
    key: str,
    fallback: str,
    default: float,
) -> float:
    try:
        return float(setting_value(config_override, key, fallback))
    except ValueError:
        return default
