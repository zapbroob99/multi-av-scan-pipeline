"""ESET Server Security for Linux adapter (on-demand CLI, `odscan`).

Stage A status: RESEARCH. This adapter is written against the official ESET
`odscan` exit-code contract but has NOT been validated against a real ESET
install. Anything that depends on the textual output format (threat-name
parsing) is deliberately minimal and marked FIXTURE-PENDING until a sanitized
fixture comes back from the corporate test environment (see
docs/integrations/ESET_SERVER_SECURITY.md).

Exit-code contract used (official Linux odscan):
  0   = no threat found          -> completed, clean
  1   = threat found and cleaned -> completed, DETECTED + warning (unexpected
                                    under --readonly, which must not clean)
  10  = some files not scanned   -> failed (unscannable; never "clean")
  50  = threat found             -> completed, DETECTED
  100 = error                    -> failed
  other/unknown                  -> failed
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from time import perf_counter

from app.models import EngineResultInput, ScanRecord
from app.services.sample_paths import resolve_sample_path, sample_path_error


ENGINE_NAME = "ESET Server Security"
ADAPTER_TAG = "eset_server_security_linux_cli"
DEFAULT_TIMEOUT_SECONDS = 300

# Standard ESET Server Security for Linux (EFS) install location. Not a secret;
# kept explicit so `executable_path=auto` works out of the box on a supported VM.
DEFAULT_ODSCAN_CANDIDATES = (
    "/opt/eset/efs/bin/odscan",
)


def get_eset_config(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | int | bool]:
    override = config_override or {}
    return {
        # Resolution: config_override -> DB setting -> MASP_ODSCAN_PATH env
        # (written by the worker bootstrap) -> "auto".
        "executable_path": setting_value(
            override,
            "executable_path",
            engine_setting(
                f"{ADAPTER_TAG}.executable_path",
                os.getenv("MASP_ODSCAN_PATH", "auto"),
            ),
        ).strip()
        or "auto",
        "timeout_seconds": setting_int(
            override,
            "timeout_seconds",
            engine_setting(
                f"{ADAPTER_TAG}.timeout_seconds", str(DEFAULT_TIMEOUT_SECONDS)
            ),
            DEFAULT_TIMEOUT_SECONDS,
        ),
        # Bypass ESET central-policy exclusions so an org exclusion cannot make
        # MASP report a scanned file "clean". Default on. Disabling it is a
        # security downgrade (see docs/integrations/ESET_SERVER_SECURITY.md).
        # FIXTURE-PENDING: --ignore-exclusions is fail-safe if the flag is
        # unsupported (scan errors out rather than returning a false clean).
        "ignore_exclusions": setting_bool(
            override,
            "ignore_exclusions",
            engine_setting(f"{ADAPTER_TAG}.ignore_exclusions", "true"),
        ),
    }


def resolve_odscan_path(configured_path: str) -> str | None:
    if configured_path and configured_path.lower() != "auto":
        return configured_path if Path(configured_path).is_file() else None

    for candidate in DEFAULT_ODSCAN_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    # Last resort: PATH lookup, for non-standard installs.
    return shutil.which("odscan")


def check_eset_health(
    config_override: dict[str, str] | None = None,
    *,
    config: dict[str, str | int | bool] | None = None,
) -> dict[str, str | bool]:
    """Health = executable presence ONLY. Runs NO subprocess.

    This is called at the start of every scan, so it must stay off the process
    hot path: no version/help probing here (that lives in tools/eset_discovery.py).
    The production health contract is finalized once a corporate fixture confirms
    a real version command (FIXTURE-PENDING).
    """
    if config is None:
        config = get_eset_config(config_override)

    if os.name == "nt":
        return {
            "ok": False,
            "status": "unsupported",
            "detail": "ESET Server Security for Linux adapter runs on Linux workers only.",
        }

    executable = resolve_odscan_path(str(config["executable_path"]))
    if executable is None:
        return {
            "ok": False,
            "status": "not configured",
            "detail": (
                "ESET odscan executable was not found. Set executable_path or "
                "install ESET Server Security for Linux on this worker."
            ),
        }

    return {
        "ok": True,
        "status": "available",
        "detail": f"ESET odscan found at {executable}.",
    }


def run_eset_server_security_linux_engine(
    scan: ScanRecord,
    config_override: dict[str, str] | None = None,
) -> EngineResultInput:
    started_at = perf_counter()
    config = get_eset_config(config_override)
    health = check_eset_health(config=config)
    base_details = {
        "adapter": ADAPTER_TAG,
        "support_state": "research",
        "sample": {
            "filename": scan.original_filename,
            "sha256": scan.sha256,
            "size_bytes": scan.size_bytes,
        },
        "config": {
            "executable_path": config["executable_path"],
            "timeout_seconds": config["timeout_seconds"],
            "ignore_exclusions": config["ignore_exclusions"],
        },
        "health": health,
    }

    if not bool(health["ok"]):
        return build_result(
            status="skipped",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=str(health["detail"]),
            error_message=f"ESET Server Security is not ready: {health['status']}.",
            duration_ms=elapsed_ms(started_at),
            details=base_details,
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
            details=base_details,
        )

    executable = resolve_odscan_path(str(config["executable_path"]))
    if executable is None:
        return build_result(
            status="skipped",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output="ESET odscan executable could not be resolved.",
            error_message="ESET odscan is not configured.",
            duration_ms=elapsed_ms(started_at),
            details=base_details,
        )

    scan_result = run_odscan(
        executable,
        sample_path,
        int(config["timeout_seconds"]),
        bool(config["ignore_exclusions"]),
    )
    base_details["scan_command"] = scan_result["command"]
    base_details["scan_returncode"] = scan_result["returncode"]
    base_details["scan_mode"] = "odscan_readonly"
    if scan_result["error_message"]:
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=str(scan_result["raw_output"]),
            error_message=str(scan_result["error_message"]),
            duration_ms=elapsed_ms(started_at),
            details=base_details,
        )

    return normalize_odscan_result(
        returncode=int(scan_result["returncode"]),
        raw_output=str(scan_result["raw_output"]),
        duration_ms=elapsed_ms(started_at),
        details=base_details,
    )


def run_odscan(
    executable: str,
    sample_path: Path,
    timeout_seconds: int,
    ignore_exclusions: bool = True,
) -> dict[str, object]:
    # --readonly: scan only, never clean/quarantine, so MASP's stored sample is
    # left byte-for-byte intact (verified with SHA-256 in the discovery tool).
    # --ignore-exclusions: do not honor central-policy exclusions, so an org
    # exclusion cannot yield a false "clean".
    command = [executable, "--scan", "--readonly"]
    if ignore_exclusions:
        command.append("--ignore-exclusions")
    command.append(str(sample_path))
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "returncode": -1,
            "raw_output": combined_output(exc.stdout, exc.stderr),
            "error_message": f"ESET odscan timed out after {timeout_seconds} seconds.",
        }
    except OSError as exc:
        return {
            "command": command,
            "returncode": -1,
            "raw_output": str(exc),
            "error_message": "ESET odscan could not be executed.",
        }

    return {
        "command": command,
        "returncode": completed.returncode,
        "raw_output": combined_output(completed.stdout, completed.stderr),
        "error_message": None,
    }


def normalize_odscan_result(
    returncode: int,
    raw_output: str,
    duration_ms: int,
    details: dict[str, object] | None = None,
) -> EngineResultInput:
    clean_raw = raw_output.strip() or "ESET odscan produced no output."

    if returncode == 0:
        return build_result(
            status="completed",
            detected=False,
            signature=None,
            severity="info",
            confidence=100,
            raw_output=clean_raw,
            error_message=None,
            duration_ms=duration_ms,
            details=details,
        )

    if returncode == 50:
        return build_result(
            status="completed",
            detected=True,
            # FIXTURE-PENDING: no threat-name parsing until a real fixture
            # confirms odscan's output format. A generic signature is safer
            # than a guessed parse that could mislabel detections.
            signature="ESET Server Security detection (threat name pending fixture)",
            severity="high",
            confidence=90,
            raw_output=clean_raw,
            error_message=None,
            duration_ms=duration_ms,
            details=details,
        )

    if returncode == 1:
        # Threat found AND cleaned. Under --readonly ESET should not clean, so
        # this is unexpected: still report DETECTED (fail safe) but flag it.
        return build_result(
            status="completed",
            detected=True,
            signature="ESET Server Security detection (threat name pending fixture)",
            severity="high",
            confidence=90,
            raw_output=clean_raw,
            error_message=(
                "odscan exit code 1 (threat found and cleaned) is unexpected under "
                "--readonly; treated as detection. Verify scan configuration."
            ),
            duration_ms=duration_ms,
            details=details,
        )

    if returncode == 10:
        # Unscannable files (e.g. encrypted archives). Never treat as clean.
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=clean_raw,
            error_message="odscan exit code 10: some files could not be scanned.",
            duration_ms=duration_ms,
            details=details,
        )

    if returncode == -1:
        error_message = "ESET odscan could not complete."
    elif returncode == 100:
        error_message = "odscan exit code 100: scan error."
    else:
        error_message = f"odscan exited with unexpected code {returncode}."

    return build_result(
        status="failed",
        detected=False,
        signature=None,
        severity="info",
        confidence=0,
        raw_output=clean_raw,
        error_message=error_message,
        duration_ms=duration_ms,
        details=details,
    )


def build_result(
    status: str,
    detected: bool,
    signature: str | None,
    severity: str,
    confidence: int,
    raw_output: str,
    error_message: str | None,
    duration_ms: int,
    details: dict[str, object] | None = None,
) -> EngineResultInput:
    return EngineResultInput(
        engine_name=ENGINE_NAME,
        engine_version=None,
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
        findings_json=json.dumps([], sort_keys=True),
    )


def combined_output(stdout: str | bytes | None, stderr: str | bytes | None) -> str:
    parts = []
    for value in (stdout, stderr):
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="replace")
        else:
            text = value or ""
        if text.strip():
            parts.append(text.strip())
    return "\n".join(parts)


def elapsed_ms(started_at: float) -> int:
    return max(1, int((perf_counter() - started_at) * 1000))


def engine_setting(key: str, fallback: str) -> str:
    from app.database import get_setting

    value = get_setting(key, fallback)
    return fallback if value is None else value


def setting_value(config_override: dict[str, str], key: str, fallback: str) -> str:
    value = config_override.get(key)
    if value is None:
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


def setting_bool(
    config_override: dict[str, str],
    key: str,
    fallback: str,
    *,
    safe_default: bool = True,
) -> bool:
    value = setting_value(config_override, key, fallback).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    # This flag prevents central exclusions from producing a false clean. A
    # typo or unknown value must therefore fail safe instead of disabling it.
    return safe_default
