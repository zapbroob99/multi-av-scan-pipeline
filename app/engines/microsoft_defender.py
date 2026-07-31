import json
import os
from pathlib import Path
import shutil
import subprocess
from time import monotonic, perf_counter

from app.models import EngineResultInput, ScanRecord
from app.services.findings import evidence_object, normalized_finding
from app.services.sample_paths import resolve_sample_path, sample_path_error


ENGINE_NAME = "Microsoft Defender"
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_SIGNATURE_STALE_DAYS = 3
DEFAULT_SCAN_TYPE = "custom"
DEFAULT_HEALTH_CACHE_SECONDS = 30
# Negative (ok=False) health results get a much shorter TTL so a transient
# PowerShell/Defender hiccup does not skip every scan for the full positive TTL.
DEFAULT_NEGATIVE_HEALTH_CACHE_SECONDS = 5

# Per-worker-process TTL caches. The Defender health probe shells out to
# PowerShell (Get-MpComputerStatus) and MpCmdRun path resolution walks the
# filesystem; both are stable for the life of a worker between config changes,
# so caching them per process removes that fixed cost from every scan.
_health_cache: dict[tuple, tuple[float, dict[str, str | bool]]] = {}
_mpcmdrun_path_cache: dict[str, tuple[float, str | None]] = {}


def health_cache_seconds() -> int:
    raw = os.getenv(
        "MASP_MICROSOFT_DEFENDER_HEALTH_CACHE_SECONDS",
        str(DEFAULT_HEALTH_CACHE_SECONDS),
    ).strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_HEALTH_CACHE_SECONDS


def negative_health_cache_seconds() -> int:
    raw = os.getenv(
        "MASP_MICROSOFT_DEFENDER_NEGATIVE_HEALTH_CACHE_SECONDS",
        str(DEFAULT_NEGATIVE_HEALTH_CACHE_SECONDS),
    ).strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_NEGATIVE_HEALTH_CACHE_SECONDS


def defender_health_cache_key(config: dict[str, str | int | bool]) -> tuple:
    # Only fields that can change the health verdict belong in the key, so a
    # scan-type or update-before-scan change does not needlessly invalidate.
    return (
        str(config["execution_mode"]),
        str(config["powershell_path"]),
        str(config["mpcmdrun_path"]),
        int(config["timeout_seconds"]),
        bool(config["require_real_time_enabled"]),
    )


def clear_defender_caches() -> None:
    _health_cache.clear()
    _mpcmdrun_path_cache.clear()


def get_microsoft_defender_config(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | int | bool]:
    override = config_override or {}
    return {
        "execution_mode": setting_value(
            override,
            "execution_mode",
            engine_setting("microsoft_defender.execution_mode", "powershell"),
        ).strip().lower()
        or "powershell",
        "powershell_path": setting_value(
            override,
            "powershell_path",
            engine_setting("microsoft_defender.powershell_path", "powershell.exe"),
        ).strip()
        or "powershell.exe",
        "mpcmdrun_path": setting_value(
            override,
            "mpcmdrun_path",
            engine_setting("microsoft_defender.mpcmdrun_path", "auto"),
        ).strip()
        or "auto",
        "default_scan_type": setting_value(
            override,
            "default_scan_type",
            engine_setting("microsoft_defender.default_scan_type", DEFAULT_SCAN_TYPE),
        ).strip().lower()
        or DEFAULT_SCAN_TYPE,
        "timeout_seconds": setting_int(
            override,
            "timeout_seconds",
            engine_setting("microsoft_defender.timeout_seconds", str(DEFAULT_TIMEOUT_SECONDS)),
            DEFAULT_TIMEOUT_SECONDS,
        ),
        "update_before_scan": setting_bool(
            override,
            "update_before_scan",
            engine_setting("microsoft_defender.update_before_scan", "false"),
        ),
        "require_real_time_enabled": setting_bool(
            override,
            "require_real_time_enabled",
            engine_setting("microsoft_defender.require_real_time_enabled", "true"),
        ),
    }


def check_microsoft_defender_health(
    config_override: dict[str, str] | None = None,
    *,
    config: dict[str, str | int | bool] | None = None,
) -> dict[str, str | bool]:
    if config is None:
        config = get_microsoft_defender_config(config_override)
    if os.name != "nt":
        return {
            "ok": False,
            "status": "unsupported",
            "detail": "Microsoft Defender local CLI is only supported on Windows workers.",
        }

    powershell_path = resolve_powershell_path(str(config["powershell_path"]))
    if powershell_path is None:
        return {
            "ok": False,
            "status": "not configured",
            "detail": f"PowerShell executable {config['powershell_path']!r} could not be resolved.",
        }

    timeout_seconds = int(config["timeout_seconds"])
    status_result = get_mpcomputerstatus(powershell_path, timeout_seconds)
    if not status_result["ok"]:
        return {
            "ok": False,
            "status": str(status_result["status"]),
            "detail": str(status_result["detail"]),
        }

    payload = status_result["payload"]
    if not isinstance(payload, dict):
        return {
            "ok": False,
            "status": "unexpected",
            "detail": "Get-MpComputerStatus returned an unexpected payload shape.",
        }

    evaluated = evaluate_status_payload(
        payload,
        require_real_time_enabled=bool(config["require_real_time_enabled"]),
    )

    if str(config["execution_mode"]) == "mpcmdrun":
        resolved_mpcmdrun = resolve_mpcmdrun_path(str(config["mpcmdrun_path"]))
        if resolved_mpcmdrun is None:
            return {
                "ok": False,
                "status": "not configured",
                "detail": "MpCmdRun.exe could not be resolved from configured path or default Defender locations.",
            }

    return evaluated


def cached_microsoft_defender_health(
    config: dict[str, str | int | bool],
    config_override: dict[str, str] | None = None,
) -> dict[str, str | bool]:
    """Health probe with a per-process TTL cache keyed by health-affecting config.

    ``ok=True`` results are cached for the positive TTL
    (``MASP_MICROSOFT_DEFENDER_HEALTH_CACHE_SECONDS``, default 30); ``ok=False``
    results only for the short negative TTL
    (``MASP_MICROSOFT_DEFENDER_NEGATIVE_HEALTH_CACHE_SECONDS``, default 5) so a
    transient failure does not skip every scan for the full positive window.
    Re-probes on TTL expiry, config change, or when caching is disabled (both
    TTLs 0).
    """
    positive_ttl = health_cache_seconds()
    negative_ttl = negative_health_cache_seconds()
    if positive_ttl <= 0 and negative_ttl <= 0:
        return check_microsoft_defender_health(config_override, config=config)

    key = defender_health_cache_key(config)
    now = monotonic()
    entry = _health_cache.get(key)
    if entry is not None and entry[0] > now:
        return entry[1]

    result = check_microsoft_defender_health(config_override, config=config)
    ttl = positive_ttl if bool(result["ok"]) else negative_ttl
    if ttl > 0:
        _health_cache[key] = (now + ttl, result)
    return result


def run_microsoft_defender_engine(
    scan: ScanRecord,
    config_override: dict[str, str] | None = None,
) -> EngineResultInput:
    started_at = perf_counter()
    config = get_microsoft_defender_config(config_override)
    health = cached_microsoft_defender_health(config, config_override)
    base_details = {
        "adapter": "microsoft_defender_local_cli",
        "sample": {
            "filename": scan.original_filename,
            "sha256": scan.sha256,
            "size_bytes": scan.size_bytes,
        },
        "config": {
            "execution_mode": config["execution_mode"],
            "default_scan_type": config["default_scan_type"],
            "timeout_seconds": config["timeout_seconds"],
            "update_before_scan": config["update_before_scan"],
            "require_real_time_enabled": config["require_real_time_enabled"],
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
            error_message=f"Microsoft Defender is not ready: {health['status']}.",
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

    resolved_mpcmdrun = resolve_mpcmdrun_path(str(config["mpcmdrun_path"]))
    if resolved_mpcmdrun is None:
        return build_result(
            status="skipped",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output="MpCmdRun.exe could not be resolved.",
            error_message="Microsoft Defender MpCmdRun.exe is not configured.",
            duration_ms=elapsed_ms(started_at),
            details=base_details,
        )

    if bool(config["update_before_scan"]):
        update_result = run_mpcmdrun_signature_update(
            resolved_mpcmdrun,
            int(config["timeout_seconds"]),
        )
        base_details["signature_update"] = update_result
        if not bool(update_result["ok"]):
            return build_result(
                status="failed",
                detected=False,
                signature=None,
                severity="info",
                confidence=0,
                raw_output=str(update_result["raw_output"]),
                error_message=str(update_result["error_message"]),
                duration_ms=elapsed_ms(started_at),
                details=base_details,
            )

    scan_result = run_mpcmdrun_custom_scan(
        resolved_mpcmdrun,
        sample_path,
        int(config["timeout_seconds"]),
    )
    base_details["scan_command"] = scan_result["command"]
    base_details["scan_returncode"] = scan_result["returncode"]
    base_details["scan_mode"] = "mpcmdrun_custom_disable_remediation"
    return normalize_mpcmdrun_scan_result(
        returncode=int(scan_result["returncode"]),
        raw_output=str(scan_result["raw_output"]),
        duration_ms=elapsed_ms(started_at),
        details=base_details,
    )


def resolve_powershell_path(configured_path: str) -> str | None:
    if Path(configured_path).is_file():
        return configured_path
    return shutil.which(configured_path)


def resolve_mpcmdrun_path(configured_path: str) -> str | None:
    ttl = health_cache_seconds()
    if ttl <= 0:
        return _resolve_mpcmdrun_path_uncached(configured_path)

    now = monotonic()
    entry = _mpcmdrun_path_cache.get(configured_path)
    if entry is not None and entry[0] > now:
        return entry[1]

    resolved = _resolve_mpcmdrun_path_uncached(configured_path)
    _mpcmdrun_path_cache[configured_path] = (now + ttl, resolved)
    return resolved


def _resolve_mpcmdrun_path_uncached(configured_path: str) -> str | None:
    if configured_path and configured_path.lower() != "auto":
        return configured_path if Path(configured_path).is_file() else None

    candidates = []
    program_data = os.getenv("ProgramData", r"C:\ProgramData")
    platform_root = Path(program_data) / "Microsoft" / "Windows Defender" / "Platform"
    if platform_root.is_dir():
        candidates.extend(
            platform_dir / "MpCmdRun.exe"
            for platform_dir in sorted(platform_root.iterdir(), reverse=True)
            if platform_dir.is_dir()
        )

    program_files = os.getenv("ProgramFiles", r"C:\Program Files")
    candidates.append(Path(program_files) / "Windows Defender" / "MpCmdRun.exe")

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def run_mpcmdrun_signature_update(mpcmdrun_path: str, timeout_seconds: int) -> dict[str, object]:
    command = [mpcmdrun_path, "-SignatureUpdate"]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "command": command,
            "raw_output": "",
            "error_message": f"MpCmdRun signature update timed out after {timeout_seconds} seconds.",
        }
    except OSError as exc:
        return {
            "ok": False,
            "command": command,
            "raw_output": str(exc),
            "error_message": "MpCmdRun signature update could not be executed.",
        }

    raw_output = combined_output(completed.stdout, completed.stderr)
    return {
        "ok": completed.returncode == 0,
        "command": command,
        "returncode": completed.returncode,
        "raw_output": raw_output,
        "error_message": None
        if completed.returncode == 0
        else f"MpCmdRun signature update exited with code {completed.returncode}.",
    }


def run_mpcmdrun_custom_scan(
    mpcmdrun_path: str,
    sample_path: Path,
    timeout_seconds: int,
) -> dict[str, object]:
    command = [
        mpcmdrun_path,
        "-Scan",
        "-ScanType",
        "3",
        "-File",
        str(sample_path),
        "-DisableRemediation",
    ]
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
            "error_message": f"MpCmdRun custom scan timed out after {timeout_seconds} seconds.",
        }
    except OSError as exc:
        return {
            "command": command,
            "returncode": -1,
            "raw_output": str(exc),
            "error_message": "MpCmdRun custom scan could not be executed.",
        }

    return {
        "command": command,
        "returncode": completed.returncode,
        "raw_output": combined_output(completed.stdout, completed.stderr),
        "error_message": None,
    }


def normalize_mpcmdrun_scan_result(
    returncode: int,
    raw_output: str,
    duration_ms: int,
    details: dict[str, object] | None = None,
) -> EngineResultInput:
    clean_raw = raw_output.strip() or "MpCmdRun produced no output."
    signature = parse_mpcmdrun_signature(clean_raw)

    if returncode == 0 and not signature and not has_detection_indicator(clean_raw):
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

    if returncode == 2 and (signature or has_detection_indicator(clean_raw)):
        signature = signature or "Microsoft Defender detection"
        return build_result(
            status="completed",
            detected=True,
            signature=signature,
            severity="high",
            confidence=90,
            raw_output=clean_raw,
            error_message=None,
            duration_ms=duration_ms,
            details=details,
            findings=defender_findings(signature, clean_raw),
        )

    if returncode == -1:
        error_message = "MpCmdRun custom scan could not complete."
    elif returncode == 0:
        error_message = "MpCmdRun returned success with possible detection indicators; MASP will not classify this as clean."
    elif returncode == 2:
        error_message = "MpCmdRun returned code 2 without a clear detection signature; this may be a scan error."
    else:
        error_message = f"MpCmdRun custom scan exited with code {returncode}."

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


def parse_mpcmdrun_signature(raw_output: str) -> str | None:
    for line in raw_output.splitlines():
        stripped = line.strip(" \t:-")
        if not stripped:
            continue
        lowered = stripped.lower()
        if "no threat" in lowered or "no malware" in lowered:
            continue
        key, separator, value = stripped.partition(":")
        if separator and value.strip():
            normalized_key = " ".join(key.lower().split())
            if normalized_key in {"threat", "threat name", "malware", "virus"}:
                return value.strip()
        if lowered.startswith(("virus:", "trojan:", "worm:", "hacktool:", "pua:")):
            return stripped
    return None


def has_detection_indicator(raw_output: str) -> bool:
    for line in raw_output.splitlines():
        lowered = line.strip().lower()
        if not lowered:
            continue
        if "no threat" in lowered or "no malware" in lowered or "no threats" in lowered:
            continue
        if any(marker in lowered for marker in ("eicar", "threat detected", "malware detected")):
            return True
    return False


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
    findings: list[dict[str, object]] | None = None,
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
        findings_json=json.dumps(findings or [], sort_keys=True),
    )


def defender_findings(signature: str, raw_output: str) -> list[dict[str, object]]:
    return [
        normalized_finding(
            title=signature,
            finding_type="antivirus_signature",
            source=ENGINE_NAME,
            severity="high",
            confidence=90,
            action="detected",
            category="test_file" if "eicar" in signature.lower() else "malware",
            tags=["av", "signature", "microsoft_defender"],
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


def get_mpcomputerstatus(powershell_path: str, timeout_seconds: int) -> dict[str, object]:
    command = [
        powershell_path,
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-MpComputerStatus | ConvertTo-Json -Compress",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": "unavailable",
            "detail": f"Get-MpComputerStatus timed out after {timeout_seconds} seconds.",
        }
    except OSError as exc:
        return {
            "ok": False,
            "status": "unavailable",
            "detail": f"PowerShell could not execute Get-MpComputerStatus: {exc}",
        }

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        return classify_status_command_failure(stdout, stderr, completed.returncode)

    if not stdout:
        return {
            "ok": False,
            "status": "unexpected",
            "detail": "Get-MpComputerStatus returned no output.",
        }

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "status": "unexpected",
            "detail": "Get-MpComputerStatus returned output that MASP could not parse as JSON.",
        }

    return {"ok": True, "payload": payload}


def classify_status_command_failure(stdout: str, stderr: str, returncode: int) -> dict[str, object]:
    raw = "\n".join(part for part in [stdout.strip(), stderr.strip()] if part).strip()
    lowered = raw.lower()
    if "access denied" in lowered or "0x80041003" in lowered:
        return {
            "ok": False,
            "status": "permission denied",
            "detail": "Get-MpComputerStatus returned access denied. MASP likely needs elevated privileges on this Windows node.",
        }
    if "not recognized" in lowered or "get-mpcomputerstatus" in lowered and "not found" in lowered:
        return {
            "ok": False,
            "status": "unavailable",
            "detail": "Get-MpComputerStatus is unavailable on this node.",
        }
    return {
        "ok": False,
        "status": "unexpected",
        "detail": f"Get-MpComputerStatus failed with exit code {returncode}.",
    }


def evaluate_status_payload(
    payload: dict[str, object],
    require_real_time_enabled: bool,
) -> dict[str, str | bool]:
    am_service_enabled = bool(payload.get("AMServiceEnabled"))
    antivirus_enabled = bool(payload.get("AntivirusEnabled"))
    real_time_enabled = bool(payload.get("RealTimeProtectionEnabled"))
    signature_age = safe_int(payload.get("AntivirusSignatureAge"))

    if not am_service_enabled:
        return {
            "ok": False,
            "status": "disabled",
            "detail": "Microsoft Defender service is installed but disabled on this node.",
        }
    if not antivirus_enabled:
        return {
            "ok": False,
            "status": "disabled",
            "detail": "Microsoft Defender Antivirus is disabled on this node.",
        }
    if require_real_time_enabled and not real_time_enabled:
        return {
            "ok": True,
            "status": "degraded",
            "detail": "Microsoft Defender is available, but real-time protection is disabled.",
        }
    if signature_age is not None and signature_age > DEFAULT_SIGNATURE_STALE_DAYS:
        return {
            "ok": True,
            "status": "degraded",
            "detail": (
                "Microsoft Defender is available, but antivirus signatures appear stale "
                f"({signature_age} days old)."
            ),
        }

    version_bits = []
    for key, label in (
        ("AMEngineVersion", "engine"),
        ("AMProductVersion", "product"),
        ("AntivirusSignatureVersion", "signatures"),
    ):
        value = payload.get(key)
        if value:
            version_bits.append(f"{label} {value}")

    detail = "Microsoft Defender is available."
    if version_bits:
        detail = f"Microsoft Defender is available ({', '.join(version_bits)})."
    return {"ok": True, "status": "available", "detail": detail}


def safe_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def elapsed_ms(started_at: float) -> int:
    return max(1, int((perf_counter() - started_at) * 1000))


def engine_setting(key: str, fallback: str) -> str:
    from app.database import get_setting

    value = get_setting(key, fallback)
    return fallback if value is None else value


def setting_value(config_override: dict[str, str], key: str, fallback: str) -> str:
    """Resolve one setting, treating a blank override as "not configured".

    Same trap as the ClamAV engine (see its copy): a present-but-empty value used
    to beat the fallback, so saving the engine config form could persist an empty
    executable path or scan type over an environment-provided one and break the
    engine. None of these settings has a meaningful empty value.
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


def setting_bool(config_override: dict[str, str], key: str, fallback: str) -> bool:
    value = setting_value(config_override, key, fallback).strip().lower()
    return value in {"1", "true", "yes", "on"}
