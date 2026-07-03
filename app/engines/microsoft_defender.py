import json
import os
from pathlib import Path
import shutil
import subprocess
from time import perf_counter

from app.models import EngineResultInput, ScanRecord


ENGINE_NAME = "Microsoft Defender"
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_SIGNATURE_STALE_DAYS = 3
DEFAULT_SCAN_TYPE = "custom"


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
) -> dict[str, str | bool]:
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


def run_microsoft_defender_engine(
    scan: ScanRecord,
    config_override: dict[str, str] | None = None,
) -> EngineResultInput:
    started_at = perf_counter()
    config = get_microsoft_defender_config(config_override)
    health = check_microsoft_defender_health(config_override)
    details = {
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
    return EngineResultInput(
        engine_name=ENGINE_NAME,
        engine_version=None,
        signature_version=None,
        status="skipped",
        detected=False,
        signature=None,
        severity="info",
        confidence=0,
        raw_output="Microsoft Defender scan flow is not implemented yet on this branch.",
        error_message="Microsoft Defender adapter is still in research phase.",
        duration_ms=elapsed_ms(started_at),
        details_json=json.dumps(details, sort_keys=True),
        findings_json="[]",
    )


def resolve_powershell_path(configured_path: str) -> str | None:
    if Path(configured_path).is_file():
        return configured_path
    return shutil.which(configured_path)


def resolve_mpcmdrun_path(configured_path: str) -> str | None:
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


def setting_bool(config_override: dict[str, str], key: str, fallback: str) -> bool:
    value = setting_value(config_override, key, fallback).strip().lower()
    return value in {"1", "true", "yes", "on"}
