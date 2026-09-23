from collections.abc import Mapping

from app.services.engine_registry import adapter_definition
from app.services.secret_store import encrypt_secret


def _setup_form_text(form: Mapping[str, object], key: str) -> str:
    value = form.get(key, "")
    return value.strip() if isinstance(value, str) else ""


def _required_setup_text(
    form: Mapping[str, object],
    key: str,
    label: str,
) -> str:
    value = _setup_form_text(form, key)
    if not value:
        raise ValueError(f"{label} is required.")
    return value


def _required_setup_choice(
    form: Mapping[str, object],
    key: str,
    label: str,
    choices: set[str],
) -> str:
    value = _required_setup_text(form, key, label).lower()
    if value not in choices:
        raise ValueError(f"Select a valid {label.lower()}.")
    return value


def _required_setup_int(
    form: Mapping[str, object],
    key: str,
    label: str,
    minimum: int,
    maximum: int,
) -> str:
    raw_value = _required_setup_text(form, key, label)
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an integer.") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}.")
    return str(value)


def engine_setup_from_form(
    adapter_key: str,
    form: Mapping[str, object],
    existing_config: Mapping[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """Validate initial setup before an engine instance is persisted."""
    adapter_definition(adapter_key)
    display_name = _required_setup_text(
        form, "engine_display_name", "Engine instance name"
    )
    if len(display_name) > 128:
        raise ValueError("Engine instance name must be 128 characters or fewer.")

    if adapter_key in {"static_metadata", "hash_list"}:
        return display_name, {}

    if adapter_key == "file_type":
        return display_name, {
            "header_bytes": _required_setup_int(
                form, "file_type_header_bytes", "File type header bytes", 512, 1024 * 1024
            ),
            "mismatch_action": _required_setup_choice(
                form, "file_type_mismatch_action", "File type mismatch action", {"report", "detect"}
            ),
        }

    if adapter_key == "clamav":
        mode = _required_setup_choice(
            form, "clamav_mode", "ClamAV connection mode", {"clamd", "cli"}
        )
        config = {
            "mode": mode,
            "timeout_seconds": _required_setup_int(
                form, "clamav_timeout_seconds", "ClamAV timeout seconds", 1, 600
            ),
            "max_file_size_bytes": _required_setup_int(
                form,
                "clamav_max_file_size_bytes",
                "ClamAV max file size bytes",
                0,
                1099511627776,
            ),
        }
        if mode == "clamd":
            config.update(
                {
                    "host": _required_setup_text(
                        form, "clamav_host", "ClamAV clamd host"
                    ),
                    "port": _required_setup_int(
                        form, "clamav_port", "ClamAV clamd port", 1, 65535
                    ),
                }
            )
        else:
            config["command"] = _required_setup_text(
                form, "clamav_command", "ClamAV CLI command"
            )
        return display_name, config

    if adapter_key == "yara":
        return display_name, {
            "command": _required_setup_text(form, "yara_command", "YARA CLI command"),
            "rules_dir": _required_setup_text(
                form, "yara_rules_dir", "YARA rules directory"
            ),
            "timeout_seconds": _required_setup_int(
                form, "yara_timeout_seconds", "YARA timeout seconds", 1, 600
            ),
        }

    if adapter_key == "microsoft_defender":
        return display_name, {
            "execution_mode": _required_setup_choice(
                form,
                "microsoft_defender_execution_mode",
                "Microsoft Defender execution mode",
                {"powershell", "mpcmdrun"},
            ),
            "powershell_path": _required_setup_text(
                form,
                "microsoft_defender_powershell_path",
                "Microsoft Defender PowerShell path",
            ),
            "mpcmdrun_path": _required_setup_text(
                form,
                "microsoft_defender_mpcmdrun_path",
                "Microsoft Defender MpCmdRun path",
            ),
            "default_scan_type": _required_setup_choice(
                form,
                "microsoft_defender_default_scan_type",
                "Microsoft Defender default scan type",
                {"custom", "quick", "full"},
            ),
            "timeout_seconds": _required_setup_int(
                form,
                "microsoft_defender_timeout_seconds",
                "Microsoft Defender timeout seconds",
                30,
                86400,
            ),
            "update_before_scan": _required_setup_choice(
                form,
                "microsoft_defender_update_before_scan",
                "Microsoft Defender signature update policy",
                {"true", "false"},
            ),
            "require_real_time_enabled": _required_setup_choice(
                form,
                "microsoft_defender_require_real_time_enabled",
                "Microsoft Defender real-time protection policy",
                {"true", "false"},
            ),
        }

    if adapter_key == "virustotal":
        api_key = _setup_form_text(form, "virustotal_api_key")
        encrypted = (existing_config or {}).get("api_key_encrypted", "")
        if api_key:
            encrypted = encrypt_secret(api_key)
        elif not encrypted:
            raise ValueError("VirusTotal API key is required.")
        return display_name, {
            "api_key_encrypted": encrypted,
            "timeout_seconds": _required_setup_int(
                form, "virustotal_timeout_seconds", "VirusTotal timeout seconds", 1, 60
            ),
            "cache_seconds": _required_setup_int(
                form,
                "virustotal_cache_seconds",
                "VirusTotal known-result cache seconds",
                0,
                86400,
            ),
            "unknown_cache_seconds": _required_setup_int(
                form,
                "virustotal_unknown_cache_seconds",
                "VirusTotal unknown-result cache seconds",
                0,
                3600,
            ),
            "cache_max_entries": _required_setup_int(
                form,
                "virustotal_cache_max_entries",
                "VirusTotal cache maximum entries",
                1,
                100000,
            ),
            "malicious_threshold": _required_setup_int(
                form,
                "virustotal_malicious_threshold",
                "VirusTotal malicious threshold",
                1,
                100,
            ),
            "allow_undetected": _required_setup_choice(
                form,
                "virustotal_allow_undetected",
                "VirusTotal undetected-report policy",
                {"true", "false"},
            ),
            "max_age_days": _required_setup_int(
                form,
                "virustotal_max_age_days",
                "VirusTotal maximum report age days",
                1,
                3650,
            ),
        }

    raise ValueError("This adapter does not expose an initial setup form.")
