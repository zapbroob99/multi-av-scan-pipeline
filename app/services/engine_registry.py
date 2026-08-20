from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from app.database import (
    create_engine_instance,
    delete_engine_instance,
    get_engine_instance,
    get_setting,
    list_engine_instances,
    set_setting,
    update_engine_instance,
)
from app.engines.clamav import check_clamav_health, get_clamav_config, run_clamav_engine
from app.engines.clamav import env_or_setting as clamav_env_or_setting
from app.engines.microsoft_defender import (
    check_microsoft_defender_health,
    get_microsoft_defender_config,
    run_microsoft_defender_engine,
)
from app.engines.static_metadata import ENGINE_NAME as STATIC_METADATA_NAME
from app.engines.static_metadata import run_static_metadata_engine
from app.engines.virustotal import (
    check_virustotal_health,
    get_virustotal_config,
    run_virustotal_file_hash_engine,
    run_virustotal_hash_engine,
    test_virustotal_connection,
)
from app.services.hash_scanning import HashEngineExecution
from app.engines.yara_engine import check_yara_health, get_yara_config, run_yara_engine
from app.models import EngineInstanceRecord, EngineResultInput, ScanRecord


RuntimeConfigFactory = Callable[[dict[str, str] | None], dict[str, str | int | float | bool]]
HealthCheckFunction = Callable[[dict[str, str] | None], dict[str, str | bool]]
ConnectionTestFunction = Callable[[dict[str, str] | None], dict[str, str | bool]]
ScanFunction = Callable[[ScanRecord, dict[str, str] | None], EngineResultInput]
HashScanFunction = Callable[[str, dict[str, str] | None], HashEngineExecution]


@dataclass(frozen=True)
class EngineConfigField:
    key: str
    label: str
    field_type: str
    required: bool
    default: str = ""
    secret: bool = False
    help_text: str = ""


@dataclass(frozen=True)
class EngineAdapterDefinition:
    key: str
    label: str
    short_label: str
    category: str
    description: str
    vendor: str
    product: str
    integration_method: str
    support_state: str
    detection: bool
    configurable: bool
    supports_rules: bool = False
    docs_path: str = ""
    config_fields: tuple[EngineConfigField, ...] = ()


@dataclass(frozen=True)
class EngineCapabilityProfile:
    input_modes: tuple[str, ...]
    deployment: str
    supported_platforms: tuple[str, ...]
    execution_model: str
    supports_file_upload: bool
    supports_hash_lookup: bool
    supports_rules: bool = False
    supports_archives: bool = False
    requires_network: bool = False
    max_file_size_bytes: int | None = None
    supports_file_hash_scan: bool = False


@dataclass(frozen=True)
class RegisteredEngineAdapter:
    definition: EngineAdapterDefinition
    capabilities: EngineCapabilityProfile
    runtime_config_factory: RuntimeConfigFactory
    health_check_function: HealthCheckFunction
    scan_function: ScanFunction | None
    hash_scan_function: HashScanFunction | None = None
    connection_test_function: ConnectionTestFunction | None = None

    @property
    def key(self) -> str:
        return self.definition.key

    def runtime_config(self, config_override: dict[str, str] | None = None) -> dict[str, str | int | float | bool]:
        return self.runtime_config_factory(config_override)

    def health_check(self, config_override: dict[str, str] | None = None) -> dict[str, str | bool]:
        return self.health_check_function(config_override)

    def test_connection(self, config_override: dict[str, str] | None = None) -> dict[str, str | bool]:
        if self.connection_test_function is None:
            return self.health_check(config_override)
        return self.connection_test_function(config_override)

    def scan(self, scan: ScanRecord, config_override: dict[str, str] | None = None) -> EngineResultInput:
        if self.scan_function is None:
            raise RuntimeError(f"Adapter {self.key} does not support file-backed scans.")
        return self.scan_function(scan, config_override)

    def scan_hash(
        self,
        sha256: str,
        config_override: dict[str, str] | None = None,
    ) -> HashEngineExecution:
        if self.hash_scan_function is None:
            raise RuntimeError(f"Adapter {self.key} does not support hash-only scans.")
        return self.hash_scan_function(sha256, config_override)

    def supports_platform(self, platform_name: str) -> bool:
        return platform_name in self.capabilities.supported_platforms


@dataclass(frozen=True)
class RoadmapAdapterDefinition:
    label: str
    short_label: str
    vendor: str
    product: str
    integration_method: str
    description: str
    status: str
    blocker: str


def static_metadata_runtime_config(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | int | float | bool]:
    return {
        "mode": "builtin",
        "enabled": True,
        "timeout_seconds": 1,
    }


def static_metadata_health_check(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | bool]:
    return {
        "ok": True,
        "status": "available",
        "detail": "Built-in analyzer is available.",
    }


def static_metadata_scan(
    scan: ScanRecord,
    config_override: dict[str, str] | None = None,
) -> EngineResultInput:
    return run_static_metadata_engine(scan)


REGISTERED_ADAPTERS: dict[str, RegisteredEngineAdapter] = {
    "static_metadata": RegisteredEngineAdapter(
        definition=EngineAdapterDefinition(
            key="static_metadata",
            label=STATIC_METADATA_NAME,
            short_label="ST",
            category="metadata",
            description="Built-in metadata analyzer.",
            vendor="MASP",
            product="Built-in metadata analyzer",
            integration_method="local",
            support_state="supported",
            detection=False,
            configurable=False,
            docs_path="docs/integrations/SUPPORT_MATRIX.md",
        ),
        capabilities=EngineCapabilityProfile(
            input_modes=("metadata", "file", "hash"),
            deployment="local",
            supported_platforms=("linux", "windows"),
            execution_model="sync",
            supports_file_upload=True,
            supports_hash_lookup=False,
            supports_archives=False,
            requires_network=False,
        ),
        runtime_config_factory=static_metadata_runtime_config,
        health_check_function=static_metadata_health_check,
        scan_function=static_metadata_scan,
    ),
    "clamav": RegisteredEngineAdapter(
        definition=EngineAdapterDefinition(
            key="clamav",
            label="ClamAV",
            short_label="CL",
            category="detection",
            description="clamd TCP adapter with local CLI fallback.",
            vendor="Cisco Talos",
            product="ClamAV",
            integration_method="clamd TCP / local CLI",
            support_state="supported",
            detection=True,
            configurable=True,
            docs_path="docs/integrations/SUPPORT_MATRIX.md",
            config_fields=(
                EngineConfigField("host", "clamd host", "text", False, help_text="Set to use clamd TCP; leave empty for CLI fallback."),
                EngineConfigField("port", "clamd port", "number", False, "3310"),
                EngineConfigField("command", "CLI command", "text", False, "clamscan"),
                EngineConfigField("timeout_seconds", "timeout seconds", "number", False, "60"),
                EngineConfigField("max_file_size_bytes", "max file size bytes", "number", False, "0"),
            ),
        ),
        capabilities=EngineCapabilityProfile(
            input_modes=("file", "path"),
            deployment="worker",
            supported_platforms=("linux",),
            execution_model="sync",
            supports_file_upload=True,
            supports_hash_lookup=False,
            supports_archives=True,
            requires_network=True,
        ),
        runtime_config_factory=get_clamav_config,
        health_check_function=check_clamav_health,
        scan_function=run_clamav_engine,
    ),
    "yara": RegisteredEngineAdapter(
        definition=EngineAdapterDefinition(
            key="yara",
            label="YARA",
            short_label="YR",
            category="detection",
            description="Local rule engine adapter for pattern-based detection.",
            vendor="YARA",
            product="YARA CLI",
            integration_method="local CLI",
            support_state="supported",
            detection=True,
            configurable=True,
            supports_rules=True,
            docs_path="docs/integrations/SUPPORT_MATRIX.md",
            config_fields=(
                EngineConfigField("command", "CLI command", "text", False, "yara"),
                EngineConfigField("rules_dir", "rules directory", "text", False, "rules"),
                EngineConfigField("timeout_seconds", "timeout seconds", "number", False, "30"),
            ),
        ),
        capabilities=EngineCapabilityProfile(
            input_modes=("file", "path"),
            deployment="worker",
            supported_platforms=("linux", "windows"),
            execution_model="sync",
            supports_file_upload=True,
            supports_hash_lookup=False,
            supports_rules=True,
            supports_archives=False,
            requires_network=False,
        ),
        runtime_config_factory=get_yara_config,
        health_check_function=check_yara_health,
        scan_function=run_yara_engine,
    ),
    "microsoft_defender": RegisteredEngineAdapter(
        definition=EngineAdapterDefinition(
            key="microsoft_defender",
            label="Microsoft Defender",
            short_label="MD",
            category="detection",
            description="Windows local antivirus integration validated in lab.",
            vendor="Microsoft",
            product="Microsoft Defender Antivirus",
            integration_method="PowerShell / CLI",
            support_state="lab",
            detection=True,
            configurable=True,
            docs_path="docs/integrations/microsoft_defender_local_cli.md",
            config_fields=(
                EngineConfigField("execution_mode", "execution mode", "text", False, "powershell"),
                EngineConfigField("powershell_path", "PowerShell path", "text", False, "powershell.exe"),
                EngineConfigField("mpcmdrun_path", "MpCmdRun path", "text", False, "auto"),
                EngineConfigField("default_scan_type", "default scan type", "text", False, "custom"),
                EngineConfigField("timeout_seconds", "timeout seconds", "number", False, "900"),
                EngineConfigField("update_before_scan", "update before scan", "checkbox", False, "false"),
                EngineConfigField("require_real_time_enabled", "require real-time protection", "checkbox", False, "true"),
            ),
        ),
        capabilities=EngineCapabilityProfile(
            input_modes=("file", "path"),
            deployment="worker",
            supported_platforms=("windows",),
            execution_model="sync",
            supports_file_upload=True,
            supports_hash_lookup=False,
            supports_archives=True,
            requires_network=False,
        ),
        runtime_config_factory=get_microsoft_defender_config,
        health_check_function=check_microsoft_defender_health,
        scan_function=run_microsoft_defender_engine,
    ),
    "virustotal": RegisteredEngineAdapter(
        definition=EngineAdapterDefinition(
            key="virustotal",
            label="VirusTotal",
            short_label="VT",
            category="reputation",
            description="SHA-256 reputation lookup without file upload.",
            vendor="Google/VirusTotal",
            product="VirusTotal API v3",
            integration_method="REST API hash lookup",
            support_state="blocked",
            detection=True,
            configurable=True,
            docs_path="docs/integrations/API_SCAN_GATEWAY.md",
            config_fields=(
                EngineConfigField(
                    "api_key",
                    "API key",
                    "password",
                    True,
                    secret=True,
                    help_text="Stored encrypted; leave blank to keep the current key.",
                ),
                EngineConfigField("timeout_seconds", "timeout seconds", "number", False, "10"),
                EngineConfigField("cache_seconds", "known-result cache seconds", "number", False, "3600"),
                EngineConfigField("unknown_cache_seconds", "unknown-result cache seconds", "number", False, "300"),
                EngineConfigField("cache_max_entries", "cache maximum entries", "number", False, "10000"),
                EngineConfigField("malicious_threshold", "malicious threshold", "number", False, "1"),
                EngineConfigField("allow_undetected", "allow fresh undetected reports", "checkbox", False, "false"),
                EngineConfigField("max_age_days", "maximum report age days", "number", False, "30"),
            ),
        ),
        capabilities=EngineCapabilityProfile(
            input_modes=("hash", "file hash"),
            deployment="api worker",
            supported_platforms=("linux", "windows"),
            execution_model="sync",
            supports_file_upload=False,
            supports_hash_lookup=True,
            supports_archives=False,
            requires_network=True,
            supports_file_hash_scan=True,
        ),
        runtime_config_factory=get_virustotal_config,
        health_check_function=check_virustotal_health,
        scan_function=run_virustotal_file_hash_engine,
        hash_scan_function=run_virustotal_hash_engine,
        connection_test_function=test_virustotal_connection,
    ),
}

ADAPTERS: dict[str, EngineAdapterDefinition] = {
    key: adapter.definition for key, adapter in REGISTERED_ADAPTERS.items()
}

ROADMAP_ADAPTERS: list[RoadmapAdapterDefinition] = [
    RoadmapAdapterDefinition(
        label="ESET Server Security via ICAP",
        short_label="ES",
        vendor="ESET",
        product="ESET Server Security or ICAP-capable gateway product",
        integration_method="ICAP",
        description="Commercial AV gateway integration.",
        status="research",
        blocker="Confirm exact product, ICAP service behavior, licensing, and response semantics.",
    ),
    RoadmapAdapterDefinition(
        label="Trellix ATD via REST API",
        short_label="TX",
        vendor="Trellix",
        product="Advanced Threat Defense / Malware Analysis",
        integration_method="REST API",
        description="Commercial sandbox submission and verdict integration.",
        status="research",
        blocker="Confirm submission flow, polling model, verdict schema, auth, and rate limits.",
    ),
    RoadmapAdapterDefinition(
        label="Sophos via local CLI",
        short_label="SP",
        vendor="Sophos",
        product="Sophos Protection for Linux or endpoint product",
        integration_method="local CLI",
        description="Endpoint CLI scan integration.",
        status="research",
        blocker="Confirm command availability, OS support, exit codes, and output format.",
    ),
    RoadmapAdapterDefinition(
        label="Trend Micro via ICAP",
        short_label="TM",
        vendor="Trend Micro",
        product="ICAP-capable gateway product",
        integration_method="ICAP",
        description="Commercial gateway AV integration.",
        status="research",
        blocker="Confirm product name, service names, status codes, and detection headers.",
    ),
]


DEFAULT_ENGINE_SEED_KEY = "engines.default_seeded"


def seed_default_engines() -> None:
    if get_setting(DEFAULT_ENGINE_SEED_KEY) == "1":
        return

    if list_engine_instances():
        set_setting(DEFAULT_ENGINE_SEED_KEY, "1")
        return

    for adapter_key in ("static_metadata", "clamav", "yara"):
        definition = ADAPTERS[adapter_key]
        create_engine_instance(
            adapter_key=definition.key,
            display_name=definition.label,
            enabled=True,
            config_json="{}",
        )
    set_setting(DEFAULT_ENGINE_SEED_KEY, "1")


def configured_engines() -> list[EngineInstanceRecord]:
    return list_engine_instances()


def enabled_engines() -> list[EngineInstanceRecord]:
    """Enabled engines eligible for ordinary file-backed scan intake."""
    return [
        engine
        for engine in configured_engines()
        if engine.enabled
        and (
            adapter_capabilities(engine.adapter_key).supports_file_upload
            or adapter_capabilities(engine.adapter_key).supports_file_hash_scan
        )
    ]


def enabled_hash_engines() -> list[EngineInstanceRecord]:
    return [
        engine
        for engine in configured_engines()
        if engine.enabled and adapter_capabilities(engine.adapter_key).supports_hash_lookup
    ]


def detection_engine_names() -> list[str]:
    names = []
    for engine in enabled_engines():
        definition = adapter_definition(engine.adapter_key)
        if definition.detection:
            names.append(engine.display_name)
    return names


def adapter_definition(adapter_key: str) -> EngineAdapterDefinition:
    adapter = REGISTERED_ADAPTERS.get(adapter_key)
    if adapter is None:
        raise KeyError(f"Unknown adapter: {adapter_key}")
    return adapter.definition


def adapter_registry_entry(adapter_key: str) -> RegisteredEngineAdapter:
    adapter = REGISTERED_ADAPTERS.get(adapter_key)
    if adapter is None:
        raise KeyError(f"Unknown adapter: {adapter_key}")
    return adapter


def adapter_capabilities(adapter_key: str) -> EngineCapabilityProfile:
    return adapter_registry_entry(adapter_key).capabilities


def available_adapter_definitions() -> list[EngineAdapterDefinition]:
    configured_keys = {engine.adapter_key for engine in configured_engines()}
    return [
        definition
        for definition in ADAPTERS.values()
        if definition.key not in configured_keys
    ]


def add_engine(adapter_key: str) -> None:
    definition = adapter_definition(adapter_key)
    if get_engine_instance(adapter_key) is not None:
        return
    create_engine_instance(
        adapter_key=definition.key,
        display_name=definition.label,
        enabled=True,
        config_json="{}",
    )


def toggle_engine(adapter_key: str) -> None:
    instance = get_engine_instance(adapter_key)
    if instance is None:
        return
    update_engine_instance(adapter_key, enabled=not instance.enabled)


def remove_engine(adapter_key: str) -> None:
    delete_engine_instance(adapter_key)


def update_engine_config(adapter_key: str, config: dict[str, str]) -> None:
    instance = get_engine_instance(adapter_key)
    if instance is None:
        add_engine(adapter_key)
        instance = get_engine_instance(adapter_key)
    if instance is None:
        return
    update_engine_instance(adapter_key, config_json=json.dumps(config, sort_keys=True))


def engine_config(instance: EngineInstanceRecord) -> dict[str, str]:
    try:
        config = json.loads(instance.config_json)
    except json.JSONDecodeError:
        config = {}
    if not isinstance(config, dict):
        config = {}
    return {str(key): str(value) for key, value in config.items()}


def runtime_config(instance: EngineInstanceRecord) -> dict[str, str | int | float | bool]:
    config = engine_config(instance)
    return adapter_registry_entry(instance.adapter_key).runtime_config(config)


def engine_health(instance: EngineInstanceRecord) -> dict[str, str | bool]:
    config = engine_config(instance)
    return adapter_registry_entry(instance.adapter_key).health_check(config)


def test_engine_connection(instance: EngineInstanceRecord) -> dict[str, str | bool]:
    config = engine_config(instance)
    return adapter_registry_entry(instance.adapter_key).test_connection(config)


def run_engine(instance: EngineInstanceRecord, scan: ScanRecord) -> EngineResultInput:
    config = engine_config(instance)
    return adapter_registry_entry(instance.adapter_key).scan(scan, config)


def run_hash_engine(instance: EngineInstanceRecord, sha256: str) -> HashEngineExecution:
    config = engine_config(instance)
    return adapter_registry_entry(instance.adapter_key).scan_hash(sha256, config)


def config_value(config: dict[str, str], key: str, fallback: str) -> str:
    value = config.get(key)
    if value is None or not value.strip():
        return fallback
    return value.strip()


def clamav_form_values(instance: EngineInstanceRecord | None) -> dict[str, str]:
    # Fall back to the same env-then-setting chain the engine itself resolves
    # (env_or_setting), not to the stored setting alone. Otherwise a host coming
    # from MASP_CLAMD_HOST renders as an empty field, and saving the form for an
    # unrelated reason persists host="" over the env value -- which drops ClamAV
    # into CLI mode and breaks every scan.
    config = engine_config(instance) if instance is not None else {}
    return {
        "host": config_value(
            config, "host", clamav_env_or_setting("MASP_CLAMD_HOST", "clamav.host", "")
        ),
        "port": config_value(
            config, "port", clamav_env_or_setting("MASP_CLAMD_PORT", "clamav.port", "3310")
        ),
        "command": config_value(
            config,
            "command",
            clamav_env_or_setting("MASP_CLAMAV_COMMAND", "clamav.command", "clamscan"),
        ),
        "timeout_seconds": config_value(
            config,
            "timeout_seconds",
            clamav_env_or_setting(
                "MASP_CLAMD_TIMEOUT_SECONDS", "clamav.timeout_seconds", "60"
            ),
        ),
        "max_file_size_bytes": config_value(
            config,
            "max_file_size_bytes",
            get_setting("clamav.max_file_size_bytes", "0") or "0",
        ),
    }


def yara_form_values(instance: EngineInstanceRecord | None) -> dict[str, str]:
    config = engine_config(instance) if instance is not None else {}
    return {
        "command": config_value(
            config,
            "command",
            get_setting("yara.command", "yara") or "yara",
        ),
        "rules_dir": config_value(
            config,
            "rules_dir",
            get_setting("yara.rules_dir", "rules") or "rules",
        ),
        "timeout_seconds": config_value(
            config,
            "timeout_seconds",
            get_setting("yara.timeout_seconds", "30") or "30",
        ),
    }


def microsoft_defender_form_values(instance: EngineInstanceRecord | None) -> dict[str, str]:
    config = engine_config(instance) if instance is not None else {}
    return {
        "execution_mode": config_value(
            config,
            "execution_mode",
            get_setting("microsoft_defender.execution_mode", "powershell") or "powershell",
        ),
        "powershell_path": config_value(
            config,
            "powershell_path",
            get_setting("microsoft_defender.powershell_path", "powershell.exe") or "powershell.exe",
        ),
        "mpcmdrun_path": config_value(
            config,
            "mpcmdrun_path",
            get_setting("microsoft_defender.mpcmdrun_path", "auto") or "auto",
        ),
        "default_scan_type": config_value(
            config,
            "default_scan_type",
            get_setting("microsoft_defender.default_scan_type", "custom") or "custom",
        ),
        "timeout_seconds": config_value(
            config,
            "timeout_seconds",
            get_setting("microsoft_defender.timeout_seconds", "900") or "900",
        ),
        "update_before_scan": config_value(
            config,
            "update_before_scan",
            get_setting("microsoft_defender.update_before_scan", "false") or "false",
        ),
        "require_real_time_enabled": config_value(
            config,
            "require_real_time_enabled",
            get_setting("microsoft_defender.require_real_time_enabled", "true") or "true",
        ),
    }
