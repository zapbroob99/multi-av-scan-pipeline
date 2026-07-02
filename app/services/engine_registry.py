from __future__ import annotations

import json
from dataclasses import dataclass

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
from app.engines.static_metadata import ENGINE_NAME as STATIC_METADATA_NAME
from app.engines.static_metadata import run_static_metadata_engine
from app.engines.yara_engine import check_yara_health, get_yara_config, run_yara_engine
from app.models import EngineInstanceRecord, EngineResultInput, ScanRecord


@dataclass(frozen=True)
class EngineAdapterDefinition:
    key: str
    label: str
    short_label: str
    description: str
    detection: bool
    configurable: bool
    supports_rules: bool = False


ADAPTERS: dict[str, EngineAdapterDefinition] = {
    "static_metadata": EngineAdapterDefinition(
        key="static_metadata",
        label=STATIC_METADATA_NAME,
        short_label="ST",
        description="Built-in metadata analyzer.",
        detection=False,
        configurable=False,
    ),
    "clamav": EngineAdapterDefinition(
        key="clamav",
        label="ClamAV",
        short_label="CL",
        description="clamd TCP adapter with local CLI fallback.",
        detection=True,
        configurable=True,
    ),
    "yara": EngineAdapterDefinition(
        key="yara",
        label="YARA",
        short_label="YR",
        description="Local rule engine adapter for pattern-based detection.",
        detection=True,
        configurable=True,
        supports_rules=True,
    ),
}

ROADMAP_ADAPTERS = [
    {"label": "ESET", "short_label": "ES", "description": "Commercial AV adapter", "status": "Planned"},
    {"label": "ICAP", "short_label": "IC", "description": "Network AV gateway adapter", "status": "Planned"},
    {"label": "REST AV", "short_label": "API", "description": "Vendor API adapter", "status": "Planned"},
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
    return [engine for engine in configured_engines() if engine.enabled]


def detection_engine_names() -> list[str]:
    names = []
    for engine in enabled_engines():
        definition = adapter_definition(engine.adapter_key)
        if definition.detection:
            names.append(engine.display_name)
    return names


def adapter_definition(adapter_key: str) -> EngineAdapterDefinition:
    definition = ADAPTERS.get(adapter_key)
    if definition is None:
        raise KeyError(f"Unknown adapter: {adapter_key}")
    return definition


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


def runtime_config(instance: EngineInstanceRecord) -> dict[str, str | int | bool]:
    config = engine_config(instance)
    if instance.adapter_key == "clamav":
        return get_clamav_config(config)
    if instance.adapter_key == "yara":
        return get_yara_config(config)
    return {"mode": "builtin", "enabled": True}


def engine_health(instance: EngineInstanceRecord) -> dict[str, str | bool]:
    config = engine_config(instance)
    if instance.adapter_key == "clamav":
        return check_clamav_health(config)
    if instance.adapter_key == "yara":
        return check_yara_health(config)
    return {
        "ok": True,
        "status": "available",
        "detail": "Built-in analyzer is available.",
    }


def run_engine(instance: EngineInstanceRecord, scan: ScanRecord) -> EngineResultInput:
    config = engine_config(instance)
    if instance.adapter_key == "clamav":
        return run_clamav_engine(scan, config)
    if instance.adapter_key == "yara":
        return run_yara_engine(scan, config)
    return run_static_metadata_engine(scan)


def config_value(config: dict[str, str], key: str, fallback: str) -> str:
    value = config.get(key)
    if value is None or not value.strip():
        return fallback
    return value.strip()


def clamav_form_values(instance: EngineInstanceRecord | None) -> dict[str, str]:
    config = engine_config(instance) if instance is not None else {}
    return {
        "host": config_value(config, "host", get_setting("clamav.host", "") or ""),
        "port": config_value(config, "port", get_setting("clamav.port", "3310") or "3310"),
        "command": config_value(
            config,
            "command",
            get_setting("clamav.command", "clamscan") or "clamscan",
        ),
        "timeout_seconds": config_value(
            config,
            "timeout_seconds",
            get_setting("clamav.timeout_seconds", "60") or "60",
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
