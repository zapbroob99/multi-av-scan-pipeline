import os

from app.models import EngineInstanceRecord
from app.services.engine_registry import adapter_capabilities


WINDOWS_DEFAULT_ENGINE_KEYS = ("static_metadata", "microsoft_defender")
POSIX_DEFAULT_ENGINE_KEYS = ("static_metadata", "clamav", "yara")


def worker_platform() -> str:
    return "windows" if os.name == "nt" else "linux"


def adapter_supported_on_platform(adapter_key: str, platform_name: str) -> bool:
    try:
        capabilities = adapter_capabilities(adapter_key)
    except KeyError:
        return False
    return platform_name in capabilities.supported_platforms


def worker_engine_keys() -> set[str]:
    configured = os.getenv("MASP_WORKER_ENGINE_KEYS", "").strip()
    if configured:
        raw_keys = {
            item.strip()
            for item in configured.split(",")
            if item.strip()
        }
    elif os.name == "nt":
        raw_keys = set(WINDOWS_DEFAULT_ENGINE_KEYS)
    else:
        raw_keys = set(POSIX_DEFAULT_ENGINE_KEYS)
    platform_name = worker_platform()
    return {
        adapter_key
        for adapter_key in raw_keys
        if adapter_supported_on_platform(adapter_key, platform_name)
    }


def supported_engines(
    engines: list[EngineInstanceRecord],
    engine_keys: set[str] | None = None,
) -> list[EngineInstanceRecord]:
    keys = worker_engine_keys() if engine_keys is None else engine_keys
    platform_name = worker_platform()
    return [
        engine
        for engine in engines
        if engine.adapter_key in keys
        and adapter_supported_on_platform(engine.adapter_key, platform_name)
    ]


def missing_supported_engines(
    engines: list[EngineInstanceRecord],
    existing_engine_names: set[str],
    engine_keys: set[str] | None = None,
) -> list[EngineInstanceRecord]:
    return [
        engine
        for engine in supported_engines(engines, engine_keys)
        if engine.display_name not in existing_engine_names
    ]


def all_enabled_engines_have_results(
    engines: list[EngineInstanceRecord],
    existing_engine_names: set[str],
) -> bool:
    return all(engine.display_name in existing_engine_names for engine in engines)
