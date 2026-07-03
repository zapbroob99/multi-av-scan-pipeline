import os

from app.models import EngineInstanceRecord


WINDOWS_DEFAULT_ENGINE_KEYS = ("static_metadata", "microsoft_defender")
POSIX_DEFAULT_ENGINE_KEYS = ("static_metadata", "clamav", "yara")


def worker_engine_keys() -> set[str]:
    configured = os.getenv("MASP_WORKER_ENGINE_KEYS", "").strip()
    if configured:
        return {
            item.strip()
            for item in configured.split(",")
            if item.strip()
        }
    if os.name == "nt":
        return set(WINDOWS_DEFAULT_ENGINE_KEYS)
    return set(POSIX_DEFAULT_ENGINE_KEYS)


def supported_engines(
    engines: list[EngineInstanceRecord],
    engine_keys: set[str] | None = None,
) -> list[EngineInstanceRecord]:
    keys = worker_engine_keys() if engine_keys is None else engine_keys
    return [engine for engine in engines if engine.adapter_key in keys]


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
