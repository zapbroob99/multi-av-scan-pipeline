from __future__ import annotations

import hashlib
import json
import time

from app.database import (
    ensure_legacy_service_client_profile,
    get_api_client_credential_by_hash,
    get_default_scan_profile_for_client,
    get_service_client,
    get_service_client_by_key,
    list_engine_instances_by_ids,
    list_scan_profile_engines,
)
from app.models import (
    ApiClientIdentity,
    EngineInstanceRecord,
    ScanBatchRecord,
    ScanRecord,
)
from app.services.engine_registry import (
    adapter_capabilities,
    adapter_definition,
    configured_engines,
    engine_allowed_for_source,
)


PROFILE_SNAPSHOT_VERSION = 1


def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def seed_legacy_service_client() -> ApiClientIdentity:
    client, profile = ensure_legacy_service_client_profile(
        [engine.id for engine in configured_engines()]
    )
    return ApiClientIdentity(
        client=client,
        profile=profile,
        credential_id=None,
        legacy_credential=True,
    )


def legacy_service_client_identity() -> ApiClientIdentity:
    """Resolve the startup-seeded compatibility identity without per-request writes."""
    client = get_service_client_by_key("legacy-default")
    if client is None:
        return seed_legacy_service_client()
    profile = get_default_scan_profile_for_client(client.id)
    if profile is None:
        return seed_legacy_service_client()
    return ApiClientIdentity(
        client=client,
        profile=profile,
        credential_id=None,
        legacy_credential=True,
    )


def identity_for_service_client_key(client_key: str) -> ApiClientIdentity:
    """Resolve a configured integration identity, including ICAP instances."""
    normalized_key = client_key.strip().lower() or "legacy-default"
    if normalized_key == "legacy-default":
        return legacy_service_client_identity()
    client = get_service_client_by_key(normalized_key)
    if client is None or not client.enabled:
        raise ValueError(f"Service client {normalized_key!r} is missing or disabled.")
    profile = get_default_scan_profile_for_client(client.id)
    if profile is None or not profile.enabled:
        raise ValueError(
            f"Service client {normalized_key!r} has no enabled default scan profile."
        )
    return ApiClientIdentity(
        client=client,
        profile=profile,
        credential_id=None,
        legacy_credential=False,
    )


def resolve_stored_api_client(token: str) -> ApiClientIdentity | None:
    credential = get_api_client_credential_by_hash(
        hash_api_token(token), current_time=int(time.time())
    )
    if credential is None:
        return None
    client = get_service_client(credential.service_client_id)
    if client is None or not client.enabled:
        return None
    profile = get_default_scan_profile_for_client(client.id)
    if profile is None or not profile.enabled:
        return None
    return ApiClientIdentity(
        client=client,
        profile=profile,
        credential_id=credential.id,
        legacy_credential=False,
    )


def _file_capable(engine: EngineInstanceRecord) -> bool:
    capabilities = adapter_capabilities(engine.adapter_key)
    return capabilities.supports_file_upload or capabilities.supports_file_hash_scan


def engines_for_profile(
    profile_id: int,
    *,
    source: str,
) -> list[EngineInstanceRecord]:
    return [
        engine
        for engine in list_scan_profile_engines(profile_id)
        if engine.enabled
        and engine_allowed_for_source(engine, source)
        and _file_capable(engine)
    ]


def hash_engines_for_profile(
    profile_id: int,
    *,
    source: str,
) -> list[EngineInstanceRecord]:
    return [
        engine
        for engine in list_scan_profile_engines(profile_id)
        if engine.enabled
        and engine_allowed_for_source(engine, source)
        and adapter_capabilities(engine.adapter_key).supports_hash_lookup
    ]


def profile_snapshot_json(
    identity: ApiClientIdentity,
    engines: list[EngineInstanceRecord],
) -> str:
    try:
        policy = json.loads(identity.profile.policy_json or "{}")
    except (TypeError, json.JSONDecodeError):
        policy = {}
    if not isinstance(policy, dict):
        policy = {}
    return json.dumps(
        {
            "version": PROFILE_SNAPSHOT_VERSION,
            "service_client": {
                "id": identity.client.id,
                "key": identity.client.client_key,
                "name": identity.client.display_name,
            },
            "scan_profile": {
                "id": identity.profile.id,
                "name": identity.profile.name,
                "policy": policy,
            },
            "engines": [
                {
                    "id": engine.id,
                    "adapter_key": engine.adapter_key,
                    "name": engine.display_name,
                    "detection": adapter_definition(engine.adapter_key).detection,
                    "required": True,
                }
                for engine in engines
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def parse_profile_snapshot(scan: ScanRecord) -> dict[str, object]:
    try:
        value = json.loads(scan.profile_snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def engines_for_scan(scan: ScanRecord) -> list[EngineInstanceRecord]:
    snapshot = parse_profile_snapshot(scan)
    raw_engines = snapshot.get("engines")
    instance_ids: list[int] = []
    if isinstance(raw_engines, list):
        for entry in raw_engines:
            if not isinstance(entry, dict):
                continue
            try:
                instance_ids.append(int(entry["id"]))
            except (KeyError, TypeError, ValueError):
                continue
    if instance_ids:
        return [
            engine
            for engine in list_engine_instances_by_ids(instance_ids)
            if engine.enabled
            and engine_allowed_for_source(engine, scan.source)
            and _file_capable(engine)
        ]
    if scan.scan_profile_id is not None:
        return engines_for_profile(scan.scan_profile_id, source=scan.source)
    # Historical/manual scans retain the global source-aware behavior.
    from app.services.engine_registry import enabled_engines

    return enabled_engines(source=scan.source)


def required_detection_engine_names(scan: ScanRecord) -> list[str]:
    snapshot = parse_profile_snapshot(scan)
    raw_engines = snapshot.get("engines")
    if isinstance(raw_engines, list):
        names = [
            str(entry.get("name"))
            for entry in raw_engines
            if isinstance(entry, dict)
            and entry.get("required", True)
            and entry.get("detection")
            and entry.get("name")
        ]
        if names:
            return names
    return [
        engine.display_name
        for engine in engines_for_scan(scan)
        if adapter_definition(engine.adapter_key).detection
    ]


def snapshot_labels(scan: ScanRecord) -> tuple[str | None, str | None]:
    snapshot = parse_profile_snapshot(scan)
    client = snapshot.get("service_client")
    profile = snapshot.get("scan_profile")
    client_name = (
        str(client.get("name"))
        if isinstance(client, dict) and client.get("name")
        else None
    )
    profile_name = (
        str(profile.get("name"))
        if isinstance(profile, dict) and profile.get("name")
        else None
    )
    return client_name, profile_name


def identity_can_access_scan(identity: ApiClientIdentity, scan: ScanRecord) -> bool:
    if scan.source != "api":
        return False
    service_client_id = getattr(scan, "service_client_id", None)
    if service_client_id == identity.client.id:
        return True
    return service_client_id is None and identity.client.client_key == "legacy-default"


def identity_can_access_batch(
    identity: ApiClientIdentity, batch: ScanBatchRecord
) -> bool:
    if batch.source != "api":
        return False
    service_client_id = getattr(batch, "service_client_id", None)
    if service_client_id == identity.client.id:
        return True
    return service_client_id is None and identity.client.client_key == "legacy-default"
