from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from app import database as db

from app.database import (
    ensure_legacy_service_client_profile,
    get_api_client_credential_by_hash,
    get_default_scan_profile_for_client,
    get_service_client,
    get_service_client_by_key,
    list_engine_instances_by_ids,
    list_scan_engine_jobs,
    list_scan_profile_engines,
)
from app.models import (
    ApiClientIdentity,
    EngineInstanceRecord,
    ScanBatchRecord,
    ScanRecord,
    ScanEngineJobRecord,
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


def resolve_profile_routing(identity: ApiClientIdentity, profile_id: int | None = None, *,
                            source: str = 'api', hash_lookup: bool = False) -> tuple[ApiClientIdentity, list[EngineInstanceRecord]]:
    """Resolve only this client's live profile and engine set in one snapshot.

    A removed profile retains its database identity for accepted/deferred work,
    but is no longer selectable for a new submission.
    """
    if identity.legacy_credential:
        if profile_id is not None:
            raise ValueError('Scan profile is unavailable for this client.')
        return identity, engines_for_profile(identity.profile.id, source=source)
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        client = connection.execute('SELECT * FROM service_clients WHERE id = ? AND enabled = ?',
            (identity.client.id, db.db_bool(True))).fetchone()
        profile = connection.execute('''SELECT * FROM scan_profiles WHERE service_client_id = ?
            AND enabled = ? AND deleted_at IS NULL ''' +
            ('AND id = ? ' if profile_id is not None else '') + 'ORDER BY is_default DESC, id LIMIT 1',
            (identity.client.id, db.db_bool(True), *((profile_id,) if profile_id is not None else ()))).fetchone()
        if client is None or profile is None:
            raise ValueError('Scan profile is unavailable for this client.')
        rows = connection.execute('''SELECT e.* FROM scan_profile_engines pe JOIN engine_instances e
            ON e.id = pe.engine_instance_id WHERE pe.scan_profile_id = ? ORDER BY e.id''', (profile['id'],)).fetchall()
    selected = []
    for row in rows:
        engine = db.row_to_engine_instance_record(row)
        if engine.enabled and engine_allowed_for_source(engine, source) and (
            adapter_capabilities(engine.adapter_key).supports_hash_lookup if hash_lookup else _file_capable(engine)
        ):
            selected.append(engine)
    return replace(identity, client=db.row_to_service_client_record(client), profile=db.row_to_scan_profile_record(profile)), selected


def profile_snapshot_json(
    identity: ApiClientIdentity,
    engines: list[EngineInstanceRecord],
    *,
    delivery_mode: str | None = None,
    client_request_id: str | None = None,
) -> str:
    try:
        policy = json.loads(identity.profile.policy_json or "{}")
    except (TypeError, json.JSONDecodeError):
        policy = {}
    if not isinstance(policy, dict):
        policy = {}
    snapshot: dict[str, object] = {
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
        }
    if delivery_mode:
        snapshot["delivery"] = {
            "mode": delivery_mode,
            "client_request_id": client_request_id,
        }
    return json.dumps(
        snapshot,
        separators=(",", ":"),
        sort_keys=True,
    )


def parse_profile_snapshot(scan: ScanRecord) -> dict[str, object]:
    try:
        value = json.loads(scan.profile_snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def is_security_event_deferred_scan(scan: ScanRecord) -> bool:
    """Return whether a scan belongs to the long-lived deferred intake flow."""
    delivery = parse_profile_snapshot(scan).get("delivery")
    return (
        isinstance(delivery, dict)
        and delivery.get("mode") == "security_events_only"
    )


def engines_for_scan(scan: ScanRecord) -> list[EngineInstanceRecord]:
    snapshot = parse_profile_snapshot(scan)
    raw_engines = snapshot.get("engines")
    if isinstance(raw_engines, list):
        # An explicit empty snapshot must not fall back to the current profile.
        return engines_for_snapshot_json(scan.profile_snapshot_json, source=scan.source)
    if scan.scan_profile_id is not None:
        return engines_for_profile(scan.scan_profile_id, source=scan.source)
    # Historical/manual scans retain the global source-aware behavior.
    from app.services.engine_registry import enabled_engines

    return enabled_engines(source=scan.source)


def engines_for_snapshot_json(
    snapshot_json: str, *, source: str, strict: bool = False
) -> list[EngineInstanceRecord]:
    try:
        snapshot = json.loads(snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        snapshot = {}
    raw_engines = snapshot.get("engines") if isinstance(snapshot, dict) else None
    instance_ids: list[int] = []
    snapshot_names: dict[int, str] = {}
    if isinstance(raw_engines, list):
        for entry in raw_engines:
            if not isinstance(entry, dict):
                continue
            try:
                instance_id = int(entry["id"])
            except (KeyError, TypeError, ValueError):
                continue
            instance_ids.append(instance_id)
            snapshot_name = str(entry.get("name") or "").strip()
            if snapshot_name:
                snapshot_names[instance_id] = snapshot_name
    engines = [
        replace(
            engine,
            display_name=snapshot_names.get(engine.id, engine.display_name),
        )
        for engine in list_engine_instances_by_ids(instance_ids)
        if engine.enabled
        and engine_allowed_for_source(engine, source)
        and _file_capable(engine)
    ]
    if strict:
        requested = set(instance_ids)
        resolved = {engine.id for engine in engines}
        missing = requested - resolved
        if missing or len(resolved) != len(requested):
            raise ValueError(
                "Deferred routing snapshot contains unavailable engine instances: "
                + ", ".join(str(value) for value in sorted(missing))
            )
    return engines


def required_detection_engine_names(scan: ScanRecord, *, jobs: list[ScanEngineJobRecord] | None = None) -> list[str]:
    snapshot = parse_profile_snapshot(scan)
    raw_engines = snapshot.get("engines")
    if isinstance(raw_engines, list):
        return [
            str(entry.get("name"))
            for entry in raw_engines
            if isinstance(entry, dict)
            and entry.get("required", True)
            and entry.get("detection")
            and entry.get("name")
        ]

    # Manual and historical scans may predate routing snapshots, but every
    # modern intake still has immutable engine-job rows. Use their snapshotted
    # names and adapter keys so later instance renames/enables do not rewrite a
    # completed scan's coverage. Fall back to current configuration only for
    # truly legacy scans without engine jobs.
    jobs = list_scan_engine_jobs(scan.id) if jobs is None else jobs
    if jobs:
        names: list[str] = []
        for job in jobs:
            try:
                detection = adapter_definition(job.engine_key).detection
            except KeyError:
                detection = True
            if detection:
                names.append(job.engine_name)
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
