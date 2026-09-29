"""Admin management of protected storage locations.

A location's identity (client, backend, prefix) is fixed at creation: its
inventory describes exactly that tree, so pointing it elsewhere would make
every recorded object and finding describe the wrong files. Name, profile,
policy and enabled state can change under a management-revision fence.
Deletion is not offered; disabling stops the worker and keeps every finding.
"""
from __future__ import annotations

import time
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app import database as db
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms
from app.services.content_types import FAMILIES
from app.services.deferred_storage import (
    DeferredSourceError,
    client_backend_scope,
    configured_backend_keys,
    validate_object_id,
)
from app.services.storage_policy import StoragePolicy, policy_json

CLIENT_LIMIT = 200
PROFILE_LIMIT = 2000
MANAGED_CLIENT = "legacy-default"


class ProfileChoice(BaseModel):
    id: int
    name: str
    enabled: bool


class ClientChoice(BaseModel):
    id: int
    name: str
    client_key: str
    enabled: bool
    profiles: list[ProfileChoice]


class StorageOptions(BaseModel):
    backends: list[str]
    clients: list[ClientChoice]
    clients_truncated: bool
    families: list[str]
    default_policy: StoragePolicy


class LocationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=128)
    service_client_id: int = Field(ge=1, le=9007199254740991)
    scan_profile_id: int = Field(ge=1, le=9007199254740991)
    backend_key: str = Field(min_length=1, max_length=128)
    prefix: str = Field(default="", max_length=512)
    # Manifest and combined discovery arrive with a later phase.
    mode: Literal["crawl"] = "crawl"
    enabled: bool = True
    policy: StoragePolicy


class LocationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_management_revision: int = Field(ge=0, le=9007199254740991)
    name: str = Field(min_length=1, max_length=128)
    scan_profile_id: int = Field(ge=1, le=9007199254740991)
    enabled: bool
    policy: StoragePolicy


class LocationCreated(BaseModel):
    id: int


def options() -> StorageOptions:
    with db.connect() as connection:
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ" if db.using_postgres() else "BEGIN")
        apply_read_budget(connection)
        clients = connection.execute("""SELECT id, SUBSTR(display_name, 1, 256) AS name,
            SUBSTR(client_key, 1, 128) AS client_key, enabled FROM service_clients
            WHERE client_key != ? ORDER BY id LIMIT ?""", (MANAGED_CLIENT, CLIENT_LIMIT + 1)).fetchall()
        shown = clients[:CLIENT_LIMIT]
        profiles: dict[int, list[ProfileChoice]] = {int(row["id"]): [] for row in shown}
        if shown:
            marks = ", ".join("?" for _ in shown)
            for row in connection.execute(f"""SELECT id, service_client_id, SUBSTR(name, 1, 256) AS name, enabled
                    FROM scan_profiles WHERE deleted_at IS NULL AND service_client_id IN ({marks})
                    ORDER BY service_client_id, id LIMIT ?""",
                    (*[int(row["id"]) for row in shown], PROFILE_LIMIT)).fetchall():
                profiles[int(row["service_client_id"])].append(
                    ProfileChoice(id=int(row["id"]), name=row["name"], enabled=bool(row["enabled"])))
    try:
        backends = sorted(configured_backend_keys())
    except DeferredSourceError as exc:
        raise HTTPException(503, "Deployment storage configuration is invalid.") from exc
    return StorageOptions(
        backends=backends,
        clients=[ClientChoice(id=int(row["id"]), name=row["name"], client_key=row["client_key"],
                              enabled=bool(row["enabled"]), profiles=profiles[int(row["id"])]) for row in shown],
        clients_truncated=len(clients) > CLIENT_LIMIT, families=list(FAMILIES), default_policy=StoragePolicy())


def _normalized_prefix(prefix: str) -> str:
    cleaned = prefix.strip().strip("/")
    if not cleaned:
        return ""
    try:
        return validate_object_id(cleaned)
    except DeferredSourceError as exc:
        raise HTTPException(422, "Prefix must be a relative path inside the backend.") from exc


def _overlaps(first: str, second: str) -> bool:
    if not first or not second:
        return True
    return first == second or first.startswith(second + "/") or second.startswith(first + "/")


def _lock(connection) -> None:
    if db.using_postgres():
        connection.execute("SELECT set_config('lock_timeout', ?, true)", (f"{write_lock_timeout_ms()}ms",))
        # Serializes location writes so the overlap check sees every committed location.
        connection.execute("SELECT pg_advisory_xact_lock(?)", (7_401_117_001,))
    else:
        connection.execute("BEGIN IMMEDIATE")


def _checked_profile(connection, client_id: int, profile_id: int) -> None:
    profile = connection.execute("""SELECT service_client_id, enabled, deleted_at FROM scan_profiles
        WHERE id = ?""", (profile_id,)).fetchone()
    if (profile is None or int(profile["service_client_id"]) != client_id or profile["deleted_at"] is not None
            or not bool(profile["enabled"])):
        raise HTTPException(422, "Select an enabled scan profile owned by the location's client.")


def _name_taken(connection, name: str, exclude_id: int | None = None) -> bool:
    row = connection.execute("SELECT id FROM storage_locations WHERE name = ?", (name,)).fetchone()
    return row is not None and int(row["id"]) != exclude_id


def create(body: LocationCreate, created_by: str) -> LocationCreated:
    name = body.name.strip()
    if not name:
        raise HTTPException(422, "Name is required.")
    prefix = _normalized_prefix(body.prefix)
    backend = body.backend_key.strip().lower()
    try:
        if backend not in configured_backend_keys():
            raise HTTPException(422, "Select a backend configured on this deployment.")
    except DeferredSourceError as exc:
        raise HTTPException(503, "Deployment storage configuration is invalid.") from exc
    now = int(time.time())
    with db.connect() as connection:
        _lock(connection)
        client = connection.execute("SELECT client_key, enabled FROM service_clients WHERE id = ?",
                                    (body.service_client_id,)).fetchone()
        if client is None or client["client_key"] == MANAGED_CLIENT:
            raise HTTPException(422, "Select a service client.")
        if not bool(client["enabled"]):
            raise HTTPException(422, "The service client is disabled.")
        _checked_profile(connection, body.service_client_id, body.scan_profile_id)
        try:
            scope = client_backend_scope(backend, str(client["client_key"]))
        except DeferredSourceError as exc:
            raise HTTPException(503, "Deployment storage configuration is invalid.") from exc
        if scope is None or not scope.covers_prefix(prefix):
            raise HTTPException(422, "The client's storage grant does not cover this backend and prefix. "
                                     "Grant access under Service clients > Storage first.")
        if _name_taken(connection, name):
            raise HTTPException(409, "A storage location with this name already exists.")
        for row in connection.execute("SELECT prefix FROM storage_locations WHERE backend_key = ?",
                                      (backend,)).fetchall():
            if _overlaps(prefix, str(row["prefix"])):
                raise HTTPException(409, "Another location already covers part of this tree. "
                                         "Locations on one backend must not overlap.")
        cursor = connection.execute(f"""INSERT INTO storage_locations
            (name, service_client_id, scan_profile_id, backend_key, prefix, mode, enabled, policy_json,
             created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) {db.returning_id_clause()}""",
            (name, body.service_client_id, body.scan_profile_id, backend, prefix, body.mode,
             db.db_bool(body.enabled), policy_json(body.policy), created_by, now, now))
        return LocationCreated(id=db.require_lastrowid(cursor))


def update(location_id: int, body: LocationUpdate) -> None:
    name = body.name.strip()
    if not name:
        raise HTTPException(422, "Name is required.")
    stored_policy = policy_json(body.policy)
    with db.connect() as connection:
        _lock(connection)
        row = connection.execute("""SELECT service_client_id, policy_json, management_revision
            FROM storage_locations WHERE id = ?""" + (" FOR UPDATE" if db.using_postgres() else ""),
            (location_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Storage location not found.")
        if int(row["management_revision"]) != body.expected_management_revision:
            raise HTTPException(409, "The location changed since it was displayed. Refresh before saving.")
        _checked_profile(connection, int(row["service_client_id"]), body.scan_profile_id)
        if _name_taken(connection, name, exclude_id=location_id):
            raise HTTPException(409, "A storage location with this name already exists.")
        policy_changed = str(row["policy_json"]) != stored_policy
        connection.execute("""UPDATE storage_locations SET name = ?, scan_profile_id = ?, enabled = ?,
            policy_json = ?, policy_revision = policy_revision + ?, management_revision = management_revision + 1,
            updated_at = ? WHERE id = ?""",
            (name, body.scan_profile_id, db.db_bool(body.enabled), stored_policy, 1 if policy_changed else 0,
             int(time.time()), location_id))
