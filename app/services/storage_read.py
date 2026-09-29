"""Folder Scanning reads: locations, their inventory and findings.

Every read is bounded and keyset-paged, never totals over history except the
per-location state counts an operator needs to judge coverage. Light-tier
states are reported as what they are; nothing here turns "no finding" into
"clean".
"""
from __future__ import annotations

import json
import time
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget
from app.services.deferred_storage import redact_paths
from app.services.storage_inventory import STATES
from app.services.storage_policy import StoragePolicy, parse_policy
from app.services.storage_protection import LAST_CYCLE_SETTING

LOCATION_LIMIT = 100
TEXT_LIMIT = 1000
PATH_LIMIT = 1024
STALE_POLL_INTERVALS = 4
MIN_STALE_SECONDS = 60
# A location cycle older than this, with the worker otherwise alive, means the
# location is not being run (lease held elsewhere, backend not mounted).
LOCATION_STALE_SECONDS = 900

ObjectState = Literal["waiting", "changed", "light_passed", "light_detected", "full_pending",
                      "unreadable", "removed"]


class StorageWorker(BaseModel):
    at: int
    age_seconds: int
    stale: bool
    ok: bool
    error: str | None
    poll_seconds: float
    locations: int
    worker_id: str | None
    backends: list[str]


class LocationCycle(BaseModel):
    at: int
    age_seconds: int
    ok: bool
    error: str | None
    pass_id: int | None
    pass_completed: bool
    crawled: int
    new: int
    changed: int
    removed: int
    inspected: int
    findings: int
    directory_errors: int
    errors: list[str]


class PassSummary(BaseModel):
    id: int
    status: Literal["running", "completed", "abandoned"]
    started_at: int
    finished_at: int | None
    objects_seen: int
    objects_new: int
    objects_changed: int
    objects_removed: int


class NamedRef(BaseModel):
    id: int
    name: str


class StateCounts(BaseModel):
    waiting: int
    changed: int
    light_passed: int
    light_detected: int
    full_pending: int
    unreadable: int
    removed: int


class LocationSummary(BaseModel):
    id: int
    name: str
    enabled: bool
    mode: Literal["crawl", "manifest", "both"]
    backend_key: str
    prefix: str
    client: NamedRef
    profile: NamedRef
    policy_revision: int
    management_revision: int
    counts: StateCounts
    detected_findings: int
    last_cycle: LocationCycle | None
    last_cycle_invalid: bool
    last_completed_pass: PassSummary | None
    current_pass: PassSummary | None


class StorageOverview(BaseModel):
    worker: StorageWorker | None
    worker_record_invalid: bool
    locations: list[LocationSummary]
    locations_truncated: bool


class LocationDetail(LocationSummary):
    policy: StoragePolicy
    policy_invalid: bool


class StorageObject(BaseModel):
    id: int
    object_id: str
    size_bytes: int
    state: ObjectState
    tier: Literal["full", "light"] | None
    detected_type: str | None
    families: list[str]
    sha256: str | None
    hash_list_kind: Literal["block", "allow"] | None
    finding_count: int
    policy_revision: int | None
    first_seen_at: int
    last_changed_at: int
    processed_at: int | None
    last_error: str | None


class ObjectPage(BaseModel):
    items: list[StorageObject]
    next_before: int | None


class StorageFinding(BaseModel):
    id: int
    location: NamedRef
    storage_object_id: int
    object_id: str
    object_state: ObjectState | None
    sha256: str | None
    kind: Literal["type_policy", "type_mismatch", "archive_policy", "hash_block"]
    severity: str
    detected: bool
    title: str
    detail: dict
    policy_revision: int
    created_at: int


class FindingPage(BaseModel):
    items: list[StorageFinding]
    next_before: int | None


def _record(raw: str | None) -> tuple[dict | None, bool]:
    if not raw:
        return None, False
    try:
        record = json.loads(raw)
        int(record["at"])
    except (ValueError, TypeError, KeyError):
        return None, True
    return record, False


def worker_status(raw: str | None, now: int) -> tuple[StorageWorker | None, bool]:
    record, invalid = _record(raw)
    if record is None:
        return None, invalid
    try:
        age = max(0, now - int(record["at"]))
        poll = float(record.get("poll_seconds") or 0)
        return StorageWorker(
            at=int(record["at"]), age_seconds=age, ok=bool(record.get("ok")),
            stale=age > max(MIN_STALE_SECONDS, STALE_POLL_INTERVALS * poll),
            error=redact_paths(str(record["error"]))[:TEXT_LIMIT] if record.get("error") else None,
            poll_seconds=poll, locations=int(record.get("locations") or 0),
            worker_id=str(record["worker_id"])[:256] if record.get("worker_id") else None,
            backends=[str(item)[:128] for item in (record.get("backends") or [])][:50]), False
    except (ValueError, TypeError):
        return None, True


def location_cycle(raw: str | None, now: int) -> tuple[LocationCycle | None, bool]:
    record, invalid = _record(raw)
    if record is None:
        return None, invalid
    try:
        return LocationCycle(
            at=int(record["at"]), age_seconds=max(0, now - int(record["at"])), ok=bool(record.get("ok")),
            error=redact_paths(str(record["error"]))[:TEXT_LIMIT] if record.get("error") else None,
            pass_id=record.get("pass_id"), pass_completed=bool(record.get("pass_completed")),
            **{key: int(record.get(key) or 0) for key in (
                "crawled", "new", "changed", "removed", "inspected", "findings", "directory_errors")},
            errors=[redact_paths(str(item))[:300] for item in (record.get("errors") or [])][:5]), False
    except (ValueError, TypeError):
        return None, True


def _pass(row) -> PassSummary | None:
    return None if row is None else PassSummary(**{key: row[key] for key in PassSummary.model_fields})


_LOCATION_COLUMNS = """l.id, SUBSTR(l.name, 1, 128) AS name, l.enabled, l.mode, l.backend_key,
    SUBSTR(l.prefix, 1, 1024) AS prefix, l.service_client_id, SUBSTR(c.display_name, 1, 256) AS client_name,
    l.scan_profile_id, SUBSTR(p.name, 1, 256) AS profile_name, l.policy_revision, l.management_revision,
    r.last_cycle_json"""
_LOCATION_FROM = """FROM storage_locations l
    JOIN service_clients c ON c.id = l.service_client_id
    JOIN scan_profiles p ON p.id = l.scan_profile_id
    LEFT JOIN storage_location_runtime r ON r.location_id = l.id"""


def _summaries(connection, rows, now: int) -> list[dict]:
    ids = [int(row["id"]) for row in rows]
    counts: dict[int, dict[str, int]] = {location_id: {} for location_id in ids}
    detected: dict[int, int] = {}
    passes: dict[int, tuple] = {}
    if ids:
        marks = ", ".join("?" for _ in ids)
        for row in connection.execute(f"""SELECT location_id, state, COUNT(*) AS entries FROM storage_objects
                WHERE location_id IN ({marks}) GROUP BY location_id, state""", tuple(ids)).fetchall():
            counts[int(row["location_id"])][str(row["state"])] = int(row["entries"])
        for row in connection.execute(f"""SELECT location_id, COUNT(*) AS entries FROM storage_findings
                WHERE location_id IN ({marks}) AND detected = ? GROUP BY location_id""",
                (*ids, db.db_bool(True))).fetchall():
            detected[int(row["location_id"])] = int(row["entries"])
        for location_id in ids:
            completed = connection.execute("""SELECT * FROM storage_passes WHERE location_id = ?
                AND status = 'completed' ORDER BY id DESC LIMIT 1""", (location_id,)).fetchone()
            running = connection.execute("""SELECT * FROM storage_passes WHERE location_id = ?
                AND status = 'running' ORDER BY id DESC LIMIT 1""", (location_id,)).fetchone()
            passes[location_id] = (_pass(completed), _pass(running))
    summaries = []
    for row in rows:
        location_id = int(row["id"])
        cycle, invalid = location_cycle(row["last_cycle_json"], now)
        summaries.append({
            "id": location_id, "name": row["name"], "enabled": bool(row["enabled"]), "mode": row["mode"],
            "backend_key": row["backend_key"], "prefix": row["prefix"],
            "client": NamedRef(id=int(row["service_client_id"]), name=row["client_name"] or ""),
            "profile": NamedRef(id=int(row["scan_profile_id"]), name=row["profile_name"] or ""),
            "policy_revision": int(row["policy_revision"]), "management_revision": int(row["management_revision"]),
            "counts": StateCounts(**{state: counts[location_id].get(state, 0) for state in STATES}),
            "detected_findings": detected.get(location_id, 0),
            "last_cycle": cycle, "last_cycle_invalid": invalid,
            "last_completed_pass": passes[location_id][0], "current_pass": passes[location_id][1],
        })
    return summaries


def overview() -> StorageOverview:
    now = int(time.time())
    with db.connect() as connection:
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ" if db.using_postgres() else "BEGIN")
        apply_read_budget(connection)
        setting = connection.execute("SELECT value FROM app_settings WHERE key = ?",
                                     (LAST_CYCLE_SETTING,)).fetchone()
        rows = connection.execute(f"SELECT {_LOCATION_COLUMNS} {_LOCATION_FROM} ORDER BY l.id LIMIT ?",
                                  (LOCATION_LIMIT + 1,)).fetchall()
        summaries = _summaries(connection, rows[:LOCATION_LIMIT], now)
    worker, invalid = worker_status(setting["value"] if setting else None, now)
    return StorageOverview(worker=worker, worker_record_invalid=invalid,
                           locations=[LocationSummary(**item) for item in summaries],
                           locations_truncated=len(rows) > LOCATION_LIMIT)


def location(location_id: int) -> LocationDetail:
    now = int(time.time())
    with db.connect() as connection:
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ" if db.using_postgres() else "BEGIN")
        apply_read_budget(connection)
        row = connection.execute(f"SELECT {_LOCATION_COLUMNS}, l.policy_json {_LOCATION_FROM} WHERE l.id = ?",
                                 (location_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Storage location not found.")
        summary = _summaries(connection, [row], now)[0]
    try:
        policy, invalid = parse_policy(str(row["policy_json"])), False
    except ValueError:
        # Never present a default as if it were the stored policy.
        policy, invalid = StoragePolicy(), True
    return LocationDetail(**summary, policy=policy, policy_invalid=invalid)


def _literal(term: str) -> str:
    return term.replace("!", "!!").replace("%", "!%").replace("_", "!_")


def objects(location_id: int, *, limit: int, before: int | None, state: str, query: str) -> ObjectPage:
    conditions, values = ["location_id = ?"], [location_id]
    if before is not None:
        conditions.append("id < ?")
        values.append(before)
    if state != "all":
        conditions.append("state = ?")
        values.append(state)
    if query.strip():
        conditions.append("object_id LIKE ? ESCAPE '!'")
        values.append("%" + _literal(query.strip()) + "%")
    with db.connect() as connection:
        apply_read_budget(connection)
        if connection.execute("SELECT 1 FROM storage_locations WHERE id = ?", (location_id,)).fetchone() is None:
            raise HTTPException(404, "Storage location not found.")
        rows = connection.execute(f"""SELECT id, SUBSTR(object_id, 1, {PATH_LIMIT}) AS object_id, size_bytes, state,
            tier, detected_type, families, sha256, hash_list_kind, finding_count, policy_revision,
            first_seen_at, last_changed_at, processed_at, SUBSTR(last_error, 1, {TEXT_LIMIT}) AS last_error
            FROM storage_objects WHERE {' AND '.join(conditions)} ORDER BY id DESC LIMIT ?""",
            (*values, limit + 1)).fetchall()
    items = [StorageObject(**{**dict(row), "families": [item for item in str(row["families"] or "").split(",") if item],
                              "last_error": redact_paths(row["last_error"]) if row["last_error"] else None})
             for row in rows[:limit]]
    return ObjectPage(items=items, next_before=items[-1].id if len(rows) > limit else None)


def findings(*, limit: int, before: int | None, location_id: int | None, kind: str,
             detected: str) -> FindingPage:
    conditions, values = [], []
    if before is not None:
        conditions.append("f.id < ?")
        values.append(before)
    if location_id is not None:
        conditions.append("f.location_id = ?")
        values.append(location_id)
    if kind != "all":
        conditions.append("f.kind = ?")
        values.append(kind)
    if detected != "all":
        conditions.append("f.detected = ?")
        values.append(db.db_bool(detected == "detected"))
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute(f"""SELECT f.id, f.location_id, SUBSTR(l.name, 1, 128) AS location_name,
            f.storage_object_id, SUBSTR(f.object_id, 1, {PATH_LIMIT}) AS object_id, o.state AS object_state,
            f.sha256, f.kind, f.severity, f.detected, SUBSTR(f.title, 1, 500) AS title,
            SUBSTR(f.detail_json, 1, 4096) AS detail_json, f.policy_revision, f.created_at
            FROM storage_findings f JOIN storage_locations l ON l.id = f.location_id
            LEFT JOIN storage_objects o ON o.id = f.storage_object_id{where}
            ORDER BY f.id DESC LIMIT ?""", (*values, limit + 1)).fetchall()
    items = []
    for row in rows[:limit]:
        try:
            detail = json.loads(row["detail_json"] or "{}")
        except json.JSONDecodeError:
            detail = {"truncated": True}
        items.append(StorageFinding(
            id=int(row["id"]), location=NamedRef(id=int(row["location_id"]), name=row["location_name"]),
            storage_object_id=int(row["storage_object_id"]), object_id=row["object_id"],
            object_state=row["object_state"], sha256=row["sha256"], kind=row["kind"],
            severity=row["severity"], detected=bool(row["detected"]), title=row["title"],
            detail=detail if isinstance(detail, dict) else {}, policy_revision=int(row["policy_revision"]),
            created_at=int(row["created_at"])))
    return FindingPage(items=items, next_before=items[-1].id if len(rows) > limit else None)
