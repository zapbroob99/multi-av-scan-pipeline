"""Database access for protected storage locations and their inventory.

Only the protection worker writes inventory rows, and it holds a per-location
lease while it does, so crawl and inspection for one location never race each
other. Every write that depends on what an earlier read saw is still fenced on
that observation (size and modification time), so a lost lease cannot apply a
stale result.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any, Iterable

from app import database as db
from app.services.storage_policy import LightFinding, StoragePolicy, parse_policy, policy_json

# Object states. Only the two "due" states are ever picked up for inspection.
DUE_STATES = ("waiting", "changed")
STATES = ("waiting", "changed", "light_passed", "light_detected", "full_pending",
          "unreadable", "removed")
LOCATION_MODES = ("crawl", "manifest", "both")
NOTIFY_SEVERITIES = ("high", "critical")
_IN_CHUNK = 400


@dataclass(frozen=True)
class StorageLocation:
    id: int
    name: str
    service_client_id: int
    scan_profile_id: int
    backend_key: str
    prefix: str
    mode: str
    enabled: bool
    policy: StoragePolicy
    policy_revision: int
    management_revision: int
    # Set when the stored policy cannot be parsed; the location then refuses to
    # run rather than falling back to defaults it was never configured with.
    policy_error: str | None = None


@dataclass(frozen=True)
class Runtime:
    location_id: int
    pass_id: int | None
    stack: list[str]
    errors: int
    next_pass_at: int


def _location(row: Any) -> StorageLocation:
    try:
        policy, error = parse_policy(str(row["policy_json"])), None
    except ValueError as exc:
        policy, error = StoragePolicy(), f"The stored policy is invalid: {str(exc)[:200]}"
    return StorageLocation(
        id=int(row["id"]), name=str(row["name"]), service_client_id=int(row["service_client_id"]),
        scan_profile_id=int(row["scan_profile_id"]), backend_key=str(row["backend_key"]),
        prefix=str(row["prefix"]), mode=str(row["mode"]), enabled=bool(row["enabled"]),
        policy=policy, policy_revision=int(row["policy_revision"]),
        management_revision=int(row["management_revision"]), policy_error=error)


def create_location(*, name: str, service_client_id: int, scan_profile_id: int, backend_key: str,
                    prefix: str, mode: str, policy: StoragePolicy, enabled: bool = True,
                    created_by: str | None = None) -> int:
    now = int(time.time())
    with db.connect() as connection:
        cursor = connection.execute(f"""INSERT INTO storage_locations
            (name, service_client_id, scan_profile_id, backend_key, prefix, mode, enabled,
             policy_json, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) {db.returning_id_clause()}""",
            (name, service_client_id, scan_profile_id, backend_key, prefix, mode, db.db_bool(enabled),
             policy_json(policy), created_by, now, now))
        return db.require_lastrowid(cursor)


def get_location(location_id: int) -> StorageLocation | None:
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM storage_locations WHERE id = ?", (location_id,)).fetchone()
    return None if row is None else _location(row)


def enabled_locations(backend_keys: Iterable[str]) -> list[StorageLocation]:
    keys = sorted(set(backend_keys))
    if not keys:
        return []
    marks = ", ".join("?" for _ in keys)
    with db.connect() as connection:
        rows = connection.execute(f"""SELECT * FROM storage_locations
            WHERE enabled = ? AND backend_key IN ({marks}) ORDER BY id""",
            (db.db_bool(True), *keys)).fetchall()
    return [_location(row) for row in rows]


def claim_location(location_id: int, worker_id: str, lease_seconds: int, now: int) -> bool:
    """Take or renew the per-location lease; one worker crawls a location."""
    with db.connect() as connection:
        connection.execute("""INSERT INTO storage_location_runtime (location_id, updated_at)
            VALUES (?, ?) ON CONFLICT (location_id) DO NOTHING""", (location_id, now))
        cursor = connection.execute("""UPDATE storage_location_runtime
            SET worker_id = ?, lease_expires_at = ?, updated_at = ?
            WHERE location_id = ? AND (worker_id IS NULL OR worker_id = ?
                                       OR lease_expires_at IS NULL OR lease_expires_at <= ?)""",
            (worker_id, now + lease_seconds, now, location_id, worker_id, now))
        return int(cursor.rowcount) > 0


def release_location(location_id: int, worker_id: str) -> None:
    with db.connect() as connection:
        connection.execute("""UPDATE storage_location_runtime SET worker_id = NULL, lease_expires_at = NULL
            WHERE location_id = ? AND worker_id = ?""", (location_id, worker_id))


def get_runtime(location_id: int) -> Runtime:
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM storage_location_runtime WHERE location_id = ?",
                                 (location_id,)).fetchone()
    if row is None:
        return Runtime(location_id, None, [], 0, 0)
    try:
        cursor = json.loads(str(row["cursor_json"] or "{}"))
    except json.JSONDecodeError:
        cursor = {}
    if not isinstance(cursor, dict):
        cursor = {}
    stack = [str(item) for item in cursor.get("stack", []) if isinstance(item, str)]
    return Runtime(location_id, None if row["pass_id"] is None else int(row["pass_id"]),
                   stack, int(cursor.get("errors", 0) or 0), int(row["next_pass_at"] or 0))


def save_cursor(location_id: int, worker_id: str, pass_id: int | None, stack: list[str],
                errors: int, next_pass_at: int, now: int) -> bool:
    with db.connect() as connection:
        cursor = connection.execute("""UPDATE storage_location_runtime
            SET pass_id = ?, cursor_json = ?, next_pass_at = ?, updated_at = ?
            WHERE location_id = ? AND worker_id = ?""",
            (pass_id, json.dumps({"stack": stack, "errors": errors}, separators=(",", ":")),
             next_pass_at, now, location_id, worker_id))
        return int(cursor.rowcount) > 0


def record_location_cycle(location_id: int, payload: dict) -> None:
    """Best effort: visibility must never stop protection."""
    try:
        with db.connect() as connection:
            connection.execute("""UPDATE storage_location_runtime SET last_cycle_json = ?
                WHERE location_id = ?""", (json.dumps(payload, sort_keys=True), location_id))
    except Exception:  # noqa: BLE001
        pass


def start_pass(location_id: int, now: int) -> int:
    with db.connect() as connection:
        # A pass that never finished (lost lease, restart) cannot prove removals.
        connection.execute("""UPDATE storage_passes SET status = 'abandoned', finished_at = ?
            WHERE location_id = ? AND status = 'running'""", (now, location_id))
        cursor = connection.execute(f"""INSERT INTO storage_passes (location_id, status, started_at)
            VALUES (?, 'running', ?) {db.returning_id_clause()}""", (location_id, now))
        return db.require_lastrowid(cursor)


def add_pass_counts(pass_id: int, *, seen: int, new: int, changed: int) -> None:
    if not (seen or new or changed):
        return
    with db.connect() as connection:
        connection.execute("""UPDATE storage_passes SET objects_seen = objects_seen + ?,
            objects_new = objects_new + ?, objects_changed = objects_changed + ? WHERE id = ?""",
            (seen, new, changed, pass_id))


def finish_pass(location_id: int, pass_id: int, now: int, *, prove_removals: bool) -> int:
    """Close a pass. Objects it never saw are removed only when every directory
    was read: an unreadable subtree is not evidence that its files are gone."""
    with db.connect() as connection:
        removed = 0
        if prove_removals:
            cursor = connection.execute("""UPDATE storage_objects SET state = 'removed', last_changed_at = ?
                WHERE location_id = ? AND last_seen_pass < ? AND state != 'removed'""",
                (now, location_id, pass_id))
            removed = max(0, int(cursor.rowcount))
        connection.execute("""UPDATE storage_passes SET status = ?, finished_at = ?, objects_removed = ?
            WHERE id = ? AND status = 'running'""",
            ("completed" if prove_removals else "abandoned", now, removed, pass_id))
    return removed


def observe(location_id: int, pass_id: int, observations: list[tuple[str, int, int]],
            now: int) -> tuple[int, int]:
    """Record (object_id, size, mtime_ns) seen by the crawl. Returns (new, changed).

    A size or modification-time change sends an object back to waiting for
    stability; an unchanged one only has its last-seen pass advanced.
    """
    new = changed = 0
    if not observations:
        return 0, 0
    with db.connect() as connection:
        for start in range(0, len(observations), _IN_CHUNK):
            chunk = observations[start:start + _IN_CHUNK]
            marks = ", ".join("?" for _ in chunk)
            existing = {str(row["object_id"]): row for row in connection.execute(
                f"""SELECT id, object_id, size_bytes, mtime_ns, state FROM storage_objects
                WHERE location_id = ? AND object_id IN ({marks})""",
                (location_id, *[item[0] for item in chunk])).fetchall()}
            unchanged: list[int] = []
            for object_id, size, mtime_ns in chunk:
                row = existing.get(object_id)
                if row is None:
                    connection.execute("""INSERT INTO storage_objects
                        (location_id, object_id, size_bytes, mtime_ns, state, stable_since,
                         last_seen_pass, first_seen_at, last_changed_at)
                        VALUES (?, ?, ?, ?, 'waiting', ?, ?, ?, ?)
                        ON CONFLICT (location_id, object_id) DO NOTHING""",
                        (location_id, object_id, size, mtime_ns, now, pass_id, now, now))
                    new += 1
                elif (int(row["size_bytes"]) != size or int(row["mtime_ns"]) != mtime_ns
                      or str(row["state"]) == "removed"):
                    state = "waiting" if str(row["state"]) == "waiting" else "changed"
                    connection.execute("""UPDATE storage_objects SET size_bytes = ?, mtime_ns = ?,
                        state = ?, stable_since = ?, last_changed_at = ?, last_seen_pass = ?,
                        sha256 = NULL, last_error = NULL WHERE id = ?""",
                        (size, mtime_ns, state, now, now, pass_id, int(row["id"])))
                    changed += 1
                else:
                    unchanged.append(int(row["id"]))
            for id_start in range(0, len(unchanged), _IN_CHUNK):
                ids = unchanged[id_start:id_start + _IN_CHUNK]
                connection.execute(
                    f"UPDATE storage_objects SET last_seen_pass = ? WHERE id IN ({', '.join('?' for _ in ids)})",
                    (pass_id, *ids))
    return new, changed


@dataclass(frozen=True)
class DueObject:
    id: int
    object_id: str
    size_bytes: int
    mtime_ns: int


def due_objects(location_id: int, stable_before: int, limit: int) -> list[DueObject]:
    with db.connect() as connection:
        rows = connection.execute("""SELECT id, object_id, size_bytes, mtime_ns FROM storage_objects
            WHERE location_id = ? AND state IN ('waiting', 'changed') AND stable_since <= ?
            ORDER BY stable_since, id LIMIT ?""", (location_id, stable_before, limit)).fetchall()
    return [DueObject(int(row["id"]), str(row["object_id"]), int(row["size_bytes"]), int(row["mtime_ns"]))
            for row in rows]


def _fenced(connection: Any, item: DueObject, assignments: str, params: tuple) -> bool:
    cursor = connection.execute(f"""UPDATE storage_objects SET {assignments}
        WHERE id = ? AND size_bytes = ? AND mtime_ns = ? AND state IN ('waiting', 'changed')""",
        (*params, item.id, item.size_bytes, item.mtime_ns))
    return int(cursor.rowcount) > 0


def mark_changed(item: DueObject, size: int, mtime_ns: int, now: int) -> None:
    with db.connect() as connection:
        _fenced(connection, item, "size_bytes = ?, mtime_ns = ?, state = 'changed', stable_since = ?, "
                "last_changed_at = ?, sha256 = NULL", (size, mtime_ns, now, now))


def mark_simple(item: DueObject, state: str, now: int, *, error: str | None = None,
                tier: str | None = None, policy_revision: int | None = None) -> None:
    with db.connect() as connection:
        _fenced(connection, item, "state = ?, processed_at = ?, last_error = ?, tier = ?, policy_revision = ?",
                (state, now, error, tier, policy_revision))


def hash_list_kinds(digests: Iterable[str]) -> dict[str, str]:
    """Batch lookup of MASP-computed digests on the institution hash list."""
    unique = sorted({digest for digest in digests if digest})
    found: dict[str, str] = {}
    with db.connect() as connection:
        for start in range(0, len(unique), _IN_CHUNK):
            chunk = unique[start:start + _IN_CHUNK]
            for row in connection.execute(
                    f"SELECT sha256, list_kind FROM hash_list_entries WHERE sha256 IN ({', '.join('?' for _ in chunk)})",
                    tuple(chunk)).fetchall():
                found[str(row["sha256"])] = str(row["list_kind"])
    return found


def record_light_result(location: StorageLocation, item: DueObject, *, state: str, now: int,
                        sha256: str | None, detected_type: str | None, families: list[str],
                        hash_list_kind: str | None, findings: list[LightFinding],
                        client_snapshot: dict) -> int:
    """Store one light-tier outcome, its findings and their notifications in
    one transaction. Returns the number of new findings (0 when fenced out)."""
    created = 0
    with db.connect() as connection:
        if not db.using_postgres():
            connection.execute("BEGIN IMMEDIATE")
        if not _fenced(connection, item, """state = ?, processed_at = ?, sha256 = ?, tier = 'light',
                policy_revision = ?, detected_type = ?, families = ?, hash_list_kind = ?,
                finding_count = ?, last_error = NULL""",
                (state, now, sha256, location.policy_revision, detected_type, ",".join(families),
                 hash_list_kind, len(findings))):
            return 0
        for finding in findings:
            # One finding per object version and kind: re-inspecting the same
            # bytes (a policy edit, a retry) never raises it twice.
            fingerprint = f"{item.id}:{item.size_bytes}:{item.mtime_ns}:{finding.kind}"
            cursor = connection.execute(f"""INSERT INTO storage_findings
                (location_id, storage_object_id, object_id, sha256, kind, severity, detected, title,
                 detail_json, fingerprint, policy_revision, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (fingerprint) DO NOTHING {db.returning_id_clause()}""",
                (location.id, item.id, item.object_id, sha256, finding.kind, finding.severity,
                 db.db_bool(finding.detected), finding.title[:500],
                 json.dumps(finding.detail, sort_keys=True), fingerprint, location.policy_revision, now))
            if db.using_postgres():
                row = cursor.fetchone()
                finding_id = None if row is None else int(row["id"])
            else:
                finding_id = int(cursor.lastrowid) if cursor.rowcount else None
            if finding_id is None:
                continue
            created += 1
            if finding.detected and finding.severity in NOTIFY_SEVERITIES:
                _enqueue_notification(connection, location, item, finding_id, finding, sha256,
                                      client_snapshot, now)
    return created


def _enqueue_notification(connection: Any, location: StorageLocation, item: DueObject, finding_id: int,
                          finding: LightFinding, sha256: str | None, client_snapshot: dict, now: int) -> None:
    key = f"storage-finding:{finding_id}:storage.finding"
    payload = {
        "schema_version": 1,
        "event_type": "storage.finding",
        "idempotency_key": key,
        "finding_id": finding_id,
        "location": {"id": location.id, "name": location.name},
        "client": client_snapshot,
        "object_id": item.object_id,
        "size_bytes": item.size_bytes,
        "sha256": sha256,
        "kind": finding.kind,
        "severity": finding.severity,
        "title": finding.title,
        "inspection": "light",
        "detail": finding.detail,
    }
    connection.execute("""INSERT INTO storage_notification_outbox
        (storage_finding_id, service_client_id, event_type, idempotency_key, payload_json,
         created_at, updated_at)
        VALUES (?, ?, 'storage.finding', ?, ?, ?, ?) ON CONFLICT (idempotency_key) DO NOTHING""",
        (finding_id, location.service_client_id, key,
         json.dumps(payload, separators=(",", ":"), sort_keys=True), now, now))


# --- Notification delivery (mirrors the scan outbox, see notification_delivery) ---

@dataclass(frozen=True)
class StorageNotification:
    id: int
    idempotency_key: str
    payload_json: str
    attempt_count: int


def claim_next_storage_notification(worker_id: str, *, lease_seconds: int,
                                    now: int | None = None) -> StorageNotification | None:
    current = int(time.time()) if now is None else now
    with db.connect() as connection:
        if not db.using_postgres():
            connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(f"""SELECT id FROM storage_notification_outbox
            WHERE status = 'pending' AND available_at <= ? ORDER BY id LIMIT 1
            {"FOR UPDATE SKIP LOCKED" if db.using_postgres() else ""}""", (current,)).fetchone()
        if row is None:
            return None
        event_id = int(row["id"])
        connection.execute("""UPDATE storage_notification_outbox SET status = 'delivering', worker_id = ?,
            lease_expires_at = ?, attempt_count = attempt_count + 1, updated_at = ?
            WHERE id = ? AND status = 'pending'""",
            (worker_id, current + max(30, lease_seconds), current, event_id))
        claimed = connection.execute("""SELECT id, idempotency_key, payload_json, attempt_count
            FROM storage_notification_outbox WHERE id = ?""", (event_id,)).fetchone()
    return None if claimed is None else StorageNotification(
        int(claimed["id"]), str(claimed["idempotency_key"]), str(claimed["payload_json"]),
        int(claimed["attempt_count"]))


def mark_storage_notification_delivered(event_id: int, worker_id: str, generation: int) -> bool:
    now = int(time.time())
    with db.connect() as connection:
        cursor = connection.execute("""UPDATE storage_notification_outbox SET status = 'delivered',
            worker_id = NULL, lease_expires_at = NULL, delivered_at = ?, last_error = NULL, updated_at = ?
            WHERE id = ? AND status = 'delivering' AND worker_id = ? AND attempt_count = ?""",
            (now, now, event_id, worker_id, generation))
        return int(cursor.rowcount) > 0


def retry_storage_notification(event_id: int, worker_id: str, generation: int, error: str,
                               *, retry_at: int) -> bool:
    with db.connect() as connection:
        cursor = connection.execute("""UPDATE storage_notification_outbox SET status = 'pending',
            worker_id = NULL, lease_expires_at = NULL, available_at = ?, last_error = ?, updated_at = ?
            WHERE id = ? AND status = 'delivering' AND worker_id = ? AND attempt_count = ?""",
            (retry_at, error[:2000], int(time.time()), event_id, worker_id, generation))
        return int(cursor.rowcount) > 0


def recover_expired_storage_notifications(*, now: int | None = None) -> int:
    current = int(time.time()) if now is None else now
    with db.connect() as connection:
        cursor = connection.execute("""UPDATE storage_notification_outbox SET status = 'pending',
            worker_id = NULL, lease_expires_at = NULL, available_at = ?,
            last_error = 'Recovered after notification lease expired.', updated_at = ?
            WHERE status = 'delivering' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?""",
            (current, current, current))
        return max(0, int(cursor.rowcount))
