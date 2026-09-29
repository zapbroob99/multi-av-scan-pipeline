"""One protection cycle for one location: crawl a bounded slice, then inspect
the objects that have stopped changing.

Nothing here writes to the source. Crawling reads directory metadata only;
inspection opens objects through ``open_deferred_source`` (link, traversal and
hardlink checks included) and reads a bounded header, plus one streaming pass
when the location hashes. Phase 1 runs the light tier only: an object routed to
the full tier is recorded as ``full_pending`` and nothing claims it is clean.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import time

from app import database as db
from app.services.content_types import classify
from app.services.deferred_storage import (
    DeferredSourceError,
    DeferredSourcePolicyError,
    backend_allowed_for_client,
    client_backend_scope,
    configured_backends,
    open_deferred_source,
    redact_paths,
)
from app.services import storage_inventory as inventory
from app.services.storage_inventory import DueObject, StorageLocation
from app.services.storage_policy import choose_tier, evaluate_light, ignored

HEADER_BYTES = 4096
READ_CHUNK = 1024 * 1024
OBSERVATION_FLUSH = 1000
# The worker records its latest cycle here; the API process does not share the
# worker's environment, so the console reads only this row.
LAST_CYCLE_SETTING = "storage_protection_last_cycle"


def crawl_seconds() -> float:
    try:
        return max(1.0, min(float(os.getenv("MASP_STORAGE_CRAWL_SECONDS", "20")), 600.0))
    except ValueError:
        return 20.0


def lease_seconds() -> int:
    try:
        return max(60, min(int(os.getenv("MASP_STORAGE_LEASE_SECONDS", "300")), 3600))
    except ValueError:
        return 300


class LocationUnavailable(RuntimeError):
    """The location may not run now; the reason is shown to operators."""


@dataclass
class CycleResult:
    crawled: int = 0
    new: int = 0
    changed: int = 0
    removed: int = 0
    inspected: int = 0
    findings: int = 0
    directory_errors: int = 0
    pass_id: int | None = None
    pass_completed: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def did_work(self) -> bool:
        return bool(self.crawled or self.inspected)

    def payload(self, *, ok: bool, now: int, error: str | None = None) -> dict:
        return {"at": now, "ok": ok, "error": redact_paths(error)[:1000] if error else None,
                "pass_id": self.pass_id, "pass_completed": self.pass_completed,
                "crawled": self.crawled, "new": self.new, "changed": self.changed,
                "removed": self.removed, "inspected": self.inspected, "findings": self.findings,
                "directory_errors": self.directory_errors,
                "errors": [redact_paths(item)[:300] for item in self.errors[:5]]}


def _authorize(location: StorageLocation) -> tuple[str, dict]:
    """Fail closed on anything that would make the location's access stale."""
    if location.policy_error:
        raise LocationUnavailable(location.policy_error)
    client = db.get_service_client(location.service_client_id)
    if client is None or not client.enabled:
        raise LocationUnavailable("The location's service client is missing or disabled.")
    with db.connect() as connection:
        profile = connection.execute("""SELECT service_client_id, enabled, deleted_at FROM scan_profiles
            WHERE id = ?""", (location.scan_profile_id,)).fetchone()
    if (profile is None or int(profile["service_client_id"]) != client.id
            or not bool(profile["enabled"]) or profile["deleted_at"] is not None):
        raise LocationUnavailable("The location's scan profile is missing, disabled or not owned by its client.")
    if location.mode != "crawl":
        raise LocationUnavailable("Manifest discovery for protected locations is not available in this release.")
    scope = client_backend_scope(location.backend_key, client.client_key)
    if scope is None or not scope.covers_prefix(location.prefix):
        raise LocationUnavailable("The client's storage grant does not cover this location.")
    return client.client_key, {"id": client.id, "key": client.client_key, "name": client.display_name}


def _inside(root: Path, path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    return resolved == root or root in resolved.parents


def _crawl(location: StorageLocation, worker_id: str, now: int, result: CycleResult) -> None:
    runtime = inventory.get_runtime(location.id)
    policy = location.policy
    stack, errors, pass_id = runtime.stack, runtime.errors, runtime.pass_id
    if pass_id is None or (not stack and now >= runtime.next_pass_at):
        pass_id = inventory.start_pass(location.id, now)
        stack, errors = [location.prefix], 0
    result.pass_id = pass_id
    if not stack:
        return
    root = configured_backends()[location.backend_key].resolve(strict=True)
    deadline = time.monotonic() + crawl_seconds()
    pending: list[tuple[str, int, int]] = []
    seen = 0

    def flush() -> None:
        nonlocal pending
        new, changed = inventory.observe(location.id, pass_id, pending, now)
        inventory.add_pass_counts(pass_id, seen=len(pending), new=new, changed=changed)
        result.new += new
        result.changed += changed
        pending = []
        inventory.claim_location(location.id, worker_id, lease_seconds(), int(time.time()))

    while stack and seen < policy.crawl_entries_per_cycle and time.monotonic() < deadline:
        relative = stack.pop()
        directory = root.joinpath(*relative.split("/")) if relative else root
        try:
            if not _inside(root, directory):
                raise DeferredSourcePolicyError("Directory resolves outside the backend root.")
            with os.scandir(directory) as entries:
                children: list[str] = []
                for entry in entries:
                    seen += 1
                    if entry.is_symlink():
                        continue
                    info = entry.stat(follow_symlinks=False)
                    if getattr(info, "st_file_attributes", 0) & 0x400:
                        continue  # Windows junction or other reparse point.
                    child = f"{relative}/{entry.name}" if relative else entry.name
                    if entry.is_dir(follow_symlinks=False):
                        children.append(child)
                    elif entry.is_file(follow_symlinks=False) and not ignored(policy, entry.name):
                        pending.append((child, int(info.st_size), int(info.st_mtime_ns)))
                        if len(pending) >= OBSERVATION_FLUSH:
                            flush()
                # Depth-first, stable order: the cursor stays small on wide trees.
                stack.extend(sorted(children, reverse=True))
        except (OSError, DeferredSourceError) as exc:
            errors += 1
            result.directory_errors += 1
            result.errors.append(f"{relative or '/'}: {type(exc).__name__}: {exc}")
    if pending:
        flush()
    result.crawled = seen
    if stack:
        inventory.save_cursor(location.id, worker_id, pass_id, stack, errors, runtime.next_pass_at, now)
        return
    result.removed = inventory.finish_pass(location.id, pass_id, now, prove_removals=errors == 0)
    result.pass_completed = errors == 0
    inventory.save_cursor(location.id, worker_id, pass_id, [], 0, now + policy.crawl_interval_seconds, now)


@dataclass(frozen=True)
class _Read:
    item: DueObject
    sha256: str | None
    header: bytes


def _read(location: StorageLocation, item: DueObject, now: int) -> _Read | None:
    """Read header (and hash) of one object, or record why it could not be."""
    policy = location.policy
    try:
        with open_deferred_source(location.backend_key, item.object_id) as handle:
            before = os.fstat(handle.fileno())
            if before.st_size != item.size_bytes or before.st_mtime_ns != item.mtime_ns:
                inventory.mark_changed(item, int(before.st_size), int(before.st_mtime_ns), now)
                return None
            header = handle.read(HEADER_BYTES)
            digest = None
            if policy.hash_check.enabled and before.st_size <= policy.hash_check.max_bytes:
                hasher = hashlib.sha256(header)
                total = len(header)
                while chunk := handle.read(READ_CHUNK):
                    hasher.update(chunk)
                    total += len(chunk)
                if total != before.st_size:
                    inventory.mark_changed(item, int(total), int(before.st_mtime_ns), now)
                    return None
                digest = hasher.hexdigest()
            after = os.fstat(handle.fileno())
    except (OSError, DeferredSourceError) as exc:
        inventory.mark_simple(item, "unreadable", now, error=redact_paths(f"{type(exc).__name__}: {exc}")[:500])
        return None
    if (after.st_size != before.st_size or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns):
        inventory.mark_changed(item, int(after.st_size), int(after.st_mtime_ns), now)
        return None
    return _Read(item, digest, header)


def _relative(location: StorageLocation, object_id: str) -> str:
    if location.prefix and object_id.startswith(location.prefix + "/"):
        return object_id[len(location.prefix) + 1:]
    return object_id


def _inspect(location: StorageLocation, client_key: str, client_snapshot: dict, now: int,
             result: CycleResult) -> None:
    policy = location.policy
    due = inventory.due_objects(location.id, now - policy.stability_seconds, policy.inspections_per_cycle)
    reads: list[_Read] = []
    for item in due:
        result.inspected += 1
        # Re-checked per object: a grant narrowed mid-pass must stop reads at once.
        if not backend_allowed_for_client(location.backend_key, client_key, item.object_id):
            inventory.mark_simple(item, "unreadable", now, error="Object is outside the client's storage grant.")
            continue
        if choose_tier(policy, _relative(location, item.object_id), item.size_bytes) == "full":
            inventory.mark_simple(item, "full_pending", now, tier="full", policy_revision=location.policy_revision)
            continue
        read = _read(location, item, now)
        if read is not None:
            reads.append(read)
    kinds = inventory.hash_list_kinds(read.sha256 for read in reads if read.sha256)
    for read in reads:
        name = read.item.object_id.rsplit("/", 1)[-1]
        classification = classify(read.header, name)
        hash_kind = kinds.get(read.sha256) if read.sha256 else None
        outcome = evaluate_light(policy, classification, hash_kind)
        if outcome.escalate_to_full:
            inventory.mark_simple(read.item, "full_pending", now, tier="full",
                                  policy_revision=location.policy_revision)
            continue
        result.findings += inventory.record_light_result(
            location, read.item, state="light_detected" if outcome.detected else "light_passed", now=now,
            sha256=read.sha256, detected_type=classification.detected_type,
            families=sorted(classification.families), hash_list_kind=hash_kind,
            findings=list(outcome.findings), client_snapshot=client_snapshot)


def run_location_cycle(location: StorageLocation, worker_id: str, now: int | None = None) -> CycleResult:
    """Crawl and inspect one location under its lease. Never raises for
    location-level problems: they are recorded on the location instead."""
    current = int(time.time()) if now is None else now
    result = CycleResult()
    try:
        client_key, snapshot = _authorize(location)
        _crawl(location, worker_id, current, result)
        _inspect(location, client_key, snapshot, current, result)
    except LocationUnavailable as exc:
        inventory.record_location_cycle(location.id, result.payload(ok=False, now=current, error=str(exc)))
        return result
    except Exception as exc:  # noqa: BLE001 - one broken location must not stop the others
        inventory.record_location_cycle(location.id, result.payload(
            ok=False, now=current, error=f"{type(exc).__name__}: {exc}"))
        raise
    inventory.record_location_cycle(location.id, result.payload(ok=result.directory_errors == 0, now=current))
    return result


def record_worker_cycle(*, ok: bool, poll_seconds: float, locations: int, worker_id: str,
                        backends: list[str], error: str | None = None) -> None:
    """Best effort, like the manifest worker: a dead worker must look dead."""
    payload = {"at": int(time.time()), "ok": ok, "poll_seconds": poll_seconds, "locations": locations,
               "worker_id": worker_id, "backends": backends,
               "error": redact_paths(error)[:1000] if error else None}
    try:
        db.set_setting(LAST_CYCLE_SETTING, json.dumps(payload, sort_keys=True))
    except Exception:  # noqa: BLE001
        pass
