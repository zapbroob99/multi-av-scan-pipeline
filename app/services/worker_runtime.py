from __future__ import annotations

import json
import os
import socket
import threading
import time
from datetime import datetime
from typing import Iterator

from app.database import (
    DatabaseOperationalError,
    delete_settings_if_values_match,
    list_settings_by_prefix,
    set_setting,
)
from app.services.worker_capabilities import worker_engine_keys


# Legacy single-worker key (one process only) and legacy bulk key (all workers
# packed into one JSON row). Both are still READ for backward compatibility but
# are never written by the current code — the shared bulk row was the source of
# the read-modify-write lost-update race. Each worker now owns its own row under
# ``WORKER_HEARTBEAT_ROW_PREFIX`` and writes it with a single atomic UPSERT.
WORKER_HEARTBEAT_KEY = "worker.scan_worker.heartbeat"
WORKER_HEARTBEATS_KEY = "worker.scan_worker.heartbeats"
WORKER_HEARTBEAT_ROW_PREFIX = "worker.scan_worker.heartbeats."
# Prefix that matches all three shapes at once (single, bulk, and per-worker
# rows all start with it), so one prefix query loads every heartbeat record.
WORKER_HEARTBEAT_QUERY_PREFIX = "worker.scan_worker.heartbeat"


_HEARTBEAT_CLEANUP_LOCK = threading.Lock()
_last_heartbeat_cleanup_at = 0.0


def worker_poll_seconds() -> float:
    try:
        return max(0.5, float(os.getenv("MASP_WORKER_POLL_SECONDS", "2")))
    except ValueError:
        return 2.0


def worker_stale_seconds() -> int:
    configured = os.getenv("MASP_WORKER_STALE_SECONDS", "").strip()
    if configured:
        try:
            return max(5, int(configured))
        except ValueError:
            pass
    return max(15, int(worker_poll_seconds() * 6))


def worker_retention_seconds() -> int:
    configured = os.getenv("MASP_WORKER_RETENTION_SECONDS", "").strip()
    if configured:
        try:
            return max(worker_stale_seconds(), int(configured))
        except ValueError:
            pass
    return max(300, worker_stale_seconds() * 10)


def record_worker_heartbeat(state: str, active_scan_id: int | None = None) -> bool:
    hostname = socket.gethostname()
    pid = os.getpid()
    timestamp = int(time.time())
    payload = {
        "state": state,
        "hostname": hostname,
        "pid": pid,
        "timestamp": timestamp,
        "active_scan_id": active_scan_id,
        "poll_seconds": worker_poll_seconds(),
        "engine_keys": sorted(worker_engine_keys()),
    }
    row_key = f"{WORKER_HEARTBEAT_ROW_PREFIX}{worker_identity(payload)}"
    try:
        # One independent atomic UPSERT of this worker's own row. No shared
        # read-modify-write, so concurrent workers can never clobber each other.
        set_setting(row_key, json.dumps(payload, sort_keys=True))
    except DatabaseOperationalError as exc:
        print(f"Worker heartbeat could not be recorded: {exc}", flush=True)
        return False
    # Cleanup is best-effort and throttled; a failure here must never break the
    # heartbeat write above.
    _maybe_cleanup_stale_heartbeats(timestamp)
    return True


def get_worker_status(now: int | None = None) -> dict[str, object]:
    current_time = int(time.time()) if now is None else now
    workers = get_worker_heartbeats(current_time)
    online_workers = [worker for worker in workers if bool(worker["online"])]
    if workers:
        active_scan_id = next(
            (
                worker["active_scan_id"]
                for worker in online_workers
                if worker.get("active_scan_id")
            ),
            None,
        )
        state = summarize_worker_state(online_workers)
        engine_keys = sorted(
            {
                engine_key
                for worker in online_workers
                for engine_key in normalize_engine_keys(worker.get("engine_keys"))
            }
        )
        hostnames = sorted({str(worker.get("hostname") or "-") for worker in online_workers})
        return {
            "online": bool(online_workers),
            "state": state,
            "hostname": ", ".join(hostnames) if hostnames else "-",
            "pid": int(online_workers[0].get("pid", 0) or 0) if online_workers else 0,
            "active_scan_id": active_scan_id,
            "engine_keys": engine_keys,
            "age_seconds": min(
                int(worker["age_seconds"])
                for worker in online_workers
                if worker.get("age_seconds") is not None
            )
            if online_workers
            else None,
            "last_seen_at": max(
                str(worker["last_seen_at"])
                for worker in online_workers
                if worker.get("last_seen_at")
            )
            if online_workers
            else None,
            "stale_after_seconds": worker_stale_seconds(),
            "workers": workers,
            "online_count": len(online_workers),
            "total_worker_records": len(workers),
        }

    return offline_worker_status()


def offline_worker_status() -> dict[str, object]:
    """Status payload when no heartbeat record of any shape is present."""
    return {
        "online": False,
        "state": "offline",
        "hostname": "-",
        "pid": 0,
        "active_scan_id": None,
        "engine_keys": [],
        "age_seconds": None,
        "last_seen_at": None,
        "stale_after_seconds": worker_stale_seconds(),
        "workers": [],
        "online_count": 0,
        "total_worker_records": 0,
    }


def get_worker_heartbeats(current_time: int) -> list[dict[str, object]]:
    """Merge per-worker rows with the legacy single/bulk rows.

    During a rolling upgrade the store can hold new per-worker rows AND the old
    shared rows at the same time. Records are merged by worker identity; the
    highest timestamp wins, and a per-worker row wins a timestamp tie (it is the
    authoritative post-upgrade source). Records older than the retention window
    are dropped from the view.
    """
    try:
        settings = list_settings_by_prefix(WORKER_HEARTBEAT_QUERY_PREFIX)
    except DatabaseOperationalError:
        settings = {}

    retention_seconds = worker_retention_seconds()
    best: dict[str, tuple[int, bool, dict[str, object]]] = {}
    for payload, from_per_worker in _iter_heartbeat_payloads(settings):
        timestamp = int(payload.get("timestamp", 0) or 0)
        if timestamp <= 0:
            continue
        if current_time - timestamp > retention_seconds:
            continue
        identity = worker_identity(payload)
        current = best.get(identity)
        if current is None:
            best[identity] = (timestamp, from_per_worker, payload)
            continue
        current_ts, current_from_per_worker, _ = current
        if timestamp > current_ts or (
            timestamp == current_ts and from_per_worker and not current_from_per_worker
        ):
            best[identity] = (timestamp, from_per_worker, payload)

    workers = []
    for identity, (timestamp, _from_per_worker, payload) in best.items():
        worker = dict(payload)
        age_seconds = max(0, current_time - timestamp)
        stale = age_seconds > worker_stale_seconds()
        worker["worker_id"] = identity
        worker["online"] = not stale
        worker["age_seconds"] = age_seconds
        worker["engine_keys"] = normalize_engine_keys(worker.get("engine_keys"))
        worker["last_seen_at"] = datetime.fromtimestamp(timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        if not bool(worker["online"]):
            worker["state"] = "offline"
        workers.append(worker)
    return sorted(
        workers,
        key=lambda worker: int(worker.get("timestamp", 0) or 0),
        reverse=True,
    )


def _iter_heartbeat_payloads(
    settings: dict[str, str],
) -> Iterator[tuple[dict[str, object], bool]]:
    """Yield ``(payload, from_per_worker)`` for every heartbeat record shape."""
    for key, raw in settings.items():
        try:
            parsed = json.loads(raw or "")
        except (json.JSONDecodeError, TypeError):
            continue
        if key.startswith(WORKER_HEARTBEAT_ROW_PREFIX):
            if isinstance(parsed, dict):
                yield parsed, True
        elif key == WORKER_HEARTBEATS_KEY:
            if isinstance(parsed, dict):
                for value in parsed.values():
                    if isinstance(value, dict):
                        yield value, False
        elif key == WORKER_HEARTBEAT_KEY:
            if isinstance(parsed, dict):
                yield parsed, False


def _maybe_cleanup_stale_heartbeats(now: int) -> None:
    global _last_heartbeat_cleanup_at
    interval = max(worker_stale_seconds(), 1)
    with _HEARTBEAT_CLEANUP_LOCK:
        if now - _last_heartbeat_cleanup_at < interval:
            return
        _last_heartbeat_cleanup_at = now
    try:
        cleanup_stale_worker_heartbeats(now)
    except Exception as exc:  # cleanup must never break the heartbeat write
        print(f"Worker heartbeat cleanup failed: {exc}", flush=True)


def cleanup_stale_worker_heartbeats(now: int | None = None) -> int:
    """Bulk-delete heartbeat rows past the retention window.

    Covers per-worker rows AND the two legacy exact keys. A legacy key kept
    fresh by an active old worker (its embedded timestamp is recent) survives;
    it is removed only once nothing refreshes it. Returns the count deleted.
    """
    current_time = int(time.time()) if now is None else now
    retention_seconds = worker_retention_seconds()
    settings = list_settings_by_prefix(WORKER_HEARTBEAT_QUERY_PREFIX)
    stale_settings: dict[str, str] = {}
    for key, raw in settings.items():
        if not _is_heartbeat_setting_key(key):
            continue
        newest = _key_newest_timestamp(key, raw)
        if newest <= 0 or current_time - newest > retention_seconds:
            stale_settings[key] = raw
    if not stale_settings:
        return 0
    return delete_settings_if_values_match(stale_settings)


def _is_heartbeat_setting_key(key: str) -> bool:
    return key in {WORKER_HEARTBEAT_KEY, WORKER_HEARTBEATS_KEY} or key.startswith(
        WORKER_HEARTBEAT_ROW_PREFIX
    )


def _key_newest_timestamp(key: str, raw: str) -> int:
    """Newest embedded timestamp for a heartbeat row (0 if unreadable)."""
    try:
        parsed = json.loads(raw or "")
    except (json.JSONDecodeError, TypeError):
        return 0
    if key == WORKER_HEARTBEATS_KEY and isinstance(parsed, dict):
        timestamps = [
            int(value.get("timestamp", 0) or 0)
            for value in parsed.values()
            if isinstance(value, dict)
        ]
        return max(timestamps) if timestamps else 0
    if isinstance(parsed, dict):
        return int(parsed.get("timestamp", 0) or 0)
    return 0


def worker_is_running_scan_engine(
    scan_id: int,
    engine_key: str,
    *,
    now: int | None = None,
) -> bool:
    current_time = int(time.time()) if now is None else now
    for worker in get_worker_heartbeats(current_time):
        if not bool(worker.get("online")):
            continue
        if str(worker.get("state") or "") != "running":
            continue
        if int(worker.get("active_scan_id", 0) or 0) != scan_id:
            continue
        if engine_key in normalize_engine_keys(worker.get("engine_keys")):
            return True
    return False


def worker_identity(payload: dict[str, object]) -> str:
    return f'{payload.get("hostname", "-")}:{payload.get("pid", 0)}'


def summarize_worker_state(online_workers: list[dict[str, object]]) -> str:
    if not online_workers:
        return "offline"
    states = {str(worker.get("state") or "idle") for worker in online_workers}
    if "error" in states:
        return "error"
    if "running" in states:
        return "running"
    if "starting" in states:
        return "starting"
    return "idle"


def normalize_engine_keys(value: object) -> list[str]:
    if isinstance(value, list):
        return sorted(str(item) for item in value if str(item).strip())
    if isinstance(value, str):
        return sorted(item.strip() for item in value.split(",") if item.strip())
    return []
