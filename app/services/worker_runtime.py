from __future__ import annotations

import json
import os
import socket
import time
from datetime import datetime

from app.database import DatabaseOperationalError, get_setting, set_setting
from app.services.worker_capabilities import worker_engine_keys


WORKER_HEARTBEAT_KEY = "worker.scan_worker.heartbeat"
WORKER_HEARTBEATS_KEY = "worker.scan_worker.heartbeats"


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


def record_worker_heartbeat(state: str, active_scan_id: int | None = None) -> None:
    hostname = socket.gethostname()
    pid = os.getpid()
    payload = {
        "state": state,
        "hostname": hostname,
        "pid": pid,
        "timestamp": int(time.time()),
        "active_scan_id": active_scan_id,
        "poll_seconds": worker_poll_seconds(),
        "engine_keys": sorted(worker_engine_keys()),
    }
    try:
        set_setting(WORKER_HEARTBEAT_KEY, json.dumps(payload, sort_keys=True))
        set_setting(
            WORKER_HEARTBEATS_KEY,
            json.dumps(update_worker_heartbeats(payload), sort_keys=True),
        )
    except DatabaseOperationalError as exc:
        print(f"Worker heartbeat could not be recorded: {exc}", flush=True)


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

    return get_legacy_worker_status(current_time)


def get_legacy_worker_status(current_time: int) -> dict[str, object]:
    try:
        raw = get_setting(WORKER_HEARTBEAT_KEY, "")
    except DatabaseOperationalError:
        raw = ""
    payload: dict[str, object] = {}

    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            payload = parsed

    timestamp = int(payload.get("timestamp", 0) or 0)
    age_seconds = max(0, current_time - timestamp) if timestamp else None
    stale = timestamp == 0 or (age_seconds is not None and age_seconds > worker_stale_seconds())
    online = not stale

    last_seen_at = None
    if timestamp:
        last_seen_at = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    state = str(payload.get("state", "offline"))
    if not online:
        state = "offline"

    return {
        "online": online,
        "state": state,
        "hostname": str(payload.get("hostname", "-")),
        "pid": int(payload.get("pid", 0) or 0),
        "active_scan_id": payload.get("active_scan_id"),
        "engine_keys": normalize_engine_keys(payload.get("engine_keys")),
        "age_seconds": age_seconds,
        "last_seen_at": last_seen_at,
        "stale_after_seconds": worker_stale_seconds(),
        "workers": [],
        "online_count": 1 if online else 0,
        "total_worker_records": 1 if payload else 0,
    }


def update_worker_heartbeats(payload: dict[str, object]) -> dict[str, object]:
    try:
        raw = get_setting(WORKER_HEARTBEATS_KEY, "{}")
    except DatabaseOperationalError:
        raw = "{}"
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        parsed = {}
    heartbeats = parsed if isinstance(parsed, dict) else {}
    heartbeats = prune_worker_heartbeats(
        heartbeats,
        int(payload.get("timestamp", 0) or 0),
    )
    worker_id = worker_identity(payload)
    heartbeats[worker_id] = payload
    return heartbeats


def get_worker_heartbeats(current_time: int) -> list[dict[str, object]]:
    try:
        raw = get_setting(WORKER_HEARTBEATS_KEY, "{}")
    except DatabaseOperationalError:
        raw = "{}"
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        parsed = {}
    if not isinstance(parsed, dict):
        return []
    parsed = prune_worker_heartbeats(parsed, current_time)

    workers = []
    for worker_id, value in parsed.items():
        if not isinstance(value, dict):
            continue
        worker = dict(value)
        timestamp = int(worker.get("timestamp", 0) or 0)
        age_seconds = max(0, current_time - timestamp) if timestamp else None
        stale = timestamp == 0 or (
            age_seconds is not None and age_seconds > worker_stale_seconds()
        )
        worker["worker_id"] = str(worker_id)
        worker["online"] = not stale
        worker["age_seconds"] = age_seconds
        worker["engine_keys"] = normalize_engine_keys(worker.get("engine_keys"))
        worker["last_seen_at"] = (
            datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            if timestamp
            else None
        )
        if not bool(worker["online"]):
            worker["state"] = "offline"
        workers.append(worker)
    return sorted(
        workers,
        key=lambda worker: int(worker.get("timestamp", 0) or 0),
        reverse=True,
    )


def prune_worker_heartbeats(
    heartbeats: dict[str, object],
    current_time: int,
) -> dict[str, object]:
    retention_seconds = worker_retention_seconds()
    pruned: dict[str, object] = {}
    for worker_id, value in heartbeats.items():
        if not isinstance(value, dict):
            continue
        timestamp = int(value.get("timestamp", 0) or 0)
        if timestamp <= 0:
            continue
        age_seconds = max(0, current_time - timestamp)
        if age_seconds > retention_seconds:
            continue
        pruned[str(worker_id)] = value
    return pruned


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
