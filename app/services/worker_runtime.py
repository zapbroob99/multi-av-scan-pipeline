from __future__ import annotations

import json
import os
import socket
import time
from datetime import datetime

from app.database import get_setting, set_setting


WORKER_HEARTBEAT_KEY = "worker.scan_worker.heartbeat"


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


def record_worker_heartbeat(state: str, active_scan_id: int | None = None) -> None:
    payload = {
        "state": state,
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "timestamp": int(time.time()),
        "active_scan_id": active_scan_id,
        "poll_seconds": worker_poll_seconds(),
    }
    set_setting(WORKER_HEARTBEAT_KEY, json.dumps(payload, sort_keys=True))


def get_worker_status(now: int | None = None) -> dict[str, object]:
    raw = get_setting(WORKER_HEARTBEAT_KEY, "")
    current_time = int(time.time()) if now is None else now
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
        "age_seconds": age_seconds,
        "last_seen_at": last_seen_at,
        "stale_after_seconds": worker_stale_seconds(),
    }
