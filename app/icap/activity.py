"""What the ICAP gateway has been doing, visible from the console.

The gateway otherwise leaves no trace outside its container log: a storage
client blocked by the allowlist, a fail-closed answer or a scan error is
invisible to an administrator who only has the console. The gateway keeps
counters and a short list of notable events in memory and writes them as one
``app_settings`` row per listener every ``FLUSH_SECONDS``. The row doubles as a
heartbeat: a record that stops being refreshed means the gateway stopped.

Allowed requests are only counted; listing them would bury the events that need
attention. Nothing here is on the request path's critical section: recording
is an in-memory append, and the flush runs in a thread.
"""
from __future__ import annotations

from collections import deque
import json
import time

from app.icap.config import IcapConfig
from app.services.deferred_storage import redact_paths


SETTING_PREFIX = "icap_gateway_status:"
FLUSH_SECONDS = 30
EVENT_LIMIT = 25
DETAIL_LIMIT = 300

COUNTERS = ("connections_accepted", "connections_rejected", "requests", "allowed", "blocked",
            "fail_actions", "errors", "policy_rejected")


class IcapActivity:
    def __init__(self, config: IcapConfig, *, now: float | None = None) -> None:
        started = int(time.time() if now is None else now)
        self.key = f"{SETTING_PREFIX}{config.service_client_key}:{config.port}"
        self.identity = {
            "service_name": config.service_name,
            "client_key": config.service_client_key,
            "port": config.port,
            "fail_closed": config.fail_closed,
            "block_on_review": config.block_on_review,
            # What the gateway decides on its own settings, so the console can say
            # what happens to a client's files instead of naming an env variable.
            "block_archives": config.block_archives,
            "max_bytes": config.max_bytes or 0,  # 0: no limit; a missing field means unknown
            "wait_seconds": config.wait_seconds,
            "allowlist_entries": len(config.allowed_ips),
            "started_at": started,
        }
        self.counters = dict.fromkeys(COUNTERS, 0)
        self.last_request_at: int | None = None
        self.events: deque[dict[str, object]] = deque(maxlen=EVENT_LIMIT)

    def count(self, counter: str) -> None:
        self.counters[counter] += 1

    def event(self, kind: str, detail: str, *, peer: str | None = None, scan_id: int | None = None,
              now: float | None = None) -> None:
        self.events.appendleft({
            "at": int(time.time() if now is None else now),
            "kind": kind,
            "detail": redact_paths(detail)[:DETAIL_LIMIT],
            "peer": peer,
            "scan_id": scan_id,
        })

    def request(self, now: float | None = None) -> None:
        self.count("requests")
        self.last_request_at = int(time.time() if now is None else now)

    def snapshot(self, now: float | None = None) -> str:
        return json.dumps({
            **self.identity,
            "at": int(time.time() if now is None else now),
            "counters": dict(self.counters),
            "last_request_at": self.last_request_at,
            "events": list(self.events),
        }, sort_keys=True)


# One listener per process. None outside serve(), so handlers stay usable in tests.
ACTIVITY: IcapActivity | None = None


def count(counter: str) -> None:
    if ACTIVITY is not None:
        ACTIVITY.count(counter)


def event(kind: str, detail: str, *, peer: str | None = None, scan_id: int | None = None) -> None:
    if ACTIVITY is not None:
        ACTIVITY.event(kind, detail, peer=peer, scan_id=scan_id)


def request() -> None:
    if ACTIVITY is not None:
        ACTIVITY.request()
