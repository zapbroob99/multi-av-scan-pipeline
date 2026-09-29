"""Crawl protected storage locations and inspect what stops changing.

Runs every enabled location whose backend this process has mounted. A
per-location lease keeps two workers from crawling the same location.
"""
from __future__ import annotations

import os
import socket
import time

from app.database import init_db
from app.services import storage_inventory as inventory
from app.services.deferred_storage import configured_backends
from app.services.storage_protection import lease_seconds, record_worker_cycle, run_location_cycle

POLL_SECONDS = float(os.getenv("MASP_STORAGE_POLL_SECONDS", "10"))
# Even a sweep with work waits this long before the next, so a large share is
# crawled in steady slices rather than back to back against the file server.
SWEEP_PAUSE_SECONDS = float(os.getenv("MASP_STORAGE_SWEEP_PAUSE_SECONDS", "1"))
WORKER_ID = os.getenv("MASP_STORAGE_WORKER_ID", f"storage-{socket.gethostname()}-{os.getpid()}")


def run_once() -> tuple[int, bool]:
    """One sweep over every eligible location. Returns (locations run, any work done)."""
    backends = configured_backends()
    ran, worked = 0, False
    for location in inventory.enabled_locations(backends):
        if not inventory.claim_location(location.id, WORKER_ID, lease_seconds(), int(time.time())):
            continue
        ran += 1
        try:
            worked = run_location_cycle(location, WORKER_ID).did_work or worked
        except Exception as exc:  # noqa: BLE001 - recorded on the location already
            print(f"Storage location {location.id} cycle failed: {type(exc).__name__}: {exc}", flush=True)
    return ran, worked


def run_forever() -> None:
    init_db()
    backends = sorted(configured_backends())
    print(f"MASP storage protection worker started ({WORKER_ID}; backends: {', '.join(backends) or 'none'})",
          flush=True)
    inventory.recover_expired_storage_notifications()
    while True:
        try:
            ran, worked = run_once()
        except Exception as exc:  # noqa: BLE001 - a database outage must not end the worker
            print(f"Storage protection sweep failed: {exc}", flush=True)
            record_worker_cycle(ok=False, poll_seconds=POLL_SECONDS, locations=0, worker_id=WORKER_ID,
                                backends=backends, error=f"{type(exc).__name__}: {exc}")
            time.sleep(POLL_SECONDS)
            continue
        record_worker_cycle(ok=True, poll_seconds=POLL_SECONDS, locations=ran, worker_id=WORKER_ID,
                            backends=backends)
        # A sweep that crawled or inspected something continues after a short
        # pause, so a backlog drains; an idle share costs one sweep per poll.
        time.sleep(SWEEP_PAUSE_SECONDS if worked else POLL_SECONDS)


if __name__ == "__main__":
    run_forever()
