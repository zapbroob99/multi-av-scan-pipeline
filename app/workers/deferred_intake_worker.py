from __future__ import annotations

import contextlib
import os
from pathlib import Path
import socket
import threading
import time

from app.database import (
    claim_next_deferred_scan_submission,
    complete_deferred_scan_intake,
    fail_deferred_scan_intake,
    get_service_client,
    init_db,
    recover_expired_deferred_scan_intakes,
    renew_deferred_scan_lease,
)
from app.services.archive_extractor import detect_archive_format
from app.services.deferred_storage import (
    DeferredSourceChangedError,
    DeferredSourcePermanentError,
    backend_allowed_for_client,
    configured_backend_keys,
    copy_deferred_source,
)
from app.services.service_clients import engines_for_snapshot_json


POLL_SECONDS = float(os.getenv("MASP_DEFERRED_INTAKE_POLL_SECONDS", "5"))
LEASE_SECONDS = int(os.getenv("MASP_DEFERRED_INTAKE_LEASE_SECONDS", "3600"))
MAX_BACKOFF_SECONDS = int(os.getenv("MASP_DEFERRED_INTAKE_MAX_BACKOFF_SECONDS", "3600"))
WORKER_ID = os.getenv(
    "MASP_DEFERRED_INTAKE_WORKER_ID",
    f"deferred-intake-{socket.gethostname()}-{os.getpid()}",
)


@contextlib.contextmanager
def lease_renewal(submission_id: int, generation: int):
    stop = threading.Event()

    def renew() -> None:
        while not stop.wait(max(10.0, LEASE_SECONDS / 3.0)):
            if not renew_deferred_scan_lease(
                submission_id, WORKER_ID, generation, LEASE_SECONDS
            ):
                return

    thread = threading.Thread(target=renew, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1)


def process_next() -> bool:
    request = claim_next_deferred_scan_submission(
        configured_backend_keys(), WORKER_ID, lease_seconds=LEASE_SECONDS
    )
    if request is None:
        return False
    stored = None
    try:
        with lease_renewal(request.id, request.attempt_count):
            client = get_service_client(request.service_client_id)
            if client is None or not backend_allowed_for_client(
                request.backend_key, client.client_key, request.object_id
            ):
                raise DeferredSourceChangedError(
                    "Deferred storage backend is no longer authorized for this client."
                )
            try:
                engines = engines_for_snapshot_json(
                    request.profile_snapshot_json, source="api", strict=True
                )
            except ValueError as exc:
                raise DeferredSourceChangedError(str(exc)) from exc
            if not engines:
                raise DeferredSourceChangedError(
                    "Deferred routing snapshot has no available engine instances."
                )
            stored = copy_deferred_source(request)
            archive_format = detect_archive_format(stored.storage_path)
            scan_id = complete_deferred_scan_intake(
                submission_id=request.id,
                worker_id=WORKER_ID,
                generation=request.attempt_count,
                sample=stored,
                engines=engines,
                archive_format=archive_format,
            )
            if scan_id is None:
                Path(stored.storage_path).unlink(missing_ok=True)
                return True
        print(f"Deferred submission {request.id} queued as scan {scan_id}", flush=True)
        return True
    except Exception as exc:
        if stored is not None:
            Path(stored.storage_path).unlink(missing_ok=True)
        permanent = isinstance(exc, DeferredSourcePermanentError)
        backoff = min(MAX_BACKOFF_SECONDS, 30 * (2 ** min(request.attempt_count - 1, 7)))
        fail_deferred_scan_intake(
            request.id,
            WORKER_ID,
            request.attempt_count,
            str(exc),
            permanent=permanent,
            retry_at=int(time.time()) + backoff,
        )
        print(
            f"Deferred submission {request.id} {'failed' if permanent else 'deferred'}: {exc}",
            flush=True,
        )
        return True


def run_forever() -> None:
    init_db()
    if not configured_backend_keys():
        raise SystemExit("No deferred storage backend is configured.")
    recover_expired_deferred_scan_intakes()
    print(
        f"MASP deferred intake worker started (backends: {', '.join(sorted(configured_backend_keys()))})",
        flush=True,
    )
    last_recovery = time.monotonic()
    while True:
        if not process_next():
            time.sleep(POLL_SECONDS)
        if time.monotonic() - last_recovery >= 60:
            recover_expired_deferred_scan_intakes()
            last_recovery = time.monotonic()


if __name__ == "__main__":
    run_forever()
