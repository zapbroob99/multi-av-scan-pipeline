"""Poll a read-only storage share for upload manifests and accept them.

This worker only creates deferred submissions. The existing deferred intake
worker still copies, verifies and queues the sample, so every guard that path
already has stays in force.
"""
from __future__ import annotations

import os
import time

from app.database import init_db
from app.services.manifest_intake import (
    ManifestConfigError,
    backend_key,
    candidate_directories,
    client_key,
    process_cycle,
    record_cycle,
)

POLL_SECONDS = float(os.getenv('MASP_MANIFEST_POLL_SECONDS', '15'))
IDLE_REPORT_SECONDS = float(os.getenv('MASP_MANIFEST_IDLE_REPORT_SECONDS', '300'))


def run_forever() -> None:
    init_db()
    try:
        backend, client = backend_key(), client_key()
        directories = candidate_directories()
    except ManifestConfigError as exc:
        record_cycle(ok=False, poll_seconds=POLL_SECONDS, error=str(exc))
        raise SystemExit(str(exc)) from exc
    print(f'MASP manifest intake worker started (backend: {backend or "unset"}, '
          f'client: {client or "unset"}, watching {len(directories)} partition(s))', flush=True)
    last_report = 0.0
    last_rejected = 0
    while True:
        try:
            accepted, duplicates, rejected = process_cycle()
        except ManifestConfigError as exc:
            # Configuration problems are operator errors, not transient ones.
            record_cycle(ok=False, poll_seconds=POLL_SECONDS, error=str(exc))
            raise SystemExit(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - a share outage must not end the worker
            print(f'Manifest intake cycle failed: {exc}', flush=True)
            record_cycle(ok=False, poll_seconds=POLL_SECONDS, error=f'{type(exc).__name__}: {exc}')
            time.sleep(POLL_SECONDS)
            continue
        record_cycle(ok=True, poll_seconds=POLL_SECONDS, accepted=accepted,
                     duplicates=duplicates, rejected=rejected)
        if accepted or rejected != last_rejected or (time.monotonic() - last_report) >= IDLE_REPORT_SECONDS:
            print(f'Manifest intake: {accepted} accepted, {duplicates} already known, '
                  f'{rejected} rejected', flush=True)
            last_report = time.monotonic()
        last_rejected = rejected
        # Only a cycle that accepted new work continues at once, to drain a
        # backlog. A rejected manifest stays on the share and is re-read every
        # cycle, so treating rejections as work spun the loop without pause.
        if not accepted:
            time.sleep(POLL_SECONDS)


if __name__ == '__main__':
    run_forever()
