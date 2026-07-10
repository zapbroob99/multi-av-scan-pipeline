"""Turn a stored sample into a queued scan, and wait for it to finish.

Extracted from ``app.main`` so both the FastAPI upload path and the standalone
ICAP server create scans through one code path, without the ICAP process having
to import the web app.
"""

from __future__ import annotations

import asyncio
import json

from app.database import (
    create_sample,
    create_scan_batch,
    create_scan_engine_jobs,
    create_scan_job,
    get_scan,
)
from app.models import ScanRecord, StoredSample
from app.services.archive_extractor import detect_archive_format
from app.services.engine_registry import enabled_engines


API_TERMINAL_SCAN_STATUSES = {"completed", "failed"}
DEFAULT_ARCHIVE_MODE = "lazy_extract_on_detection"


def scan_is_terminal(scan: ScanRecord) -> bool:
    return scan.status in API_TERMINAL_SCAN_STATUSES


def enqueue_scan_from_stored_sample(
    stored_sample: StoredSample,
    *,
    case_name: str,
    priority: str,
    note: str,
    source: str,
    archive_mode: str = DEFAULT_ARCHIVE_MODE,
) -> ScanRecord:
    """Create a scan job (and archive batch/container when applicable).

    ``archive_mode`` must already be normalized by the caller; this service
    does not perform web-layer validation.
    """
    sample_id = create_sample(stored_sample)
    batch_id: int | None = None
    relative_path: str | None = None
    scan_role = "standalone"
    archive_format = detect_archive_format(stored_sample.storage_path)
    if archive_format is not None:
        batch_id = create_scan_batch(
            source=source,
            original_filename=stored_sample.original_filename,
            archive_mode=archive_mode,
            total_items=1,
            metadata_json=json.dumps(
                {
                    "container_sha256": stored_sample.sha256,
                    "container_size_bytes": stored_sample.size_bytes,
                    "container_archive_format": archive_format,
                }
            ),
        )
        relative_path = stored_sample.original_filename
        scan_role = "container"

    scan_id = create_scan_job(
        sample_id=sample_id,
        case_name=case_name.strip() or "Unassigned",
        priority=priority,
        note=note.strip(),
        source=source,
        batch_id=batch_id,
        relative_path=relative_path,
        scan_role=scan_role,
    )
    create_scan_engine_jobs(scan_id, enabled_engines())
    scan = get_scan(scan_id)
    if scan is None:
        raise RuntimeError("Scan could not be loaded after creation.")
    return scan


async def wait_for_terminal_scan(scan_id: int, wait_seconds: int) -> ScanRecord | None:
    scan = get_scan(scan_id)
    if scan is None or wait_seconds <= 0 or scan_is_terminal(scan):
        return scan

    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_seconds
    while loop.time() < deadline:
        await asyncio.sleep(min(0.5, max(0.1, deadline - loop.time())))
        scan = get_scan(scan_id)
        if scan is None or scan_is_terminal(scan):
            return scan
    return get_scan(scan_id)
