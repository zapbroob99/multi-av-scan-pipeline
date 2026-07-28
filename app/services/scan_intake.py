"""Turn a stored sample into a queued scan, and wait for it to finish.

Extracted from ``app.main`` so both the FastAPI upload path and the standalone
ICAP server create scans through one code path, without the ICAP process having
to import the web app.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from app.database import create_scan_intake, get_scan
from app.models import ScanRecord, StoredSample
from app.services.archive_extractor import detect_archive_format
from app.services.engine_registry import enabled_engines


API_TERMINAL_SCAN_STATUSES = {"completed", "failed"}
DEFAULT_ARCHIVE_MODE = "lazy_extract_on_detection"


class NoEligibleEnginesError(RuntimeError):
    """Intake attempted with no enabled scan engines.

    Creating such a scan would leave it with zero engine jobs and no way ever to
    reach a terminal state, so intake is rejected up front instead.
    """


def scan_is_terminal(scan: ScanRecord) -> bool:
    return scan.status in API_TERMINAL_SCAN_STATUSES


def _discard_stored_sample_file(stored_sample: StoredSample) -> None:
    # The file was written for THIS intake only: a unique uuid-named file with no
    # deduplication, so no other scan references it. Safe to remove when the DB
    # transaction that would own it fails. (Revisit if content dedup is added.)
    try:
        Path(stored_sample.storage_path).unlink(missing_ok=True)
    except OSError:
        pass


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

    Sample, optional batch, scan job, and engine jobs are created in one
    transaction, so a failure leaves no orphan rows or engine-jobless scan.
    Rejects intake when no engine is enabled. ``archive_mode`` must already be
    normalized by the caller.
    """
    try:
        engines = enabled_engines()
        if not engines:
            raise NoEligibleEnginesError("No scan engines are enabled; intake rejected.")
        archive_format = detect_archive_format(stored_sample.storage_path)
        scan_id = create_scan_intake(
            sample=stored_sample,
            engines=engines,
            case_name=case_name.strip() or "Unassigned",
            priority=priority,
            note=note.strip(),
            source=source,
            archive_mode=archive_mode,
            archive_format=archive_format,
        )
    except Exception:
        # Any failure BEFORE the intake transaction commits (zero engines,
        # archive detection error, or a DB error) leaves the just-written sample
        # file orphaned — no DB row references it — so remove it.
        _discard_stored_sample_file(stored_sample)
        raise

    # The sample row is committed and now references the file, so a failure from
    # here on must NOT delete it.
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
