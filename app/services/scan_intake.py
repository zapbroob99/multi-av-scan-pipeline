"""Turn a stored sample into a queued scan, and wait for it to finish.

Extracted from ``app.main`` so both the FastAPI upload path and the standalone
ICAP server create scans through one code path, without the ICAP process having
to import the web app.
"""

from __future__ import annotations

import asyncio
from starlette.concurrency import run_in_threadpool
from pathlib import Path

from app.database import count_active_batch_scans, create_scan_intake, get_scan
from app.models import EngineInstanceRecord, ScanRecord, StoredSample
from app.services.archive_extractor import EXTRACT_ALL_ARCHIVE_MODE, detect_archive_format
from app.services.engine_registry import enabled_engines
from app.services.profile_policy import apply_intake_policy, not_allowed_code, scans_every_member
from app.services import profile_rules


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
    engines: list[EngineInstanceRecord] | None = None,
    service_client_id: int | None = None,
    scan_profile_id: int | None = None,
    profile_snapshot_json: str = "{}",
    refuse_archives: bool = False,
) -> ScanRecord:
    """Create a scan job (and archive batch/container when applicable).

    Sample, optional batch, scan job, and engine jobs are created in one
    transaction, so a failure leaves no orphan rows or engine-jobless scan.
    Rejects intake when no engine is enabled. ``archive_mode`` must already be
    normalized by the caller.
    """
    try:
        selected_engines = engines if engines is not None else enabled_engines(source=source)
        if not selected_engines:
            raise NoEligibleEnginesError(
                f"No eligible scan engines are available for source {source!r}; "
                "intake rejected."
            )
        # Raises PolicyRejectedError when the client's profile refuses the
        # sample outright; the file is discarded below and no scan is created.
        profile_snapshot_json = apply_intake_policy(
            profile_snapshot_json,
            filename=stored_sample.original_filename,
            size=stored_sample.size_bytes,
            storage_path=stored_sample.storage_path,
            refuse_archives=refuse_archives,
        )
        # A rule profile runs only the matched rule's engines; Block and Allow
        # without scanning run none and complete at intake.
        selected_engines, rule_action = profile_rules.narrow(selected_engines, profile_snapshot_json)
        if rule_action in ("scan", "light") and not selected_engines:
            raise NoEligibleEnginesError("None of the matched profile rule's engines is available; intake rejected.")
        # Only a Scan rule opens an archive; any other rule treats it as one file.
        archive_format = (detect_archive_format(stored_sample.storage_path)
                          if rule_action in (None, "scan") else None)
        archive_mode = effective_archive_mode(profile_snapshot_json, archive_mode)
        scan_id = create_scan_intake(
            sample=stored_sample,
            engines=selected_engines,
            case_name=case_name.strip() or "Unassigned",
            priority=priority,
            note=note.strip(),
            source=source,
            archive_mode=archive_mode,
            archive_format=archive_format,
            service_client_id=service_client_id,
            scan_profile_id=scan_profile_id,
            profile_snapshot_json=profile_snapshot_json,
            not_allowed=not_allowed_code(profile_snapshot_json),
            rule_action=rule_action,
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


def effective_archive_mode(profile_snapshot_json: str, requested_archive_mode: str) -> str:
    """The batch mode for this sample: the profile's scan_members overrides the request."""
    if scans_every_member(profile_snapshot_json):
        return EXTRACT_ALL_ARCHIVE_MODE
    return requested_archive_mode


async def wait_for_terminal_scan(scan_id: int, wait_seconds: int) -> ScanRecord | None:
    scan = await run_in_threadpool(get_scan, scan_id)
    if scan is None or wait_seconds <= 0 or scan_is_terminal(scan):
        return scan

    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_seconds
    while loop.time() < deadline:
        await asyncio.sleep(min(0.5, max(0.1, deadline - loop.time())))
        scan = await run_in_threadpool(get_scan, scan_id)
        if scan is None or scan_is_terminal(scan):
            return scan
    return await run_in_threadpool(get_scan, scan_id)


async def wait_for_settled_batch(batch_id: int, wait_seconds: float) -> bool:
    """Wait until no scan in the batch is active; False when the window ends first.

    A member registers its own members before it completes, so a batch with no
    active scan cannot grow any further.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, wait_seconds)
    while True:
        if await run_in_threadpool(count_active_batch_scans, batch_id) == 0:
            return True
        if loop.time() >= deadline:
            return False
        await asyncio.sleep(min(0.5, max(0.1, deadline - loop.time())))
