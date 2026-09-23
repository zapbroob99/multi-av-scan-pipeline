"""Admin visibility into deferred intake: the manifest worker, queue lag,
rejected manifests and submissions that failed before becoming scans.

A storage producer that drops manifests receives no delivery, backpressure or
error feedback, so this is the only place a stopped worker, a growing backlog
or a malformed drop becomes visible. Every read is bounded; nothing here
writes, retries or clears anything.
"""
from datetime import datetime, timezone
import json
import time

from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget
from app.services.deferred_storage import redact_paths
from app.services.manifest_intake import LAST_CYCLE_SETTING


REJECTION_LIMIT = 50
FAILURE_LIMIT = 20
TEXT_LIMIT = 1000
# A cycle older than this many poll intervals (and at least a minute) means
# the worker stopped or is stuck, not that the share is quiet.
STALE_POLL_INTERVALS = 4
MIN_STALE_SECONDS = 60


class ManifestWorker(BaseModel):
    at: int
    age_seconds: int
    stale: bool
    ok: bool
    error: str | None
    accepted: int
    duplicates: int
    rejected: int
    poll_seconds: float
    backend_key: str | None
    client_key: str | None
    root_prefix: str
    date_layout: str
    lookback_days: int
    batch_limit: int


class IntakeQueue(BaseModel):
    pending: int
    retrying: int
    claimed: int
    queued: int
    oldest_pending_at: str | None
    oldest_pending_age_seconds: int | None


class ManifestRejection(BaseModel):
    backend_key: str
    manifest_object_id: str
    reason: str
    first_seen_at: int
    last_seen_at: int
    occurrences: int


class IntakeFailure(BaseModel):
    id: int
    service_client_id: int
    client_name: str | None
    client_request_id: str
    backend_key: str
    object_id: str
    original_filename: str
    last_error: str
    attempt_count: int
    updated_at: str


class IntakeOverview(BaseModel):
    manifest_worker: ManifestWorker | None
    manifest_record_invalid: bool
    queue: IntakeQueue
    rejections: list[ManifestRejection]
    rejections_total: int
    failures: list[IntakeFailure]
    failures_truncated: bool


def _timestamp(value: object) -> datetime | None:
    """PostgreSQL returns datetimes; SQLite returns UTC text."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace(' ', 'T'))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _manifest_worker(raw: str | None, now: int) -> tuple[ManifestWorker | None, bool]:
    if not raw:
        return None, False
    try:
        record = json.loads(raw)
        age = max(0, now - int(record['at']))
        poll = float(record.get('poll_seconds') or 0)
        worker = ManifestWorker(
            **{**record, 'error': redact_paths(record['error'])[:TEXT_LIMIT] if record.get('error') else None},
            age_seconds=age,
            stale=age > max(MIN_STALE_SECONDS, STALE_POLL_INTERVALS * poll),
        )
    except (ValueError, TypeError, KeyError):
        # An unreadable record must not look like a healthy worker.
        return None, True
    return worker, False


def overview() -> IntakeOverview:
    now = int(time.time())
    with db.connect() as connection:
        apply_read_budget(connection)
        # Setting read shares the snapshot's connection so the page is coherent.
        setting = connection.execute('SELECT value FROM app_settings WHERE key = ?',
                                     (LAST_CYCLE_SETTING,)).fetchone()
        counts = {str(row['status']): int(row['entries']) for row in connection.execute(
            """SELECT status, COUNT(*) AS entries FROM deferred_scan_submissions
               WHERE status IN ('pending', 'claimed', 'queued') GROUP BY status""").fetchall()}
        pending = connection.execute(
            """SELECT MIN(created_at) AS oldest, SUM(CASE WHEN attempt_count > 0 THEN 1 ELSE 0 END) AS retrying
               FROM deferred_scan_submissions WHERE status = 'pending'""").fetchone()
        rejections = connection.execute(
            f"""SELECT backend_key, SUBSTR(manifest_object_id, 1, 1024) AS manifest_object_id,
                SUBSTR(reason, 1, {TEXT_LIMIT}) AS reason, first_seen_at, last_seen_at, occurrences
                FROM manifest_rejections ORDER BY last_seen_at DESC, manifest_object_id LIMIT ?""",
            (REJECTION_LIMIT,)).fetchall()
        rejections_total = int(connection.execute(
            'SELECT COUNT(*) AS entries FROM manifest_rejections').fetchone()['entries'])
        # Permanent intake failures never became scans, so no report shows them.
        failures = connection.execute(
            f"""SELECT d.id, d.service_client_id, SUBSTR(c.display_name, 1, 256) AS client_name,
                SUBSTR(d.client_request_id, 1, 256) AS client_request_id, d.backend_key,
                SUBSTR(d.object_id, 1, 1024) AS object_id, SUBSTR(d.original_filename, 1, 255) AS original_filename,
                SUBSTR(COALESCE(d.last_error, ''), 1, {TEXT_LIMIT}) AS last_error, d.attempt_count, d.updated_at
                FROM deferred_scan_submissions d LEFT JOIN service_clients c ON c.id = d.service_client_id
                WHERE d.status = 'failed' AND d.scan_job_id IS NULL ORDER BY d.id DESC LIMIT ?""",
            (FAILURE_LIMIT + 1,)).fetchall()

    worker, invalid = _manifest_worker(setting['value'] if setting else None, now)
    oldest = _timestamp(pending['oldest'] if pending else None)
    return IntakeOverview(
        manifest_worker=worker,
        manifest_record_invalid=invalid,
        queue=IntakeQueue(
            pending=counts.get('pending', 0), retrying=int((pending['retrying'] if pending else 0) or 0),
            claimed=counts.get('claimed', 0), queued=counts.get('queued', 0),
            oldest_pending_at=oldest.isoformat() if oldest else None,
            oldest_pending_age_seconds=max(0, now - int(oldest.timestamp())) if oldest else None,
        ),
        rejections=[ManifestRejection(**{**dict(row), 'reason': redact_paths(row['reason'])})
                    for row in rejections],
        rejections_total=rejections_total,
        failures=[IntakeFailure(**{**dict(row), 'last_error': redact_paths(row['last_error']),
                                   'updated_at': str(row['updated_at'])})
                  for row in failures[:FAILURE_LIMIT]],
        failures_truncated=len(failures) > FAILURE_LIMIT,
    )
