"""Operator actions on deferred intake: retry a failed copy, dismiss a rejection.

Both act on one named record and leave the copying and scanning to the
existing workers. A retry returns a permanently failed submission to the
pending queue exactly as a transient failure would, so the worker's lease and
attempt fencing apply unchanged. A dismissed rejection only removes the
record; a manifest still inside the lookback window is read again and, if it
is still invalid, recorded again.
"""
from __future__ import annotations

import time

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app import database as db
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms


class RejectionDismissal(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    backend_key: str = Field(min_length=1, max_length=128)
    manifest_object_id: str = Field(min_length=1, max_length=1024)


def _locked(connection) -> None:
    apply_read_budget(connection)
    if db.using_postgres():
        connection.execute("SELECT set_config('lock_timeout', ?, true)", (f'{write_lock_timeout_ms()}ms',))


def retry_failed_submission(submission_id: int, now: int | None = None) -> None:
    current = int(time.time()) if now is None else now
    with db.connect() as connection:
        _locked(connection)
        cursor = connection.execute('''UPDATE deferred_scan_submissions
            SET status = 'pending', available_at = ?, worker_id = NULL, lease_expires_at = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'failed' AND scan_job_id IS NULL''', (current, submission_id))
        if not cursor.rowcount:
            raise HTTPException(409, 'Submission is no longer a failed intake. Refresh before retrying.')


def dismiss_rejection(body: RejectionDismissal) -> None:
    with db.connect() as connection:
        _locked(connection)
        cursor = connection.execute('''DELETE FROM manifest_rejections
            WHERE backend_key = ? AND manifest_object_id = ?''', (body.backend_key, body.manifest_object_id))
        if not cursor.rowcount:
            raise HTTPException(409, 'Rejection is already gone. Refresh the page.')
