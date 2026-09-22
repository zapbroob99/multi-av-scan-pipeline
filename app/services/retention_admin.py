"""Bounded, explicitly reviewed retention batches for browser administrators."""
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app import database as db
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms
from app.services.cleanup import delete_sample_file
from app.services.retention import retention_policy_from_env, retention_cutoff_value
from app.services.scan_management import BulkDeleteCandidate, BulkDeleteResult


class RetentionCandidate(BulkDeleteCandidate):
    filename: str
    source: str
    status: str
    created_at: str


class RetentionPage(BaseModel):
    days: int
    batch_size: int
    cutoff: str | None
    items: list[RetentionCandidate]
    next_after: int | None


class RetentionRunBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    days: int = Field(ge=1)
    batch_size: int = Field(ge=1)
    scans: list[BulkDeleteCandidate] = Field(min_length=1, max_length=20)


def policy_and_cutoff():
    policy = retention_policy_from_env()
    try:
        cutoff = retention_cutoff_value(policy)
    except (OverflowError, ValueError) as exc:
        raise HTTPException(409, 'Retention window is outside the supported date range.') from exc
    return policy, cutoff


def preview(after: int | None) -> RetentionPage:
    policy, cutoff = policy_and_cutoff()
    if cutoff is None:
        return RetentionPage(days=policy.days, batch_size=policy.batch_size, cutoff=None, items=[], next_after=None)
    limit = min(policy.batch_size, 20)
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute('''SELECT j.id AS scan_id, j.attempt_count AS attempt,
            (SELECT COALESCE(MAX(e.id), 0) FROM scan_engine_jobs e WHERE e.scan_job_id = j.id) AS job_revision,
            SUBSTR(s.original_filename, 1, 512) AS filename, j.source, j.status, j.created_at
            FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
            WHERE j.created_at < ? AND j.status NOT IN ('queued', 'running', 'finalizing')
            ''' + ('AND j.id > ? ' if after is not None else '') + 'ORDER BY j.id LIMIT ?',
            (cutoff, *((after,) if after is not None else ()), limit + 1)).fetchall()
    return RetentionPage(days=policy.days, batch_size=policy.batch_size, cutoff=cutoff,
        items=[RetentionCandidate(**{**dict(row), 'created_at': str(row['created_at'])}) for row in rows[:limit]],
        next_after=rows[limit - 1]['scan_id'] if len(rows) > limit else None)


def run(body: RetentionRunBody) -> BulkDeleteResult:
    policy, cutoff = policy_and_cutoff()
    if cutoff is None or (body.days, body.batch_size) != (policy.days, policy.batch_size):
        raise HTTPException(409, 'Retention policy changed or is disabled. Refresh the preview.')
    ids = [row.scan_id for row in body.scans]
    if len(ids) > min(policy.batch_size, 20) or len(set(ids)) != len(ids):
        raise HTTPException(422, 'Select unique candidates within the retention batch limit.')
    result = BulkDeleteResult(requested_count=len(ids), deleted_ids=[], blocked_ids=[], cleanup_failed_ids=[])
    for candidate in body.scans:
        scan = db.delete_scan(candidate.scan_id, expected_attempt=candidate.attempt,
            expected_job_revision=candidate.job_revision, protect_children=True,
            created_before=cutoff, lock_timeout_ms=write_lock_timeout_ms())
        if scan is None:
            result.blocked_ids.append(candidate.scan_id)
            continue
        result.deleted_ids.append(candidate.scan_id)
        try:
            removed = delete_sample_file(scan)
        except OSError:
            removed = False
        if not removed:
            result.cleanup_failed_ids.append(candidate.scan_id)
    return result
