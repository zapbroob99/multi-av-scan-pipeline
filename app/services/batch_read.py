"""Bounded, read-only browser view of one registered manual scan batch."""
from fastapi import HTTPException
from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget


class BatchCounts(BaseModel):
    total: int
    queued: int
    running: int
    completed: int
    failed: int
    malicious: int
    skipped: int


class BatchScan(BaseModel):
    id: int
    path: str
    path_truncated: bool
    filename: str
    size_bytes: int
    parent_scan_id: int | None
    role: str
    status: str
    risk_score: int | None
    risk_level: str
    attempt_count: int
    created_at: str
    completed_at: str | None


class BatchPage(BaseModel):
    batch_id: int
    filename: str
    filename_truncated: bool
    archive_mode: str
    status: str
    counts: BatchCounts
    created_at: str
    updated_at: str
    completed_at: str | None
    items: list[BatchScan]
    next_after_id: int | None
    next_after_created: str | None


def page(batch_id: int, *, limit: int, after_id: int | None,
         after_created: str | None) -> BatchPage:
    with db.connect() as connection:
        connection.execute(
            'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN'
        )
        apply_read_budget(connection)
        batch = connection.execute('''SELECT id,
            SUBSTR(original_filename, 1, 512) AS filename,
            CASE WHEN LENGTH(original_filename) > 512 THEN 1 ELSE 0 END AS filename_truncated,
            archive_mode, status, total_items, queued_items, running_items,
            completed_items, failed_items, malicious_items, skipped_items,
            created_at, updated_at, completed_at
            FROM scan_batches WHERE id = ? AND source = 'manual' ''', (batch_id,)).fetchone()
        if batch is None:
            raise HTTPException(404, 'Manual batch not found.')

        conditions = ["j.batch_id = ?", "j.source = 'manual'"]
        params: list[object] = [batch_id]
        if after_id is not None and after_created is not None:
            conditions.append('(j.created_at, j.id) > (?, ?)')
            params.extend((after_created, after_id))
        params.append(limit + 1)
        rows = connection.execute(f'''SELECT j.id,
            SUBSTR(COALESCE(j.relative_path, s.original_filename), 1, 1024) AS path,
            CASE WHEN LENGTH(COALESCE(j.relative_path, s.original_filename)) > 1024 THEN 1 ELSE 0 END AS path_truncated,
            SUBSTR(s.original_filename, 1, 512) AS filename, s.size_bytes,
            j.parent_scan_id, j.scan_role AS role, j.status, j.risk_score,
            j.verdict AS risk_level, j.attempt_count, j.created_at, j.completed_at
            FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
            WHERE {' AND '.join(conditions)}
            ORDER BY j.created_at ASC, j.id ASC LIMIT ?''', tuple(params)).fetchall()

    items: list[BatchScan] = []
    for row in rows[:limit]:
        values = dict(row)
        values['created_at'] = str(values['created_at'])
        values['completed_at'] = None if values['completed_at'] is None else str(values['completed_at'])
        items.append(BatchScan(**values))
    has_next = len(rows) > limit
    cursor = items[-1] if has_next and items else None
    return BatchPage(
        batch_id=batch['id'], filename=batch['filename'],
        filename_truncated=bool(batch['filename_truncated']), archive_mode=batch['archive_mode'],
        status=batch['status'],
        counts=BatchCounts(
            total=batch['total_items'], queued=batch['queued_items'], running=batch['running_items'],
            completed=batch['completed_items'], failed=batch['failed_items'],
            malicious=batch['malicious_items'], skipped=batch['skipped_items'],
        ),
        created_at=str(batch['created_at']), updated_at=str(batch['updated_at']),
        completed_at=None if batch['completed_at'] is None else str(batch['completed_at']),
        items=items,
        next_after_id=cursor.id if cursor else None,
        next_after_created=cursor.created_at if cursor else None,
    )
