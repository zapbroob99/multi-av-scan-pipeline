"""Read-only, bounded navigation of registered manual archive child scans."""
from fastapi import HTTPException
from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget


class ArchiveChild(BaseModel):
    id: int
    path: str
    path_truncated: bool
    filename: str
    size_bytes: int
    status: str
    risk_score: int | None
    risk_level: str
    has_children: bool


class ArchivePage(BaseModel):
    parent_id: int
    parent_filename: str
    parent_status: str
    parent_scan_id: int | None
    batch_id: int | None
    archive_mode: str | None
    attempt_count: int
    items: list[ArchiveChild]
    next_after: int | None


def child_presence_statement(rows) -> tuple[str, tuple[object, ...]]:
    branches: list[str] = []
    params: list[object] = []
    for row in rows:
        branches.append('''SELECT ? AS parent_id WHERE EXISTS (
            SELECT 1 FROM scan_jobs nested WHERE nested.parent_scan_id = ?
            AND nested.source = 'manual' AND nested.scan_role = 'child'
            AND ''' + ('nested.batch_id IS NULL' if row['child_batch_id'] is None else 'nested.batch_id = ?') +
            ' LIMIT 1)')
        params.extend((row['id'], row['id']))
        if row['child_batch_id'] is not None:
            params.append(row['child_batch_id'])
    return ' UNION ALL '.join(branches), tuple(params)


def children(scan_id: int, *, limit: int, after: int | None, attempt: int | None,
             query: str, status: str) -> ArchivePage:
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        parent = connection.execute('''SELECT j.id, j.status, j.attempt_count, j.parent_scan_id, j.batch_id,
            SUBSTR(s.original_filename, 1, 512) AS filename, b.archive_mode
            FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
            LEFT JOIN scan_batches b ON b.id = j.batch_id AND b.source = 'manual'
            WHERE j.id = ? AND j.source = 'manual' ''', (scan_id,)).fetchone()
        if parent is None:
            raise HTTPException(404, 'Manual parent scan not found.')
        if attempt is not None and attempt != parent['attempt_count']:
            raise HTTPException(409, 'The parent scan has a new attempt. Return to the first page to refresh archive contents.')
        conditions = ["c.parent_scan_id = ?", "c.source = 'manual'", "c.scan_role = 'child'"]
        params: list[object] = [scan_id]
        # Do not cross a batch boundary even if a corrupt/misassigned row points
        # at this parent. If the batch was deleted, only detached children match.
        if parent['batch_id'] is None:
            conditions.append('c.batch_id IS NULL')
        else:
            conditions.append('c.batch_id = ?')
            params.append(parent['batch_id'])
        if after is not None:
            conditions.append('c.id > ?')
            params.append(after)
        if status == 'active':
            conditions.append("c.status IN ('queued', 'running', 'finalizing')")
        elif status != 'all':
            conditions.append('c.status = ?')
            params.append(status)
        if query.strip():
            pattern = '%' + query.strip().lower().replace('!', '!!').replace('%', '!%').replace('_', '!_') + '%'
            conditions.append("(LOWER(COALESCE(c.relative_path, s.original_filename)) LIKE ? ESCAPE '!' OR LOWER(s.original_filename) LIKE ? ESCAPE '!')")
            params.extend([pattern, pattern])
        params.append(limit + 1)
        rows = connection.execute(f'''SELECT c.id, c.batch_id AS child_batch_id,
            SUBSTR(COALESCE(c.relative_path, s.original_filename), 1, 1024) AS path,
            CASE WHEN LENGTH(COALESCE(c.relative_path, s.original_filename)) > 1024 THEN 1 ELSE 0 END AS path_truncated,
            SUBSTR(s.original_filename, 1, 512) AS filename, s.size_bytes,
            c.status, c.risk_score, c.verdict AS risk_level
            FROM scan_jobs c JOIN samples s ON s.id = c.sample_id
            WHERE {' AND '.join(conditions)} ORDER BY c.id ASC LIMIT ?''', tuple(params)).fetchall()
        # PostgreSQL can choose a correlated sequential scan for EXISTS when one
        # archive parent dominates statistics. Give every bounded page ID its own
        # constant branch so idx_scan_jobs_parent is costed and used. This stays
        # one round trip and at most limit+1 probes in the same read snapshot.
        child_parent_ids: set[int] = set()
        if rows:
            child_sql, child_params = child_presence_statement(rows)
            child_rows = connection.execute(child_sql, child_params).fetchall()
            child_parent_ids = {int(row['parent_id']) for row in child_rows}
    items = [ArchiveChild(**{key: value for key, value in dict(row).items() if key != 'child_batch_id'},
                          has_children=row['id'] in child_parent_ids) for row in rows[:limit]]
    return ArchivePage(parent_id=parent['id'], parent_filename=parent['filename'], parent_status=parent['status'],
        parent_scan_id=parent['parent_scan_id'], batch_id=parent['batch_id'], archive_mode=parent['archive_mode'],
        attempt_count=parent['attempt_count'], items=items, next_after=items[-1].id if len(rows) > limit else None)
