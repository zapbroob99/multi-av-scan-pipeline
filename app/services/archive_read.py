"""Read-only, bounded navigation of registered archive child scans with explicit source and owner scope."""
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


def child_presence_statement(rows, *, automation=False, source='manual', client_id=None) -> tuple[str, tuple[object, ...]]:
    branches: list[str] = []
    params: list[object] = []
    for row in rows:
        conditions = ["nested.parent_scan_id = ?", "nested.source = ?", "nested.scan_role = 'child'"]
        values = [row['id'], row['id'], source]
        if automation:
            conditions.append('nested.service_client_id IS NULL' if client_id is None else 'nested.service_client_id = ?')
            if client_id is not None:
                values.append(client_id)
        conditions.append('nested.batch_id IS NULL' if row['child_batch_id'] is None else 'nested.batch_id = ?')
        if row['child_batch_id'] is not None:
            values.append(row['child_batch_id'])
        branches.append('SELECT ? AS parent_id WHERE EXISTS (SELECT 1 FROM scan_jobs nested WHERE '
                        + ' AND '.join(conditions) + ' LIMIT 1)')
        params.extend(values)
    return ' UNION ALL '.join(branches), tuple(params)


def children(scan_id: int, *, limit: int, after: int | None, attempt: int | None,
             query: str, status: str, automation: bool = False) -> ArchivePage:
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        scope = "j.source IN ('api', 'icap')" if automation else "j.source = 'manual'"
        owner_join = 'AND (b.service_client_id = j.service_client_id OR (b.service_client_id IS NULL AND j.service_client_id IS NULL))' if automation else ''
        parent = connection.execute(f'''SELECT j.id, j.source, j.service_client_id, b.id AS matched_batch, j.status, j.attempt_count, j.parent_scan_id, j.batch_id,
            SUBSTR(s.original_filename, 1, 512) AS filename, b.archive_mode
            FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
            LEFT JOIN scan_batches b ON b.id = j.batch_id AND b.source = j.source
                {owner_join}
            WHERE j.id = ? AND {scope} ''', (scan_id,)).fetchone()
        if parent is None:
            raise HTTPException(404, 'Automation parent scan not found.' if automation else 'Manual parent scan not found.')
        if automation and parent['batch_id'] is not None and parent['matched_batch'] is None:
            raise HTTPException(409, 'Parent batch has inconsistent source or ownership.')
        if attempt is not None and attempt != parent['attempt_count']:
            raise HTTPException(409, 'The parent scan has a new attempt. Return to the first page to refresh archive contents.')
        conditions = ["c.parent_scan_id = ?", "c.source = ?", "c.scan_role = 'child'"]
        params: list[object] = [scan_id, parent['source']]
        if automation:
            conditions.append('c.service_client_id IS NULL' if parent['service_client_id'] is None else 'c.service_client_id = ?')
            if parent['service_client_id'] is not None:
                params.append(parent['service_client_id'])
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
            child_sql, child_params = child_presence_statement(rows, automation=automation, source=parent['source'], client_id=parent['service_client_id'])
            child_rows = connection.execute(child_sql, child_params).fetchall()
            child_parent_ids = {int(row['parent_id']) for row in child_rows}
        parent_scan_id = parent['parent_scan_id']
        if automation and parent_scan_id is not None:
            # Never offer an upward link across source, owner or batch boundaries.
            checks = ['id = ?', 'source = ?']
            values = [parent_scan_id, parent['source']]
            for column in ('service_client_id', 'batch_id'):
                if parent[column] is None:
                    checks.append(column + ' IS NULL')
                else:
                    checks.append(column + ' = ?')
                    values.append(parent[column])
            if connection.execute('SELECT id FROM scan_jobs WHERE ' + ' AND '.join(checks), tuple(values)).fetchone() is None:
                parent_scan_id = None
    items = [ArchiveChild(**{key: value for key, value in dict(row).items() if key != 'child_batch_id'},
                          has_children=row['id'] in child_parent_ids) for row in rows[:limit]]
    return ArchivePage(parent_id=parent['id'], parent_filename=parent['filename'], parent_status=parent['status'],
        parent_scan_id=parent_scan_id, batch_id=parent['batch_id'], archive_mode=parent['archive_mode'],
        attempt_count=parent['attempt_count'], items=items, next_after=items[-1].id if len(rows) > limit else None)
