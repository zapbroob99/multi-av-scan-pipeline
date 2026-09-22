"""Admin active-queue projection; no historical aggregates or result hydration."""
from pydantic import BaseModel
from app import database as db
from app.services.browser_db_budget import apply_read_budget


class ActiveScan(BaseModel):
    id: int
    filename: str
    source: str
    status: str
    priority: str
    created_at: str


class ActiveQueuePage(BaseModel):
    items: list[ActiveScan]
    next_after: int | None


def page(*, limit: int, after: int | None) -> ActiveQueuePage:
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute('''SELECT j.id, SUBSTR(s.original_filename, 1, 512) AS filename,
            j.source, j.status, SUBSTR(j.priority, 1, 32) AS priority, j.created_at
            FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
            WHERE j.status IN ('queued', 'running', 'finalizing') ''' +
            ('AND j.id > ? ' if after is not None else '') + 'ORDER BY j.id LIMIT ?',
            (*((after,) if after is not None else ()), limit + 1)).fetchall()
    items = [ActiveScan(**{**dict(row), 'created_at': str(row['created_at'])}) for row in rows[:limit]]
    return ActiveQueuePage(items=items, next_after=items[-1].id if len(rows) > limit else None)
