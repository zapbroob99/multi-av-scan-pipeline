"""Bounded operator history for API/ICAP scans; no integration bearer access."""
from pydantic import BaseModel
from app import database as db
from app.services.browser_db_budget import apply_read_budget


class LedgerScan(BaseModel):
    id: int
    attempt_count: int
    job_revision: int
    filename: str
    sha256: str
    size_bytes: int
    case_name: str
    source: str
    service_client_id: int | None
    client_name: str | None
    batch_id: int | None
    status: str
    risk_level: str
    risk_score: int | None
    created_at: str


class LedgerPage(BaseModel):
    items: list[LedgerScan]
    next_before: int | None


def page(*, limit: int, before: int | None, query: str, source: str, status: str,
         risk: str, client_id: int | None, unassigned: bool) -> LedgerPage:
    conditions = ["j.source IN ('api', 'icap')", "j.scan_role != 'child'"]
    values: list[object] = []
    for expression, value in (('j.id < ?', before), ('j.service_client_id = ?', client_id)):
        if value is not None:
            conditions.append(expression)
            values.append(value)
    if unassigned:
        conditions.append('j.service_client_id IS NULL')
    if source != 'all':
        conditions.append('j.source = ?')
        values.append(source)
    if status == 'active':
        conditions.append("j.status IN ('queued', 'running', 'finalizing')")
    elif status != 'all':
        conditions.append('j.status = ?')
        values.append(status)
    if risk != 'all':
        conditions.append('j.verdict = ?')
        values.append(risk)
    if query.strip():
        pattern = '%' + query.strip().lower().replace('!', '!!').replace('%', '!%').replace('_', '!_') + '%'
        columns = ('s.original_filename', 's.sha256', 's.sha1', 's.md5', 'j.case_name')
        conditions.append('(' + ' OR '.join(f"LOWER({column}) LIKE ? ESCAPE '!'" for column in columns) + ')')
        values.extend([pattern] * len(columns))
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute(f"""
            SELECT j.id, j.attempt_count, COALESCE((SELECT MAX(ej.id) FROM scan_engine_jobs ej
                    WHERE ej.scan_job_id = j.id), 0) AS job_revision, SUBSTR(s.original_filename, 1, 512) AS filename,
                SUBSTR(s.sha256, 1, 64) AS sha256, s.size_bytes,
                SUBSTR(j.case_name, 1, 128) AS case_name, j.source,
                j.service_client_id, SUBSTR(c.display_name, 1, 100) AS client_name,
                j.batch_id, j.status, j.verdict AS risk_level, j.risk_score, j.created_at
            FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
            LEFT JOIN service_clients c ON c.id = j.service_client_id
            WHERE {' AND '.join(conditions)} ORDER BY j.id DESC LIMIT ?
        """, (*values, limit + 1)).fetchall()
    items = [LedgerScan(**{**dict(row), 'created_at': str(row['created_at'])}) for row in rows[:limit]]
    return LedgerPage(items=items, next_before=items[-1].id if len(rows) > limit else None)
