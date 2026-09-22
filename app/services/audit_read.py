"""Admin-only bounded audit history. Append-only table; no update or delete."""
from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget


DETAILS_LIMIT = 4096


class AuditEvent(BaseModel):
    id: int
    created_at: str
    actor_type: str
    actor_id: str | None
    actor_name: str | None
    action: str
    target_type: str
    target_id: str | None
    outcome: str
    source_ip: str | None
    request_id: str
    details: str
    details_truncated: bool


class AuditPage(BaseModel):
    items: list[AuditEvent]
    next_before: int | None


def page(*, limit: int, before: int | None, query: str, outcome: str) -> AuditPage:
    conditions: list[str] = []
    values: list[object] = []
    if before is not None:
        conditions.append('id < ?')
        values.append(before)
    if outcome != 'all':
        conditions.append('outcome = ?')
        values.append(outcome)
    if query.strip():
        # Literal search: legacy passed the raw term to LIKE, so an operator
        # character silently widened the filter instead of matching itself.
        pattern = '%' + query.strip().lower().replace('!', '!!').replace('%', '!%').replace('_', '!_') + '%'
        columns = ('actor_name', 'actor_id', 'action', 'target_type', 'target_id', 'request_id')
        conditions.append('(' + ' OR '.join(
            f"LOWER(COALESCE({column}, '')) LIKE ? ESCAPE '!'" for column in columns) + ')')
        values.extend([pattern] * len(columns))
    where = (' WHERE ' + ' AND '.join(conditions)) if conditions else ''
    with db.connect() as connection:
        apply_read_budget(connection)
        # No total: counting the full trail is unbounded administrative work and
        # the page itself is the record operators act on.
        rows = connection.execute(f'''SELECT id, created_at, actor_type,
            SUBSTR(actor_id, 1, 128) AS actor_id, SUBSTR(actor_name, 1, 128) AS actor_name,
            SUBSTR(action, 1, 128) AS action, SUBSTR(target_type, 1, 64) AS target_type,
            SUBSTR(target_id, 1, 128) AS target_id, outcome, SUBSTR(source_ip, 1, 64) AS source_ip,
            SUBSTR(request_id, 1, 128) AS request_id, SUBSTR(details_json, 1, {DETAILS_LIMIT}) AS details,
            LENGTH(details_json) > {DETAILS_LIMIT} AS details_truncated
            FROM audit_events{where} ORDER BY id DESC LIMIT ?''', (*values, limit + 1)).fetchall()
    items = [AuditEvent(**{**dict(row), 'created_at': str(row['created_at']),
                           'details_truncated': bool(row['details_truncated'])}) for row in rows[:limit]]
    return AuditPage(items=items, next_before=items[-1].id if len(rows) > limit else None)
