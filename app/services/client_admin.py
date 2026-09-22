"""Bounded service-client metadata; credentials and routing stay separate."""
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app import database as db
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms


class ServiceClientSummary(BaseModel):
    id: int
    client_key: str
    display_name: str
    enabled: bool
    managed: bool
    metadata_incomplete: bool


class ServiceClientPage(BaseModel):
    items: list[ServiceClientSummary]
    next_after: int | None


class ServiceClientUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    display_name: str = Field(min_length=1, max_length=100)
    enabled: bool


def page(limit: int, after: int | None) -> ServiceClientPage:
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute('''SELECT id, SUBSTR(client_key, 1, 128) AS client_key,
            SUBSTR(display_name, 1, 100) AS display_name, enabled,
            client_key = 'legacy-default' AS managed,
            (LENGTH(client_key) > 128 OR LENGTH(display_name) > 100) AS metadata_incomplete
            FROM service_clients ''' + ('WHERE id > ? ' if after is not None else '') + 'ORDER BY id LIMIT ?',
            (*((after,) if after is not None else ()), limit + 1)).fetchall()
    return ServiceClientPage(items=[ServiceClientSummary(**dict(row)) for row in rows[:limit]],
        next_after=rows[limit - 1]['id'] if len(rows) > limit else None)


def update(client_id: int, body: ServiceClientUpdate) -> None:
    name = body.display_name.strip()
    if not name:
        raise HTTPException(422, 'Service client name must not be blank.')
    with db.connect() as connection:
        apply_read_budget(connection)
        if db.using_postgres():
            connection.execute("SELECT set_config('lock_timeout', ?, true)", (f'{write_lock_timeout_ms()}ms',))
        changed = connection.execute('''UPDATE service_clients SET display_name = ?, enabled = ?,
            updated_at = CURRENT_TIMESTAMP WHERE id = ? AND client_key != 'legacy-default' ''',
            (name, db.db_bool(body.enabled), client_id))
        if not changed.rowcount:
            raise HTTPException(409, 'Service client is missing or managed by the deployment. Refresh before editing.')
