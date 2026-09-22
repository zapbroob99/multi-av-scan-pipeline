"""Client-scoped routing without profile policies or engine configuration."""
from typing import Annotated
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app import database as db
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms

SafeId = Annotated[int, Field(ge=1, le=9007199254740991)]


class ProfileRoutingBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    engine_ids: list[SafeId] = Field(min_length=1, max_length=100)
    expected_engine_ids: list[SafeId] = Field(max_length=100)


class ProfileEngineChoice(BaseModel):
    id: int
    display_name: str
    adapter_key: str
    enabled: bool


class ProfileSummary(BaseModel):
    id: int
    name: str
    enabled: bool
    is_default: bool
    engine_ids: list[int]
    incomplete: bool


class ClientProfiles(BaseModel):
    client_id: int
    managed: bool
    items: list[ProfileSummary]
    engines: list[ProfileEngineChoice]
    engines_incomplete: bool
    next_after: int | None


def page(client_id: int, after: int | None) -> ClientProfiles:
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        client = connection.execute("SELECT client_key = 'legacy-default' AS managed FROM service_clients WHERE id = ?", (client_id,)).fetchone()
        if client is None:
            raise HTTPException(404, 'Service client not found.')
        choices = connection.execute('''SELECT id, SUBSTR(display_name, 1, 128) AS display_name,
            SUBSTR(adapter_key, 1, 64) AS adapter_key, enabled FROM engine_instances ORDER BY id LIMIT 101''').fetchall()
        rows = connection.execute('''SELECT id, SUBSTR(name, 1, 128) AS name, LENGTH(name) > 128 AS incomplete,
            enabled, is_default FROM scan_profiles WHERE service_client_id = ? ''' +
            ('AND id > ? ' if after is not None else '') + 'ORDER BY id LIMIT 21',
            (client_id, *((after,) if after is not None else ()))).fetchall()
        items = []
        for row in rows[:20]:
            assigned = connection.execute('SELECT engine_instance_id FROM scan_profile_engines WHERE scan_profile_id = ? ORDER BY engine_instance_id LIMIT 101', (row['id'],)).fetchall()
            values = dict(row)
            values['incomplete'] = bool(values['incomplete']) or len(assigned) > 100
            items.append(ProfileSummary(**values, engine_ids=[item['engine_instance_id'] for item in assigned[:100]]))
    return ClientProfiles(client_id=client_id, managed=client['managed'], items=items,
        engines=[ProfileEngineChoice(**dict(row)) for row in choices[:100]], engines_incomplete=len(choices) > 100,
        next_after=rows[19]['id'] if len(rows) > 20 else None)


def save(client_id: int, profile_id: int, body: ProfileRoutingBody):
    if len(set(body.engine_ids)) != len(body.engine_ids) or len(set(body.expected_engine_ids)) != len(body.expected_engine_ids):
        raise HTTPException(422, 'Engine IDs must be unique.')
    try:
        db.set_scan_profile_engines(profile_id, body.engine_ids, client_id=client_id,
            expected_engine_ids=body.expected_engine_ids, lock_timeout_ms=write_lock_timeout_ms())
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
