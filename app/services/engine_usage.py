"""Bounded current profile references to an engine instance, without scan history."""
import time

from fastapi import HTTPException
from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget

PAGE_SIZE = 20


class EngineProfileReference(BaseModel):
    profile_id: int
    profile_name: str
    profile_enabled: bool
    is_default: bool
    client_id: int
    client_name: str
    client_enabled: bool
    names_truncated: bool


class EngineUsage(BaseModel):
    engine_id: int
    engine_name: str
    profiles: list[EngineProfileReference]
    next_after: int | None
    observed_at: int


def read(instance_id: int, after: int | None = None) -> EngineUsage:
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        engine = connection.execute('SELECT id, SUBSTR(display_name, 1, 128) AS name FROM engine_instances WHERE id = ?', (instance_id,)).fetchone()
        if engine is None:
            raise HTTPException(404, 'Engine instance not found.')
        rows = connection.execute('''SELECT p.id AS profile_id, SUBSTR(p.name, 1, 100) AS profile_name,
            p.enabled AS profile_enabled, p.is_default, c.id AS client_id,
            SUBSTR(c.display_name, 1, 100) AS client_name, c.enabled AS client_enabled,
            (LENGTH(p.name) > 100 OR LENGTH(c.display_name) > 100) AS names_truncated
            FROM scan_profile_engines pe JOIN scan_profiles p ON p.id = pe.scan_profile_id
            JOIN service_clients c ON c.id = p.service_client_id
            WHERE pe.engine_instance_id = ? AND pe.scan_profile_id > ? AND p.deleted_at IS NULL
            ORDER BY pe.scan_profile_id LIMIT ?''', (instance_id, after or 0, PAGE_SIZE + 1)).fetchall()
        items = [EngineProfileReference(**dict(row)) for row in rows[:PAGE_SIZE]]
    return EngineUsage(engine_id=instance_id, engine_name=engine['name'], profiles=items,
        next_after=items[-1].profile_id if len(rows) > PAGE_SIZE else None, observed_at=int(time.time()))
