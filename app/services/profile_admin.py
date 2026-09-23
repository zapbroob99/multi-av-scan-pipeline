"""Client-scoped routing without profile policies or engine configuration."""
from typing import Annotated
import time
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app import database as db
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms

SafeId = Annotated[int, Field(ge=1, le=9007199254740991)]


class ProfileRoutingBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    engine_ids: list[SafeId] = Field(min_length=1, max_length=100)
    expected_engine_ids: list[SafeId] = Field(max_length=100)
    expected_revision: int | None = Field(default=None, ge=0, le=9007199254740991)


class ProfileCreateBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    name: str = Field(min_length=1, max_length=100)
    engine_ids: list[SafeId] = Field(min_length=1, max_length=100)


class ProfileCreated(BaseModel):
    profile_id: int


class ProfileFence(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    expected_revision: int = Field(ge=0, le=9007199254740991)


class ProfileUpdateBody(ProfileFence):
    name: str = Field(min_length=1, max_length=100)
    enabled: bool


class ProfileDefaultBody(ProfileFence):
    expected_default_profile_id: SafeId | None


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
    management_revision: int


class ClientProfiles(BaseModel):
    client_id: int
    managed: bool
    items: list[ProfileSummary]
    engines: list[ProfileEngineChoice]
    engines_incomplete: bool
    next_after: int | None
    default_profile_id: int | None


def page(client_id: int, after: int | None) -> ClientProfiles:
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        client = connection.execute("SELECT client_key = 'legacy-default' AS managed FROM service_clients WHERE id = ?", (client_id,)).fetchone()
        if client is None:
            raise HTTPException(404, 'Service client not found.')
        default = connection.execute('SELECT id FROM scan_profiles WHERE service_client_id = ? AND is_default = ? AND deleted_at IS NULL LIMIT 1',
            (client_id, db.db_bool(True))).fetchone()
        choices = connection.execute('''SELECT id, SUBSTR(display_name, 1, 128) AS display_name,
            SUBSTR(adapter_key, 1, 64) AS adapter_key, enabled FROM engine_instances ORDER BY id LIMIT 101''').fetchall()
        rows = connection.execute('''SELECT id, SUBSTR(name, 1, 100) AS name, LENGTH(name) > 100 AS incomplete,
            enabled, is_default, management_revision FROM scan_profiles WHERE service_client_id = ? AND deleted_at IS NULL ''' +
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
        next_after=rows[19]['id'] if len(rows) > 20 else None,
        default_profile_id=None if default is None else default['id'])


def save(client_id: int, profile_id: int, body: ProfileRoutingBody):
    if len(set(body.engine_ids)) != len(body.engine_ids) or len(set(body.expected_engine_ids)) != len(body.expected_engine_ids):
        raise HTTPException(422, 'Engine IDs must be unique.')
    try:
        db.set_scan_profile_engines(profile_id, body.engine_ids, client_id=client_id,
            expected_engine_ids=body.expected_engine_ids, expected_revision=body.expected_revision,
            lock_timeout_ms=write_lock_timeout_ms())
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


def create(client_id: int, body: ProfileCreateBody) -> ProfileCreated:
    name = body.name.strip()
    if not name or len(set(body.engine_ids)) != len(body.engine_ids):
        raise HTTPException(422, 'Supply a nonblank profile name and unique engine IDs.')
    try:
        profile_id = db.create_scan_profile(client_id, name, engine_instance_ids=body.engine_ids,
            managed_guard=True, lock_timeout_ms=write_lock_timeout_ms())
    except db.IntegrityViolation as exc:
        raise HTTPException(409, 'That profile name is already reserved for this client, including deleted profiles.') from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return ProfileCreated(profile_id=profile_id)


def manage(client_id: int, profile_id: int, body: ProfileFence, operation: str) -> None:
    try:
        with db.profile_write_transaction(client_id, write_lock_timeout_ms()) as (connection, client):
            if client['client_key'] == 'legacy-default':
                raise ValueError('Profiles for the compatibility client are deployment-managed.')
            profile = connection.execute('''SELECT id, enabled, is_default, management_revision FROM scan_profiles
                WHERE id = ? AND service_client_id = ? AND deleted_at IS NULL''' +
                (' FOR UPDATE' if db.using_postgres() else ''), (profile_id, client_id)).fetchone()
            if profile is None or profile['management_revision'] != body.expected_revision:
                raise ValueError('Profile is missing or changed. Refresh before continuing.')
            if operation == 'update' and isinstance(body, ProfileUpdateBody):
                name = body.name.strip()
                if not name:
                    raise HTTPException(422, 'Profile name must not be blank.')
                if profile['is_default'] and not body.enabled:
                    raise ValueError('Select another default profile before disabling this one.')
                connection.execute('''UPDATE scan_profiles SET name = ?, enabled = ?,
                    management_revision = management_revision + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?''',
                    (name, db.db_bool(body.enabled), profile_id))
            elif operation == 'default' and isinstance(body, ProfileDefaultBody):
                current = connection.execute('''SELECT id FROM scan_profiles WHERE service_client_id = ?
                    AND is_default = ? AND deleted_at IS NULL''', (client_id, db.db_bool(True))).fetchone()
                if (None if current is None else current['id']) != body.expected_default_profile_id:
                    raise ValueError('Default profile changed. Refresh before continuing.')
                assigned = connection.execute('SELECT 1 FROM scan_profile_engines WHERE scan_profile_id = ? LIMIT 1', (profile_id,)).fetchone()
                if not profile['enabled'] or assigned is None:
                    raise ValueError('The default profile must be enabled and have assigned engines.')
                connection.execute('''UPDATE scan_profiles SET is_default = ?, management_revision = management_revision + 1,
                    updated_at = CURRENT_TIMESTAMP WHERE service_client_id = ? AND is_default = ?''',
                    (db.db_bool(False), client_id, db.db_bool(True)))
                connection.execute('''UPDATE scan_profiles SET is_default = ?, management_revision = management_revision + 1,
                    updated_at = CURRENT_TIMESTAMP WHERE id = ?''', (db.db_bool(True), profile_id))
            elif operation == 'delete':
                if profile['is_default']:
                    raise ValueError('Select another default profile before deleting this one.')
                # Retain the identity and engine rows: deferred submissions have a
                # cascading FK and old reports may still refer to the profile.
                connection.execute('''UPDATE scan_profiles SET deleted_at = ?, enabled = ?,
                    management_revision = management_revision + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?''',
                    (int(time.time()), db.db_bool(False), profile_id))
            else:
                raise ValueError('Unsupported profile operation.')
    except db.IntegrityViolation as exc:
        raise HTTPException(409, 'That profile name is already reserved for this client, including deleted profiles.') from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
