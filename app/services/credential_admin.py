"""Admin credential workflows: accept secrets, never return them."""
import re
import time
from typing import Annotated
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from app import database as db
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms
from app.services.service_clients import hash_api_token
from app.services.profile_admin import ProfileEngineChoice


def validated_api_token(raw: str) -> str:
    token = raw.strip()
    if len(token) < 32 or len(token) > 512 or any(character.isspace() for character in token):
        raise ValueError('API tokens must contain 32 to 512 non-whitespace characters.')
    return token


class CredentialBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    credential_label: str = Field(min_length=1, max_length=100)
    api_token: SecretStr


class ClientCreateBody(CredentialBody):
    client_key: str = Field(min_length=2, max_length=64)
    display_name: str = Field(min_length=1, max_length=100)
    profile_name: str = Field(min_length=1, max_length=100)
    engine_ids: list[Annotated[int, Field(ge=1, le=9007199254740991)]] = Field(min_length=1, max_length=100)


class ClientCreated(BaseModel):
    client_id: int
    profile_id: int
    credential_id: int


class CredentialCreated(BaseModel):
    credential_id: int


class CredentialSummary(BaseModel):
    id: int
    label: str
    created_at: str
    last_used_at: int | None
    revoked_at: int | None


class CredentialPage(BaseModel):
    items: list[CredentialSummary]
    next_after: int | None


class ClientCreateOptions(BaseModel):
    engines: list[ProfileEngineChoice]
    incomplete: bool


def options() -> ClientCreateOptions:
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute('''SELECT id, SUBSTR(display_name, 1, 128) AS display_name,
            SUBSTR(adapter_key, 1, 64) AS adapter_key, enabled FROM engine_instances ORDER BY id LIMIT 101''').fetchall()
    return ClientCreateOptions(engines=[ProfileEngineChoice(**dict(row)) for row in rows[:100]], incomplete=len(rows) > 100)


def clean_secret(body: CredentialBody):
    label = body.credential_label.strip()
    if not label:
        raise HTTPException(422, 'Credential label must not be blank.')
    token = validated_api_token(body.api_token.get_secret_value())
    return label, hash_api_token(token), token[:8]


def create_client(body: ClientCreateBody) -> ClientCreated:
    key = body.client_key.strip().lower()
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{1,63}', key) or key == 'legacy-default':
        raise HTTPException(422, 'Use a unique 2-64 character client key; legacy-default is reserved.')
    name, profile = body.display_name.strip(), body.profile_name.strip()
    if not name or not profile or len(set(body.engine_ids)) != len(body.engine_ids):
        raise HTTPException(422, 'Names must be nonblank and engine IDs unique.')
    label, token_hash, prefix = clean_secret(body)
    try:
        client_id, profile_id, credential_id = db.create_service_client_bundle(client_key=key, display_name=name,
            profile_name=profile, engine_instance_ids=body.engine_ids, credential_label=label,
            token_hash=token_hash, token_prefix=prefix)
    except db.IntegrityViolation as exc:
        raise HTTPException(409, 'Client key or API token is already registered.') from exc
    return ClientCreated(client_id=client_id, profile_id=profile_id, credential_id=credential_id)


def create_credential(client_id: int, body: CredentialBody) -> CredentialCreated:
    if db.get_service_client(client_id) is None:
        raise HTTPException(404, 'Service client not found.')
    label, token_hash, prefix = clean_secret(body)
    try:
        credential_id = db.create_api_client_credential(client_id, label=label, token_hash=token_hash, token_prefix=prefix)
    except db.IntegrityViolation as exc:
        raise HTTPException(409, 'Client changed or API token is already registered.') from exc
    return CredentialCreated(credential_id=credential_id)


def page(client_id: int, after: int | None) -> CredentialPage:
    with db.connect() as connection:
        apply_read_budget(connection)
        if connection.execute('SELECT id FROM service_clients WHERE id = ?', (client_id,)).fetchone() is None:
            raise HTTPException(404, 'Service client not found.')
        rows = connection.execute('''SELECT id, SUBSTR(label, 1, 128) AS label, created_at, last_used_at, revoked_at
            FROM api_client_credentials WHERE service_client_id = ? ''' + ('AND id > ? ' if after is not None else '') +
            'ORDER BY id LIMIT 21', (client_id, *((after,) if after is not None else ()))).fetchall()
    return CredentialPage(items=[CredentialSummary(**{**dict(row), 'created_at': str(row['created_at'])}) for row in rows[:20]],
        next_after=rows[19]['id'] if len(rows) > 20 else None)


def revoke(client_id: int, credential_id: int):
    with db.connect() as connection:
        apply_read_budget(connection)
        if db.using_postgres():
            connection.execute("SELECT set_config('lock_timeout', ?, true)", (f'{write_lock_timeout_ms()}ms',))
        result = connection.execute('''UPDATE api_client_credentials SET revoked_at = ?
            WHERE id = ? AND service_client_id = ? AND revoked_at IS NULL''', (int(time.time()), credential_id, client_id))
        if not result.rowcount:
            raise HTTPException(409, 'Active credential not found for this client. Refresh before continuing.')
