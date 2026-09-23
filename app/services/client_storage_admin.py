"""Admin metadata and fenced replacement of client storage access. No filesystem I/O."""
import hashlib
import json
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app import database as db
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms
from app.services.client_storage_policy import (
    StorageGrant, MAX_POLICY_CHARS, MAX_BACKENDS, normalize_grants, parse_grants, serialize_grants,
)
from app.services.deferred_storage import DeferredSourceError, configured_backend_keys, _configured_client_scopes


class ClientStorageAccess(BaseModel):
    client_id: int
    managed: bool
    mode: Literal['environment', 'custom']
    revision: int
    environment_fingerprint: str
    backends: list[str]
    grants: list[StorageGrant]
    environment_grants: list[StorageGrant]


class StorageAccessUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    expected_revision: int = Field(ge=0, le=9007199254740991)
    expected_environment_fingerprint: str = Field(pattern=r'^[0-9a-f]{64}$')
    mode: Literal['environment', 'custom']
    grants: list[StorageGrant] = Field(max_length=MAX_BACKENDS)


def environment_view(client_key: str) -> tuple[list[str], list[StorageGrant], str]:
    try:
        backends = sorted(configured_backend_keys())
        if len(backends) > MAX_BACKENDS or any(not key or len(key) > 128 for key in backends):
            raise HTTPException(413, 'Backend inventory exceeds the console limit; editing is unavailable.')
        grants = []
        for key, clients in _configured_client_scopes().items():
            if isinstance(clients, list):
                if client_key in {str(value).strip().lower() for value in clients}:
                    grants.append(StorageGrant(backend_key=key, access='all'))
            elif isinstance(clients, dict):
                prefixes = clients.get(client_key)
                if prefixes is None:
                    continue
                if isinstance(prefixes, str):
                    prefixes = [prefixes]
                if not isinstance(prefixes, list):
                    raise ValueError('Invalid prefixes')
                # Legacy empty arrays authorize no object; never turn them into
                # whole-backend access when bringing settings into the console.
                if prefixes:
                    grants.append(StorageGrant(backend_key=key, access='prefixes', prefixes=prefixes))
            elif clients is not None:
                raise ValueError('Invalid backend mapping')
        grants = normalize_grants(grants)
        serialized = serialize_grants(grants)
    except (DeferredSourceError, ValueError, TypeError) as exc:
        raise HTTPException(503, 'Deployment storage configuration is invalid or exceeds console limits. Correct it before editing access.') from exc
    fingerprint = hashlib.sha256(json.dumps([backends, serialized], separators=(',', ':')).encode()).hexdigest()
    return backends, grants, fingerprint


def read(client_id: int) -> ClientStorageAccess:
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        row = connection.execute('''SELECT c.id, SUBSTR(c.client_key, 1, 129) AS client_key,
            p.mode, p.revision, SUBSTR(p.grants_json, 1, ?) AS grants_json
            FROM service_clients c LEFT JOIN service_client_storage_policies p ON p.service_client_id = c.id
            WHERE c.id = ?''', (MAX_POLICY_CHARS + 1, client_id)).fetchone()
    if row is None:
        raise HTTPException(404, 'Service client not found.')
    if len(row['client_key']) > 128:
        raise HTTPException(413, 'Client key exceeds the console limit; editing is unavailable.')
    backends, environment, fingerprint = environment_view(row['client_key'])
    mode = row['mode'] or 'environment'
    if mode not in {'environment', 'custom'}:
        raise HTTPException(503, 'Stored client storage mode is invalid.')
    try:
        grants = environment if mode == 'environment' else parse_grants(row['grants_json'])
    except DeferredSourceError as exc:
        raise HTTPException(503, str(exc)) from exc
    return ClientStorageAccess(client_id=client_id, managed=row['client_key'] == 'legacy-default',
        mode=mode, revision=row['revision'] or 0, backends=backends, grants=grants,
        environment_grants=environment, environment_fingerprint=fingerprint)


def save(client_id: int, body: StorageAccessUpdate) -> None:
    try:
        if body.mode == 'environment' and body.grants:
            raise ValueError('Environment mode must not include custom grants.')
        grants = normalize_grants(body.grants)
        serialized = serialize_grants(grants)
    except (ValueError, DeferredSourceError) as exc:
        raise HTTPException(422, str(exc)) from exc
    with db.connect() as connection:
        if db.using_postgres():
            connection.execute("SELECT set_config('lock_timeout', ?, true)", (f'{write_lock_timeout_ms()}ms',))
        else:
            connection.execute('BEGIN IMMEDIATE')
        client = connection.execute('SELECT client_key FROM service_clients WHERE id = ?' +
            (' FOR UPDATE' if db.using_postgres() else ''), (client_id,)).fetchone()
        if client is None:
            raise HTTPException(404, 'Service client not found.')
        if client['client_key'] == 'legacy-default':
            raise HTTPException(409, 'Compatibility client storage access is deployment-managed.')
        backends, _environment, fingerprint = environment_view(client['client_key'])
        current = connection.execute('SELECT revision FROM service_client_storage_policies WHERE service_client_id = ?', (client_id,)).fetchone()
        revision = 0 if current is None else current['revision']
        if revision != body.expected_revision or fingerprint != body.expected_environment_fingerprint:
            raise HTTPException(409, 'Storage access or deployment configuration changed. Refresh before saving.')
        if any(grant.backend_key not in backends for grant in grants):
            raise HTTPException(422, 'Select only backends configured on this deployment.')
        # Keep a revision row when returning to inheritance to prevent ABA writes.
        connection.execute('''INSERT INTO service_client_storage_policies (service_client_id, mode, grants_json, revision)
            VALUES (?, ?, ?, ?) ON CONFLICT(service_client_id) DO UPDATE SET
            mode = excluded.mode, grants_json = excluded.grants_json, revision = excluded.revision''',
            (client_id, body.mode, serialized, revision + 1))
