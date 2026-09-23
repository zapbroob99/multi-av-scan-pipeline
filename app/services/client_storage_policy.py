"""Bounded client storage grants shared by HTTP admission and deferred workers.

Deployment owns backend roots. A persisted custom policy replaces (never unions
with) environment grants. An empty custom policy denies all backend access.
"""
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app import database as db
from app.services.deferred_storage import DeferredSourceError, _normalize_prefix

MAX_POLICY_CHARS = 65536
MAX_BACKENDS = 50


class StorageGrant(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    backend_key: str = Field(min_length=1, max_length=128)
    access: Literal['all', 'prefixes']
    prefixes: list[Annotated[str, Field(min_length=1, max_length=512)]] = Field(default_factory=list, max_length=32)


def normalize_grants(grants: list[StorageGrant]) -> list[StorageGrant]:
    if len(grants) > MAX_BACKENDS:
        raise ValueError('Storage access supports at most 50 backend grants.')
    normalized = []
    seen = set()
    for grant in grants:
        key = grant.backend_key.strip().lower()
        if not key or key in seen or any(ord(char) < 32 for char in key):
            raise ValueError('Backend keys must be nonblank and unique.')
        seen.add(key)
        if grant.access == 'all':
            if grant.prefixes:
                raise ValueError('Whole-backend access cannot include prefixes.')
            prefixes = []
        else:
            if not grant.prefixes:
                raise ValueError('Prefix access requires at least one relative prefix.')
            prefixes = sorted({_normalize_prefix(prefix) for prefix in grant.prefixes})
            if any(prefix == '/' or len(prefix) > 512 for prefix in prefixes):
                raise ValueError('Prefixes must identify a relative object or folder within the backend.')
        normalized.append(StorageGrant(backend_key=key, access=grant.access, prefixes=prefixes))
    return sorted(normalized, key=lambda grant: grant.backend_key)


def serialize_grants(grants: list[StorageGrant]) -> str:
    value = json.dumps([grant.model_dump() for grant in grants], separators=(',', ':'), sort_keys=True)
    if len(value) > MAX_POLICY_CHARS:
        raise ValueError('Storage access exceeds the 64 KiB policy limit.')
    return value


def parse_grants(raw: str) -> list[StorageGrant]:
    try:
        if len(raw) > MAX_POLICY_CHARS:
            raise ValueError('Oversized policy')
        value = json.loads(raw)
        if not isinstance(value, list) or len(value) > MAX_BACKENDS:
            raise ValueError('Invalid policy')
        return normalize_grants([StorageGrant.model_validate(grant) for grant in value])
    except (ValueError, TypeError, ValidationError, DeferredSourceError) as exc:
        raise DeferredSourceError('Stored client storage policy is invalid; access is unavailable.') from exc


def custom_grants_for_client(client_key: str) -> list[StorageGrant] | None:
    """None inherits the environment; [] is an explicit deny-all override.

    Do not cache or swallow database failures: admission and workers must see
    revocations, and failure must never restore a broader environment grant.
    """
    try:
        with db.connect() as connection:
            row = connection.execute('''SELECT p.mode, SUBSTR(p.grants_json, 1, ?) AS grants_json
                FROM service_client_storage_policies p JOIN service_clients c ON c.id = p.service_client_id
                WHERE c.client_key = ?''', (MAX_POLICY_CHARS + 1, client_key)).fetchone()
    except db.DatabaseOperationalError as exc:
        raise DeferredSourceError('Client storage authorization is unavailable.') from exc
    if row is None or row['mode'] == 'environment':
        return None
    if row['mode'] != 'custom':
        raise DeferredSourceError('Stored client storage mode is invalid; access is unavailable.')
    return parse_grants(row['grants_json'])
