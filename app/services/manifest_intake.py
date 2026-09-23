"""Read upload manifests a storage producer drops beside each finished file.

The producer writes the object, then writes a sibling manifest last. The
manifest appearing is therefore the completion signal: MASP never has to guess
whether an upload is still being written.

Nothing here writes to the source. The mount stays read-only, and the manifest
is never deleted or moved; re-reading one is harmless because the deferred
submission table is unique on (service_client_id, client_request_id).

A manifest names what to scan. It never grants access: the object must still
resolve inside the client's approved backend prefix, and it must sit in the
manifest's own directory so a stray manifest cannot reach across the share.
"""
from datetime import date, timedelta
import json
import os
from pathlib import Path
import time

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app import database as db
from app.services.deferred_storage import (
    DeferredSourceError,
    DeferredSourcePermanentError,
    backend_allowed_for_client,
    configured_backends,
    redact_paths,
    resolve_source_path,
    validate_object_id,
)
from app.services.service_clients import (
    identity_for_service_client_key,
    profile_snapshot_json,
    resolve_profile_routing,
)

MANIFEST_SUFFIX = '.json'
MAX_MANIFEST_BYTES = 64 * 1024
DEFAULT_LOOKBACK_DAYS = 3
MAX_LOOKBACK_DAYS = 90
DEFAULT_BATCH = 200
MAX_BATCH = 2000
DEFAULT_DATE_LAYOUT = '%Y/%m/%d'
# The API process does not share the worker's environment, so the worker
# records what it actually ran with; the console reads only this row.
LAST_CYCLE_SETTING = 'manifest_intake_last_cycle'


class ManifestConfigError(RuntimeError):
    """The deployment has not finished configuring manifest intake."""


class UploadManifest(BaseModel):
    # Tolerate unknown keys: the producer owns this format and may add fields
    # without coordinating a MASP release. Only the fields below are read.
    model_config = ConfigDict(extra='ignore')

    upload_id: str = Field(min_length=1, max_length=128)
    original_filename: str = Field(min_length=1, max_length=255)
    object_id: str | None = Field(default=None, max_length=1024)
    sha256: str | None = Field(default=None, min_length=64, max_length=64)
    size_bytes: int | None = Field(default=None, ge=0)
    uploaded_at: str | None = Field(default=None, max_length=64)
    user_id: str | None = Field(default=None, max_length=128)
    user_display: str | None = Field(default=None, max_length=256)
    tenant_id: str | None = Field(default=None, max_length=128)
    content_type: str | None = Field(default=None, max_length=255)


def _bounded_int(name: str, default: int, low: int, high: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(low, min(value, high))


def backend_key() -> str:
    return os.getenv('MASP_MANIFEST_BACKEND_KEY', '').strip().lower()


def client_key() -> str:
    return os.getenv('MASP_MANIFEST_CLIENT_KEY', '').strip().lower()


def root_prefix() -> str:
    return os.getenv('MASP_MANIFEST_ROOT_PREFIX', '').strip().strip('/')


def date_layout() -> str:
    # Empty means the producer does not partition by date; scan the prefix
    # itself instead of a dated subtree.
    return os.getenv('MASP_MANIFEST_DATE_LAYOUT', DEFAULT_DATE_LAYOUT).strip().strip('/')


def lookback_days() -> int:
    return _bounded_int('MASP_MANIFEST_LOOKBACK_DAYS', DEFAULT_LOOKBACK_DAYS, 1, MAX_LOOKBACK_DAYS)


def batch_limit() -> int:
    return _bounded_int('MASP_MANIFEST_BATCH', DEFAULT_BATCH, 1, MAX_BATCH)


def require_configuration() -> tuple[str, str]:
    backend, client = backend_key(), client_key()
    if not backend or not client:
        raise ManifestConfigError(
            'Set MASP_MANIFEST_BACKEND_KEY and MASP_MANIFEST_CLIENT_KEY before starting manifest intake.')
    if backend not in configured_backends():
        raise ManifestConfigError(f'Manifest backend {backend!r} is not a configured storage backend.')
    return backend, client


def candidate_directories(today: date | None = None) -> list[str]:
    """Bounded scan surface: the prefix, or its recent dated partitions.

    A full recursive walk of a share that only grows is not a backstop, it is
    the most expensive part of the system. Scanning a fixed number of recent
    partitions keeps each cycle predictable; a manifest that lands late is
    still picked up while its partition is in range, and re-reading it later
    is free because submission creation is idempotent.
    """
    prefix, layout = root_prefix(), date_layout()
    if not layout:
        return [prefix]
    current = today or date.today()
    return [f'{prefix}/{(current - timedelta(days=offset)).strftime(layout)}'.strip('/')
            for offset in range(lookback_days())]


def discover(backend: str, directories: list[str], limit: int) -> list[str]:
    """Return relative manifest object ids, oldest name first, bounded."""
    root = configured_backends().get(backend)
    if root is None:
        raise ManifestConfigError(f'Manifest backend {backend!r} is not a configured storage backend.')
    found: list[str] = []
    for relative in directories:
        directory = root / relative if relative else root
        try:
            entries = sorted(entry.name for entry in os.scandir(directory)
                             if entry.is_file(follow_symlinks=False) and entry.name.endswith(MANIFEST_SUFFIX))
        except (OSError, ValueError):
            # A partition that does not exist yet is normal, not an error.
            continue
        for name in entries:
            found.append(f'{relative}/{name}'.strip('/') if relative else name)
            if len(found) >= limit:
                return found
    return found


def _resolve_object(manifest_object_id: str, manifest: UploadManifest, directory_files: set[str]) -> str:
    parent = manifest_object_id.rsplit('/', 1)[0] if '/' in manifest_object_id else ''
    if manifest.object_id:
        candidate = validate_object_id(manifest.object_id)
        candidate_parent = candidate.rsplit('/', 1)[0] if '/' in candidate else ''
        if candidate_parent != parent:
            # Defence in depth behind the prefix grant: a manifest may only
            # point at an object beside itself.
            raise DeferredSourcePermanentError(
                'Manifest object_id must name a file in the same directory as the manifest.')
        return candidate
    stem = manifest_object_id.rsplit('/', 1)[-1][: -len(MANIFEST_SUFFIX)]
    siblings = sorted(name for name in directory_files
                      if name != stem + MANIFEST_SUFFIX and name.rsplit('.', 1)[0] == stem)
    if len(siblings) != 1:
        raise DeferredSourcePermanentError(
            'Manifest has no object_id and its directory does not contain exactly one matching object.')
    return f'{parent}/{siblings[0]}'.strip('/') if parent else siblings[0]


def read_manifest(backend: str, manifest_object_id: str) -> UploadManifest:
    path = resolve_source_path(backend, manifest_object_id)
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise DeferredSourcePermanentError(
                f'Manifest exceeds the {MAX_MANIFEST_BYTES} byte limit.')
        raw = path.read_bytes()
    except OSError as exc:
        raise DeferredSourceError(
            f'Manifest is unavailable ({exc.strerror or type(exc).__name__}).') from exc
    try:
        payload = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeferredSourcePermanentError(f'Manifest is not valid UTF-8 JSON: {exc}') from exc
    if not isinstance(payload, dict):
        raise DeferredSourcePermanentError('Manifest must be a JSON object.')
    try:
        return UploadManifest.model_validate(payload)
    except ValidationError as exc:
        raise DeferredSourcePermanentError(f'Manifest fields are invalid: {exc.error_count()} problem(s).') from exc


def _note(manifest: UploadManifest) -> str:
    parts = [f'{key}={value}' for key, value in (
        ('upload_id', manifest.upload_id), ('user_id', manifest.user_id),
        ('tenant_id', manifest.tenant_id), ('uploaded_at', manifest.uploaded_at),
        ('user_display', manifest.user_display),
    ) if value]
    return '; '.join(parts)[:2000]


def submit(backend: str, client: str, manifest_object_id: str,
           directory_files: set[str]) -> tuple[int, bool]:
    """Accept one manifest as a deferred submission. Returns (id, created)."""
    manifest = read_manifest(backend, manifest_object_id)
    object_id = _resolve_object(manifest_object_id, manifest, directory_files)
    if not backend_allowed_for_client(backend, client, object_id):
        raise DeferredSourcePermanentError(
            'Manifest names an object outside this client approved storage scope.')
    # Confirm the object exists and passes the same traversal/link checks the
    # copying worker will repeat before it reads anything.
    resolve_source_path(backend, object_id)
    identity = identity_for_service_client_key(client)
    identity, engines = resolve_profile_routing(identity, source='api')
    if not engines:
        raise DeferredSourceError('No eligible engines are assigned to this client scan profile.')
    snapshot = profile_snapshot_json(identity, engines, delivery_mode='security_events_only',
                                     client_request_id=manifest.upload_id)
    record, created = db.create_deferred_scan_submission(
        service_client_id=identity.client.id,
        scan_profile_id=identity.profile.id,
        client_request_id=manifest.upload_id,
        backend_key=backend,
        object_id=object_id,
        original_filename=manifest.original_filename,
        content_type=(manifest.content_type or 'application/octet-stream'),
        expected_size_bytes=manifest.size_bytes,
        expected_sha256=(manifest.sha256.lower() if manifest.sha256 else None),
        archive_mode='lazy_extract_on_detection',
        case_name='Storage upload',
        priority='Normal',
        note=_note(manifest),
        profile_snapshot_json=snapshot,
    )
    return record.id, created


def process_cycle(now: date | None = None) -> tuple[int, int, int]:
    """Read one bounded batch. Returns (accepted, duplicates, rejected)."""
    backend, client = require_configuration()
    root = configured_backends()[backend]
    manifests = discover(backend, candidate_directories(now), batch_limit())
    listings: dict[str, set[str]] = {}
    accepted = duplicates = rejected = 0
    for manifest_object_id in manifests:
        parent = manifest_object_id.rsplit('/', 1)[0] if '/' in manifest_object_id else ''
        if parent not in listings:
            try:
                listings[parent] = {entry.name for entry in os.scandir(root / parent if parent else root)
                                    if entry.is_file(follow_symlinks=False)}
            except OSError:
                listings[parent] = set()
        try:
            _submission_id, created = submit(backend, client, manifest_object_id, listings[parent])
        except Exception as exc:  # noqa: BLE001 - one bad manifest must not stop the batch
            rejected += 1
            db.record_manifest_rejection(backend, manifest_object_id, redact_paths(str(exc))[:1000])
            continue
        db.clear_manifest_rejection(backend, manifest_object_id)
        accepted += created
        duplicates += 0 if created else 1
    return accepted, duplicates, rejected


def record_cycle(*, ok: bool, poll_seconds: float, accepted: int = 0, duplicates: int = 0,
                 rejected: int = 0, error: str | None = None) -> None:
    """Record the latest cycle so a stopped or failing worker is visible.

    The producer never learns whether MASP is reading its share, so without
    this a dead worker looks exactly like a quiet one. Recording is best
    effort: visibility must never stop intake.
    """
    payload = {
        'at': int(time.time()), 'ok': ok, 'poll_seconds': poll_seconds,
        'accepted': accepted, 'duplicates': duplicates, 'rejected': rejected,
        'error': redact_paths(error)[:1000] if error else None,
        'backend_key': backend_key() or None, 'client_key': client_key() or None,
        'root_prefix': root_prefix(), 'date_layout': date_layout(),
        'lookback_days': lookback_days(), 'batch_limit': batch_limit(),
    }
    try:
        db.set_setting(LAST_CYCLE_SETTING, json.dumps(payload, sort_keys=True))
    except Exception:  # noqa: BLE001 - see docstring
        pass
