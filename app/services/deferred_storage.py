from __future__ import annotations

import hashlib
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid

from app.models import DeferredScanRecord, StoredSample
from app.services.ingest import SAMPLES_DIR, sanitize_filename


class DeferredSourceError(RuntimeError):
    pass


class DeferredSourcePermanentError(DeferredSourceError):
    pass


class DeferredSourceChangedError(DeferredSourcePermanentError):
    pass


class DeferredSourcePolicyError(DeferredSourcePermanentError):
    pass


# OSError renders the path it failed on as a quoted absolute path. Deployment
# roots are never shown to operators, so errors are stored and shown without them.
_QUOTED_ABSOLUTE_PATH = re.compile(r"""(['"])(?:[A-Za-z]:[\\/]|[\\/])[^'"]*\1""")


def redact_paths(text: str) -> str:
    """Replace absolute filesystem paths in an error message with a placeholder."""
    return _QUOTED_ABSOLUTE_PATH.sub(r"\1<path>\1", text)


def configured_backends() -> dict[str, Path]:
    """Return deployment-approved filesystem roots, never request-provided paths."""
    raw_json = os.getenv("MASP_DEFERRED_STORAGE_BACKENDS_JSON", "").strip()
    values: dict[str, object] = {}
    if raw_json:
        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise DeferredSourceError(
                "MASP_DEFERRED_STORAGE_BACKENDS_JSON is not valid JSON."
            ) from exc
        if not isinstance(parsed, dict):
            raise DeferredSourceError(
                "MASP_DEFERRED_STORAGE_BACKENDS_JSON must be an object."
            )
        values = parsed
    else:
        key = os.getenv("MASP_DEFERRED_FILESYSTEM_BACKEND_KEY", "").strip()
        root = os.getenv("MASP_DEFERRED_FILESYSTEM_ROOT", "").strip()
        if key and root:
            values = {key: root}

    backends: dict[str, Path] = {}
    for key, root in values.items():
        normalized_key = str(key).strip().lower()
        path = Path(str(root)).expanduser()
        if not normalized_key or not path.is_absolute():
            raise DeferredSourceError(
                "Deferred backend keys must be non-empty and roots must be absolute."
            )
        backends[normalized_key] = path
    return backends


def configured_backend_keys() -> set[str]:
    return set(configured_backends())


def _configured_client_scopes() -> dict[str, object]:
    raw_json = os.getenv("MASP_DEFERRED_BACKEND_CLIENTS_JSON", "").strip()
    if not raw_json:
        return {}
    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise DeferredSourceError(
            "MASP_DEFERRED_BACKEND_CLIENTS_JSON is not valid JSON."
        ) from exc
    if not isinstance(parsed, dict):
        raise DeferredSourceError("MASP_DEFERRED_BACKEND_CLIENTS_JSON must be an object.")
    return {str(key).strip().lower(): value for key, value in parsed.items()}


def _normalize_prefix(prefix: object) -> str:
    normalized = validate_object_id(str(prefix))
    return normalized.rstrip("/") + "/"


def _object_matches_prefix(object_id: str, prefix: str) -> bool:
    normalized = validate_object_id(object_id)
    bare_prefix = prefix.rstrip("/")
    return normalized == bare_prefix or normalized.startswith(prefix)


def backend_allowed_for_client(
    backend_key: str, client_key: str, object_id: str | None = None
) -> bool:
    """Enforce tenant-to-storage routing without accepting paths from callers.

    Custom database grants replace the environment policy for this client.
    Otherwise MASP_DEFERRED_BACKEND_CLIENTS_JSON is the compatibility source.
    Neither source can introduce a backend root absent from deployment config.
    """
    normalized_backend = backend_key.strip().lower()
    normalized_client = client_key.strip().lower()
    backends = configured_backend_keys()
    if normalized_backend not in backends:
        return False
    # Imported lazily to keep the shared policy validator dependent on this
    # module's existing relative-prefix normalization, without an import cycle.
    from app.services.client_storage_policy import custom_grants_for_client
    grants = custom_grants_for_client(normalized_client)
    if grants is not None:
        grant = next((item for item in grants if item.backend_key == normalized_backend), None)
        if grant is None:
            return False
        if grant.access == 'all':
            return True
        return bool(grant.prefixes) if object_id is None else any(
            _object_matches_prefix(object_id, prefix) for prefix in grant.prefixes)
    scopes = _configured_client_scopes()
    raw_clients = scopes.get(normalized_backend)
    if raw_clients is None:
        return False
    if isinstance(raw_clients, list):
        allowed_clients = {str(value).strip().lower() for value in raw_clients}
        return normalized_client in allowed_clients
    if isinstance(raw_clients, dict):
        prefixes = raw_clients.get(normalized_client)
        if prefixes is None:
            return False
        if isinstance(prefixes, str):
            prefixes = [prefixes]
        if not isinstance(prefixes, list):
            raise DeferredSourceError(
                "Deferred backend prefix mappings must be strings or arrays."
            )
        if object_id is None:
            return True
        return any(
            _object_matches_prefix(object_id, _normalize_prefix(prefix))
            for prefix in prefixes
        )
    raise DeferredSourceError(
        "Deferred backend client mappings must be arrays or objects."
    )


def max_deferred_source_bytes() -> int:
    raw = os.getenv("MASP_DEFERRED_MAX_BYTES", "0").strip() or "0"
    try:
        return max(0, int(raw))
    except ValueError as exc:
        raise DeferredSourceError("MASP_DEFERRED_MAX_BYTES must be an integer.") from exc


def validate_object_id(object_id: str) -> str:
    normalized = object_id.strip().replace("\\", "/")
    relative = PurePosixPath(normalized)
    if (
        not normalized
        or ":" in normalized
        or "\x00" in normalized
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise DeferredSourceError("object_id must be a normalized relative object path.")
    return "/".join(relative.parts)


def _reject_link(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        # Includes Windows junctions/reparse points, not only symbolic links.
        raise DeferredSourcePolicyError("Deferred object paths must not contain links.")


def resolve_source_path(backend_key: str, object_id: str) -> Path:
    backends = configured_backends()
    root = backends.get(backend_key.strip().lower())
    if root is None:
        raise DeferredSourceError(f"Deferred storage backend {backend_key!r} is not configured.")
    normalized = validate_object_id(object_id)
    relative = PurePosixPath(normalized)
    try:
        resolved_root = root.resolve(strict=True)
        cursor = resolved_root
        for part in relative.parts:
            cursor = cursor / part
            _reject_link(cursor)
        candidate = resolved_root.joinpath(*relative.parts).resolve(strict=True)
    except OSError as exc:
        raise DeferredSourceError("Deferred source object is unavailable.") from exc
    if resolved_root not in candidate.parents or not candidate.is_file():
        raise DeferredSourcePolicyError(
            "Deferred source object is outside its approved backend root or is not a file."
        )
    return candidate


def _windows_opened_path(handle) -> Path:
    """Resolve the opened handle, rather than re-resolving a mutable pathname."""
    import ctypes
    from ctypes import wintypes
    import msvcrt

    function = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
    function.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    function.restype = wintypes.DWORD
    file_handle = msvcrt.get_osfhandle(handle.fileno())
    size = function(file_handle, None, 0, 0)
    if not size:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(size + 1)
    length = function(file_handle, buffer, len(buffer), 0)
    if not length or length >= len(buffer):
        raise DeferredSourcePolicyError("Unable to validate the opened source path.")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


@contextmanager
def open_deferred_source(backend_key: str, object_id: str):
    source = resolve_source_path(backend_key, object_id)
    root = configured_backends()[backend_key.strip().lower()].resolve(strict=True)
    relative = PurePosixPath(validate_object_id(object_id))
    expected_path = root.joinpath(*relative.parts)
    if source != expected_path:
        raise DeferredSourcePolicyError("Deferred source path changed during validation.")
    handle = None
    try:
        if os.name == "posix":
            # Anchor each component to the already-open parent directory. A
            # concurrent rename/symlink swap cannot redirect a subsequent open.
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for part in relative.parts[:-1]:
                    child = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory,
                    )
                    os.close(directory)
                    directory = child
                descriptor = os.open(
                    relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=directory,
                )
                handle = os.fdopen(descriptor, "rb")
            finally:
                os.close(directory)
        elif os.name == "nt":
            handle = source.open("rb")
            if _windows_opened_path(handle) != expected_path:
                raise DeferredSourcePolicyError("Opened source escaped its authorized path.")
        else:
            raise DeferredSourcePolicyError("Secure deferred file access is unsupported on this OS.")
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise DeferredSourcePolicyError("Deferred source must be a regular, non-hardlinked file.")
        yield handle
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise DeferredSourcePolicyError("Deferred source path contains a link or non-directory.") from exc
        raise
    finally:
        if handle is not None:
            handle.close()


def copy_deferred_source(request: DeferredScanRecord) -> StoredSample:
    max_bytes = max_deferred_source_bytes()

    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = sanitize_filename(request.original_filename)
    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    target = SAMPLES_DIR / stored_name
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    try:
        with open_deferred_source(request.backend_key, request.object_id) as source_handle, target.open("xb") as target_handle:
            before = os.fstat(source_handle.fileno())
            if request.expected_size_bytes is not None and before.st_size != request.expected_size_bytes:
                raise DeferredSourceChangedError("Source size does not match expected_size_bytes.")
            if max_bytes and before.st_size > max_bytes:
                raise DeferredSourcePolicyError("Deferred source exceeds MASP_DEFERRED_MAX_BYTES.")
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
            while chunk := source_handle.read(1024 * 1024):
                size += len(chunk)
                if max_bytes and size > max_bytes:
                    raise DeferredSourcePolicyError(
                        "Deferred source exceeds MASP_DEFERRED_MAX_BYTES."
                    )
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                target_handle.write(chunk)
            after = os.fstat(source_handle.fileno())
        if (
            size != before.st_size
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise DeferredSourceChangedError("Source changed while MASP was copying it.")
        digest = sha256.hexdigest()
        if request.expected_sha256 and digest.lower() != request.expected_sha256.lower():
            raise DeferredSourceChangedError("Source SHA-256 does not match expected_sha256.")
    except Exception:
        target.unlink(missing_ok=True)
        raise

    return StoredSample(
        original_filename=safe_name,
        stored_filename=stored_name,
        storage_path=str(target),
        content_type=request.content_type or "application/octet-stream",
        size_bytes=size,
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
    )
