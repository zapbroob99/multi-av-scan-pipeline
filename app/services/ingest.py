import hashlib
from pathlib import Path
import re
import uuid

from fastapi import UploadFile

from app.models import StoredSample


ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SAMPLES_DIR = ROOT_DIR / "storage" / "samples"


class UploadTooLargeError(ValueError):
    def __init__(self, max_size_bytes: int, observed_size_bytes: int) -> None:
        self.max_size_bytes = max_size_bytes
        self.observed_size_bytes = observed_size_bytes
        super().__init__(
            f"Upload exceeds the configured {max_size_bytes} byte limit."
        )


def configured_upload_max_bytes() -> int | None:
    # Resolved centrally (DB override -> MASP_UPLOAD_MAX_BYTES -> default) so the
    # Scan Policy admin panel and the API upload path share one value. Imported
    # lazily to keep this low-level storage module free of a boot-time DB import.
    from app.services import scan_policy

    limit = scan_policy.resolve_int("upload_max_bytes")
    if limit <= 0:
        return None
    return limit


def sanitize_filename(filename: str) -> str:
    name = Path(filename).name
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return safe_name or "sample.bin"


async def store_upload(
    upload: UploadFile,
    max_size_bytes: int | None = None,
) -> StoredSample:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    upload_limit = configured_upload_max_bytes() if max_size_bytes is None else max_size_bytes

    safe_filename = sanitize_filename(upload.filename or "sample.bin")
    stored_filename = f"{uuid.uuid4().hex}_{safe_filename}"
    storage_path = SAMPLES_DIR / stored_filename

    md5_hash = hashlib.md5(usedforsecurity=False)
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    size_bytes = 0

    try:
        with storage_path.open("wb") as target:
            while chunk := await upload.read(1024 * 1024):
                size_bytes += len(chunk)
                if upload_limit is not None and size_bytes > upload_limit:
                    raise UploadTooLargeError(upload_limit, size_bytes)
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                target.write(chunk)
    except Exception:
        storage_path.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()

    return StoredSample(
        original_filename=safe_filename,
        stored_filename=stored_filename,
        storage_path=str(storage_path),
        content_type=upload.content_type or "application/octet-stream",
        size_bytes=size_bytes,
        md5=md5_hash.hexdigest(),
        sha1=sha1_hash.hexdigest(),
        sha256=sha256_hash.hexdigest(),
    )


def store_bytes(
    filename: str,
    content_type: str,
    data: bytes,
    max_size_bytes: int | None = None,
) -> StoredSample:
    """Persist an in-memory buffer as a sample.

    Byte-based counterpart to :func:`store_upload` for callers that already
    hold the full content (e.g. the ICAP server). Honors the same size cap and
    produces an identical :class:`StoredSample`.
    """
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    upload_limit = configured_upload_max_bytes() if max_size_bytes is None else max_size_bytes
    if upload_limit is not None and len(data) > upload_limit:
        raise UploadTooLargeError(upload_limit, len(data))

    safe_filename = sanitize_filename(filename or "sample.bin")
    stored_filename = f"{uuid.uuid4().hex}_{safe_filename}"
    storage_path = SAMPLES_DIR / stored_filename

    try:
        storage_path.write_bytes(data)
    except Exception:
        storage_path.unlink(missing_ok=True)
        raise

    return StoredSample(
        original_filename=safe_filename,
        stored_filename=stored_filename,
        storage_path=str(storage_path),
        content_type=content_type or "application/octet-stream",
        size_bytes=len(data),
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )
