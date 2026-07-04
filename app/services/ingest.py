import hashlib
import os
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
    raw_value = os.getenv("MASP_UPLOAD_MAX_BYTES", "0").strip()
    try:
        limit = int(raw_value or "0")
    except ValueError:
        return None
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
