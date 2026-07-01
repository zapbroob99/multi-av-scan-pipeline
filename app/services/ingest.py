import hashlib
from pathlib import Path
import re
import uuid

from fastapi import UploadFile

from app.models import StoredSample


ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SAMPLES_DIR = ROOT_DIR / "storage" / "samples"


def sanitize_filename(filename: str) -> str:
    name = Path(filename).name
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return safe_name or "sample.bin"


async def store_upload(upload: UploadFile) -> StoredSample:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    safe_filename = sanitize_filename(upload.filename or "sample.bin")
    stored_filename = f"{uuid.uuid4().hex}_{safe_filename}"
    storage_path = SAMPLES_DIR / stored_filename

    md5_hash = hashlib.md5(usedforsecurity=False)
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    size_bytes = 0

    with storage_path.open("wb") as target:
        while chunk := await upload.read(1024 * 1024):
            size_bytes += len(chunk)
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
            target.write(chunk)

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
