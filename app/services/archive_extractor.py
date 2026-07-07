import hashlib
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import uuid
import zipfile

from app.models import StoredSample
from app.services.ingest import SAMPLES_DIR, sanitize_filename


DEFAULT_ARCHIVE_MAX_FILES = 1000
DEFAULT_ARCHIVE_MAX_TOTAL_BYTES = 250 * 1024 * 1024
DEFAULT_ARCHIVE_MAX_SINGLE_FILE_BYTES = 50 * 1024 * 1024
DEFAULT_ARCHIVE_MAX_DEPTH = 8
ARCHIVE_READ_CHUNK_BYTES = 1024 * 1024


class ArchiveExtractionError(ValueError):
    pass


class ArchiveExtractionLimitError(ArchiveExtractionError):
    pass


class UnsafeArchivePathError(ArchiveExtractionError):
    pass


@dataclass(frozen=True)
class ArchiveExtractionLimits:
    max_files: int = DEFAULT_ARCHIVE_MAX_FILES
    max_total_bytes: int = DEFAULT_ARCHIVE_MAX_TOTAL_BYTES
    max_single_file_bytes: int = DEFAULT_ARCHIVE_MAX_SINGLE_FILE_BYTES
    max_depth: int = DEFAULT_ARCHIVE_MAX_DEPTH


@dataclass(frozen=True)
class ExtractedArchiveMember:
    relative_path: str
    sample: StoredSample


@dataclass(frozen=True)
class ArchiveExtractionResult:
    archive_path: str
    members: list[ExtractedArchiveMember]
    total_uncompressed_bytes: int


def configured_archive_limits() -> ArchiveExtractionLimits:
    return ArchiveExtractionLimits(
        max_files=_env_int("MASP_ARCHIVE_MAX_FILES", DEFAULT_ARCHIVE_MAX_FILES, 1),
        max_total_bytes=_env_int(
            "MASP_ARCHIVE_MAX_TOTAL_BYTES",
            DEFAULT_ARCHIVE_MAX_TOTAL_BYTES,
            1,
        ),
        max_single_file_bytes=_env_int(
            "MASP_ARCHIVE_MAX_SINGLE_FILE_BYTES",
            DEFAULT_ARCHIVE_MAX_SINGLE_FILE_BYTES,
            1,
        ),
        max_depth=_env_int("MASP_ARCHIVE_MAX_DEPTH", DEFAULT_ARCHIVE_MAX_DEPTH, 1),
    )


def archive_extraction_enabled() -> bool:
    return os.getenv("MASP_ARCHIVE_EXTRACT_ENABLED", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def is_zip_file(path: str | Path) -> bool:
    try:
        return zipfile.is_zipfile(path)
    except OSError:
        return False


def extract_zip_archive(
    archive_path: str | Path,
    *,
    limits: ArchiveExtractionLimits | None = None,
    destination_dir: Path | None = None,
) -> ArchiveExtractionResult:
    if not archive_extraction_enabled():
        raise ArchiveExtractionError("Archive extraction is disabled.")

    effective_limits = limits or configured_archive_limits()
    target_dir = destination_dir or SAMPLES_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    archive = Path(archive_path)
    if not is_zip_file(archive):
        raise ArchiveExtractionError("Archive is not a valid ZIP file.")

    members: list[ExtractedArchiveMember] = []
    created_paths: list[Path] = []
    total_uncompressed_bytes = 0

    try:
        with zipfile.ZipFile(archive) as zip_file:
            infos = [info for info in zip_file.infolist() if not info.is_dir()]
            if len(infos) > effective_limits.max_files:
                raise ArchiveExtractionLimitError(
                    f"Archive contains {len(infos)} files, limit is {effective_limits.max_files}."
                )

            for info in infos:
                relative_path = safe_zip_relative_path(info.filename, effective_limits)
                if info.flag_bits & 0x1:
                    raise ArchiveExtractionError(
                        f"Encrypted ZIP member is not supported: {relative_path}"
                    )
                if info.file_size > effective_limits.max_single_file_bytes:
                    raise ArchiveExtractionLimitError(
                        f"Archive member exceeds {effective_limits.max_single_file_bytes} bytes: {relative_path}"
                    )
                if total_uncompressed_bytes + info.file_size > effective_limits.max_total_bytes:
                    raise ArchiveExtractionLimitError(
                        f"Archive exceeds {effective_limits.max_total_bytes} extracted bytes."
                    )

                extracted = extract_zip_member(
                    zip_file,
                    info,
                    relative_path=relative_path,
                    destination_dir=target_dir,
                    max_single_file_bytes=effective_limits.max_single_file_bytes,
                )
                created_paths.append(Path(extracted.sample.storage_path))
                members.append(extracted)
                total_uncompressed_bytes += extracted.sample.size_bytes

    except Exception:
        for path in created_paths:
            path.unlink(missing_ok=True)
        raise

    return ArchiveExtractionResult(
        archive_path=str(archive),
        members=members,
        total_uncompressed_bytes=total_uncompressed_bytes,
    )


def extract_zip_member(
    zip_file: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    relative_path: str,
    destination_dir: Path,
    max_single_file_bytes: int,
) -> ExtractedArchiveMember:
    safe_filename = sanitize_filename(PurePosixPath(relative_path).name)
    stored_filename = f"{uuid.uuid4().hex}_{safe_filename}"
    storage_path = destination_dir / stored_filename

    md5_hash = hashlib.md5(usedforsecurity=False)
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    size_bytes = 0

    with zip_file.open(info) as source, storage_path.open("wb") as target:
        while chunk := source.read(ARCHIVE_READ_CHUNK_BYTES):
            size_bytes += len(chunk)
            if size_bytes > max_single_file_bytes:
                storage_path.unlink(missing_ok=True)
                raise ArchiveExtractionLimitError(
                    f"Archive member exceeds {max_single_file_bytes} bytes while extracting: {relative_path}"
                )
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
            target.write(chunk)

    return ExtractedArchiveMember(
        relative_path=relative_path,
        sample=StoredSample(
            original_filename=safe_filename,
            stored_filename=stored_filename,
            storage_path=str(storage_path),
            content_type="application/octet-stream",
            size_bytes=size_bytes,
            md5=md5_hash.hexdigest(),
            sha1=sha1_hash.hexdigest(),
            sha256=sha256_hash.hexdigest(),
        ),
    )


def safe_zip_relative_path(
    raw_path: str,
    limits: ArchiveExtractionLimits,
) -> str:
    normalized = raw_path.replace("\\", "/").strip()
    if not normalized:
        raise UnsafeArchivePathError("Archive member has an empty path.")
    if normalized.startswith("/") or normalized.startswith("\\"):
        raise UnsafeArchivePathError(f"Archive member path is absolute: {raw_path}")
    if len(normalized) >= 2 and normalized[1] == ":":
        raise UnsafeArchivePathError(f"Archive member path has a drive prefix: {raw_path}")

    path = PurePosixPath(normalized)
    parts = path.parts
    if not parts:
        raise UnsafeArchivePathError("Archive member has an empty path.")
    if any(part in {"", ".", ".."} for part in parts):
        raise UnsafeArchivePathError(f"Archive member path is unsafe: {raw_path}")
    if len(parts) > limits.max_depth:
        raise ArchiveExtractionLimitError(
            f"Archive member depth exceeds {limits.max_depth}: {raw_path}"
        )
    return path.as_posix()


def _env_int(name: str, default: int, minimum: int) -> int:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        value = int(raw_value)
    except ValueError:
        return default
    return max(minimum, value)
