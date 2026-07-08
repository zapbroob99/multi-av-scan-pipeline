import hashlib
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO
import uuid
import zipfile

import py7zr
import py7zr.exceptions

from app.models import StoredSample
from app.services.ingest import SAMPLES_DIR, sanitize_filename


ARCHIVE_FORMAT_ZIP = "zip"
ARCHIVE_FORMAT_TAR = "tar"
ARCHIVE_FORMAT_SEVEN_ZIP = "7z"
SUPPORTED_ARCHIVE_FORMATS = (
    ARCHIVE_FORMAT_ZIP,
    ARCHIVE_FORMAT_TAR,
    ARCHIVE_FORMAT_SEVEN_ZIP,
)

DEFAULT_ARCHIVE_MAX_FILES = 1000
DEFAULT_ARCHIVE_MAX_TOTAL_BYTES = 250 * 1024 * 1024
DEFAULT_ARCHIVE_MAX_SINGLE_FILE_BYTES = 50 * 1024 * 1024
DEFAULT_ARCHIVE_MAX_DEPTH = 8
DEFAULT_ARCHIVE_MAX_NESTED_LEVELS = 3
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


def configured_max_nested_levels() -> int:
    return _env_int(
        "MASP_ARCHIVE_MAX_NESTED_LEVELS",
        DEFAULT_ARCHIVE_MAX_NESTED_LEVELS,
        1,
    )


def archive_extraction_enabled() -> bool:
    return os.getenv("MASP_ARCHIVE_EXTRACT_ENABLED", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def detect_archive_format(path: str | Path) -> str | None:
    # 7z and ZIP checks are magic-byte based and cheap. TAR detection is
    # checksum-based and can false-positive on unlucky binaries, so it runs last.
    try:
        if py7zr.is_7zfile(path):
            return ARCHIVE_FORMAT_SEVEN_ZIP
        if zipfile.is_zipfile(path):
            return ARCHIVE_FORMAT_ZIP
        if tarfile.is_tarfile(path):
            return ARCHIVE_FORMAT_TAR
    except OSError:
        return None
    return None


def is_supported_archive(path: str | Path) -> bool:
    return detect_archive_format(path) is not None


def extract_archive(
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
    archive_format = detect_archive_format(archive)
    if archive_format is None:
        raise ArchiveExtractionError("Archive is not a supported archive format.")

    members: list[ExtractedArchiveMember] = []
    created_paths: list[Path] = []
    try:
        if archive_format == ARCHIVE_FORMAT_ZIP:
            _extract_zip_members(archive, effective_limits, target_dir, members, created_paths)
        elif archive_format == ARCHIVE_FORMAT_TAR:
            _extract_tar_members(archive, effective_limits, target_dir, members, created_paths)
        else:
            _extract_7z_members(archive, effective_limits, target_dir, members, created_paths)
    except Exception:
        for path in created_paths:
            path.unlink(missing_ok=True)
        raise

    return ArchiveExtractionResult(
        archive_path=str(archive),
        members=members,
        total_uncompressed_bytes=sum(member.sample.size_bytes for member in members),
    )


def _extract_zip_members(
    archive: Path,
    limits: ArchiveExtractionLimits,
    target_dir: Path,
    members: list[ExtractedArchiveMember],
    created_paths: list[Path],
) -> None:
    total_uncompressed_bytes = 0
    with zipfile.ZipFile(archive) as zip_file:
        infos = [info for info in zip_file.infolist() if not info.is_dir()]
        if len(infos) > limits.max_files:
            raise ArchiveExtractionLimitError(
                f"Archive contains {len(infos)} files, limit is {limits.max_files}."
            )

        for info in infos:
            relative_path = safe_member_relative_path(info.filename, limits)
            if info.flag_bits & 0x1:
                raise ArchiveExtractionError(
                    f"Encrypted ZIP member is not supported: {relative_path}"
                )
            _check_declared_member_size(info.file_size, relative_path, total_uncompressed_bytes, limits)

            with zip_file.open(info) as source:
                extracted = _store_member_stream(
                    source,
                    relative_path=relative_path,
                    destination_dir=target_dir,
                    max_single_file_bytes=limits.max_single_file_bytes,
                )
            created_paths.append(Path(extracted.sample.storage_path))
            members.append(extracted)
            total_uncompressed_bytes += extracted.sample.size_bytes


def _extract_tar_members(
    archive: Path,
    limits: ArchiveExtractionLimits,
    target_dir: Path,
    members: list[ExtractedArchiveMember],
    created_paths: list[Path],
) -> None:
    total_uncompressed_bytes = 0
    try:
        tar_file = tarfile.open(archive, mode="r:*")
    except tarfile.TarError as exc:
        raise ArchiveExtractionError(f"Archive is not a readable TAR file: {exc}") from exc

    with tar_file:
        # Symlinks, hardlinks, devices, and FIFOs carry no scannable payload and
        # are never materialized as links because members stream into flat
        # uuid-named sample files. They are skipped instead of rejected.
        infos = [info for info in tar_file.getmembers() if info.isreg()]
        if len(infos) > limits.max_files:
            raise ArchiveExtractionLimitError(
                f"Archive contains {len(infos)} files, limit is {limits.max_files}."
            )

        for info in infos:
            relative_path = safe_member_relative_path(info.name, limits)
            _check_declared_member_size(info.size, relative_path, total_uncompressed_bytes, limits)

            source = tar_file.extractfile(info)
            if source is None:
                raise ArchiveExtractionError(
                    f"TAR member could not be opened: {relative_path}"
                )
            with source:
                extracted = _store_member_stream(
                    source,
                    relative_path=relative_path,
                    destination_dir=target_dir,
                    max_single_file_bytes=limits.max_single_file_bytes,
                )
            created_paths.append(Path(extracted.sample.storage_path))
            members.append(extracted)
            total_uncompressed_bytes += extracted.sample.size_bytes


def _extract_7z_members(
    archive: Path,
    limits: ArchiveExtractionLimits,
    target_dir: Path,
    members: list[ExtractedArchiveMember],
    created_paths: list[Path],
) -> None:
    try:
        seven_zip = py7zr.SevenZipFile(archive)
    except py7zr.exceptions.PasswordRequired as exc:
        raise ArchiveExtractionError("Encrypted 7z archive is not supported.") from exc
    except py7zr.exceptions.ArchiveError as exc:
        raise ArchiveExtractionError(f"Archive is not a readable 7z file: {exc}") from exc

    with seven_zip:
        if seven_zip.needs_password():
            raise ArchiveExtractionError("Encrypted 7z archive is not supported.")

        infos = [info for info in seven_zip.list() if not info.is_directory]
        if len(infos) > limits.max_files:
            raise ArchiveExtractionLimitError(
                f"Archive contains {len(infos)} files, limit is {limits.max_files}."
            )

        relative_paths: dict[str, str] = {}
        total_declared_bytes = 0
        for info in infos:
            relative_path = safe_member_relative_path(info.filename, limits)
            if info.filename in relative_paths:
                raise ArchiveExtractionError(
                    f"Archive contains duplicate member paths: {relative_path}"
                )
            _check_declared_member_size(
                info.uncompressed, relative_path, total_declared_bytes, limits
            )
            relative_paths[info.filename] = relative_path
            total_declared_bytes += info.uncompressed

        # Declared header sizes are validated above, but a crafted archive can
        # lie, so the writer factory re-enforces both limits on actual
        # decompressed bytes and aborts extraction mid-stream when exceeded.
        factory = _BoundedWriterFactory(
            destination_dir=target_dir,
            relative_paths=relative_paths,
            limits=limits,
        )
        try:
            seven_zip.extract(targets=list(relative_paths), factory=factory)
        except py7zr.exceptions.ArchiveError as exc:
            factory.cleanup_files()
            raise ArchiveExtractionError(f"7z extraction failed: {exc}") from exc
        except Exception:
            factory.cleanup_files()
            raise

    try:
        for filename, relative_path in relative_paths.items():
            writer = factory.writers.get(filename)
            if writer is None:
                raise ArchiveExtractionError(
                    f"7z member was not extracted: {relative_path}"
                )
            extracted = _finalize_stored_member(
                writer.storage_path,
                relative_path=relative_path,
            )
            created_paths.append(Path(extracted.sample.storage_path))
            members.append(extracted)
    except Exception:
        factory.cleanup_files()
        raise


class _BoundedWriterFactory:
    """py7zr WriterFactory that streams members to disk with limit enforcement."""

    def __init__(
        self,
        *,
        destination_dir: Path,
        relative_paths: dict[str, str],
        limits: ArchiveExtractionLimits,
    ) -> None:
        self.destination_dir = destination_dir
        self.relative_paths = relative_paths
        self.limits = limits
        self.writers: dict[str, _BoundedMemberWriter] = {}
        self.total_written_bytes = 0

    def create(self, filename: str) -> "_BoundedMemberWriter":
        relative_path = self.relative_paths.get(filename)
        if relative_path is None:
            raise UnsafeArchivePathError(
                f"7z extraction produced an unexpected member: {filename}"
            )
        safe_filename = sanitize_filename(PurePosixPath(relative_path).name)
        storage_path = self.destination_dir / f"{uuid.uuid4().hex}_{safe_filename}"
        writer = _BoundedMemberWriter(
            factory=self,
            storage_path=storage_path,
            relative_path=relative_path,
        )
        self.writers[filename] = writer
        return writer

    def close_all(self) -> None:
        for writer in self.writers.values():
            writer.close()

    def cleanup_files(self) -> None:
        self.close_all()
        for writer in self.writers.values():
            writer.storage_path.unlink(missing_ok=True)


class _BoundedMemberWriter(py7zr.Py7zIO):
    def __init__(
        self,
        *,
        factory: _BoundedWriterFactory,
        storage_path: Path,
        relative_path: str,
    ) -> None:
        self.factory = factory
        self.storage_path = storage_path
        self.relative_path = relative_path
        self._file: BinaryIO | None = storage_path.open("w+b")

    def write(self, s: bytes | bytearray) -> int:
        if self._file is None:
            raise ArchiveExtractionError(
                f"7z member writer is closed: {self.relative_path}"
            )
        self.factory.total_written_bytes += len(s)
        if self.factory.total_written_bytes > self.factory.limits.max_total_bytes:
            self.factory.cleanup_files()
            raise ArchiveExtractionLimitError(
                f"Archive exceeds {self.factory.limits.max_total_bytes} extracted bytes."
            )
        written = self._file.write(s)
        if self._file.tell() > self.factory.limits.max_single_file_bytes:
            self.factory.cleanup_files()
            raise ArchiveExtractionLimitError(
                f"Archive member exceeds {self.factory.limits.max_single_file_bytes} bytes "
                f"while extracting: {self.relative_path}"
            )
        return written

    def read(self, size: int | None = None) -> bytes:
        if self._file is None:
            return b""
        return self._file.read(-1 if size is None else size)

    def seek(self, offset: int, whence: int = 0) -> int:
        if self._file is None:
            return 0
        return self._file.seek(offset, whence)

    def flush(self) -> None:
        if self._file is not None:
            self._file.flush()

    def size(self) -> int:
        if self._file is None:
            return 0
        current = self._file.tell()
        self._file.seek(0, os.SEEK_END)
        end = self._file.tell()
        self._file.seek(current)
        return end

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None


def _check_declared_member_size(
    declared_bytes: int,
    relative_path: str,
    total_bytes_so_far: int,
    limits: ArchiveExtractionLimits,
) -> None:
    declared = max(0, int(declared_bytes or 0))
    if declared > limits.max_single_file_bytes:
        raise ArchiveExtractionLimitError(
            f"Archive member exceeds {limits.max_single_file_bytes} bytes: {relative_path}"
        )
    if total_bytes_so_far + declared > limits.max_total_bytes:
        raise ArchiveExtractionLimitError(
            f"Archive exceeds {limits.max_total_bytes} extracted bytes."
        )


def _store_member_stream(
    source: BinaryIO,
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

    with storage_path.open("wb") as target:
        while chunk := source.read(ARCHIVE_READ_CHUNK_BYTES):
            size_bytes += len(chunk)
            if size_bytes > max_single_file_bytes:
                target.close()
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


def _finalize_stored_member(storage_path: Path, *, relative_path: str) -> ExtractedArchiveMember:
    md5_hash = hashlib.md5(usedforsecurity=False)
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    size_bytes = 0

    with storage_path.open("rb") as source:
        while chunk := source.read(ARCHIVE_READ_CHUNK_BYTES):
            size_bytes += len(chunk)
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return ExtractedArchiveMember(
        relative_path=relative_path,
        sample=StoredSample(
            original_filename=sanitize_filename(PurePosixPath(relative_path).name),
            stored_filename=storage_path.name,
            storage_path=str(storage_path),
            content_type="application/octet-stream",
            size_bytes=size_bytes,
            md5=md5_hash.hexdigest(),
            sha1=sha1_hash.hexdigest(),
            sha256=sha256_hash.hexdigest(),
        ),
    )


def safe_member_relative_path(
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
