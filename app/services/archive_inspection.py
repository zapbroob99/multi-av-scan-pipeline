"""Archive inspection for a client's profile policy.

Engines scan an archive as one file, and ClamAV and Defender unpack the common
formats themselves. What a clean result cannot say is what the engine could not
see: an encrypted member, content past the engine's own limits, or a format it
skips all read as clean. Inspection opens the archive with MASP's own bounded
extractor at intake and records everything that would make that clean result
untrustworthy. It also judges every member against the profile's content rules
and the institution hash blocklist, which otherwise only ever see the container.

No engine job is created per member; scanning every member is the separate
``scan_members`` handling, which uses the member count recorded here to prove
that every member was registered for scanning.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app.services.archive_extractor import (
    ArchiveEncryptedError,
    ArchiveExtractionError,
    ArchiveExtractionLimitError,
    configured_archive_limits,
    configured_max_nested_levels,
    detect_archive_format,
    extract_archive,
    is_office_document,
    new_staging_dir,
    remove_staging_dir,
)
from app.services.content_types import detect_type

HEADER_BYTES = 4096
# Formats MASP recognizes but cannot open. Their content is unknown to MASP, and
# an encrypted one reads as clean to every engine, so they never pass inspection.
UNSUPPORTED_ARCHIVE_TYPES = {"rar": "RAR", "cab": "CAB", "gzip": "gzip", "bzip2": "bzip2", "xz": "xz"}
# Formats MASP opens; a file whose header claims one but cannot be opened is damaged.
OPENABLE_ARCHIVE_TYPES = {"zip", "7z", "tar"}
MAX_RECORDED_VIOLATIONS = 20
MAX_MEMBER_PATH_CHARS = 200

# Judges one member's header and name; returns a detail for each rule it breaks.
MemberCheck = Callable[[bytes, str], list[dict]]


@dataclass(frozen=True)
class ArchiveInspection:
    archive_format: str
    violations: tuple[dict, ...]
    violation_total: int
    # Every member at every level: the children scan_members registers.
    member_count: int
    total_bytes: int
    nested_archives: int

    def summary(self, handling: str) -> dict:
        return {"handling": handling, "format": self.archive_format, "members": self.member_count,
                "bytes": self.total_bytes, "nested_archives": self.nested_archives,
                "violation_total": self.violation_total}


@dataclass
class _Walk:
    member_check: MemberCheck
    check_blocklist: bool
    max_files: int
    max_total_bytes: int
    max_nested_levels: int
    violations: list[dict] = field(default_factory=list)
    violation_total: int = 0
    member_count: int = 0
    total_bytes: int = 0
    nested_archives: int = 0
    digests: dict[str, str] = field(default_factory=dict)
    # Set once a limit across all levels is exceeded: the verdict is known, stop reading.
    stopped: bool = False

    def add(self, kind: str, detail: str, member: str | None = None) -> None:
        self.violation_total += 1
        if len(self.violations) < MAX_RECORDED_VIOLATIONS:
            entry = {"kind": kind, "detail": detail}
            if member is not None:
                entry["member"] = member
            self.violations.append(entry)


def _short(path: str) -> str:
    return path if len(path) <= MAX_MEMBER_PATH_CHARS else "..." + path[-(MAX_MEMBER_PATH_CHARS - 3):]


def _read_header(path: str | Path) -> bytes:
    with Path(path).open("rb") as handle:
        return handle.read(HEADER_BYTES)


def _not_openable(path: str | Path, header: bytes) -> tuple[str, str] | None:
    """For a file MASP cannot open as an archive: (kind, format label) if it is one."""
    detected = detect_type(header)
    if detected in UNSUPPORTED_ARCHIVE_TYPES:
        return "archive_unsupported", UNSUPPORTED_ARCHIVE_TYPES[detected]
    if detected == "zip" and is_office_document(path):
        return None
    if detected in OPENABLE_ARCHIVE_TYPES:
        return "archive_unreadable", detected
    return None


def _describe_unopenable(kind: str, label: str, where: str) -> str:
    if kind == "archive_unsupported":
        return f"{where} is a {label} archive, which MASP cannot open, so its content cannot be checked."
    return f"{where} looks like a {label} archive but cannot be opened."


def inspect_archive(path: str | Path, *, header: bytes, member_check: MemberCheck,
                    check_blocklist: bool) -> ArchiveInspection | None:
    """Inspect a stored sample; ``None`` when it is not an archive at all.

    Raises only for an infrastructure failure such as an unreadable hash list:
    a check that did not happen must never read as a check that passed.
    """
    archive_format = detect_archive_format(path)
    if archive_format is None:
        unopenable = _not_openable(path, header)
        if unopenable is None:
            return None
        kind, label = unopenable
        return ArchiveInspection(archive_format=label.lower(), violation_total=1, member_count=0,
                                 total_bytes=0, nested_archives=0,
                                 violations=({"kind": kind, "detail": _describe_unopenable(kind, label, "The file")},))
    limits = configured_archive_limits()
    walk = _Walk(member_check=member_check, check_blocklist=check_blocklist, max_files=limits.max_files,
                 max_total_bytes=limits.max_total_bytes, max_nested_levels=configured_max_nested_levels())
    staging = new_staging_dir()
    try:
        _walk_archive(Path(path), prefix="", level=1, walk=walk, staging=staging)
    finally:
        remove_staging_dir(staging)
    if walk.digests:
        _check_blocklist(walk)
    return ArchiveInspection(archive_format=archive_format, violations=tuple(walk.violations),
                             violation_total=walk.violation_total, member_count=walk.member_count,
                             total_bytes=walk.total_bytes, nested_archives=walk.nested_archives)


def _walk_archive(path: Path, *, prefix: str, level: int, walk: _Walk, staging: Path) -> None:
    where = f"Nested archive {_short(prefix.rstrip('/'))}" if prefix else "The archive"
    target = staging / f"level-{level}-{walk.nested_archives}"
    try:
        extraction = extract_archive(path, destination_dir=target)
    except ArchiveEncryptedError as exc:
        walk.add("archive_encrypted", f"{where} is encrypted, so its content cannot be checked ({exc}).",
                 prefix.rstrip("/") or None)
        return
    except ArchiveExtractionLimitError as exc:
        walk.add("archive_limit", f"{where} exceeds an extraction limit: {exc}", prefix.rstrip("/") or None)
        return
    except ArchiveExtractionError as exc:
        walk.add("archive_unreadable", f"{where} cannot be opened: {exc}", prefix.rstrip("/") or None)
        return
    except Exception as exc:  # noqa: BLE001 - a damaged archive raises from its own library
        walk.add("archive_unreadable", f"{where} cannot be opened ({type(exc).__name__}).", prefix.rstrip("/") or None)
        return
    try:
        walk.member_count += len(extraction.members)
        walk.total_bytes += extraction.total_uncompressed_bytes
        if walk.member_count > walk.max_files:
            walk.add("archive_limit", f"The archive holds more than {walk.max_files} files across all levels.")
            walk.stopped = True
            return
        if walk.total_bytes > walk.max_total_bytes:
            walk.add("archive_limit", f"The archive's content exceeds {walk.max_total_bytes} bytes across all levels.")
            walk.stopped = True
            return
        for member in extraction.members:
            if walk.stopped:
                return
            name = f"{prefix}{member.relative_path}"
            shown = _short(name)
            member_path = Path(member.sample.storage_path)
            header = _read_header(member_path)
            for violation in walk.member_check(header, member.sample.original_filename):
                walk.add(f"member_{violation['kind']}", f"Archive member {shown}: {violation['detail']}", shown)
            if walk.check_blocklist:
                walk.digests.setdefault(member.sample.sha256, shown)
            if detect_archive_format(member_path) is not None:
                walk.nested_archives += 1
                if level + 1 > walk.max_nested_levels:
                    walk.add("archive_nesting",
                             f"Archive member {shown} nests archives deeper than {walk.max_nested_levels} levels.", shown)
                else:
                    _walk_archive(member_path, prefix=f"{name}/", level=level + 1, walk=walk, staging=staging)
            else:
                unopenable = _not_openable(member_path, header)
                if unopenable is not None:
                    kind, label = unopenable
                    walk.add(kind, _describe_unopenable(kind, label, f"Archive member {shown}"), shown)
            member_path.unlink(missing_ok=True)
    finally:
        remove_staging_dir(target)


def _check_blocklist(walk: _Walk) -> None:
    from app.database import blocklisted_sha256s

    for digest in sorted(blocklisted_sha256s(list(walk.digests))):
        walk.add("member_blocklisted", f"Archive member {walk.digests[digest]} is on the institution hash blocklist.",
                 walk.digests[digest])
