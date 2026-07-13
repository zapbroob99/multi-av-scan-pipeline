import json
import os
from pathlib import Path

from app.models import ScanRecord


ROOT_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = ROOT_DIR / "storage"
SAMPLES_DIR = STORAGE_DIR / "samples"

DEFAULT_PATH_MAPPINGS = (
    ("/app/storage/samples", SAMPLES_DIR),
    ("/app/storage", STORAGE_DIR),
)

SAMPLE_PATH_MAPPINGS_ENV = "MASP_SAMPLE_PATH_MAPPINGS_JSON"


class SamplePathConfigError(Exception):
    """Raised when MASP_SAMPLE_PATH_MAPPINGS_JSON is present but malformed.

    Deliberately NOT swallowed: a misconfigured mount mapping must surface as an
    explicit error rather than silently falling back to defaults and scanning
    (or failing to find) the wrong file.
    """


def configured_path_mappings() -> tuple[tuple[str, Path], ...]:
    """Parse operator-supplied prefix->root mappings, e.g. a VM's read-only mount.

    Format: a JSON object mapping a source prefix (as stored in the DB, e.g.
    ``/app/storage/samples``) to an absolute target root on this host. Any
    parse/shape/type problem raises SamplePathConfigError instead of degrading.
    """
    raw = os.getenv(SAMPLE_PATH_MAPPINGS_ENV, "").strip()
    if not raw:
        return ()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SamplePathConfigError(
            f"{SAMPLE_PATH_MAPPINGS_ENV} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise SamplePathConfigError(
            f"{SAMPLE_PATH_MAPPINGS_ENV} must be a JSON object of "
            "{source_prefix: target_root}."
        )
    mappings: list[tuple[str, Path]] = []
    for source, target in parsed.items():
        if not isinstance(source, str) or not source.strip():
            raise SamplePathConfigError(
                f"{SAMPLE_PATH_MAPPINGS_ENV} keys must be non-empty strings."
            )
        if not isinstance(target, str) or not target.strip():
            raise SamplePathConfigError(
                f"{SAMPLE_PATH_MAPPINGS_ENV} values must be non-empty strings "
                f"(offending key {source!r})."
            )
        # Absolute check uses the runtime platform's native semantics: the
        # target is a path on THIS worker host, so it must be absolute here.
        # (A Windows-style target on Linux would otherwise be read relative to
        # the working directory.)
        if not Path(target).is_absolute():
            raise SamplePathConfigError(
                f"{SAMPLE_PATH_MAPPINGS_ENV} target {target!r} for prefix "
                f"{source!r} must be an absolute path on this worker."
            )
        mappings.append((source.strip(), Path(target)))
    return tuple(mappings)


def ordered_mappings(configured: tuple[tuple[str, Path], ...]) -> tuple[tuple[str, Path], ...]:
    """Configured mappings first, then defaults, longest prefix first.

    Longest-prefix ordering makes ``/app/storage/samples`` win over
    ``/app/storage`` regardless of insertion order.
    """
    combined = list(configured) + list(DEFAULT_PATH_MAPPINGS)
    combined.sort(key=lambda pair: len(pair[0].rstrip("/")), reverse=True)
    return tuple(combined)


def all_path_mappings() -> tuple[tuple[str, Path], ...]:
    return ordered_mappings(configured_path_mappings())


def has_parent_traversal(path_text: str) -> bool:
    return ".." in path_text.replace("\\", "/").split("/")


def acceptable_direct_path(
    path_text: str,
    direct_path: Path,
    configured: tuple[tuple[str, Path], ...],
) -> bool:
    """Whether a stored path may be used verbatim, without prefix mapping.

    Two layers:
    - A ``..`` segment is ALWAYS rejected (no direct traversal), regardless of
      configuration.
    - When path mappings are configured (VM worker mode, the new attack
      surface), a direct path must additionally resolve inside a known root
      (a mapping target or the app-host STORAGE_DIR). Without mappings the
      original app-host behavior (accept any existing file) is preserved.
    """
    if has_parent_traversal(path_text):
        return False
    if not direct_path.is_file():
        return False
    if not configured:
        return True
    known_roots = [target for _, target in configured]
    known_roots.append(STORAGE_DIR)
    return any(path_within_root(direct_path, root) for root in known_roots)


def resolve_sample_path(scan: ScanRecord) -> Path:
    configured = configured_path_mappings()  # raises on malformed config
    direct_path = Path(scan.storage_path)
    if acceptable_direct_path(scan.storage_path, direct_path, configured):
        return direct_path

    for source_prefix, target_root in ordered_mappings(configured):
        mapped_path = safe_map_path_prefix(scan.storage_path, source_prefix, target_root)
        if mapped_path is not None and mapped_path.is_file():
            return mapped_path

    fallback_path = SAMPLES_DIR / scan.stored_filename
    if fallback_path.is_file():
        return fallback_path

    return direct_path


def safe_map_path_prefix(
    path_text: str, source_prefix: str, target_root: Path
) -> Path | None:
    """Map a prefix, then reject anything that escapes the target root.

    Guards against ``..`` traversal, absolute-path injection, and symlinks that
    point outside ``target_root`` (checked via resolved real paths).
    """
    mapped_path = map_path_prefix(path_text, source_prefix, target_root)
    if mapped_path is None:
        return None
    if not path_within_root(mapped_path, target_root):
        return None
    return mapped_path


def path_within_root(candidate: Path, root: Path) -> bool:
    try:
        resolved = candidate.resolve()
        resolved_root = root.resolve()
    except OSError:
        return False
    return resolved == resolved_root or resolved_root in resolved.parents


def map_path_prefix(path_text: str, source_prefix: str, target_root: Path) -> Path | None:
    normalized_path = path_text.replace("\\", "/")
    normalized_prefix = source_prefix.rstrip("/").replace("\\", "/")
    if normalized_path == normalized_prefix:
        return target_root
    if not normalized_path.startswith(normalized_prefix + "/"):
        return None

    relative_text = normalized_path[len(normalized_prefix) :].lstrip("/")
    if not relative_text:
        return target_root
    return target_root.joinpath(*relative_text.split("/"))


def sample_path_error(scan: ScanRecord, resolved_path: Path) -> str:
    if str(resolved_path) == scan.storage_path:
        return f"Sample file not found: {scan.storage_path}"
    return f"Sample file not found: {scan.storage_path} (resolved locally as {resolved_path})"
