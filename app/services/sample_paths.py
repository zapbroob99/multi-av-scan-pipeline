from pathlib import Path

from app.models import ScanRecord


ROOT_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = ROOT_DIR / "storage"
SAMPLES_DIR = STORAGE_DIR / "samples"

DEFAULT_PATH_MAPPINGS = (
    ("/app/storage/samples", SAMPLES_DIR),
    ("/app/storage", STORAGE_DIR),
)


def resolve_sample_path(scan: ScanRecord) -> Path:
    direct_path = Path(scan.storage_path)
    if direct_path.is_file():
        return direct_path

    for source_prefix, target_root in DEFAULT_PATH_MAPPINGS:
        mapped_path = map_path_prefix(scan.storage_path, source_prefix, target_root)
        if mapped_path is not None and mapped_path.is_file():
            return mapped_path

    fallback_path = SAMPLES_DIR / scan.stored_filename
    if fallback_path.is_file():
        return fallback_path

    return direct_path


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
