from app.models import ScanRecord
from app.services.sample_paths import SAMPLES_DIR, resolve_sample_path


def delete_sample_file(scan: ScanRecord) -> bool:
    storage_path = resolve_sample_path(scan)

    try:
        resolved_path = storage_path.resolve()
        resolved_samples_dir = SAMPLES_DIR.resolve()
    except OSError:
        return False

    if resolved_samples_dir not in resolved_path.parents:
        return False

    if not resolved_path.is_file():
        return False

    resolved_path.unlink()
    return True
