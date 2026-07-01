from pathlib import Path

from app.models import ScanRecord


ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SAMPLES_DIR = ROOT_DIR / "storage" / "samples"


def delete_sample_file(scan: ScanRecord) -> bool:
    storage_path = Path(scan.storage_path)

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
