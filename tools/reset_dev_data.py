"""Dev-only: wipe all scan/sample data for a clean local testing slate.

Deletes every sample (cascades to scan_jobs, engine_results,
scan_engine_jobs, scan_worker_events) and every scan_batch, then removes
the stored sample files from disk. Engine configuration, app settings, and
user accounts are left untouched.

Usage:
    .venv\\Scripts\\python.exe tools\\reset_dev_data.py --yes
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import connect, init_db
from app.services.sample_paths import SAMPLES_DIR


def count_rows(connection, table: str) -> int:
    row = connection.execute(f"SELECT COUNT(*) AS total FROM {table}").fetchone()
    return int(row["total"] if isinstance(row, dict) else row[0])


def wipe_sample_files() -> int:
    if not SAMPLES_DIR.is_dir():
        return 0
    removed = 0
    for path in SAMPLES_DIR.rglob("*"):
        if path.is_file():
            path.unlink()
            removed += 1
    return removed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Actually perform the deletion. Without this flag, only reports counts.",
    )
    args = parser.parse_args()

    init_db()

    with connect() as connection:
        scan_count = count_rows(connection, "scan_jobs")
        sample_count = count_rows(connection, "samples")
        batch_count = count_rows(connection, "scan_batches")

    print(f"scan_jobs: {scan_count}, samples: {sample_count}, scan_batches: {batch_count}")

    if not args.yes:
        print("Dry run only. Re-run with --yes to delete all scan/sample data.")
        return

    with connect() as connection:
        connection.execute("DELETE FROM samples")
        connection.execute("DELETE FROM scan_batches")

    removed_files = wipe_sample_files()
    print(
        f"Deleted {sample_count} samples (cascaded scans/results/events), "
        f"{batch_count} batches, and {removed_files} stored files."
    )


if __name__ == "__main__":
    main()
