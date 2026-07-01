import os
import time
import traceback

from app.database import (
    claim_next_scan_job,
    create_engine_result,
    list_engine_results,
    update_scan_assessment,
    update_scan_status,
)
from app.engines.clamav import run_clamav_engine
from app.engines.static_metadata import run_static_metadata_engine
from app.engines.yara_engine import run_yara_engine
from app.models import ScanRecord
from app.services.scoring import calculate_risk


POLL_INTERVAL_SECONDS = float(os.getenv("MASP_WORKER_POLL_SECONDS", "2"))


def process_scan(scan: ScanRecord) -> None:
    create_engine_result(scan.id, run_static_metadata_engine(scan))
    create_engine_result(scan.id, run_clamav_engine(scan))
    create_engine_result(scan.id, run_yara_engine(scan))

    engine_results = list_engine_results(scan.id)
    assessment = calculate_risk(engine_results)
    update_scan_assessment(scan.id, assessment.verdict, assessment.score)
    update_scan_status(scan.id, "completed")


def process_next_scan_job() -> bool:
    scan = claim_next_scan_job()
    if scan is None:
        return False

    print(f"Processing scan job {scan.id}: {scan.original_filename}", flush=True)
    try:
        process_scan(scan)
    except Exception:
        update_scan_status(scan.id, "failed")
        print(f"Scan job {scan.id} failed", flush=True)
        traceback.print_exc()
        return True

    print(f"Completed scan job {scan.id}", flush=True)
    return True


def run_forever() -> None:
    print("MASP scan worker started", flush=True)
    while True:
        processed = process_next_scan_job()
        if not processed:
            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_forever()
