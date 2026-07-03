import os
import time
import traceback

from app.database import (
    claim_next_scan_job,
    create_engine_result,
    init_db,
    list_engine_results,
    recover_running_scan_jobs,
    update_scan_assessment,
    update_scan_status,
)
from app.models import ScanRecord
from app.services.engine_registry import enabled_engines, run_engine, seed_default_engines
from app.services.scoring import calculate_risk
from app.services.worker_runtime import record_worker_heartbeat


POLL_INTERVAL_SECONDS = float(os.getenv("MASP_WORKER_POLL_SECONDS", "2"))


def process_scan(scan: ScanRecord) -> None:
    record_worker_heartbeat("running", active_scan_id=scan.id)
    for engine in enabled_engines():
        create_engine_result(scan.id, run_engine(engine, scan))

    engine_results = list_engine_results(scan.id)
    assessment = calculate_risk(engine_results)
    update_scan_assessment(scan.id, assessment.verdict, assessment.score)
    update_scan_status(scan.id, "completed")


def process_next_scan_job() -> bool:
    scan = claim_next_scan_job()
    if scan is None:
        record_worker_heartbeat("idle")
        return False

    print(f"Processing scan job {scan.id}: {scan.original_filename}", flush=True)
    try:
        process_scan(scan)
    except Exception as exc:
        update_scan_status(scan.id, "failed", last_error=str(exc))
        record_worker_heartbeat("error", active_scan_id=scan.id)
        print(f"Scan job {scan.id} failed", flush=True)
        traceback.print_exc()
        return True

    record_worker_heartbeat("idle")
    print(f"Completed scan job {scan.id}", flush=True)
    return True


def run_forever() -> None:
    init_db()
    seed_default_engines()
    recovered = recover_running_scan_jobs()
    record_worker_heartbeat("starting")
    print("MASP scan worker started", flush=True)
    if recovered:
        print(f"Recovered {recovered} interrupted scan job(s)", flush=True)
    while True:
        processed = process_next_scan_job()
        if not processed:
            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_forever()
