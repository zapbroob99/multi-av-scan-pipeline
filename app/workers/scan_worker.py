import os
import time
import traceback

from app.database import (
    create_engine_result_if_missing,
    init_db,
    list_active_scans,
    list_engine_results,
    mark_scan_running,
    recover_running_scan_jobs,
    update_scan_assessment,
    update_scan_status,
)
from app.models import ScanRecord
from app.services.engine_registry import enabled_engines, run_engine, seed_default_engines
from app.services.scoring import calculate_risk
from app.services.worker_capabilities import (
    all_enabled_engines_have_results,
    missing_supported_engines,
    worker_engine_keys,
)
from app.services.worker_runtime import record_worker_heartbeat


POLL_INTERVAL_SECONDS = float(os.getenv("MASP_WORKER_POLL_SECONDS", "2"))
ACTIVE_SCAN_LIMIT = int(os.getenv("MASP_WORKER_ACTIVE_SCAN_LIMIT", "20"))


def process_scan(scan: ScanRecord, engine_keys: set[str]) -> bool:
    record_worker_heartbeat("running", active_scan_id=scan.id)
    engines = enabled_engines()
    engine_results = list_engine_results(scan.id)
    existing_engine_names = {result.engine_name for result in engine_results}
    missing_engines = missing_supported_engines(
        engines,
        existing_engine_names,
        engine_keys,
    )

    if not missing_engines:
        finalize_scan_if_complete(scan, engines)
        return False

    mark_scan_running(scan.id)
    for engine in missing_engines:
        print(f"Running {engine.display_name} for scan job {scan.id}", flush=True)
        create_engine_result_if_missing(scan.id, run_engine(engine, scan))

    finalize_scan_if_complete(scan, engines)
    return True


def finalize_scan_if_complete(scan: ScanRecord, engines: list) -> bool:
    engine_results = list_engine_results(scan.id)
    existing_engine_names = {result.engine_name for result in engine_results}
    if not all_enabled_engines_have_results(engines, existing_engine_names):
        return False

    assessment = calculate_risk(engine_results)
    update_scan_assessment(scan.id, assessment.verdict, assessment.score)
    update_scan_status(scan.id, "completed")
    print(f"Completed scan job {scan.id}", flush=True)
    return True


def process_next_scan_job() -> bool:
    engine_keys = worker_engine_keys()
    for scan in list_active_scans(limit=ACTIVE_SCAN_LIMIT):
        try:
            processed = process_scan(scan, engine_keys)
        except Exception as exc:
            update_scan_status(scan.id, "failed", last_error=str(exc))
            record_worker_heartbeat("error", active_scan_id=scan.id)
            print(f"Scan job {scan.id} failed", flush=True)
            traceback.print_exc()
            return True

        if processed:
            record_worker_heartbeat("idle")
            return True

    record_worker_heartbeat("idle")
    return False


def run_forever() -> None:
    init_db()
    seed_default_engines()
    engine_keys = worker_engine_keys()
    recovered = recover_running_scan_jobs()
    record_worker_heartbeat("starting")
    print(
        "MASP scan worker started "
        f"(engines: {', '.join(sorted(engine_keys)) or 'none'})",
        flush=True,
    )
    if recovered:
        print(f"Recovered {recovered} interrupted scan job(s)", flush=True)
    while True:
        processed = process_next_scan_job()
        if not processed:
            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_forever()
