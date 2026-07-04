import json
import os
import time
import traceback
from datetime import datetime, timezone

from app.database import (
    DatabaseOperationalError,
    create_engine_result_if_missing,
    init_db,
    list_active_scans,
    list_engine_results,
    mark_scan_running,
    recover_running_scan_jobs,
    update_scan_assessment,
    update_scan_status,
)
from app.models import EngineInstanceRecord, EngineResultInput, ScanRecord
from app.services.engine_registry import (
    enabled_engines,
    run_engine,
    runtime_config,
    seed_default_engines,
)
from app.services.scoring import calculate_risk
from app.services.worker_capabilities import (
    all_enabled_engines_have_results,
    missing_supported_engines,
    worker_engine_keys,
)
from app.services.worker_runtime import record_worker_heartbeat


POLL_INTERVAL_SECONDS = float(os.getenv("MASP_WORKER_POLL_SECONDS", "2"))
ACTIVE_SCAN_LIMIT = int(os.getenv("MASP_WORKER_ACTIVE_SCAN_LIMIT", "20"))
PARTIAL_RESULTS_MAX_WAIT_SECONDS = int(
    os.getenv("MASP_SCAN_PARTIAL_RESULTS_MAX_WAIT_SECONDS", "120")
)
PARTIAL_RESULTS_MIN_WAIT_SECONDS = int(
    os.getenv("MASP_SCAN_PARTIAL_RESULTS_MIN_WAIT_SECONDS", "15")
)
ENGINE_TIMEOUT_GRACE_SECONDS = int(
    os.getenv("MASP_ENGINE_TIMEOUT_GRACE_SECONDS", "5")
)


def process_scan(scan: ScanRecord, engine_keys: set[str]) -> bool:
    record_worker_heartbeat("running", active_scan_id=scan.id)
    engines = enabled_engines()
    engine_results = list_engine_results(scan.id)
    existing_engine_names = {result.engine_name for result in engine_results}
    missing_enabled_engines = missing_enabled_engine_instances(engines, existing_engine_names)
    missing_supported = missing_supported_engines(
        engines,
        existing_engine_names,
        engine_keys,
    )

    if not missing_supported:
        finalize_scan_if_complete_or_timeout(
            scan,
            engines,
            missing_enabled_engines,
        )
        return False

    mark_scan_running(scan.id)
    for engine in missing_supported:
        print(f"Running {engine.display_name} for scan job {scan.id}", flush=True)
        create_engine_result_if_missing(scan.id, run_engine(engine, scan))

    engine_results = list_engine_results(scan.id)
    existing_engine_names = {result.engine_name for result in engine_results}
    finalize_scan_if_complete_or_timeout(
        scan,
        engines,
        missing_enabled_engine_instances(engines, existing_engine_names),
    )
    return True


def finalize_scan_if_complete_or_timeout(
    scan: ScanRecord,
    engines: list[EngineInstanceRecord],
    missing_engines: list[EngineInstanceRecord],
) -> bool:
    if missing_engines and should_finalize_scan_with_partial_results(scan, missing_engines):
        wait_seconds = partial_results_wait_seconds(missing_engines)
        for engine in missing_engines:
            create_engine_result_if_missing(
                scan.id,
                skipped_engine_result(scan, engine, wait_seconds),
            )

    engine_results = list_engine_results(scan.id)
    existing_engine_names = {result.engine_name for result in engine_results}
    if not all_enabled_engines_have_results(engines, existing_engine_names):
        return False

    assessment = calculate_risk(engine_results)
    update_scan_assessment(scan.id, assessment.verdict, assessment.score)
    update_scan_status(scan.id, "completed")
    print(f"Completed scan job {scan.id}", flush=True)
    return True


def missing_enabled_engine_instances(
    engines: list[EngineInstanceRecord],
    existing_engine_names: set[str],
) -> list[EngineInstanceRecord]:
    return [
        engine
        for engine in engines
        if engine.display_name not in existing_engine_names
    ]


def should_finalize_scan_with_partial_results(
    scan: ScanRecord,
    missing_engines: list[EngineInstanceRecord],
) -> bool:
    if not missing_engines:
        return False
    return scan_elapsed_seconds(scan) >= partial_results_wait_seconds(missing_engines)


def partial_results_wait_seconds(
    missing_engines: list[EngineInstanceRecord],
) -> int:
    configured_timeouts = []
    for engine in missing_engines:
        timeout_value = runtime_config(engine).get("timeout_seconds")
        try:
            configured_timeouts.append(int(timeout_value))
        except (TypeError, ValueError):
            continue

    if configured_timeouts:
        derived_timeout = max(configured_timeouts) + ENGINE_TIMEOUT_GRACE_SECONDS
    else:
        derived_timeout = PARTIAL_RESULTS_MAX_WAIT_SECONDS

    return max(
        PARTIAL_RESULTS_MIN_WAIT_SECONDS,
        min(derived_timeout, PARTIAL_RESULTS_MAX_WAIT_SECONDS),
    )


def scan_elapsed_seconds(scan: ScanRecord, now: datetime | None = None) -> int:
    reference_text = scan.started_at or scan.created_at
    started_at = parse_scan_timestamp(reference_text)
    current_time = datetime.now(timezone.utc) if now is None else now
    return max(0, int((current_time - started_at).total_seconds()))


def parse_scan_timestamp(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def skipped_engine_result(
    scan: ScanRecord,
    engine: EngineInstanceRecord,
    wait_seconds: int | None = None,
) -> EngineResultInput:
    effective_wait_seconds = (
        partial_results_wait_seconds([engine])
        if wait_seconds is None
        else wait_seconds
    )
    message = (
        "No compatible worker recorded a result before the orchestration wait window "
        f"expired ({effective_wait_seconds}s)."
    )
    details = {
        "adapter": engine.adapter_key,
        "orchestration": {
            "reason": "worker_timeout",
            "wait_seconds": effective_wait_seconds,
        },
        "sample": {
            "filename": scan.original_filename,
            "sha256": scan.sha256,
            "size_bytes": scan.size_bytes,
        },
    }
    return EngineResultInput(
        engine_name=engine.display_name,
        status="skipped",
        detected=False,
        severity="info",
        confidence=0,
        signature=None,
        raw_output=message,
        error_message=message,
        duration_ms=max(1, scan_elapsed_seconds(scan) * 1000),
        details_json=json.dumps(details, sort_keys=True),
    )


def process_next_scan_job() -> bool:
    engine_keys = worker_engine_keys()
    for scan in list_active_scans(limit=ACTIVE_SCAN_LIMIT):
        try:
            processed = process_scan(scan, engine_keys)
        except Exception as exc:
            try:
                update_scan_status(scan.id, "failed", last_error=str(exc))
            except DatabaseOperationalError as update_exc:
                print(
                    f"Scan job {scan.id} failed, but status could not be recorded: {update_exc}",
                    flush=True,
                )
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
        try:
            processed = process_next_scan_job()
        except DatabaseOperationalError as exc:
            print(f"Worker database operation failed, retrying: {exc}", flush=True)
            record_worker_heartbeat("error")
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        if not processed:
            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_forever()
