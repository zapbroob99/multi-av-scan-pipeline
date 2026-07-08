import json
import os
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from app.database import (
    DatabaseOperationalError,
    claim_next_scan_engine_job,
    create_sample,
    create_scan_engine_jobs,
    create_scan_job,
    create_scan_worker_event,
    create_engine_result_if_missing,
    get_scan_batch,
    get_scan,
    init_db,
    list_active_scans,
    list_engine_results,
    list_scan_batch_scans,
    list_scan_engine_jobs,
    mark_scan_engine_job_running,
    mark_scan_engine_job_terminal,
    mark_scan_running,
    refresh_scan_batch_counts,
    recover_running_scan_jobs,
    update_scan_assessment,
    update_scan_status,
)
from app.models import (
    EngineInstanceRecord,
    EngineResultInput,
    EngineResultRecord,
    ScanEngineJobRecord,
    ScanRecord,
)
from app.services.engine_registry import (
    enabled_engines,
    run_engine,
    runtime_config,
    seed_default_engines,
)
from app.services.routing import (
    EngineRouteDecision,
    ROUTE_ACTION_RUN,
    ROUTE_ACTION_SKIP,
    ROUTE_REASON_WORKER_TIMEOUT,
    build_skipped_engine_result,
    route_engine_for_worker,
)
from app.services.scoring import RiskAssessment, calculate_risk
from app.services.archive_extractor import (
    ArchiveExtractionError,
    configured_archive_limits,
    configured_max_nested_levels,
    extract_archive,
    is_supported_archive,
)
from app.services.sample_paths import resolve_sample_path, sample_path_error
from app.services.worker_capabilities import (
    all_enabled_engines_have_results,
    worker_engine_keys,
)
from app.services.worker_runtime import record_worker_heartbeat, worker_is_running_scan_engine


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
WORKER_TIMING_EVENTS_ENABLED = os.getenv(
    "MASP_WORKER_TIMING_EVENTS_ENABLED",
    "1",
).strip().lower() not in {"0", "false", "no", "off"}
ENGINE_JOB_QUEUE_ENABLED = os.getenv(
    "MASP_ENGINE_JOB_QUEUE_ENABLED",
    "1",
).strip().lower() not in {"0", "false", "no", "off"}
LEGACY_SCAN_WORKER_FALLBACK_ENABLED = os.getenv(
    "MASP_LEGACY_SCAN_WORKER_FALLBACK_ENABLED",
    "0",
).strip().lower() in {"1", "true", "yes", "on"}
ENGINE_JOB_LEASE_SECONDS = int(os.getenv("MASP_ENGINE_JOB_LEASE_SECONDS", "120"))
ENGINE_JOB_TERMINAL_STATUSES = {"completed", "failed", "skipped"}
LAZY_ARCHIVE_TRIGGER_VERDICTS = {"medium", "high", "critical"}
WORKER_ID = (
    os.getenv("MASP_WORKER_ID")
    or os.getenv("HOSTNAME")
    or os.getenv("COMPUTERNAME")
    or f"pid-{os.getpid()}"
)


def elapsed_ms(started_at: float) -> int:
    return max(0, int((time.perf_counter() - started_at) * 1000))


def record_worker_timing_event(
    scan_id: int,
    event_name: str,
    engine_keys: set[str],
    *,
    engine_name: str | None = None,
    duration_ms: int | None = None,
    details: dict[str, object] | None = None,
) -> None:
    if not WORKER_TIMING_EVENTS_ENABLED:
        return

    try:
        create_scan_worker_event(
            scan_job_id=scan_id,
            event_name=event_name,
            worker_id=WORKER_ID,
            worker_engine_keys=",".join(sorted(engine_keys)),
            engine_name=engine_name,
            duration_ms=duration_ms,
            details_json=json.dumps(details or {}, sort_keys=True),
        )
    except DatabaseOperationalError as exc:
        print(f"Worker timing event could not be recorded: {exc}", flush=True)


def synthetic_engine_duration_ms() -> int:
    return 1


def process_next_scan_engine_job() -> bool:
    engine_keys = worker_engine_keys()
    job = claim_next_scan_engine_job(
        engine_keys,
        WORKER_ID,
        lease_seconds=ENGINE_JOB_LEASE_SECONDS,
    )
    if job is None:
        record_worker_heartbeat("idle")
        return False

    try:
        processed = process_scan_engine_job(job, engine_keys)
    except Exception as exc:
        mark_scan_engine_job_terminal(job.id, "failed", last_error=str(exc))
        try:
            update_scan_status(job.scan_job_id, "failed", last_error=str(exc))
        except DatabaseOperationalError as update_exc:
            print(
                f"Scan job {job.scan_job_id} failed, but status could not be recorded: {update_exc}",
                flush=True,
            )
        record_worker_timing_event(
            job.scan_job_id,
            "process_engine_job_failed",
            engine_keys,
            engine_name=job.engine_name,
            details={"engine_job_id": job.id, "error": str(exc)},
        )
        record_worker_heartbeat("error", active_scan_id=job.scan_job_id)
        print(f"Scan engine job {job.id} failed", flush=True)
        traceback.print_exc()
        return True

    record_worker_heartbeat("idle")
    return processed


def process_scan_engine_job(job: ScanEngineJobRecord, engine_keys: set[str]) -> bool:
    process_started_at = time.perf_counter()
    scan = get_scan(job.scan_job_id)
    if scan is None:
        mark_scan_engine_job_terminal(job.id, "failed", last_error="Scan not found.")
        return True

    record_worker_heartbeat("running", active_scan_id=scan.id)

    engines = enabled_engines()
    engine = find_engine_for_job(job, engines)
    if engine is None:
        mark_scan_engine_job_terminal(
            job.id,
            "skipped",
            last_error="Engine is no longer enabled for this scan.",
        )
        record_worker_timing_event(
            scan.id,
            "engine_job_skipped",
            engine_keys,
            engine_name=job.engine_name,
            duration_ms=elapsed_ms(process_started_at),
            details={"engine_job_id": job.id, "reason": "engine_not_enabled"},
        )
        finalize_scan_if_complete(scan, engines)
        return True

    decision = route_engine_for_worker(engine, scan, engine_keys)
    if decision.action == ROUTE_ACTION_SKIP:
        stage_started_at = time.perf_counter()
        mark_scan_running(scan.id)
        mark_scan_engine_job_running(
            job.id,
            WORKER_ID,
            lease_seconds=ENGINE_JOB_LEASE_SECONDS,
        )
        create_engine_result_if_missing(
            scan.id,
            build_skipped_engine_result(
                decision,
                duration_ms=synthetic_engine_duration_ms(),
            ),
        )
        mark_scan_engine_job_terminal(job.id, "skipped", last_error=decision.reason)
        record_worker_timing_event(
            scan.id,
            "engine_job_skip",
            engine_keys,
            engine_name=engine.display_name,
            duration_ms=elapsed_ms(stage_started_at),
            details={
                "engine_job_id": job.id,
                "reason_code": decision.reason_code,
            },
        )
        finalize_scan_if_complete(refresh_scan_record(scan), engines)
        return True

    if decision.action != ROUTE_ACTION_RUN:
        mark_scan_engine_job_terminal(job.id, "failed", last_error=decision.reason)
        record_worker_timing_event(
            scan.id,
            "engine_job_not_runnable",
            engine_keys,
            engine_name=engine.display_name,
            duration_ms=elapsed_ms(process_started_at),
            details={
                "engine_job_id": job.id,
                "reason_code": decision.reason_code,
                "reason": decision.reason,
            },
        )
        return True

    stage_started_at = time.perf_counter()
    mark_scan_running(scan.id)
    scan = refresh_scan_record(scan)
    mark_scan_engine_job_running(
        job.id,
        WORKER_ID,
        lease_seconds=ENGINE_JOB_LEASE_SECONDS,
    )
    record_worker_timing_event(
        scan.id,
        "mark_engine_job_running",
        engine_keys,
        engine_name=engine.display_name,
        duration_ms=elapsed_ms(stage_started_at),
        details={"engine_job_id": job.id},
    )

    print(f"Running {engine.display_name} for scan job {scan.id}", flush=True)
    stage_started_at = time.perf_counter()
    result = run_engine(engine, scan)
    result_id = create_engine_result_if_missing(scan.id, result)
    terminal_status = engine_job_terminal_status(result.status)
    mark_scan_engine_job_terminal(
        job.id,
        terminal_status,
        last_error=result.error_message,
    )
    record_worker_timing_event(
        scan.id,
        "engine_job_run",
        engine_keys,
        engine_name=engine.display_name,
        duration_ms=elapsed_ms(stage_started_at),
        details={
            "engine_job_id": job.id,
            "adapter_duration_ms": result.duration_ms,
            "result_created": result_id is not None,
            "result_status": result.status,
            "job_status": terminal_status,
        },
    )

    stage_started_at = time.perf_counter()
    finalized = finalize_scan_if_complete(refresh_scan_record(scan), engines)
    record_worker_timing_event(
        scan.id,
        "finalize",
        engine_keys,
        duration_ms=elapsed_ms(stage_started_at),
        details={"completed": finalized, "engine_job_id": job.id},
    )
    record_worker_timing_event(
        scan.id,
        "process_engine_job",
        engine_keys,
        engine_name=engine.display_name,
        duration_ms=elapsed_ms(process_started_at),
        details={"engine_job_id": job.id, "completed": finalized},
    )
    return True


def process_scan(scan: ScanRecord, engine_keys: set[str]) -> bool:
    process_started_at = time.perf_counter()
    record_worker_heartbeat("running", active_scan_id=scan.id)

    stage_started_at = time.perf_counter()
    engines = enabled_engines()
    engine_results = list_engine_results(scan.id)
    existing_engine_names = {result.engine_name for result in engine_results}
    missing_enabled_engines = missing_enabled_engine_instances(engines, existing_engine_names)
    route_decisions = route_missing_engines(scan, missing_enabled_engines, engine_keys)
    runnable_decisions = [decision for decision in route_decisions if decision.action == ROUTE_ACTION_RUN]
    skipped_decisions = [decision for decision in route_decisions if decision.action == ROUTE_ACTION_SKIP]
    record_worker_timing_event(
        scan.id,
        "load_context",
        engine_keys,
        duration_ms=elapsed_ms(stage_started_at),
        details={
            "enabled_engines": len(engines),
            "existing_results": len(engine_results),
            "missing_engines": [engine.display_name for engine in missing_enabled_engines],
            "runnable_engines": [decision.engine.display_name for decision in runnable_decisions],
            "skipped_engines": [decision.engine.display_name for decision in skipped_decisions],
            "waiting_engines": [
                decision.engine.display_name
                for decision in route_decisions
                if decision not in runnable_decisions and decision not in skipped_decisions
            ],
        },
    )

    if skipped_decisions or runnable_decisions:
        stage_started_at = time.perf_counter()
        mark_scan_running(scan.id)
        scan = refresh_scan_record(scan)
        record_worker_timing_event(
            scan.id,
            "mark_running",
            engine_keys,
            duration_ms=elapsed_ms(stage_started_at),
        )
        for decision in skipped_decisions:
            stage_started_at = time.perf_counter()
            create_engine_result_if_missing(
                scan.id,
                build_skipped_engine_result(
                    decision,
                    duration_ms=synthetic_engine_duration_ms(),
                ),
            )
            record_worker_timing_event(
                scan.id,
                "create_skipped_result",
                engine_keys,
                engine_name=decision.engine.display_name,
                duration_ms=elapsed_ms(stage_started_at),
                details={"reason_code": decision.reason_code},
            )

    if skipped_decisions:
        stage_started_at = time.perf_counter()
        engine_results = list_engine_results(scan.id)
        existing_engine_names = {result.engine_name for result in engine_results}
        missing_enabled_engines = missing_enabled_engine_instances(engines, existing_engine_names)
        record_worker_timing_event(
            scan.id,
            "reload_after_skips",
            engine_keys,
            duration_ms=elapsed_ms(stage_started_at),
            details={
                "existing_results": len(engine_results),
                "missing_engines": [engine.display_name for engine in missing_enabled_engines],
            },
        )

    if not runnable_decisions:
        if not skipped_decisions and not should_attempt_passive_finalize(scan, missing_enabled_engines):
            record_worker_timing_event(
                scan.id,
                "passive_defer",
                engine_keys,
                duration_ms=elapsed_ms(process_started_at),
                details={
                    "missing_engines": [engine.display_name for engine in missing_enabled_engines],
                },
            )
            return False
        scan = refresh_scan_record(scan)
        stage_started_at = time.perf_counter()
        finalized = finalize_scan_if_complete_or_timeout(
            scan,
            engines,
            missing_enabled_engines,
            engine_keys=engine_keys,
        )
        record_worker_timing_event(
            scan.id,
            "finalize",
            engine_keys,
            duration_ms=elapsed_ms(stage_started_at),
            details={
                "completed": finalized,
                "missing_engines": [engine.display_name for engine in missing_enabled_engines],
            },
        )
        record_worker_timing_event(
            scan.id,
            "process_scan",
            engine_keys,
            duration_ms=elapsed_ms(process_started_at),
            details={"changed_scan": bool(skipped_decisions), "completed": finalized},
        )
        return bool(skipped_decisions)

    for decision in runnable_decisions:
        engine = decision.engine
        print(f"Running {engine.display_name} for scan job {scan.id}", flush=True)
        stage_started_at = time.perf_counter()
        result = run_engine(engine, scan)
        result_id = create_engine_result_if_missing(scan.id, result)
        record_worker_timing_event(
            scan.id,
            "engine_run",
            engine_keys,
            engine_name=engine.display_name,
            duration_ms=elapsed_ms(stage_started_at),
            details={
                "adapter_duration_ms": result.duration_ms,
                "result_created": result_id is not None,
                "result_status": result.status,
            },
        )

    stage_started_at = time.perf_counter()
    engine_results = list_engine_results(scan.id)
    existing_engine_names = {result.engine_name for result in engine_results}
    missing_after_run = missing_enabled_engine_instances(engines, existing_engine_names)
    scan = refresh_scan_record(scan)
    finalized = finalize_scan_if_complete_or_timeout(
        scan,
        engines,
        missing_after_run,
        engine_keys=engine_keys,
    )
    record_worker_timing_event(
        scan.id,
        "finalize",
        engine_keys,
        duration_ms=elapsed_ms(stage_started_at),
        details={
            "completed": finalized,
            "existing_results": len(engine_results),
            "missing_engines": [engine.display_name for engine in missing_after_run],
        },
    )
    record_worker_timing_event(
        scan.id,
        "process_scan",
        engine_keys,
        duration_ms=elapsed_ms(process_started_at),
        details={"changed_scan": True, "completed": finalized},
    )
    return True


def finalize_scan_if_complete_or_timeout(
    scan: ScanRecord,
    engines: list[EngineInstanceRecord],
    missing_engines: list[EngineInstanceRecord],
    engine_keys: set[str],
) -> bool:
    if missing_engines and should_finalize_scan_with_partial_results(scan, missing_engines):
        wait_seconds = partial_results_wait_seconds(missing_engines)
        for engine in missing_engines:
            if worker_is_running_scan_engine(scan.id, engine.adapter_key):
                continue
            create_engine_result_if_missing(
                scan.id,
                skipped_engine_result(scan, engine, engine_keys, wait_seconds),
            )

    engine_results = list_engine_results(scan.id)
    existing_engine_names = {result.engine_name for result in engine_results}
    if not all_enabled_engines_have_results(engines, existing_engine_names):
        return False

    assessment = calculate_risk(engine_results)
    update_scan_assessment(scan.id, assessment.verdict, assessment.score)
    update_scan_status(scan.id, "completed")
    maybe_enqueue_lazy_archive_children(scan, assessment, engine_results, engines, engine_keys)
    print(f"Completed scan job {scan.id}", flush=True)
    return True


def finalize_scan_if_complete(
    scan: ScanRecord,
    engines: list[EngineInstanceRecord],
) -> bool:
    engine_results = list_engine_results(scan.id)
    existing_engine_names = {result.engine_name for result in engine_results}
    if ENGINE_JOB_QUEUE_ENABLED:
        engine_jobs = list_scan_engine_jobs(scan.id)
        if engine_jobs:
            if not all_scan_engine_jobs_terminal(engine_jobs):
                return False
            required_engine_names = required_engine_job_result_names(engine_jobs, engines)
            if not required_engine_names.issubset(existing_engine_names):
                return False
        elif not all_enabled_engines_have_results(engines, existing_engine_names):
            return False
    elif not all_enabled_engines_have_results(engines, existing_engine_names):
        return False

    assessment = calculate_risk(engine_results)
    update_scan_assessment(scan.id, assessment.verdict, assessment.score)
    update_scan_status(scan.id, "completed")
    maybe_enqueue_lazy_archive_children(scan, assessment, engine_results, engines, set())
    print(f"Completed scan job {scan.id}", flush=True)
    return True


def maybe_enqueue_lazy_archive_children(
    scan: ScanRecord,
    assessment: RiskAssessment,
    engine_results: list[EngineResultRecord],
    engines: list[EngineInstanceRecord],
    engine_keys: set[str],
) -> int:
    if scan.scan_role not in {"container", "child"} or scan.batch_id is None:
        return 0

    batch = get_scan_batch(scan.batch_id)
    if batch is None or batch.archive_mode != "lazy_extract_on_detection":
        return 0

    detected = any(
        getattr(result, "status", "") == "completed"
        and bool(getattr(result, "detected", False))
        for result in engine_results
    )
    verdict = assessment.verdict
    if not detected and verdict not in LAZY_ARCHIVE_TRIGGER_VERDICTS:
        refresh_scan_batch_counts(batch.id)
        return 0

    archive_path = resolve_sample_path(scan)
    if scan.scan_role == "child" and (
        not archive_path.is_file() or not is_supported_archive(archive_path)
    ):
        # Most detected children are plain files, not nested archives.
        refresh_scan_batch_counts(batch.id)
        return 0

    limits = configured_archive_limits()
    existing_scans = list_scan_batch_scans(batch.id, limit=limits.max_files + 1)
    if any(
        existing_scan.scan_role == "child" and existing_scan.parent_scan_id == scan.id
        for existing_scan in existing_scans
    ):
        refresh_scan_batch_counts(batch.id)
        return 0

    child_level = archive_nesting_level(scan, existing_scans) + 1
    max_nested_levels = configured_max_nested_levels()
    if child_level > max_nested_levels:
        record_worker_timing_event(
            scan.id,
            "archive_nested_level_exceeded",
            engine_keys,
            details={
                "batch_id": batch.id,
                "nesting_level": child_level,
                "max_nested_levels": max_nested_levels,
            },
        )
        refresh_scan_batch_counts(batch.id)
        return 0

    existing_children = sum(
        1 for existing_scan in existing_scans if existing_scan.scan_role == "child"
    )
    remaining_child_budget = limits.max_files - existing_children

    if not archive_path.is_file():
        record_worker_timing_event(
            scan.id,
            "archive_lazy_extract_failed",
            engine_keys,
            details={
                "batch_id": batch.id,
                "error": sample_path_error(scan, archive_path),
            },
        )
        refresh_scan_batch_counts(batch.id)
        return 0

    try:
        extraction = extract_archive(archive_path)
    except ArchiveExtractionError as exc:
        record_worker_timing_event(
            scan.id,
            "archive_lazy_extract_failed",
            engine_keys,
            details={
                "batch_id": batch.id,
                "error": str(exc),
            },
        )
        refresh_scan_batch_counts(batch.id)
        return 0

    if len(extraction.members) > remaining_child_budget:
        # Creating a partial child set would silently understate coverage, so
        # nothing is enqueued and the skip is recorded as an explicit event.
        for member in extraction.members:
            Path(member.sample.storage_path).unlink(missing_ok=True)
        record_worker_timing_event(
            scan.id,
            "archive_batch_child_limit_reached",
            engine_keys,
            details={
                "batch_id": batch.id,
                "extracted_members": len(extraction.members),
                "remaining_child_budget": max(0, remaining_child_budget),
                "max_files": limits.max_files,
            },
        )
        refresh_scan_batch_counts(batch.id)
        return 0

    relative_prefix = (
        f"{scan.relative_path}/" if scan.scan_role == "child" and scan.relative_path else ""
    )
    created_children = 0
    for member in extraction.members:
        sample_id = create_sample(member.sample)
        child_scan_id = create_scan_job(
            sample_id=sample_id,
            case_name=scan.case_name,
            priority=scan.priority,
            note=scan.note,
            source=scan.source,
            batch_id=batch.id,
            parent_scan_id=scan.id,
            relative_path=f"{relative_prefix}{member.relative_path}",
            scan_role="child",
        )
        create_scan_engine_jobs(child_scan_id, engines)
        created_children += 1

    refresh_scan_batch_counts(batch.id)
    record_worker_timing_event(
        scan.id,
        "archive_lazy_extract",
        engine_keys,
        details={
            "batch_id": batch.id,
            "created_children": created_children,
            "nesting_level": child_level,
            "total_uncompressed_bytes": extraction.total_uncompressed_bytes,
        },
    )
    return created_children


def archive_nesting_level(scan: ScanRecord, batch_scans: list[ScanRecord]) -> int:
    """Hop count from this scan up to the batch container (container = 0)."""
    scans_by_id = {batch_scan.id: batch_scan for batch_scan in batch_scans}
    level = 0
    current = scan
    while current.parent_scan_id is not None and level < 32:
        parent = scans_by_id.get(current.parent_scan_id) or get_scan(current.parent_scan_id)
        if parent is None:
            break
        level += 1
        current = parent
    return level


def all_scan_engine_jobs_terminal(jobs: list[ScanEngineJobRecord]) -> bool:
    return all(job.status in ENGINE_JOB_TERMINAL_STATUSES for job in jobs)


def required_engine_job_result_names(
    jobs: list[ScanEngineJobRecord],
    engines: list[EngineInstanceRecord],
) -> set[str]:
    enabled_engine_ids = {engine.id for engine in engines}
    enabled_engine_keys = {engine.adapter_key for engine in engines}
    return {
        job.engine_name
        for job in jobs
        if job.engine_key in enabled_engine_keys
        or (
            job.engine_instance_id is not None
            and job.engine_instance_id in enabled_engine_ids
        )
    }


def find_engine_for_job(
    job: ScanEngineJobRecord,
    engines: list[EngineInstanceRecord],
) -> EngineInstanceRecord | None:
    for engine in engines:
        if job.engine_instance_id is not None and engine.id == job.engine_instance_id:
            return engine
        if engine.adapter_key == job.engine_key:
            return engine
    return None


def engine_job_terminal_status(result_status: str) -> str:
    if result_status in {"completed", "failed", "skipped"}:
        return result_status
    return "completed"


def missing_enabled_engine_instances(
    engines: list[EngineInstanceRecord],
    existing_engine_names: set[str],
) -> list[EngineInstanceRecord]:
    return [
        engine
        for engine in engines
        if engine.display_name not in existing_engine_names
    ]


def refresh_scan_record(scan: ScanRecord) -> ScanRecord:
    refreshed = get_scan(scan.id)
    return refreshed if refreshed is not None else scan


def should_attempt_passive_finalize(
    scan: ScanRecord,
    missing_engines: list[EngineInstanceRecord],
) -> bool:
    if not missing_engines:
        return True
    return should_finalize_scan_with_partial_results(scan, missing_engines)


def route_missing_engines(
    scan: ScanRecord,
    engines: list[EngineInstanceRecord],
    engine_keys: set[str],
) -> list[EngineRouteDecision]:
    return [
        route_engine_for_worker(engine, scan, engine_keys)
        for engine in engines
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
    engine_keys: set[str],
    wait_seconds: int | None = None,
) -> EngineResultInput:
    effective_wait_seconds = (
        partial_results_wait_seconds([engine])
        if wait_seconds is None
        else wait_seconds
    )
    deferred_decision = route_engine_for_worker(engine, scan, engine_keys)
    message = (
        "No compatible worker recorded a result before the orchestration wait window "
        f"expired ({effective_wait_seconds}s)."
    )
    timeout_decision = EngineRouteDecision(
        engine=engine,
        action=ROUTE_ACTION_SKIP,
        reason_code=ROUTE_REASON_WORKER_TIMEOUT,
        reason=message,
        details={
            **deferred_decision.details,
            "orchestration": {
                "reason": ROUTE_REASON_WORKER_TIMEOUT,
                "wait_seconds": effective_wait_seconds,
                "elapsed_seconds": scan_elapsed_seconds(scan),
            },
            "deferred_reason_code": deferred_decision.reason_code,
            "deferred_reason": deferred_decision.reason,
        },
    )
    return build_skipped_engine_result(
        timeout_decision,
        duration_ms=synthetic_engine_duration_ms(),
        error_message=message,
        raw_output=message,
    )


def process_next_scan_job() -> bool:
    if ENGINE_JOB_QUEUE_ENABLED:
        processed = process_next_scan_engine_job()
        if processed or not LEGACY_SCAN_WORKER_FALLBACK_ENABLED:
            return processed

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
            record_worker_timing_event(
                scan.id,
                "process_scan_failed",
                engine_keys,
                details={"error": str(exc)},
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
