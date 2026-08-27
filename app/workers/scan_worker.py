import contextlib
import json
import os
import threading
import time
import traceback
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from app.database import (
    DatabaseOperationalError,
    claim_next_scan_engine_job,
    claim_scan_finalization,
    complete_finalizing_scan,
    commit_engine_job_result_if_owned,
    renew_scan_finalization,
    StaleFinalizerError,
    mark_scan_engine_job_terminal_if_owned,
    renew_scan_engine_job_lease,
    create_archive_child,
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
    mark_scan_running,
    skip_pending_scan_engine_job,
    refresh_scan_batch_counts,
    recover_running_scan_jobs,
    record_engine_node_scan_success,
    filter_referenced_storage_paths,
    get_scan_statuses,
    remove_orphan_child_sample,
    transition_scan_to_completed,
    update_scan_status,
)
from app.models import (
    EngineInstanceRecord,
    EngineResultInput,
    EngineResultRecord,
    ScanEngineJobRecord,
    ScanRecord,
    TERMINAL_SCAN_STATUSES,
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
    cleanup_stale_staging_dirs,
    configured_archive_limits,
    configured_max_nested_levels,
    deterministic_child_stored_filename,
    extract_archive,
    is_supported_archive,
    new_staging_dir,
    parse_child_parent_scan_id,
    promote_staged_file,
    remove_staging_dir,
)
from app.services.sample_paths import SAMPLES_DIR, resolve_sample_path, sample_path_error
from app.services.worker_capabilities import (
    all_enabled_engines_have_results,
    worker_engine_keys,
)
from app.services.worker_runtime import (
    current_worker_node_id,
    current_worker_process_id,
    get_worker_status,
    record_worker_heartbeat,
    worker_accepts_new_work,
    worker_is_running_scan_engine,
)
from app.services.worker_scheduling import (
    eligible_engine_instance_ids_for_node,
    schedulable_engine_instance_ids,
)
from app.services.service_clients import (
    engines_for_scan as profile_engines_for_scan,
    seed_legacy_service_client,
)
from app.services.worker_health import run_due_worker_health_checks


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


def engines_for_scan(scan: ScanRecord) -> list[EngineInstanceRecord]:
    """Use immutable profile routing, with global fallback for legacy scans."""
    snapshot = getattr(scan, "profile_snapshot_json", "") or ""
    if getattr(scan, "scan_profile_id", None) is not None or snapshot not in {"", "{}"}:
        return profile_engines_for_scan(scan)
    return enabled_engines(source=scan.source)


LEGACY_SCAN_WORKER_FALLBACK_ENABLED = os.getenv(
    "MASP_LEGACY_SCAN_WORKER_FALLBACK_ENABLED",
    "0",
).strip().lower() in {"1", "true", "yes", "on"}
ENGINE_JOB_LEASE_SECONDS = int(os.getenv("MASP_ENGINE_JOB_LEASE_SECONDS", "120"))
ORPHANED_ENGINE_JOB_REAP_ENABLED = os.getenv(
    "MASP_ORPHANED_ENGINE_JOB_REAP_ENABLED",
    "1",
).strip().lower() not in {"0", "false", "no", "off"}
ENGINE_JOB_RECOVERY_ENABLED = os.getenv(
    "MASP_ENGINE_JOB_RECOVERY_ENABLED",
    "1",
).strip().lower() not in {"0", "false", "no", "off"}
ENGINE_JOB_MAX_ATTEMPTS = int(os.getenv("MASP_ENGINE_JOB_MAX_ATTEMPTS", "5"))
# Lease for the finalize claim (assessment + archive-child extraction + complete).
FINALIZE_LEASE_SECONDS = int(os.getenv("MASP_FINALIZE_LEASE_SECONDS", "120"))
# Extra headroom added to an engine's own hard timeout when leasing its job, so a
# legitimately long run never has its lease expire mid-scan and get reclaimed.
ENGINE_JOB_LEASE_GRACE_SECONDS = int(os.getenv("MASP_ENGINE_JOB_LEASE_GRACE_SECONDS", "60"))
# Maintenance (recovery, reaper, finalizer sweep) runs on this cadence
# independent of load, so a stuck scan is recovered even while the queue is busy.
MAINTENANCE_INTERVAL_SECONDS = max(
    5, int(os.getenv("MASP_WORKER_MAINTENANCE_INTERVAL_SECONDS", "30"))
)
ENGINE_JOB_TERMINAL_STATUSES = {"completed", "failed", "skipped"}
LAZY_ARCHIVE_TRIGGER_VERDICTS = {"medium", "high", "critical"}
WORKER_ID = current_worker_process_id()
WORKER_NODE_ID = current_worker_node_id()


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


def engine_lease_seconds(engine: EngineInstanceRecord) -> int:
    """Lease long enough to outlast this engine's own hard timeout plus grace.

    A flat lease shorter than an engine's timeout (e.g. 120s lease vs a 180s
    ClamAV timeout) would let a legitimately long run's lease expire and be
    reclaimed mid-scan. Deriving the lease from the engine's configured timeout
    keeps an expired lease meaning "no longer authorized", not "still working".
    """
    try:
        timeout = int(runtime_config(engine).get("timeout_seconds") or 0)
    except (TypeError, ValueError):
        timeout = 0
    return max(ENGINE_JOB_LEASE_SECONDS, timeout + ENGINE_JOB_LEASE_GRACE_SECONDS)


def lease_renewal_interval(lease_seconds: int) -> float:
    """Renew roughly three times per lease, so two missed renewals still fit."""
    return max(5.0, lease_seconds / 3.0)


@contextlib.contextmanager
def finalization_lease_renewal(scan_id: int, generation: int, lease_seconds: int):
    """Renew the finalization lease while long work (archive extraction) runs.

    Extraction runtime is not bounded by a wall-clock guarantee, so without
    renewal a long extraction could let the finalize lease expire and be stolen.
    The renewer is fenced to this owner+generation and stopped/joined on exit
    (before completion, which is itself fenced). If it loses ownership it stops;
    the child-intake fence and the fenced completion then reject any stale work.
    """
    stop = threading.Event()
    interval = lease_renewal_interval(lease_seconds)

    def renew_loop() -> None:
        while not stop.wait(interval):
            try:
                if not renew_scan_finalization(
                    scan_id, WORKER_ID, generation, lease_seconds
                ):
                    return  # ownership lost; stop renewing
            except DatabaseOperationalError:
                continue

    renewer = threading.Thread(
        target=renew_loop, name=f"finalize-renew-{scan_id}", daemon=True
    )
    renewer.start()
    try:
        yield
    finally:
        stop.set()
        renewer.join()


def run_engine_with_lease_renewal(
    engine: EngineInstanceRecord,
    scan: ScanRecord,
    job: ScanEngineJobRecord,
    lease_seconds: int,
) -> EngineResultInput:
    """Run an engine while a background thread renews the job's lease.

    ``timeout_seconds`` is not the true maximum runtime — an engine can chain
    several timeouts (YARA per-rule-file fallback, Defender health+update+scan,
    ClamAV readiness+scan) — so a fixed lease can still expire mid-run. The
    renewer extends the lease (fenced to this owner+generation) until the run
    finishes; it is stopped and joined BEFORE the result is committed. If it ever
    loses ownership it stops, and the fenced commit rejects the result anyway.
    """
    stop = threading.Event()
    interval = lease_renewal_interval(lease_seconds)

    def renew_loop() -> None:
        while not stop.wait(interval):
            try:
                if not renew_scan_engine_job_lease(
                    job.id, WORKER_ID, job.attempt_count, lease_seconds
                ):
                    return  # ownership lost; stop renewing
            except DatabaseOperationalError:
                continue  # transient; try again next interval

    renewer = threading.Thread(
        target=renew_loop, name=f"lease-renew-{job.id}", daemon=True
    )
    renewer.start()
    try:
        return run_engine(engine, scan)
    finally:
        stop.set()
        renewer.join()


def process_next_scan_engine_job() -> bool:
    engine_keys = worker_engine_keys()
    eligible_instance_ids = eligible_engine_instance_ids_for_node(
        WORKER_NODE_ID,
        engine_keys,
    )
    job = claim_next_scan_engine_job(
        engine_keys,
        WORKER_ID,
        worker_node_id=WORKER_NODE_ID,
        eligible_engine_instance_ids=eligible_instance_ids,
        lease_seconds=ENGINE_JOB_LEASE_SECONDS,
        max_attempts=ENGINE_JOB_MAX_ATTEMPTS,
    )
    if job is None:
        # Maintenance (recovery/reaper/sweep) is driven by the periodic tick in
        # run_forever, not here, so it also runs while the queue is busy.
        record_worker_heartbeat("idle")
        return False

    try:
        processed = process_scan_engine_job(job, engine_keys)
    except Exception as exc:
        # Fence the failure: only mark the job (and the scan) failed if this
        # worker still owns the job. A superseded worker whose adapter raised
        # must not fail the new owner's job or the whole scan.
        owned = mark_scan_engine_job_terminal_if_owned(
            job.id, WORKER_ID, job.attempt_count, "failed", last_error=str(exc)
        )
        if owned:
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
        mark_scan_engine_job_terminal_if_owned(
            job.id, WORKER_ID, job.attempt_count, "failed", last_error="Scan not found."
        )
        return True

    record_worker_heartbeat("running", active_scan_id=scan.id)

    engines = engines_for_scan(scan)
    engine = find_engine_for_job(job, engines)
    if engine is None:
        mark_scan_engine_job_terminal_if_owned(
            job.id,
            WORKER_ID,
            job.attempt_count,
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

    lease_seconds = engine_lease_seconds(engine)
    decision = route_engine_for_worker(engine, scan, engine_keys)
    if decision.action == ROUTE_ACTION_SKIP:
        stage_started_at = time.perf_counter()
        mark_scan_running(scan.id)
        mark_scan_engine_job_running(
            job.id,
            WORKER_ID,
            lease_seconds=lease_seconds,
            attempt_generation=job.attempt_count,
        )
        commit_engine_job_result_if_owned(
            job_id=job.id,
            worker_id=WORKER_ID,
            attempt_generation=job.attempt_count,
            result=build_skipped_engine_result(
                decision,
                duration_ms=synthetic_engine_duration_ms(),
            ),
            terminal_status="skipped",
            last_error=decision.reason,
        )
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
        mark_scan_engine_job_terminal_if_owned(
            job.id, WORKER_ID, job.attempt_count, "failed", last_error=decision.reason
        )
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
    if not mark_scan_engine_job_running(
        job.id,
        WORKER_ID,
        lease_seconds=lease_seconds,
        attempt_generation=job.attempt_count,
    ):
        # Ownership was already lost before the run started; another worker has
        # this job. Do nothing and let that worker produce the result.
        record_worker_timing_event(
            scan.id,
            "engine_job_ownership_lost",
            engine_keys,
            engine_name=engine.display_name,
            details={"engine_job_id": job.id, "stage": "pre_run"},
        )
        return True
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
    result = run_engine_with_lease_renewal(engine, scan, job, lease_seconds)
    terminal_status = engine_job_terminal_status(result.status)
    committed = commit_engine_job_result_if_owned(
        job_id=job.id,
        worker_id=WORKER_ID,
        attempt_generation=job.attempt_count,
        result=result,
        terminal_status=terminal_status,
        last_error=result.error_message,
    )
    if not committed:
        # The lease expired and the job was re-claimed while this engine ran, so
        # this worker is no longer authorized to commit. Discard the result — the
        # new owner will produce the authoritative one — and do not finalize.
        record_worker_timing_event(
            scan.id,
            "engine_job_ownership_lost",
            engine_keys,
            engine_name=engine.display_name,
            duration_ms=elapsed_ms(stage_started_at),
            details={"engine_job_id": job.id, "stage": "post_run"},
        )
        return True
    if result.status == "completed":
        record_engine_node_scan_success(
            WORKER_NODE_ID,
            engine.id,
            engine_version=result.engine_version,
            signature_version=result.signature_version,
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
    engines = engines_for_scan(scan)
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
    if not transition_scan_to_completed(scan.id, assessment.verdict, assessment.score):
        return False
    maybe_enqueue_lazy_archive_children(scan, assessment, engine_results, engines, engine_keys)
    print(f"Completed scan job {scan.id}", flush=True)
    return True


def backfill_missing_engine_results(
    scan_id: int,
    engine_jobs: list[ScanEngineJobRecord],
    missing_engine_names: set[str],
) -> bool:
    """Write a synthetic result for each terminal failed/skipped job that is
    required but has no result yet. Idempotent; returns whether anything was
    written. A ``completed`` job is never synthesized (a real result must exist)."""
    wrote_any = False
    for job in engine_jobs:
        if job.engine_name not in missing_engine_names:
            continue
        if job.status not in {"failed", "skipped"}:
            continue
        create_engine_result_if_missing(
            scan_id,
            EngineResultInput(
                engine_name=job.engine_name,
                status=job.status,
                detected=False,
                severity="info",
                confidence=0,
                signature=None,
                raw_output=job.last_error
                or f"Engine job reached '{job.status}' without producing a result.",
                error_message=job.last_error,
                duration_ms=synthetic_engine_duration_ms(),
            ),
        )
        wrote_any = True
    return wrote_any


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
            missing = required_engine_names - existing_engine_names
            if missing:
                # A job can reach a terminal failed/skipped state without a
                # result (recovery poisoning at the attempt cap, or a
                # non-runnable route). Backfill a synthetic result from the
                # engine-job snapshot so the scan finalizes with partial coverage
                # instead of hanging. Idempotent (create-if-missing).
                if backfill_missing_engine_results(scan.id, engine_jobs, missing):
                    engine_results = list_engine_results(scan.id)
                    existing_engine_names = {r.engine_name for r in engine_results}
            if not required_engine_names.issubset(existing_engine_names):
                return False
        elif not all_enabled_engines_have_results(engines, existing_engine_names):
            return False
    elif not all_enabled_engines_have_results(engines, existing_engine_names):
        return False

    # Claim the finalization: queued/running -> finalizing, fenced to one owner.
    # An expired finalizing claim (crashed finalizer) can be stolen here.
    generation = claim_scan_finalization(
        scan.id, WORKER_ID, lease_seconds=FINALIZE_LEASE_SECONDS
    )
    if generation is None:
        return False  # another worker owns the finalization

    assessment = calculate_risk(engine_results)
    # Register archive children BEFORE completing, inside the finalization
    # ownership, so a crash before completion is redone by a later finalizer
    # (idempotent child registration) rather than leaving a completed container
    # whose members were never scanned.
    try:
        with finalization_lease_renewal(scan.id, generation, FINALIZE_LEASE_SECONDS):
            maybe_enqueue_lazy_archive_children(
                scan, assessment, engine_results, engines, set(), finalize_generation=generation
            )
    except StaleFinalizerError:
        # Lost the finalization (lease expired, stolen) during extraction; stop
        # and let the new owner redo it. Do not complete.
        return False
    if not complete_finalizing_scan(
        scan.id, WORKER_ID, generation, assessment.verdict, assessment.score
    ):
        # Lost the finalization (lease expired and it was stolen); the new owner
        # will complete it. Do not run completion side effects again.
        return False
    print(f"Completed scan job {scan.id}", flush=True)
    return True


def maybe_enqueue_lazy_archive_children(
    scan: ScanRecord,
    assessment: RiskAssessment,
    engine_results: list[EngineResultRecord],
    engines: list[EngineInstanceRecord],
    engine_keys: set[str],
    *,
    finalize_generation: int | None = None,
) -> int:
    if scan.scan_role not in {"container", "child"} or scan.batch_id is None:
        return 0
    if finalize_generation is None:
        # Child registration must run inside a fenced finalization (it mutates the
        # DB and files on behalf of the parent). Callers without a generation
        # cannot fence, so no children are created.
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

    # Exclude THIS parent's own children so a re-run (idempotent re-registration)
    # does not shrink its own budget and wrongly trip the over-budget guard.
    existing_children = sum(
        1
        for existing_scan in existing_scans
        if existing_scan.scan_role == "child" and existing_scan.parent_scan_id != scan.id
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

    staging = new_staging_dir()
    try:
        extraction = extract_archive(archive_path, destination_dir=staging)
    except ArchiveExtractionError as exc:
        remove_staging_dir(staging)
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
        # nothing is enqueued and the staged files are discarded.
        remove_staging_dir(staging)
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
    for member_ordinal, member in enumerate(extraction.members):
        # Deterministic final path (parent + ordinal + content hash), identical
        # across retries, so a re-extraction restores the file to the exact path
        # the child's DB row references.
        final_name = deterministic_child_stored_filename(
            scan.id, member_ordinal, member.sample.sha256, member.sample.original_filename
        )
        final_path = SAMPLES_DIR / final_name
        # Promote (atomic os.replace) BEFORE the child row becomes visible, so a
        # worker can never claim a child whose sample file is not yet in place.
        promote_staged_file(Path(member.sample.storage_path), final_path)
        child_sample = replace(
            member.sample, stored_filename=final_name, storage_path=str(final_path)
        )
        # Idempotent by (parent_scan_id, ordinal) and fenced to this finalizer:
        # a re-run registers only missing members; a superseded finalizer cannot
        # mutate the DB (raises StaleFinalizerError, handled by the caller).
        child_scope: dict[str, object] = {}
        snapshot = getattr(scan, "profile_snapshot_json", "{}") or "{}"
        if (
            getattr(scan, "service_client_id", None) is not None
            or getattr(scan, "scan_profile_id", None) is not None
            or snapshot != "{}"
        ):
            child_scope = {
                "service_client_id": getattr(scan, "service_client_id", None),
                "scan_profile_id": getattr(scan, "scan_profile_id", None),
                "profile_snapshot_json": snapshot,
            }
        child_scan_id = create_archive_child(
            parent_scan_id=scan.id,
            parent_finalize_worker_id=WORKER_ID,
            parent_finalize_generation=finalize_generation,
            batch_id=batch.id,
            sample=child_sample,
            engines=engines,
            case_name=scan.case_name,
            priority=scan.priority,
            note=scan.note,
            source=scan.source,
            relative_path=f"{relative_prefix}{member.relative_path}",
            member_ordinal=member_ordinal,
            **child_scope,
        )
        if child_scan_id is not None:
            created_children += 1

    remove_staging_dir(staging)

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
        if (
            job.engine_instance_id in enabled_engine_ids
            if job.engine_instance_id is not None
            else job.engine_key in enabled_engine_keys
        )
    }


def find_engine_for_job(
    job: ScanEngineJobRecord,
    engines: list[EngineInstanceRecord],
) -> EngineInstanceRecord | None:
    if job.engine_instance_id is not None:
        return next(
            (engine for engine in engines if engine.id == job.engine_instance_id),
            None,
        )
    # Legacy rows created before engine_instance_id existed can still be routed
    # by adapter key. New jobs always carry the immutable database id.
    for engine in engines:
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


def online_worker_engine_keys() -> set[str]:
    """Engine keys advertised by any worker currently sending heartbeats."""
    status = get_worker_status()
    return {str(key) for key in status.get("engine_keys", []) if str(key)}


def sweep_finalize_stuck_scans() -> int:
    """Finalize scans whose engine jobs are all terminal but were never closed.

    If a worker dies after marking the last engine job terminal but before
    finalizing, the scan stays ``running`` forever: no pending jobs remain (so
    the reaper ignores it) and no worker will claim it. This idle sweep finds
    such scans and finalizes them. ``finalize_scan_if_complete`` uses the atomic
    completion transition, so running this on several workers at once is safe —
    only one wins and no duplicate results or children are produced.
    """
    finalized = 0
    for scan in list_active_scans(limit=ACTIVE_SCAN_LIMIT):
        engines = engines_for_scan(scan)
        engine_jobs = list_scan_engine_jobs(scan.id)
        if not engine_jobs or not all_scan_engine_jobs_terminal(engine_jobs):
            continue
        if finalize_scan_if_complete(refresh_scan_record(scan), engines):
            finalized += 1
    return finalized


def reap_orphaned_engine_jobs(engine_keys: set[str]) -> bool:
    """Skip pending engine jobs that no online worker can ever claim.

    In engine-job-queue mode a worker only claims jobs for its own engine keys.
    If an engine is enabled but no online worker advertises it (its worker is
    down or was never started), its jobs sit ``pending`` forever, and because
    ``finalize_scan_if_complete`` requires every job to be terminal, the scan
    never finalizes. This sweep converts such jobs to ``skipped`` once the
    orchestration wait window has elapsed, mirroring the legacy timeout path so
    the scan finishes with partial coverage instead of hanging indefinitely.
    """
    worker_status = get_worker_status()
    reaped_any = False

    for scan in list_active_scans(limit=ACTIVE_SCAN_LIMIT):
        engines = engines_for_scan(scan)
        covered_instance_ids = schedulable_engine_instance_ids(worker_status, engines)
        engine_jobs = list_scan_engine_jobs(scan.id)
        if not engine_jobs:
            continue

        orphan_jobs: list[tuple[ScanEngineJobRecord, EngineInstanceRecord]] = []
        for job in engine_jobs:
            if job.status != "pending":
                continue
            engine = find_engine_for_job(job, engines)
            if engine is not None and engine.id not in covered_instance_ids:
                orphan_jobs.append((job, engine))
        if not orphan_jobs:
            continue

        missing_engines = [engine for _, engine in orphan_jobs]
        if not should_finalize_scan_with_partial_results(scan, missing_engines):
            continue

        wait_seconds = partial_results_wait_seconds(missing_engines)
        message = (
            "No online worker advertises this engine; skipped after the "
            f"orchestration wait window expired ({wait_seconds}s)."
        )
        skipped_scan = False
        for job, engine in orphan_jobs:
            if not skip_pending_scan_engine_job(job.id, last_error=message):
                # A worker came online and claimed the job between our checks.
                continue
            create_engine_result_if_missing(
                scan.id,
                skipped_engine_result(scan, engine, engine_keys, wait_seconds),
            )
            record_worker_timing_event(
                scan.id,
                "engine_job_reaped",
                engine_keys,
                engine_name=engine.display_name,
                details={
                    "engine_job_id": job.id,
                    "engine_key": job.engine_key,
                    "reason_code": ROUTE_REASON_WORKER_TIMEOUT,
                    "wait_seconds": wait_seconds,
                },
            )
            reaped_any = True
            skipped_scan = True

        if skipped_scan:
            finalize_scan_if_complete(refresh_scan_record(scan), engines)

    return reaped_any


def process_next_scan_job() -> bool:
    if not worker_accepts_new_work():
        record_worker_heartbeat("idle")
        return False
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


CHILD_SAMPLE_ORPHAN_MAX_AGE_SECONDS = int(
    os.getenv("MASP_CHILD_SAMPLE_ORPHAN_MAX_AGE_SECONDS", str(6 * 60 * 60))
)


def cleanup_orphan_child_samples(max_age_seconds: int | None = None) -> int:
    """Delete deterministic ``child-*`` sample files left by a fenced finalizer.

    A finalizer promotes a child's file to its deterministic path *before*
    committing the DB row, so one fenced out (or crashed) in that window leaves a
    file no scan references. Removing it safely means never racing a live
    finalizer that is about to commit a child for the same path. Rather than a
    fragile mtime-vs-reference check (the mtime read and the unlink straddle a
    possible commit), we key off the parent scan's lifecycle:

    A file ``child-<parent>-...`` is removed only when ALL hold, re-verified
    under the parent scan's row lock at the moment of deletion
    (:func:`database.remove_orphan_child_sample`):
      * the parent scan is **terminal** (completed/failed) or **missing** — with
        the row locked, neither ``retry_scan_job`` nor a new finalization claim
        can commit until the deletion finishes, and every child-file promote
        happens only after a claim committed ``finalizing``, so no finalizer can
        be about to commit a child for this path; and
      * no ``samples`` row references the file; and
      * the file is older than the TTL (defense in depth).

    The bulk prefilter (one status query + one reference query) only discards
    the common non-orphan cases cheaply — its reads can go stale (a retry can
    flip a terminal parent back to active right after them), which is why it is
    never the basis for a deletion. The locked confirm runs just for the rare
    surviving candidates, so there is still no per-file N+1 in the steady
    state. Returns the count removed.
    """
    max_age = (
        CHILD_SAMPLE_ORPHAN_MAX_AGE_SECONDS if max_age_seconds is None else max_age_seconds
    )
    if not SAMPLES_DIR.is_dir():
        return 0
    cutoff = time.time() - max(1, max_age)

    candidates: list[tuple[Path, int]] = []
    for entry in SAMPLES_DIR.glob("child-*"):
        try:
            if not entry.is_file() or entry.stat().st_mtime >= cutoff:
                continue
        except OSError:
            continue
        parent_id = parse_child_parent_scan_id(entry.name)
        if parent_id is None:
            continue  # unrecognized name: leave it alone
        candidates.append((entry, parent_id))
    if not candidates:
        return 0

    parent_statuses = get_scan_statuses([pid for _entry, pid in candidates])
    referenced = filter_referenced_storage_paths([str(entry) for entry, _pid in candidates])

    removed = 0
    for entry, parent_id in candidates:
        status = parent_statuses.get(parent_id)
        parent_settled = status is None or status in TERMINAL_SCAN_STATUSES
        if not parent_settled:
            continue  # parent may still commit a child for this file
        if str(entry) in referenced:
            continue  # a scan references it — never delete a live child's file
        try:
            # Authoritative gate: re-confirm terminal-and-unreferenced under the
            # parent row lock and unlink while holding it, so a retry that
            # reactivated the parent after the bulk reads cannot lose its file.
            if remove_orphan_child_sample(
                parent_id, str(entry), lambda: entry.unlink(missing_ok=True)
            ):
                removed += 1
        except OSError:
            continue
    return removed


def run_maintenance() -> int:
    """Recover orphaned leases, reap uncoverable jobs, and finalize stuck scans.

    Runs regardless of queue load so a scan wedged by a crashed worker is
    recovered even under continuous traffic. Returns the number of leases
    recovered (for startup logging).
    """
    engine_keys = worker_engine_keys()
    recovered = 0
    if ENGINE_JOB_RECOVERY_ENABLED:
        recovered = recover_running_scan_jobs(max_attempts=ENGINE_JOB_MAX_ATTEMPTS)
    if ORPHANED_ENGINE_JOB_REAP_ENABLED:
        reap_orphaned_engine_jobs(engine_keys)
    if ENGINE_JOB_RECOVERY_ENABLED:
        sweep_finalize_stuck_scans()
    run_due_worker_health_checks()
    # Remove archive-extraction staging dirs orphaned by a crash mid-extraction,
    # and deterministic child-* sample files no scan references (a fenced-out
    # stale finalizer can leave one).
    try:
        cleanup_stale_staging_dirs()
        cleanup_orphan_child_samples()
    except OSError as exc:  # best-effort; never break the maintenance tick
        print(f"Sample/staging cleanup failed: {exc}", flush=True)
    return recovered


def run_forever() -> None:
    transport = os.getenv("MASP_WORKER_TRANSPORT", "database").strip().lower()
    if transport == "control_api":
        from app.workers.control_api_worker import run_forever as run_control_api_worker

        run_control_api_worker()
        return
    if transport != "database":
        raise SystemExit(
            "MASP_WORKER_TRANSPORT must be 'database' or 'control_api'."
        )
    # The legacy process_scan path finalizes with the old completed-then-extract
    # ordering (no finalizing state machine), reintroducing the completion/child
    # crash gap. It is entered when the engine-job queue is off OR the fallback is
    # on, so both are refused: only the fenced engine-job path is supported.
    if not ENGINE_JOB_QUEUE_ENABLED or LEGACY_SCAN_WORKER_FALLBACK_ENABLED:
        raise SystemExit(
            "The legacy scan path is not supported (it bypasses the fenced "
            "finalization state machine). Run with MASP_ENGINE_JOB_QUEUE_ENABLED=1 "
            "(the default) and MASP_LEGACY_SCAN_WORKER_FALLBACK_ENABLED unset."
        )
    init_db()
    seed_default_engines()
    seed_legacy_service_client()
    engine_keys = worker_engine_keys()
    record_worker_heartbeat("starting")
    recovered = run_maintenance()
    print(
        "MASP scan worker started "
        f"(engines: {', '.join(sorted(engine_keys)) or 'none'})",
        flush=True,
    )
    if recovered:
        print(f"Recovered {recovered} interrupted scan job(s)", flush=True)
    last_maintenance = time.monotonic()
    while True:
        try:
            processed = process_next_scan_job()
        except DatabaseOperationalError as exc:
            print(f"Worker database operation failed, retrying: {exc}", flush=True)
            record_worker_heartbeat("error")
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        if time.monotonic() - last_maintenance >= MAINTENANCE_INTERVAL_SECONDS:
            try:
                run_maintenance()
            except DatabaseOperationalError as exc:
                print(f"Worker maintenance failed, will retry: {exc}", flush=True)
            last_maintenance = time.monotonic()

        if not processed:
            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_forever()
