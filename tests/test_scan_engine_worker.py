import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import ANY, patch

from app.models import (
    EngineInstanceRecord,
    EngineResultInput,
    EngineResultRecord,
    ScanBatchRecord,
    ScanEngineJobRecord,
    ScanRecord,
    StoredSample,
)
from app.services.archive_extractor import (
    ArchiveExtractionLimits,
    ArchiveExtractionResult,
    ExtractedArchiveMember,
)
from app.services.routing import EngineRouteDecision, ROUTE_ACTION_RUN
from app.services.scoring import RiskAssessment
from app.workers.scan_worker import (
    finalize_scan_if_complete,
    maybe_enqueue_lazy_archive_children,
    process_next_scan_job,
    process_scan_engine_job,
    reap_orphaned_engine_jobs,
    run_maintenance,
)


class ExceptionPathFencingTests(unittest.TestCase):
    """A crashed adapter must not fail the job/scan if the worker lost ownership."""

    def _run(self, *, owned: bool):
        engine = make_engine("static_metadata", "Static Metadata")
        job = make_job(1, engine)
        with patch(
            "app.workers.scan_worker.claim_next_scan_engine_job", return_value=job
        ), patch(
            "app.workers.scan_worker.process_scan_engine_job",
            side_effect=RuntimeError("adapter boom"),
        ), patch(
            "app.workers.scan_worker.mark_scan_engine_job_terminal_if_owned",
            return_value=owned,
        ) as terminal, patch(
            "app.workers.scan_worker.update_scan_status"
        ) as update_status, patch(
            "app.workers.scan_worker.record_worker_timing_event"
        ), patch(
            "app.workers.scan_worker.record_worker_heartbeat"
        ):
            from app.workers.scan_worker import process_next_scan_engine_job

            process_next_scan_engine_job()
        return terminal, update_status, job

    def test_lost_ownership_does_not_fail_the_scan(self) -> None:
        terminal, update_status, job = self._run(owned=False)
        # Terminal is attempted but fenced (returns False); the scan is untouched.
        terminal.assert_called_once_with(
            job.id, ANY, job.attempt_count, "failed", last_error="adapter boom"
        )
        update_status.assert_not_called()

    def test_owned_failure_marks_the_scan_failed(self) -> None:
        _terminal, update_status, job = self._run(owned=True)
        update_status.assert_called_once_with(
            job.scan_job_id, "failed", last_error="adapter boom"
        )


class RunMaintenanceTests(unittest.TestCase):
    def test_run_maintenance_runs_recovery_reaper_and_sweep(self) -> None:
        with patch(
            "app.workers.scan_worker.worker_engine_keys", return_value={"clamav"}
        ), patch(
            "app.workers.scan_worker.recover_running_scan_jobs", return_value=2
        ) as recover, patch(
            "app.workers.scan_worker.reap_orphaned_engine_jobs"
        ) as reap, patch(
            "app.workers.scan_worker.sweep_finalize_stuck_scans"
        ) as sweep:
            recovered = run_maintenance()

        self.assertEqual(recovered, 2)
        recover.assert_called_once()
        reap.assert_called_once()
        sweep.assert_called_once()

    def test_run_forever_refuses_any_legacy_config(self) -> None:
        from app.workers import scan_worker

        # The legacy scan path must be unreachable in EVERY config combination:
        # the fallback flag on, OR the engine-job queue off.
        for queue_enabled, fallback_enabled in [(True, True), (False, False), (False, True)]:
            with patch(
                "app.workers.scan_worker.ENGINE_JOB_QUEUE_ENABLED", queue_enabled
            ), patch(
                "app.workers.scan_worker.LEGACY_SCAN_WORKER_FALLBACK_ENABLED",
                fallback_enabled,
            ), patch("app.workers.scan_worker.init_db") as init_db:
                with self.assertRaises(SystemExit):
                    scan_worker.run_forever()
                init_db.assert_not_called()  # refused before touching the DB


class ScanEngineWorkerTests(unittest.TestCase):
    def test_process_scan_engine_job_runs_adapter_and_marks_terminal(self) -> None:
        scan = replace(make_scan(), source="api")
        engine = make_engine("static_metadata", "Static Metadata")
        job = make_job(scan.id, engine)
        result = EngineResultInput(
            engine_name=engine.display_name,
            status="completed",
            detected=False,
            severity="info",
            confidence=100,
            signature=None,
            raw_output="ok",
            duration_ms=12,
        )

        with patch("app.workers.scan_worker.record_worker_heartbeat"), patch(
            "app.workers.scan_worker.get_scan",
            return_value=scan,
        ), patch(
            "app.workers.scan_worker.enabled_engines",
            return_value=[engine],
        ) as enabled_engines, patch(
            "app.workers.scan_worker.route_engine_for_worker",
            return_value=EngineRouteDecision(
                engine=engine,
                action=ROUTE_ACTION_RUN,
                reason_code="eligible",
                reason="ok",
                details={},
            ),
        ), patch(
            "app.workers.scan_worker.mark_scan_running",
        ), patch(
            "app.workers.scan_worker.mark_scan_engine_job_running",
            return_value=True,
        ) as mark_running, patch(
            "app.workers.scan_worker.run_engine",
            return_value=result,
        ) as run_engine, patch(
            "app.workers.scan_worker.commit_engine_job_result_if_owned",
            return_value=True,
        ) as commit_result, patch(
            "app.workers.scan_worker.finalize_scan_if_complete",
            return_value=True,
        ) as finalize, patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ):
            processed = process_scan_engine_job(job, {"static_metadata"})

        self.assertTrue(processed)
        enabled_engines.assert_called_once_with(source="api")
        mark_running.assert_called_once()
        run_engine.assert_called_once_with(engine, scan)
        commit_result.assert_called_once()
        _, commit_kwargs = commit_result.call_args
        self.assertEqual(commit_kwargs["job_id"], job.id)
        self.assertEqual(commit_kwargs["result"], result)
        self.assertEqual(commit_kwargs["terminal_status"], "completed")
        self.assertEqual(commit_kwargs["attempt_generation"], job.attempt_count)
        finalize.assert_called_once()

    def test_process_next_scan_job_does_not_use_legacy_fallback_by_default(self) -> None:
        with patch(
            "app.workers.scan_worker.worker_accepts_new_work", return_value=True
        ), patch("app.workers.scan_worker.ENGINE_JOB_QUEUE_ENABLED", True), patch(
            "app.workers.scan_worker.LEGACY_SCAN_WORKER_FALLBACK_ENABLED",
            False,
        ), patch(
            "app.workers.scan_worker.process_next_scan_engine_job",
            return_value=False,
        ), patch(
            "app.workers.scan_worker.list_active_scans",
        ) as list_active:
            processed = process_next_scan_job()

        self.assertFalse(processed)
        list_active.assert_not_called()

    def test_draining_worker_does_not_claim_new_work(self) -> None:
        with patch(
            "app.workers.scan_worker.worker_accepts_new_work", return_value=False
        ), patch(
            "app.workers.scan_worker.process_next_scan_engine_job"
        ) as process_engine_job, patch(
            "app.workers.scan_worker.record_worker_heartbeat"
        ) as heartbeat:
            processed = process_next_scan_job()

        self.assertFalse(processed)
        process_engine_job.assert_not_called()
        heartbeat.assert_called_once_with("idle")

    def test_finalize_scan_waits_for_terminal_engine_jobs(self) -> None:
        scan = make_scan()
        engine = make_engine("static_metadata", "Static Metadata")
        job = replace(make_job(scan.id, engine), status="running")
        result = make_engine_result(scan.id, engine.display_name)

        with patch("app.workers.scan_worker.ENGINE_JOB_QUEUE_ENABLED", True), patch(
            "app.workers.scan_worker.list_scan_engine_jobs",
            return_value=[job],
        ), patch(
            "app.workers.scan_worker.list_engine_results",
            return_value=[result],
        ), patch(
            "app.workers.scan_worker.claim_scan_finalization",
            return_value=1,
        ) as claim_finalize:
            finalized = finalize_scan_if_complete(scan, [engine])

        self.assertFalse(finalized)
        claim_finalize.assert_not_called()

    def test_finalize_scan_uses_terminal_engine_jobs_and_results(self) -> None:
        scan = make_scan()
        engine = make_engine("static_metadata", "Static Metadata")
        job = replace(make_job(scan.id, engine), status="completed")
        result = make_engine_result(scan.id, engine.display_name)

        with patch("app.workers.scan_worker.ENGINE_JOB_QUEUE_ENABLED", True), patch(
            "app.workers.scan_worker.list_scan_engine_jobs",
            return_value=[job],
        ), patch(
            "app.workers.scan_worker.list_engine_results",
            return_value=[result],
        ), patch(
            "app.workers.scan_worker.claim_scan_finalization",
            return_value=3,
        ) as claim_finalize, patch(
            "app.workers.scan_worker.complete_finalizing_scan",
            return_value=True,
        ) as complete:
            finalized = finalize_scan_if_complete(scan, [engine])

        self.assertTrue(finalized)
        claim_finalize.assert_called_once()
        complete.assert_called_once_with(scan.id, ANY, 3, "low", 10)

    def test_finalize_scan_enqueues_lazy_archive_children_for_detected_container(self) -> None:
        engine = make_engine("static_metadata", "Static Metadata")
        existing_archive_path = Path(__file__).resolve()
        scan = replace(
            make_scan(),
            source="api",
            batch_id=42,
            scan_role="container",
            relative_path="bundle.zip",
            storage_path="storage/samples/bundle.zip",
        )
        job = replace(make_job(scan.id, engine), status="completed")
        result = make_engine_result(scan.id, engine.display_name, detected=True)
        child_sample = StoredSample(
            original_filename="tool.exe",
            stored_filename="stored-tool.exe",
            storage_path="storage/samples/stored-tool.exe",
            content_type="application/octet-stream",
            size_bytes=12,
            md5="0" * 32,
            sha1="0" * 40,
            sha256="1" * 64,
        )
        extraction = ArchiveExtractionResult(
            archive_path=scan.storage_path,
            members=[
                ExtractedArchiveMember(
                    relative_path="bin/tool.exe",
                    sample=child_sample,
                )
            ],
            total_uncompressed_bytes=12,
        )

        with patch("app.workers.scan_worker.ENGINE_JOB_QUEUE_ENABLED", True), patch(
            "app.workers.scan_worker.list_scan_engine_jobs",
            return_value=[job],
        ), patch(
            "app.workers.scan_worker.list_engine_results",
            return_value=[result],
        ), patch(
            "app.workers.scan_worker.claim_scan_finalization",
            return_value=1,
        ), patch(
            "app.workers.scan_worker.complete_finalizing_scan",
            return_value=True,
        ), patch(
            "app.workers.scan_worker.get_scan_batch",
            return_value=make_batch(42),
        ), patch(
            "app.workers.scan_worker.list_scan_batch_scans",
            return_value=[scan],
        ), patch(
            "app.workers.scan_worker.resolve_sample_path",
            return_value=existing_archive_path,
        ), patch(
            "app.workers.scan_worker.extract_archive",
            return_value=extraction,
        ) as extract_archive, patch(
            "app.workers.scan_worker.new_staging_dir", return_value=Path("staging"),
        ), patch(
            "app.workers.scan_worker.promote_staged_file",
        ), patch(
            "app.workers.scan_worker.remove_staging_dir",
        ), patch(
            "app.workers.scan_worker.create_archive_child",
            return_value=456,
        ) as create_child, patch(
            "app.workers.scan_worker.refresh_scan_batch_counts",
        ) as refresh_counts, patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ):
            finalized = finalize_scan_if_complete(scan, [engine])

        self.assertTrue(finalized)
        extract_archive.assert_called_once_with(existing_archive_path, destination_dir=Path("staging"))
        create_child.assert_called_once_with(
            parent_scan_id=scan.id,
            parent_finalize_worker_id=ANY,
            parent_finalize_generation=1,
            batch_id=42,
            sample=ANY,
            engines=[engine],
            case_name=scan.case_name,
            priority=scan.priority,
            note=scan.note,
            source="api",
            relative_path="bin/tool.exe",
            member_ordinal=0,
        )
        refresh_counts.assert_called_once_with(42)

    def test_finalize_scan_records_failure_when_archive_path_cannot_be_resolved(self) -> None:
        engine = make_engine("static_metadata", "Static Metadata")
        scan = replace(
            make_scan(),
            source="api",
            batch_id=42,
            scan_role="container",
            relative_path="bundle.zip",
            storage_path="/app/storage/samples/bundle.zip",
        )
        job = replace(make_job(scan.id, engine), status="completed")
        result = make_engine_result(scan.id, engine.display_name, detected=True)

        with patch("app.workers.scan_worker.ENGINE_JOB_QUEUE_ENABLED", True), patch(
            "app.workers.scan_worker.list_scan_engine_jobs",
            return_value=[job],
        ), patch(
            "app.workers.scan_worker.list_engine_results",
            return_value=[result],
        ), patch(
            "app.workers.scan_worker.claim_scan_finalization",
            return_value=1,
        ), patch(
            "app.workers.scan_worker.complete_finalizing_scan",
            return_value=True,
        ), patch(
            "app.workers.scan_worker.get_scan_batch",
            return_value=make_batch(42),
        ), patch(
            "app.workers.scan_worker.list_scan_batch_scans",
            return_value=[scan],
        ), patch(
            "app.workers.scan_worker.resolve_sample_path",
            return_value=Path("C:/missing/bundle.zip"),
        ), patch(
            "app.workers.scan_worker.extract_archive",
        ) as extract_archive, patch(
            "app.workers.scan_worker.refresh_scan_batch_counts",
        ) as refresh_counts, patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ) as record_event:
            finalized = finalize_scan_if_complete(scan, [engine])

        self.assertTrue(finalized)
        extract_archive.assert_not_called()
        refresh_counts.assert_called_once_with(42)
        record_event.assert_any_call(
            scan.id,
            "archive_lazy_extract_failed",
            set(),
            details={
                "batch_id": 42,
                "error": "Sample file not found: /app/storage/samples/bundle.zip (resolved locally as C:\\missing\\bundle.zip)",
            },
        )


class NestedArchiveEnqueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = make_engine("static_metadata", "Static Metadata")
        self.container = replace(
            make_scan(),
            id=1,
            batch_id=42,
            scan_role="container",
            relative_path="outer.zip",
        )
        self.child = replace(
            make_scan(),
            id=2,
            batch_id=42,
            parent_scan_id=1,
            scan_role="child",
            relative_path="payloads/inner.zip",
            storage_path="storage/samples/inner.zip",
        )
        self.detected_result = make_engine_result(2, self.engine.display_name, detected=True)
        self.assessment = RiskAssessment(score=80, verdict="high", reasons=[])

    def test_detected_child_archive_enqueues_grandchildren_with_prefixed_paths(self) -> None:
        existing_archive_path = Path(__file__).resolve()
        grandchild_sample = StoredSample(
            original_filename="evil.exe",
            stored_filename="stored-evil.exe",
            storage_path="storage/samples/stored-evil.exe",
            content_type="application/octet-stream",
            size_bytes=12,
            md5="0" * 32,
            sha1="0" * 40,
            sha256="1" * 64,
        )
        extraction = ArchiveExtractionResult(
            archive_path=self.child.storage_path,
            members=[
                ExtractedArchiveMember(relative_path="bin/evil.exe", sample=grandchild_sample)
            ],
            total_uncompressed_bytes=12,
        )

        with patch(
            "app.workers.scan_worker.get_scan_batch",
            return_value=make_batch(42),
        ), patch(
            "app.workers.scan_worker.list_scan_batch_scans",
            return_value=[self.container, self.child],
        ), patch(
            "app.workers.scan_worker.resolve_sample_path",
            return_value=existing_archive_path,
        ), patch(
            "app.workers.scan_worker.is_supported_archive",
            return_value=True,
        ), patch(
            "app.workers.scan_worker.extract_archive",
            return_value=extraction,
        ) as extract, patch(
            "app.workers.scan_worker.new_staging_dir", return_value=Path("staging"),
        ), patch(
            "app.workers.scan_worker.promote_staged_file",
        ), patch(
            "app.workers.scan_worker.remove_staging_dir",
        ), patch(
            "app.workers.scan_worker.create_archive_child",
            return_value=456,
        ) as create_child, patch(
            "app.workers.scan_worker.refresh_scan_batch_counts",
        ) as refresh_counts, patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ):
            created = maybe_enqueue_lazy_archive_children(
                self.child,
                self.assessment,
                [self.detected_result],
                [self.engine],
                set(),
                finalize_generation=1,
            )

        self.assertEqual(created, 1)
        extract.assert_called_once_with(existing_archive_path, destination_dir=Path("staging"))
        create_child.assert_called_once_with(
            parent_scan_id=2,
            parent_finalize_worker_id=ANY,
            parent_finalize_generation=1,
            batch_id=42,
            sample=ANY,
            engines=[self.engine],
            case_name=self.child.case_name,
            priority=self.child.priority,
            note=self.child.note,
            source=self.child.source,
            relative_path="payloads/inner.zip/bin/evil.exe",
            member_ordinal=0,
        )
        refresh_counts.assert_called_once_with(42)

    def test_rerun_after_partial_crash_registers_only_missing_members(self) -> None:
        # Simulate a re-finalization after a crash that had registered member 0:
        # create_archive_child returns None for the already-present ordinal and a
        # new id for the missing one. Both are re-attempted (idempotent), only the
        # missing one is counted, and the ordinals are deterministic.
        existing_archive_path = Path(__file__).resolve()
        members = [
            ExtractedArchiveMember(
                relative_path="dup.exe",
                sample=StoredSample("dup.exe", f"stored-{i}.exe", f"storage/samples/stored-{i}.exe", "application/octet-stream", 1, "0" * 32, "0" * 40, str(i) * 64),
            )
            for i in range(2)
        ]
        extraction = ArchiveExtractionResult(
            archive_path=self.child.storage_path, members=members, total_uncompressed_bytes=2
        )
        with patch(
            "app.workers.scan_worker.get_scan_batch", return_value=make_batch(42)
        ), patch(
            "app.workers.scan_worker.list_scan_batch_scans",
            return_value=[self.container, self.child],
        ), patch(
            "app.workers.scan_worker.resolve_sample_path",
            return_value=existing_archive_path,
        ), patch(
            "app.workers.scan_worker.is_supported_archive", return_value=True
        ), patch(
            "app.workers.scan_worker.extract_archive", return_value=extraction
        ), patch(
            "app.workers.scan_worker.new_staging_dir", return_value=Path("staging")
        ), patch(
            "app.workers.scan_worker.promote_staged_file"
        ), patch(
            "app.workers.scan_worker.remove_staging_dir"
        ), patch(
            "app.workers.scan_worker.create_archive_child", side_effect=[None, 999]
        ) as create_child, patch(
            "app.workers.scan_worker.refresh_scan_batch_counts"
        ), patch(
            "app.workers.scan_worker.record_worker_timing_event"
        ):
            created = maybe_enqueue_lazy_archive_children(
                self.child, self.assessment, [self.detected_result], [self.engine], set(),
                finalize_generation=1,
            )

        self.assertEqual(created, 1)  # only the previously-missing member counts
        self.assertEqual(create_child.call_count, 2)  # both re-attempted (idempotent)
        self.assertEqual(create_child.call_args_list[0].kwargs["member_ordinal"], 0)
        self.assertEqual(create_child.call_args_list[1].kwargs["member_ordinal"], 1)

    def test_detected_child_that_is_not_an_archive_is_ignored(self) -> None:
        with patch(
            "app.workers.scan_worker.get_scan_batch",
            return_value=make_batch(42),
        ), patch(
            "app.workers.scan_worker.resolve_sample_path",
            return_value=Path(__file__).resolve(),
        ), patch(
            "app.workers.scan_worker.is_supported_archive",
            return_value=False,
        ), patch(
            "app.workers.scan_worker.extract_archive",
        ) as extract, patch(
            "app.workers.scan_worker.refresh_scan_batch_counts",
        ) as refresh_counts, patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ) as record_event:
            created = maybe_enqueue_lazy_archive_children(
                self.child,
                self.assessment,
                [self.detected_result],
                [self.engine],
                set(),
                finalize_generation=1,
            )

        self.assertEqual(created, 0)
        extract.assert_not_called()
        record_event.assert_not_called()
        refresh_counts.assert_called_once_with(42)

    def test_nested_extraction_respects_max_nested_levels(self) -> None:
        with patch(
            "app.workers.scan_worker.get_scan_batch",
            return_value=make_batch(42),
        ), patch(
            "app.workers.scan_worker.list_scan_batch_scans",
            return_value=[self.container, self.child],
        ), patch(
            "app.workers.scan_worker.resolve_sample_path",
            return_value=Path(__file__).resolve(),
        ), patch(
            "app.workers.scan_worker.is_supported_archive",
            return_value=True,
        ), patch(
            "app.workers.scan_worker.configured_max_nested_levels",
            return_value=1,
        ), patch(
            "app.workers.scan_worker.extract_archive",
        ) as extract, patch(
            "app.workers.scan_worker.refresh_scan_batch_counts",
        ) as refresh_counts, patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ) as record_event:
            created = maybe_enqueue_lazy_archive_children(
                self.child,
                self.assessment,
                [self.detected_result],
                [self.engine],
                set(),
                finalize_generation=1,
            )

        self.assertEqual(created, 0)
        extract.assert_not_called()
        refresh_counts.assert_called_once_with(42)
        record_event.assert_any_call(
            2,
            "archive_nested_level_exceeded",
            set(),
            details={
                "batch_id": 42,
                "nesting_level": 2,
                "max_nested_levels": 1,
            },
        )

    def test_nested_extraction_skips_when_batch_child_budget_is_exhausted(self) -> None:
        sibling_child = replace(
            make_scan(),
            id=3,
            batch_id=42,
            parent_scan_id=1,
            scan_role="child",
            relative_path="payloads/other.bin",
        )
        member_sample = StoredSample(
            original_filename="evil.exe",
            stored_filename="stored-evil.exe",
            storage_path="storage/samples/stored-evil.exe",
            content_type="application/octet-stream",
            size_bytes=12,
            md5="0" * 32,
            sha1="0" * 40,
            sha256="1" * 64,
        )
        extraction = ArchiveExtractionResult(
            archive_path=self.child.storage_path,
            members=[
                ExtractedArchiveMember(relative_path="bin/evil.exe", sample=member_sample)
            ],
            total_uncompressed_bytes=12,
        )

        with patch(
            "app.workers.scan_worker.get_scan_batch",
            return_value=make_batch(42),
        ), patch(
            "app.workers.scan_worker.list_scan_batch_scans",
            return_value=[self.container, self.child, sibling_child],
        ), patch(
            "app.workers.scan_worker.resolve_sample_path",
            return_value=Path(__file__).resolve(),
        ), patch(
            "app.workers.scan_worker.is_supported_archive",
            return_value=True,
        ), patch(
            "app.workers.scan_worker.configured_archive_limits",
            return_value=ArchiveExtractionLimits(max_files=2),
        ), patch(
            "app.workers.scan_worker.extract_archive",
            return_value=extraction,
        ), patch(
            "app.workers.scan_worker.new_staging_dir", return_value=Path("staging"),
        ), patch(
            "app.workers.scan_worker.promote_staged_file",
        ), patch(
            "app.workers.scan_worker.remove_staging_dir",
        ), patch(
            "app.workers.scan_worker.create_archive_child",
        ) as create_child, patch(
            "app.workers.scan_worker.refresh_scan_batch_counts",
        ) as refresh_counts, patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ) as record_event:
            created = maybe_enqueue_lazy_archive_children(
                self.child,
                self.assessment,
                [self.detected_result],
                [self.engine],
                set(),
                finalize_generation=1,
            )

        self.assertEqual(created, 0)
        create_child.assert_not_called()
        refresh_counts.assert_called_once_with(42)
        record_event.assert_any_call(
            2,
            "archive_batch_child_limit_reached",
            set(),
            details={
                "batch_id": 42,
                "extracted_members": 1,
                "remaining_child_budget": 0,
                "max_files": 2,
            },
        )


class ReapOrphanedEngineJobsTests(unittest.TestCase):
    WORKER_KEYS = {"static_metadata", "clamav", "yara"}

    def _reap(self, **overrides):
        scan = make_scan()
        static_engine = replace(
            make_engine("static_metadata", "Static Metadata"), id=10
        )
        defender_engine = replace(
            make_engine("microsoft_defender", "Microsoft Defender"), id=11
        )
        static_job = replace(
            make_job(scan.id, static_engine), id=1, status="completed"
        )
        defender_job = replace(
            make_job(scan.id, defender_engine),
            id=2,
            engine_instance_id=None,
            worker_id=None,
            status=overrides.get("defender_status", "pending"),
        )

        patches = {
            "get_worker_status": {
                "engine_keys": overrides.get(
                    "online_engine_keys", ["static_metadata", "clamav", "yara"]
                )
            },
            "enabled_engines": [static_engine, defender_engine],
            "list_active_scans": [scan],
            "list_scan_engine_jobs": [static_job, defender_job],
            "should_finalize_scan_with_partial_results": overrides.get(
                "window_elapsed", True
            ),
            "skip_pending_scan_engine_job": overrides.get("skip_won", True),
            "skipped_engine_result": "skipped-result-sentinel",
            "refresh_scan_record": scan,
        }

        with patch(
            "app.workers.scan_worker.get_worker_status",
            return_value=patches["get_worker_status"],
        ), patch(
            "app.workers.scan_worker.enabled_engines",
            return_value=patches["enabled_engines"],
        ), patch(
            "app.workers.scan_worker.list_active_scans",
            return_value=patches["list_active_scans"],
        ), patch(
            "app.workers.scan_worker.list_scan_engine_jobs",
            return_value=patches["list_scan_engine_jobs"],
        ), patch(
            "app.workers.scan_worker.should_finalize_scan_with_partial_results",
            return_value=patches["should_finalize_scan_with_partial_results"],
        ), patch(
            "app.workers.scan_worker.partial_results_wait_seconds",
            return_value=30,
        ), patch(
            "app.workers.scan_worker.skip_pending_scan_engine_job",
            return_value=patches["skip_pending_scan_engine_job"],
        ) as skip_pending, patch(
            "app.workers.scan_worker.skipped_engine_result",
            return_value=patches["skipped_engine_result"],
        ), patch(
            "app.workers.scan_worker.create_engine_result_if_missing",
            return_value=99,
        ) as create_result, patch(
            "app.workers.scan_worker.finalize_scan_if_complete",
            return_value=True,
        ) as finalize, patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ):
            reaped = reap_orphaned_engine_jobs(self.WORKER_KEYS)

        return reaped, skip_pending, create_result, finalize, scan, defender_job

    def test_reaps_orphaned_pending_job_after_window(self) -> None:
        reaped, skip_pending, create_result, finalize, scan, defender_job = self._reap()

        self.assertTrue(reaped)
        skip_pending.assert_called_once()
        self.assertEqual(skip_pending.call_args.args[0], defender_job.id)
        create_result.assert_called_once_with(scan.id, "skipped-result-sentinel")
        finalize.assert_called_once()

    def test_ignores_job_covered_by_online_worker(self) -> None:
        reaped, skip_pending, create_result, finalize, _, _ = self._reap(
            online_engine_keys=["static_metadata", "clamav", "yara", "microsoft_defender"],
        )

        self.assertFalse(reaped)
        skip_pending.assert_not_called()
        create_result.assert_not_called()
        finalize.assert_not_called()

    def test_waits_until_orchestration_window_elapses(self) -> None:
        reaped, skip_pending, create_result, finalize, _, _ = self._reap(
            window_elapsed=False,
        )

        self.assertFalse(reaped)
        skip_pending.assert_not_called()
        create_result.assert_not_called()
        finalize.assert_not_called()

    def test_respects_claim_race_when_skip_loses(self) -> None:
        reaped, skip_pending, create_result, finalize, _, _ = self._reap(
            skip_won=False,
        )

        self.assertFalse(reaped)
        skip_pending.assert_called_once()
        create_result.assert_not_called()
        finalize.assert_not_called()

    def test_reaper_preserves_instance_identity_for_shared_adapter(self) -> None:
        scan = make_scan()
        clamav_primary = replace(
            make_engine("clamav", "ClamAV Primary"), id=10
        )
        clamav_dr = replace(make_engine("clamav", "ClamAV DR"), id=11)
        jobs = [
            replace(
                make_job(scan.id, clamav_primary),
                id=1,
                status="pending",
                worker_id=None,
            ),
            replace(
                make_job(scan.id, clamav_dr),
                id=2,
                status="pending",
                worker_id=None,
            ),
        ]

        with patch(
            "app.workers.scan_worker.get_worker_status",
            return_value={"engine_keys": ["static_metadata"]},
        ), patch(
            "app.workers.scan_worker.enabled_engines",
            return_value=[clamav_primary, clamav_dr],
        ), patch(
            "app.workers.scan_worker.list_active_scans", return_value=[scan]
        ), patch(
            "app.workers.scan_worker.list_scan_engine_jobs", return_value=jobs
        ), patch(
            "app.workers.scan_worker.should_finalize_scan_with_partial_results",
            return_value=True,
        ), patch(
            "app.workers.scan_worker.partial_results_wait_seconds", return_value=30
        ), patch(
            "app.workers.scan_worker.skip_pending_scan_engine_job", return_value=True
        ), patch(
            "app.workers.scan_worker.skipped_engine_result",
            side_effect=lambda _scan, engine, _keys, _wait: engine.display_name,
        ), patch(
            "app.workers.scan_worker.create_engine_result_if_missing"
        ) as create_result, patch(
            "app.workers.scan_worker.finalize_scan_if_complete", return_value=True
        ), patch("app.workers.scan_worker.record_worker_timing_event"):
            reaped = reap_orphaned_engine_jobs(self.WORKER_KEYS)

        self.assertTrue(reaped)
        self.assertEqual(
            [entry.args for entry in create_result.call_args_list],
            [
                (scan.id, "ClamAV Primary"),
                (scan.id, "ClamAV DR"),
            ],
        )


def make_engine(adapter_key: str, display_name: str) -> EngineInstanceRecord:
    return EngineInstanceRecord(
        id=10,
        adapter_key=adapter_key,
        display_name=display_name,
        enabled=True,
        config_json="{}",
        created_at="",
        updated_at="",
    )


def make_job(scan_id: int, engine: EngineInstanceRecord) -> ScanEngineJobRecord:
    return ScanEngineJobRecord(
        id=20,
        scan_job_id=scan_id,
        engine_instance_id=engine.id,
        engine_key=engine.adapter_key,
        engine_name=engine.display_name,
        status="claimed",
        worker_id="worker-1",
        claimed_at="2026-07-06 00:00:00+00:00",
        started_at=None,
        finished_at=None,
        lease_expires_at=120,
        attempt_count=1,
        last_error=None,
        created_at="2026-07-06 00:00:00+00:00",
        updated_at="2026-07-06 00:00:00+00:00",
    )


def make_engine_result(
    scan_id: int,
    engine_name: str,
    *,
    detected: bool = False,
) -> EngineResultRecord:
    return EngineResultRecord(
        id=30,
        scan_job_id=scan_id,
        engine_name=engine_name,
        engine_version=None,
        signature_version=None,
        status="completed",
        detected=detected,
        signature="Test.Detection" if detected else None,
        severity="high" if detected else "info",
        confidence=100,
        raw_output="ok",
        error_message=None,
        duration_ms=12,
        created_at="2026-07-06 00:00:00+00:00",
        details_json="{}",
        findings_json="[]",
    )


def make_batch(batch_id: int) -> ScanBatchRecord:
    return ScanBatchRecord(
        id=batch_id,
        source="api",
        original_filename="bundle.zip",
        archive_mode="lazy_extract_on_detection",
        status="queued",
        total_items=1,
        queued_items=1,
        running_items=0,
        completed_items=0,
        failed_items=0,
        malicious_items=0,
        skipped_items=0,
        metadata_json="{}",
        created_at="2026-07-06 00:00:00+00:00",
        updated_at="2026-07-06 00:00:00+00:00",
        completed_at=None,
        last_error=None,
    )


def make_scan() -> ScanRecord:
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(seconds=1)
    return ScanRecord(
        id=1,
        sample_id=1,
        case_name="Case",
        priority="Normal",
        note="",
        source="manual",
        status="queued",
        verdict="pending",
        risk_score=None,
        created_at=created_at.isoformat(sep=" "),
        started_at=None,
        completed_at=None,
        failed_at=None,
        attempt_count=0,
        last_error=None,
        original_filename="sample.bin",
        stored_filename="sample.bin",
        storage_path="storage/samples/sample.bin",
        content_type="application/octet-stream",
        size_bytes=16,
        md5="md5",
        sha1="sha1",
        sha256="sha256",
    )


if __name__ == "__main__":
    unittest.main()
