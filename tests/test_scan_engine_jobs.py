import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database
from app.models import EngineResultInput, StoredSample


class ScanEngineJobTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_setting_set_get_delete_round_trip(self) -> None:
        self.assertIsNone(database.get_setting("scan_policy.api_max_wait_seconds"))
        database.set_setting("scan_policy.api_max_wait_seconds", "45")
        self.assertEqual(
            database.get_setting("scan_policy.api_max_wait_seconds"), "45"
        )
        database.delete_setting("scan_policy.api_max_wait_seconds")
        self.assertIsNone(database.get_setting("scan_policy.api_max_wait_seconds"))
        # Deleting a missing key is a no-op, not an error.
        database.delete_setting("scan_policy.api_max_wait_seconds")

    def test_scan_engine_jobs_are_claimed_by_engine_key_and_lease(self) -> None:
        scan_id = create_scan_with_two_engines()
        engines = database.list_engine_instances()

        self.assertEqual(database.create_scan_engine_jobs(scan_id, engines), 2)
        self.assertEqual(database.create_scan_engine_jobs(scan_id, engines), 0)

        claimed = database.claim_next_scan_engine_job(
            {"microsoft_defender"},
            "windows-1",
            lease_seconds=30,
            now=1000,
        )

        self.assertIsNotNone(claimed)
        assert claimed is not None
        self.assertEqual(claimed.engine_key, "microsoft_defender")
        self.assertEqual(claimed.status, "claimed")
        self.assertEqual(claimed.worker_id, "windows-1")
        self.assertEqual(claimed.lease_expires_at, 1030)
        self.assertEqual(claimed.attempt_count, 1)

        self.assertIsNone(
            database.claim_next_scan_engine_job(
                {"microsoft_defender"},
                "windows-2",
                lease_seconds=30,
                now=1010,
            )
        )

        # The lease expires. claim no longer reclaims an expired job directly;
        # recovery returns it to pending, then another worker can claim it.
        self.assertEqual(
            database.recover_running_scan_jobs(now=1031, max_attempts=5), 1
        )
        reclaimed = database.claim_next_scan_engine_job(
            {"microsoft_defender"},
            "windows-2",
            lease_seconds=30,
            now=1031,
        )

        self.assertIsNotNone(reclaimed)
        assert reclaimed is not None
        self.assertEqual(reclaimed.id, claimed.id)
        self.assertEqual(reclaimed.worker_id, "windows-2")
        self.assertEqual(reclaimed.attempt_count, 2)
        self.assertEqual(reclaimed.lease_expires_at, 1061)

        self.assertTrue(
            database.mark_scan_engine_job_running(
                reclaimed.id,
                "windows-2",
                lease_seconds=30,
                now=1040,
            )
        )
        running = database.get_scan_engine_job(reclaimed.id)
        self.assertIsNotNone(running)
        assert running is not None
        self.assertEqual(running.status, "running")
        self.assertIsNotNone(running.started_at)
        self.assertEqual(running.lease_expires_at, 1070)

        self.assertTrue(database.mark_scan_engine_job_terminal(running.id, "completed"))
        completed = database.get_scan_engine_job(running.id)
        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(completed.status, "completed")
        self.assertIsNone(completed.lease_expires_at)
        self.assertIsNotNone(completed.finished_at)
        self.assertIsNone(
            database.claim_next_scan_engine_job(
                {"microsoft_defender"},
                "windows-3",
                lease_seconds=30,
                now=1100,
            )
        )

    def test_two_instances_of_the_same_adapter_get_distinct_jobs(self) -> None:
        scan_id = create_scan_with_two_engines()
        first_id = database.create_engine_instance(
            "clamav",
            "ClamAV Istanbul",
            config_json='{"host":"clamav-ist.example"}',
        )
        second_id = database.create_engine_instance(
            "clamav",
            "ClamAV Ankara",
            config_json='{"host":"clamav-ank.example"}',
        )
        instances = database.list_engine_instances_for_adapter("clamav")

        self.assertEqual(database.create_scan_engine_jobs(scan_id, instances), 2)
        self.assertEqual(database.create_scan_engine_jobs(scan_id, instances), 0)
        jobs = database.list_scan_engine_jobs(scan_id)
        self.assertEqual({job.engine_instance_id for job in jobs}, {first_id, second_id})
        self.assertEqual({job.engine_key for job in jobs}, {"clamav"})

        first_claim = database.claim_next_scan_engine_job({"clamav"}, "linux-1")
        second_claim = database.claim_next_scan_engine_job({"clamav"}, "linux-2")
        self.assertIsNotNone(first_claim)
        self.assertIsNotNone(second_claim)
        assert first_claim is not None and second_claim is not None
        self.assertNotEqual(first_claim.engine_instance_id, second_claim.engine_instance_id)

    def test_claim_does_not_reclaim_an_expired_job_without_recovery(self) -> None:
        scan_id = create_scan_with_two_engines(status="running")
        database.create_scan_engine_jobs(scan_id, database.list_engine_instances())
        claimed = database.claim_next_scan_engine_job(
            {"microsoft_defender"}, "w1", lease_seconds=30, now=1000
        )
        assert claimed is not None
        # Lease long expired, but recovery has not run: the claim must NOT revive
        # a possibly-still-live owner. Only recovery returns it to pending.
        self.assertIsNone(
            database.claim_next_scan_engine_job(
                {"microsoft_defender"}, "w2", lease_seconds=30, now=9000
            )
        )

    def test_claim_skips_a_pending_job_at_the_attempt_cap(self) -> None:
        scan_id = create_scan_with_two_engines(status="running")
        database.create_scan_engine_jobs(scan_id, database.list_engine_instances())
        job = next(
            j
            for j in database.list_scan_engine_jobs(scan_id)
            if j.engine_key == "microsoft_defender"
        )
        with database.connect() as connection:
            connection.execute(
                "UPDATE scan_engine_jobs SET attempt_count = 5 WHERE id = ?",
                (job.id,),
            )
        self.assertIsNone(
            database.claim_next_scan_engine_job(
                {"microsoft_defender"}, "w1", lease_seconds=30, now=1000, max_attempts=5
            )
        )

    def test_skip_pending_scan_engine_job_only_affects_pending(self) -> None:
        scan_id = create_scan_with_two_engines()
        engines = database.list_engine_instances()
        database.create_scan_engine_jobs(scan_id, engines)

        jobs = database.list_scan_engine_jobs(scan_id)
        defender_job = next(j for j in jobs if j.engine_key == "microsoft_defender")

        self.assertTrue(
            database.skip_pending_scan_engine_job(
                defender_job.id, last_error="no worker"
            )
        )
        skipped = database.get_scan_engine_job(defender_job.id)
        assert skipped is not None
        self.assertEqual(skipped.status, "skipped")
        self.assertEqual(skipped.last_error, "no worker")
        self.assertIsNotNone(skipped.finished_at)
        self.assertIsNone(skipped.lease_expires_at)

        # Second call is a no-op: job no longer pending.
        self.assertFalse(database.skip_pending_scan_engine_job(defender_job.id))

    def test_skip_pending_does_not_clobber_claimed_job(self) -> None:
        scan_id = create_scan_with_two_engines()
        engines = database.list_engine_instances()
        database.create_scan_engine_jobs(scan_id, engines)

        claimed = database.claim_next_scan_engine_job(
            {"microsoft_defender"}, "windows-1", lease_seconds=30, now=1000
        )
        assert claimed is not None

        # Reaper loses the race: job already claimed, skip must not apply.
        self.assertFalse(database.skip_pending_scan_engine_job(claimed.id))
        still = database.get_scan_engine_job(claimed.id)
        assert still is not None
        self.assertEqual(still.status, "claimed")

    def test_retry_scan_job_removes_engine_jobs(self) -> None:
        scan_id = create_scan_with_two_engines(status="completed")
        engines = database.list_engine_instances()
        database.create_scan_engine_jobs(scan_id, engines)

        self.assertEqual(len(database.list_scan_engine_jobs(scan_id)), 2)
        self.assertTrue(database.retry_scan_job(scan_id))
        self.assertEqual(database.list_scan_engine_jobs(scan_id), [])

    def test_scan_history_can_be_filtered_by_source(self) -> None:
        manual_scan_id = create_scan_with_two_engines()
        api_scan_id = create_scan_with_two_engines(source="api")

        manual_scan = database.get_scan(manual_scan_id)
        api_scan = database.get_scan(api_scan_id)

        self.assertIsNotNone(manual_scan)
        self.assertIsNotNone(api_scan)
        assert manual_scan is not None
        assert api_scan is not None
        self.assertEqual(manual_scan.source, "manual")
        self.assertEqual(api_scan.source, "api")

        api_scans = database.list_recent_scans(source="api")
        self.assertEqual([scan.id for scan in api_scans], [api_scan_id])
        self.assertEqual(database.count_scan_history(source="api"), 1)

        api_counts = database.get_scan_counts(source="api")
        self.assertEqual(api_counts["total"], 1)
        self.assertEqual(api_counts["running"], 1)

    def test_scan_batch_metadata_links_container_and_child_scans(self) -> None:
        batch_id = database.create_scan_batch(
            source="api",
            original_filename="bundle.zip",
            archive_mode="container_and_extracted",
            total_items=2,
        )

        container_scan_id = create_scan_with_two_engines(
            source="api",
            batch_id=batch_id,
            scan_role="container",
            relative_path="bundle.zip",
        )
        child_scan_id = create_scan_with_two_engines(
            source="api",
            batch_id=batch_id,
            parent_scan_id=container_scan_id,
            scan_role="child",
            relative_path="docs/readme.txt",
        )

        batch = database.get_scan_batch(batch_id)
        self.assertIsNotNone(batch)
        assert batch is not None
        self.assertEqual(batch.source, "api")
        self.assertEqual(batch.archive_mode, "container_and_extracted")
        self.assertEqual(batch.total_items, 2)

        container_scan = database.get_scan(container_scan_id)
        child_scan = database.get_scan(child_scan_id)
        self.assertIsNotNone(container_scan)
        self.assertIsNotNone(child_scan)
        assert container_scan is not None
        assert child_scan is not None
        self.assertEqual(container_scan.scan_role, "container")
        self.assertEqual(container_scan.batch_id, batch_id)
        self.assertIsNone(container_scan.parent_scan_id)
        self.assertEqual(child_scan.scan_role, "child")
        self.assertEqual(child_scan.batch_id, batch_id)
        self.assertEqual(child_scan.parent_scan_id, container_scan_id)
        self.assertEqual(child_scan.relative_path, "docs/readme.txt")

        batch_scans = database.list_scan_batch_scans(batch_id)
        self.assertEqual([scan.id for scan in batch_scans], [container_scan_id, child_scan_id])

        standalone_scan_id = create_scan_with_two_engines(source="api")
        standalone_scan = database.get_scan(standalone_scan_id)
        self.assertIsNotNone(standalone_scan)
        assert standalone_scan is not None
        self.assertEqual(standalone_scan.scan_role, "standalone")
        self.assertIsNone(standalone_scan.batch_id)

    def test_scan_history_can_exclude_child_scans(self) -> None:
        batch_id = database.create_scan_batch(
            source="api",
            original_filename="bundle.zip",
            archive_mode="lazy_extract_on_detection",
            total_items=2,
        )
        container_scan_id = create_scan_with_two_engines(
            source="api",
            batch_id=batch_id,
            scan_role="container",
            relative_path="bundle.zip",
        )
        child_scan_id = create_scan_with_two_engines(
            source="api",
            batch_id=batch_id,
            parent_scan_id=container_scan_id,
            scan_role="child",
            relative_path="bin/tool.exe",
        )

        all_api_scans = database.list_scan_history(source="api", include_child_scans=True)
        ledger_scans = database.list_scan_history(source="api", include_child_scans=False)

        self.assertIn(container_scan_id, [scan.id for scan in all_api_scans])
        self.assertIn(child_scan_id, [scan.id for scan in all_api_scans])
        self.assertIn(container_scan_id, [scan.id for scan in ledger_scans])
        self.assertNotIn(child_scan_id, [scan.id for scan in ledger_scans])
        self.assertEqual(
            database.count_scan_history(source="api", include_child_scans=False),
            1,
        )
        self.assertEqual(
            database.get_scan_counts(source="api", include_child_scans=False)["total"],
            1,
        )


def create_scan_with_two_engines(
    status: str = "queued",
    source: str = "manual",
    batch_id: int | None = None,
    parent_scan_id: int | None = None,
    relative_path: str | None = None,
    scan_role: str = "standalone",
) -> int:
    sample_id = database.create_sample(
        StoredSample(
            original_filename="sample.bin",
            stored_filename="sample.bin",
            storage_path="storage/samples/sample.bin",
            content_type="application/octet-stream",
            size_bytes=16,
            md5="md5",
            sha1="sha1",
            sha256="sha256",
        )
    )
    configured_keys = {engine.adapter_key for engine in database.list_engine_instances()}
    if "static_metadata" not in configured_keys:
        database.create_engine_instance("static_metadata", "Static Metadata")
    if "microsoft_defender" not in configured_keys:
        database.create_engine_instance("microsoft_defender", "Microsoft Defender")
    return database.create_scan_job(
        sample_id,
        case_name="Case",
        priority="Normal",
        note="",
        source=source,
        batch_id=batch_id,
        parent_scan_id=parent_scan_id,
        relative_path=relative_path,
        scan_role=scan_role,
        status=status,
        verdict="pending",
    )


class CommitEngineJobResultIfOwnedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def _claim(self, worker_id: str, now: int):
        scan_id = create_scan_with_two_engines(status="running")
        database.create_scan_engine_jobs(scan_id, database.list_engine_instances())
        job = database.claim_next_scan_engine_job(
            {"microsoft_defender"}, worker_id, lease_seconds=120, now=now
        )
        assert job is not None
        return scan_id, job

    def _result(self, name: str, status: str = "completed") -> EngineResultInput:
        return EngineResultInput(
            engine_name=name,
            status=status,
            detected=False,
            severity="info",
            confidence=0,
            signature=None,
            raw_output="",
            duration_ms=1,
        )

    def test_owner_commits_result_and_terminal_atomically(self) -> None:
        scan_id, job = self._claim("worker-A", now=1000)
        self.assertTrue(
            database.commit_engine_job_result_if_owned(
                job_id=job.id,
                worker_id="worker-A",
                attempt_generation=job.attempt_count,
                result=self._result(job.engine_name),
                terminal_status="completed",
            )
        )
        updated = database.get_scan_engine_job(job.id)
        assert updated is not None
        self.assertEqual(updated.status, "completed")
        self.assertEqual(len(database.list_engine_results(scan_id)), 1)

    def test_wrong_generation_or_worker_commits_nothing(self) -> None:
        scan_id, job = self._claim("worker-A", now=1000)
        # Wrong attempt generation.
        self.assertFalse(
            database.commit_engine_job_result_if_owned(
                job_id=job.id,
                worker_id="worker-A",
                attempt_generation=job.attempt_count + 1,
                result=self._result(job.engine_name),
                terminal_status="completed",
            )
        )
        # Wrong worker id at the right generation.
        self.assertFalse(
            database.commit_engine_job_result_if_owned(
                job_id=job.id,
                worker_id="worker-B",
                attempt_generation=job.attempt_count,
                result=self._result(job.engine_name),
                terminal_status="completed",
            )
        )
        updated = database.get_scan_engine_job(job.id)
        assert updated is not None
        self.assertEqual(updated.status, "claimed")
        self.assertEqual(len(database.list_engine_results(scan_id)), 0)

    def test_stale_worker_loses_to_new_owner_after_reclaim(self) -> None:
        scan_id, job_a = self._claim("worker-A", now=1000)
        # Lease expires; recovery resets to pending; worker-B claims (attempt++).
        database.recover_running_scan_jobs(now=2000, max_attempts=5)
        job_b = database.claim_next_scan_engine_job(
            {"microsoft_defender"}, "worker-B", lease_seconds=120, now=2001
        )
        assert job_b is not None
        self.assertEqual(job_b.id, job_a.id)
        self.assertGreater(job_b.attempt_count, job_a.attempt_count)

        # Stale worker-A commits at its old generation: nothing is written.
        self.assertFalse(
            database.commit_engine_job_result_if_owned(
                job_id=job_a.id,
                worker_id="worker-A",
                attempt_generation=job_a.attempt_count,
                result=self._result(job_a.engine_name, status="failed"),
                terminal_status="failed",
            )
        )
        # The new owner commits and wins.
        self.assertTrue(
            database.commit_engine_job_result_if_owned(
                job_id=job_b.id,
                worker_id="worker-B",
                attempt_generation=job_b.attempt_count,
                result=self._result(job_b.engine_name, status="completed"),
                terminal_status="completed",
            )
        )
        results = database.list_engine_results(scan_id)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "completed")


class FencedTerminalAndRenewalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def _claim(self, worker: str = "worker-A", now: int = 1000):
        scan_id = create_scan_with_two_engines(status="running")
        database.create_scan_engine_jobs(scan_id, database.list_engine_instances())
        job = database.claim_next_scan_engine_job(
            {"microsoft_defender"}, worker, lease_seconds=120, now=now
        )
        assert job is not None
        return scan_id, job

    def test_terminal_if_owned_fences_on_generation(self) -> None:
        _scan_id, job = self._claim()
        # Wrong generation: no-op.
        self.assertFalse(
            database.mark_scan_engine_job_terminal_if_owned(
                job.id, "worker-A", job.attempt_count + 1, "failed", last_error="x"
            )
        )
        self.assertEqual(database.get_scan_engine_job(job.id).status, "claimed")
        # Owner + generation: applies.
        self.assertTrue(
            database.mark_scan_engine_job_terminal_if_owned(
                job.id, "worker-A", job.attempt_count, "failed", last_error="boom"
            )
        )
        self.assertEqual(database.get_scan_engine_job(job.id).status, "failed")

    def test_commit_rejects_cross_engine_result(self) -> None:
        scan_id, job = self._claim()
        with self.assertRaises(ValueError):
            database.commit_engine_job_result_if_owned(
                job_id=job.id,
                worker_id="worker-A",
                attempt_generation=job.attempt_count,
                result=EngineResultInput(
                    engine_name="Some Other Engine",
                    status="completed",
                    detected=False,
                    severity="info",
                    confidence=0,
                    signature=None,
                    raw_output="",
                    duration_ms=1,
                ),
                terminal_status="completed",
            )
        # The guarded update rolled back with the raise: job is still claimed.
        self.assertEqual(database.get_scan_engine_job(job.id).status, "claimed")
        self.assertEqual(len(database.list_engine_results(scan_id)), 0)

    def test_commit_conflict_raises_instead_of_attributing_stale_result(self) -> None:
        scan_id, job = self._claim()
        # A stale result already exists for this engine.
        database.create_engine_result_if_missing(
            scan_id,
            EngineResultInput(
                engine_name=job.engine_name,
                status="completed",
                detected=False,
                severity="info",
                confidence=0,
                signature=None,
                raw_output="stale",
                duration_ms=1,
            ),
        )
        with self.assertRaises(database.EngineResultConflictError):
            database.commit_engine_job_result_if_owned(
                job_id=job.id,
                worker_id="worker-A",
                attempt_generation=job.attempt_count,
                result=EngineResultInput(
                    engine_name=job.engine_name,
                    status="failed",
                    detected=False,
                    severity="info",
                    confidence=0,
                    signature=None,
                    raw_output="new",
                    duration_ms=1,
                ),
                terminal_status="failed",
            )
        # Rolled back: job still claimed, only the one pre-existing result remains.
        self.assertEqual(database.get_scan_engine_job(job.id).status, "claimed")
        self.assertEqual(len(database.list_engine_results(scan_id)), 1)

    def test_renew_lease_is_fenced_and_only_for_running_jobs(self) -> None:
        _scan_id, job = self._claim()
        # Claimed (not running) yet: renew targets running only -> no-op.
        self.assertFalse(
            database.renew_scan_engine_job_lease(job.id, "worker-A", job.attempt_count, 120, now=2000)
        )
        database.mark_scan_engine_job_running(
            job.id, "worker-A", lease_seconds=30, now=2000, attempt_generation=job.attempt_count
        )
        # Wrong generation: no-op.
        self.assertFalse(
            database.renew_scan_engine_job_lease(job.id, "worker-A", job.attempt_count + 1, 120, now=2100)
        )
        # Owner + generation + running: extends the lease.
        self.assertTrue(
            database.renew_scan_engine_job_lease(job.id, "worker-A", job.attempt_count, 120, now=2100)
        )
        self.assertEqual(database.get_scan_engine_job(job.id).lease_expires_at, 2220)


class RunEngineLeaseRenewalTests(unittest.TestCase):
    def test_lease_is_renewed_while_a_long_engine_runs(self) -> None:
        import time as _time
        from app.models import EngineInstanceRecord, ScanEngineJobRecord, ScanRecord
        from app.workers import scan_worker

        engine = EngineInstanceRecord(
            id=1,
            adapter_key="clamav",
            display_name="ClamAV",
            enabled=True,
            config_json="{}",
            created_at="",
            updated_at="",
        )
        scan = ScanRecord.__new__(ScanRecord)
        job = ScanEngineJobRecord.__new__(ScanEngineJobRecord)
        object.__setattr__(job, "id", 7)
        object.__setattr__(job, "attempt_count", 1)

        renewals: list[int] = []

        def slow_run(_engine, _scan):
            _time.sleep(0.16)  # spans several renewal intervals
            return "RESULT"

        with patch("app.workers.scan_worker.lease_renewal_interval", return_value=0.05), patch(
            "app.workers.scan_worker.run_engine", side_effect=slow_run
        ), patch(
            "app.workers.scan_worker.renew_scan_engine_job_lease",
            side_effect=lambda *a, **k: renewals.append(1) or True,
        ):
            result = scan_worker.run_engine_with_lease_renewal(engine, scan, job, lease_seconds=30)

        self.assertEqual(result, "RESULT")
        self.assertGreaterEqual(len(renewals), 1)  # renewed during the long run

    def test_finalization_lease_is_renewed_during_long_work(self) -> None:
        import time as _time

        from app.workers import scan_worker

        calls: list[int] = []
        with patch(
            "app.workers.scan_worker.lease_renewal_interval", return_value=0.05
        ), patch(
            "app.workers.scan_worker.renew_scan_finalization",
            side_effect=lambda *a, **k: calls.append(1) or True,
        ):
            with scan_worker.finalization_lease_renewal(7, 1, 30):
                _time.sleep(0.16)  # spans several renewal intervals
        self.assertGreaterEqual(len(calls), 1)

    def test_renewal_stops_when_ownership_is_lost(self) -> None:
        import time as _time
        from app.models import EngineInstanceRecord, ScanEngineJobRecord, ScanRecord
        from app.workers import scan_worker

        engine = EngineInstanceRecord(
            id=1, adapter_key="clamav", display_name="ClamAV", enabled=True,
            config_json="{}", created_at="", updated_at="",
        )
        scan = ScanRecord.__new__(ScanRecord)
        job = ScanEngineJobRecord.__new__(ScanEngineJobRecord)
        object.__setattr__(job, "id", 7)
        object.__setattr__(job, "attempt_count", 1)

        calls: list[int] = []

        def slow_run(_engine, _scan):
            _time.sleep(0.16)
            return "RESULT"

        # renew returns False -> ownership lost -> the loop must stop calling it.
        with patch("app.workers.scan_worker.lease_renewal_interval", return_value=0.05), patch(
            "app.workers.scan_worker.run_engine", side_effect=slow_run
        ), patch(
            "app.workers.scan_worker.renew_scan_engine_job_lease",
            side_effect=lambda *a, **k: (calls.append(1), False)[1],
        ):
            scan_worker.run_engine_with_lease_renewal(engine, scan, job, lease_seconds=30)

        self.assertLessEqual(len(calls), 2)  # stopped after the first False


class TransitionScanToCompletedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_transition_completes_once_and_is_idempotent(self) -> None:
        scan_id = create_scan_with_two_engines(status="running")

        self.assertTrue(database.transition_scan_to_completed(scan_id, "low", 10))
        scan = database.get_scan(scan_id)
        assert scan is not None
        self.assertEqual(scan.status, "completed")
        self.assertEqual(scan.verdict, "low")
        self.assertEqual(scan.risk_score, 10)

        # A second (concurrent) finalizer loses the transition and changes nothing.
        self.assertFalse(database.transition_scan_to_completed(scan_id, "high", 99))
        scan = database.get_scan(scan_id)
        assert scan is not None
        self.assertEqual(scan.verdict, "low")
        self.assertEqual(scan.risk_score, 10)

    def test_failed_scan_is_never_completed(self) -> None:
        scan_id = create_scan_with_two_engines(status="running")
        database.update_scan_status(scan_id, "failed", last_error="boom")
        self.assertFalse(database.transition_scan_to_completed(scan_id, "low", 10))
        scan = database.get_scan(scan_id)
        assert scan is not None
        self.assertEqual(scan.status, "failed")


class ArchiveStagingTests(unittest.TestCase):
    def test_promote_moves_file_and_cleanup_removes_only_stale_dirs(self) -> None:
        import os as _os
        import time as _time

        from app.services import archive_extractor as ae

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            with patch.object(ae, "STAGING_DIR", Path(d) / "staging"):
                staging = ae.new_staging_dir()
                staged_file = staging / "x.bin"
                staged_file.write_bytes(b"hi")
                final = Path(d) / "final.bin"
                ae.promote_staged_file(staged_file, final)
                self.assertTrue(final.is_file())
                self.assertFalse(staged_file.exists())

                stale = ae.new_staging_dir()
                old = _time.time() - 10_000
                _os.utime(stale, (old, old))
                fresh = ae.new_staging_dir()

                removed = ae.cleanup_stale_staging_dirs(max_age_seconds=3600)
                self.assertGreaterEqual(removed, 1)
                self.assertFalse(stale.exists())
                self.assertTrue(fresh.exists())


class ArchiveChildIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def _sample(self, sha: str):
        return StoredSample("m.bin", "m.bin", "/tmp/m.bin", "application/octet-stream", 1, "0" * 32, "0" * 40, sha)

    def _child(self, parent_id: int, batch_id: int, relative_path: str, ordinal: int):
        return database.create_archive_child(
            parent_scan_id=parent_id,
            parent_finalize_worker_id=self.finalizer,
            parent_finalize_generation=self.generation,
            batch_id=batch_id,
            sample=self._sample(str(ordinal) * 64 if len(str(ordinal)) == 1 else "2" * 64),
            engines=database.list_engine_instances(),
            case_name="C",
            priority="Normal",
            note="",
            source="api",
            relative_path=relative_path,
            member_ordinal=ordinal,
        )

    def test_child_intake_is_atomic_and_idempotent_by_ordinal(self) -> None:
        parent = create_scan_with_two_engines(status="running")
        self.finalizer = "w-A"
        self.generation = database.claim_scan_finalization(parent, self.finalizer, lease_seconds=120, now=1000)
        batch_id = database.create_scan_batch(
            source="api", original_filename="a.zip", archive_mode="lazy_extract_on_detection", total_items=1
        )
        c1 = self._child(parent, batch_id, "dup.txt", 0)
        self.assertIsNotNone(c1)
        # Same ordinal again -> idempotent no-op (no new scan, no orphan sample).
        before = database.count_scan_history()
        c1b = self._child(parent, batch_id, "dup.txt", 0)
        self.assertIsNone(c1b)
        self.assertEqual(database.count_scan_history(), before)
        # A DUPLICATE member name at a different ordinal is a distinct child.
        c2 = self._child(parent, batch_id, "dup.txt", 1)
        self.assertIsNotNone(c2)
        self.assertNotEqual(c1, c2)
        # Each child got its engine jobs in the same transaction.
        self.assertEqual(len(database.list_scan_engine_jobs(c1)), 2)
        self.assertEqual(len(database.list_scan_engine_jobs(c2)), 2)

    def test_non_conflict_integrity_error_propagates(self) -> None:
        from app.models import EngineInstanceRecord

        parent = create_scan_with_two_engines(status="running")
        self.finalizer = "w-A"
        self.generation = database.claim_scan_finalization(parent, self.finalizer, lease_seconds=120, now=1000)
        batch_id = database.create_scan_batch(
            source="api", original_filename="a.zip", archive_mode="lazy_extract_on_detection", total_items=1
        )
        # An engine job referencing a non-existent engine instance -> FK violation.
        # It is NOT a member-ordinal duplicate, so it must propagate (not be
        # silently treated as already-registered), and leave no orphan sample.
        bad_engine = EngineInstanceRecord(
            id=999999, adapter_key="ghost", display_name="Ghost", enabled=True,
            config_json="{}", created_at="", updated_at="",
        )
        samples_before = _sample_count_local()
        with self.assertRaises(Exception):
            database.create_archive_child(
                parent_scan_id=parent,
                parent_finalize_worker_id=self.finalizer,
                parent_finalize_generation=self.generation,
                batch_id=batch_id,
                sample=self._sample("3" * 64),
                engines=[bad_engine],
                case_name="C",
                priority="Normal",
                note="",
                source="api",
                relative_path="x.bin",
                member_ordinal=0,
            )
        self.assertEqual(_sample_count_local(), samples_before)


    def test_cleanup_orphan_child_samples_removes_only_unreferenced_old_children(self) -> None:
        import os as _os
        import time as _time

        from app.workers import scan_worker

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            samples = Path(d) / "samples"
            samples.mkdir()
            old = _time.time() - 10_000
            with patch.object(scan_worker, "SAMPLES_DIR", samples):
                orphan = samples / "child-1-0-abc-x.bin"
                orphan.write_bytes(b"x")
                _os.utime(orphan, (old, old))

                referenced = samples / "child-2-0-def-y.bin"
                referenced.write_bytes(b"y")
                _os.utime(referenced, (old, old))
                database.create_sample(
                    StoredSample("y", referenced.name, str(referenced), "application/octet-stream", 1, "0" * 32, "0" * 40, "2" * 64)
                )

                other = samples / "regular.bin"
                other.write_bytes(b"z")
                _os.utime(other, (old, old))

                fresh = samples / "child-3-0-ghi-z.bin"
                fresh.write_bytes(b"z")

                removed = scan_worker.cleanup_orphan_child_samples(max_age_seconds=3600)

            self.assertEqual(removed, 1)
            self.assertFalse(orphan.exists())  # unreferenced + old + child-* -> removed
            self.assertTrue(referenced.exists())  # a sample row points at it
            self.assertTrue(other.exists())  # not a child-* file
            self.assertTrue(fresh.exists())  # within the TTL


def _sample_count_local() -> int:
    with database.connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()
    return int(row["n"] if isinstance(row, dict) else row[0])


class FinalizingIsActiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_decision_for_finalizing_scan_is_wait(self) -> None:
        from app.services.decisions import decide_scan_action

        decision = decide_scan_action(
            scan_status="finalizing",
            verdict="high",
            risk_score=90,
            detected_engines=1,
            detection_engines=1,
            unavailable_engines=[],
        )
        self.assertEqual(decision.action, "wait")

    def test_finalizing_scan_cannot_be_retried(self) -> None:
        scan_id = create_scan_with_two_engines(status="running")
        database.create_scan_engine_jobs(scan_id, database.list_engine_instances())
        database.claim_scan_finalization(scan_id, "w-A", lease_seconds=120, now=1000)
        self.assertEqual(database.get_scan(scan_id).status, "finalizing")
        # Retry must refuse an active (finalizing) scan and leave its jobs intact.
        self.assertFalse(database.retry_scan_job(scan_id))
        self.assertEqual(len(database.list_scan_engine_jobs(scan_id)), 2)


class ScanFinalizationStateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_claim_is_exclusive_and_completion_is_fenced(self) -> None:
        scan_id = create_scan_with_two_engines(status="running")
        gen = database.claim_scan_finalization(scan_id, "w-A", lease_seconds=120, now=1000)
        self.assertIsNotNone(gen)
        self.assertEqual(database.get_scan(scan_id).status, "finalizing")
        # A second claim while the lease is valid loses.
        self.assertIsNone(
            database.claim_scan_finalization(scan_id, "w-B", lease_seconds=120, now=1010)
        )
        # Wrong generation cannot complete.
        self.assertFalse(
            database.complete_finalizing_scan(scan_id, "w-A", gen + 1, "low", 10)
        )
        # The owner completes.
        self.assertTrue(
            database.complete_finalizing_scan(scan_id, "w-A", gen, "low", 10)
        )
        self.assertEqual(database.get_scan(scan_id).status, "completed")

    def test_expired_finalizing_is_stolen_and_crashed_owner_is_fenced(self) -> None:
        scan_id = create_scan_with_two_engines(status="running")
        gen_a = database.claim_scan_finalization(scan_id, "w-A", lease_seconds=30, now=1000)
        # Lease expired; another worker steals the finalization.
        gen_b = database.claim_scan_finalization(scan_id, "w-B", lease_seconds=30, now=2000)
        self.assertIsNotNone(gen_b)
        self.assertGreater(gen_b, gen_a)
        # The crashed original owner cannot complete with its stale generation.
        self.assertFalse(
            database.complete_finalizing_scan(scan_id, "w-A", gen_a, "low", 10)
        )
        self.assertTrue(
            database.complete_finalizing_scan(scan_id, "w-B", gen_b, "high", 90)
        )
        self.assertEqual(database.get_scan(scan_id).verdict, "high")

    def test_renew_finalization_is_fenced(self) -> None:
        scan_id = create_scan_with_two_engines(status="running")
        gen = database.claim_scan_finalization(scan_id, "w-A", lease_seconds=30, now=1000)
        self.assertFalse(
            database.renew_scan_finalization(scan_id, "w-A", gen + 1, 30, now=1010)
        )
        self.assertTrue(
            database.renew_scan_finalization(scan_id, "w-A", gen, 30, now=1010)
        )

    def test_failed_scan_cannot_be_claimed_for_finalization(self) -> None:
        scan_id = create_scan_with_two_engines(status="running")
        database.update_scan_status(scan_id, "failed")
        self.assertIsNone(
            database.claim_scan_finalization(scan_id, "w-A", lease_seconds=30, now=1000)
        )


class SweepFinalizeStuckScansTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_sweep_finalizes_all_terminal_scan_and_is_idempotent(self) -> None:
        from app.workers import scan_worker

        scan_id = create_scan_with_two_engines(status="running")
        engines = database.list_engine_instances()
        database.create_scan_engine_jobs(scan_id, engines)
        # A crashed worker left every engine job terminal but never finalized.
        for job in database.list_scan_engine_jobs(scan_id):
            database.mark_scan_engine_job_terminal(job.id, "completed")
            database.create_engine_result_if_missing(
                scan_id,
                EngineResultInput(
                    engine_name=job.engine_name,
                    status="completed",
                    detected=False,
                    severity="info",
                    confidence=0,
                    signature=None,
                    raw_output="",
                    duration_ms=1,
                ),
            )
        self.assertEqual(database.get_scan(scan_id).status, "running")

        with patch("app.workers.scan_worker.enabled_engines", return_value=engines):
            self.assertEqual(scan_worker.sweep_finalize_stuck_scans(), 1)
            self.assertEqual(database.get_scan(scan_id).status, "completed")
            # Idempotent: the completed scan is no longer active, nothing to do.
            self.assertEqual(scan_worker.sweep_finalize_stuck_scans(), 0)

    def test_sweep_backfills_synthetic_result_for_poisoned_job(self) -> None:
        from app.workers import scan_worker

        scan_id = create_scan_with_two_engines(status="running")
        engines = database.list_engine_instances()
        database.create_scan_engine_jobs(scan_id, engines)
        jobs = database.list_scan_engine_jobs(scan_id)
        for index, job in enumerate(jobs):
            if index == 0:
                database.mark_scan_engine_job_terminal(job.id, "completed")
                database.create_engine_result_if_missing(
                    scan_id,
                    EngineResultInput(
                        engine_name=job.engine_name,
                        status="completed",
                        detected=False,
                        severity="info",
                        confidence=0,
                        signature=None,
                        raw_output="",
                        duration_ms=1,
                    ),
                )
            else:
                # Poisoned by recovery: terminal 'failed' with NO result.
                database.mark_scan_engine_job_terminal(
                    job.id, "failed", last_error="exceeded max attempts"
                )

        with patch("app.workers.scan_worker.enabled_engines", return_value=engines):
            self.assertEqual(scan_worker.sweep_finalize_stuck_scans(), 1)

        self.assertEqual(database.get_scan(scan_id).status, "completed")
        results = {r.engine_name: r.status for r in database.list_engine_results(scan_id)}
        self.assertEqual(len(results), 2)  # one real, one synthetic
        self.assertIn("failed", results.values())


class RecoverRunningScanJobsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def _claim_one(self, lease_seconds: int, now: int):
        scan_id = create_scan_with_two_engines(status="running")
        database.create_scan_engine_jobs(scan_id, database.list_engine_instances())
        claimed = database.claim_next_scan_engine_job(
            {"microsoft_defender"}, "worker-dead", lease_seconds=lease_seconds, now=now
        )
        assert claimed is not None
        return claimed

    def test_expired_claimed_job_is_reset_to_pending(self) -> None:
        claimed = self._claim_one(lease_seconds=30, now=1000)
        # now is well past the lease (1000 + 30).
        recovered = database.recover_running_scan_jobs(now=2000, max_attempts=5)
        self.assertEqual(recovered, 1)
        job = database.get_scan_engine_job(claimed.id)
        assert job is not None
        self.assertEqual(job.status, "pending")
        self.assertIsNone(job.worker_id)
        self.assertIsNone(job.lease_expires_at)

    def test_valid_lease_job_is_not_touched(self) -> None:
        claimed = self._claim_one(lease_seconds=120, now=1000)
        # now is still within the lease window (1000 + 120).
        recovered = database.recover_running_scan_jobs(now=1050, max_attempts=5)
        self.assertEqual(recovered, 0)
        job = database.get_scan_engine_job(claimed.id)
        assert job is not None
        self.assertEqual(job.status, "claimed")
        self.assertEqual(job.worker_id, "worker-dead")

    def test_expired_job_over_attempt_cap_is_failed(self) -> None:
        scan_id = create_scan_with_two_engines(status="running")
        database.create_scan_engine_jobs(scan_id, database.list_engine_instances())

        # Each cycle: claim (attempt++), the lease expires, recovery returns it
        # to pending while under the cap. The claim that reaches the cap is then
        # poisoned to failed by the next recovery pass.
        now = 1000
        job = None
        for _ in range(5):
            job = database.claim_next_scan_engine_job(
                {"microsoft_defender"}, "worker-dead", lease_seconds=30, now=now
            )
            assert job is not None
            now += 100
            database.recover_running_scan_jobs(now=now, max_attempts=5)

        assert job is not None
        final = database.get_scan_engine_job(job.id)
        assert final is not None
        self.assertGreaterEqual(final.attempt_count, 5)
        self.assertEqual(final.status, "failed")
        self.assertIsNotNone(final.last_error)


if __name__ == "__main__":
    unittest.main()
