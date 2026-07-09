import tempfile
import unittest
from pathlib import Path

from app import database
from app.models import StoredSample


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


if __name__ == "__main__":
    unittest.main()
