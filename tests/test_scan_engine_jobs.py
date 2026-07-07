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


def create_scan_with_two_engines(status: str = "queued", source: str = "manual") -> int:
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
        status=status,
        verdict="pending",
    )


if __name__ == "__main__":
    unittest.main()
