import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database as db
from app.services import intake_read, manifest_intake
from app.services.deferred_storage import DeferredSourceError, redact_paths


class IntakeReadCase(unittest.TestCase):
    postgres = False

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.original = (db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED)
        db.close_pool()
        url = os.environ["MASP_TEST_POSTGRES_URL"] if self.postgres else ""
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = Path(self.temp.name) / "intake.db", url, False
        self.addCleanup(self._restore)
        if self.postgres:
            import psycopg
            with psycopg.connect(url, autocommit=True) as connection:
                connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
                connection.execute("CREATE SCHEMA public")
        db.init_db()
        self.client_id = db.create_service_client("drive-storage", "Drive storage")
        engine = db.create_engine_instance("static_metadata", "Metadata")
        self.profile_id = db.create_scan_profile(self.client_id, "Full scan", engine_instance_ids=[engine],
                                                 is_default=True)

    def _restore(self) -> None:
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def submission(self, request_id: str, *, status: str = "pending", attempts: int = 0,
                   error: str | None = None, created_at: str | None = None) -> int:
        record, _ = db.create_deferred_scan_submission(
            service_client_id=self.client_id, scan_profile_id=self.profile_id,
            client_request_id=request_id, backend_key="drive", object_id=f"uploads/{request_id}.pdf",
            original_filename=f"{request_id}.pdf", content_type="application/pdf",
            expected_size_bytes=None, expected_sha256=None, archive_mode="lazy_extract_on_detection",
            case_name="Storage upload", priority="Normal", note="", profile_snapshot_json="{}")
        with db.connect() as connection:
            connection.execute("""UPDATE deferred_scan_submissions SET status = ?, attempt_count = ?,
                last_error = ? WHERE id = ?""", (status, attempts, error, record.id))
            if created_at is not None:
                connection.execute("UPDATE deferred_scan_submissions SET created_at = ? WHERE id = ?",
                                   (created_at, record.id))
        return record.id


class IntakeOverviewTests(IntakeReadCase):
    def test_empty_deployment_reports_no_worker_rather_than_a_healthy_one(self) -> None:
        view = intake_read.overview()
        self.assertIsNone(view.manifest_worker)
        self.assertFalse(view.manifest_record_invalid)
        self.assertEqual(view.queue.pending, 0)
        self.assertIsNone(view.queue.oldest_pending_age_seconds)
        self.assertEqual((view.rejections, view.rejections_total, view.failures), ([], 0, []))

    def test_queue_counts_active_states_and_the_oldest_pending_age(self) -> None:
        self.submission("a", created_at="2026-09-20 10:00:00")
        self.submission("b", attempts=2, error="Deferred source object is unavailable.")
        self.submission("c", status="claimed")
        self.submission("d", status="queued")
        self.submission("e", status="completed")
        queue = intake_read.overview().queue
        self.assertEqual((queue.pending, queue.retrying, queue.claimed, queue.queued), (2, 1, 1, 1))
        self.assertTrue(queue.oldest_pending_at.startswith("2026-09-20T10:00:00"))
        self.assertGreater(queue.oldest_pending_age_seconds, 24 * 3600)

    def test_failures_are_newest_first_bounded_and_path_free(self) -> None:
        ids = [self.submission(f"f{index}", status="failed", attempts=1,
                               error=f"[Errno 13] Permission denied: '/mnt/share/uploads/f{index}.pdf'")
               for index in range(intake_read.FAILURE_LIMIT + 1)]
        view = intake_read.overview()
        self.assertEqual(len(view.failures), intake_read.FAILURE_LIMIT)
        self.assertTrue(view.failures_truncated)
        self.assertEqual([row.id for row in view.failures], ids[::-1][:intake_read.FAILURE_LIMIT])
        self.assertEqual(view.failures[0].client_name, "Drive storage")
        self.assertEqual(view.failures[0].last_error, "[Errno 13] Permission denied: '<path>'")
        self.assertNotIn("/mnt/share", json.dumps(view.model_dump()))

    def test_rejections_are_bounded_counted_and_path_free(self) -> None:
        for index in range(intake_read.REJECTION_LIMIT + 2):
            db.record_manifest_rejection("drive", f"uploads/m{index:03}.json", "Manifest must be a JSON object.")
        db.record_manifest_rejection("drive", "uploads/legacy.json",
                                     "Manifest is unavailable: [Errno 2] No such file: 'C:\\share\\legacy.json'")
        view = intake_read.overview()
        self.assertEqual(len(view.rejections), intake_read.REJECTION_LIMIT)
        self.assertEqual(view.rejections_total, intake_read.REJECTION_LIMIT + 3)
        legacy = next(row for row in view.rejections if row.manifest_object_id == "uploads/legacy.json")
        self.assertEqual(legacy.reason, "Manifest is unavailable: [Errno 2] No such file: '<path>'")

    def test_worker_cycle_is_reported_with_its_own_configuration(self) -> None:
        env = {"MASP_MANIFEST_BACKEND_KEY": "Drive", "MASP_MANIFEST_CLIENT_KEY": "drive-storage",
               "MASP_MANIFEST_ROOT_PREFIX": "/uploads/", "MASP_MANIFEST_LOOKBACK_DAYS": "5"}
        with patch.dict(os.environ, env):
            manifest_intake.record_cycle(ok=True, poll_seconds=15, accepted=2, duplicates=1, rejected=1)
        worker = intake_read.overview().manifest_worker
        self.assertTrue(worker.ok)
        self.assertFalse(worker.stale)
        self.assertEqual((worker.accepted, worker.duplicates, worker.rejected), (2, 1, 1))
        self.assertEqual((worker.backend_key, worker.root_prefix, worker.lookback_days), ("drive", "uploads", 5))

    def test_old_cycle_is_stale_and_failed_cycle_carries_a_path_free_error(self) -> None:
        with patch("app.services.manifest_intake.time.time", return_value=time.time() - 3600):
            manifest_intake.record_cycle(ok=False, poll_seconds=15,
                                         error="OSError: [Errno 5] I/O error: '/mnt/share/uploads'")
        worker = intake_read.overview().manifest_worker
        self.assertTrue(worker.stale)
        self.assertFalse(worker.ok)
        self.assertEqual(worker.error, "OSError: [Errno 5] I/O error: '<path>'")

    def test_unreadable_worker_record_is_flagged_not_shown_as_healthy(self) -> None:
        db.set_setting(manifest_intake.LAST_CYCLE_SETTING, '{"at": "never"}')
        view = intake_read.overview()
        self.assertIsNone(view.manifest_worker)
        self.assertTrue(view.manifest_record_invalid)

    def test_recording_never_stops_intake(self) -> None:
        with patch("app.services.manifest_intake.db.set_setting", side_effect=RuntimeError("db down")):
            manifest_intake.record_cycle(ok=True, poll_seconds=15)


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class IntakeOverviewPostgresTests(IntakeOverviewTests):
    postgres = True


class PathRedactionTests(unittest.TestCase):
    def test_absolute_paths_are_replaced_and_relative_object_ids_kept(self) -> None:
        self.assertEqual(redact_paths("denied: '/srv/a b/c.pdf'"), "denied: '<path>'")
        self.assertEqual(redact_paths('denied: "D:\\share\\c.pdf"'), 'denied: "<path>"')
        self.assertEqual(redact_paths("object 'uploads/c.pdf' missing"), "object 'uploads/c.pdf' missing")

    def test_unreadable_manifest_reason_carries_no_path(self) -> None:
        with patch("app.services.manifest_intake.resolve_source_path",
                   return_value=Path(tempfile.gettempdir()) / "missing-masp-manifest.json"):
            with self.assertRaises(DeferredSourceError) as raised:
                manifest_intake.read_manifest("drive", "uploads/missing.json")
        self.assertNotIn(tempfile.gettempdir(), str(raised.exception))
        self.assertIn("Manifest is unavailable", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
