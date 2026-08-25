import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database
from app.services import ingest
from app.services.ingest import UploadTooLargeError, store_bytes
from app.services.scan_intake import (
    NoEligibleEnginesError,
    enqueue_scan_from_stored_sample,
)


class StoreBytesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.samples_patch = patch.object(
            ingest, "SAMPLES_DIR", Path(self.temp_dir.name)
        )
        self.samples_patch.start()

    def tearDown(self) -> None:
        self.samples_patch.stop()
        self.temp_dir.cleanup()

    def test_store_bytes_writes_file_and_computes_hashes(self) -> None:
        data = b"hello world payload"
        stored = store_bytes("upload.bin", "application/octet-stream", data)

        self.assertEqual(stored.size_bytes, len(data))
        self.assertEqual(stored.md5, hashlib.md5(data).hexdigest())
        self.assertEqual(stored.sha1, hashlib.sha1(data).hexdigest())
        self.assertEqual(stored.sha256, hashlib.sha256(data).hexdigest())
        self.assertTrue(Path(stored.storage_path).is_file())
        self.assertEqual(Path(stored.storage_path).read_bytes(), data)

    def test_store_bytes_sanitizes_filename(self) -> None:
        stored = store_bytes("../../etc/passwd", "text/plain", b"x")
        self.assertNotIn("/", stored.original_filename)
        self.assertNotIn("..", stored.original_filename)

    def test_store_bytes_enforces_size_cap(self) -> None:
        with self.assertRaises(UploadTooLargeError):
            store_bytes("big.bin", "application/octet-stream", b"A" * 100, max_size_bytes=10)


class EnqueueFromStoredSampleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()
        database.create_engine_instance("static_metadata", "Static Metadata")
        self.engines = database.list_engine_instances()
        self.engines_patch = patch(
            "app.services.scan_intake.enabled_engines", return_value=self.engines
        )
        self.enabled_engines_mock = self.engines_patch.start()

    def tearDown(self) -> None:
        self.engines_patch.stop()
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def _stored(self, filename: str = "sample.bin"):
        from app.models import StoredSample

        path = Path(self.temp_dir.name) / filename
        path.write_bytes(b"payload")
        return StoredSample(
            original_filename=filename,
            stored_filename=f"stored-{filename}",
            storage_path=str(path),
            content_type="application/octet-stream",
            size_bytes=10,
            md5="0" * 32,
            sha1="0" * 40,
            sha256="1" * 64,
        )

    def test_enqueue_creates_standalone_icap_scan(self) -> None:
        with patch("app.services.scan_intake.detect_archive_format", return_value=None):
            scan = enqueue_scan_from_stored_sample(
                self._stored(),
                case_name="ICAP",
                priority="Normal",
                note="via icap",
                source="icap",
            )

        self.assertEqual(scan.source, "icap")
        self.assertEqual(scan.scan_role, "standalone")
        self.assertIsNone(scan.batch_id)
        self.enabled_engines_mock.assert_called_with(source="icap")
        # Engine jobs were created in the same transaction.
        self.assertEqual(len(database.list_scan_engine_jobs(scan.id)), 1)

    def test_enqueue_creates_container_batch_for_archive(self) -> None:
        with patch("app.services.scan_intake.detect_archive_format", return_value="zip"):
            scan = enqueue_scan_from_stored_sample(
                self._stored("bundle.zip"),
                case_name="ICAP",
                priority="Normal",
                note="",
                source="icap",
            )

        self.assertEqual(scan.scan_role, "container")
        self.assertIsNotNone(scan.batch_id)
        assert scan.batch_id is not None
        batch = database.get_scan_batch(scan.batch_id)
        assert batch is not None
        self.assertEqual(batch.source, "icap")

    def test_zero_enabled_engines_rejects_intake_and_removes_file(self) -> None:
        stored = self._stored()
        self.assertTrue(Path(stored.storage_path).is_file())
        with patch("app.services.scan_intake.enabled_engines", return_value=[]):
            with self.assertRaises(NoEligibleEnginesError):
                enqueue_scan_from_stored_sample(
                    stored,
                    case_name="ICAP",
                    priority="Normal",
                    note="",
                    source="icap",
                )
        # Rejected before any DB commit: the orphaned file is cleaned up.
        self.assertEqual(database.count_scan_history(), 0)
        self.assertFalse(Path(stored.storage_path).is_file())

    def test_archive_detection_error_removes_file(self) -> None:
        stored = self._stored()
        with patch(
            "app.services.scan_intake.detect_archive_format",
            side_effect=OSError("cannot read"),
        ):
            with self.assertRaises(OSError):
                enqueue_scan_from_stored_sample(
                    stored,
                    case_name="ICAP",
                    priority="Normal",
                    note="",
                    source="icap",
                )
        self.assertEqual(database.count_scan_history(), 0)
        self.assertFalse(Path(stored.storage_path).is_file())

    def test_db_failure_compensates_stored_file_and_creates_no_scan(self) -> None:
        stored = self._stored()
        self.assertTrue(Path(stored.storage_path).is_file())
        with patch("app.services.scan_intake.detect_archive_format", return_value=None), patch(
            "app.services.scan_intake.create_scan_intake",
            side_effect=RuntimeError("boom"),
        ):
            with self.assertRaises(RuntimeError):
                enqueue_scan_from_stored_sample(
                    stored,
                    case_name="ICAP",
                    priority="Normal",
                    note="",
                    source="icap",
                )
        # The orphaned file was removed and no scan/sample persisted.
        self.assertFalse(Path(stored.storage_path).is_file())
        self.assertEqual(database.count_scan_history(), 0)

    def test_engine_job_insert_failure_rolls_back_the_whole_scan(self) -> None:
        # A failure while inserting engine jobs must roll back the sample + scan
        # too (single transaction), leaving nothing behind.
        stored = self._stored()
        with patch("app.services.scan_intake.detect_archive_format", return_value=None), patch(
            "app.database._insert_engine_jobs", side_effect=RuntimeError("engine insert failed")
        ):
            with self.assertRaises(RuntimeError):
                enqueue_scan_from_stored_sample(
                    stored,
                    case_name="ICAP",
                    priority="Normal",
                    note="",
                    source="icap",
                )
        self.assertEqual(database.count_scan_history(), 0)
        self.assertFalse(Path(stored.storage_path).is_file())


if __name__ == "__main__":
    unittest.main()
