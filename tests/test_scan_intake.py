import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database
from app.services import ingest
from app.services.ingest import UploadTooLargeError, store_bytes
from app.services.scan_intake import enqueue_scan_from_stored_sample


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

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def _stored(self, filename: str = "sample.bin"):
        from app.models import StoredSample

        return StoredSample(
            original_filename=filename,
            stored_filename=f"stored-{filename}",
            storage_path=str(Path(self.temp_dir.name) / filename),
            content_type="application/octet-stream",
            size_bytes=10,
            md5="0" * 32,
            sha1="0" * 40,
            sha256="1" * 64,
        )

    def test_enqueue_creates_standalone_icap_scan(self) -> None:
        with patch("app.services.scan_intake.detect_archive_format", return_value=None), patch(
            "app.services.scan_intake.enabled_engines", return_value=[]
        ):
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

    def test_enqueue_creates_container_batch_for_archive(self) -> None:
        with patch("app.services.scan_intake.detect_archive_format", return_value="zip"), patch(
            "app.services.scan_intake.enabled_engines", return_value=[]
        ):
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


if __name__ == "__main__":
    unittest.main()
