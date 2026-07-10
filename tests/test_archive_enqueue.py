import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from app import database
from app.main import enqueue_scan_from_upload, normalized_archive_mode
from app.models import StoredSample
from app.services.ingest import UploadTooLargeError


class ArchiveEnqueueTests(unittest.TestCase):
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

    def test_zip_upload_creates_container_scan_batch(self) -> None:
        stored_sample = StoredSample(
            original_filename="bundle.zip",
            stored_filename="bundle.zip",
            storage_path=str(Path(self.temp_dir.name) / "bundle.zip"),
            content_type="application/zip",
            size_bytes=123,
            md5="0" * 32,
            sha1="0" * 40,
            sha256="1" * 64,
        )

        with patch("app.main.store_upload", new=AsyncMock(return_value=stored_sample)), patch(
            "app.services.scan_intake.detect_archive_format",
            return_value="zip",
        ), patch("app.services.scan_intake.enabled_engines", return_value=[]):
            scan = asyncio.run(
                enqueue_scan_from_upload(
                    FakeUpload("bundle.zip"),
                    case_name="Case",
                    priority="Normal",
                    note="",
                    source="api",
                    archive_mode="lazy",
                )
            )

        self.assertEqual(scan.scan_role, "container")
        self.assertEqual(scan.relative_path, "bundle.zip")
        self.assertIsNotNone(scan.batch_id)
        assert scan.batch_id is not None

        batch = database.get_scan_batch(scan.batch_id)
        self.assertIsNotNone(batch)
        assert batch is not None
        self.assertEqual(batch.source, "api")
        self.assertEqual(batch.original_filename, "bundle.zip")
        self.assertEqual(batch.archive_mode, "lazy_extract_on_detection")
        self.assertEqual(batch.total_items, 1)

        metadata = json.loads(batch.metadata_json)
        self.assertEqual(metadata["container_archive_format"], "zip")

    def test_non_zip_upload_remains_standalone(self) -> None:
        stored_sample = StoredSample(
            original_filename="sample.bin",
            stored_filename="sample.bin",
            storage_path=str(Path(self.temp_dir.name) / "sample.bin"),
            content_type="application/octet-stream",
            size_bytes=42,
            md5="0" * 32,
            sha1="0" * 40,
            sha256="2" * 64,
        )

        with patch("app.main.store_upload", new=AsyncMock(return_value=stored_sample)), patch(
            "app.services.scan_intake.detect_archive_format",
            return_value=None,
        ), patch("app.services.scan_intake.enabled_engines", return_value=[]):
            scan = asyncio.run(
                enqueue_scan_from_upload(
                    FakeUpload("sample.bin"),
                    case_name="Case",
                    priority="Normal",
                    note="",
                    source="api",
                )
            )

        self.assertEqual(scan.scan_role, "standalone")
        self.assertIsNone(scan.batch_id)
        self.assertIsNone(scan.relative_path)

    def test_oversized_upload_is_rejected_with_413(self) -> None:
        with patch(
            "app.main.store_upload",
            new=AsyncMock(side_effect=UploadTooLargeError(50 * 1024 * 1024, 60 * 1024 * 1024)),
        ):
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(
                    enqueue_scan_from_upload(
                        FakeUpload("large.bin"),
                        case_name="Case",
                        priority="Normal",
                        note="",
                        source="api",
                    )
                )

        self.assertEqual(ctx.exception.status_code, 413)

    def test_archive_mode_aliases_are_normalized(self) -> None:
        self.assertEqual(normalized_archive_mode("lazy"), "lazy_extract_on_detection")
        self.assertEqual(normalized_archive_mode("container"), "container")


class FakeUpload:
    def __init__(self, filename: str) -> None:
        self.filename = filename


if __name__ == "__main__":
    unittest.main()
