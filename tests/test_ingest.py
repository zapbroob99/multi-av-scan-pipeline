import asyncio
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import UploadFile

from app.services.ingest import UploadTooLargeError, sanitize_filename, store_upload


class IngestServiceTests(unittest.TestCase):
    def test_sanitize_filename_removes_unsafe_characters(self) -> None:
        self.assertEqual(
            sanitize_filename("../Quarterly Report (final).exe"),
            "Quarterly_Report_final_.exe",
        )

    def test_store_upload_removes_partial_file_when_limit_is_exceeded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_samples_dir = Path(temp_dir)
            upload = UploadFile(
                filename="sample.bin",
                file=io.BytesIO(b"abcdef"),
            )

            with patch("app.services.ingest.SAMPLES_DIR", temp_samples_dir):
                with self.assertRaises(UploadTooLargeError):
                    asyncio.run(store_upload(upload, max_size_bytes=3))

            self.assertEqual(list(temp_samples_dir.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
