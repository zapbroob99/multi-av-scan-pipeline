import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import zipfile

from app.services.archive_extractor import (
    ArchiveExtractionLimitError,
    ArchiveExtractionLimits,
    UnsafeArchivePathError,
    extract_zip_archive,
    safe_zip_relative_path,
)


class ArchiveExtractorTests(unittest.TestCase):
    def test_extract_zip_archive_stores_child_samples_with_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "bundle.zip"
            samples_dir = root / "samples"

            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("docs/readme.txt", b"hello archive")
                archive.writestr("bin/tool.exe", b"MZ")

            with patch("app.services.archive_extractor.SAMPLES_DIR", samples_dir):
                result = extract_zip_archive(archive_path)

            self.assertEqual(result.total_uncompressed_bytes, len(b"hello archive") + len(b"MZ"))
            self.assertEqual([member.relative_path for member in result.members], ["docs/readme.txt", "bin/tool.exe"])
            self.assertEqual(len(list(samples_dir.iterdir())), 2)
            self.assertEqual(result.members[0].sample.original_filename, "readme.txt")
            self.assertEqual(result.members[0].sample.size_bytes, len(b"hello archive"))
            self.assertEqual(result.members[0].sample.sha256, "f8976760708ac1d60ab4b2dd1fa3c02d3bbf9693846f1db27aa77b46f0bb4276")

    def test_extract_zip_archive_rejects_zip_slip_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "evil.zip"
            samples_dir = root / "samples"

            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape.txt", b"escape")

            with patch("app.services.archive_extractor.SAMPLES_DIR", samples_dir):
                with self.assertRaises(UnsafeArchivePathError):
                    extract_zip_archive(archive_path)

            self.assertEqual(list(samples_dir.iterdir()), [])

    def test_extract_zip_archive_applies_file_count_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "too-many.zip"

            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("a.txt", b"a")
                archive.writestr("b.txt", b"b")

            limits = ArchiveExtractionLimits(max_files=1)

            with self.assertRaises(ArchiveExtractionLimitError):
                extract_zip_archive(archive_path, limits=limits, destination_dir=root / "samples")

    def test_safe_zip_relative_path_rejects_absolute_and_deep_paths(self) -> None:
        limits = ArchiveExtractionLimits(max_depth=2)

        self.assertEqual(safe_zip_relative_path("nested/file.txt", limits), "nested/file.txt")
        with self.assertRaises(UnsafeArchivePathError):
            safe_zip_relative_path("/absolute.txt", limits)
        with self.assertRaises(UnsafeArchivePathError):
            safe_zip_relative_path("C:/absolute.txt", limits)
        with self.assertRaises(ArchiveExtractionLimitError):
            safe_zip_relative_path("a/b/c.txt", limits)


if __name__ == "__main__":
    unittest.main()
