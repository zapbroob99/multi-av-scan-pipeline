import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import zipfile

import py7zr

from app.services.archive_extractor import (
    ArchiveExtractionError,
    ArchiveExtractionLimitError,
    ArchiveExtractionLimits,
    UnsafeArchivePathError,
    detect_archive_format,
    extract_archive,
    is_supported_archive,
    safe_member_relative_path,
)


class ArchiveExtractorZipTests(unittest.TestCase):
    def test_extract_archive_stores_child_samples_with_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "bundle.zip"
            samples_dir = root / "samples"

            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("docs/readme.txt", b"hello archive")
                archive.writestr("bin/tool.exe", b"MZ")

            with patch("app.services.archive_extractor.SAMPLES_DIR", samples_dir):
                result = extract_archive(archive_path)

            self.assertEqual(result.total_uncompressed_bytes, len(b"hello archive") + len(b"MZ"))
            self.assertEqual([member.relative_path for member in result.members], ["docs/readme.txt", "bin/tool.exe"])
            self.assertEqual(len(list(samples_dir.iterdir())), 2)
            self.assertEqual(result.members[0].sample.original_filename, "readme.txt")
            self.assertEqual(result.members[0].sample.size_bytes, len(b"hello archive"))
            self.assertEqual(result.members[0].sample.sha256, "f8976760708ac1d60ab4b2dd1fa3c02d3bbf9693846f1db27aa77b46f0bb4276")

    def test_extract_archive_rejects_zip_slip_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "evil.zip"
            samples_dir = root / "samples"

            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape.txt", b"escape")

            with patch("app.services.archive_extractor.SAMPLES_DIR", samples_dir):
                with self.assertRaises(UnsafeArchivePathError):
                    extract_archive(archive_path)

            self.assertEqual(list(samples_dir.iterdir()), [])

    def test_extract_archive_applies_file_count_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "too-many.zip"

            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("a.txt", b"a")
                archive.writestr("b.txt", b"b")

            limits = ArchiveExtractionLimits(max_files=1)

            with self.assertRaises(ArchiveExtractionLimitError):
                extract_archive(archive_path, limits=limits, destination_dir=root / "samples")


class ArchiveExtractorTarTests(unittest.TestCase):
    def test_extract_tar_gz_archive_stores_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "bundle.tar.gz"
            samples_dir = root / "samples"

            with tarfile.open(archive_path, "w:gz") as archive:
                _add_tar_member(archive, "docs/readme.txt", b"hello tar")
                _add_tar_member(archive, "bin/tool.exe", b"MZ")

            with patch("app.services.archive_extractor.SAMPLES_DIR", samples_dir):
                result = extract_archive(archive_path)

            self.assertEqual([member.relative_path for member in result.members], ["docs/readme.txt", "bin/tool.exe"])
            self.assertEqual(result.total_uncompressed_bytes, len(b"hello tar") + len(b"MZ"))
            self.assertEqual(result.members[0].sample.size_bytes, len(b"hello tar"))
            self.assertEqual(len(list(samples_dir.iterdir())), 2)

    def test_extract_tar_skips_symlinks_and_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "links.tar"
            samples_dir = root / "samples"

            with tarfile.open(archive_path, "w") as archive:
                directory = tarfile.TarInfo("nested")
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)

                symlink = tarfile.TarInfo("nested/link.txt")
                symlink.type = tarfile.SYMTYPE
                symlink.linkname = "/etc/passwd"
                archive.addfile(symlink)

                _add_tar_member(archive, "nested/real.txt", b"real content")

            with patch("app.services.archive_extractor.SAMPLES_DIR", samples_dir):
                result = extract_archive(archive_path)

            self.assertEqual([member.relative_path for member in result.members], ["nested/real.txt"])
            self.assertEqual(len(list(samples_dir.iterdir())), 1)

    def test_extract_tar_rejects_traversal_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "evil.tar"
            samples_dir = root / "samples"

            with tarfile.open(archive_path, "w") as archive:
                _add_tar_member(archive, "../escape.txt", b"escape")

            with patch("app.services.archive_extractor.SAMPLES_DIR", samples_dir):
                with self.assertRaises(UnsafeArchivePathError):
                    extract_archive(archive_path)

            self.assertEqual(list(samples_dir.iterdir()), [])

    def test_extract_tar_applies_single_file_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "big.tar"

            with tarfile.open(archive_path, "w") as archive:
                _add_tar_member(archive, "big.bin", b"x" * 64)

            limits = ArchiveExtractionLimits(max_single_file_bytes=16)

            with self.assertRaises(ArchiveExtractionLimitError):
                extract_archive(archive_path, limits=limits, destination_dir=root / "samples")


class ArchiveExtractorSevenZipTests(unittest.TestCase):
    def test_extract_7z_archive_stores_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "bundle.7z"
            samples_dir = root / "samples"

            with py7zr.SevenZipFile(archive_path, "w") as archive:
                archive.writestr(b"hello seven zip", "docs/readme.txt")
                archive.writestr(b"MZ", "bin/tool.exe")
                archive.writestr(b"", "empty.txt")

            with patch("app.services.archive_extractor.SAMPLES_DIR", samples_dir):
                result = extract_archive(archive_path)

            by_path = {member.relative_path: member for member in result.members}
            self.assertEqual(set(by_path), {"docs/readme.txt", "bin/tool.exe", "empty.txt"})
            self.assertEqual(by_path["docs/readme.txt"].sample.size_bytes, len(b"hello seven zip"))
            self.assertEqual(by_path["empty.txt"].sample.size_bytes, 0)
            self.assertEqual(result.total_uncompressed_bytes, len(b"hello seven zip") + len(b"MZ"))
            self.assertEqual(len(list(samples_dir.iterdir())), 3)

    def test_extract_7z_rejects_encrypted_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "locked.7z"
            samples_dir = root / "samples"

            with py7zr.SevenZipFile(archive_path, "w", password="secret") as archive:
                archive.writestr(b"secret payload", "hidden.txt")

            with patch("app.services.archive_extractor.SAMPLES_DIR", samples_dir):
                with self.assertRaises(ArchiveExtractionError):
                    extract_archive(archive_path)

            self.assertEqual(list(samples_dir.iterdir()), [])

    def test_extract_7z_applies_declared_size_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "big.7z"

            with py7zr.SevenZipFile(archive_path, "w") as archive:
                archive.writestr(b"x" * 64, "big.bin")

            limits = ArchiveExtractionLimits(max_single_file_bytes=16)

            with self.assertRaises(ArchiveExtractionLimitError):
                extract_archive(archive_path, limits=limits, destination_dir=root / "samples")


class ArchiveFormatDetectionTests(unittest.TestCase):
    def test_detect_archive_format_for_each_supported_format(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            zip_path = root / "a.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("a.txt", b"a")

            tar_path = root / "a.tar.gz"
            with tarfile.open(tar_path, "w:gz") as archive:
                _add_tar_member(archive, "a.txt", b"a")

            seven_zip_path = root / "a.7z"
            with py7zr.SevenZipFile(seven_zip_path, "w") as archive:
                archive.writestr(b"a", "a.txt")

            plain_path = root / "plain.bin"
            plain_path.write_bytes(b"just bytes, not an archive")

            self.assertEqual(detect_archive_format(zip_path), "zip")
            self.assertEqual(detect_archive_format(tar_path), "tar")
            self.assertEqual(detect_archive_format(seven_zip_path), "7z")
            self.assertIsNone(detect_archive_format(plain_path))
            self.assertIsNone(detect_archive_format(root / "missing.bin"))

            self.assertTrue(is_supported_archive(zip_path))
            self.assertFalse(is_supported_archive(plain_path))

    def test_extract_archive_rejects_unsupported_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain_path = root / "plain.bin"
            plain_path.write_bytes(b"just bytes, not an archive")

            with self.assertRaises(ArchiveExtractionError):
                extract_archive(plain_path, destination_dir=root / "samples")


class SafeMemberRelativePathTests(unittest.TestCase):
    def test_safe_member_relative_path_rejects_absolute_and_deep_paths(self) -> None:
        limits = ArchiveExtractionLimits(max_depth=2)

        self.assertEqual(safe_member_relative_path("nested/file.txt", limits), "nested/file.txt")
        with self.assertRaises(UnsafeArchivePathError):
            safe_member_relative_path("/absolute.txt", limits)
        with self.assertRaises(UnsafeArchivePathError):
            safe_member_relative_path("C:/absolute.txt", limits)
        with self.assertRaises(ArchiveExtractionLimitError):
            safe_member_relative_path("a/b/c.txt", limits)


def _add_tar_member(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))


if __name__ == "__main__":
    unittest.main()
