import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.engines import file_type
from app.engines.file_type import (
    declared_extension,
    detect_type,
    get_file_type_config,
    run_file_type_engine,
)
from app.models import ScanRecord


def make_scan(path: Path, filename: str, *, content_type: str = "application/octet-stream") -> ScanRecord:
    return ScanRecord(
        id=1, sample_id=1, case_name="Case", priority="Normal", note="", source="api",
        batch_id=None, parent_scan_id=None, relative_path=None, scan_role="standalone",
        service_client_id=None, scan_profile_id=None, profile_snapshot_json="",
        status="running", verdict="pending", risk_score=None,
        created_at="2026-09-22 00:00:00+00:00", started_at=None, completed_at=None,
        failed_at=None, attempt_count=0, last_error=None,
        original_filename=filename, stored_filename=filename, storage_path=str(path),
        content_type=content_type, size_bytes=path.stat().st_size if path.exists() else 0,
        md5="md5", sha1="sha1", sha256="sha256",
    )


class FileTypeEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def run_engine(self, filename: str, payload: bytes, override: dict | None = None):
        path = self.root / filename.replace("/", "_")
        path.write_bytes(payload)
        result = run_file_type_engine(make_scan(path, filename), override)
        return result, json.loads(result.details_json), json.loads(result.findings_json)

    def test_matching_declaration_reports_no_finding(self) -> None:
        for filename, payload in (
            ("invoice.pdf", b"%PDF-1.7 body"),
            ("report.docx", b"PK\x03\x04rest"),
            ("setup.exe", b"MZ\x90\x00"),
            ("photo.png", b"\x89PNG\r\n\x1a\nrest"),
        ):
            with self.subTest(filename=filename):
                result, details, findings = self.run_engine(filename, payload)
                self.assertEqual(result.status, "completed")
                self.assertEqual(details["outcome"], "match")
                self.assertEqual(result.severity, "info")
                self.assertFalse(result.detected)
                self.assertEqual(findings, [])

    def test_executable_masquerading_as_document_is_high_severity(self) -> None:
        result, details, findings = self.run_engine("invoice.pdf", b"MZ\x90\x00payload")
        self.assertEqual(details["outcome"], "mismatch")
        self.assertEqual(details["detected_type"], "pe")
        self.assertEqual(details["expected_types"], ["pdf"])
        self.assertEqual(result.severity, "high")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "file_type_mismatch")
        self.assertEqual(findings[0]["category"], "masquerade")
        self.assertIn("executable", findings[0]["tags"])

    def test_non_executable_mismatch_stays_medium(self) -> None:
        result, details, findings = self.run_engine("photo.png", b"GIF89a rest")
        self.assertEqual(details["outcome"], "mismatch")
        self.assertEqual(result.severity, "medium")
        self.assertNotIn("executable", findings[0]["tags"])

    def test_report_action_never_claims_a_detection(self) -> None:
        # The shared scoring layer adds 70 points for any detected result, so a
        # masquerading extension must not reach it unless an operator opts in.
        result, _, findings = self.run_engine("invoice.pdf", b"MZ\x90\x00")
        self.assertFalse(result.detected)
        self.assertEqual(len(findings), 1)
        # The signature still names what was seen; only the detected flag, which
        # the scoring layer reads, stays off.
        self.assertEqual(result.signature, "TypeMismatch.pdf-is-pe")

    def test_detect_action_marks_the_result_and_names_the_mismatch(self) -> None:
        result, details, _ = self.run_engine("invoice.pdf", b"MZ\x90\x00", {"mismatch_action": "detect"})
        self.assertTrue(result.detected)
        self.assertEqual(result.signature, "TypeMismatch.pdf-is-pe")
        self.assertEqual(details["mismatch_action"], "detect")

    def test_unknown_content_and_unknown_extension_are_not_mismatches(self) -> None:
        _, plain, _ = self.run_engine("notes.txt", b"just some text")
        self.assertEqual(plain["outcome"], "undetermined")
        self.assertIsNone(plain["detected_type"])
        _, nameless, _ = self.run_engine("payload", b"%PDF-1.4")
        self.assertEqual(nameless["outcome"], "undeclared")
        self.assertIsNone(nameless["expected_types"])

    def test_container_extensions_accept_their_archive_family(self) -> None:
        for filename in ("bundle.jar", "sheet.xlsx", "deck.pptx", "app.apk"):
            with self.subTest(filename=filename):
                _, details, findings = self.run_engine(filename, b"PK\x03\x04payload")
                self.assertEqual(details["outcome"], "match", filename)
                self.assertEqual(findings, [])

    def test_only_a_bounded_header_is_read(self) -> None:
        path = self.root / "large.pdf"
        path.write_bytes(b"%PDF-1.7" + b"x" * (5 * 1024 * 1024))
        reads: list[int] = []
        real_open = Path.open

        def tracking_open(self, *args, **kwargs):
            handle = real_open(self, *args, **kwargs)
            real_read = handle.read

            def read(size=-1):
                reads.append(size)
                return real_read(size)

            handle.read = read
            return handle

        with patch.object(Path, "open", tracking_open):
            result = run_file_type_engine(make_scan(path, "large.pdf"))
        details = json.loads(result.details_json)
        self.assertEqual(result.status, "completed")
        self.assertEqual(details["outcome"], "match")
        # One bounded read on a 5 MiB sample: cost does not grow with size.
        self.assertEqual(reads, [file_type.DEFAULT_HEADER_BYTES])
        self.assertEqual(details["header_bytes_read"], file_type.DEFAULT_HEADER_BYTES)

    def test_missing_sample_is_skipped_not_failed(self) -> None:
        scan = make_scan(self.root / "absent.pdf", "absent.pdf")
        result = run_file_type_engine(scan)
        self.assertEqual(result.status, "skipped")
        self.assertFalse(result.detected)
        self.assertIsNotNone(result.error_message)

    def test_unreadable_sample_fails_without_claiming_a_verdict(self) -> None:
        path = self.root / "locked.pdf"
        path.write_bytes(b"%PDF-1.7")
        with patch.object(Path, "open", side_effect=OSError("permission denied")):
            result = run_file_type_engine(make_scan(path, "locked.pdf"))
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.detected)
        self.assertEqual(result.severity, "info")
        self.assertIn("permission denied", result.error_message)


class FileTypeConfigTests(unittest.TestCase):
    def test_blank_override_falls_back_instead_of_disabling(self) -> None:
        # A present-but-empty value beat its fallback in the ClamAV and Defender
        # adapters and broke scanning on the pilot host; do not repeat it.
        with patch.dict(os.environ, {"MASP_FILE_TYPE_MISMATCH_ACTION": "detect"}, clear=False):
            self.assertEqual(get_file_type_config({"mismatch_action": ""})["mismatch_action"], "detect")
            self.assertEqual(get_file_type_config({})["mismatch_action"], "detect")

    def test_header_bytes_is_clamped_and_invalid_values_fall_back(self) -> None:
        self.assertEqual(get_file_type_config({"header_bytes": "1"})["header_bytes"], file_type.MIN_HEADER_BYTES)
        self.assertEqual(
            get_file_type_config({"header_bytes": str(10 * 1024 * 1024)})["header_bytes"],
            file_type.MAX_HEADER_BYTES,
        )
        self.assertEqual(
            get_file_type_config({"header_bytes": "not-a-number"})["header_bytes"],
            file_type.DEFAULT_HEADER_BYTES,
        )

    def test_unknown_mismatch_action_falls_back_to_report(self) -> None:
        self.assertEqual(get_file_type_config({"mismatch_action": "quarantine"})["mismatch_action"], "report")
        self.assertEqual(get_file_type_config({"mismatch_action": "DETECT"})["mismatch_action"], "detect")


class SignatureTableTests(unittest.TestCase):
    def test_longer_signatures_win_over_shared_prefixes(self) -> None:
        # ZIP and OOXML share PK; OLE2 and nothing else share D0CF. A shorter
        # entry placed first would shadow a longer, more specific one.
        self.assertEqual(detect_type(b"\x89PNG\r\n\x1a\n"), "png")
        self.assertEqual(detect_type(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), "ole2")
        self.assertEqual(detect_type(b"7z\xbc\xaf\x27\x1c"), "7z")

    def test_offset_signatures_are_honoured(self) -> None:
        self.assertEqual(detect_type(b"\x00" * 257 + b"ustar\x00"), "tar")
        self.assertIsNone(detect_type(b"ustar" + b"\x00" * 100))

    def test_declared_extension_ignores_names_without_one(self) -> None:
        self.assertEqual(declared_extension("report.PDF"), "pdf")
        self.assertEqual(declared_extension("archive.tar.gz"), "gz")
        self.assertEqual(declared_extension("noextension"), "")
        self.assertEqual(declared_extension(""), "")


if __name__ == "__main__":
    unittest.main()
