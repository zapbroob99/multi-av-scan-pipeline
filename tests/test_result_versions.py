"""Each engine result names the engine and signatures that produced it."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.engines import clamav, microsoft_defender, yara_engine
from app.models import EngineResultInput, ScanRecord


def completed(details=None):
    return EngineResultInput(engine_name="ClamAV", status="completed", detected=False, severity="info", confidence=0,
                             signature=None, raw_output="stream: OK", duration_ms=5, engine_version="clamd",
                             details_json=json.dumps(details or {"adapter": "clamav"}))


class ClamavDatabaseVersionTests(unittest.TestCase):
    def test_a_completed_scan_records_the_engine_and_signature_database(self):
        with patch.object(clamav, "version_clamd", return_value="ClamAV 1.4.2/27771/Mon Sep 22 08:21:03 2026"):
            result = clamav.with_database_version(completed(), "clamav", 3310, 5)
        self.assertEqual((result.engine_version, result.signature_version), ("1.4.2", "27771"))
        details = json.loads(result.details_json)
        self.assertEqual(details["database"], {"signature_version": "27771", "signature_date": "2026-09-22T08:21:03+00:00"})
        self.assertEqual(details["adapter"], "clamav")
        self.assertEqual((result.status, result.raw_output), ("completed", "stream: OK"))

    def test_an_unanswered_version_query_keeps_the_scan_and_says_so(self):
        with patch.object(clamav, "version_clamd", side_effect=ConnectionRefusedError()):
            result = clamav.with_database_version(completed(), "clamav", 3310, 5)
        self.assertEqual((result.status, result.engine_version, result.signature_version), ("completed", "clamd", None))
        self.assertIn("error", json.loads(result.details_json)["database"])

    def test_an_unfinished_scan_asks_nothing(self):
        failed = EngineResultInput(engine_name="ClamAV", status="failed", detected=False, severity="info",
                                   confidence=0, signature=None, raw_output="", duration_ms=1)
        with patch.object(clamav, "version_clamd") as query:
            self.assertIs(clamav.with_database_version(failed, "clamav", 3310, 5), failed)
        query.assert_not_called()


class DefenderVersionTests(unittest.TestCase):
    def test_a_defender_result_carries_the_versions_read_before_the_scan(self):
        health = {"ok": True, "status": "available", "detail": "ready", "engine_version": "1.1.24090.11",
                  "signature_version": "1.419.150.0"}
        scan = ScanRecord(id=1, sample_id=1, case_name="", priority="normal", note="", source="manual", status="running",
                          verdict="pending", risk_score=None, created_at="", started_at=None, completed_at=None,
                          failed_at=None, attempt_count=1, last_error=None,
                          original_filename="a.txt", stored_filename="a", storage_path="a", content_type="text/plain",
                          size_bytes=1, md5="0", sha1="0", sha256="0" * 64)
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "a.txt"
            sample.write_bytes(b"x")
            with patch.object(microsoft_defender, "cached_microsoft_defender_health", return_value=health), \
                    patch.object(microsoft_defender, "resolve_sample_path", return_value=sample), \
                    patch.object(microsoft_defender, "resolve_mpcmdrun_path", return_value="MpCmdRun.exe"), \
                    patch.object(microsoft_defender, "run_mpcmdrun_custom_scan",
                                 return_value={"command": "x", "returncode": 0, "raw_output": "found no threats"}):
                result = microsoft_defender.run_microsoft_defender_engine(scan, {"update_before_scan": "false"})
        self.assertEqual((result.engine_version, result.signature_version), ("1.1.24090.11", "1.419.150.0"))


class YaraRuleSetTests(unittest.TestCase):
    def test_the_rule_set_is_named_by_content_never_by_path(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for directory in (first, second):
                (Path(directory) / "a.yar").write_text("rule A { condition: true }")
            one = yara_engine.rule_set_version([Path(first) / "a.yar"])
            self.assertEqual(one, yara_engine.rule_set_version([Path(second) / "a.yar"]))
            self.assertTrue(one.startswith("1 rule files, set "))
            self.assertNotIn(first, one)
            (Path(second) / "a.yar").write_text("rule A { condition: false }")
            self.assertNotEqual(one, yara_engine.rule_set_version([Path(second) / "a.yar"]))
        self.assertIsNone(yara_engine.rule_set_version([]))


if __name__ == "__main__":
    unittest.main()
