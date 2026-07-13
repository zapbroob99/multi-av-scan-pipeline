import subprocess
import unittest
from unittest import mock

from app.engines import eset_server_security_linux as eset


class NormalizeOdscanResultTests(unittest.TestCase):
    def normalize(self, returncode: int, raw_output: str = "output"):
        return eset.normalize_odscan_result(
            returncode=returncode,
            raw_output=raw_output,
            duration_ms=5,
            details={},
        )

    def test_exit_0_is_clean(self) -> None:
        result = self.normalize(0)
        self.assertEqual(result.status, "completed")
        self.assertFalse(result.detected)
        self.assertIsNone(result.error_message)

    def test_exit_50_is_detected(self) -> None:
        result = self.normalize(50)
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.detected)
        self.assertIsNone(result.error_message)

    def test_exit_1_is_detected_with_warning(self) -> None:
        # threat found and cleaned — unexpected under --readonly
        result = self.normalize(1)
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.detected)
        self.assertIsNotNone(result.error_message)
        self.assertIn("readonly", str(result.error_message).lower())

    def test_exit_10_is_failed_never_clean(self) -> None:
        result = self.normalize(10)
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.detected)
        self.assertIn("could not be scanned", str(result.error_message))

    def test_exit_100_is_failed(self) -> None:
        result = self.normalize(100)
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.detected)

    def test_unknown_exit_is_failed(self) -> None:
        result = self.normalize(7)
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.detected)
        self.assertIn("unexpected code 7", str(result.error_message))

    def test_negative_one_is_failed(self) -> None:
        result = self.normalize(-1)
        self.assertEqual(result.status, "failed")

    def test_no_threat_name_parsing_generic_signature(self) -> None:
        # FIXTURE-PENDING: even with threat-like text, the signature stays generic.
        result = self.normalize(50, raw_output="Eicar-Test-Signature found")
        self.assertIn("pending fixture", str(result.signature))


class CheckEsetHealthTests(unittest.TestCase):
    def test_unsupported_on_windows(self) -> None:
        with mock.patch.object(eset.os, "name", "nt"):
            health = eset.check_eset_health(config={"executable_path": "auto", "timeout_seconds": 5})
        self.assertFalse(health["ok"])
        self.assertEqual(health["status"], "unsupported")

    def test_not_ready_when_executable_missing(self) -> None:
        with mock.patch.object(eset.os, "name", "posix"), mock.patch.object(
            eset, "resolve_odscan_path", return_value=None
        ):
            health = eset.check_eset_health(config={"executable_path": "auto", "timeout_seconds": 5})
        self.assertFalse(health["ok"])
        self.assertEqual(health["status"], "not configured")

    def test_ok_when_executable_present(self) -> None:
        with mock.patch.object(eset.os, "name", "posix"), mock.patch.object(
            eset, "resolve_odscan_path", return_value="/opt/eset/efs/bin/odscan"
        ):
            health = eset.check_eset_health(config={"executable_path": "auto", "timeout_seconds": 5})
        self.assertTrue(health["ok"])
        self.assertEqual(health["status"], "available")

    def test_health_runs_no_subprocess(self) -> None:
        # Health is on the per-scan hot path; it must never shell out.
        with mock.patch.object(eset.os, "name", "posix"), mock.patch.object(
            eset, "resolve_odscan_path", return_value="/opt/eset/efs/bin/odscan"
        ), mock.patch.object(eset.subprocess, "run") as mock_run:
            eset.check_eset_health(config={"executable_path": "auto", "timeout_seconds": 5})
        mock_run.assert_not_called()

    def test_probe_function_removed(self) -> None:
        self.assertFalse(hasattr(eset, "probe_odscan_version"))


class RunOdscanTests(unittest.TestCase):
    def test_timeout_returns_error_message(self) -> None:
        with mock.patch.object(
            eset.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="odscan", timeout=1),
        ):
            outcome = eset.run_odscan("/x/odscan", __import__("pathlib").Path("/tmp/s"), 1)
        self.assertEqual(outcome["returncode"], -1)
        self.assertIn("timed out", str(outcome["error_message"]))

    def test_oserror_returns_error_message(self) -> None:
        with mock.patch.object(eset.subprocess, "run", side_effect=OSError("no exec")):
            outcome = eset.run_odscan("/x/odscan", __import__("pathlib").Path("/tmp/s"), 1)
        self.assertEqual(outcome["returncode"], -1)
        self.assertIn("could not be executed", str(outcome["error_message"]))

    def test_readonly_flag_present_in_command(self) -> None:
        completed = mock.Mock(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(eset.subprocess, "run", return_value=completed):
            outcome = eset.run_odscan("/x/odscan", __import__("pathlib").Path("/tmp/s"), 5)
        self.assertIn("--readonly", outcome["command"])
        self.assertIn("--scan", outcome["command"])

    def test_ignore_exclusions_on_adds_flag(self) -> None:
        completed = mock.Mock(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(eset.subprocess, "run", return_value=completed):
            outcome = eset.run_odscan(
                "/x/odscan", __import__("pathlib").Path("/tmp/s"), 5, True
            )
        self.assertIn("--ignore-exclusions", outcome["command"])

    def test_ignore_exclusions_off_omits_flag(self) -> None:
        completed = mock.Mock(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(eset.subprocess, "run", return_value=completed):
            outcome = eset.run_odscan(
                "/x/odscan", __import__("pathlib").Path("/tmp/s"), 5, False
            )
        self.assertNotIn("--ignore-exclusions", outcome["command"])
        # sample path still last, scan still present
        self.assertIn("--scan", outcome["command"])


class SettingBoolTests(unittest.TestCase):
    def test_explicit_false_disables(self) -> None:
        for value in ("0", "false", "no", "off"):
            with self.subTest(value=value):
                self.assertFalse(eset.setting_bool({}, "flag", value))

    def test_invalid_value_fails_safe(self) -> None:
        self.assertTrue(eset.setting_bool({}, "flag", "treu"))

    def test_explicit_true_enables(self) -> None:
        for value in ("1", "true", "yes", "on"):
            with self.subTest(value=value):
                self.assertTrue(eset.setting_bool({}, "flag", value))


if __name__ == "__main__":
    unittest.main()
