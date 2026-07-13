import json
import os
import stat
import tempfile
import unittest
from unittest import mock

import tools.eset_discovery as discovery


class RedactionTests(unittest.TestCase):
    def test_redacts_sample_and_custom_executable(self) -> None:
        redact = discovery.build_redactor(
            [("[SAMPLE_PATH]", "/srv/corp/staging/evil.bin"), ("[EXECUTABLE]", "/custom/odscan")]
        )
        out = redact("ran /custom/odscan on /srv/corp/staging/evil.bin")
        self.assertNotIn("/srv/corp", out)
        self.assertNotIn("/custom/odscan", out)
        self.assertIn("[SAMPLE_PATH]", out)
        self.assertIn("[EXECUTABLE]", out)

    def test_redacts_ipv4(self) -> None:
        redact = discovery.build_redactor()
        self.assertNotIn("10.1.2.3", redact("connect 10.1.2.3"))

    def test_longer_literal_wins(self) -> None:
        # sample path contained inside another literal should still be masked
        redact = discovery.build_redactor(
            [("[A]", "/srv/x"), ("[B]", "/srv/x/staging/evil.bin")]
        )
        out = redact("/srv/x/staging/evil.bin")
        self.assertEqual(out, "[B]")

    def test_inventory_redacts_custom_executable_path(self) -> None:
        executable = "/srv/corp/eset/bin/odscan"
        redact = discovery.build_redactor([("[EXECUTABLE]", executable)])
        with mock.patch.object(discovery, "VERSION_PROBE_CANDIDATES", ()):
            inventory = discovery.run_inventory(executable, 5, redact)
        self.assertEqual(inventory["odscan_path"], "[EXECUTABLE]")


class ScanRefusalTests(unittest.TestCase):
    def test_scan_without_yes_exits_2(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b"x")
            path = handle.name
        try:
            rc = discovery.main(["--scan-sample", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 2)


class SampleScanFieldsTests(unittest.TestCase):
    def test_records_sha_and_change_fields(self) -> None:
        redact = discovery.build_redactor()
        completed = mock.Mock(returncode=50, stdout="threat", stderr="")
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b"content")
            path = handle.name
        try:
            with mock.patch.object(discovery.subprocess, "run", return_value=completed):
                outcome = discovery.run_sample_scan(
                    "/opt/eset/efs/bin/odscan", path, 5, redact
                )
        finally:
            os.unlink(path)
        for key in ("sha256_before", "sha256_after", "file_changed", "file_missing_after_scan"):
            self.assertIn(key, outcome)
        self.assertEqual(outcome["exit_code"], 50)
        self.assertFalse(outcome["file_changed"])  # subprocess mocked, file untouched
        self.assertFalse(outcome["file_missing_after_scan"])
        self.assertIn("--ignore-exclusions", outcome["argv"])

    def test_detects_missing_file_after_scan(self) -> None:
        redact = discovery.build_redactor()
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b"content")
            path = handle.name

        def fake_run(*args, **kwargs):
            os.unlink(path)  # simulate real-time quarantine removing the file
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(discovery.subprocess, "run", side_effect=fake_run):
            outcome = discovery.run_sample_scan("/opt/eset/efs/bin/odscan", path, 5, redact)
        self.assertTrue(outcome["file_missing_after_scan"])


class OutputPermissionsTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX file mode check")
    def test_output_written_0600(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "report.json")
            # os.open(..., mode) does not change an existing file's mode.
            # Pre-create it as world-readable to exercise the overwrite path.
            with open(out_path, "w", encoding="utf-8") as handle:
                handle.write("old\n")
            os.chmod(out_path, 0o644)
            rc = discovery.main(["--output", out_path])
            self.assertEqual(rc, 0)
            mode = stat.S_IMODE(os.stat(out_path).st_mode)
            self.assertEqual(mode, 0o600)
            with open(out_path) as handle:
                json.load(handle)  # valid JSON


if __name__ == "__main__":
    unittest.main()
