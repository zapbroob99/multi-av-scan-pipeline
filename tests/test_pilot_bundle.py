import tempfile
import unittest
from pathlib import Path

from tools.package_pilot_release import (
    checked_payloads,
    collect_files,
    write_checksum_sidecar,
)


ROOT_DIR = Path(__file__).resolve().parent.parent


class PilotBundleTests(unittest.TestCase):
    def test_compose_keeps_database_private_and_icap_fail_closed(self) -> None:
        compose = (ROOT_DIR / "docker-compose.pilot.yml").read_text(encoding="utf-8")
        postgres_section = compose.split("  postgres:\n", 1)[1].split("  clamav:\n", 1)[0]

        self.assertNotIn("ports:", postgres_section)
        self.assertIn('MASP_ICAP_FAIL_MODE_CLOSED: "1"', compose)
        self.assertIn('MASP_ICAP_BLOCK_ON_REVIEW: "1"', compose)
        self.assertIn("MASP_ICAP_ALLOWED_IPS:", compose)
        self.assertIn("MASP_STORAGE_DIR", compose)

    def test_example_contains_placeholders_not_credentials(self) -> None:
        env_text = (ROOT_DIR / ".env.pilot.example").read_text(encoding="utf-8")

        self.assertIn("MASP_POSTGRES_PASSWORD=CHANGE_ME", env_text)
        self.assertIn("MASP_API_TOKEN=CHANGE_ME", env_text)
        self.assertIn("MASP_ICAP_ALLOWED_IPS=127.0.0.1", env_text)

    def test_release_allowlist_excludes_local_and_benchmark_files(self) -> None:
        relative_paths = {
            str(path.relative_to(ROOT_DIR)).replace("\\", "/") for path in collect_files()
        }

        self.assertIn("docker-compose.pilot.yml", relative_paths)
        self.assertIn("deploy/pilot/install.sh", relative_paths)
        self.assertIn("docs/deployment/PILOT.md", relative_paths)
        # Apache-2.0 4(a)/4(d): every distributed copy carries these.
        self.assertIn("LICENSE", relative_paths)
        self.assertIn("NOTICE", relative_paths)
        # The PostgreSQL acceptance gate runs on the pilot host from the bundled
        # suite (the image deliberately does not contain it), so the runbook's
        # documented command is unrunnable without these.
        self.assertIn("deploy/pilot/run_gated_tests.sh", relative_paths)
        for module in (
            "tests/test_db_concurrent_init.py",
            "tests/test_reliability_postgres.py",
            "tests/test_worker_heartbeat_concurrency.py",
            "tests/test_worker_fencing_concurrency.py",
            "tests/test_archive_finalization_integration.py",
        ):
            self.assertIn(module, relative_paths)
        self.assertFalse(any(path.startswith("storage/") for path in relative_paths))
        self.assertFalse(any(path.startswith("benchmark-results/") for path in relative_paths))
        self.assertFalse(any(path.startswith("benchmark-samples/") for path in relative_paths))
        self.assertFalse(any(path.startswith("sample_") for path in relative_paths))
        self.assertNotIn(".env.pilot", relative_paths)

    def test_shipped_files_have_unix_line_endings(self) -> None:
        # The release is built on Windows (git checks the tree out with CRLF) and
        # runs on Linux. A CRLF shell script fails with "/usr/bin/env: 'bash\r':
        # No such file or directory" -- an error that names bash, not the line
        # endings, so it costs real time on a live host. Every shipped file is
        # text, so none of them may carry CRLF.
        offenders = [
            name for name, data in checked_payloads(collect_files()) if b"\r\n" in data
        ]

        self.assertEqual(offenders, [], f"CRLF in shipped files: {offenders}")

    def test_checksum_sidecar_uses_unix_line_endings(self) -> None:
        # Releases are built on a Windows machine and verified on the Linux pilot
        # host with `sha256sum -c`. Text-mode writing turns the trailing \n into
        # \r\n there, and the carriage return becomes part of the parsed
        # filename, so verification fails on a perfectly good archive. (This
        # assertion only fails on a Windows builder -- on Linux both spellings
        # produce the same bytes -- which is exactly where the release is made.)
        with tempfile.TemporaryDirectory() as temp_dir:
            sidecar = Path(temp_dir) / "release.zip.sha256"
            write_checksum_sidecar(sidecar, "a" * 64, "release.zip")
            raw = sidecar.read_bytes()

        self.assertEqual(raw, b"a" * 64 + b"  release.zip\n")
        self.assertNotIn(b"\r", raw)

    def test_release_inputs_pass_secret_scan(self) -> None:
        payloads = checked_payloads(collect_files())
        self.assertGreater(len(payloads), 10)


if __name__ == "__main__":
    unittest.main()
