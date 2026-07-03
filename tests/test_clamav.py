import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.engines.clamav import (
    get_clamav_config,
    is_retryable_clamd_connection_error,
    run_clamd_scan,
)
from app.models import ScanRecord


class ClamAVConfigTests(unittest.TestCase):
    def test_clamd_config_includes_readiness_retry_defaults(self) -> None:
        config = get_clamav_config({"host": "clamav"})

        self.assertEqual(config["mode"], "clamd")
        self.assertEqual(config["ready_timeout_seconds"], 30)
        self.assertEqual(config["retry_interval_seconds"], 1.0)


class ClamAVRetryTests(unittest.TestCase):
    def test_connection_refused_is_retryable(self) -> None:
        self.assertTrue(
            is_retryable_clamd_connection_error(
                ConnectionRefusedError(111, "Connection refused")
            )
        )

    def test_socket_timeout_is_retryable(self) -> None:
        self.assertTrue(is_retryable_clamd_connection_error(socket.timeout("timed out")))

    def test_unrelated_os_error_is_not_retryable(self) -> None:
        self.assertFalse(
            is_retryable_clamd_connection_error(
                FileNotFoundError(2, "No such file or directory")
            )
        )


class ClamAVLargeSampleTests(unittest.TestCase):
    def test_clamd_size_limit_error_is_failed_with_hint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample_path = Path(temp_dir) / "large.bin"
            sample_path.write_bytes(b"x")
            with patch(
                "app.engines.clamav.scan_with_clamd_when_ready",
                return_value="INSTREAM: Size limit exceeded. ERROR",
            ):
                result = run_clamd_scan(
                    scan_record(sample_path),
                    host="clamav",
                    port=3310,
                    timeout=180,
                    ready_timeout=30,
                    retry_interval=1.0,
                )

        self.assertEqual(result.status, "failed")
        self.assertIn("StreamMaxLength", result.error_message or "")
        self.assertIn("Size limit exceeded", result.raw_output)

    def test_clamd_broken_pipe_is_failed_with_hint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample_path = Path(temp_dir) / "large.bin"
            sample_path.write_bytes(b"x")
            with patch(
                "app.engines.clamav.scan_with_clamd_when_ready",
                side_effect=BrokenPipeError(32, "Broken pipe"),
            ):
                result = run_clamd_scan(
                    scan_record(sample_path),
                    host="clamav",
                    port=3310,
                    timeout=180,
                    ready_timeout=30,
                    retry_interval=1.0,
                )

        self.assertEqual(result.status, "failed")
        self.assertIn("StreamMaxLength", result.error_message or "")
        self.assertIn("Broken pipe", result.raw_output)


def scan_record(sample_path: Path) -> ScanRecord:
    return ScanRecord(
        id=1,
        sample_id=1,
        case_name="case",
        priority="Normal",
        note="",
        status="running",
        verdict="pending",
        risk_score=None,
        created_at="2026-07-03 19:00:00",
        started_at=None,
        completed_at=None,
        failed_at=None,
        attempt_count=1,
        last_error=None,
        original_filename=sample_path.name,
        stored_filename=sample_path.name,
        storage_path=str(sample_path),
        content_type="application/octet-stream",
        size_bytes=sample_path.stat().st_size,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


if __name__ == "__main__":
    unittest.main()
