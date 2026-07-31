import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.engines.clamav import (
    effective_max_file_size,
    get_clamav_config,
    is_retryable_clamd_connection_error,
    parse_size_bytes,
    run_clamd_scan,
)
from app.models import ScanRecord


class ClamAVConfigTests(unittest.TestCase):
    def test_clamd_config_includes_readiness_retry_defaults(self) -> None:
        config = get_clamav_config({"host": "clamav"})

        self.assertEqual(config["mode"], "clamd")
        self.assertEqual(config["ready_timeout_seconds"], 30)
        self.assertEqual(config["retry_interval_seconds"], 1.0)

    def test_blank_host_override_falls_back_to_the_environment(self) -> None:
        # Regression, found live on the pilot host: saving the engine config form
        # persisted host="" over the env-provided host. A present-but-empty value
        # used to win over the fallback, dropping ClamAV into clamscan CLI mode --
        # a binary the app image does not ship -- so every scan failed. Under
        # fail-closed ICAP that blocks otherwise-clean uploads.
        with patch.dict(os.environ, {"MASP_CLAMD_HOST": "clamav"}, clear=False):
            config = get_clamav_config({"host": ""})

        self.assertEqual(config["mode"], "clamd")
        self.assertEqual(config["host"], "clamav")

    def test_whitespace_only_host_override_is_also_treated_as_unset(self) -> None:
        with patch.dict(os.environ, {"MASP_CLAMD_HOST": "clamav"}, clear=False):
            config = get_clamav_config({"host": "   "})

        self.assertEqual(config["mode"], "clamd")
        self.assertEqual(config["host"], "clamav")

    def test_explicit_host_override_still_wins_over_the_environment(self) -> None:
        # Blank means "unset", but a real value must still override the env.
        with patch.dict(os.environ, {"MASP_CLAMD_HOST": "clamav"}, clear=False):
            config = get_clamav_config({"host": "other-clamd"})

        self.assertEqual(config["host"], "other-clamd")

    def test_cli_mode_still_reachable_when_no_host_is_configured_anywhere(self) -> None:
        # Blank-as-unset must not make CLI mode unreachable: with no override and
        # no env, the engine still falls back to the clamscan CLI.
        with patch.dict(os.environ, {"MASP_CLAMD_HOST": ""}, clear=False), patch(
            "app.engines.clamav.engine_setting", side_effect=lambda key, fallback: fallback
        ):
            config = get_clamav_config({"host": ""})

        self.assertEqual(config["mode"], "cli")


class ClamAVSizeChainTests(unittest.TestCase):
    """The adapter cap and clamd's own cap must reconcile into one limit.

    Found live: raising the upload limit and the adapter's max_file_size let a
    large sample through to clamd, which rejected it for its own 64M cap. The
    result was an opaque engine failure, and raising "the limit" in one place
    appeared to do nothing.
    """

    def _env(self, **values):
        return patch.dict(os.environ, {"MASP_CLAMD_HOST": "clamav", **values}, clear=False)

    def test_parses_clamd_style_sizes(self) -> None:
        self.assertEqual(parse_size_bytes("64M"), 64 * 1024**2)
        self.assertEqual(parse_size_bytes("1G"), 1024**3)
        self.assertEqual(parse_size_bytes("512k"), 512 * 1024)
        self.assertEqual(parse_size_bytes("1048576"), 1048576)

    def test_unparseable_or_empty_size_means_no_limit(self) -> None:
        for value in ("", "   ", "abc", "-5", "0"):
            self.assertEqual(parse_size_bytes(value), 0, value)

    def test_clamd_cap_binds_when_the_adapter_cap_is_larger(self) -> None:
        with self._env(MASP_CLAMD_STREAM_MAX_LENGTH="64M", MASP_CLAMD_MAX_FILE_SIZE="64M"):
            config = get_clamav_config({"max_file_size_bytes": str(500 * 1024**2)})

        self.assertEqual(config["effective_max_file_size_bytes"], 64 * 1024**2)
        self.assertIn("clamd", str(config["effective_max_file_size_source"]))

    def test_unlimited_adapter_cap_still_respects_clamd(self) -> None:
        # 0 means "no adapter limit" -- previously this sent everything to clamd.
        with self._env(MASP_CLAMD_STREAM_MAX_LENGTH="64M", MASP_CLAMD_MAX_FILE_SIZE="64M"):
            config = get_clamav_config({"max_file_size_bytes": "0"})

        self.assertEqual(config["effective_max_file_size_bytes"], 64 * 1024**2)

    def test_adapter_cap_binds_when_it_is_the_smaller_one(self) -> None:
        with self._env(MASP_CLAMD_STREAM_MAX_LENGTH="64M", MASP_CLAMD_MAX_FILE_SIZE="64M"):
            config = get_clamav_config({"max_file_size_bytes": str(1024**2)})

        self.assertEqual(config["effective_max_file_size_bytes"], 1024**2)
        self.assertIn("adapter", str(config["effective_max_file_size_source"]))

    def test_smallest_clamd_limit_wins(self) -> None:
        with self._env(MASP_CLAMD_STREAM_MAX_LENGTH="64M", MASP_CLAMD_MAX_FILE_SIZE="16M"):
            config = get_clamav_config({"max_file_size_bytes": "0"})

        self.assertEqual(config["effective_max_file_size_bytes"], 16 * 1024**2)

    def test_effective_limit_helper_reports_unlimited_when_nothing_is_capped(self) -> None:
        self.assertEqual(effective_max_file_size(0, 0), (0, "unlimited"))


class ClamAVSizeLimitResultTests(unittest.TestCase):
    def test_clamd_size_rejection_is_skipped_not_failed(self) -> None:
        # An engine declining a sample for its own size cap is missing coverage,
        # not a malfunction. Scoring counts skipped and failed alike as missing
        # coverage, so the scan still lands on review -- this only stops the
        # result reading as a broken engine.
        with tempfile.TemporaryDirectory() as temp_dir:
            sample_path = Path(temp_dir) / "large.bin"
            sample_path.write_bytes(b"x")
            with patch(
                "app.engines.clamav.scan_with_clamd_when_ready",
                return_value="INSTREAM: Size limit exceeded. ERROR",
            ):
                result = run_clamd_scan(
                    scan_record(sample_path),
                    host="clamav", port=3310, timeout=180,
                    ready_timeout=30, retry_interval=1.0,
                )

        self.assertEqual(result.status, "skipped")
        self.assertFalse(result.detected)
        self.assertIn("clamd", (result.error_message or "").lower())
        self.assertIn("MASP_CLAMD_STREAM_MAX_LENGTH", result.error_message or "")
        # clamd's own words are kept for the operator.
        self.assertIn("Size limit exceeded", result.raw_output)

    def test_generic_clamd_error_is_still_a_failure(self) -> None:
        # Only the size case becomes a skip; a real error must stay a failure.
        with tempfile.TemporaryDirectory() as temp_dir:
            sample_path = Path(temp_dir) / "s.bin"
            sample_path.write_bytes(b"x")
            with patch(
                "app.engines.clamav.scan_with_clamd_when_ready",
                return_value="INSTREAM: Can't allocate memory ERROR",
            ):
                result = run_clamd_scan(
                    scan_record(sample_path),
                    host="clamav", port=3310, timeout=180,
                    ready_timeout=30, retry_interval=1.0,
                )

        self.assertEqual(result.status, "failed")


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
    # The size-limit response is now a skip, not a failure: see
    # ClamAVSizeLimitResultTests.test_clamd_size_rejection_is_skipped_not_failed.

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
        source="manual",
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
