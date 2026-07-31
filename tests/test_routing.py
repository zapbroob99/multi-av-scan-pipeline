import os
from unittest.mock import patch
import unittest
from datetime import datetime, timezone

from app.models import EngineInstanceRecord, ScanRecord
from app.services.routing import (
    ROUTE_ACTION_RUN,
    ROUTE_ACTION_SKIP,
    ROUTE_ACTION_WAIT,
    ROUTE_REASON_FILE_TOO_LARGE,
    ROUTE_REASON_UNSUPPORTED_PLATFORM,
    ROUTE_REASON_WORKER_NOT_ASSIGNED,
    route_engine_for_worker,
)


class RoutingTests(unittest.TestCase):
    def test_linux_worker_waits_for_windows_only_engine(self) -> None:
        decision = route_engine_for_worker(
            make_engine("microsoft_defender", "Microsoft Defender", "{}"),
            make_scan(),
            {"microsoft_defender"},
            platform_name="linux",
        )

        self.assertEqual(decision.action, ROUTE_ACTION_WAIT)
        self.assertEqual(decision.reason_code, ROUTE_REASON_UNSUPPORTED_PLATFORM)

    def test_worker_waits_when_adapter_not_assigned_to_current_node(self) -> None:
        decision = route_engine_for_worker(
            make_engine("clamav", "ClamAV", "{}"),
            make_scan(),
            {"yara"},
            platform_name="linux",
        )

        self.assertEqual(decision.action, ROUTE_ACTION_WAIT)
        self.assertEqual(decision.reason_code, ROUTE_REASON_WORKER_NOT_ASSIGNED)

    def test_clamav_can_skip_large_file_using_configured_limit(self) -> None:
        decision = route_engine_for_worker(
            make_engine("clamav", "ClamAV", '{"max_file_size_bytes":"100"}'),
            make_scan(size_bytes=120),
            {"clamav"},
            platform_name="linux",
        )

        self.assertEqual(decision.action, ROUTE_ACTION_SKIP)
        self.assertEqual(decision.reason_code, ROUTE_REASON_FILE_TOO_LARGE)
        self.assertEqual(decision.details["routing"]["max_file_size_bytes"], 100)

    def test_clamd_own_limit_skips_before_streaming_and_names_the_source(self) -> None:
        # The adapter cap is unlimited (0), but clamd enforces 64M. Routing must
        # skip on the effective limit; otherwise the sample is streamed to clamd
        # just to be rejected there, which surfaces as an engine failure and
        # makes "I raised the adapter limit" look like it did nothing.
        with patch.dict(
            os.environ,
            {
                "MASP_CLAMD_HOST": "clamav",
                "MASP_CLAMD_STREAM_MAX_LENGTH": "64M",
                "MASP_CLAMD_MAX_FILE_SIZE": "64M",
            },
            clear=False,
        ):
            decision = route_engine_for_worker(
                make_engine("clamav", "ClamAV", '{"max_file_size_bytes": "0"}'),
                make_scan(size_bytes=100 * 1024**2),
                {"clamav"},
                platform_name="linux",
            )

        self.assertEqual(decision.action, ROUTE_ACTION_SKIP)
        self.assertEqual(decision.reason_code, ROUTE_REASON_FILE_TOO_LARGE)
        routing = decision.details["routing"]
        self.assertEqual(routing["max_file_size_bytes"], 64 * 1024**2)
        self.assertIn("clamd", routing["max_file_size_source"])
        # The operator must be able to tell which setting to raise.
        self.assertIn("clamd", decision.reason)

    def test_engine_runs_when_within_both_limits(self) -> None:
        with patch.dict(
            os.environ,
            {
                "MASP_CLAMD_HOST": "clamav",
                "MASP_CLAMD_STREAM_MAX_LENGTH": "64M",
                "MASP_CLAMD_MAX_FILE_SIZE": "64M",
            },
            clear=False,
        ):
            decision = route_engine_for_worker(
                make_engine("clamav", "ClamAV", '{"max_file_size_bytes": "0"}'),
                make_scan(size_bytes=1024),
                {"clamav"},
                platform_name="linux",
            )

        self.assertEqual(decision.action, ROUTE_ACTION_RUN)

    def test_supported_engine_runs_when_eligible(self) -> None:
        decision = route_engine_for_worker(
            make_engine("yara", "YARA", "{}"),
            make_scan(),
            {"yara"},
            platform_name="linux",
        )

        self.assertEqual(decision.action, ROUTE_ACTION_RUN)
        self.assertEqual(decision.reason_code, "eligible")


def make_engine(adapter_key: str, display_name: str, config_json: str) -> EngineInstanceRecord:
    return EngineInstanceRecord(
        id=1,
        adapter_key=adapter_key,
        display_name=display_name,
        enabled=True,
        config_json=config_json,
        created_at="",
        updated_at="",
    )


def make_scan(size_bytes: int = 16) -> ScanRecord:
    timestamp = datetime.now(timezone.utc).isoformat(sep=" ")
    return ScanRecord(
        id=1,
        sample_id=1,
        case_name="Case",
        priority="Normal",
        note="",
        source="manual",
        status="queued",
        verdict="pending",
        risk_score=None,
        created_at=timestamp,
        started_at=None,
        completed_at=None,
        failed_at=None,
        attempt_count=1,
        last_error=None,
        original_filename="sample.bin",
        stored_filename="sample.bin",
        storage_path="storage/samples/sample.bin",
        content_type="application/octet-stream",
        size_bytes=size_bytes,
        md5="md5",
        sha1="sha1",
        sha256="sha256",
    )


if __name__ == "__main__":
    unittest.main()
