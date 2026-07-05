import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.models import EngineInstanceRecord, ScanRecord
from app.workers.scan_worker import (
    partial_results_wait_seconds,
    scan_elapsed_seconds,
    should_finalize_scan_with_partial_results,
    skipped_engine_result,
)


class WorkerTimeoutTests(unittest.TestCase):
    def test_missing_engine_wait_uses_engine_timeout_plus_grace(self) -> None:
        engine = make_engine(
            "microsoft_defender",
            "Microsoft Defender",
            '{"timeout_seconds":"30"}',
        )
        self.assertEqual(partial_results_wait_seconds([engine]), 35)

    def test_missing_engine_wait_is_capped_for_long_timeouts(self) -> None:
        engine = make_engine(
            "microsoft_defender",
            "Microsoft Defender",
            '{"timeout_seconds":"900"}',
        )
        self.assertEqual(partial_results_wait_seconds([engine]), 120)

    def test_scan_finalizes_when_wait_window_expires(self) -> None:
        engine = make_engine(
            "microsoft_defender",
            "Microsoft Defender",
            '{"timeout_seconds":"30"}',
        )
        scan = make_scan(started_seconds_ago=40)
        self.assertTrue(should_finalize_scan_with_partial_results(scan, [engine]))

    def test_scan_elapsed_seconds_uses_started_at_when_present(self) -> None:
        scan = make_scan(started_seconds_ago=12, created_seconds_ago=50)
        now = datetime.now(timezone.utc)
        elapsed = scan_elapsed_seconds(scan, now=now)
        self.assertGreaterEqual(elapsed, 12)
        self.assertLess(elapsed, 20)

    def test_timeout_creates_skipped_engine_result(self) -> None:
        engine = make_engine(
            "microsoft_defender",
            "Microsoft Defender",
            '{"timeout_seconds":"30"}',
        )
        scan = make_scan(started_seconds_ago=40)
        with patch("app.services.routing.worker_platform", return_value="linux"):
            result = skipped_engine_result(scan, engine, {"clamav"})

        self.assertEqual(result.engine_name, "Microsoft Defender")
        self.assertEqual(result.status, "skipped")
        self.assertIn("expired", result.error_message or "")
        details = json.loads(result.details_json)
        self.assertEqual(details["orchestration"]["reason"], "worker_timeout")
        self.assertEqual(details["routing"]["reason_code"], "worker_timeout")
        self.assertEqual(details["routing"]["deferred_reason_code"], "unsupported_platform")


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


def make_scan(
    started_seconds_ago: int | None = None,
    created_seconds_ago: int = 50,
) -> ScanRecord:
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(seconds=created_seconds_ago)
    started_at = None
    if started_seconds_ago is not None:
        started_at = now - timedelta(seconds=started_seconds_ago)

    return ScanRecord(
        id=1,
        sample_id=1,
        case_name="Case",
        priority="Normal",
        note="",
        status="running",
        verdict="pending",
        risk_score=None,
        created_at=created_at.isoformat(sep=" "),
        started_at=started_at.isoformat(sep=" ") if started_at is not None else None,
        completed_at=None,
        failed_at=None,
        attempt_count=1,
        last_error=None,
        original_filename="sample.bin",
        stored_filename="sample.bin",
        storage_path="storage/samples/sample.bin",
        content_type="application/octet-stream",
        size_bytes=16,
        md5="md5",
        sha1="sha1",
        sha256="sha256",
    )


if __name__ == "__main__":
    unittest.main()
