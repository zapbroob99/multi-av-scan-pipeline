import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.models import EngineInstanceRecord, EngineResultInput, EngineResultRecord, ScanRecord
from app.services.routing import EngineRouteDecision, ROUTE_ACTION_RUN, ROUTE_ACTION_WAIT
from app.workers.scan_worker import (
    partial_results_wait_seconds,
    process_scan,
    scan_elapsed_seconds,
    should_attempt_passive_finalize,
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

    def test_passive_finalize_waits_until_timeout_window(self) -> None:
        engine = make_engine(
            "microsoft_defender",
            "Microsoft Defender",
            '{"timeout_seconds":"30"}',
        )
        scan = make_scan(started_seconds_ago=5)
        self.assertFalse(should_attempt_passive_finalize(scan, [engine]))

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
        self.assertEqual(result.duration_ms, 1)
        self.assertIn("expired", result.error_message or "")
        details = json.loads(result.details_json)
        self.assertEqual(details["orchestration"]["reason"], "worker_timeout")
        self.assertGreaterEqual(details["orchestration"]["elapsed_seconds"], 40)
        self.assertEqual(details["routing"]["reason_code"], "worker_timeout")
        self.assertEqual(details["routing"]["deferred_reason_code"], "unsupported_platform")

    def test_process_scan_refreshes_started_at_before_timeout_skip(self) -> None:
        static_engine = make_engine(
            "static_metadata",
            "Static Metadata",
            '{"timeout_seconds":"1"}',
        )
        defender_engine = make_engine(
            "microsoft_defender",
            "Microsoft Defender",
            '{"timeout_seconds":"30"}',
        )
        stale_scan = make_scan(started_seconds_ago=None, created_seconds_ago=40)
        refreshed_scan = make_scan(started_seconds_ago=0, created_seconds_ago=40)
        route_decisions = [
            EngineRouteDecision(
                engine=static_engine,
                action=ROUTE_ACTION_RUN,
                reason_code="eligible",
                reason="ok",
                details={},
            ),
            EngineRouteDecision(
                engine=defender_engine,
                action=ROUTE_ACTION_WAIT,
                reason_code="worker_not_assigned",
                reason="wait",
                details={},
            ),
        ]
        created_results: list[EngineResultInput] = []

        def fake_create(_scan_job_id: int, result: EngineResultInput) -> int:
            created_results.append(result)
            return len(created_results)

        def fake_list(_scan_job_id: int) -> list[EngineResultRecord]:
            return [
                engine_result_record(index + 1, stale_scan.id, result)
                for index, result in enumerate(created_results)
            ]

        with patch("app.workers.scan_worker.record_worker_heartbeat"), patch(
            "app.workers.scan_worker.enabled_engines",
            return_value=[static_engine, defender_engine],
        ), patch(
            "app.workers.scan_worker.route_missing_engines",
            return_value=route_decisions,
        ), patch(
            "app.workers.scan_worker.mark_scan_running",
        ), patch(
            "app.workers.scan_worker.get_scan",
            return_value=refreshed_scan,
        ), patch(
            "app.workers.scan_worker.list_engine_results",
            side_effect=fake_list,
        ), patch(
            "app.workers.scan_worker.run_engine",
            return_value=EngineResultInput(
                engine_name="Static Metadata",
                status="completed",
                detected=False,
                severity="info",
                confidence=100,
                signature=None,
                raw_output="ok",
                duration_ms=1,
            ),
        ), patch(
            "app.workers.scan_worker.create_engine_result_if_missing",
            side_effect=fake_create,
        ), patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ), patch(
            "app.workers.scan_worker.worker_is_running_scan_engine",
            return_value=False,
        ):
            processed = process_scan(stale_scan, {"static_metadata"})

        self.assertTrue(processed)
        self.assertEqual([result.engine_name for result in created_results], ["Static Metadata"])

    def test_process_scan_skips_passive_finalize_before_timeout(self) -> None:
        defender_engine = make_engine(
            "microsoft_defender",
            "Microsoft Defender",
            '{"timeout_seconds":"30"}',
        )
        scan = make_scan(started_seconds_ago=5, created_seconds_ago=40)
        route_decisions = [
            EngineRouteDecision(
                engine=defender_engine,
                action=ROUTE_ACTION_WAIT,
                reason_code="worker_not_assigned",
                reason="wait",
                details={},
            ),
        ]

        with patch("app.workers.scan_worker.record_worker_heartbeat"), patch(
            "app.workers.scan_worker.enabled_engines",
            return_value=[defender_engine],
        ), patch(
            "app.workers.scan_worker.list_engine_results",
            return_value=[],
        ), patch(
            "app.workers.scan_worker.route_missing_engines",
            return_value=route_decisions,
        ), patch(
            "app.workers.scan_worker.finalize_scan_if_complete_or_timeout",
        ) as finalize_mock, patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ):
            processed = process_scan(scan, {"clamav"})

        self.assertFalse(processed)
        finalize_mock.assert_not_called()


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


def engine_result_record(
    result_id: int,
    scan_job_id: int,
    result: EngineResultInput,
) -> EngineResultRecord:
    return EngineResultRecord(
        id=result_id,
        scan_job_id=scan_job_id,
        engine_name=result.engine_name,
        engine_version=result.engine_version,
        signature_version=result.signature_version,
        status=result.status,
        detected=result.detected,
        signature=result.signature,
        severity=result.severity,
        confidence=result.confidence,
        raw_output=result.raw_output,
        error_message=result.error_message,
        duration_ms=result.duration_ms,
        created_at="2026-07-06 00:00:00+00:00",
        details_json=result.details_json,
        findings_json=result.findings_json,
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
        source="manual",
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
