import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.models import (
    EngineInstanceRecord,
    EngineResultInput,
    EngineResultRecord,
    ScanEngineJobRecord,
    ScanRecord,
)
from app.services.routing import EngineRouteDecision, ROUTE_ACTION_RUN
from app.workers.scan_worker import (
    finalize_scan_if_complete,
    process_next_scan_job,
    process_scan_engine_job,
)


class ScanEngineWorkerTests(unittest.TestCase):
    def test_process_scan_engine_job_runs_adapter_and_marks_terminal(self) -> None:
        scan = make_scan()
        engine = make_engine("static_metadata", "Static Metadata")
        job = make_job(scan.id, engine)
        result = EngineResultInput(
            engine_name=engine.display_name,
            status="completed",
            detected=False,
            severity="info",
            confidence=100,
            signature=None,
            raw_output="ok",
            duration_ms=12,
        )

        with patch("app.workers.scan_worker.record_worker_heartbeat"), patch(
            "app.workers.scan_worker.get_scan",
            return_value=scan,
        ), patch(
            "app.workers.scan_worker.enabled_engines",
            return_value=[engine],
        ), patch(
            "app.workers.scan_worker.route_engine_for_worker",
            return_value=EngineRouteDecision(
                engine=engine,
                action=ROUTE_ACTION_RUN,
                reason_code="eligible",
                reason="ok",
                details={},
            ),
        ), patch(
            "app.workers.scan_worker.mark_scan_running",
        ), patch(
            "app.workers.scan_worker.mark_scan_engine_job_running",
            return_value=True,
        ) as mark_running, patch(
            "app.workers.scan_worker.run_engine",
            return_value=result,
        ) as run_engine, patch(
            "app.workers.scan_worker.create_engine_result_if_missing",
            return_value=123,
        ) as create_result, patch(
            "app.workers.scan_worker.mark_scan_engine_job_terminal",
            return_value=True,
        ) as mark_terminal, patch(
            "app.workers.scan_worker.finalize_scan_if_complete",
            return_value=True,
        ) as finalize, patch(
            "app.workers.scan_worker.record_worker_timing_event",
        ):
            processed = process_scan_engine_job(job, {"static_metadata"})

        self.assertTrue(processed)
        mark_running.assert_called_once()
        run_engine.assert_called_once_with(engine, scan)
        create_result.assert_called_once_with(scan.id, result)
        mark_terminal.assert_called_once_with(job.id, "completed", last_error=None)
        finalize.assert_called_once()

    def test_process_next_scan_job_does_not_use_legacy_fallback_by_default(self) -> None:
        with patch("app.workers.scan_worker.ENGINE_JOB_QUEUE_ENABLED", True), patch(
            "app.workers.scan_worker.LEGACY_SCAN_WORKER_FALLBACK_ENABLED",
            False,
        ), patch(
            "app.workers.scan_worker.process_next_scan_engine_job",
            return_value=False,
        ), patch(
            "app.workers.scan_worker.list_active_scans",
        ) as list_active:
            processed = process_next_scan_job()

        self.assertFalse(processed)
        list_active.assert_not_called()

    def test_finalize_scan_waits_for_terminal_engine_jobs(self) -> None:
        scan = make_scan()
        engine = make_engine("static_metadata", "Static Metadata")
        job = replace(make_job(scan.id, engine), status="running")
        result = make_engine_result(scan.id, engine.display_name)

        with patch("app.workers.scan_worker.ENGINE_JOB_QUEUE_ENABLED", True), patch(
            "app.workers.scan_worker.list_scan_engine_jobs",
            return_value=[job],
        ), patch(
            "app.workers.scan_worker.list_engine_results",
            return_value=[result],
        ), patch(
            "app.workers.scan_worker.update_scan_assessment",
        ) as update_assessment, patch(
            "app.workers.scan_worker.update_scan_status",
        ) as update_status:
            finalized = finalize_scan_if_complete(scan, [engine])

        self.assertFalse(finalized)
        update_assessment.assert_not_called()
        update_status.assert_not_called()

    def test_finalize_scan_uses_terminal_engine_jobs_and_results(self) -> None:
        scan = make_scan()
        engine = make_engine("static_metadata", "Static Metadata")
        job = replace(make_job(scan.id, engine), status="completed")
        result = make_engine_result(scan.id, engine.display_name)

        with patch("app.workers.scan_worker.ENGINE_JOB_QUEUE_ENABLED", True), patch(
            "app.workers.scan_worker.list_scan_engine_jobs",
            return_value=[job],
        ), patch(
            "app.workers.scan_worker.list_engine_results",
            return_value=[result],
        ), patch(
            "app.workers.scan_worker.update_scan_assessment",
        ) as update_assessment, patch(
            "app.workers.scan_worker.update_scan_status",
        ) as update_status:
            finalized = finalize_scan_if_complete(scan, [engine])

        self.assertTrue(finalized)
        update_assessment.assert_called_once_with(scan.id, "low", 10)
        update_status.assert_called_once_with(scan.id, "completed")


def make_engine(adapter_key: str, display_name: str) -> EngineInstanceRecord:
    return EngineInstanceRecord(
        id=10,
        adapter_key=adapter_key,
        display_name=display_name,
        enabled=True,
        config_json="{}",
        created_at="",
        updated_at="",
    )


def make_job(scan_id: int, engine: EngineInstanceRecord) -> ScanEngineJobRecord:
    return ScanEngineJobRecord(
        id=20,
        scan_job_id=scan_id,
        engine_instance_id=engine.id,
        engine_key=engine.adapter_key,
        engine_name=engine.display_name,
        status="claimed",
        worker_id="worker-1",
        claimed_at="2026-07-06 00:00:00+00:00",
        started_at=None,
        finished_at=None,
        lease_expires_at=120,
        attempt_count=1,
        last_error=None,
        created_at="2026-07-06 00:00:00+00:00",
        updated_at="2026-07-06 00:00:00+00:00",
    )


def make_engine_result(scan_id: int, engine_name: str) -> EngineResultRecord:
    return EngineResultRecord(
        id=30,
        scan_job_id=scan_id,
        engine_name=engine_name,
        engine_version=None,
        signature_version=None,
        status="completed",
        detected=False,
        signature=None,
        severity="info",
        confidence=100,
        raw_output="ok",
        error_message=None,
        duration_ms=12,
        created_at="2026-07-06 00:00:00+00:00",
        details_json="{}",
        findings_json="[]",
    )


def make_scan() -> ScanRecord:
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(seconds=1)
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
        created_at=created_at.isoformat(sep=" "),
        started_at=None,
        completed_at=None,
        failed_at=None,
        attempt_count=0,
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
