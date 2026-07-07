import unittest
from unittest.mock import patch

from starlette.datastructures import URLPath
from starlette.requests import Request

from app.main import (
    build_scan_batch_result_payload,
    build_scan_batch_status_payload,
    build_api_scan_result_payload,
    build_api_scan_status_payload,
    configured_api_retry_after_seconds,
)
from app.models import EngineResultRecord, ScanBatchRecord, ScanRecord, ScanWorkerEventRecord


def make_request() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("localhost", 8000),
        "path": "/api/v1/scans/29",
        "headers": [],
        "router": None,
    }
    request = Request(scope)
    request.scope["router"] = FakeRouter()
    return request


class ApiContractTests(unittest.TestCase):
    def test_status_payload_marks_running_scans_as_not_ready(self) -> None:
        with patch("app.main.get_queue_metrics", return_value={"queued": 1, "running": 1, "active": 2, "completed": 3, "failed": 0, "total": 5}), patch(
            "app.main.get_scan_queue_position",
            return_value=0,
        ), patch("app.main.enabled_engines", return_value=[object(), object(), object()]):
            payload = build_api_scan_status_payload(
                make_request(),
                make_scan("running"),
                engine_results=[make_result("ClamAV", detected=False)],
                worker_events=[make_worker_event("engine_run", "ClamAV", 22)],
            )

        self.assertFalse(payload["completed"])
        self.assertFalse(payload["result_ready"])
        self.assertEqual(payload["decision"]["action"], "wait")
        self.assertEqual(
            payload["recommended_poll_seconds"],
            configured_api_retry_after_seconds(),
        )
        self.assertEqual(payload["scan"]["timing"]["queue_wait_ms"], 1000)
        self.assertEqual(payload["scan"]["batch"]["role"], "standalone")
        self.assertIsNone(payload["scan"]["batch"]["id"])
        self.assertIsNone(payload["scan"]["timing"]["processing_duration_ms"])
        self.assertEqual(payload["engine_results"][0]["engine_name"], "ClamAV")
        self.assertEqual(payload["engine_results"][0]["duration_ms"], 15)
        self.assertEqual(payload["worker_events"][0]["event_name"], "engine_run")
        self.assertEqual(payload["worker_events"][0]["duration_ms"], 22)

    def test_result_payload_marks_completed_scans_as_ready(self) -> None:
        with patch("app.main.enabled_engines", return_value=[object()]):
            payload = build_api_scan_result_payload(
                make_request(),
                make_scan("completed"),
                engine_results=[make_result("ClamAV", detected=True)],
            )

        self.assertTrue(payload["completed"])
        self.assertTrue(payload["result_ready"])
        self.assertEqual(payload["decision"]["action"], "block")
        self.assertIn("links", payload)
        self.assertEqual(payload["scan"]["batch"]["role"], "standalone")
        self.assertEqual(payload["scan"]["timing"]["queue_wait_ms"], 1000)
        self.assertEqual(payload["scan"]["timing"]["processing_duration_ms"], 1000)

    def test_scan_payload_exposes_batch_links_for_archive_scans(self) -> None:
        archive_scan = make_scan("completed", batch_id=44, scan_role="container", relative_path="bundle.zip")
        with patch("app.main.enabled_engines", return_value=[object()]):
            status_payload = build_api_scan_status_payload(
                make_request(),
                archive_scan,
                engine_results=[make_result("ClamAV", detected=True)],
            )
            result_payload = build_api_scan_result_payload(
                make_request(),
                archive_scan,
                engine_results=[make_result("ClamAV", detected=True)],
            )

        self.assertEqual(status_payload["batch_links"]["status"], "http://localhost:8000/api/v1/batches/44")
        self.assertEqual(result_payload["batch_links"]["ui"], "http://localhost:8000/api-ledger/batches/44")

    def test_batch_status_payload_includes_scan_links(self) -> None:
        payload = build_scan_batch_status_payload(
            make_request(),
            make_batch(44),
            [make_scan("completed", batch_id=44, scan_role="container", relative_path="bundle.zip")],
        )

        self.assertTrue(payload["completed"])
        self.assertEqual(payload["batch"]["id"], 44)
        self.assertEqual(payload["batch"]["links"]["result"], "http://localhost:8000/api/v1/batches/44/result")
        self.assertEqual(payload["scans"][0]["links"]["status"], "http://localhost:8000/api/v1/scans/29")

    def test_batch_result_payload_includes_child_scan_result(self) -> None:
        batch = make_batch(44)
        scan = make_scan("completed", batch_id=44, scan_role="child", relative_path="bin/tool.exe")
        with patch("app.main.list_engine_results", return_value=[make_result("ClamAV", detected=True)]):
            payload = build_scan_batch_result_payload(make_request(), batch, [scan])

        self.assertTrue(payload["completed"])
        self.assertEqual(payload["scans"][0]["role"], "child")
        self.assertEqual(payload["scans"][0]["result"]["scan"]["batch"]["id"], 44)


class FakeRouter:
    def url_path_for(self, name: str, **path_params: object) -> URLPath:
        if name == "api_scan_status":
            return URLPath(f"/api/v1/scans/{path_params['scan_id']}")
        if name == "api_scan_result":
            return URLPath(f"/api/v1/scans/{path_params['scan_id']}/result")
        if name == "api_batch_status":
            return URLPath(f"/api/v1/batches/{path_params['batch_id']}")
        if name == "api_batch_result":
            return URLPath(f"/api/v1/batches/{path_params['batch_id']}/result")
        raise KeyError(name)


def make_scan(
    status: str,
    *,
    batch_id: int | None = None,
    scan_role: str = "standalone",
    relative_path: str | None = None,
) -> ScanRecord:
    completed_at = "2026-07-04 00:00:02+00:00" if status == "completed" else None
    started_at = "2026-07-04 00:00:01+00:00" if status in {"running", "completed"} else None
    return ScanRecord(
        id=29,
        sample_id=29,
        case_name="IR-2026-001",
        priority="Normal",
        note="manual api test",
        source="api",
        status=status,
        verdict="pending" if status != "completed" else "critical",
        risk_score=None if status != "completed" else 90,
        created_at="2026-07-04 00:00:00+00:00",
        started_at=started_at,
        completed_at=completed_at,
        failed_at=None,
        attempt_count=1,
        last_error=None,
        original_filename="eicar.com",
        stored_filename="eicar.com",
        storage_path="/app/storage/samples/eicar.com",
        content_type="application/octet-stream",
        size_bytes=68,
        md5="44d88612fea8a8f36de82e1278abb02f",
        sha1="3395856ce81f2b7382dee72602f798b642f14140",
        sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        batch_id=batch_id,
        relative_path=relative_path,
        scan_role=scan_role,
    )


def make_result(engine_name: str, detected: bool) -> EngineResultRecord:
    return EngineResultRecord(
        id=1,
        scan_job_id=29,
        engine_name=engine_name,
        engine_version="test",
        signature_version=None,
        status="completed",
        detected=detected,
        signature="EICAR-Test-File" if detected else None,
        severity="high" if detected else "info",
        confidence=90 if detected else 100,
        raw_output="ok",
        error_message=None,
        duration_ms=15,
        created_at="2026-07-04 00:00:02+00:00",
        details_json="{}",
        findings_json="[]",
    )


def make_worker_event(
    event_name: str,
    engine_name: str | None,
    duration_ms: int | None,
) -> ScanWorkerEventRecord:
    return ScanWorkerEventRecord(
        id=1,
        scan_job_id=29,
        event_name=event_name,
        worker_id="test-worker",
        worker_engine_keys="clamav,yara",
        engine_name=engine_name,
        duration_ms=duration_ms,
        details_json="{}",
        created_at="2026-07-04 00:00:02+00:00",
    )


def make_batch(batch_id: int) -> ScanBatchRecord:
    return ScanBatchRecord(
        id=batch_id,
        source="api",
        original_filename="bundle.zip",
        archive_mode="lazy_extract_on_detection",
        status="completed",
        total_items=2,
        queued_items=0,
        running_items=0,
        completed_items=2,
        failed_items=0,
        malicious_items=1,
        skipped_items=0,
        metadata_json="{}",
        created_at="2026-07-04 00:00:00+00:00",
        updated_at="2026-07-04 00:00:02+00:00",
        completed_at="2026-07-04 00:00:02+00:00",
        last_error=None,
    )


if __name__ == "__main__":
    unittest.main()
