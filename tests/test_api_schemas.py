"""Contract drift guard for the public REST API.

Validates the payloads produced by the real payload builders in ``app.main``
against the Pydantic contract models in ``app.services.api_schemas``. The
models use ``extra="forbid"``, so adding, renaming, or removing a payload
field without updating the published contract breaks these tests instead of
silently diverging from the vendor documentation.

Also asserts the OpenAPI schema carries the bearer security requirement and
the typed response models the vendor package is generated from.
"""

import json
import unittest
from unittest.mock import patch

from pydantic import ValidationError
from starlette.datastructures import URLPath
from starlette.requests import Request

from app.main import (
    app,
    build_api_scan_result_payload,
    build_api_scan_status_payload,
    build_scan_batch_result_payload,
    build_scan_batch_status_payload,
)
from app.models import EngineResultRecord, ScanBatchRecord, ScanRecord
from app.services import api_schemas


QUEUE_METRICS = {"queued": 1, "running": 1, "active": 2, "completed": 3, "failed": 0, "total": 5}

EICAR_FINDING = {
    "source": "YARA",
    "title": "EICAR_Test_File",
    "type": "yara_rule",
    "severity": "high",
    "confidence": 90,
    "action": "detected",
}


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


def make_request() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("localhost", 8000),
        "path": "/api/v1/scans/29",
        "headers": [],
        "router": FakeRouter(),
    }
    return Request(scope)


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
        note="contract drift fixture",
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
        original_filename="sample.bin",
        stored_filename="sample.bin",
        storage_path="/app/storage/samples/sample.bin",
        content_type="application/octet-stream",
        size_bytes=68,
        md5="44d88612fea8a8f36de82e1278abb02f",
        sha1="3395856ce81f2b7382dee72602f798b642f14140",
        sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        batch_id=batch_id,
        relative_path=relative_path,
        scan_role=scan_role,
    )


def make_result(engine_name: str, detected: bool, findings: list[dict] | None = None) -> EngineResultRecord:
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
        findings_json=json.dumps(findings or []),
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


def build_status_payload(scan: ScanRecord, results: list[EngineResultRecord]) -> dict:
    with patch("app.main.get_queue_metrics", return_value=dict(QUEUE_METRICS)), patch(
        "app.main.get_scan_queue_position",
        return_value=0,
    ), patch("app.main.enabled_engines", return_value=[object(), object(), object()]):
        return build_api_scan_status_payload(
            make_request(),
            scan,
            engine_results=results,
        )


def build_result_payload(scan: ScanRecord, results: list[EngineResultRecord]) -> dict:
    with patch("app.main.enabled_engines", return_value=[object(), object(), object()]):
        return build_api_scan_result_payload(make_request(), scan, engine_results=results)


class ContractDriftTests(unittest.TestCase):
    def test_status_payload_matches_contract_for_running_scan(self) -> None:
        payload = build_status_payload(make_scan("running"), [make_result("ClamAV", detected=False)])

        model = api_schemas.ScanStatusResponse.model_validate(payload)

        self.assertEqual(model.decision.action, "wait")
        self.assertIsNone(model.batch_links)

    def test_status_payload_matches_contract_for_archive_member(self) -> None:
        scan = make_scan("completed", batch_id=44, scan_role="container", relative_path="bundle.zip")
        payload = build_status_payload(scan, [make_result("ClamAV", detected=True)])

        model = api_schemas.ScanStatusResponse.model_validate(payload)

        self.assertIsNotNone(model.batch_links)
        self.assertEqual(model.decision.action, "block")

    def test_result_payload_matches_contract_including_findings(self) -> None:
        payload = build_result_payload(
            make_scan("completed"),
            [
                make_result("YARA", detected=True, findings=[EICAR_FINDING]),
                make_result("ClamAV", detected=True),
                make_result("Static Metadata", detected=False),
            ],
        )

        model = api_schemas.ScanResultResponse.model_validate(payload)

        self.assertEqual(model.decision.action, "block")
        self.assertGreaterEqual(len(model.findings), 1)
        self.assertEqual(len(model.engine_results), 3)

    def test_submit_completed_body_matches_contract(self) -> None:
        scan = make_scan("completed")
        results = [make_result("ClamAV", detected=False)]
        payload = build_status_payload(scan, results)
        # Mirror the additions api_create_scan makes for the 200 body.
        payload["accepted"] = True
        payload["wait_seconds_applied"] = 15
        payload["detail"] = "Scan completed within the requested wait window."
        payload["result"] = build_result_payload(scan, results)

        api_schemas.ScanSubmitCompletedResponse.model_validate(payload)

    def test_submit_accepted_body_matches_contract(self) -> None:
        payload = build_status_payload(make_scan("running"), [])
        # Mirror the additions api_create_scan makes for the 202 body.
        payload["accepted"] = True
        payload["wait_seconds_applied"] = 0
        payload["detail"] = "Scan accepted and still processing."

        api_schemas.ScanSubmitAcceptedResponse.model_validate(payload)

    def test_result_not_ready_body_matches_contract(self) -> None:
        payload = build_status_payload(make_scan("running"), [])
        # Mirror the addition api_scan_result makes for the 409 body.
        payload["detail"] = "Scan result is not ready yet."

        api_schemas.ScanResultNotReadyResponse.model_validate(payload)

    def test_batch_status_payload_matches_contract(self) -> None:
        scan = make_scan("completed", batch_id=44, scan_role="container", relative_path="bundle.zip")
        payload = build_scan_batch_status_payload(make_request(), make_batch(44), [scan])

        model = api_schemas.BatchStatusResponse.model_validate(payload)

        self.assertEqual(model.batch.id, 44)
        self.assertTrue(model.scans[0].result_ready)

    def test_batch_result_payload_matches_contract(self) -> None:
        scan = make_scan("completed", batch_id=44, scan_role="child", relative_path="bin/tool.exe")
        with patch(
            "app.main.list_engine_results",
            return_value=[make_result("ClamAV", detected=True)],
        ):
            payload = build_scan_batch_result_payload(make_request(), make_batch(44), [scan])

        model = api_schemas.BatchResultResponse.model_validate(payload)

        self.assertEqual(model.scans[0].role, "child")
        self.assertEqual(model.scans[0].result.scan.batch.id, 44)

    def test_unknown_field_breaks_the_contract(self) -> None:
        payload = build_status_payload(make_scan("running"), [])
        payload["surprise_field"] = 1

        with self.assertRaises(ValidationError):
            api_schemas.ScanStatusResponse.model_validate(payload)

    def test_missing_required_field_breaks_the_contract(self) -> None:
        payload = build_status_payload(make_scan("running"), [])
        del payload["decision"]

        with self.assertRaises(ValidationError):
            api_schemas.ScanStatusResponse.model_validate(payload)


class OpenApiContractTests(unittest.TestCase):
    API_OPERATIONS = (
        ("/api/v1/scans", "post"),
        ("/api/v1/scans/{scan_id}", "get"),
        ("/api/v1/scans/{scan_id}/result", "get"),
        ("/api/v1/batches/{batch_id}", "get"),
        ("/api/v1/batches/{batch_id}/result", "get"),
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = app.openapi()

    def test_bearer_security_scheme_is_declared(self) -> None:
        scheme = self.spec["components"]["securitySchemes"]["bearerAuth"]
        self.assertEqual(scheme["type"], "http")
        self.assertEqual(scheme["scheme"], "bearer")

    def test_api_operations_require_bearer_token(self) -> None:
        for path, method in self.API_OPERATIONS:
            with self.subTest(path=path):
                operation = self.spec["paths"][path][method]
                self.assertEqual(operation.get("security"), [{"bearerAuth": []}])

    def test_health_endpoint_is_public(self) -> None:
        operation = self.spec["paths"]["/health"]["get"]
        self.assertIsNone(operation.get("security"))

    def test_response_bodies_reference_contract_models(self) -> None:
        def schema_ref(path: str, method: str, status: str) -> str:
            response = self.spec["paths"][path][method]["responses"][status]
            return response["content"]["application/json"]["schema"]["$ref"]

        self.assertEqual(
            schema_ref("/api/v1/scans", "post", "200"),
            "#/components/schemas/ScanSubmitCompletedResponse",
        )
        self.assertEqual(
            schema_ref("/api/v1/scans", "post", "202"),
            "#/components/schemas/ScanSubmitAcceptedResponse",
        )
        self.assertEqual(
            schema_ref("/api/v1/scans", "post", "400"),
            "#/components/schemas/ApiErrorResponse",
        )
        self.assertEqual(
            schema_ref("/api/v1/scans", "post", "413"),
            "#/components/schemas/ApiErrorResponse",
        )
        self.assertEqual(
            schema_ref("/api/v1/scans/{scan_id}/result", "get", "409"),
            "#/components/schemas/ScanResultNotReadyResponse",
        )
        self.assertEqual(
            schema_ref("/api/v1/batches/{batch_id}/result", "get", "409"),
            "#/components/schemas/BatchResultNotReadyResponse",
        )


if __name__ == "__main__":
    unittest.main()
