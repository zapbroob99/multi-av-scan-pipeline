import asyncio
import json
import os
import unittest
from unittest.mock import patch

from app.engines.virustotal import HashEngineExecution
from app.main import app
from app.models import EngineInstanceRecord, EngineResultInput
from app.services import api_schemas
from app.services.virustotal import (
    VirusTotalNotConfiguredError,
    VirusTotalQuotaError,
    VirusTotalUnavailableError,
)


SHA256 = "a" * 64


def response_payload() -> dict[str, object]:
    return {
        "hash": SHA256,
        "algorithm": "sha256",
        "source": "virustotal",
        "found": True,
        "status": "malicious",
        "detail": "1 VirusTotal engine reported malicious.",
        "decision": {
            "action": "block",
            "reason": "1 VirusTotal engine reported malicious.",
        },
        "stats": {
            "malicious": 1,
            "suspicious": 0,
            "undetected": 59,
            "harmless": 0,
            "timeout": 0,
            "failure": 0,
            "type_unsupported": 0,
            "confirmed_timeout": 0,
            "total": 60,
        },
        "last_analysis_date": "2026-08-17T00:00:00+00:00",
        "permalink": f"https://www.virustotal.com/gui/file/{SHA256}",
        "cached": False,
        "policy": {
            "malicious_threshold": 1,
            "allow_undetected": False,
            "max_age_days": 30,
        },
    }


def virustotal_engine(*, enabled: bool = True) -> EngineInstanceRecord:
    return EngineInstanceRecord(
        id=10,
        adapter_key="virustotal",
        display_name="VirusTotal",
        enabled=enabled,
        config_json="{}",
        created_at="2026-08-17T00:00:00+00:00",
        updated_at="2026-08-17T00:00:00+00:00",
    )


def engine_execution(payload: dict[str, object]) -> HashEngineExecution:
    return HashEngineExecution(
        result=EngineResultInput(
            engine_name="VirusTotal",
            engine_version="api-v3",
            signature_version=None,
            status="completed",
            detected=True,
            signature="VirusTotal 1/60 malicious",
            severity="critical",
            confidence=95,
            raw_output=json.dumps(payload),
            duration_ms=1,
        ),
        payload=payload,
    )


def asgi_get(path: str, *, token: str | None = "shared-secret") -> tuple[int, dict[str, str], dict]:
    headers = [] if token is None else [(b"authorization", f"Bearer {token}".encode("ascii"))]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 51000),
        "server": ("localhost", 8000),
    }
    statuses: list[int] = []
    response_headers: list[list[tuple[bytes, bytes]]] = []
    body_parts: list[bytes] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            statuses.append(message["status"])
            response_headers.append(list(message.get("headers", [])))
        elif message["type"] == "http.response.body":
            body_parts.append(message.get("body", b""))

    asyncio.run(app(scope, receive, send))
    header_map = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in response_headers[0]
    }
    return statuses[0], header_map, json.loads(b"".join(body_parts) or b"{}")


class VirusTotalApiTests(unittest.TestCase):
    def configured_auth(self) -> tuple[patch, patch]:
        return (
            patch.dict(os.environ, {"MASP_API_TOKEN": "shared-secret"}, clear=False),
            patch("app.services.auth.get_setting", return_value=""),
        )

    def test_endpoint_requires_the_existing_bearer_authentication(self) -> None:
        env, setting = self.configured_auth()
        with env, setting:
            status, headers, payload = asgi_get(f"/api/v1/hashes/{SHA256}", token=None)

        self.assertEqual(status, 401)
        self.assertEqual(headers["www-authenticate"], "Bearer")
        self.assertEqual(payload["detail"], "Bearer token required.")

    def test_endpoint_returns_typed_reputation_without_file_upload(self) -> None:
        env, setting = self.configured_auth()
        payload = response_payload()
        with env, setting, patch(
            "app.main.enabled_hash_engines", return_value=[virustotal_engine()]
        ) as enabled_hash, patch(
            "app.main.run_hash_engine", return_value=engine_execution(payload)
        ) as run_hash:
            status, _, actual = asgi_get(f"/api/v1/hashes/{SHA256}")

        self.assertEqual(status, 200)
        self.assertEqual(actual["decision"]["action"], "block")
        self.assertEqual(actual["engines"], {"expected": 1, "completed": 1, "failed": 0})
        self.assertEqual(actual["results"][0]["engine"], {
            "key": "virustotal", "name": "VirusTotal", "support_state": "blocked"
        })
        self.assertEqual(actual["results"][0]["data"], payload)
        run_hash.assert_called_once_with(virustotal_engine(), SHA256)
        enabled_hash.assert_called_once_with(source="api")
        api_schemas.HashScanResponse.model_validate(actual)

    def test_invalid_hash_returns_400(self) -> None:
        env, setting = self.configured_auth()
        with env, setting:
            status, _, payload = asgi_get("/api/v1/hashes/not-a-sha256")

        self.assertEqual(status, 400)
        self.assertIn("SHA-256", payload["detail"])

    def test_engine_must_be_added_and_enabled(self) -> None:
        env, setting = self.configured_auth()
        with env, setting, patch("app.main.enabled_hash_engines", return_value=[]):
            status, _, payload = asgi_get(f"/api/v1/hashes/{SHA256}")

        self.assertEqual(status, 503)
        self.assertIn("non-metered", payload["detail"])

    def test_configured_virustotal_is_excluded_from_api_hash_automation(self) -> None:
        env, setting = self.configured_auth()
        with env, setting, patch(
            "app.services.engine_registry.configured_engines",
            return_value=[virustotal_engine()],
        ), patch("app.main.run_hash_engine") as run_hash:
            status, _, payload = asgi_get(f"/api/v1/hashes/{SHA256}")

        self.assertEqual(status, 503)
        self.assertIn("non-metered", payload["detail"])
        run_hash.assert_not_called()

    def test_missing_credentials_returns_503_after_engine_is_enabled(self) -> None:
        env, setting = self.configured_auth()
        with env, setting, patch(
            "app.main.enabled_hash_engines", return_value=[virustotal_engine()]
        ), patch(
            "app.main.run_hash_engine",
            side_effect=VirusTotalNotConfiguredError("VirusTotal credentials are missing."),
        ):
            status, _, payload = asgi_get(f"/api/v1/hashes/{SHA256}")

        self.assertEqual(status, 503)
        self.assertEqual(payload["detail"], "VirusTotal credentials are missing.")

    def test_quota_and_upstream_failures_are_fail_closed(self) -> None:
        env, setting = self.configured_auth()
        with env, setting, patch(
            "app.main.enabled_hash_engines", return_value=[virustotal_engine()]
        ), patch(
            "app.main.run_hash_engine", side_effect=VirusTotalQuotaError(30)
        ):
            status, headers, payload = asgi_get(f"/api/v1/hashes/{SHA256}")
        self.assertEqual(status, 503)
        self.assertEqual(headers["retry-after"], "30")
        self.assertIn("quota", payload["detail"])

        env, setting = self.configured_auth()
        with env, setting, patch(
            "app.main.enabled_hash_engines", return_value=[virustotal_engine()]
        ), patch(
            "app.main.run_hash_engine",
            side_effect=VirusTotalUnavailableError("VirusTotal could not be reached."),
        ):
            status, _, payload = asgi_get(f"/api/v1/hashes/{SHA256}")
        self.assertEqual(status, 502)
        self.assertEqual(payload["detail"], "VirusTotal could not be reached.")

    def test_openapi_documents_bearer_auth_and_response_model(self) -> None:
        operation = app.openapi()["paths"]["/api/v1/hashes/{sha256}"]["get"]

        self.assertEqual(operation["security"], [{"bearerAuth": []}])
        response_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(response_schema["$ref"], "#/components/schemas/HashScanResponse")


if __name__ == "__main__":
    unittest.main()
