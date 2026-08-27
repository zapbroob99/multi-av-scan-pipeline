import asyncio
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app.main import app
from app.services.auth import (
    bearer_token_from_request,
    configured_api_tokens,
    require_api_token,
)


def make_request(headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/scans",
        "headers": headers or [],
    }
    return Request(scope)


class ApiAuthTests(unittest.TestCase):
    def test_configured_api_tokens_combines_all_sources_without_duplicates(self) -> None:
        with patch.dict(
            os.environ,
            {
                "MASP_API_TOKENS": "alpha,beta",
                "MASP_API_TOKEN": "beta,gamma",
            },
            clear=False,
        ), patch("app.services.auth.get_setting", return_value="gamma\ndelta"):
            self.assertEqual(
                configured_api_tokens(),
                ["alpha", "beta", "gamma", "delta"],
            )

    def test_bearer_token_is_extracted_from_request(self) -> None:
        request = make_request(headers=[(b"authorization", b"Bearer secret-token")])

        self.assertEqual(bearer_token_from_request(request), "secret-token")

    def test_require_api_token_rejects_missing_configuration(self) -> None:
        with patch.dict(os.environ, {}, clear=False), patch(
            "app.services.auth.get_setting",
            return_value="",
        ):
            with self.assertRaises(HTTPException) as context:
                require_api_token(make_request())

        self.assertEqual(context.exception.status_code, 503)

    def test_require_api_token_accepts_matching_bearer_token(self) -> None:
        request = make_request(headers=[(b"authorization", b"Bearer shared-secret")])
        with patch.dict(os.environ, {"MASP_API_TOKEN": "shared-secret"}, clear=False), patch(
            "app.services.auth.get_setting",
            return_value="",
        ):
            self.assertEqual(require_api_token(request), "shared-secret")

    def test_require_api_token_rejects_invalid_bearer_token(self) -> None:
        request = make_request(headers=[(b"authorization", b"Bearer wrong-secret")])
        with patch.dict(os.environ, {"MASP_API_TOKEN": "shared-secret"}, clear=False), patch(
            "app.services.auth.get_setting",
            return_value="",
        ):
            with self.assertRaises(HTTPException) as context:
                require_api_token(request)

        self.assertEqual(context.exception.status_code, 401)


def asgi_get(path: str, headers: list[tuple[bytes, bytes]] | None = None) -> tuple[int, dict[str, str], dict]:
    """Drive the FastAPI app through its ASGI interface (stdlib only).

    Lets the auth regression tests exercise the full HTTP path — including
    the OpenAPI-only HTTPBearer dependency added for documentation — without
    a test-client dependency.
    """

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
        "headers": headers or [],
        "client": ("127.0.0.1", 51000),
        "server": ("localhost", 8000),
    }
    received_status: list[int] = []
    received_headers: list[list[tuple[bytes, bytes]]] = []
    body_parts: list[bytes] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            received_status.append(message["status"])
            received_headers.append(list(message.get("headers", [])))
        elif message["type"] == "http.response.body":
            body_parts.append(message.get("body", b""))

    asyncio.run(app(scope, receive, send))
    header_map = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in received_headers[0]
    }
    payload = json.loads(b"".join(body_parts) or b"{}")
    return received_status[0], header_map, payload


class HttpAuthRegressionTests(unittest.TestCase):
    """HTTP-level regressions for the documentation-only HTTPBearer scheme.

    The bearer scheme on the API routes exists purely so OpenAPI carries the
    security requirement; enforcement must remain in require_api_token with
    identical status codes and headers. auto_error=False means HTTPBearer
    itself must never produce a 403 for missing or malformed credentials.
    """

    def configured(self) -> tuple[patch, patch]:
        return (
            patch.dict(os.environ, {"MASP_API_TOKEN": "shared-secret"}, clear=False),
            patch("app.services.auth.get_setting", return_value=""),
        )

    def test_missing_token_yields_401_with_www_authenticate(self) -> None:
        env, setting = self.configured()
        with env, setting:
            status, headers, payload = asgi_get("/api/v1/scans/1")

        self.assertEqual(status, 401)
        self.assertEqual(headers.get("www-authenticate"), "Bearer")
        self.assertEqual(payload["detail"], "Bearer token required.")

    def test_malformed_authorization_scheme_yields_401(self) -> None:
        env, setting = self.configured()
        with env, setting:
            status, headers, _ = asgi_get(
                "/api/v1/scans/1",
                headers=[(b"authorization", b"Basic shared-secret")],
            )

        self.assertEqual(status, 401)
        self.assertEqual(headers.get("www-authenticate"), "Bearer")

    def test_empty_bearer_credentials_yield_401(self) -> None:
        env, setting = self.configured()
        with env, setting:
            status, headers, _ = asgi_get(
                "/api/v1/scans/1",
                headers=[(b"authorization", b"Bearer ")],
            )

        self.assertEqual(status, 401)
        self.assertEqual(headers.get("www-authenticate"), "Bearer")

    def test_unconfigured_token_yields_503(self) -> None:
        cleaned_env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"MASP_API_TOKEN", "MASP_API_TOKENS"}
        }
        with patch.dict(os.environ, cleaned_env, clear=True), patch(
            "app.services.auth.get_setting",
            return_value="",
        ):
            status, _, payload = asgi_get("/api/v1/scans/1")

        self.assertEqual(status, 503)
        self.assertEqual(payload["detail"], "API token authentication is not configured.")

    def test_valid_token_passes_auth_and_reaches_the_handler(self) -> None:
        env, setting = self.configured()
        with env, setting, patch("app.main.get_scan", return_value=None):
            status, _, payload = asgi_get(
                "/api/v1/scans/1",
                headers=[(b"authorization", b"Bearer shared-secret")],
            )

        # 404 (not 401/403) proves auth passed and the handler executed.
        self.assertEqual(status, 404)
        self.assertEqual(payload["detail"], "Scan not found.")


class ApiScanSourceIsolationTests(unittest.TestCase):
    """The public scan API must expose API-sourced scans only.

    An API/vendor token must not be able to enumerate or read ICAP or
    manual/UI scans by guessing scan ids. Non-API scans return 404, matching the
    source guard already present on the batch endpoints.
    """

    def configured(self) -> tuple[patch, patch]:
        return (
            patch.dict(os.environ, {"MASP_API_TOKEN": "shared-secret"}, clear=False),
            patch("app.services.auth.get_setting", return_value=""),
        )

    def _scan(self, source: str, status: str = "completed"):
        return SimpleNamespace(id=1, source=source, status=status)

    def _auth_header(self) -> list[tuple[bytes, bytes]]:
        return [(b"authorization", b"Bearer shared-secret")]

    def test_status_hides_non_api_scans(self) -> None:
        for source in ("icap", "manual"):
            env, setting = self.configured()
            with env, setting, patch("app.main.get_scan", return_value=self._scan(source)):
                status, _, payload = asgi_get("/api/v1/scans/1", headers=self._auth_header())
            self.assertEqual(status, 404, source)
            self.assertEqual(payload["detail"], "Scan not found.")

    def test_status_allows_api_scan(self) -> None:
        env, setting = self.configured()
        with env, setting, patch(
            "app.main.get_scan", return_value=self._scan("api")
        ), patch("app.main.build_api_scan_status_payload", return_value={"ok": True}):
            status, _, payload = asgi_get("/api/v1/scans/1", headers=self._auth_header())
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

    def test_result_hides_non_api_scans(self) -> None:
        for source in ("icap", "manual"):
            env, setting = self.configured()
            with env, setting, patch("app.main.get_scan", return_value=self._scan(source)):
                status, _, payload = asgi_get(
                    "/api/v1/scans/1/result", headers=self._auth_header()
                )
            self.assertEqual(status, 404, source)
            self.assertEqual(payload["detail"], "Scan not found.")

    def test_result_allows_api_scan(self) -> None:
        env, setting = self.configured()
        with env, setting, patch(
            "app.main.get_scan", return_value=self._scan("api", status="completed")
        ), patch("app.main.build_api_scan_result_payload", return_value={"ok": True}):
            status, _, payload = asgi_get(
                "/api/v1/scans/1/result", headers=self._auth_header()
            )
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

    def test_status_hides_another_service_clients_api_scan(self) -> None:
        env, setting = self.configured()
        identity = SimpleNamespace(client=SimpleNamespace(id=10, client_key="client-a"))
        other_scan = SimpleNamespace(
            id=1, source="api", status="completed", service_client_id=20
        )
        with env, setting, patch(
            "app.main.api_client_identity", return_value=identity
        ), patch("app.main.get_scan", return_value=other_scan):
            status, _, payload = asgi_get(
                "/api/v1/scans/1", headers=self._auth_header()
            )

        self.assertEqual(status, 404)
        self.assertEqual(payload["detail"], "Scan not found.")


if __name__ == "__main__":
    unittest.main()
