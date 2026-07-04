import os
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

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


if __name__ == "__main__":
    unittest.main()
