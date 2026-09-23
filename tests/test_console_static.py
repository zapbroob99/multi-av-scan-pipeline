import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

from fastapi import FastAPI

from app.services import console_static


class AsgiClient:
    """Minimal GET client over raw ASGI, matching the other browser tests."""

    def __init__(self, app) -> None:
        self.app = app

    def get(self, target: str):
        parsed = urlsplit(target)
        scope = dict(type='http', asgi={'version': '3.0'}, http_version='1.1', method='GET', scheme='http',
                     path=parsed.path, raw_path=parsed.path.encode(), query_string=parsed.query.encode(),
                     root_path='', headers=[(b'host', b'testserver')], server=('testserver', 80),
                     client=('127.0.0.1', 1234))
        messages = []

        async def receive():
            return {'type': 'http.request', 'body': b'', 'more_body': False}

        async def send(message):
            messages.append(message)

        asyncio.run(self.app(scope, receive, send))
        start = next(m for m in messages if m['type'] == 'http.response.start')
        body = b''.join(m.get('body', b'') for m in messages if m['type'] == 'http.response.body')
        headers = {k.decode().lower(): v.decode() for k, v in start['headers']}
        return SimpleNamespace(status_code=start['status'], headers=headers, text=body.decode('utf-8', 'replace'))


class ConsoleStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "dist"
        (self.root / "assets").mkdir(parents=True)
        (self.root / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
        (self.root / "theme-init.js").write_text("/* theme */", encoding="utf-8")
        (self.root / "assets" / "index-abc123.js").write_text("console.log(1)", encoding="utf-8")
        (self.root / ".env").write_text("SECRET=1", encoding="utf-8")
        (Path(self.temp.name) / "outside.txt").write_text("private", encoding="utf-8")
        env = patch.dict(os.environ, {"MASP_CONSOLE_DIST": str(self.root)})
        env.start()
        self.addCleanup(env.stop)
        app = FastAPI()
        app.include_router(console_static.router)
        self.client = AsgiClient(app)

    def test_client_routes_load_the_single_page_with_strict_headers(self) -> None:
        for path in ("/console/", "/console/dashboard", "/console/scans/42/print", "/console/engines/hash-list"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn("id=root", response.text)
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
                self.assertEqual(response.headers["x-frame-options"], "DENY")
                self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    def test_bare_prefix_redirects(self) -> None:
        response = self.client.get("/console")
        self.assertEqual((response.status_code, response.headers["location"]), (302, "/console/"))

    def test_fingerprinted_assets_are_immutable_and_never_fall_back(self) -> None:
        asset = self.client.get("/console/assets/index-abc123.js")
        self.assertEqual(asset.status_code, 200)
        self.assertIn("immutable", asset.headers["cache-control"])
        self.assertEqual(self.client.get("/console/assets/index-stale.js").status_code, 404)

    def test_public_files_are_served_uncached(self) -> None:
        response = self.client.get("/console/theme-init.js")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "/* theme */")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_traversal_and_dotfiles_never_leave_the_build(self) -> None:
        for path in ("/console/.env", "/console/assets/../../outside.txt", "/console/..%2Foutside.txt",
                     "/console/assets/%2e%2e/%2e%2e/outside.txt"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertNotIn("private", response.text)
                self.assertNotIn("SECRET", response.text)

    def test_missing_build_is_an_explicit_unavailable_page(self) -> None:
        with patch.dict(os.environ, {"MASP_CONSOLE_DIST": str(Path(self.temp.name) / "absent")}):
            response = self.client.get("/console/dashboard")
        self.assertEqual(response.status_code, 503)
        self.assertIn("npm --prefix frontend run build", response.text)


if __name__ == "__main__":
    unittest.main()
