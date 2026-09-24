import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from app import database as db
from app.main import LEGACY_REDIRECTS, app
from app.models import StoredSample
from app.services import auth


class LegacyRedirectTests(unittest.TestCase):
    """The server-rendered UI is retired; its GET paths lead to the console."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.original = (db.DB_PATH, db.DATABASE_URL)
        db.DB_PATH, db.DATABASE_URL = Path(self.temp.name) / "redirects.db", ""
        self.addCleanup(self._restore)
        db.init_db()
        user_id = db.create_user("redirect-admin", auth.hash_password("test-password"), "admin")
        self.token = "synthetic-redirect-session"
        db.create_auth_session(user_id=user_id, token_hash=auth.hash_session_token(self.token),
                               expires_at=int(time.time()) + 3600)

    def _restore(self) -> None:
        db.DB_PATH, db.DATABASE_URL = self.original

    def request(self, target: str, method: str = "GET", *, session: bool = False):
        parsed = urlsplit(target)
        headers = [(b"host", b"testserver")]
        if session:
            headers.append((b"cookie", f"{auth.SESSION_COOKIE}={self.token}".encode()))
        scope = dict(type="http", asgi={"version": "3.0"}, http_version="1.1", method=method, scheme="http",
                     path=parsed.path, raw_path=parsed.path.encode(), query_string=parsed.query.encode(),
                     root_path="", headers=headers, server=("testserver", 80), client=("127.0.0.1", 1234))
        messages = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)

        asyncio.run(app(scope, receive, send))
        start = next(m for m in messages if m["type"] == "http.response.start")
        return start["status"], dict((k.decode().lower(), v.decode()) for k, v in start["headers"]).get("location")

    def scan(self, source: str) -> int:
        sample = db.create_sample(StoredSample("x.bin", "x.bin", "/private/x", "application/octet-stream", 1,
                                              "a" * 32, "b" * 40, "c" * 64))
        return db.create_scan_job(sample, "Case", "normal", "", source=source)

    def test_every_retired_page_redirects_to_its_console_screen(self) -> None:
        for path, target in LEGACY_REDIRECTS.items():
            with self.subTest(path=path):
                self.assertEqual(self.request(path), (301, target))
        self.assertEqual(self.request("/batches/7"), (301, "/console/batches/7"))
        self.assertEqual(self.request("/api-ledger/batches/7"), (301, "/console/api-ledger/batches/7"))
        self.assertEqual(self.request("/api-ledger/scans/3/status"), (301, "/console/api-ledger/scans/3/status-json"))
        self.assertEqual(self.request("/api-ledger/batches/3/result"), (301, "/console/api-ledger/batches/3/result-json"))
        self.assertEqual(self.request("/api-ledger/scans/3/other")[0], 404)

    def test_scan_links_reveal_the_source_only_to_a_signed_in_operator(self) -> None:
        manual, automation = self.scan("manual"), self.scan("api")
        # Anonymous: no lookup, so an ID cannot be probed for its source.
        self.assertEqual(self.request(f"/scans/{automation}"), (302, f"/console/scans/{automation}"))
        self.assertEqual(self.request(f"/scans/{automation}", session=True),
                         (302, f"/console/api-ledger/scans/{automation}"))
        self.assertEqual(self.request(f"/scans/{manual}/report", session=True), (302, f"/console/scans/{manual}/print"))
        self.assertEqual(self.request(f"/scans/{manual}/export.csv", session=True), (302, f"/console/scans/{manual}/manage"))
        self.assertEqual(self.request("/scans/999999", session=True), (302, "/console/scans/999999"))

    def test_legacy_forms_and_static_assets_are_gone(self) -> None:
        for method, path in (("POST", "/login"), ("POST", "/logout"), ("POST", "/scans/4/delete"),
                             ("POST", "/engines/add"), ("POST", "/users"), ("GET", "/static/css/app.css")):
            with self.subTest(path=path):
                self.assertIn(self.request(path, method)[0], {404, 405})


if __name__ == "__main__":
    unittest.main()
