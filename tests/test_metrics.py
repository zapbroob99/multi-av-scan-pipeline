"""Tests for the Prometheus metrics endpoint and payload.

The endpoint exists so an outage is detectable from outside: ICAP is
fail-closed, so a stalled MASP blocks real uploads. These tests pin the two
properties that make the metrics trustworthy for alerting -- queue latency is
reported (not just depth) and the payload is authenticated -- plus the
exposition-format details a scraper depends on.
"""

import asyncio
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from app import database
from app.main import app
from app.models import StoredSample
from app.services import metrics


def asgi_get_raw(
    path: str, headers: list[tuple[bytes, bytes]] | None = None
) -> tuple[int, dict[str, str], str]:
    """Drive the app over ASGI and return the body as text, not JSON."""
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
    status: list[int] = []
    raw_headers: list[list[tuple[bytes, bytes]]] = []
    body: list[bytes] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            status.append(message["status"])
            raw_headers.append(list(message.get("headers", [])))
        elif message["type"] == "http.response.body":
            body.append(message.get("body", b""))

    asyncio.run(app(scope, receive, send))
    header_map = {
        key.decode("latin-1").lower(): value.decode("latin-1") for key, value in raw_headers[0]
    }
    return status[0], header_map, b"".join(body).decode("utf-8")


def _sample(sha: str) -> StoredSample:
    return StoredSample(
        original_filename="s.bin",
        stored_filename="s.bin",
        storage_path=f"/tmp/{sha}.bin",
        content_type="application/octet-stream",
        size_bytes=1,
        md5="0" * 32,
        sha1="0" * 40,
        sha256=sha,
    )


class _MetricsDbFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def _queued_scan(self) -> int:
        sample_id = database.create_sample(_sample("1" * 64))
        return database.create_scan_job(
            sample_id, case_name="C", priority="Normal", note="", status="queued"
        )


class MetricsPayloadTests(_MetricsDbFixture):
    def test_payload_declares_help_and_type_for_every_metric(self) -> None:
        body = metrics.render_metrics()
        names = {
            line.split()[2] for line in body.splitlines() if line.startswith("# TYPE")
        }
        # A scraper rejects a series it has no TYPE for; every emitted sample
        # must belong to a declared metric.
        emitted = {
            line.split("{")[0].split()[0]
            for line in body.splitlines()
            if line and not line.startswith("#")
        }
        self.assertTrue(emitted)
        self.assertTrue(emitted <= names, emitted - names)
        for name in emitted:
            self.assertIn(f"# HELP {name} ", body)

    def test_queue_depth_and_status_counts_follow_the_database(self) -> None:
        self._queued_scan()
        body = metrics.render_metrics()
        self.assertIn('masp_scans_total{status="queued"} 1', body)
        self.assertIn("masp_scan_queue_depth 1", body)

    def test_oldest_queued_age_reports_the_wait_not_just_the_depth(self) -> None:
        # Depth alone cannot separate "busy" from "stalled"; the age series is
        # the one an alert rule fires on.
        self._queued_scan()
        later = datetime.now(timezone.utc) + timedelta(seconds=600)
        body = metrics.render_metrics(now=later)
        age_line = next(
            line for line in body.splitlines()
            if line.startswith("masp_scan_oldest_queued_age_seconds ")
        )
        age = float(age_line.split()[1])
        self.assertGreaterEqual(age, 600)

    def test_empty_queue_reports_zero_age_rather_than_omitting_the_series(self) -> None:
        # Alert rules stay simple only if the series is always present.
        body = metrics.render_metrics()
        self.assertIn("masp_scan_oldest_queued_age_seconds 0", body)
        self.assertIn("masp_scan_oldest_running_age_seconds 0", body)

    def test_worker_heartbeat_age_is_negative_when_no_worker_is_online(self) -> None:
        body = metrics.render_metrics()
        self.assertIn("masp_workers_online 0", body)
        self.assertIn("masp_worker_nodes_schedulable 0", body)
        self.assertIn("masp_worker_heartbeat_age_seconds -1", body)

    def test_engine_label_values_are_escaped(self) -> None:
        rows = [{"engine_name": 'we"ird\\engine', "completed_results": 1,
                 "failed_results": 0, "skipped_results": 0, "detections": 0}]
        with patch.object(metrics, "list_engine_result_metrics", return_value=rows):
            body = metrics.render_metrics()
        self.assertIn(r'engine="we\"ird\\engine"', body)


class MetricsEndpointTests(_MetricsDbFixture):
    def _configured(self):
        return (
            patch.dict(os.environ, {"MASP_API_TOKEN": "metrics-secret"}, clear=False),
            patch("app.services.auth.get_setting", return_value=""),
        )

    def test_metrics_requires_the_api_token(self) -> None:
        # The payload reports scan volumes and detection counts, so unlike
        # /health it must not be anonymous.
        env, setting = self._configured()
        with env, setting:
            status, headers, _ = asgi_get_raw("/metrics")
        self.assertEqual(status, 401)
        self.assertEqual(headers.get("www-authenticate"), "Bearer")

    def test_metrics_rejects_a_wrong_token(self) -> None:
        env, setting = self._configured()
        with env, setting:
            status, _, _ = asgi_get_raw(
                "/metrics", headers=[(b"authorization", b"Bearer wrong")]
            )
        self.assertEqual(status, 401)

    def test_metrics_served_in_prometheus_format_with_a_valid_token(self) -> None:
        env, setting = self._configured()
        with env, setting:
            status, headers, body = asgi_get_raw(
                "/metrics", headers=[(b"authorization", b"Bearer metrics-secret")]
            )
        self.assertEqual(status, 200)
        self.assertTrue(
            headers.get("content-type", "").startswith("text/plain"),
            headers.get("content-type"),
        )
        self.assertIn("# TYPE masp_scan_queue_depth gauge", body)

    def test_metrics_can_be_disabled(self) -> None:
        env, setting = self._configured()
        with env, setting, patch.dict(
            os.environ, {"MASP_METRICS_ENABLED": "0"}, clear=False
        ):
            status, _, _ = asgi_get_raw(
                "/metrics", headers=[(b"authorization", b"Bearer metrics-secret")]
            )
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
