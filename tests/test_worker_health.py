import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database
from app.services import worker_health


class WorkerEngineHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "worker-health.db"
        database.DATABASE_URL = ""
        database.init_db()
        self.engine_id = database.create_engine_instance(
            "static_metadata", "Static Metadata"
        )
        database.upsert_worker_node_heartbeat(
            node_id="linux-01",
            display_name="Linux 01",
            hostname="linux-01",
            platform="linux",
            agent_version="0.3.0",
            labels_json='{"site": "istanbul"}',
            capacity=1,
            advertised_engine_keys_json='["static_metadata"]',
            runtime_state="idle",
            active_scan_id=None,
            process_id=101,
            last_heartbeat_at=1000,
        )

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def worker_patches(self):
        return (
            patch("app.services.worker_health.current_worker_node_id", return_value="linux-01"),
            patch("app.services.worker_health.current_worker_process_id", return_value="linux-01:101"),
            patch("app.services.worker_health.worker_engine_keys", return_value={"static_metadata"}),
            patch("app.services.worker_health.health_checks_per_tick", return_value=2),
        )

    def test_worker_probe_persists_versions_storage_and_success(self) -> None:
        node_id, process_id, engine_keys, checks_per_tick = self.worker_patches()
        with node_id, process_id, engine_keys, checks_per_tick, patch(
            "app.services.worker_health.engine_health",
            return_value={
                "ok": True,
                "status": "available",
                "detail": "Analyzer ready.",
                "product_version": "builtin",
                "engine_version": "builtin-1",
                "signature_version": "rules-7",
                "service_state": "available",
            },
        ), patch(
            "app.services.worker_health.storage_access",
            return_value=(True, True, "Storage ready."),
        ):
            self.assertEqual(worker_health.run_due_worker_health_checks(now=1000), 1)
            self.assertEqual(worker_health.run_due_worker_health_checks(now=1000), 0)

        records = database.list_engine_node_health(
            node_id="linux-01", engine_instance_id=self.engine_id
        )
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.status, "healthy")
        self.assertTrue(record.ok)
        self.assertEqual(record.engine_version, "builtin-1")
        self.assertEqual(record.signature_version, "rules-7")
        self.assertTrue(record.storage_readable)
        self.assertEqual(record.last_success_at, 1000)
        self.assertEqual(json.loads(record.details_json)["adapter_key"], "static_metadata")

    def test_failed_probe_increments_failures_and_keeps_last_success(self) -> None:
        node_id, process_id, engine_keys, checks_per_tick = self.worker_patches()
        with node_id, process_id, engine_keys, checks_per_tick, patch(
            "app.services.worker_health.engine_health",
            return_value={"ok": True, "status": "available", "detail": "Ready."},
        ), patch(
            "app.services.worker_health.storage_access", return_value=(True, True, "Ready.")
        ):
            worker_health.run_due_worker_health_checks(now=1000)

        database.request_engine_node_health_check(self.engine_id)
        node_id, process_id, engine_keys, checks_per_tick = self.worker_patches()
        with node_id, process_id, engine_keys, checks_per_tick, patch(
            "app.services.worker_health.engine_health",
            return_value={"ok": False, "status": "unavailable", "detail": "Stopped."},
        ), patch(
            "app.services.worker_health.storage_access", return_value=(True, True, "Ready.")
        ):
            worker_health.run_due_worker_health_checks(now=1001)

        record = database.list_engine_node_health(engine_instance_id=self.engine_id)[0]
        self.assertEqual(record.status, "unhealthy")
        self.assertEqual(record.consecutive_failures, 1)
        self.assertEqual(record.last_success_at, 1000)

    def test_health_commit_is_fenced_after_lease_reclaim(self) -> None:
        database.ensure_engine_node_health_rows("linux-01", {self.engine_id})
        first = database.claim_due_engine_node_health(
            "linux-01",
            "worker-a",
            {self.engine_id},
            interval_seconds=60,
            lease_seconds=30,
            now=1000,
        )
        second = database.claim_due_engine_node_health(
            "linux-01",
            "worker-b",
            {self.engine_id},
            interval_seconds=60,
            lease_seconds=30,
            now=1031,
        )
        assert first is not None and second is not None

        common = {
            "node_id": "linux-01",
            "engine_instance_id": self.engine_id,
            "ok": True,
            "health_status": "available",
            "detail": "Ready.",
            "product_version": None,
            "engine_version": None,
            "signature_version": None,
            "service_state": "available",
            "storage_readable": True,
            "storage_writable": True,
            "details_json": "{}",
        }
        self.assertFalse(
            database.commit_engine_node_health_if_owned(
                **common,
                worker_id="worker-a",
                check_generation=first.check_generation,
                now=1031,
            )
        )
        self.assertTrue(
            database.commit_engine_node_health_if_owned(
                **common,
                worker_id="worker-b",
                check_generation=second.check_generation,
                now=1031,
            )
        )

    def test_successful_scan_updates_last_scan_and_versions(self) -> None:
        database.ensure_engine_node_health_rows("linux-01", {self.engine_id})
        database.record_engine_node_scan_success(
            "linux-01",
            self.engine_id,
            engine_version="builtin-2",
            signature_version="rules-8",
            now=2000,
        )

        record = database.list_engine_node_health(engine_instance_id=self.engine_id)[0]
        self.assertEqual(record.last_scan_success_at, 2000)
        self.assertEqual(record.engine_version, "builtin-2")
        self.assertEqual(record.signature_version, "rules-8")


if __name__ == "__main__":
    unittest.main()
