import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database
from app.main import render_worker_node_rows
from app.services import worker_runtime


class WorkerNodeDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "worker-nodes.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def heartbeat(self, **overrides: object):
        values: dict[str, object] = {
            "node_id": "windows-defender-01",
            "display_name": "Defender Node 01",
            "hostname": "win-av-01",
            "platform": "windows",
            "agent_version": "0.1.0",
            "labels_json": '{"site": "istanbul"}',
            "capacity": 2,
            "advertised_engine_keys_json": '["microsoft_defender"]',
            "runtime_state": "idle",
            "active_scan_id": None,
            "process_id": 101,
            "last_heartbeat_at": 1000,
        }
        values.update(overrides)
        return database.upsert_worker_node_heartbeat(**values)

    def test_heartbeat_registers_durable_node_metadata(self) -> None:
        node = self.heartbeat()

        self.assertEqual(node.node_id, "windows-defender-01")
        self.assertEqual(node.platform, "windows")
        self.assertEqual(node.capacity, 2)
        self.assertEqual(json.loads(node.labels_json), {"site": "istanbul"})
        self.assertEqual(database.list_worker_nodes(), [node])

    def test_heartbeat_preserves_admin_lifecycle_choice(self) -> None:
        self.heartbeat()
        self.assertTrue(
            database.update_worker_node_lifecycle(
                "windows-defender-01", "draining"
            )
        )

        refreshed = self.heartbeat(
            runtime_state="running", active_scan_id=42, process_id=202
        )

        self.assertEqual(refreshed.lifecycle_state, "draining")
        self.assertEqual(refreshed.runtime_state, "running")
        self.assertEqual(refreshed.active_scan_id, 42)
        self.assertEqual(refreshed.process_id, 202)

    def test_lifecycle_rejects_unknown_state(self) -> None:
        self.heartbeat()
        with self.assertRaises(ValueError):
            database.update_worker_node_lifecycle(
                "windows-defender-01", "offline"
            )

    def test_existing_database_is_upgraded_in_place(self) -> None:
        legacy_path = Path(self.temp_dir.name) / "legacy-worker.db"
        with sqlite3.connect(legacy_path) as connection:
            connection.execute(
                "CREATE TABLE app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO app_settings (key, value) VALUES ('legacy', 'kept')"
            )
        database.DB_PATH = legacy_path

        database.init_db()
        self.heartbeat()

        self.assertEqual(database.get_setting("legacy"), "kept")
        with database.connect() as connection:
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(worker_nodes)").fetchall()
            }
        self.assertIn("lifecycle_state", columns)
        self.assertIn("last_heartbeat_at", columns)


class WorkerNodeRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "worker-runtime.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def heartbeat(self, **overrides: object):
        values: dict[str, object] = {
            "node_id": "windows-defender-01",
            "display_name": "Defender Node 01",
            "hostname": "win-av-01",
            "platform": "windows",
            "agent_version": "0.1.0",
            "labels_json": '{"site": "istanbul"}',
            "capacity": 2,
            "advertised_engine_keys_json": '["microsoft_defender"]',
            "runtime_state": "idle",
            "active_scan_id": None,
            "process_id": 101,
            "last_heartbeat_at": 1000,
        }
        values.update(overrides)
        return database.upsert_worker_node_heartbeat(**values)

    def test_stable_node_id_survives_process_restart_and_disabled_node_pauses(self) -> None:
        environment = {
            "MASP_WORKER_NODE_ID": "defender-pool-a",
            "MASP_WORKER_NODE_NAME": "Defender Pool A",
            "MASP_WORKER_LABELS": "site=istanbul,tier=primary",
            "MASP_WORKER_CAPACITY": "3",
            "MASP_WORKER_AGENT_VERSION": "0.2.0",
        }
        with patch.dict("os.environ", environment, clear=False), patch(
            "app.services.worker_runtime.socket.gethostname", return_value="win-av-01"
        ), patch(
            "app.services.worker_runtime.worker_engine_keys",
            return_value={"microsoft_defender"},
        ), patch(
            "app.services.worker_runtime.os.getpid", return_value=101
        ), patch(
            "app.services.worker_runtime.time.time", return_value=1000
        ):
            self.assertTrue(worker_runtime.record_worker_heartbeat("idle"))

        self.assertTrue(
            database.update_worker_node_lifecycle("defender-pool-a", "disabled")
        )

        with patch.dict("os.environ", environment, clear=False), patch(
            "app.services.worker_runtime.socket.gethostname", return_value="win-av-01"
        ), patch(
            "app.services.worker_runtime.worker_engine_keys",
            return_value={"microsoft_defender"},
        ), patch(
            "app.services.worker_runtime.os.getpid", return_value=202
        ), patch(
            "app.services.worker_runtime.time.time", return_value=1001
        ):
            self.assertTrue(worker_runtime.record_worker_heartbeat("starting"))
            self.assertFalse(worker_runtime.worker_accepts_new_work())
            status = worker_runtime.get_worker_status(now=1001)

        nodes = database.list_worker_nodes()
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].node_id, "defender-pool-a")
        self.assertEqual(nodes[0].process_id, 202)
        self.assertEqual(nodes[0].lifecycle_state, "disabled")
        self.assertEqual(status["online_count"], 2)
        self.assertEqual(status["schedulable_count"], 0)
        self.assertEqual(status["engine_keys"], [])

    def test_node_status_derives_offline_without_mutating_lifecycle(self) -> None:
        self.heartbeat(last_heartbeat_at=100)

        with patch(
            "app.services.worker_runtime.worker_stale_seconds", return_value=30
        ):
            statuses = worker_runtime.get_worker_node_statuses(now=200)

        self.assertEqual(statuses[0]["lifecycle_state"], "active")
        self.assertEqual(statuses[0]["effective_state"], "offline")
        self.assertFalse(statuses[0]["schedulable"])

    def test_system_row_exposes_lifecycle_control_and_metadata(self) -> None:
        html = render_worker_node_rows(
            {
                "nodes": [
                    {
                        "node_id": "defender-pool-a",
                        "display_name": "Defender Pool A",
                        "hostname": "win-av-01",
                        "platform": "windows",
                        "agent_version": "0.2.0",
                        "labels": {"site": "istanbul"},
                        "capacity": 2,
                        "engine_keys": ["microsoft_defender"],
                        "lifecycle_state": "draining",
                        "effective_state": "draining",
                        "active_scan_id": 42,
                        "last_seen_at": "2026-08-24 12:00:00",
                        "age_seconds": 2,
                    }
                ]
            }
        )

        self.assertIn("Defender Pool A", html)
        self.assertIn("microsoft_defender", html)
        self.assertIn("site=istanbul", html)
        self.assertIn('action="/workers/state"', html)
        self.assertIn('value="draining" selected', html)


if __name__ == "__main__":
    unittest.main()
