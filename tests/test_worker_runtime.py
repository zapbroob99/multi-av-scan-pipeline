import json
import unittest
from unittest.mock import patch

from app.services import worker_runtime


class WorkerRuntimeTests(unittest.TestCase):
    def test_worker_status_summarizes_multiple_online_workers(self) -> None:
        payload = {
            "linux:1": {
                "state": "idle",
                "hostname": "linux",
                "pid": 1,
                "timestamp": 100,
                "active_scan_id": None,
                "engine_keys": ["static_metadata", "clamav", "yara"],
            },
            "windows:2": {
                "state": "running",
                "hostname": "windows",
                "pid": 2,
                "timestamp": 99,
                "active_scan_id": 42,
                "engine_keys": ["microsoft_defender"],
            },
        }

        def fake_get_setting(key: str, default: str | None = None) -> str:
            if key == worker_runtime.WORKER_HEARTBEATS_KEY:
                return json.dumps(payload)
            return default or ""

        with patch("app.services.worker_runtime.get_setting", side_effect=fake_get_setting):
            status = worker_runtime.get_worker_status(now=102)

        self.assertTrue(status["online"])
        self.assertEqual(status["online_count"], 2)
        self.assertEqual(status["state"], "running")
        self.assertEqual(status["active_scan_id"], 42)
        self.assertEqual(
            status["engine_keys"],
            ["clamav", "microsoft_defender", "static_metadata", "yara"],
        )

    def test_worker_is_running_scan_engine_checks_online_running_worker(self) -> None:
        payload = {
            "windows:2": {
                "state": "running",
                "hostname": "windows",
                "pid": 2,
                "timestamp": 100,
                "active_scan_id": 42,
                "engine_keys": ["microsoft_defender"],
            },
            "linux:1": {
                "state": "idle",
                "hostname": "linux",
                "pid": 1,
                "timestamp": 100,
                "active_scan_id": None,
                "engine_keys": ["clamav", "yara"],
            },
        }

        def fake_get_setting(key: str, default: str | None = None) -> str:
            if key == worker_runtime.WORKER_HEARTBEATS_KEY:
                return json.dumps(payload)
            return default or ""

        with patch("app.services.worker_runtime.get_setting", side_effect=fake_get_setting):
            self.assertTrue(
                worker_runtime.worker_is_running_scan_engine(
                    42,
                    "microsoft_defender",
                    now=102,
                )
            )
            self.assertFalse(
                worker_runtime.worker_is_running_scan_engine(
                    42,
                    "clamav",
                    now=102,
                )
            )

    def test_worker_status_prunes_expired_offline_workers(self) -> None:
        payload = {
            "linux:1": {
                "state": "idle",
                "hostname": "linux",
                "pid": 1,
                "timestamp": 100,
                "active_scan_id": None,
                "engine_keys": ["clamav"],
            },
            "offline:9": {
                "state": "idle",
                "hostname": "offline",
                "pid": 9,
                "timestamp": 1,
                "active_scan_id": None,
                "engine_keys": ["yara"],
            },
        }

        def fake_get_setting(key: str, default: str | None = None) -> str:
            if key == worker_runtime.WORKER_HEARTBEATS_KEY:
                return json.dumps(payload)
            return default or ""

        with patch("app.services.worker_runtime.get_setting", side_effect=fake_get_setting), patch(
            "app.services.worker_runtime.worker_retention_seconds",
            return_value=60,
        ):
            status = worker_runtime.get_worker_status(now=102)

        self.assertEqual(status["online_count"], 1)
        self.assertEqual(status["total_worker_records"], 1)
        self.assertEqual(len(status["workers"]), 1)
        self.assertEqual(status["workers"][0]["hostname"], "linux")

    def test_update_worker_heartbeats_prunes_expired_records_before_insert(self) -> None:
        existing_payload = {
            "offline:9": {
                "state": "idle",
                "hostname": "offline",
                "pid": 9,
                "timestamp": 1,
                "active_scan_id": None,
                "engine_keys": ["yara"],
            }
        }
        new_payload = {
            "state": "idle",
            "hostname": "linux",
            "pid": 1,
            "timestamp": 100,
            "active_scan_id": None,
            "engine_keys": ["clamav"],
        }

        def fake_get_setting(key: str, default: str | None = None) -> str:
            if key == worker_runtime.WORKER_HEARTBEATS_KEY:
                return json.dumps(existing_payload)
            return default or ""

        with patch("app.services.worker_runtime.get_setting", side_effect=fake_get_setting), patch(
            "app.services.worker_runtime.worker_retention_seconds",
            return_value=60,
        ):
            updated = worker_runtime.update_worker_heartbeats(new_payload)

        self.assertEqual(list(updated.keys()), ["linux:1"])


if __name__ == "__main__":
    unittest.main()
