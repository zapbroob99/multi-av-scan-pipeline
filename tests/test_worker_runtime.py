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


if __name__ == "__main__":
    unittest.main()
