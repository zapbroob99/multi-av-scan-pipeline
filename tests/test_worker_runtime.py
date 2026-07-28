import json
import unittest
from unittest.mock import patch

from app.services import worker_runtime


def _row_key(hostname: str, pid: int) -> str:
    return f"{worker_runtime.WORKER_HEARTBEAT_ROW_PREFIX}{hostname}:{pid}"


def _payload(hostname: str, pid: int, timestamp: int, **overrides: object) -> dict:
    payload = {
        "state": "idle",
        "hostname": hostname,
        "pid": pid,
        "timestamp": timestamp,
        "active_scan_id": None,
        "engine_keys": [],
    }
    payload.update(overrides)
    return payload


def _patch_settings(settings: dict[str, str]):
    return patch(
        "app.services.worker_runtime.list_settings_by_prefix",
        return_value=settings,
    )


class WorkerRuntimeReaderTests(unittest.TestCase):
    def test_worker_status_summarizes_multiple_online_workers(self) -> None:
        settings = {
            _row_key("linux", 1): json.dumps(
                _payload(
                    "linux",
                    1,
                    100,
                    state="idle",
                    engine_keys=["static_metadata", "clamav", "yara"],
                )
            ),
            _row_key("windows", 2): json.dumps(
                _payload(
                    "windows",
                    2,
                    99,
                    state="running",
                    active_scan_id=42,
                    engine_keys=["microsoft_defender"],
                )
            ),
        }

        with _patch_settings(settings):
            status = worker_runtime.get_worker_status(now=102)

        self.assertTrue(status["online"])
        self.assertEqual(status["online_count"], 2)
        self.assertEqual(status["state"], "running")
        self.assertEqual(status["active_scan_id"], 42)
        self.assertEqual(
            status["engine_keys"],
            ["clamav", "microsoft_defender", "static_metadata", "yara"],
        )

    def test_worker_status_offline_when_no_records(self) -> None:
        with _patch_settings({}):
            status = worker_runtime.get_worker_status(now=102)

        self.assertFalse(status["online"])
        self.assertEqual(status["state"], "offline")
        self.assertEqual(status["online_count"], 0)
        self.assertEqual(status["workers"], [])

    def test_worker_is_running_scan_engine_checks_online_running_worker(self) -> None:
        settings = {
            _row_key("windows", 2): json.dumps(
                _payload(
                    "windows",
                    2,
                    100,
                    state="running",
                    active_scan_id=42,
                    engine_keys=["microsoft_defender"],
                )
            ),
            _row_key("linux", 1): json.dumps(
                _payload("linux", 1, 100, engine_keys=["clamav", "yara"])
            ),
        }

        with _patch_settings(settings):
            self.assertTrue(
                worker_runtime.worker_is_running_scan_engine(42, "microsoft_defender", now=102)
            )
            self.assertFalse(
                worker_runtime.worker_is_running_scan_engine(42, "clamav", now=102)
            )

    def test_worker_status_drops_records_past_retention(self) -> None:
        settings = {
            _row_key("linux", 1): json.dumps(_payload("linux", 1, 100, engine_keys=["clamav"])),
            _row_key("offline", 9): json.dumps(_payload("offline", 9, 1, engine_keys=["yara"])),
        }

        with _patch_settings(settings), patch(
            "app.services.worker_runtime.worker_retention_seconds",
            return_value=60,
        ):
            status = worker_runtime.get_worker_status(now=102)

        self.assertEqual(status["online_count"], 1)
        self.assertEqual(status["total_worker_records"], 1)
        self.assertEqual(len(status["workers"]), 1)
        self.assertEqual(status["workers"][0]["hostname"], "linux")


class WorkerRuntimeLegacyMergeTests(unittest.TestCase):
    def test_reads_legacy_bulk_and_single_rows(self) -> None:
        settings = {
            worker_runtime.WORKER_HEARTBEATS_KEY: json.dumps(
                {"linux:1": _payload("linux", 1, 100, engine_keys=["clamav"])}
            ),
            worker_runtime.WORKER_HEARTBEAT_KEY: json.dumps(
                _payload("windows", 2, 100, engine_keys=["microsoft_defender"])
            ),
        }

        with _patch_settings(settings):
            status = worker_runtime.get_worker_status(now=101)

        self.assertEqual(status["online_count"], 2)
        self.assertEqual(
            status["engine_keys"], ["clamav", "microsoft_defender"]
        )

    def test_newest_timestamp_wins_across_sources(self) -> None:
        settings = {
            worker_runtime.WORKER_HEARTBEATS_KEY: json.dumps(
                {"linux:1": _payload("linux", 1, 100, state="idle")}
            ),
            _row_key("linux", 1): json.dumps(
                _payload("linux", 1, 150, state="running", active_scan_id=7)
            ),
        }

        with _patch_settings(settings):
            workers = worker_runtime.get_worker_heartbeats(160)

        self.assertEqual(len(workers), 1)
        self.assertEqual(workers[0]["state"], "running")
        self.assertEqual(workers[0]["active_scan_id"], 7)

    def test_per_worker_row_wins_timestamp_tie(self) -> None:
        settings = {
            worker_runtime.WORKER_HEARTBEATS_KEY: json.dumps(
                {"linux:1": _payload("linux", 1, 100, state="idle")}
            ),
            _row_key("linux", 1): json.dumps(
                _payload("linux", 1, 100, state="running", active_scan_id=9)
            ),
        }

        with _patch_settings(settings):
            workers = worker_runtime.get_worker_heartbeats(101)

        self.assertEqual(len(workers), 1)
        self.assertEqual(workers[0]["state"], "running")
        self.assertEqual(workers[0]["active_scan_id"], 9)


class WorkerRuntimeCleanupTests(unittest.TestCase):
    def test_cleanup_deletes_only_stale_rows(self) -> None:
        settings = {
            _row_key("fresh", 1): json.dumps(_payload("fresh", 1, 1000)),
            _row_key("stale", 2): json.dumps(_payload("stale", 2, 100)),
            f"{worker_runtime.WORKER_HEARTBEAT_ROW_PREFIX}broken": "{not json",
            "worker.scan_worker.heartbeat_policy": "unrelated-setting",
        }

        deleted: list[dict[str, str]] = []

        with _patch_settings(settings), patch(
            "app.services.worker_runtime.delete_settings_if_values_match",
            side_effect=lambda values: deleted.append(dict(values)) or len(values),
        ), patch(
            "app.services.worker_runtime.worker_retention_seconds",
            return_value=300,
        ):
            removed = worker_runtime.cleanup_stale_worker_heartbeats(now=1000)

        self.assertEqual(removed, 2)
        self.assertEqual(len(deleted), 1)
        self.assertEqual(
            set(deleted[0]),
            {_row_key("stale", 2), f"{worker_runtime.WORKER_HEARTBEAT_ROW_PREFIX}broken"},
        )
        self.assertEqual(deleted[0][_row_key("stale", 2)], settings[_row_key("stale", 2)])

    def test_cleanup_keeps_legacy_key_refreshed_by_active_worker(self) -> None:
        # A legacy bulk row whose newest embedded worker is still fresh must not
        # be deleted, even if another embedded worker is stale.
        settings = {
            worker_runtime.WORKER_HEARTBEATS_KEY: json.dumps(
                {
                    "old:1": _payload("old", 1, 100),
                    "active:2": _payload("active", 2, 1000),
                }
            ),
        }

        with _patch_settings(settings), patch(
            "app.services.worker_runtime.delete_settings_if_values_match"
        ) as delete_mock, patch(
            "app.services.worker_runtime.worker_retention_seconds",
            return_value=300,
        ):
            removed = worker_runtime.cleanup_stale_worker_heartbeats(now=1000)

        self.assertEqual(removed, 0)
        delete_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
