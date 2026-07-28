"""Concurrency tests for the per-worker heartbeat store.

These exercise the real database (not mocks) because the whole point of moving
each worker onto its own ``app_settings`` row is that two workers writing at the
same time can no longer clobber each other. The old shared read-modify-write row
lost updates under this exact interleaving.

SQLite runs by default. Point ``MASP_TEST_POSTGRES_URL`` at a throwaway
PostgreSQL to also cover real concurrent writes there (its ``public`` schema is
dropped and recreated).
"""

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database
from app.services import worker_runtime

TEST_POSTGRES_URL = os.getenv("MASP_TEST_POSTGRES_URL", "").strip()

# Two simulated workers advertising disjoint engine capabilities.
WORKER_ENGINE_KEYS = {
    "worker-A": {"clamav", "yara"},
    "worker-B": {"microsoft_defender"},
}


def _fake_hostname() -> str:
    return threading.current_thread().name


def _fake_worker_engine_keys() -> set[str]:
    return set(WORKER_ENGINE_KEYS.get(threading.current_thread().name, set()))


def _run_two_workers_concurrently(iterations: int) -> None:
    """Drive the real writer from two threads with distinct identities.

    Identity and advertised engine keys are derived from the running thread, so
    each thread behaves like an independent worker process. Both write on every
    iteration with no external synchronization, maximizing interleaving.
    """
    start_barrier = threading.Barrier(len(WORKER_ENGINE_KEYS))
    errors: list[str] = []
    errors_lock = threading.Lock()

    def run() -> None:
        try:
            start_barrier.wait()
            for _ in range(iterations):
                recorded = worker_runtime.record_worker_heartbeat(
                    "running", active_scan_id=1
                )
                if not recorded:
                    raise AssertionError("heartbeat write was not persisted")
        except Exception as exc:  # pragma: no cover - unexpected writer failure
            with errors_lock:
                errors.append(f"{threading.current_thread().name}: {exc!r}")

    with patch("app.services.worker_runtime.socket.gethostname", side_effect=_fake_hostname), patch(
        "app.services.worker_runtime.worker_engine_keys", side_effect=_fake_worker_engine_keys
    ):
        threads = [
            threading.Thread(target=run, name=name) for name in WORKER_ENGINE_KEYS
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert errors == [], f"heartbeat writer raised under concurrency: {errors}"


class _HeartbeatConcurrencyMixin:
    def test_both_workers_remain_visible_after_concurrent_writes(self) -> None:
        _run_two_workers_concurrently(iterations=25)

        # Both distinct rows must be present. A lost update (the old shared-row
        # bug) would drop one worker or its engine keys; we assert the actual
        # persisted content, so a write swallowed by a lock error also fails
        # this rather than passing silently.
        status = worker_runtime.get_worker_status(now=int(time.time()))
        self.assertEqual(status["online_count"], 2, status)
        self.assertEqual(
            status["engine_keys"],
            ["clamav", "microsoft_defender", "yara"],
            status,
        )

        by_host = {
            str(worker["hostname"]): worker for worker in status["workers"]
        }
        self.assertEqual(set(by_host), {"worker-A", "worker-B"})
        self.assertEqual(by_host["worker-A"]["engine_keys"], ["clamav", "yara"])
        self.assertEqual(
            by_host["worker-B"]["engine_keys"], ["microsoft_defender"]
        )

    def test_reaper_coverage_survives_heartbeat_contention(self) -> None:
        # The orphaned-job reaper decides coverage from get_worker_status()'s
        # engine key union. If concurrent heartbeats dropped a live worker, an
        # online engine would look uncovered and a real scan could be reaped and
        # blocked. Assert both engines stay covered after contention.
        _run_two_workers_concurrently(iterations=25)

        covered = set(worker_runtime.get_worker_status(now=int(time.time()))["engine_keys"])
        self.assertIn("clamav", covered)
        self.assertIn("yara", covered)
        self.assertIn("microsoft_defender", covered)

    def test_cleanup_does_not_delete_a_concurrently_refreshed_worker(self) -> None:
        row_key = (
            f"{worker_runtime.WORKER_HEARTBEAT_ROW_PREFIX}refreshing-worker:99"
        )
        stale_raw = json.dumps(
            {
                "state": "idle",
                "hostname": "refreshing-worker",
                "pid": 99,
                "timestamp": 100,
                "active_scan_id": None,
                "engine_keys": ["clamav"],
            },
            sort_keys=True,
        )
        fresh_raw = json.dumps(
            {
                "state": "running",
                "hostname": "refreshing-worker",
                "pid": 99,
                "timestamp": 1000,
                "active_scan_id": 42,
                "engine_keys": ["clamav"],
            },
            sort_keys=True,
        )
        database.set_setting(row_key, stale_raw)
        conditional_delete = database.delete_settings_if_values_match

        def refresh_before_delete(observed: dict[str, str]) -> int:
            database.set_setting(row_key, fresh_raw)
            return conditional_delete(observed)

        with patch(
            "app.services.worker_runtime.delete_settings_if_values_match",
            side_effect=refresh_before_delete,
        ), patch(
            "app.services.worker_runtime.worker_retention_seconds",
            return_value=300,
        ):
            removed = worker_runtime.cleanup_stale_worker_heartbeats(now=1000)

        self.assertEqual(removed, 0)
        self.assertEqual(database.get_setting(row_key), fresh_raw)


class SqliteHeartbeatConcurrencyTests(_HeartbeatConcurrencyMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()
        worker_runtime._last_heartbeat_cleanup_at = 0.0

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()


@unittest.skipUnless(TEST_POSTGRES_URL, "set MASP_TEST_POSTGRES_URL to a throwaway PostgreSQL")
class PostgresHeartbeatConcurrencyTests(_HeartbeatConcurrencyMixin, unittest.TestCase):
    def setUp(self) -> None:
        import psycopg

        with psycopg.connect(TEST_POSTGRES_URL, autocommit=True) as connection:
            connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
            connection.execute("CREATE SCHEMA public")

        self.original_database_url = database.DATABASE_URL
        self.original_pool_enabled = database.DB_POOL_ENABLED
        # Pool disabled so each thread opens its own PostgreSQL session, faithfully
        # modelling two independent worker processes writing at once.
        database.close_pool()
        database.DATABASE_URL = TEST_POSTGRES_URL
        database.DB_POOL_ENABLED = False
        database.init_db()
        worker_runtime._last_heartbeat_cleanup_at = 0.0

    def tearDown(self) -> None:
        database.close_pool()
        database.DATABASE_URL = self.original_database_url
        database.DB_POOL_ENABLED = self.original_pool_enabled


if __name__ == "__main__":
    unittest.main()
