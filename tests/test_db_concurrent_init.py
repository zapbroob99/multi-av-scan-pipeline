"""Concurrent schema-bootstrap test for PostgreSQL.

Reproduces the real "app and worker start together on a fresh database"
scenario that the serial-startup workaround in the verify compose used to
paper over: many independent sessions call ``init_db()`` at once against an
empty schema. Without the advisory lock in ``init_postgres_db`` this races on
``CREATE TABLE IF NOT EXISTS`` and raises a duplicate ``pg_type`` error; with
it, every session succeeds.

Requires a throwaway PostgreSQL (its ``public`` schema is dropped and
recreated). Point ``MASP_TEST_POSTGRES_URL`` at one to enable it, e.g.:

    docker run -d --name masp-pg-inittest \
        -e POSTGRES_DB=masp -e POSTGRES_USER=masp -e POSTGRES_PASSWORD=testpw \
        -p 55432:5432 postgres:16-alpine
    MASP_TEST_POSTGRES_URL=postgresql://masp:testpw@127.0.0.1:55432/masp \
        python -m unittest tests.test_db_concurrent_init

Skipped when the variable is unset (e.g. the default SQLite CI run).
"""

import os
import threading
import unittest
from unittest.mock import patch

TEST_POSTGRES_URL = os.getenv("MASP_TEST_POSTGRES_URL", "").strip()

EXPECTED_TABLES = {
    "samples",
    "scan_batches",
    "scan_jobs",
    "engine_results",
    "scan_worker_events",
    "engine_instances",
    "scan_engine_jobs",
    "app_settings",
    "users",
    "auth_sessions",
}


def reset_public_schema(url: str) -> None:
    import psycopg

    with psycopg.connect(url, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
        connection.execute("CREATE SCHEMA public")


def public_tables(url: str) -> set[str]:
    import psycopg

    with psycopg.connect(url, autocommit=True) as connection:
        rows = connection.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
        ).fetchall()
    return {row[0] for row in rows}


@unittest.skipUnless(TEST_POSTGRES_URL, "set MASP_TEST_POSTGRES_URL to a throwaway PostgreSQL")
class ConcurrentInitDbTests(unittest.TestCase):
    def test_concurrent_init_on_fresh_database_all_succeed(self) -> None:
        from app import database

        reset_public_schema(TEST_POSTGRES_URL)

        session_count = 8
        start_barrier = threading.Barrier(session_count)
        errors: list[str] = []
        errors_lock = threading.Lock()

        def bootstrap() -> None:
            # Align all sessions to hit CREATE TABLE at the same moment.
            start_barrier.wait()
            try:
                database.init_db()
            except Exception as exc:  # pragma: no cover - failure path is the bug
                with errors_lock:
                    errors.append(repr(exc))

        # Pool disabled so every thread opens its own PostgreSQL session,
        # faithfully modelling independent processes (app + worker).
        with patch.object(database, "DATABASE_URL", TEST_POSTGRES_URL), patch.object(
            database, "DB_POOL_ENABLED", False
        ):
            threads = [threading.Thread(target=bootstrap) for _ in range(session_count)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(errors, [], f"concurrent init_db() raised: {errors}")
        self.assertTrue(
            EXPECTED_TABLES.issubset(public_tables(TEST_POSTGRES_URL)),
            "schema is incomplete after concurrent bootstrap",
        )

    def test_failed_bootstrap_does_not_leak_lock_into_pool(self) -> None:
        from app import database
        import psycopg

        if database.ConnectionPool is None:
            self.skipTest("psycopg_pool is not installed")

        database.close_pool()
        try:
            with patch.object(database, "DATABASE_URL", TEST_POSTGRES_URL), patch.object(
                database, "DB_POOL_ENABLED", True
            ), patch.object(database, "DB_POOL_MIN", 0), patch.object(database, "DB_POOL_MAX", 1):
                # Abort the schema transaction after taking the lock. A
                # session-level lock cannot be explicitly released while the
                # transaction is aborted and would poison this pooled session.
                with self.assertRaises(psycopg.Error):
                    with database.connect() as connection, database.postgres_schema_init_lock(
                        connection
                    ):
                        connection.execute("SELECT * FROM masp_intentionally_missing_relation")

                # Use an independent session: re-acquiring from the same pooled
                # session would hide a leaked session lock because PostgreSQL
                # advisory locks are re-entrant for their owner.
                with psycopg.connect(TEST_POSTGRES_URL, autocommit=True) as independent:
                    acquired = independent.execute(
                        "SELECT pg_try_advisory_lock(%s)",
                        (database.SCHEMA_INIT_ADVISORY_LOCK_KEY,),
                    ).fetchone()[0]
                    self.assertTrue(acquired, "failed bootstrap leaked its advisory lock")
                    independent.execute(
                        "SELECT pg_advisory_unlock(%s)",
                        (database.SCHEMA_INIT_ADVISORY_LOCK_KEY,),
                    )
        finally:
            database.close_pool()


if __name__ == "__main__":
    unittest.main()
