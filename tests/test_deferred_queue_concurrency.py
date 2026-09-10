"""Concurrent claim coverage for deferred intake and notification delivery.

SQLite runs by default. Set ``MASP_TEST_POSTGRES_URL`` to a disposable
PostgreSQL database to exercise the production ``FOR UPDATE SKIP LOCKED`` path.
The PostgreSQL fixture drops and recreates the public schema.
"""

import os
import tempfile
import threading
import unittest
from pathlib import Path

from app import database
from app.models import StoredSample


TEST_POSTGRES_URL = os.getenv("MASP_TEST_POSTGRES_URL", "").strip()


class _DeferredQueueConcurrencyContract:
    worker_count = 5

    def _seed_queue_records(self) -> None:
        engine_id = database.create_engine_instance("static_metadata", "Metadata")
        self.client_id, self.profile_id, _ = database.create_service_client_bundle(
            client_key="drive",
            display_name="Drive",
            profile_name="Deferred",
            engine_instance_ids=[engine_id],
            credential_label="test",
            token_hash="a" * 64,
            token_prefix="aaaaaaaa",
        )

    def _race(self, claim):
        barrier = threading.Barrier(self.worker_count)
        outcomes: list[object] = []
        failures: list[BaseException] = []
        lock = threading.Lock()

        def run(index: int) -> None:
            try:
                barrier.wait()
                outcome = claim(index)
                with lock:
                    outcomes.append(outcome)
            except Exception as exc:
                with lock:
                    failures.append(exc)

        threads = [
            threading.Thread(target=run, args=(index,))
            for index in range(self.worker_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        return outcomes

    def test_concurrent_deferred_claim_has_exactly_one_winner(self) -> None:
        database.create_deferred_scan_submission(
            service_client_id=self.client_id,
            scan_profile_id=self.profile_id,
            client_request_id="drive-1",
            backend_key="drive",
            object_id="folder/sample.bin",
            original_filename="sample.bin",
            content_type="application/octet-stream",
            expected_size_bytes=7,
            expected_sha256=None,
            archive_mode="container",
            case_name="Drive",
            priority="Normal",
            note="",
            profile_snapshot_json="{}",
        )

        outcomes = self._race(
            lambda index: database.claim_next_deferred_scan_submission(
                {"drive"}, f"intake-{index}", lease_seconds=60, now=100
            )
        )

        winners = [record for record in outcomes if record is not None]
        self.assertEqual(len(winners), 1, "exactly one intake worker must win")

    def test_concurrent_outbox_claim_has_exactly_one_winner(self) -> None:
        sample_id = database.create_sample(
            StoredSample(
                original_filename="sample.bin",
                stored_filename="sample.bin",
                storage_path="/tmp/sample.bin",
                content_type="application/octet-stream",
                size_bytes=7,
                md5="0" * 32,
                sha1="0" * 40,
                sha256="1" * 64,
            )
        )
        scan_id = database.create_scan_job(
            sample_id,
            case_name="Drive",
            priority="Normal",
            note="",
            service_client_id=self.client_id,
            scan_profile_id=self.profile_id,
        )
        with database.connect() as connection:
            connection.execute(
                """
                INSERT INTO notification_outbox (
                    scan_job_id, service_client_id, event_type,
                    idempotency_key, payload_json
                ) VALUES (?, ?, 'malware.detected', ?, '{}')
                """,
                (scan_id, self.client_id, f"scan:{scan_id}:malware.detected"),
            )

        outcomes = self._race(
            lambda index: database.claim_next_notification_outbox(
                f"notify-{index}", lease_seconds=60, now=100
            )
        )

        winners = [record for record in outcomes if record is not None]
        self.assertEqual(len(winners), 1, "exactly one notification worker must win")


class SqliteDeferredQueueConcurrencyTests(
    _DeferredQueueConcurrencyContract, unittest.TestCase
):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "deferred-concurrency.db"
        database.DATABASE_URL = ""
        database.init_db()
        self._seed_queue_records()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()


@unittest.skipUnless(
    TEST_POSTGRES_URL, "set MASP_TEST_POSTGRES_URL to a throwaway PostgreSQL"
)
class PostgresDeferredQueueConcurrencyTests(
    _DeferredQueueConcurrencyContract, unittest.TestCase
):
    def setUp(self) -> None:
        import psycopg

        with psycopg.connect(TEST_POSTGRES_URL, autocommit=True) as connection:
            connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
            connection.execute("CREATE SCHEMA public")
        self.original_database_url = database.DATABASE_URL
        self.original_pool_enabled = database.DB_POOL_ENABLED
        database.close_pool()
        database.DATABASE_URL = TEST_POSTGRES_URL
        database.DB_POOL_ENABLED = False
        database.init_db()
        self._seed_queue_records()

    def tearDown(self) -> None:
        database.close_pool()
        database.DATABASE_URL = self.original_database_url
        database.DB_POOL_ENABLED = self.original_pool_enabled


if __name__ == "__main__":
    unittest.main()
