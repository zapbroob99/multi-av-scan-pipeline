"""Real-concurrency proof of the engine-job claim + fencing contracts.

Two workers race against the same database (own connections/threads):

- a single pending job is claimed by exactly one worker;
- a fenced result commit for one owner+generation is applied exactly once,
  even when two threads attempt it together, and writes exactly one result.

SQLite runs by default. Point MASP_TEST_POSTGRES_URL at a throwaway PostgreSQL
to prove the same on real PostgreSQL (SELECT ... FOR UPDATE SKIP LOCKED and the
fenced UPDATE), which the SQLite BEGIN IMMEDIATE path cannot exercise.
"""

import os
import tempfile
import threading
import time as _time
import unittest
from pathlib import Path

from app import database
from app.models import EngineResultInput, StoredSample

TEST_POSTGRES_URL = os.getenv("MASP_TEST_POSTGRES_URL", "").strip()


def _seed_scan_with_defender_job() -> tuple[int, int]:
    sample_id = database.create_sample(
        StoredSample(
            original_filename="s.bin",
            stored_filename="s.bin",
            storage_path="/tmp/s.bin",
            content_type="application/octet-stream",
            size_bytes=1,
            md5="0" * 32,
            sha1="0" * 40,
            sha256="1" * 64,
        )
    )
    if not any(
        e.adapter_key == "microsoft_defender" for e in database.list_engine_instances()
    ):
        database.create_engine_instance("microsoft_defender", "Microsoft Defender")
    scan_id = database.create_scan_job(
        sample_id, case_name="C", priority="Normal", note="", status="running"
    )
    database.create_scan_engine_jobs(scan_id, database.list_engine_instances())
    job = next(
        j
        for j in database.list_scan_engine_jobs(scan_id)
        if j.engine_key == "microsoft_defender"
    )
    return scan_id, job.id


def _result(name: str) -> EngineResultInput:
    return EngineResultInput(
        engine_name=name,
        status="completed",
        detected=False,
        severity="info",
        confidence=0,
        signature=None,
        raw_output="",
        duration_ms=1,
    )


class _FencingConcurrencyContract:
    def test_concurrent_claim_gives_the_job_to_exactly_one_worker(self) -> None:
        _seed_scan_with_defender_job()
        worker_count = 5
        barrier = threading.Barrier(worker_count)
        claimed: list[object] = []
        lock = threading.Lock()

        def run(index: int) -> None:
            barrier.wait()
            job = database.claim_next_scan_engine_job(
                {"microsoft_defender"}, f"w{index}", lease_seconds=30, now=1000
            )
            with lock:
                claimed.append(job)

        threads = [threading.Thread(target=run, args=(i,)) for i in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        winners = [job for job in claimed if job is not None]
        self.assertEqual(len(winners), 1, "exactly one worker must win the claim")

    def test_concurrent_finalization_claim_has_exactly_one_winner(self) -> None:
        scan_id, _job_id = _seed_scan_with_defender_job()
        worker_count = 5
        barrier = threading.Barrier(worker_count)
        generations: list[object] = []
        lock = threading.Lock()

        def run(index: int) -> None:
            barrier.wait()
            gen = database.claim_scan_finalization(
                scan_id, f"w{index}", lease_seconds=120, now=1000
            )
            with lock:
                generations.append(gen)

        threads = [threading.Thread(target=run, args=(i,)) for i in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        winners = [gen for gen in generations if gen is not None]
        self.assertEqual(len(winners), 1, "exactly one worker may finalize")

    def test_child_intake_and_lease_steal_are_serialized(self) -> None:
        # A finalizer registering a child races a second worker stealing the
        # (expired) finalization. FOR UPDATE / BEGIN IMMEDIATE make the ownership
        # check + child insert atomic, so the two never both win: the creator
        # either registers the child (it held the lock first) or is fenced out.
        scan_id, _job_id = _seed_scan_with_defender_job()
        generation = database.claim_scan_finalization(scan_id, "w-A", lease_seconds=120, now=1000)
        batch_id = database.create_scan_batch(
            source="api", original_filename="a.zip",
            archive_mode="lazy_extract_on_detection", total_items=1,
        )
        engines = database.list_engine_instances()
        sample = StoredSample(
            "m.bin", "m.bin", "/tmp/m.bin", "application/octet-stream", 1, "0" * 32, "0" * 40, "9" * 64
        )
        outcome: dict[str, object] = {}
        barrier = threading.Barrier(2)

        def creator() -> None:
            barrier.wait()
            try:
                outcome["child"] = database.create_archive_child(
                    parent_scan_id=scan_id,
                    parent_finalize_worker_id="w-A",
                    parent_finalize_generation=generation,
                    batch_id=batch_id,
                    sample=sample,
                    engines=engines,
                    case_name="C",
                    priority="Normal",
                    note="",
                    source="api",
                    relative_path="m.bin",
                    member_ordinal=0,
                )
            except database.StaleFinalizerError:
                outcome["stale"] = True

        def stealer() -> None:
            barrier.wait()
            database.claim_scan_finalization(scan_id, "w-B", lease_seconds=120, now=5000)

        threads = [threading.Thread(target=creator), threading.Thread(target=stealer)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        children = [
            c for c in database.list_scan_batch_scans(batch_id, limit=100) if c.scan_role == "child"
        ]
        created = outcome.get("child") is not None
        stale = bool(outcome.get("stale"))
        self.assertTrue(created ^ stale, f"exactly one outcome expected: {outcome}")
        self.assertEqual(len(children), 1 if created else 0)

    def test_for_update_blocks_lease_steal_during_child_intake(self) -> None:
        # Deterministic proof that the parent-row lock (FOR UPDATE on PostgreSQL,
        # BEGIN IMMEDIATE on SQLite) serializes child intake against a lease
        # steal. A test hook fires while create_archive_child holds the lock; the
        # steal is issued precisely then. It MUST block until the child commits,
        # so the creator (which held the lock first) always wins: the child is
        # registered and the stealer only afterwards observes the committed state
        # and takes the NEXT generation.
        scan_id, _job_id = _seed_scan_with_defender_job()
        generation = database.claim_scan_finalization(scan_id, "w-A", lease_seconds=120, now=1000)
        batch_id = database.create_scan_batch(
            source="api", original_filename="a.zip",
            archive_mode="lazy_extract_on_detection", total_items=1,
        )
        engines = database.list_engine_instances()
        sample = StoredSample(
            "m.bin", "m.bin", "/tmp/m.bin", "application/octet-stream", 1, "0" * 32, "0" * 40, "9" * 64
        )

        lock_held = threading.Event()
        steal_issued = threading.Event()
        outcome: dict[str, object] = {}

        def while_locked() -> None:
            lock_held.set()
            # Hold the parent lock until the steal has been issued (and is thus
            # blocking), then let create_archive_child commit.
            steal_issued.wait(timeout=10)

        def creator() -> None:
            database._ARCHIVE_CHILD_LOCK_TEST_HOOK = while_locked
            try:
                outcome["child"] = database.create_archive_child(
                    parent_scan_id=scan_id,
                    parent_finalize_worker_id="w-A",
                    parent_finalize_generation=generation,
                    batch_id=batch_id,
                    sample=sample,
                    engines=engines,
                    case_name="C",
                    priority="Normal",
                    note="",
                    source="api",
                    relative_path="m.bin",
                    member_ordinal=0,
                )
            except database.StaleFinalizerError:
                outcome["stale"] = True
            finally:
                database._ARCHIVE_CHILD_LOCK_TEST_HOOK = None

        def stealer() -> None:
            # Lease claimed at now=1000 (120s) is expired at now=5000, so this
            # would steal immediately if not blocked by the held lock.
            outcome["steal"] = database.claim_scan_finalization(
                scan_id, "w-B", lease_seconds=120, now=5000
            )

        creator_thread = threading.Thread(target=creator)
        creator_thread.start()
        self.assertTrue(lock_held.wait(timeout=10), "creator never acquired the lock")

        stealer_thread = threading.Thread(target=stealer)
        stealer_thread.start()
        # Give the steal a moment to reach (and block on) the locked row, then
        # release the creator.
        _time.sleep(0.3)
        steal_issued.set()

        creator_thread.join(timeout=30)
        stealer_thread.join(timeout=30)

        # Creator held the lock first -> child registered, not fenced.
        self.assertIsNotNone(outcome.get("child"), f"creator should have won: {outcome}")
        self.assertFalse(outcome.get("stale"))
        children = [
            c for c in database.list_scan_batch_scans(batch_id, limit=100) if c.scan_role == "child"
        ]
        self.assertEqual(len(children), 1)
        # Steal ran only AFTER the child committed, so it saw the committed state
        # and took the next generation (proof it was serialized behind the lock).
        self.assertEqual(outcome.get("steal"), generation + 1)

    def test_concurrent_commit_at_same_generation_writes_one_result(self) -> None:
        scan_id, _job_id = _seed_scan_with_defender_job()
        job = database.claim_next_scan_engine_job(
            {"microsoft_defender"}, "worker-A", lease_seconds=120, now=1000
        )
        assert job is not None

        outcomes: list[bool] = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def commit() -> None:
            barrier.wait()
            ok = database.commit_engine_job_result_if_owned(
                job_id=job.id,
                worker_id="worker-A",
                attempt_generation=job.attempt_count,
                result=_result(job.engine_name),
                terminal_status="completed",
            )
            with lock:
                outcomes.append(ok)

        threads = [threading.Thread(target=commit) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(sum(outcomes), 1, "exactly one commit must win")
        self.assertEqual(len(database.list_engine_results(scan_id)), 1)
        updated = database.get_scan_engine_job(job.id)
        assert updated is not None
        self.assertEqual(updated.status, "completed")


class SqliteFencingConcurrencyTests(_FencingConcurrencyContract, unittest.TestCase):
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


@unittest.skipUnless(TEST_POSTGRES_URL, "set MASP_TEST_POSTGRES_URL to a throwaway PostgreSQL")
class PostgresFencingConcurrencyTests(_FencingConcurrencyContract, unittest.TestCase):
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

    def tearDown(self) -> None:
        database.close_pool()
        database.DATABASE_URL = self.original_database_url
        database.DB_POOL_ENABLED = self.original_pool_enabled


if __name__ == "__main__":
    unittest.main()
