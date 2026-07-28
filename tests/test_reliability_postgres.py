"""PostgreSQL-gated failure-injection tests for the reliability package.

The SQLite counterparts live in tests/test_scan_intake.py and
tests/test_scan_engine_jobs.py. These re-check the same guarantees against real
PostgreSQL transaction semantics (atomic multi-row rollback, conditional
UPDATE rowcount, lease reset), which differ enough from SQLite to be worth
exercising before merge.

Point MASP_TEST_POSTGRES_URL at a throwaway PostgreSQL (its public schema is
dropped and recreated). Skipped when unset.
"""

import os
import unittest
from unittest.mock import patch

from app.models import StoredSample

TEST_POSTGRES_URL = os.getenv("MASP_TEST_POSTGRES_URL", "").strip()


def reset_public_schema(url: str) -> None:
    import psycopg

    with psycopg.connect(url, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
        connection.execute("CREATE SCHEMA public")


def _sample(sha256: str = "1" * 64) -> StoredSample:
    return StoredSample(
        original_filename="sample.bin",
        stored_filename=f"stored-{sha256[:8]}.bin",
        storage_path=f"/tmp/{sha256[:8]}.bin",
        content_type="application/octet-stream",
        size_bytes=10,
        md5="0" * 32,
        sha1="0" * 40,
        sha256=sha256,
    )


@unittest.skipUnless(TEST_POSTGRES_URL, "set MASP_TEST_POSTGRES_URL to a throwaway PostgreSQL")
class ReliabilityPostgresTests(unittest.TestCase):
    def setUp(self) -> None:
        from app import database

        reset_public_schema(TEST_POSTGRES_URL)
        self.database = database
        self.original_url = database.DATABASE_URL
        self.original_pool_enabled = database.DB_POOL_ENABLED
        database.close_pool()
        database.DATABASE_URL = TEST_POSTGRES_URL
        database.DB_POOL_ENABLED = False
        database.init_db()

    def tearDown(self) -> None:
        self.database.close_pool()
        self.database.DATABASE_URL = self.original_url
        self.database.DB_POOL_ENABLED = self.original_pool_enabled

    def _samples_count(self) -> int:
        with self.database.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()
        return int(row["n"] if isinstance(row, dict) else row[0])

    def test_atomic_intake_rolls_back_sample_and_scan_on_engine_job_failure(self) -> None:
        db = self.database
        db.create_engine_instance("static_metadata", "Static Metadata")
        engines = db.list_engine_instances()

        with patch("app.database._insert_engine_jobs", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                db.create_scan_intake(
                    sample=_sample(),
                    engines=engines,
                    case_name="Case",
                    priority="Normal",
                    note="",
                    source="api",
                    archive_mode="lazy_extract_on_detection",
                    archive_format=None,
                )

        # The whole transaction rolled back: no scan and no orphan sample row.
        self.assertEqual(db.count_scan_history(), 0)
        self.assertEqual(self._samples_count(), 0)

    def test_atomic_intake_persists_scan_and_engine_jobs(self) -> None:
        db = self.database
        db.create_engine_instance("static_metadata", "Static Metadata")
        engines = db.list_engine_instances()

        scan_id = db.create_scan_intake(
            sample=_sample(),
            engines=engines,
            case_name="Case",
            priority="Normal",
            note="",
            source="api",
            archive_mode="lazy_extract_on_detection",
            archive_format=None,
        )
        self.assertEqual(len(db.list_scan_engine_jobs(scan_id)), 1)
        self.assertEqual(self._samples_count(), 1)

    def test_transition_to_completed_is_idempotent(self) -> None:
        db = self.database
        db.create_engine_instance("static_metadata", "Static Metadata")
        scan_id = db.create_scan_intake(
            sample=_sample(),
            engines=db.list_engine_instances(),
            case_name="Case",
            priority="Normal",
            note="",
            source="api",
            archive_mode="lazy_extract_on_detection",
            archive_format=None,
        )
        self.assertTrue(db.transition_scan_to_completed(scan_id, "low", 10))
        self.assertFalse(db.transition_scan_to_completed(scan_id, "high", 99))
        scan = db.get_scan(scan_id)
        assert scan is not None
        self.assertEqual(scan.verdict, "low")

    def test_fenced_commit_derives_identity_and_rejects_conflict(self) -> None:
        db = self.database
        db.create_engine_instance("static_metadata", "Static Metadata")
        scan_id = db.create_scan_intake(
            sample=_sample(),
            engines=db.list_engine_instances(),
            case_name="C",
            priority="Normal",
            note="",
            source="api",
            archive_mode="lazy_extract_on_detection",
            archive_format=None,
        )
        db.update_scan_status(scan_id, "running")
        job = db.claim_next_scan_engine_job(
            {"static_metadata"}, "w-A", lease_seconds=120, now=1000
        )
        assert job is not None

        def result(name: str, status: str = "completed"):
            from app.models import EngineResultInput

            return EngineResultInput(
                engine_name=name,
                status=status,
                detected=False,
                severity="info",
                confidence=0,
                signature=None,
                raw_output="",
                duration_ms=1,
            )

        # Cross-engine result is rejected (identity derived from the job row).
        with self.assertRaises(ValueError):
            db.commit_engine_job_result_if_owned(
                job_id=job.id,
                worker_id="w-A",
                attempt_generation=job.attempt_count,
                result=result("Other Engine"),
                terminal_status="completed",
            )
        # Wrong generation terminal is a no-op.
        self.assertFalse(
            db.mark_scan_engine_job_terminal_if_owned(
                job.id, "w-A", job.attempt_count + 1, "failed"
            )
        )
        # Owner commits exactly one result.
        self.assertTrue(
            db.commit_engine_job_result_if_owned(
                job_id=job.id,
                worker_id="w-A",
                attempt_generation=job.attempt_count,
                result=result(job.engine_name),
                terminal_status="completed",
            )
        )
        self.assertEqual(len(db.list_engine_results(scan_id)), 1)

    def test_recover_resets_expired_lease_but_not_live_work(self) -> None:
        db = self.database
        db.create_engine_instance("static_metadata", "Static Metadata")
        scan_id = db.create_scan_intake(
            sample=_sample(),
            engines=db.list_engine_instances(),
            case_name="Case",
            priority="Normal",
            note="",
            source="api",
            archive_mode="lazy_extract_on_detection",
            archive_format=None,
        )
        db.update_scan_status(scan_id, "running")
        claimed = db.claim_next_scan_engine_job(
            {"static_metadata"}, "worker-dead", lease_seconds=30, now=1000
        )
        assert claimed is not None

        # Still-valid lease: untouched.
        self.assertEqual(db.recover_running_scan_jobs(now=1010, max_attempts=5), 0)
        # Expired lease: reset to pending.
        self.assertEqual(db.recover_running_scan_jobs(now=2000, max_attempts=5), 1)
        job = db.get_scan_engine_job(claimed.id)
        assert job is not None
        self.assertEqual(job.status, "pending")


if __name__ == "__main__":
    unittest.main()
