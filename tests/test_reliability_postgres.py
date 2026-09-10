"""PostgreSQL-gated failure-injection tests for the reliability package.

The SQLite counterparts live in tests/test_scan_intake.py and
tests/test_scan_engine_jobs.py. These re-check the same guarantees against real
PostgreSQL transaction semantics (atomic multi-row rollback, conditional
UPDATE rowcount, lease reset), which differ enough from SQLite to be worth
exercising before merge.

Point MASP_TEST_POSTGRES_URL at a throwaway PostgreSQL (its public schema is
dropped and recreated). Skipped when unset.
"""

import json
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

    def test_manual_retry_serializes_delete_and_preserves_failed_transaction(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        from app.models import EngineResultInput
        db = self.database
        engine_id = db.create_engine_instance('static_metadata', 'Metadata')
        engine = db.get_engine_instance_by_id(engine_id)
        scan = db.create_scan_job(db.create_sample(_sample()), '', 'Normal', '', status='completed')
        result = db.create_engine_result(scan, EngineResultInput('Metadata', 'completed', False, 'info', 0, None, '', 0))
        with patch.object(db, '_insert_engine_jobs', side_effect=RuntimeError('rollback')):
            with self.assertRaises(RuntimeError):
                db.retry_scan_job(scan, engines=[engine])
        self.assertEqual(db.list_engine_results(scan)[0].id, result)
        self.assertEqual(db.get_scan(scan).status, 'completed')
        inserted, release, deleting = Event(), Event(), Event()
        original = db._insert_engine_jobs
        def hold(connection, scan_id, engines):
            count = original(connection, scan_id, engines)
            inserted.set()
            if not release.wait(10):
                raise AssertionError('Retry lock test timed out')
            return count
        def delete():
            deleting.set()
            return db.delete_scan(scan, source='manual', expected_attempt=0, expected_job_revision=0)
        with ThreadPoolExecutor(max_workers=2) as pool, patch.object(db, '_insert_engine_jobs', side_effect=hold):
            retried = pool.submit(db.retry_scan_job, scan, engines=[engine], source='manual', expected_attempt=0)
            try:
                self.assertTrue(inserted.wait(5))
                deleted = pool.submit(delete)
                self.assertTrue(deleting.wait(5))
                self.assertFalse(deleted.done())
            finally:
                release.set()
            self.assertTrue(retried.result(timeout=10))
            self.assertIsNone(deleted.result(timeout=10))
        db.update_scan_status(scan, 'failed')
        self.assertFalse(db.retry_scan_job(scan, engines=[engine], expected_attempt=0, expected_job_revision=0))
        self.assertIsNone(db.delete_scan(scan, expected_attempt=0, expected_job_revision=0))

    def test_browser_statement_and_write_lock_budgets_are_local(self):
        from concurrent.futures import ThreadPoolExecutor
        from app.services.browser_db_budget import apply_read_budget
        db = self.database
        with patch.dict('os.environ', {'MASP_UI_READ_TIMEOUT_MS': '100'}):
            with db.connect() as connection:
                apply_read_budget(connection)
                self.assertEqual(connection.execute('SHOW plan_cache_mode').fetchone()['plan_cache_mode'], 'force_custom_plan')
                with self.assertRaises(db.psycopg.errors.QueryCanceled):
                    connection.execute('SELECT pg_sleep(0.25)')
        # SET LOCAL must not poison the next transaction/pooled caller.
        with db.connect() as connection:
            self.assertEqual(connection.execute('SHOW statement_timeout').fetchone()['statement_timeout'], '0')
            self.assertEqual(connection.execute('SHOW plan_cache_mode').fetchone()['plan_cache_mode'], 'auto')
        scan = db.create_scan_job(db.create_sample(_sample()), '', 'Normal', '', status='completed')
        with db.connect() as holder:
            holder.execute('SELECT id FROM scan_jobs WHERE id = ? FOR UPDATE', (scan,))
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(db.delete_scan, scan, source='manual', lock_timeout_ms=100)
                with self.assertRaises(db.psycopg.errors.LockNotAvailable):
                    future.result(timeout=5)
            self.assertIsNotNone(db.get_scan(scan))

    def test_dashboard_manual_scope_seek_filters_and_aggregate(self) -> None:
        from app.services import dashboard_read
        db = self.database
        dashboard_read._summary_cache = None
        sample_id = db.create_sample(_sample())
        first = db.create_scan_job(sample_id, 'Case%_!', 'normal', '', status='completed', verdict='high')
        second = db.create_scan_job(sample_id, '', 'normal', '', status='finalizing')
        db.create_scan_job(sample_id, '', 'normal', '', source='api')
        db.create_scan_job(sample_id, '', 'normal', '', scan_role='child')
        page = dashboard_read.scan_page(limit=1, before=None, query='', status='all', risk='all')
        self.assertEqual(page.next_before, second)
        older = dashboard_read.scan_page(limit=1, before=second, query='%_!', status='completed', risk='high')
        self.assertEqual([scan.id for scan in older.items], [first])
        summary = dashboard_read.summary()
        self.assertEqual((summary.total, summary.active, summary.high_risk), (2, 1, 1))

    def test_manual_report_repeatable_read_and_scoped_technical_projection(self) -> None:
        from app.models import EngineResultInput
        from app.services import scan_management, scan_report_read
        db = self.database
        sample = db.create_sample(_sample())
        scan = db.create_scan_job(sample, 'Case', 'Normal', '', status='completed', verdict='info', risk_score=0,
            profile_snapshot_json='{"engines":[{"name":"Historic AV","detection":true,"required":true}]}')
        result = db.create_engine_result(scan, EngineResultInput('Historic AV', 'completed', False, 'info', 100, None,
            'x' * 20000, 10))
        payload = scan_report_read.report(scan)
        self.assertEqual(payload.decision.action, 'allow')
        self.assertEqual(payload.completed_engines, 1)
        self.assertEqual(scan_report_read.technical_details(scan, result).truncated, ['raw_output'])
        exported = json.loads(scan_management.full_export(scan, 'json').content)
        self.assertEqual(exported['summary']['decision']['action'], 'allow')
        self.assertEqual(exported['engine_results'][0]['raw_output'], 'x' * 20000)

    def test_archive_child_scope_literal_search_and_keyset(self) -> None:
        from fastapi import HTTPException
        from app.services import archive_read, batch_read
        db = self.database
        sample = db.create_sample(_sample())
        batch = db.create_scan_batch(source='manual', original_filename='outer.zip', archive_mode='lazy_extract_on_detection')
        parent = db.create_scan_job(sample, '', 'normal', '', batch_id=batch, scan_role='container')
        def child(**overrides):
            args = dict(parent_scan_id=parent, batch_id=batch, scan_role='child', relative_path='literal%_!.bin')
            args.update(overrides)
            return db.create_scan_job(sample, '', 'normal', '', **args)
        first, second = child(), child()
        child(source='api')
        child(batch_id=None)
        nested = child(parent_scan_id=first)
        page = archive_read.children(parent, limit=1, after=None, attempt=None, query='%_!', status='active')
        self.assertEqual(page.next_after, first)
        self.assertTrue(page.items[0].has_children)
        page = archive_read.children(parent, limit=1, after=first, attempt=page.attempt_count, query='%_!', status='all')
        self.assertEqual([row.id for row in page.items], [second])
        self.assertFalse(page.items[0].has_children)
        batch_page = batch_read.page(batch, limit=2, after_id=None, after_created=None)
        self.assertEqual([row.id for row in batch_page.items], [parent, first])
        batch_page = batch_read.page(batch, limit=2, after_id=batch_page.next_after_id,
                                     after_created=batch_page.next_after_created)
        self.assertEqual([row.id for row in batch_page.items], [second, nested])
        with db.connect() as connection:
            connection.execute('UPDATE scan_jobs SET attempt_count = attempt_count + 1 WHERE id = ?', (parent,))
        with self.assertRaises(HTTPException) as error:
            archive_read.children(parent, limit=1, after=first, attempt=page.attempt_count, query='', status='all')
        self.assertEqual(error.exception.status_code, 409)

    def test_int4_sample_size_upgrade_preserves_data_and_accepts_large_metadata(self) -> None:
        from dataclasses import replace

        db = self.database
        sample_id = db.create_sample(_sample())
        with db.connect() as connection:
            connection.execute("ALTER TABLE samples ALTER COLUMN size_bytes TYPE INTEGER")
        db.init_db()
        db.init_db()  # Already-upgraded startup is idempotent.
        with db.connect() as connection:
            old = connection.execute("SELECT size_bytes FROM samples WHERE id = ?", (sample_id,)).fetchone()
            kind = connection.execute(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = 'samples' AND column_name = 'size_bytes'"
            ).fetchone()
        self.assertEqual(old["size_bytes"], 10)
        self.assertEqual(kind["data_type"], "bigint")
        large_id = db.create_sample(replace(_sample("2" * 64), size_bytes=50 * 1024**3))
        with db.connect() as connection:
            large = connection.execute("SELECT size_bytes FROM samples WHERE id = ?", (large_id,)).fetchone()
        self.assertEqual(large["size_bytes"], 50 * 1024**3)

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
