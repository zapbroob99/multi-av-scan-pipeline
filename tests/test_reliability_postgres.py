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

    def test_browser_worker_projection_handles_metadata_and_deleted_cursor(self):
        from app.services import worker_admin
        db = self.database
        for node in ('node-a', 'node-b', 'node-c'):
            db.upsert_worker_node_heartbeat(node_id=node, display_name='Worker', hostname='host',
                platform='windows', agent_version='1', labels_json='{"site":"lab"}', capacity=2,
                advertised_engine_keys_json='["microsoft_defender"]', runtime_state='idle',
                active_scan_id=None, process_id=1, last_heartbeat_at=1)
        with db.connect() as connection:
            connection.execute('UPDATE worker_nodes SET labels_json = ? WHERE node_id = ?', ('x' * 10000, 'node-b'))
        first = worker_admin.page(limit=1, after=None)
        self.assertEqual(first.next_after, 'node-a')
        second = worker_admin.page(limit=1, after=first.next_after)
        self.assertTrue(second.items[0].metadata_incomplete)
        self.assertFalse(second.items[0].online)
        self.assertEqual(second.items[0].lifecycle_state, 'active')
        with db.connect() as connection:
            connection.execute('DELETE FROM worker_nodes WHERE node_id = ?', ('node-b',))
        last = worker_admin.page(limit=1, after=second.next_after)
        self.assertEqual([node.node_id for node in last.items], ['node-c'])
        self.assertIsNone(last.next_after)

    def test_browser_pool_projection_and_assignment_delete_protection(self):
        from app.services import worker_admin
        db = self.database
        first = db.create_worker_pool('First', '{"site":"lab"}')
        second = db.create_worker_pool('Second', 'x' * 10000)
        engine = db.create_engine_instance('static_metadata', 'Pool engine')
        db.set_engine_instance_worker_pool(engine, first)
        page = worker_admin.pool_page(limit=1, after=None)
        self.assertEqual(page.next_after, first)
        self.assertTrue(page.items[0].has_assignments)
        with self.assertRaises(ValueError):
            db.delete_worker_pool(first)
        db.set_engine_instance_worker_pool(engine, None)
        self.assertTrue(db.delete_worker_pool(first))
        page = worker_admin.pool_page(limit=1, after=first)
        self.assertEqual(page.items[0].id, second)
        self.assertTrue(page.items[0].metadata_incomplete)
        self.assertEqual(page.items[0].selector, '')
        self.assertIsNone(page.next_after)

    def test_active_queue_projection_and_upgrade_index(self):
        from app.services import queue_read
        db = self.database
        sample = db.create_sample(_sample())
        first = db.create_scan_job(sample, '', 'Normal', '', source='api', status='queued')
        second = db.create_scan_job(sample, '', 'Normal', '', source='icap', status='finalizing')
        db.create_scan_job(sample, '', 'Normal', '', status='completed')
        page = queue_read.page(limit=1, after=None)
        self.assertEqual(page.next_after, first)
        self.assertEqual(page.items[0].source, 'api')
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET status = 'completed' WHERE id = ?", (first,))
            connection.execute('DROP INDEX idx_scan_jobs_active_seek')
        db.init_db()
        self.assertEqual(queue_read.page(limit=1, after=first).items[0].id, second)
        with db.connect() as connection:
            connection.execute('SET LOCAL enable_seqscan = off')
            plan = connection.execute("EXPLAIN SELECT id FROM scan_jobs WHERE status IN ('queued', 'running', 'finalizing') AND id > ? ORDER BY id LIMIT ?", (first, 21)).fetchall()
        self.assertIn('idx_scan_jobs_active_seek', str(plan))

    def test_system_aggregates_use_postgres_types_and_bounded_metric_groups(self):
        from app.services import system_read
        from app.models import EngineResultInput
        db = self.database
        system_read._summary_cache = system_read._metrics_cache = None
        scan = db.create_scan_job(db.create_sample(_sample()), '', 'Normal', '', source='icap', status='finalizing')
        db.create_engine_result(scan, EngineResultInput('Historical name', 'completed', True, 'high', 80, None, 'PRIVATE', 42))
        db.create_engine_result(scan, EngineResultInput('Another name', 'skipped', False, 'info', 0, None, '', 0))
        summary = system_read.summary()
        self.assertEqual((summary.total, summary.finalizing), (1, 1))
        first = system_read.metrics(limit=1, after=None)
        self.assertEqual((first.items[0].total, first.items[0].detections), (1, 1))
        self.assertEqual(first.items[0].avg_duration_ms, 42)
        second = system_read.metrics(limit=1, after=first.next_after)
        self.assertEqual(second.items[0].engine_name, 'Another name')
        self.assertIsNone(second.next_after)

    def test_retention_rechecks_age_after_concurrent_update(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        from app.services import retention_admin
        db = self.database
        scan = db.create_scan_job(db.create_sample(_sample()), '', 'Normal', '', source='api', status='completed')
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET created_at = '2000-01-01' WHERE id = ?", (scan,))
        with patch.dict('os.environ', {'MASP_RETENTION_DAYS': '30', 'MASP_RETENTION_BATCH_SIZE': '20'}):
            page = retention_admin.preview(None)
            self.assertEqual([row.scan_id for row in page.items], [scan])
            started = Event()
            def remove():
                started.set()
                return db.delete_scan(scan, expected_attempt=0, expected_job_revision=0,
                                      protect_children=True, created_before=page.cutoff)
            with ThreadPoolExecutor(max_workers=1) as pool:
                with db.connect() as holder:
                    holder.execute('UPDATE scan_jobs SET created_at = CURRENT_TIMESTAMP WHERE id = ?', (scan,))
                    future = pool.submit(remove)
                    self.assertTrue(started.wait(5))
                self.assertIsNone(future.result(timeout=10))
            self.assertIsNotNone(db.get_scan(scan))
            self.assertEqual(retention_admin.preview(None).items, [])

    def test_browser_scan_policy_atomic_save_and_clear_on_postgres(self):
        from app.services import scan_policy_admin, scan_policy
        db = self.database
        body = scan_policy_admin.ScanPolicyBody(api_max_wait_seconds='300', api_retry_after_seconds='1', upload_max_bytes=str(5 * 1024**3))
        scan_policy_admin.save(body)
        self.assertEqual([field.value for field in scan_policy_admin.read().fields], [300, 1, 5 * 1024**3])
        self.assertEqual(scan_policy.resolve_int('upload_max_bytes'), 5 * 1024**3)
        scan_policy_admin.save(scan_policy_admin.ScanPolicyBody(**{key: '' for key in body.model_dump()}))
        self.assertIsNone(db.get_setting('scan_policy.api_max_wait_seconds'))
        self.assertEqual([field.override_raw for field in scan_policy_admin.read().fields], ['', '', ''])

    def test_browser_service_client_pages_and_scoped_updates(self):
        from app.services import client_admin
        from fastapi import HTTPException
        db = self.database
        managed = db.create_service_client('legacy-default', 'Managed')
        client = db.create_service_client('api-one', 'API One')
        first = client_admin.page(1, None)
        self.assertTrue(first.items[0].managed)
        second = client_admin.page(1, first.next_after)
        self.assertEqual(second.items[0].id, client)
        self.assertIsNone(second.next_after)
        body = client_admin.ServiceClientUpdate(display_name=' Updated ', enabled=False)
        client_admin.update(client, body)
        self.assertFalse(db.get_service_client(client).enabled)
        with self.assertRaises(HTTPException):
            client_admin.update(managed, body)
        self.assertTrue(db.get_service_client(managed).enabled)

    def test_profile_routing_serializes_competing_fenced_updates(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from app.services import profile_admin
        db = self.database
        client = db.create_service_client('routing', 'Routing')
        engines = [db.create_engine_instance('static_metadata', f'Metadata {n}') for n in range(3)]
        profile = db.create_scan_profile(client, 'Default', engine_instance_ids=[engines[0]], is_default=True)
        self.assertEqual(profile_admin.page(client, None).items[0].engine_ids, [engines[0]])
        barrier = Barrier(2)
        def save(engine):
            barrier.wait(5)
            try:
                db.set_scan_profile_engines(profile, [engine], client_id=client, expected_engine_ids=[engines[0]], lock_timeout_ms=5000)
                return 'saved'
            except ValueError:
                return 'stale'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(save, engines[1:]))
        self.assertEqual(sorted(results), ['saved', 'stale'])
        self.assertEqual(len(db.list_scan_profile_engines(profile)), 1)

    def test_browser_credentials_atomic_bundle_and_scoped_revoke(self):
        from app.services import credential_admin as service
        from fastapi import HTTPException
        db = self.database
        engine = db.create_engine_instance('static_metadata', 'Credential engine')
        body = service.ClientCreateBody(client_key='credential-test', display_name='Client',
            profile_name='Default', engine_ids=[engine], credential_label='Initial', api_token='x' * 32)
        created = service.create_client(body)
        with self.assertRaises(HTTPException) as duplicate:
            service.create_client(body.model_copy(update={'client_key': 'rollback-test'}))
        self.assertEqual(duplicate.exception.status_code, 409)
        self.assertIsNone(db.get_service_client_by_key('rollback-test'))
        page = service.page(created.client_id, None)
        self.assertEqual(page.items[0].id, created.credential_id)
        self.assertIsNone(page.items[0].revoked_at)
        with self.assertRaises(HTTPException):
            service.revoke(created.client_id + 1000, created.credential_id)
        service.revoke(created.client_id, created.credential_id)
        self.assertIsNotNone(service.page(created.client_id, None).items[0].revoked_at)

    def test_browser_ledger_scoped_seek_projection_and_indexes(self):
        from app.services import ledger_read
        db = self.database
        client = db.create_service_client('ledger-test', 'Ledger client')
        sample = db.create_sample(_sample())
        api = db.create_scan_job(sample, 'Case', 'normal', '', source='api', service_client_id=client)
        icap = db.create_scan_job(sample, 'Case', 'normal', '', source='icap')
        db.create_scan_job(sample, 'Case', 'normal', '', source='manual')
        db.create_scan_job(sample, 'Case', 'normal', '', source='api', scan_role='child')
        args = dict(limit=1, before=None, query='', source='all', status='all', risk='all', client_id=None, unassigned=False)
        page = ledger_read.page(**args)
        self.assertEqual(page.items[0].id, icap)
        self.assertEqual(page.next_before, icap)
        self.assertEqual(ledger_read.page(**{**args, 'client_id': client}).items[0].id, api)
        self.assertEqual(ledger_read.page(**{**args, 'before': icap}).items[0].client_name, 'Ledger client')
        with db.connect() as connection:
            indexes = {row['indexname'] for row in connection.execute("SELECT indexname FROM pg_indexes WHERE tablename = 'scan_jobs'").fetchall()}
        self.assertIn('idx_scan_jobs_ledger_seek', indexes)
        self.assertIn('idx_scan_jobs_ledger_client_seek', indexes)

    def test_automation_reads_scoped_batch_and_fenced_delete(self):
        from app.services import batch_read, scan_report_read, scan_management
        from fastapi import HTTPException
        db = self.database
        batch = db.create_scan_batch(source='icap', original_filename='auto.zip', archive_mode='lazy_extract_on_detection')
        sample = db.create_sample(_sample())
        scan = db.create_scan_job(sample, 'Case', 'normal', '', source='icap', batch_id=batch, status='completed', profile_snapshot_json='{"engines":[]}')
        page = batch_read.page(batch, limit=1, after_id=None, after_created=None, automation=True)
        self.assertEqual(page.items[0].id, scan)
        self.assertIsNone(page.service_client_id)
        self.assertEqual(scan_report_read.report(scan, automation=True).source, 'icap')
        with self.assertRaises(HTTPException):
            scan_report_read.report(scan)
        with self.assertRaises(HTTPException) as stale:
            scan_management.delete(scan, 1, 0, automation=True)
        self.assertEqual(stale.exception.status_code, 409)
        with patch.object(scan_management, 'delete_sample_file', return_value=True):
            self.assertTrue(scan_management.delete(scan, 0, 0, automation=True).sample_removed)
        self.assertIsNone(db.get_scan(scan))

    def test_browser_user_creation_concurrent_duplicate_is_atomic(self):
        from concurrent.futures import ThreadPoolExecutor
        from fastapi import HTTPException
        from app.services import user_admin
        body = user_admin.CreateUserBody(username='same-user', role='analyst', password='test-password')
        def create():
            try:
                return user_admin.create(body).user_id
            except HTTPException as error:
                return error.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: create(), range(2)))
        self.assertEqual(outcomes.count(409), 1)
        page = user_admin.page(None)
        self.assertEqual([user.username for user in page.items], ['same-user'])
        self.assertNotIn('password', page.model_dump_json())

    def test_automation_bulk_delete_keeps_row_fences_and_partial_commits(self):
        from app.services import ledger_read, scan_management
        db = self.database
        good = db.create_scan_job(db.create_sample(_sample()), '', 'normal', '', source='api', status='completed')
        stale = db.create_scan_job(db.create_sample(_sample()), '', 'normal', '', source='icap', status='completed')
        page = ledger_read.page(limit=20, before=None, query='', source='all', status='all', risk='all', client_id=None, unassigned=False)
        candidates = [scan_management.BulkDeleteCandidate(scan_id=row.id, attempt=row.attempt_count, job_revision=row.job_revision) for row in page.items]
        with db.connect() as connection:
            connection.execute('UPDATE scan_jobs SET attempt_count = 1 WHERE id = ?', (stale,))
        with patch.object(scan_management, 'delete_sample_file', return_value=False):
            result = scan_management.bulk_delete(candidates, automation=True)
        self.assertEqual(result.deleted_ids, [good])
        self.assertEqual(result.blocked_ids, [stale])
        self.assertEqual(result.cleanup_failed_ids, [good])
        self.assertIsNone(db.get_scan(good))
        self.assertIsNotNone(db.get_scan(stale))

    def test_automation_archive_nullable_owner_and_consistent_nested_probe(self):
        from app.services import archive_read
        db = self.database
        batch = db.create_scan_batch(source='icap', original_filename='archive.zip', archive_mode='none')
        parent = db.create_scan_job(db.create_sample(_sample()), '', 'normal', '', source='icap', batch_id=batch)
        child = db.create_scan_job(db.create_sample(_sample()), '', 'normal', '', source='icap', batch_id=batch, parent_scan_id=parent, scan_role='child')
        nested = db.create_scan_job(db.create_sample(_sample()), '', 'normal', '', source='icap', batch_id=batch, parent_scan_id=child, scan_role='child')
        original = archive_read.child_presence_statement
        def update_then_probe(rows, **kwargs):
            with db.connect() as writer:
                writer.execute("UPDATE scan_jobs SET source = 'manual' WHERE id = ?", (nested,))
            return original(rows, **kwargs)
        with patch.object(archive_read, 'child_presence_statement', side_effect=update_then_probe):
            page = archive_read.children(parent, limit=20, after=None, attempt=None, query='', status='all', automation=True)
        self.assertEqual([row.id for row in page.items], [child])
        self.assertTrue(page.items[0].has_children)
        refreshed = archive_read.children(parent, limit=20, after=None, attempt=None, query='', status='all', automation=True)
        self.assertFalse(refreshed.items[0].has_children)

    def test_batch_json_result_hydration_keeps_membership_snapshot(self):
        from app.services import batch_payload
        db = self.database
        batch = db.create_scan_batch(source='api', original_filename='batch.zip', archive_mode='none')
        scan = db.create_scan_job(db.create_sample(_sample()), '', 'normal', '', source='api',
                                 status='completed', batch_id=batch, profile_snapshot_json='{"engines":[]}')
        with db.connect() as connection:
            connection.execute("UPDATE scan_batches SET status = 'completed' WHERE id = ?", (batch,))
        original = batch_payload._full_export_rows
        def update_then_hydrate(scan_id, **kwargs):
            with db.connect() as writer:
                writer.execute("UPDATE scan_jobs SET status = 'queued', batch_id = NULL WHERE id = ?", (scan,))
            return original(scan_id, **kwargs)
        with patch.object(batch_payload, '_full_export_rows', side_effect=update_then_hydrate):
            payload = json.loads(batch_payload.preview(batch, 'result', 'http://test').content)
        self.assertEqual(payload['scans'][0]['result']['scan']['status'], 'completed')
        self.assertEqual(payload['scans'][0]['result']['scan']['batch']['id'], batch)
        self.assertIsNone(db.get_scan(scan).batch_id)

    def test_automation_status_keeps_queue_and_scan_in_one_snapshot(self):
        from app.services import automation_payload
        db = self.database
        scan = db.create_scan_job(db.create_sample(_sample()), '', 'normal', '', source='api',
                                 status='queued', profile_snapshot_json='{"engines":[]}')
        original = db.get_queue_metrics
        def update_then_read(*, connection):
            budget = connection.execute("SHOW statement_timeout").fetchone()
            self.assertNotEqual(str(next(iter(budget.values()))), '0')
            with db.connect() as writer:
                writer.execute("UPDATE scan_jobs SET status = 'completed' WHERE id = ?", (scan,))
            return original(connection=connection)
        with patch.object(db, 'get_queue_metrics', side_effect=update_then_read):
            payload = json.loads(automation_payload.status_preview(scan, 'http://test').content)
        self.assertEqual(payload['scan']['status'], 'queued')
        self.assertFalse(payload['result_ready'])
        self.assertEqual(payload['queue']['queued'], 1)
        self.assertEqual(payload['queue']['completed'], 0)
        self.assertEqual(payload['queue']['position'], 1)
        self.assertEqual(db.get_scan(scan).status, 'completed')

    def test_automation_exports_keep_source_snapshot_and_bounds(self):
        from app.services import scan_management
        from app.models import EngineResultInput
        from fastapi import HTTPException
        db = self.database
        sample = db.create_sample(_sample())
        scan = db.create_scan_job(sample, 'Case', 'normal', '', source='api', status='completed', profile_snapshot_json='{"engines":[]}')
        db.create_engine_result(scan, EngineResultInput('Metadata', 'completed', False, 'info', 0, None, 'output', 12))
        result = scan_management.full_export(scan, 'json', automation=True)
        self.assertEqual(json.loads(result.content)['scan']['source'], 'api')
        self.assertEqual(json.loads(scan_management.summary_export(scan, 'json', automation=True).content)['report']['source'], 'api')
        with self.assertRaises(HTTPException) as wrong_source:
            scan_management.full_export(scan, 'json')
        self.assertEqual(wrong_source.exception.status_code, 404)
        with db.connect() as connection:
            connection.execute('UPDATE engine_results SET raw_output = ? WHERE scan_job_id = ?', ('x' * (2 * 1024 * 1024 + 1), scan))
        with self.assertRaises(HTTPException) as oversized:
            scan_management.full_export(scan, 'json', automation=True)
        self.assertEqual(oversized.exception.status_code, 413)

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

    def test_full_engine_output_preflight_and_read_use_one_snapshot(self) -> None:
        from fastapi import HTTPException
        from app.models import EngineResultInput
        from app.services import scan_report_read
        db = self.database
        scan = db.create_scan_job(db.create_sample(_sample()), '', 'Normal', '', status='completed')
        text = 'İ😀' * 17000
        result = db.create_engine_result(scan, EngineResultInput('AV', 'completed', False, 'info', 100, None, text, 10))
        original = db.connect
        fired = False
        class Reader:
            def __enter__(self):
                self.connection = original()
                self.connection.__enter__()
                return self
            def __exit__(self, *args):
                return self.connection.__exit__(*args)
            def execute(self, sql, params=()):
                nonlocal fired
                if 'j.id AS scan_id' in sql and not fired:
                    fired = True
                    with original() as writer:
                        writer.execute('UPDATE engine_results SET raw_output = ? WHERE id = ?',
                                       ('x' * (scan_report_read.FULL_OUTPUT_LIMIT + 1), result))
                return self.connection.execute(sql, params)
        with patch.object(db, 'connect', return_value=Reader()):
            output = scan_report_read.full_technical_details(scan, result)
        self.assertTrue(fired)
        self.assertEqual(output.raw_output, text)
        with self.assertRaises(HTTPException) as error:
            scan_report_read.full_technical_details(scan, result)
        self.assertEqual(error.exception.status_code, 413)
        with db.connect() as connection:
            connection.execute('DELETE FROM engine_results WHERE id = ?', (result,))
        with self.assertRaises(HTTPException) as error:
            scan_report_read.full_technical_details(scan, result)
        self.assertEqual(error.exception.status_code, 404)

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
