import asyncio
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

from cryptography.fernet import Fernet
from fastapi import FastAPI

from app import database as db
from app.models import StoredSample, EngineResultInput
from app.services import auth, ui_api
from app.services import dashboard_read, archive_read, batch_read
from app.services import scan_report_read, scan_assessment
from app.services import scan_management
from app.services import browser_db_budget


class BrowserApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original = (db.DB_PATH, db.DATABASE_URL)
        db.DB_PATH, db.DATABASE_URL = Path(self.temp.name) / 'browser.db', ''
        db.init_db()
        dashboard_read._summary_cache = None
        self.user_id = db.create_user('browser-admin', auth.hash_password('test-password'), 'admin')
        self.token = 'synthetic-browser-session'
        db.create_auth_session(user_id=self.user_id, token_hash=auth.hash_session_token(self.token), expires_at=int(time.time()) + 3600)
        self.app = FastAPI()
        self.app.include_router(ui_api.router)
        self.samples_dir = Path(self.temp.name) / 'samples'
        self.storage_patch = patch('app.services.ingest.SAMPLES_DIR', self.samples_dir)
        self.storage_patch.start()
        self.addCleanup(self.storage_patch.stop)

    def tearDown(self):
        db.DB_PATH, db.DATABASE_URL = self.original
        self.temp.cleanup()

    def request(self, path, method='GET', body=None, *, session=True, csrf=True, origin='http://testserver', chunks=None,
                content_type='application/json', content_length=None):
        headers = [(b'host', b'testserver'), (b'content-type', content_type.encode()), (b'x-masp-ui', b'1')]
        if content_length is not None:
            headers.append((b'content-length', str(content_length).encode()))
        if origin is not None:
            headers.append((b'origin', origin.encode()))
        if session:
            headers.append((b'cookie', f'{auth.SESSION_COOKIE}={self.token}'.encode()))
        if csrf:
            headers.append((b'x-csrf-token', ui_api.csrf_token(self.token).encode()))
        parsed = urlsplit(ui_api.PREFIX + path)
        scope = dict(type='http', asgi={'version': '3.0'}, http_version='1.1', method=method, scheme='http',
                     path=parsed.path, raw_path=parsed.path.encode(), query_string=parsed.query.encode(),
                     root_path='', headers=headers, server=('testserver', 80), client=('127.0.0.1', 1234))
        chunks = chunks or [json.dumps(body).encode() if body is not None else b'']
        self.reads = 0
        messages = []

        async def receive():
            index = self.reads
            self.reads += 1
            return {'type': 'http.request', 'body': chunks[index], 'more_body': index < len(chunks) - 1}

        async def send(message):
            messages.append(message)

        asyncio.run(self.app(scope, receive, send))
        start = next(m for m in messages if m['type'] == 'http.response.start')
        data = b''.join(m.get('body', b'') for m in messages if m['type'] == 'http.response.body')
        return start['status'], json.loads(data) if data else None, dict(start['headers'])

    def create_clamav(self, name='ClamAV A'):
        status, body, _ = self.request('/engines', 'POST', {
            'adapter_key': 'clamav', 'display_name': name,
            'config': {'mode': 'clamd', 'host': 'clamav.internal', 'port': '3310',
                       'timeout_seconds': '60', 'max_file_size_bytes': '52428800'},
        })
        self.assertEqual(status, 201, body)
        return body['id']

    def test_scan_management_auth_scope_csrf_and_strict_attempt(self):
        scan = self.create_scan(status='completed')
        for path, method in ((f'/scans/{scan}/retry', 'POST'), (f'/scans/{scan}', 'DELETE')):
            self.assertEqual(self.request(path, method, {'attempt': 0, 'job_revision': 0}, session=False)[0], 401)
            self.assertEqual(self.reads, 0)
            self.assertEqual(self.request(path, method, {'attempt': 0, 'job_revision': 0}, csrf=False)[0], 403)
            self.assertEqual(self.reads, 0)
            self.assertEqual(self.request(path, method, {'attempt': 0, 'job_revision': 0}, origin='https://evil.invalid')[0], 403)
            self.assertEqual(self.reads, 0)
            for body in ({}, {'attempt': -1}, {'attempt': '0'}, {'attempt': True}, {'attempt': 0, 'source': 'api'}):
                self.assertEqual(self.request(path, method, body)[0], 422)
            self.assertEqual(self.request(path, method, chunks=[b'x' * (ui_api.BODY_LIMIT + 1)])[0], 413)
        for source in ('api', 'icap'):
            other = self.create_scan(status='completed', source=source)
            self.assertEqual(self.request(f'/scans/{other}/retry', 'POST', {'attempt': 0, 'job_revision': 0})[0], 404)
            self.assertEqual(self.request(f'/scans/{other}', 'DELETE', {'attempt': 0, 'job_revision': 0})[0], 404)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(f'/scans/{scan}', 'DELETE', {'attempt': 0, 'job_revision': 0})[0], 403)
        self.assertEqual(self.reads, 0)
        self.assertIsNotNone(db.get_scan(scan))

    def test_retry_preserves_snapshot_and_queues_atomically_for_analyst(self):
        engine = self.create_clamav()
        snapshot = json.dumps({'engines': [{'id': engine, 'name': 'Historic AV', 'detection': True, 'required': True}]})
        scan = self.create_scan(status='failed', profile_snapshot_json=snapshot)
        db.create_engine_result(scan, EngineResultInput('Historic AV', 'failed', False, 'info', 0, None, '', 0))
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        status, payload, headers = self.request(f'/scans/{scan}/retry', 'POST', {'attempt': 0, 'job_revision': 0})
        self.assertEqual((status, payload['status']), (202, 'accepted'))
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(db.get_scan(scan).status, 'queued')
        self.assertEqual(db.get_scan(scan).profile_snapshot_json, snapshot)
        self.assertEqual(db.list_engine_results(scan), [])
        jobs = db.list_scan_engine_jobs(scan)
        self.assertEqual([(j.engine_instance_id, j.engine_name) for j in jobs], [(engine, 'Historic AV')])
        self.assertEqual(self.request(f'/scans/{scan}/retry', 'POST', {'attempt': 0, 'job_revision': 0})[0], 409)
        self.assertEqual(db.list_scan_engine_jobs(scan), jobs)

    def test_retry_without_engines_and_transaction_failure_preserve_results(self):
        scan, result = self.report_fixture()
        self.assertEqual(self.request(f'/scans/{scan}/retry', 'POST', {'attempt': 0, 'job_revision': 0})[0], 409)
        self.assertEqual(db.list_engine_results(scan)[0].id, result)
        engine = db.get_engine_instance_by_id(self.create_clamav())
        with patch.object(db, '_insert_engine_jobs', side_effect=RuntimeError('injected queue failure')):
            with self.assertRaises(RuntimeError):
                db.retry_scan_job(scan, engines=[engine], expected_attempt=0, source='manual')
        self.assertEqual(db.get_scan(scan).status, 'completed')
        self.assertEqual(db.list_engine_results(scan)[0].id, result)

    def test_management_rejects_active_and_stale_attempt_without_cleanup(self):
        self.create_clamav()
        for state in ('queued', 'running', 'finalizing', 'completed'):
            scan = self.create_scan(status=state)
            with patch.object(scan_management, 'delete_sample_file') as cleanup:
                self.assertEqual(self.request(f'/scans/{scan}', 'DELETE', {'attempt': 1, 'job_revision': 0})[0], 409)
                self.assertEqual(self.request(f'/scans/{scan}/retry', 'POST', {'attempt': 1, 'job_revision': 0})[0], 409)
                if state != 'completed':
                    self.assertIsNone(db.delete_scan(scan))
                    self.assertEqual(self.request(f'/scans/{scan}', 'DELETE', {'attempt': 0, 'job_revision': 0})[0], 409)
                    self.assertEqual(self.request(f'/scans/{scan}/retry', 'POST', {'attempt': 0, 'job_revision': 0})[0], 409)
                cleanup.assert_not_called()
            self.assertEqual(db.get_scan(scan).status, state)

    def test_delete_protects_children_and_shared_sample_then_reports_cleanup(self):
        parent, batch = self.archive_fixture()
        child = self.create_scan(status='completed', parent_scan_id=parent, batch_id=batch, scan_role='child')
        self.assertEqual(self.request(f'/scans/{parent}', 'DELETE', {'attempt': 0, 'job_revision': 0})[0], 409)
        self.assertEqual(db.get_scan(child).parent_scan_id, parent)
        scan = self.create_scan(status='completed')
        shared = db.create_scan_job(db.get_scan(scan).sample_id, '', 'normal', '', status='running')
        self.assertEqual(self.request(f'/scans/{scan}', 'DELETE', {'attempt': 0, 'job_revision': 0})[0], 409)
        self.assertIsNotNone(db.get_scan(shared))
        with patch.object(scan_management, 'delete_sample_file', side_effect=PermissionError('internal path')):
            status, payload, _ = self.request(f'/scans/{child}', 'DELETE', {'attempt': 0, 'job_revision': 0})
        self.assertEqual((status, payload), (200, {'scan_id': child, 'status': 'deleted', 'sample_removed': False}))
        self.assertIsNone(db.get_scan(child))
        self.assertEqual(self.request(f'/scans/{child}', 'DELETE', {'attempt': 0, 'job_revision': 0})[0], 404)

    def test_bulk_delete_is_bounded_admin_only_strict_and_duplicate_safe(self):
        scan = self.create_scan(status='completed')
        item = {'scan_id': scan, 'attempt': 0, 'job_revision': 0}
        self.assertEqual(self.request('/scans', 'DELETE', {'scans': [item]}, session=False)[0], 401)
        self.assertEqual(self.reads, 0)
        self.assertEqual(self.request('/scans', 'DELETE', {'scans': [item]}, csrf=False)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/scans', 'DELETE', {'scans': [item]})[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'admin' WHERE id = ?", (self.user_id,))
        for body in ({}, {'scans': []}, {'scans': [item, item]},
                     {'scans': [item | {'extra': 'no'}]},
                     {'scans': [{'scan_id': str(scan), 'attempt': 0, 'job_revision': 0}]},
                     {'scans': [item] * 21}):
            with self.subTest(body=body):
                self.assertEqual(self.request('/scans', 'DELETE', body)[0], 422)
                self.assertIsNotNone(db.get_scan(scan))

    def test_bulk_delete_reports_partial_fenced_results_and_cleanup_failures(self):
        deleted = self.create_scan(status='completed')
        active = self.create_scan(status='running')
        stale = self.create_scan(status='completed')
        parent, batch = self.archive_fixture()
        child = self.create_scan(status='completed', parent_scan_id=parent, batch_id=batch, scan_role='child')
        api_scan = self.create_scan(status='completed', source='api')
        candidates = [
            {'scan_id': deleted, 'attempt': 0, 'job_revision': 0},
            {'scan_id': active, 'attempt': 0, 'job_revision': 0},
            {'scan_id': stale, 'attempt': 1, 'job_revision': 0},
            {'scan_id': parent, 'attempt': 0, 'job_revision': 0},
            {'scan_id': child, 'attempt': 0, 'job_revision': 0},
            {'scan_id': api_scan, 'attempt': 0, 'job_revision': 0},
        ]
        with patch.object(scan_management, 'delete_sample_file', return_value=False):
            status, payload, _ = self.request('/scans', 'DELETE', {'scans': candidates})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload, {'requested_count': 6, 'deleted_ids': [deleted],
            'blocked_ids': [active, stale, parent, child, api_scan],
            'cleanup_failed_ids': [deleted]})
        self.assertIsNone(db.get_scan(deleted))
        for scan_id in (active, stale, parent, child, api_scan):
            self.assertIsNotNone(db.get_scan(scan_id))

    def test_summary_exports_use_shared_decision_and_explicit_bounded_scope(self):
        import csv
        import io
        for options in ({}, {'detected': True}, {'status': 'failed', 'result_status': 'failed'}, {'details': '['}):
            scan, _ = self.report_fixture(**options)
            status, exported, headers = self.request(f'/scans/{scan}/summary-export')
            self.assertEqual(status, 200)
            self.assertEqual(headers[b'cache-control'], b'no-store')
            payload = json.loads(exported['content'])
            self.assertEqual(payload['report'], self.request(f'/scans/{scan}')[1])
            self.assertIn('no raw output', payload['scope'])
            self.assertNotIn('/private/storage', exported['content'])
            self.assertNotIn('<script>', exported['content'])
        with db.connect() as connection:
            connection.execute("UPDATE samples SET original_filename = ? WHERE id = ?", ('\t=HYPERLINK("bad")', db.get_scan(scan).sample_id))
        _, exported, _ = self.request(f'/scans/{scan}/summary-export?format=csv')
        cells = dict(list(csv.reader(io.StringIO(exported['content'])))[1:])
        self.assertEqual(cells['report.filename'], "'\t=HYPERLINK(\"bad\")")
        self.assertEqual(cells['report.decision'], 'null')
        self.assertEqual(self.request(f'/scans/{scan}/summary-export?format=html')[0], 422)
        with patch.object(scan_management, 'EXPORT_LIMIT', 10):
            self.assertEqual(self.request(f'/scans/{scan}/summary-export')[0], 413)

    def test_summary_export_auth_scope_and_analyst_access(self):
        scan, _ = self.report_fixture()
        self.assertEqual(self.request(f'/scans/{scan}/summary-export', session=False)[0], 401)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(f'/scans/{scan}/summary-export')[0], 200)
        for source in ('api', 'icap'):
            other = self.create_scan(source=source)
            self.assertEqual(self.request(f'/scans/{other}/summary-export')[0], 404)

    def test_full_exports_are_snapshot_scoped_bounded_and_spreadsheet_safe(self):
        import csv
        import io
        scan, _ = self.report_fixture()
        status, exported, headers = self.request(f'/scans/{scan}/export')
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        payload = json.loads(exported['content'])
        self.assertEqual(payload['engine_results'][0]['raw_output'], '<script>not executable</script>')
        self.assertEqual(payload['summary']['decision'], self.request(f'/scans/{scan}')[1]['decision'])
        self.assertNotIn('/private/storage', exported['content'])
        self.assertNotIn('storage_path', exported['content'])
        with db.connect() as connection:
            connection.execute('UPDATE samples SET original_filename = ? WHERE id = ?',
                               ('\t=HYPERLINK("bad")', db.get_scan(scan).sample_id))
        _, exported, _ = self.request(f'/scans/{scan}/export?format=csv')
        rows = list(csv.DictReader(io.StringIO(exported['content'])))
        self.assertTrue(rows)
        self.assertNotIn('<script>not executable</script>', exported['content'])
        self.assertEqual(rows[0]['filename'], "'=HYPERLINK(\"bad\")")
        self.assertTrue(all(row['section'].startswith("'") for row in rows))
        self.assertEqual(self.request(f'/scans/{scan}/export?format=html')[0], 422)
        with patch.object(scan_management, 'MAX_EXPORT_ENGINES', 0):
            self.assertEqual(self.request(f'/scans/{scan}/export')[0], 413)
        with patch.object(scan_management, 'FULL_EXPORT_SOURCE_LIMIT', 10):
            self.assertEqual(self.request(f'/scans/{scan}/export')[0], 413)
        with patch.object(scan_management, 'EXPORT_LIMIT', 10):
            self.assertEqual(self.request(f'/scans/{scan}/export')[0], 413)

    def test_full_export_suppresses_invalid_policy_and_preserves_browser_scope(self):
        scan, _ = self.report_fixture(details='[')
        payload = json.loads(self.request(f'/scans/{scan}/export')[1]['content'])
        self.assertIsNone(payload['summary']['decision'])
        self.assertIn('Decision unavailable', payload['decision_warning'])
        self.assertEqual(self.request(f'/scans/{scan}/export', session=False)[0], 401)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(f'/scans/{scan}/export')[0], 200)
        for source in ('api', 'icap'):
            other = self.create_scan(source=source)
            self.assertEqual(self.request(f'/scans/{other}/export')[0], 404)

    def test_browser_database_budget_configuration_and_timeout_response(self):
        with patch.dict('os.environ', {'MASP_UI_READ_TIMEOUT_MS': '5', 'MASP_UI_WRITE_LOCK_TIMEOUT_MS': 'invalid'}):
            self.assertEqual(browser_db_budget.read_timeout_ms(), 100)
            self.assertEqual(browser_db_budget.write_lock_timeout_ms(), 5000)
        with patch.dict('os.environ', {'MASP_UI_READ_TIMEOUT_MS': '999999'}):
            self.assertEqual(browser_db_budget.read_timeout_ms(), 60000)
        if db.psycopg is not None:
            error = db.psycopg.errors.QueryCanceled('synthetic statement timeout')
            with patch.object(scan_report_read, 'report', side_effect=error):
                status, payload, _ = self.request('/scans/1')
            self.assertEqual(status, 503)
            self.assertEqual(payload, {'detail': 'Browser database work exceeded its time budget. Refine the request or retry after current work settles.'})
            self.assertNotIn('synthetic', payload['detail'])

    def test_concurrent_retries_have_one_winner_and_delete_cannot_remove_queued_run(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        engine = db.get_engine_instance_by_id(self.create_clamav())
        scan = self.create_scan(status='completed')
        gate = Barrier(2)
        def retry():
            gate.wait(timeout=5)
            return db.retry_scan_job(scan, source='manual', expected_attempt=0, engines=[engine])
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(retry) for _ in range(2)]
            self.assertEqual(sorted(f.result(timeout=10) for f in futures), [False, True])
        self.assertEqual(len(db.list_scan_engine_jobs(scan)), 1)
        self.assertIsNone(db.delete_scan(scan, source='manual', expected_attempt=0))

    def test_job_revision_rejects_old_actions_when_retry_finishes_without_starting(self):
        engine = db.get_engine_instance_by_id(self.create_clamav())
        scan = self.create_scan(status='completed')
        old = {'attempt': 0, 'job_revision': 0}
        self.assertEqual(self.request(f'/scans/{scan}/retry', 'POST', old)[0], 202)
        # A missing worker can settle queued work without mark_scan_running.
        db.update_scan_status(scan, 'failed')
        self.assertEqual(db.get_scan(scan).attempt_count, 0)
        self.assertEqual(self.request(f'/scans/{scan}/retry', 'POST', old)[0], 409)
        self.assertEqual(self.request(f'/scans/{scan}', 'DELETE', old)[0], 409)
        jobs = db.list_scan_engine_jobs(scan)
        fresh = self.request(f'/scans/{scan}')[1]
        self.assertEqual(fresh['job_revision'], jobs[-1].id)
        self.assertEqual(jobs[0].engine_instance_id, engine.id)

    def test_delete_waits_for_atomic_retry_commit(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        engine = db.get_engine_instance_by_id(self.create_clamav())
        scan = self.create_scan(status='completed')
        inserted, release, deleting = Event(), Event(), Event()
        original = db._insert_engine_jobs
        def hold(connection, scan_id, engines):
            result = original(connection, scan_id, engines)
            inserted.set()
            if not release.wait(5):
                raise AssertionError('Retry lock test timed out')
            return result
        def delete():
            deleting.set()
            return db.delete_scan(scan, expected_attempt=0, source='manual')
        with ThreadPoolExecutor(max_workers=2) as pool, patch.object(db, '_insert_engine_jobs', side_effect=hold):
            retried = pool.submit(db.retry_scan_job, scan, engines=[engine])
            try:
                self.assertTrue(inserted.wait(5))
                deleted = pool.submit(delete)
                self.assertTrue(deleting.wait(5))
                self.assertFalse(deleted.done())
            finally:
                release.set()
            self.assertTrue(retried.result(timeout=10))
            self.assertIsNone(deleted.result(timeout=10))
        self.assertEqual(db.get_scan(scan).status, 'queued')
        self.assertEqual(len(db.list_scan_engine_jobs(scan)), 1)

    def create_scan(self, name='sample.bin', **kwargs):
        sample_id = db.create_sample(StoredSample(name, 'internal.bin', '/private/storage',
            'application/octet-stream', 50 * 1024**3, 'a' * 32, 'b' * 40, 'c' * 64))
        return db.create_scan_job(sample_id, 'Case A', 'normal', 'internal note', **kwargs)

    def report_fixture(self, *, status='completed', detected=False, result_status='completed', details='{}'):
        snapshot = json.dumps({'engines': [{'id': 123, 'name': 'Historic Defender', 'detection': True, 'required': True}]})
        scan = self.create_scan(status=status, verdict='high' if detected else 'info',
                                risk_score=70 if detected else 0, profile_snapshot_json=snapshot)
        result = db.create_engine_result(scan, EngineResultInput(engine_name='Historic Defender', status=result_status,
            detected=detected, severity='high' if detected else 'info', confidence=100, signature='Fixture.Test' if detected else None,
            raw_output='<script>not executable</script>', duration_ms=42, details_json=details))
        return scan, result

    def archive_fixture(self):
        batch = db.create_scan_batch(source='manual', original_filename='outer.zip', archive_mode='lazy_extract_on_detection')
        parent = self.create_scan('outer.zip', batch_id=batch, scan_role='container', status='completed')
        return parent, batch

    def test_batch_auth_manual_scope_and_cursor_validation(self):
        _, batch = self.archive_fixture()
        path = f'/batches/{batch}'
        self.assertEqual(self.request(path, session=False)[0], 401)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(path)[0], 200)
        api_batch = db.create_scan_batch(source='api', original_filename='private.zip', archive_mode='lazy')
        self.assertEqual(self.request(f'/batches/{api_batch}')[0], 404)
        for suffix in ('?limit=0', '?limit=101', '?after_id=1', '?after_created=2026-01-01',
                       '?after_id=0&after_created=x', '?after_id=1&after_created=' + 'x' * 65):
            self.assertEqual(self.request(path + suffix)[0], 422, suffix)
        self.assertEqual(self.request('/batches/0')[0], 422)
        self.assertEqual(self.request('/batches/999999')[0], 404)
        self.assertEqual(self.request(path, 'DELETE')[0], 405)

    def test_batch_keyset_is_bounded_manual_only_and_does_not_expose_storage(self):
        _, batch = self.archive_fixture()
        ids = [self.create_scan(name=f'child-{index}.bin', batch_id=batch, parent_scan_id=1,
                    scan_role='child', status='completed', verdict='info', risk_score=0,
                    relative_path=('x' * 1100 if index == 0 else f'pack/child-{index}.bin'))
               for index in range(22)]
        self.create_scan(name='api-private.bin', batch_id=batch, scan_role='child', source='api')
        with db.connect() as connection:
            connection.execute('''UPDATE scan_batches SET total_items = 23, completed_items = 22,
                queued_items = 1, malicious_items = 2 WHERE id = ?''', (batch,))
        status, first, headers = self.request(f'/batches/{batch}')
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual([row['id'] for row in first['items']], [1] + ids[:19])
        self.assertEqual(first['counts']['total'], 23)
        self.assertTrue(first['items'][1]['path_truncated'])
        self.assertEqual(len(first['items'][1]['path']), 1024)
        serialized = json.dumps(first)
        for secret in ('storage_path', '/private/storage', 'profile_snapshot_json', 'metadata_json', 'last_error'):
            self.assertNotIn(secret, serialized)
        cursor = urlencode({'limit': 20, 'after_id': first['next_after_id'],
                            'after_created': first['next_after_created']})
        with db.connect() as connection:
            connection.execute('DELETE FROM scan_jobs WHERE id = ?', (first['next_after_id'],))
        second = self.request(f'/batches/{batch}?{cursor}')[1]
        self.assertEqual([row['id'] for row in second['items']], ids[19:])
        self.assertIsNone(second['next_after_id'])
        self.assertNotIn('api-private.bin', json.dumps(second))

    def test_batch_read_is_snapshot_consistent_read_only_and_uses_batch_index(self):
        parent, batch = self.archive_fixture()
        child = self.create_scan(batch_id=batch, parent_scan_id=parent, scan_role='child',
                                 status='completed', verdict='info', risk_score=0)
        original = db.connect
        with original() as connection:
            connection.execute('PRAGMA journal_mode=WAL')
        fired = False
        statements: list[str] = []
        class Reader:
            def __enter__(self):
                self.connection = original()
                self.connection.__enter__()
                self.connection.set_trace_callback(statements.append)
                return self
            def __exit__(self, *args):
                try:
                    return self.connection.__exit__(*args)
                finally:
                    self.connection.close()
            def execute(self, sql, params=()):
                nonlocal fired
                if 'FROM scan_jobs j JOIN samples' in sql and not fired:
                    fired = True
                    with original() as writer:
                        writer.execute("UPDATE scan_batches SET status = 'running' WHERE id = ?", (batch,))
                        writer.execute("UPDATE scan_jobs SET status = 'running' WHERE id = ?", (child,))
                return self.connection.execute(sql, params)
        with patch.object(db, 'connect', return_value=Reader()):
            page = batch_read.page(batch, limit=20, after_id=None, after_created=None)
        self.assertTrue(fired)
        self.assertEqual(page.status, 'queued')
        self.assertEqual(next(row.status for row in page.items if row.id == child), 'completed')
        item_sql = next(sql for sql in statements if 'FROM scan_jobs j JOIN samples' in sql)
        self.assertNotIn('OFFSET', item_sql)
        for statement in statements:
            self.assertTrue(statement.strip().split()[0].upper() in ('SELECT', 'BEGIN', 'COMMIT'), statement)
            for excluded in ('engine_results', 'storage_path', 'metadata_json', 'profile_snapshot_json'):
                self.assertNotIn(excluded, statement)
        with original() as connection:
            plan = connection.execute('EXPLAIN QUERY PLAN ' + item_sql).fetchall()
        self.assertIn('idx_scan_jobs_batch_created', str([tuple(row) for row in plan]))
        refreshed = self.request(f'/batches/{batch}')[1]
        self.assertEqual((refreshed['status'], next(row['status'] for row in refreshed['items'] if row['id'] == child)),
                         ('running', 'running'))

    def test_archive_auth_scope_and_validation(self):
        parent, _ = self.archive_fixture()
        path = f'/scans/{parent}/children'
        self.assertEqual(self.request(path, session=False)[0], 401)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(path)[0], 200)
        for source in ('api', 'icap'):
            other = self.create_scan(source=source)
            self.assertEqual(self.request(f'/scans/{other}/children')[0], 404)
        for suffix in ('?limit=0', '?limit=101', '?after=0', '?after=1', '?attempt=-1', '?q=' + 'x' * 201,
                       '?status=clean', '?after=9007199254740992&attempt=0'):
            self.assertEqual(self.request(path + suffix)[0], 422, suffix)
        for scan_id in (0, 9007199254740992):
            self.assertEqual(self.request(f'/scans/{scan_id}/children')[0], 422)
        self.assertEqual(self.request('/scans/999999/children')[0], 404)
        self.assertEqual(self.request(path, 'DELETE')[0], 405)

    def test_archive_direct_children_batch_scope_and_duplicate_paths(self):
        parent, batch = self.archive_fixture()
        def child(**overrides):
            args = dict(parent_scan_id=parent, batch_id=batch, scan_role='child', relative_path='same/path.bin')
            args.update(overrides)
            return self.create_scan(**args)
        first, second = child(), child()
        child(parent_scan_id=first)
        child(source='api')
        child(batch_id=None)
        child(parent_scan_id=second, source='icap')
        child(scan_role='standalone')
        page = self.request(f'/scans/{parent}/children')[1]
        self.assertEqual([row['id'] for row in page['items']], [first, second])
        self.assertEqual([row['path'] for row in page['items']], ['same/path.bin'] * 2)
        self.assertEqual([row['has_children'] for row in page['items']], [True, False])
        self.assertEqual(page['archive_mode'], 'lazy_extract_on_detection')
        nested = self.request(f'/scans/{first}/children')[1]
        self.assertEqual(nested['parent_scan_id'], parent)
        self.assertEqual(len(nested['items']), 1)

    def test_archive_keyset_append_deleted_cursor_and_retry_generation(self):
        parent, batch = self.archive_fixture()
        ids = [self.create_scan(parent_scan_id=parent, batch_id=batch, scan_role='child') for _ in range(25)]
        path = f'/scans/{parent}/children'
        first = self.request(path)[1]
        self.assertEqual([row['id'] for row in first['items']], ids[:20])
        self.assertEqual(first['next_after'], ids[19])
        extra = self.create_scan(parent_scan_id=parent, batch_id=batch, scan_role='child')
        with db.connect() as connection:
            connection.execute('DELETE FROM scan_jobs WHERE id = ?', (ids[19],))
        cursor = f"?after={first['next_after']}&attempt={first['attempt_count']}"
        second = self.request(path + cursor)[1]
        self.assertEqual([row['id'] for row in second['items']], ids[20:] + [extra])
        self.assertIsNone(second['next_after'])
        with db.connect() as connection:
            connection.execute('UPDATE scan_jobs SET attempt_count = attempt_count + 1 WHERE id = ?', (parent,))
        self.assertEqual(self.request(path + cursor)[0], 409)
        self.assertEqual(self.request(path)[1]['attempt_count'], first['attempt_count'] + 1)

    def test_archive_literal_search_status_and_bounded_projection(self):
        parent, batch = self.archive_fixture()
        first = self.create_scan('literal%_!.bin', parent_scan_id=parent, batch_id=batch,
            scan_role='child', relative_path='x' * 5000, status='failed', verdict='info', risk_score=0)
        self.create_scan('literalXYZ.bin', parent_scan_id=parent, batch_id=batch, scan_role='child', status='finalizing')
        path = f'/scans/{parent}/children'
        page = self.request(path + '?q=%25_!&status=failed')[1]
        self.assertEqual(len(page['items']), 1)
        row = page['items'][0]
        self.assertEqual(row['id'], first)
        self.assertEqual(len(row['path']), 1024)
        self.assertTrue(row['path_truncated'])
        self.assertEqual(row['size_bytes'], 50 * 1024**3)
        self.assertEqual(row['status'], 'failed')
        self.assertEqual(set(row), {'id', 'path', 'path_truncated', 'filename', 'size_bytes', 'status',
                                    'risk_score', 'risk_level', 'has_children'})
        active = self.request(path + '?status=active')[1]
        self.assertEqual([row['status'] for row in active['items']], ['finalizing'])

    def test_archive_read_snapshot_does_not_mix_retry_and_child_changes(self):
        parent, batch = self.archive_fixture()
        child = self.create_scan(parent_scan_id=parent, batch_id=batch, scan_role='child', status='completed')
        original = db.connect
        with original() as connection:
            connection.execute('PRAGMA journal_mode=WAL')
        fired = False
        class Reader:
            def __enter__(self):
                self.connection = original()
                self.connection.__enter__()
                return self
            def __exit__(self, *args):
                try:
                    return self.connection.__exit__(*args)
                finally:
                    self.connection.close()
            def execute(self, sql, params=()):
                nonlocal fired
                if 'FROM scan_jobs c JOIN samples' in sql and not fired:
                    fired = True
                    with original() as writer:
                        writer.execute('UPDATE scan_jobs SET attempt_count = attempt_count + 1 WHERE id = ?', (parent,))
                        writer.execute("UPDATE scan_jobs SET status = 'running' WHERE id = ?", (child,))
                return self.connection.execute(sql, params)
        with patch.object(db, 'connect', return_value=Reader()):
            page = archive_read.children(parent, limit=20, after=None, attempt=None, query='', status='all')
        self.assertTrue(fired)
        self.assertEqual((page.attempt_count, page.items[0].status), (0, 'completed'))
        next_page = self.request(f'/scans/{parent}/children')[1]
        self.assertEqual((next_page['attempt_count'], next_page['items'][0]['status']), (1, 'running'))

    def test_archive_detached_batch_empty_and_read_only_indexed_projection(self):
        parent = self.create_scan()
        child = self.create_scan(parent_scan_id=parent, scan_role='child')
        statements, original = [], db.connect
        def traced():
            connection = original()
            connection.set_trace_callback(statements.append)
            return connection
        with patch.object(db, 'connect', side_effect=traced):
            page = archive_read.children(parent, limit=20, after=None, attempt=None, query='', status='all')
        self.assertEqual([row.id for row in page.items], [child])
        self.assertIsNone(page.batch_id)
        sql = next(sql for sql in statements if 'FROM scan_jobs c JOIN samples' in sql)
        presence_sql = next(sql for sql in statements if 'AS parent_id WHERE EXISTS' in sql)
        self.assertNotIn('OFFSET', sql)
        self.assertIn('LIMIT 21', sql)
        self.assertNotIn('WHERE EXISTS', sql)
        for statement in statements:
            self.assertTrue(statement.strip().split()[0].upper() in ('SELECT', 'BEGIN', 'COMMIT'), statement)
            self.assertNotIn('engine_results', statement)
            self.assertNotIn('storage_path', statement)
        with original() as connection:
            plan = connection.execute('EXPLAIN QUERY PLAN ' + sql).fetchall()
            presence_plan = connection.execute('EXPLAIN QUERY PLAN ' + presence_sql).fetchall()
        self.assertIn('idx_scan_jobs_parent', str([tuple(row) for row in plan]))
        self.assertIn('idx_scan_jobs_parent', str([tuple(row) for row in presence_plan]))
        empty = self.request(f'/scans/{child}/children')[1]
        self.assertEqual(empty['items'], [])
        self.assertIsNone(empty['next_after'])

    def test_report_decision_matches_shared_backend_for_clean_detected_failure_and_wait(self):
        for status, detected, result_status, action in [('completed', False, 'completed', 'allow'),
                ('completed', True, 'completed', 'block'), ('failed', False, 'failed', 'review'),
                ('finalizing', False, 'completed', 'wait'), ('completed', False, 'skipped', 'review')]:
            with self.subTest(status=status, result_status=result_status, detected=detected):
                scan, _ = self.report_fixture(status=status, detected=detected, result_status=result_status)
                code, report, _ = self.request(f'/scans/{scan}')
                self.assertEqual(code, 200, report)
                expected = scan_assessment.scan_decision(db.get_scan(scan), db.list_engine_results(scan))
                self.assertEqual(report['decision']['action'], action)
                self.assertEqual(report['decision']['policy'], expected.policy)
                self.assertEqual(report['completed_engines'], int(result_status == 'completed'))
                self.assertNotIn('raw_output', json.dumps(report))
                self.assertNotIn('storage_path', report)

    def test_report_missing_and_metadata_only_never_allow(self):
        scan, result = self.report_fixture()
        with db.connect() as connection:
            connection.execute('DELETE FROM engine_results WHERE id = ?', (result,))
        payload = self.request(f'/scans/{scan}')[1]
        self.assertEqual(payload['decision']['policy'], 'partial_coverage')
        self.assertEqual(payload['unavailable'], ['Historic Defender missing'])
        self.assertIsNone(payload['engines'][0]['result_id'])
        metadata = self.create_scan(status='completed', verdict='info', risk_score=0,
                                    profile_snapshot_json='{"engines":[]}')
        self.assertEqual(self.request(f'/scans/{metadata}')[1]['decision']['policy'], 'metadata_only')

    def test_report_limits_fail_closed_and_projection_does_not_read_raw_blobs(self):
        scan, _ = self.report_fixture()
        original = db.connect
        statements = []
        def traced():
            connection = original()
            connection.set_trace_callback(statements.append)
            return connection
        with patch.object(db, 'connect', side_effect=traced):
            report = scan_report_read.report(scan)
        self.assertEqual(report.coverage_basis, 'routing_snapshot')
        results_sql = next(sql for sql in statements if 'FROM engine_results WHERE' in sql)
        self.assertIn("'' AS raw_output", results_sql)
        self.assertIn("'[]' AS findings_json", results_sql)
        self.assertIn('SUBSTR(details_json', results_sql)
        with patch.object(scan_report_read, 'MAX_ENGINES', 0):
            self.assertEqual(self.request(f'/scans/{scan}')[0], 413)
        with patch.object(scan_report_read, 'SNAPSHOT_LIMIT', 5):
            self.assertEqual(self.request(f'/scans/{scan}')[0], 413)

    def test_report_preserves_completed_engine_review_policy(self):
        scan, _ = self.report_fixture(details='{"decision":{"action":"review","reason":"License policy"}}')
        self.assertEqual(self.request(f'/scans/{scan}')[1]['decision']['policy'], 'engine_policy_review')

    def test_report_bounds_technical_data_and_never_allows_on_incomplete_policy(self):
        for details in ('x' * (scan_report_read.POLICY_LIMIT + 1), 'not-json', '[]'):
            scan, result = self.report_fixture(details=details)
            payload = self.request(f'/scans/{scan}')[1]
            self.assertIsNone(payload['decision'])
            self.assertIn('Decision unavailable', payload['warning'])
            with db.connect() as connection:
                connection.execute('UPDATE engine_results SET raw_output = ?, findings_json = ? WHERE id = ?',
                    ('x' * 20000, 'x' * 20000, result))
            details_payload = self.request(f'/scans/{scan}/results/{result}')[1]
            self.assertEqual(len(details_payload['raw_output']), scan_report_read.TEXT_LIMIT)
            self.assertIn('raw_output', details_payload['truncated'])
            self.assertIn('findings_json', details_payload['truncated'])

    def test_report_manual_scope_analyst_auth_and_result_ownership(self):
        scan, result = self.report_fixture()
        other = self.create_scan(source='api')
        for path in (f'/scans/{scan}', f'/scans/{scan}/results/{result}'):
            self.assertEqual(self.request(path, session=False)[0], 401)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(f'/scans/{scan}')[0], 200)
        self.assertEqual(self.request(f'/scans/{scan}/results/{result}')[0], 200)
        self.assertEqual(self.request(f'/scans/{other}')[0], 404)
        self.assertEqual(self.request(f'/scans/{other}/results/{result}')[0], 404)
        self.assertEqual(self.request(f'/scans/{scan}/results/{result + 999}')[0], 404)
        self.assertEqual(self.request('/scans/0')[0], 422)
        self.assertEqual(self.request(f'/scans/{scan}', 'DELETE')[0], 403)

    def test_report_uses_historical_job_names_after_instance_rename(self):
        scan = self.create_scan(status='completed', verdict='info', risk_score=0)
        engine = db.create_engine_instance('clamav', 'Old ClamAV')
        db.create_scan_engine_jobs(scan, [db.get_engine_instance_by_id(engine)])
        db.update_engine_instance_by_id(engine, display_name='Renamed ClamAV')
        payload = self.request(f'/scans/{scan}')[1]
        self.assertEqual(payload['unavailable'], ['Old ClamAV missing'])
        self.assertEqual(payload['decision']['action'], 'review')

    def test_report_does_not_mix_state_and_results_during_concurrent_retry(self):
        scan, _ = self.report_fixture()
        original_connect = db.connect
        with original_connect() as connection:
            connection.execute('PRAGMA journal_mode=WAL')
        fired = False
        class Reader:
            def __enter__(self):
                self.connection = original_connect()
                self.connection.__enter__()
                return self
            def __exit__(self, *args):
                try:
                    return self.connection.__exit__(*args)
                finally:
                    self.connection.close()
            def execute(self, sql, params=()):
                nonlocal fired
                if 'FROM engine_results WHERE' in sql and not fired:
                    fired = True
                    with original_connect() as writer:
                        writer.execute("UPDATE scan_jobs SET status = 'running', attempt_count = attempt_count + 1 WHERE id = ?", (scan,))
                        writer.execute('DELETE FROM engine_results WHERE scan_job_id = ?', (scan,))
                return self.connection.execute(sql, params)
        with patch.object(db, 'connect', return_value=Reader()):
            payload = scan_report_read.report(scan)
        self.assertTrue(fired)
        self.assertEqual((payload.status, payload.completed_engines, payload.decision.action), ('completed', 1, 'allow'))
        next_payload = scan_report_read.report(scan)
        self.assertEqual((next_payload.status, next_payload.completed_engines, next_payload.decision.action), ('running', 0, 'wait'))

    def upload_request(self, *, data=b'benign test data', fields=None, files=1, **kwargs):
        boundary = b'console-upload-test'
        parts = []
        for name, value in (fields if fields is not None else [('case_name', 'IR-2026'), ('priority', 'High'), ('note', 'analyst note')]):
            parts.append(b'--' + boundary + b'\r\nContent-Disposition: form-data; name="' + name.encode() + b'"\r\n\r\n' + value.encode() + b'\r\n')
        for _ in range(files):
            parts.append(b'--' + boundary + b'\r\nContent-Disposition: form-data; name="sample"; filename="benign.txt"\r\nContent-Type: text/plain\r\n\r\n' + data + b'\r\n')
        payload = b''.join(parts) + b'--' + boundary + b'--\r\n'
        return self.request('/scans', 'POST', chunks=[payload[index:index + 100] for index in range(0, len(payload), 100)],
            content_type='multipart/form-data; boundary=console-upload-test', **kwargs)

    def test_submission_analyst_acceptance_uses_transactional_manual_intake(self):
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        engine = db.create_engine_instance('static_metadata', 'Static Metadata')
        self.assertEqual(self.request('/scans/options')[1]['enabled_engine_count'], 1)
        status, body, headers = self.upload_request()
        self.assertEqual(status, 202, body)
        self.assertEqual(body['status'], 'accepted')
        self.assertEqual(headers[b'location'].decode(), body['report_url'])
        self.assertEqual(headers[b'cache-control'], b'no-store')
        scan = db.get_scan(body['scan_id'])
        self.assertEqual((scan.source, scan.status, scan.case_name, scan.priority, scan.note),
                         ('manual', 'queued', 'IR-2026', 'High', 'analyst note'))
        self.assertEqual(Path(scan.storage_path).read_bytes(), b'benign test data')
        jobs = db.list_scan_engine_jobs(scan.id)
        self.assertEqual([job.engine_instance_id for job in jobs], [engine])
        self.assertEqual(set(body), {'scan_id', 'status', 'report_url'})
        schema = self.app.openapi()['paths'][ui_api.PREFIX + '/scans']['post']
        self.assertIn('multipart/form-data', schema['requestBody']['content'])

    def test_submission_auth_and_csrf_reject_before_multipart_read(self):
        for options, expected in (({'session': False}, 401), ({'csrf': False}, 403),
                                  ({'origin': 'https://other.invalid'}, 403)):
            self.assertEqual(self.upload_request(**options)[0], expected)
            self.assertEqual(self.reads, 0)
        self.assertFalse(self.samples_dir.exists())
        self.assertEqual(self.request('/scans/options', session=False)[0], 401)

    def test_submission_byte_ceiling_before_and_during_stream(self):
        with patch('app.services.upload_admission.upload_body_limit', return_value=350):
            self.assertEqual(self.upload_request(content_length=351)[0], 413)
            self.assertEqual(self.reads, 0)
            self.assertEqual(self.upload_request(data=b'x' * 1000)[0], 413)
            self.assertGreater(self.reads, 0)
            self.assertEqual(self.upload_request(content_length='invalid')[0], 400)
        self.assertFalse(self.samples_dir.exists())

    def test_submission_limits_parts_duplicate_and_unknown_fields(self):
        cases = [dict(files=2), dict(fields=[('note', 'x' * 17000)]),
                 dict(fields=[('note', 'a'), ('note', 'b')]), dict(fields=[('source', 'api')]),
                 dict(fields=[('priority', 'invalid')]), dict(fields=[('case_name', 'x' * 201)]),
                 dict(fields=[('note', 'x' * 4001)]), dict(files=0)]
        for args in cases:
            with self.subTest(args=str(args)[:80]):
                self.assertIn(self.upload_request(**args)[0], {400, 422})
        self.assertFalse(self.samples_dir.exists())

    def test_submission_closes_multipart_spools_on_stream_overflow(self):
        files = []
        def spool(*args, **kwargs):
            file = tempfile.SpooledTemporaryFile(*args, **kwargs)
            files.append(file)
            return file
        with patch('starlette.formparsers.SpooledTemporaryFile', side_effect=spool), \
             patch('app.services.upload_admission.upload_body_limit', return_value=600):
            self.assertEqual(self.upload_request(data=b'x' * 1000, content_length=1)[0], 413)
        self.assertTrue(files)
        self.assertTrue(all(file.closed for file in files))
        self.assertFalse(self.samples_dir.exists())

    def test_submission_file_policy_and_no_engine_failure_leave_no_samples(self):
        self.assertEqual(self.upload_request()[0], 503)
        self.assertEqual(list(self.samples_dir.iterdir()), [])
        db.create_engine_instance('static_metadata', 'Static Metadata')
        with patch('app.services.ingest.configured_upload_max_bytes', return_value=5):
            self.assertEqual(self.upload_request()[0], 413)
        self.assertEqual(list(self.samples_dir.iterdir()), [])
        self.assertEqual(self.request('/dashboard/scans')[1]['items'], [])

    def test_submission_database_failure_rolls_back_and_removes_owned_file(self):
        db.create_engine_instance('static_metadata', 'Static Metadata')
        with patch('app.database._insert_engine_jobs', side_effect=db.IntegrityViolation[0]('synthetic')):
            self.assertEqual(self.upload_request()[0], 409)
        self.assertEqual(list(self.samples_dir.iterdir()), [])
        self.assertEqual(self.request('/dashboard/scans')[1]['items'], [])

    def test_submission_archive_uses_existing_lazy_container_workflow(self):
        import io
        import zipfile
        db.create_engine_instance('static_metadata', 'Static Metadata')
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('safe.txt', 'benign fixture')
        status, body, _ = self.upload_request(data=data.getvalue())
        self.assertEqual(status, 202, body)
        scan = db.get_scan(body['scan_id'])
        self.assertIsNotNone(scan.batch_id)
        self.assertEqual(scan.scan_role, 'container')
        self.assertEqual(db.get_scan_batch(scan.batch_id).archive_mode, 'lazy_extract_on_detection')

    def test_submission_accepts_file_larger_than_json_limit(self):
        db.create_engine_instance('static_metadata', 'Static Metadata')
        status, body, _ = self.upload_request(data=b'x' * (ui_api.BODY_LIMIT + 10))
        self.assertEqual(status, 202, body)
        self.assertEqual(db.get_scan(body['scan_id']).size_bytes, ui_api.BODY_LIMIT + 10)

    def test_dashboard_requires_session_but_allows_analyst_read_only(self):
        for path in ('/dashboard/scans', '/dashboard/summary'):
            self.assertEqual(self.request(path, session=False)[0], 401)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        for path in ('/dashboard/scans', '/dashboard/summary'):
            code, _, headers = self.request(path)
            self.assertEqual(code, 200)
            self.assertEqual(headers[b'cache-control'], b'no-store')
            self.assertEqual(self.request(path, 'POST', {})[0], 405)
        self.assertEqual(self.request('/engines')[0], 403)

    def test_dashboard_scope_contract_and_zero_score_is_not_a_clean_verdict(self):
        scan = self.create_scan(status='failed', verdict='info', risk_score=0)
        self.create_scan(source='api')
        self.create_scan(source='icap')
        self.create_scan(scan_role='child')
        self.create_scan(status='finalizing')
        self.create_scan(status='completed', verdict='critical', risk_score=100)
        rows = self.request('/dashboard/scans')[1]['items']
        self.assertEqual(len(rows), 3)
        row = next(row for row in rows if row['id'] == scan)
        self.assertEqual(row['status'], 'failed')
        self.assertEqual(row['risk_level'], 'info')
        self.assertEqual(row['risk_score'], 0)
        self.assertEqual(row['size_bytes'], 50 * 1024**3)
        self.assertEqual(set(row), {'id', 'filename', 'sha256', 'size_bytes', 'case_name', 'status',
                                    'risk_level', 'risk_score', 'attempt_count', 'job_revision', 'created_at'})
        self.assertEqual((row['attempt_count'], row['job_revision']), (0, 0))
        summary = self.request('/dashboard/summary')[1]
        self.assertEqual((summary['total'], summary['active'], summary['high_risk']), (3, 1, 1))
        schema = self.app.openapi()['paths'][ui_api.PREFIX + '/dashboard/scans']['get']['responses']['200']
        self.assertEqual(schema['content']['application/json']['schema']['$ref'], '#/components/schemas/ScanPage')

    def test_dashboard_seek_handles_new_submissions_and_deleted_cursor(self):
        ids = [self.create_scan() for _ in range(45)]
        first = self.request('/dashboard/scans')[1]
        self.assertEqual([row['id'] for row in first['items']], ids[::-1][:20])
        before = first['next_before']
        self.create_scan()
        with db.connect() as connection:
            connection.execute('DELETE FROM scan_jobs WHERE id = ?', (before,))
        second = self.request(f'/dashboard/scans?before={before}')[1]
        third = self.request(f'/dashboard/scans?before={second["next_before"]}')[1]
        self.assertEqual([row['id'] for row in second['items'] + third['items']], ids[::-1][20:])
        self.assertIsNone(third['next_before'])

    def test_dashboard_filters_are_sql_bound_and_search_is_literal(self):
        match = self.create_scan('Odd%_!Name.bin', status='finalizing', verdict='high')
        self.create_scan('OddOTHERName.bin', status='completed', verdict='info')
        self.assertEqual([r['id'] for r in self.request('/dashboard/scans?q=%25_!&status=active&risk=high')[1]['items']], [match])
        self.assertEqual(self.request('/dashboard/scans?q=%27%20OR%201%3D1--')[1]['items'], [])
        self.assertEqual(self.request('/dashboard/scans?status=completed&risk=high')[1]['items'], [])

    def test_dashboard_query_limits_fail_closed(self):
        for query in ('limit=0', 'limit=101', 'before=0', 'before=-1', 'before=9007199254740992',
                      'before=invalid', 'status=invalid', 'risk=clean', 'q=' + 'a' * 201):
            with self.subTest(query=query):
                self.assertEqual(self.request('/dashboard/scans?' + query)[0], 422)

    def test_dashboard_query_does_not_hydrate_results_or_use_offset(self):
        self.create_scan('x' * 1000)
        statements = []
        connect = db.connect
        def traced_connect():
            connection = connect()
            connection.set_trace_callback(statements.append)
            return connection
        with patch.object(db, 'connect', side_effect=traced_connect):
            page = dashboard_read.scan_page(limit=20, before=None, query='', status='all', risk='all')
        self.assertEqual(len(page.items[0].filename), 512)
        self.assertEqual(len(statements), 1)
        sql = statements[0].lower()
        for forbidden in ('engine_results', 'raw_output', 'details_json', 'profile_snapshot_json', 'offset'):
            self.assertNotIn(forbidden, sql)
        self.assertIn('limit 21', sql)
        with db.connect() as connection:
            plan = connection.execute('EXPLAIN QUERY PLAN ' + statements[0]).fetchall()
        self.assertIn('idx_scan_jobs_dashboard_seek', str([tuple(row) for row in plan]))

    def test_dashboard_summary_cache_coalesces_readers_and_expires(self):
        from concurrent.futures import ThreadPoolExecutor
        self.create_scan()
        with patch.object(dashboard_read.time, 'monotonic', return_value=100):
            with patch.object(db, 'connect', wraps=db.connect) as connect:
                with ThreadPoolExecutor(max_workers=4) as pool:
                    results = list(pool.map(lambda _: dashboard_read.summary(), range(8)))
                self.assertEqual(connect.call_count, 1)
            self.create_scan()
            self.assertTrue(all(result.total == 1 for result in results))
            self.assertEqual(dashboard_read.summary().total, 1)
        with patch.object(dashboard_read.time, 'monotonic', return_value=131):
            self.assertEqual(dashboard_read.summary().total, 2)

    def test_dashboard_seek_index_upgrade_preserves_existing_rows(self):
        scan = self.create_scan()
        with db.connect() as connection:
            connection.execute('DROP INDEX idx_scan_jobs_dashboard_seek')
        db.init_db()
        db.init_db()
        self.assertEqual(self.request('/dashboard/scans')[1]['items'][0]['id'], scan)
        with db.connect() as connection:
            row = connection.execute("SELECT name FROM sqlite_master WHERE name = 'idx_scan_jobs_dashboard_seek'").fetchone()
        self.assertIsNotNone(row)

    def test_missing_session_returns_json_401_before_body_read(self):
        status, body, _ = self.request('/engines', 'POST', session=False, chunks=[b'x' * 200000])
        self.assertEqual(status, 401)
        self.assertEqual(self.reads, 0)
        self.assertIn('detail', body)

    def test_analyst_cannot_read_or_modify_engine_settings(self):
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/session')[0], 200)
        self.assertEqual(self.request('/engines')[0], 403)
        self.assertEqual(self.request('/engines', 'POST', {})[0], 403)

    def test_csrf_and_cross_origin_rejected_before_body_parsing(self):
        for kwargs in ({'csrf': False}, {'origin': 'https://other.invalid'}, {'origin': None}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.request('/engines', 'POST', {}, **kwargs)[0], 403)
                self.assertEqual(self.reads, 0)

    def test_login_sets_httponly_cookie_and_logout_revokes_session(self):
        status, body, headers = self.request('/session/login', 'POST',
            {'username': 'browser-admin', 'password': 'test-password'}, session=False, csrf=False)
        self.assertEqual(status, 200)
        self.assertIn(b'HttpOnly', headers[b'set-cookie'])
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertNotIn('session_token', body)
        self.assertEqual(self.request('/session/logout', 'POST')[0], 204)
        self.assertEqual(self.request('/session')[0], 401)

    def test_json_body_is_bounded_even_without_content_length(self):
        status, _, _ = self.request('/engines', 'POST', chunks=[b'{' + b'x' * 100000, b'x' * 100000])
        self.assertEqual(status, 413)

    def test_validation_response_does_not_echo_password(self):
        status, body, _ = self.request('/session/login', 'POST',
            {'username': 'a', 'password': 'sensitive-input', 'extra': True}, session=False)
        self.assertEqual(status, 422)
        self.assertNotIn('sensitive-input', json.dumps(body))

    def test_create_requires_explicit_config_and_duplicate_name_is_rejected(self):
        self.assertEqual(self.request('/engines', 'POST', {'adapter_key': 'clamav', 'display_name': 'A', 'config': {}})[0], 422)
        self.create_clamav()
        status, payload, _ = self.request('/engines')
        self.assertEqual(status, 200)
        self.assertEqual(payload['engines'][0]['health']['state'], 'unavailable')
        self.assertNotIn('api_key', payload['engines'][0]['config'])
        self.assertEqual(len(payload['engines']), 1)

    def test_instance_mutations_and_pool_binding_do_not_change_sibling(self):
        first, second = self.create_clamav(), self.create_clamav('ClamAV B')
        self.assertEqual(self.request(f'/engines/{second}/enabled', 'PUT', {'enabled': False})[0], 200)
        pool_id = db.create_worker_pool('Pool A', '{"site":"a"}')
        self.assertEqual(self.request(f'/engines/{second}/placement', 'PUT', {'pool_id': pool_id})[0], 200)
        payload = self.request('/engines')[1]
        self.assertEqual(payload['pools'][0]['name'], 'Pool A')
        self.assertTrue(db.get_engine_instance_by_id(first).enabled)
        self.assertEqual(db.list_engine_instance_worker_pool_bindings(), {second: pool_id})
        self.assertEqual(self.request(f'/engines/{second}', 'DELETE')[0], 204)
        self.assertIsNotNone(db.get_engine_instance_by_id(first))

    def test_secrets_never_return_and_blank_secret_preserves_ciphertext(self):
        key = Fernet.generate_key().decode()
        config = {field.key: field.default for field in ui_api.ADAPTERS['virustotal'].config_fields}
        config['api_key'] = 'synthetic-vendor-secret'
        with patch.dict('os.environ', {'MASP_SECRET_ENCRYPTION_KEY': key}):
            status, body, _ = self.request('/engines', 'POST', {'adapter_key': 'virustotal', 'display_name': 'VT', 'config': config})
            self.assertEqual(status, 201, body)
            instance_id = body['id']
            old = json.loads(db.get_engine_instance_by_id(instance_id).config_json)['api_key_encrypted']
            payload = self.request('/engines')[1]
            self.assertNotIn('synthetic-vendor-secret', json.dumps(payload))
            self.assertNotIn(old, json.dumps(payload))
            config['api_key'] = ''
            self.assertEqual(self.request(f'/engines/{instance_id}/config', 'PUT', {'config': config})[0], 200)
            self.assertEqual(json.loads(db.get_engine_instance_by_id(instance_id).config_json)['api_key_encrypted'], old)

    def test_get_never_runs_a_vendor_connection_probe(self):
        self.create_clamav()
        with patch.object(ui_api, 'test_engine_connection') as probe:
            self.assertEqual(self.request('/engines')[0], 200)
        probe.assert_not_called()

    def test_old_health_is_not_success_after_new_check_request(self):
        instance_id = self.create_clamav()
        db.upsert_worker_node_heartbeat(
            node_id='node-a', display_name='Node A', hostname='node-a', platform='linux',
            agent_version='test', labels_json='{}', capacity=1, advertised_engine_keys_json='["clamav"]',
            runtime_state='idle', active_scan_id=None, process_id=1, last_heartbeat_at=int(time.time()),
        )
        db.ensure_engine_node_health_rows('node-a', {instance_id})
        with db.connect() as connection:
            connection.execute("UPDATE engine_node_health SET ok = 1, last_checked_at = ?, detail = 'old success'", (int(time.time()),))
        status = {'nodes': [{'node_id': 'node-a', 'schedulable': True, 'engine_keys': ['clamav'], 'labels': {}}]}
        with patch.object(ui_api, 'get_worker_status', return_value=status):
            self.assertEqual(self.request('/engines')[1]['engines'][0]['health']['state'], 'healthy')
            code, health, _ = self.request(f'/engines/{instance_id}/checks', 'POST')
            self.assertEqual(code, 202)
            self.assertEqual(health['state'], 'pending')
            self.assertFalse(health['ok'])
            self.assertEqual(self.request('/engines')[1]['engines'][0]['health']['state'], 'pending')
            with db.connect() as connection:
                connection.execute("UPDATE engine_node_health SET check_worker_id = 'node-a:1'")
            self.assertEqual(self.request('/engines')[1]['engines'][0]['health']['state'], 'running')
            with db.connect() as connection:
                connection.execute("UPDATE engine_node_health SET check_worker_id = NULL, ok = 0, last_checked_at = ?, detail = 'CLI unavailable'", (int(time.time()),))
            self.assertEqual(self.request('/engines')[1]['engines'][0]['health']['state'], 'failed')

    def test_wrong_instance_cannot_manage_yara_rules(self):
        instance_id = self.create_clamav()
        self.assertEqual(self.request(f'/engines/{instance_id}/rules')[0], 409)

    def test_inventory_openapi_has_explicit_response_contract(self):
        schema = self.app.openapi()
        response = schema['paths'][ui_api.PREFIX + '/engines']['get']['responses']['200']
        self.assertEqual(response['content']['application/json']['schema']['$ref'], '#/components/schemas/InventoryPayload')

    def test_config_update_after_concurrent_delete_cannot_recreate_instance(self):
        instance_id = self.create_clamav()
        instance = db.get_engine_instance_by_id(instance_id)
        config = json.loads(instance.config_json)
        db.delete_engine_instance_by_id(instance_id)
        with patch.object(ui_api, 'instance_or_404', return_value=instance):
            self.assertEqual(self.request(f'/engines/{instance_id}/config', 'PUT', {'config': config})[0], 404)
        self.assertEqual(db.list_engine_instances(), [])

    def test_update_does_not_read_and_overwrite_unrelated_instance_columns(self):
        instance_id = self.create_clamav()
        with patch.object(db, 'get_engine_instance_by_id', side_effect=AssertionError('must be a partial SQL update')):
            self.assertTrue(db.update_engine_instance_by_id(instance_id, enabled=False))
            self.assertTrue(db.update_engine_instance_by_id(instance_id, config_json='{"mode":"cli"}'))
        updated = db.get_engine_instance_by_id(instance_id)
        self.assertFalse(updated.enabled)
        self.assertEqual(updated.display_name, 'ClamAV A')

    def test_rule_lifecycle_uses_existing_yara_instance(self):
        rules_dir = Path(self.temp.name).resolve() / 'rules'
        rules_dir.mkdir()
        instance_id = db.create_engine_instance('yara', 'YARA', config_json=json.dumps({'rules_dir': str(rules_dir)}))
        with patch('app.services.yara_rules.get_rules_dir', return_value=rules_dir):
            status, payload, _ = self.request(f'/engines/{instance_id}/rules', 'POST', {'filename': 'sample.yar', 'content': 'rule safe { condition: false }'})
            self.assertEqual(status, 201, payload)
            self.assertEqual(len(self.request(f'/engines/{instance_id}/rules')[1]['rules']), 1)
            self.assertEqual(self.request(f'/engines/{instance_id}/rules/sample.yar/toggle', 'POST')[0], 200)
            self.assertEqual(self.request(f'/engines/{instance_id}/rules/sample.yar.disabled', 'DELETE')[0], 204)
            self.assertEqual(list(rules_dir.iterdir()), [])
