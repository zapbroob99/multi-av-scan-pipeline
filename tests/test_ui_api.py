import asyncio
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

from cryptography.fernet import Fernet
from fastapi import FastAPI

from app import APP_VERSION
from app import database as db
from app.models import StoredSample, EngineResultInput
from app.services import auth, ui_api
from app.services import dashboard_read, archive_read, batch_read
from app.services import scan_report_read, scan_assessment
from app.services import scan_management
from app.services import batch_payload
from app.services import scan_report_read as scan_report_read
from app.services import browser_db_budget
from app.services import system_read
from app.services import retention_admin
from app.services import scan_policy, scan_policy_admin
from app.services import hash_console
from app.services import audit_read, about_read


class BrowserApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original = (db.DB_PATH, db.DATABASE_URL)
        db.DB_PATH, db.DATABASE_URL = Path(self.temp.name) / 'browser.db', ''
        db.init_db()
        dashboard_read._summary_cache = None
        system_read._summary_cache = system_read._metrics_cache = None
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
                content_type='application/json', content_length=None, raw=False):
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
        if raw:
            return start['status'], data, dict(start['headers'])
        return start['status'], json.loads(data) if data else None, dict(start['headers'])

    def create_clamav(self, name='ClamAV A'):
        status, body, _ = self.request('/engines', 'POST', {
            'adapter_key': 'clamav', 'display_name': name,
            'config': {'mode': 'clamd', 'host': 'clamav.internal', 'port': '3310',
                       'timeout_seconds': '60', 'max_file_size_bytes': '52428800'},
        })
        self.assertEqual(status, 201, body)
        return body['id']

    def test_user_management_prebody_guards_and_revision_contract(self):
        target = db.create_user('managed', auth.hash_password('managed-password'), 'analyst')
        path = f'/users/{target}'
        for method, body in [('PUT', {'expected_revision': 0, 'role': 'admin'}), ('DELETE', {'expected_revision': 0})]:
            for options in ({'session': False}, {'csrf': False}, {'origin': 'http://evil'}):
                self.assertIn(self.request(path, method, body, **options)[0], (401, 403))
                self.assertEqual(self.reads, 0)
            self.assertEqual(self.request(path, method, {**body, 'expected_revision': True})[0], 422)
            self.assertEqual(self.request(path, method, {**body, 'extra': 'private-password'})[0], 422)
        self.assertEqual(self.request(path, 'PUT', {'expected_revision': 0, 'role': 'admin', 'password': 'short'})[0], 422)
        self.assertEqual(self.request(path, 'PUT', {'expected_revision': 0, 'role': 'admin'})[0], 204)
        self.assertEqual(next(row for row in self.request('/users')[1]['items'] if row['id'] == target)['management_revision'], 1)
        self.assertEqual(self.request(path, 'DELETE', {'expected_revision': 0})[0], 409)
        self.assertEqual(self.request(f'/users/{self.user_id}', 'DELETE', {'expected_revision': 0})[0], 403)
        db.update_user(self.user_id, 'analyst')
        self.assertEqual(self.request(path, 'DELETE', {'expected_revision': 1})[0], 403)
        self.assertEqual(self.reads, 0)

    def test_user_management_reset_omits_secret_and_deletes_account(self):
        target = db.create_user('managed', auth.hash_password('managed-password'), 'analyst')
        old = auth.login('managed', 'managed-password')
        path = f'/users/{target}'
        status, body, _ = self.request(path, 'PUT', {'expected_revision': 0, 'role': 'analyst', 'password': 'replacement-password'})
        self.assertEqual(status, 204)
        self.assertIsNone(body)
        self.assertIsNone(db.get_user_by_session(auth.hash_session_token(old.session_token), int(time.time())))
        self.assertIsNotNone(auth.login('managed', 'replacement-password'))
        self.assertNotIn('replacement-password', json.dumps(self.request('/users')[1]))
        self.assertEqual(self.request(path, 'DELETE', {'expected_revision': 1})[0], 204)
        self.assertIsNone(db.get_user_by_id(target))

    def test_account_prebody_auth_csrf_and_strict_password_fields(self):
        body = dict(current_password='test-password', new_password='new-test-password', confirm_password='new-test-password')
        self.assertEqual(self.request('/account', session=False)[0], 401)
        for options in ({'session': False}, {'csrf': False}, {'origin': 'http://evil'}):
            self.assertIn(self.request('/account/password', 'POST', body, **options)[0], (401, 403))
            self.assertEqual(self.reads, 0)
        for invalid in ({**body, 'user_id': 999}, {**body, 'new_password': 'short'},
                        {**body, 'current_password': 'x' * 4097}, {**body, 'confirm_password': 123}):
            status, payload, _ = self.request('/account/password', 'POST', invalid)
            self.assertEqual(status, 422)
            self.assertNotIn('test-password', json.dumps(payload))
        self.assertEqual(self.request('/account/password', 'POST', {**body, 'current_password': 'wrong-password'})[0], 403)
        self.assertEqual(self.request('/account/password', 'POST', {**body, 'confirm_password': 'different-password'})[0], 422)
        self.assertEqual(self.request('/account/password', 'POST', {
            **body, 'new_password': 'test-password', 'confirm_password': 'test-password'})[0], 422)
        self.assertEqual(self.request('/session')[0], 200)

    def test_account_analyst_change_revokes_all_sessions_and_clears_cookie(self):
        db.update_user(self.user_id, 'analyst')
        other_session = auth.login('browser-admin', 'test-password')
        status, payload, headers = self.request('/account')
        self.assertEqual(status, 200)
        self.assertEqual(payload, dict(user_id=self.user_id, username='browser-admin', role='analyst', auth_source='local'))
        self.assertEqual(headers[b'cache-control'], b'no-store')
        with patch.object(ui_api, 'set_audit_context', wraps=ui_api.set_audit_context) as audit:
            status, payload, headers = self.request('/account/password', 'POST', dict(
                current_password='test-password', new_password='new-test-password', confirm_password='new-test-password'))
        self.assertEqual(status, 204)
        self.assertIsNone(payload)
        self.assertIn(b'Max-Age=0', headers[b'set-cookie'])
        self.assertEqual(audit.call_args.kwargs['action'], 'user.password_change')
        self.assertNotIn('new-test-password', str(audit.call_args.kwargs.get('details', {})))
        self.assertEqual(self.request('/session')[0], 401)
        self.assertIsNone(db.get_user_by_session(auth.hash_session_token(other_session.session_token), int(time.time())))
        self.assertIsNone(auth.login('browser-admin', 'test-password'))
        self.assertEqual(auth.login('browser-admin', 'new-test-password').user.role, 'analyst')

    def test_account_directory_metadata_omits_private_identity_and_denies_change(self):
        with db.connect() as connection:
            connection.execute("UPDATE users SET auth_source = 'ldap', external_id = 'PRIVATE-DN', password_hash = '!ldap' WHERE id = ?", (self.user_id,))
        status, payload, _ = self.request('/account')
        self.assertEqual(status, 200)
        self.assertEqual(payload['auth_source'], 'ldap')
        self.assertNotIn('PRIVATE', json.dumps(payload))
        self.assertNotIn('!ldap', json.dumps(payload))
        self.assertEqual(self.request('/account/password', 'POST', dict(
            current_password='test-password', new_password='new-test-password', confirm_password='new-test-password'))[0], 403)
        self.assertEqual(self.request('/session')[0], 200)

    def test_pool_crud_validation_identity_and_assignment_protection(self):
        path = '/system/pools'
        body = {'name': ' Istanbul ', 'selector': 'site=istanbul,os=windows'}
        status, created, _ = self.request(path, 'POST', body)
        self.assertEqual(status, 201)
        pool_id = created['id']
        self.assertEqual(db.get_worker_pool(pool_id).name, 'Istanbul')
        self.assertEqual(json.loads(db.get_worker_pool(pool_id).selector_json), {'site': 'istanbul', 'os': 'windows'})
        self.assertEqual(self.request(path, 'POST', body)[0], 422)
        for invalid in ({'name': ' ', 'selector': 'site=x'}, {'name': 'X', 'selector': '{}'},
                        {'name': 'X', 'selector': 'invalid'}, {'name': 'X', 'selector': ' '},
                        {'name': 'X', 'selector': 'x=' + 'a' * 4096}, {**body, 'command': 'no'}):
            self.assertEqual(self.request(path, 'POST', invalid)[0], 422)
        other = db.create_worker_pool('Other', '{"site":"other"}')
        update = {'name': 'Changed', 'selector': '{"site":"lab"}', 'enabled': False}
        self.assertEqual(self.request(f'{path}/{pool_id}', 'PUT', update)[0], 200)
        self.assertFalse(db.get_worker_pool(pool_id).enabled)
        self.assertTrue(db.get_worker_pool(other).enabled)
        self.assertEqual(self.request(f'{path}/99999', 'PUT', {**update, 'name': 'Missing'})[0], 404)
        engine_id = self.create_clamav()
        db.set_engine_instance_worker_pool(engine_id, pool_id)
        self.assertTrue(self.request(path)[1]['items'][0]['has_assignments'])
        self.assertEqual(self.request(f'{path}/{pool_id}', 'DELETE')[0], 409)
        self.assertIsNotNone(db.get_worker_pool(pool_id))
        if db.psycopg is not None:
            with patch.object(db, 'delete_worker_pool', side_effect=db.psycopg.errors.ForeignKeyViolation('concurrent assignment')):
                self.assertEqual(self.request(f'{path}/{pool_id}', 'DELETE')[0], 409)
        db.set_engine_instance_worker_pool(engine_id, None)
        self.assertEqual(self.request(f'{path}/{pool_id}', 'DELETE')[0], 204)
        self.assertEqual(self.request(f'{path}/{pool_id}', 'DELETE')[0], 404)
        self.assertIsNotNone(db.get_worker_pool(other))

    def test_pool_routes_enforce_prebody_admin_csrf(self):
        paths = [('/system/pools', 'POST', {'name': 'Pool', 'selector': 'site=lab'}),
                 ('/system/pools/1', 'PUT', {'name': 'Pool', 'selector': 'site=lab', 'enabled': True}),
                 ('/system/pools/1', 'DELETE', None)]
        self.assertEqual(self.request('/system/pools', session=False)[0], 401)
        for path, method, body in paths:
            self.assertEqual(self.request(path, method, body, session=False)[0], 401)
            self.assertEqual(self.reads, 0)
            self.assertEqual(self.request(path, method, body, csrf=False)[0], 403)
            self.assertEqual(self.reads, 0)
            self.assertEqual(self.request(path, method, body, origin='http://evil')[0], 403)
        with db.connect() as connection:
            connection.execute('UPDATE users SET role = ? WHERE id = ?', ('analyst', self.user_id))
        self.assertEqual(self.request('/system/pools')[0], 403)
        for path, method, body in paths:
            self.assertEqual(self.request(path, method, body)[0], 403)
            self.assertEqual(self.reads, 0)

    def test_pool_pages_bound_metadata_and_allow_deleted_cursor(self):
        first = db.create_worker_pool('A', '{"site":"a"}')
        second = db.create_worker_pool('B', 'x' * 10000)
        third = db.create_worker_pool('C', '[]')
        page = self.request('/system/pools?limit=1')[1]
        self.assertEqual(page['next_after'], first)
        db.delete_worker_pool(first)
        page = self.request(f'/system/pools?limit=1&after={first}')[1]
        self.assertEqual(page['items'][0]['id'], second)
        self.assertTrue(page['items'][0]['metadata_incomplete'])
        self.assertEqual(page['items'][0]['selector'], '')
        last = self.request(f'/system/pools?after={second}')[1]
        self.assertEqual(last['items'][0]['id'], third)
        self.assertTrue(last['items'][0]['metadata_incomplete'])
        self.assertIsNone(last['next_after'])
        for query in ('limit=0', 'limit=101', 'after=0', 'after=9007199254740992'):
            self.assertEqual(self.request('/system/pools?' + query)[0], 422)

    def create_worker(self, node_id='node-a', **overrides):
        values = dict(node_id=node_id, display_name=node_id, hostname='host', platform='windows',
            agent_version='test', labels_json='{"site":"lab"}', capacity=2,
            advertised_engine_keys_json='["microsoft_defender"]', runtime_state='idle',
            active_scan_id=None, process_id=1, last_heartbeat_at=int(time.time()))
        values.update(overrides)
        return db.upsert_worker_node_heartbeat(**values)

    def test_system_workers_are_admin_only_and_mutations_require_csrf(self):
        self.create_worker()
        reads = '/system/workers'
        writes = [('/system/workers/lifecycle', {'node_id': 'node-a', 'lifecycle_state': 'draining'}),
                  ('/system/workers/credentials/revoke', {'node_id': 'node-a'})]
        self.assertEqual(self.request(reads, session=False)[0], 401)
        for path, body in writes:
            self.assertEqual(self.request(path, 'POST', body, session=False)[0], 401)
            self.assertEqual(self.reads, 0)
            self.assertEqual(self.request(path, 'POST', body, csrf=False)[0], 403)
            self.assertEqual(self.reads, 0)
            self.assertEqual(self.request(path, 'POST', body, origin='https://elsewhere.invalid')[0], 403)
            self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(reads)[0], 403)
        for path, body in writes:
            self.assertEqual(self.request(path, 'POST', body)[0], 403)
            self.assertEqual(self.reads, 0)
        self.assertEqual(db.get_worker_node('node-a').lifecycle_state, 'active')

    def test_system_workers_use_bounded_keyset_and_separate_heartbeat_from_lifecycle(self):
        self.create_worker('node-a')
        self.create_worker('node-b', last_heartbeat_at=1, labels_json='x' * 5000)
        db.update_worker_node_lifecycle('node-b', 'draining')
        self.create_worker('node-c')
        db.create_worker_agent_credential(node_id='node-a', token_hash='private-hash', token_prefix='private-prefix')
        status, first, headers = self.request('/system/workers?limit=1')
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(first['next_after'], 'node-a')
        self.assertTrue(first['items'][0]['online'])
        self.assertNotIn('private', json.dumps(first))
        self.assertEqual(first['items'][0]['labels'], {'site': 'lab'})
        second = self.request('/system/workers?limit=1&after=node-a')[1]
        node = second['items'][0]
        self.assertEqual(node['node_id'], 'node-b')
        self.assertEqual(node['lifecycle_state'], 'draining')
        self.assertFalse(node['online'])
        self.assertTrue(node['metadata_incomplete'])
        self.assertEqual(node['labels'], {})
        with db.connect() as connection:
            connection.execute("DELETE FROM worker_nodes WHERE node_id = 'node-b'")
        last = self.request('/system/workers?limit=1&after=node-b')[1]
        self.assertEqual(last['items'][0]['node_id'], 'node-c')
        self.assertIsNone(last['next_after'])
        for query in ('limit=0', 'limit=101', 'after=' + 'x' * 129):
            self.assertEqual(self.request('/system/workers?' + query)[0], 422)

    def test_system_worker_actions_preserve_identity_and_heartbeat_lifecycle(self):
        self.create_worker('node-a')
        self.create_worker('node-b')
        for node in ('node-a', 'node-b'):
            db.create_worker_agent_credential(node_id=node, token_hash=f'hash-{node}', token_prefix='secret')
        path = '/system/workers/lifecycle'
        for body in ({'node_id': 'node-a', 'lifecycle_state': 'offline'},
                     {'node_id': 'node-a', 'lifecycle_state': 'draining', 'extra': True}):
            self.assertEqual(self.request(path, 'POST', body)[0], 422)
        self.assertEqual(self.request(path, 'POST', {'node_id': 'absent', 'lifecycle_state': 'active'})[0], 404)
        status, payload, _ = self.request(path, 'POST', {'node_id': 'node-a', 'lifecycle_state': 'draining'})
        self.assertEqual((status, payload), (200, {'node_id': 'node-a', 'lifecycle_state': 'draining'}))
        self.create_worker('node-a')
        self.assertEqual(db.get_worker_node('node-a').lifecycle_state, 'draining')
        self.assertEqual(db.get_worker_node('node-b').lifecycle_state, 'active')
        path = '/system/workers/credentials/revoke'
        status, payload, _ = self.request(path, 'POST', {'node_id': 'node-a'})
        self.assertEqual((status, payload), (200, {'node_id': 'node-a', 'revoked_count': 1}))
        self.assertIsNone(db.authenticate_worker_agent_credential('hash-node-a'))
        self.assertIsNotNone(db.authenticate_worker_agent_credential('hash-node-b'))
        self.assertEqual(self.request(path, 'POST', {'node_id': 'node-a'})[0], 409)

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

    def test_active_queue_is_admin_only_and_validates_cursors(self):
        self.assertEqual(self.request('/system/queue', session=False)[0], 401)
        for query in ('limit=0', 'limit=101', 'after=0', 'after=9007199254740992'):
            self.assertEqual(self.request('/system/queue?' + query)[0], 422)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/system/queue')[0], 403)

    def test_active_queue_projects_all_sources_without_private_fields(self):
        ids = [self.create_scan(name='x' * 600, source=source, status=status)
            for source, status in [('manual', 'queued'), ('api', 'running'), ('icap', 'finalizing')]]
        self.create_scan(status='completed')
        self.create_scan(status='failed')
        status, page, headers = self.request('/system/queue?limit=2')
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual([row['id'] for row in page['items']], ids[:2])
        self.assertEqual(len(page['items'][0]['filename']), 512)
        self.assertEqual(set(page['items'][0]), {'id', 'filename', 'source', 'status', 'priority', 'created_at'})
        self.assertNotIn('/private/storage', json.dumps(page))
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET status = 'completed' WHERE id = ?", (ids[1],))
        last = self.request('/system/queue?after=' + str(page['next_after']))[1]
        self.assertEqual([row['id'] for row in last['items']], ids[2:])
        self.assertIsNone(last['next_after'])

    def test_active_queue_index_is_restored_on_upgrade(self):
        with db.connect() as connection:
            connection.execute('DROP INDEX idx_scan_jobs_active_seek')
        db.init_db()
        with db.connect() as connection:
            plan = connection.execute("EXPLAIN QUERY PLAN SELECT id FROM scan_jobs WHERE status IN ('queued', 'running', 'finalizing') AND id > ? ORDER BY id LIMIT ?", (1, 21)).fetchall()
        self.assertIn('idx_scan_jobs_active_seek', str([dict(row) for row in plan]))

    def test_system_aggregates_require_admin_and_bound_metrics_pages(self):
        for path in ('/system/summary', '/system/engine-metrics'):
            self.assertEqual(self.request(path, session=False)[0], 401)
        for query in ('limit=0', 'limit=101', 'after=0', 'after=9007199254740992'):
            self.assertEqual(self.request('/system/engine-metrics?' + query)[0], 422)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        for path in ('/system/summary', '/system/engine-metrics'):
            self.assertEqual(self.request(path)[0], 403)

    def test_system_summary_counts_sources_and_separates_liveness_from_lifecycle(self):
        self.create_scan(source='api', status='finalizing')
        self.create_scan(source='manual', status='completed')
        self.create_worker('online')
        self.create_worker('offline', last_heartbeat_at=1)
        self.create_worker('draining')
        db.update_worker_node_lifecycle('draining', 'draining')
        with patch.dict('os.environ', {'MASP_RETENTION_DAYS': '30', 'MASP_RETENTION_BATCH_SIZE': '10'}):
            status, result, headers = self.request('/system/summary')
            self.assertEqual(status, 200)
            self.assertEqual(headers[b'cache-control'], b'no-store')
            self.assertEqual((result['total'], result['finalizing'], result['completed']), (2, 1, 1))
            self.assertEqual((result['registered_nodes'], result['online_nodes'], result['active_online_nodes']), (3, 2, 1))
            self.assertEqual((result['retention_days'], result['retention_batch_size']), (30, 10))
            with patch.object(db, 'connect', side_effect=AssertionError('Cache miss')):
                self.assertEqual(system_read.summary().total, 2)

    def test_engine_metrics_preserve_recorded_names_and_never_select_raw_output(self):
        one = self.create_scan(source='manual', status='completed')
        two = self.create_scan(source='api', status='failed')
        for scan, name, status, detected, duration in ((one, 'Old name', 'completed', True, 10),
                (two, 'Old name', 'failed', False, 30), (one, 'x' * 600, 'skipped', False, 0)):
            db.create_engine_result(scan, EngineResultInput(name, status, detected, 'info', 0, None, 'PRIVATE_OUTPUT', duration))
        _, first, headers = self.request('/system/engine-metrics?limit=1')
        self.assertEqual(headers[b'cache-control'], b'no-store')
        row = first['items'][0]
        self.assertEqual((row['total'], row['completed'], row['failed'], row['detections']), (2, 1, 1, 1))
        self.assertEqual(row['avg_duration_ms'], 20)
        with db.connect() as connection:
            latest = connection.execute("SELECT MAX(created_at) AS at FROM engine_results WHERE engine_name = 'Old name'").fetchone()['at']
        self.assertEqual(row['last_result_at'], str(latest))
        self.assertNotIn('PRIVATE_OUTPUT', json.dumps(first))
        with patch.object(db, 'connect', side_effect=AssertionError('Cache miss')):
            self.assertEqual(system_read.metrics(limit=1, after=None).items[0].total, 2)
        second = self.request('/system/engine-metrics?limit=1&after=' + str(first['next_after']))[1]
        self.assertEqual(len(second['items'][0]['engine_name']), 512)
        self.assertTrue(second['items'][0]['name_truncated'])
        self.assertIsNone(second['next_after'])

    def test_system_summary_uses_one_read_snapshot(self):
        self.create_scan(status='queued')
        self.create_worker('before')
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
                if 'FROM worker_nodes' in sql and not fired:
                    fired = True
                    with original() as writer:
                        writer.execute("UPDATE scan_jobs SET status = 'completed'")
                        writer.execute("UPDATE worker_nodes SET lifecycle_state = 'disabled'")
                return self.connection.execute(sql, params)
        with patch.object(db, 'connect', return_value=Reader()):
            result = system_read.summary()
        self.assertTrue(fired)
        self.assertEqual((result.queued, result.active_online_nodes), (1, 1))
        system_read._summary_cache = None
        result = system_read.summary()
        self.assertEqual((result.completed, result.active_online_nodes), (1, 0))

    def test_scan_policy_auth_validation_and_no_partial_invalid_save(self):
        body = {'api_max_wait_seconds': '20', 'api_retry_after_seconds': '3', 'upload_max_bytes': ''}
        self.assertEqual(self.request('/scan-policy', session=False)[0], 401)
        for options, expected in (({'session': False}, 401), ({'csrf': False}, 403)):
            self.assertEqual(self.request('/scan-policy', 'PUT', body, **options)[0], expected)
            self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/scan-policy')[0], 403)
        self.assertEqual(self.request('/scan-policy', 'PUT', body)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'admin' WHERE id = ?", (self.user_id,))
        for change in ({'api_retry_after_seconds': '0'}, {'upload_max_bytes': str(5 * 1024**3 + 1)},
                       {'api_max_wait_seconds': True}, {'api_max_wait_seconds': '1.5'},
                       {'upload_max_bytes': '1' * 129}, {'command': 'no'}):
            self.assertEqual(self.request('/scan-policy', 'PUT', body | change)[0], 422)
            self.assertIsNone(db.get_setting('scan_policy.api_max_wait_seconds'))
        self.assertEqual(self.request('/scan-policy', 'PUT', {})[0], 422)

    @patch.dict('os.environ', {'MASP_API_MAX_WAIT_SECONDS': '25', 'MASP_API_RETRY_AFTER_SECONDS': '', 'MASP_UPLOAD_MAX_BYTES': '4096'})
    def test_scan_policy_shared_resolution_save_clear_and_secret_omission(self):
        db.set_setting('integration.private', 'PRIVATE_TOKEN')
        db.set_setting('scan_policy.api_max_wait_seconds', '900')
        status, result, headers = self.request('/scan-policy')
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(len(result['fields']), 3)
        self.assertEqual(result['fields'][0]['value'], scan_policy.resolve_int('api_max_wait_seconds'))
        self.assertEqual(result['fields'][0]['value'], 300)
        self.assertNotIn('PRIVATE_TOKEN', json.dumps(result))
        body = {'api_max_wait_seconds': '0', 'api_retry_after_seconds': '30', 'upload_max_bytes': str(5 * 1024**3)}
        self.assertEqual(self.request('/scan-policy', 'PUT', body)[0], 204)
        self.assertEqual(scan_policy.resolve_int('upload_max_bytes'), 5 * 1024**3)
        self.assertEqual(self.request('/scan-policy', 'PUT', {key: '' for key in body})[0], 204)
        result = self.request('/scan-policy')[1]
        self.assertEqual([field['value'] for field in result['fields']], [25, 2, 4096])
        self.assertEqual(result['fields'][0]['source'], 'environment (MASP_API_MAX_WAIT_SECONDS)')

    def test_scan_policy_oversized_stored_value_fails_closed(self):
        db.set_setting('scan_policy.api_max_wait_seconds', '9' * 129)
        self.assertEqual(self.request('/scan-policy')[0], 409)

    def test_scan_policy_rolls_back_whole_save_on_database_failure(self):
        db.set_setting('scan_policy.api_max_wait_seconds', '10')
        with db.connect() as connection:
            connection.execute('''CREATE TRIGGER reject_policy BEFORE INSERT ON app_settings
                WHEN NEW.key = 'scan_policy.api_retry_after_seconds'
                BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END''')
        body = scan_policy_admin.ScanPolicyBody(api_max_wait_seconds='30', api_retry_after_seconds='3', upload_max_bytes='100')
        with self.assertRaises(db.IntegrityViolation):
            scan_policy_admin.save(body)
        self.assertEqual(db.get_setting('scan_policy.api_max_wait_seconds'), '10')
        self.assertIsNone(db.get_setting('scan_policy.upload_max_bytes'))

    def test_hash_lookup_auth_csrf_validation_and_manual_source(self):
        body = {'sha256': 'a' * 64}
        with patch.object(hash_console, 'enabled_hash_engines', return_value=[]) as engines:
            self.assertEqual(self.request('/hash-scan/options', session=False)[0], 401)
            self.assertEqual(self.request('/hash-scan', 'POST', body, session=False)[0], 401)
            self.assertEqual(self.reads, 0)
            self.assertEqual(self.request('/hash-scan', 'POST', body, csrf=False)[0], 403)
            self.assertEqual(self.reads, 0)
            engines.assert_not_called()
            with db.connect() as connection:
                connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
            self.assertEqual(self.request('/hash-scan/options')[0], 200)
            engines.assert_called_with(source='manual')
            self.assertEqual(self.request('/hash-scan', 'POST', body)[0], 409)
            for value in ('x' * 64, 'a' * 63, 'a' * 129, 123):
                self.assertEqual(self.request('/hash-scan', 'POST', {'sha256': value})[0], 422)
            self.assertEqual(self.request('/hash-scan', 'POST', body | {'source': 'api'})[0], 422)

    def test_hash_lookup_uses_backend_decisions_and_omits_provider_data(self):
        from types import SimpleNamespace
        from app.services.hash_scanning import HashEngineExecution
        engine = SimpleNamespace(id=7, display_name='<script>Engine</script>', adapter_key='virustotal')
        for action in ('allow', 'review', 'block'):
            execution = HashEngineExecution(EngineResultInput('engine', 'completed', action == 'block', 'info', 0, None, 'PRIVATE_TOKEN', 1),
                {'decision': {'action': action, 'reason': 'PRIVATE_TOKEN'}, 'found': action != 'review', 'raw': 'PRIVATE_TOKEN'})
            with patch.object(hash_console, 'enabled_hash_engines', return_value=[engine]), patch.object(hash_console, 'run_hash_engine', return_value=execution) as run:
                status, result, headers = self.request('/hash-scan', 'POST', {'sha256': 'A' * 64})
            self.assertEqual(status, 200)
            self.assertEqual(result['action'], action)
            self.assertEqual(result['sha256'], 'a' * 64)
            self.assertNotIn('PRIVATE_TOKEN', json.dumps(result))
            self.assertEqual(headers[b'cache-control'], b'no-store')
            run.assert_called_once_with(engine, 'a' * 64)

    def test_hash_lookup_projects_bounded_provider_detail(self):
        from types import SimpleNamespace
        from app.services.hash_scanning import HashEngineExecution
        engine = SimpleNamespace(id=7, display_name='Engine', adapter_key='virustotal')
        payload = {'decision': {'action': 'block', 'reason': 'PRIVATE_TOKEN'}, 'found': True, 'status': 'malicious',
                   'stats': {'malicious': 12, 'suspicious': 1, 'undetected': 50, 'harmless': 3, 'total': 70, 'timeout': 'x'},
                   'last_analysis_date': '2026-09-20T10:00:00+00:00', 'cached': True,
                   'permalink': 'https://www.virustotal.com/gui/file/' + 'a' * 64, 'policy': {'api_key': 'PRIVATE_TOKEN'}}
        execution = HashEngineExecution(EngineResultInput('engine', 'completed', True, 'high', 0, None, '', 42), payload)
        with patch.object(hash_console, 'enabled_hash_engines', return_value=[engine]), patch.object(hash_console, 'run_hash_engine', return_value=execution):
            row = self.request('/hash-scan', 'POST', {'sha256': 'a' * 64})[1]['results'][0]
        self.assertEqual(row['status'], 'malicious')
        self.assertEqual(row['stats'], {'malicious': 12, 'suspicious': 1, 'undetected': 50, 'harmless': 3, 'total': 70})
        self.assertEqual((row['last_analysis_date'], row['cached'], row['duration_ms']), ('2026-09-20T10:00:00+00:00', True, 42))
        self.assertTrue(row['permalink'].startswith('https://www.virustotal.com/'))
        self.assertNotIn('PRIVATE_TOKEN', json.dumps(row))
        hostile = payload | {'status': '<script>', 'permalink': 'javascript:alert(1)', 'cached': 'yes',
                             'stats': {'malicious': -5, 'total': True}, 'last_analysis_date': 7}
        execution = HashEngineExecution(EngineResultInput('engine', 'completed', True, 'high', 0, None, '', 1), hostile)
        with patch.object(hash_console, 'enabled_hash_engines', return_value=[engine]), patch.object(hash_console, 'run_hash_engine', return_value=execution):
            row = self.request('/hash-scan', 'POST', {'sha256': 'a' * 64})[1]['results'][0]
        self.assertEqual(row['status'], 'other')
        self.assertIsNone(row['permalink'])
        self.assertIsNone(row['cached'])
        self.assertIsNone(row['last_analysis_date'])
        self.assertEqual(row['stats'], {'malicious': 0, 'suspicious': 0, 'undetected': 0, 'harmless': 0, 'total': 0})

    def test_hash_lookup_caps_engine_count_and_sanitizes_failures(self):
        from types import SimpleNamespace
        from app.services.hash_scanning import HashEngineQuotaError
        engine = SimpleNamespace(id=7, display_name='Engine', adapter_key='virustotal')
        with patch.object(hash_console, 'enabled_hash_engines', return_value=[engine] * 17), patch.object(hash_console, 'run_hash_engine') as run:
            self.assertEqual(self.request('/hash-scan', 'POST', {'sha256': 'a' * 64})[0], 409)
            run.assert_not_called()
        quota = HashEngineQuotaError('PRIVATE_TOKEN')
        quota.retry_after = 30
        for error, expected in ((quota, 503), (ValueError('PRIVATE_TOKEN'), 502)):
            with patch.object(hash_console, 'enabled_hash_engines', return_value=[engine]), patch.object(hash_console, 'run_hash_engine', side_effect=error) as run:
                status, result, headers = self.request('/hash-scan', 'POST', {'sha256': 'a' * 64})
            self.assertEqual(status, expected)
            self.assertNotIn('PRIVATE_TOKEN', json.dumps(result))
            self.assertNotIn('action', result)
            self.assertEqual(run.call_count, 1)
            if error is quota:
                self.assertEqual(headers[b'retry-after'], b'30')
        from app.services.hash_scanning import HashEngineExecution
        first = HashEngineExecution(EngineResultInput('engine', 'completed', False, 'info', 0, None, '', 1),
            {'decision': {'action': 'allow'}, 'found': True})
        with patch.object(hash_console, 'enabled_hash_engines', return_value=[engine, engine]), patch.object(hash_console, 'run_hash_engine', side_effect=[first, quota]) as run:
            status, result, _ = self.request('/hash-scan', 'POST', {'sha256': 'a' * 64})
        self.assertEqual(status, 503)
        self.assertNotIn('action', result)
        self.assertEqual(run.call_count, 2)

    def test_service_clients_admin_csrf_and_strict_update(self):
        client = db.create_service_client('test', 'Test')
        body = {'display_name': 'Updated', 'enabled': False}
        self.assertEqual(self.request('/service-clients', session=False)[0], 401)
        self.assertEqual(self.request(f'/service-clients/{client}', 'PUT', body, csrf=False)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/service-clients')[0], 403)
        self.assertEqual(self.request(f'/service-clients/{client}', 'PUT', body)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'admin' WHERE id = ?", (self.user_id,))
        for change in ({'enabled': 'false'}, {'display_name': ' '}, {'display_name': 'x' * 101}, {'client_key': 'other'}, {'token': 'secret'}):
            self.assertEqual(self.request(f'/service-clients/{client}', 'PUT', body | change)[0], 422)
        self.assertEqual(db.get_service_client(client).display_name, 'Test')

    def test_service_client_pages_are_bounded_and_do_not_read_credentials(self):
        one = db.create_service_client('first', 'x' * 101)
        two = db.create_service_client('second', '<script>Second</script>')
        status, first, headers = self.request('/service-clients?limit=1')
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(first['next_after'], one)
        self.assertEqual(len(first['items'][0]['display_name']), 100)
        self.assertTrue(first['items'][0]['metadata_incomplete'])
        # Deleted cursors remain usable. The projection works without a credential table.
        with db.connect() as connection:
            connection.execute('DELETE FROM service_clients WHERE id = ?', (one,))
            connection.execute('DROP TABLE api_client_credentials')
        second = self.request(f'/service-clients?limit=1&after={one}')[1]
        self.assertEqual(second['items'][0]['id'], two)
        self.assertIsNone(second['next_after'])
        self.assertEqual(set(second['items'][0]), {'id', 'client_key', 'display_name', 'enabled', 'managed', 'metadata_incomplete'})
        for query in ('limit=0', 'limit=101', 'after=0', 'after=9007199254740992'):
            self.assertEqual(self.request('/service-clients?' + query)[0], 422)

    def test_service_client_update_is_scoped_and_managed_client_is_protected(self):
        managed = db.create_service_client('legacy-default', 'Managed')
        one = db.create_service_client('one', 'One')
        other = db.create_service_client('other', 'Other')
        body = {'display_name': ' Updated ', 'enabled': False}
        self.assertEqual(self.request(f'/service-clients/{managed}', 'PUT', body)[0], 409)
        self.assertEqual(self.request('/service-clients/999999', 'PUT', body)[0], 409)
        self.assertEqual(self.request(f'/service-clients/{one}', 'PUT', body)[0], 204)
        self.assertEqual((db.get_service_client(one).display_name, db.get_service_client(one).enabled), ('Updated', False))
        self.assertTrue(db.get_service_client(other).enabled)
        self.assertTrue(db.get_service_client(managed).enabled)
        self.assertEqual(db.get_service_client(one).client_key, 'one')

    def test_client_creation_credentials_secrets_atomicity_and_revocation(self):
        from app.services.service_clients import hash_api_token
        engine = db.create_engine_instance('static_metadata', 'Credential engine')
        token = 'synthetic-credential-token-' + 'a' * 32
        body = dict(client_key='new-client', display_name='New client', profile_name='Default',
                    engine_ids=[engine], credential_label='Initial', api_token=token)
        status, created, _ = self.request('/service-clients', 'POST', body)
        self.assertEqual(status, 201, created)
        self.assertEqual(set(created), {'client_id', 'profile_id', 'credential_id'})
        client, credential = created['client_id'], created['credential_id']
        self.assertIsNotNone(db.get_api_client_credential_by_hash(hash_api_token(token), current_time=int(time.time())))
        for bad in ({**body, 'client_key': 'rolled-back'}, body):
            status, error, _ = self.request('/service-clients', 'POST', bad)
            self.assertEqual(status, 409)
            self.assertNotIn(token, json.dumps(error))
        self.assertIsNone(db.get_service_client_by_key('rolled-back'))
        path = f'/service-clients/{client}/credentials'
        status, page, _ = self.request(path)
        self.assertEqual(status, 200)
        self.assertEqual(set(page['items'][0]), {'id', 'label', 'created_at', 'last_used_at', 'revoked_at'})
        self.assertNotIn(token[:8], json.dumps(page))
        other = db.create_service_client('other-client', 'Other')
        self.assertEqual(self.request(f'/service-clients/{other}/credentials/{credential}/revoke', 'POST')[0], 409)
        self.assertIsNotNone(db.get_api_client_credential_by_hash(hash_api_token(token), current_time=int(time.time())))
        self.assertEqual(self.request(f'{path}/{credential}/revoke', 'POST')[0], 204)
        self.assertIsNone(db.get_api_client_credential_by_hash(hash_api_token(token), current_time=int(time.time())))
        self.assertEqual(self.request(f'{path}/{credential}/revoke', 'POST')[0], 409)
        for index in range(22):
            status, added, _ = self.request(path, 'POST', dict(credential_label=f'Extra {index}', api_token=f'{index:032}'))
            self.assertEqual(status, 201, added)
        page = self.request(path)[1]
        self.assertEqual(len(page['items']), 20)
        self.assertEqual(len(self.request(path + '?after=' + str(page['next_after']))[1]['items']), 3)
        self.assertEqual(self.request(f'/service-clients/{other}/credentials')[1]['items'], [])
        self.assertEqual(self.request('/service-clients/999999/credentials')[0], 404)

    def test_credential_routes_prebody_permissions_and_strict_secret_validation(self):
        engine = db.create_engine_instance('static_metadata', 'Credential engine')
        client = db.create_service_client('test-client', 'Test')
        body = dict(client_key='new-client', display_name='New', profile_name='Default',
                    engine_ids=[engine], credential_label='Initial', api_token='s' * 32)
        routes = [('/service-clients', body), (f'/service-clients/{client}/credentials',
                  dict(credential_label='Initial', api_token='s' * 32)),
                  (f'/service-clients/{client}/credentials/1/revoke', None)]
        for path, payload in routes:
            self.assertEqual(self.request(path, 'POST', payload, session=False)[0], 401)
            self.assertEqual(self.reads, 0)
            self.assertEqual(self.request(path, 'POST', payload, csrf=False)[0], 403)
            self.assertEqual(self.reads, 0)
        for change in ({'api_token': 'too-short'}, {'api_token': 'x ' * 32}, {'api_token': 42},
                       {'credential_label': ' '}, {'engine_ids': []}, {'engine_ids': [engine, engine]},
                       {'engine_ids': [999999]}, {'client_key': 'legacy-default'}, {'display_name': ' '},
                       {'token_hash': 'injected'}):
            status, error, _ = self.request('/service-clients', 'POST', {**body, **change})
            self.assertEqual(status, 422, error)
            self.assertNotIn('too-short', json.dumps(error))
        self.assertIsNone(db.get_service_client_by_key('new-client'))
        options = self.request('/service-clients/create-options')[1]
        self.assertFalse(options['incomplete'])
        self.assertEqual(set(options['engines'][0]), {'id', 'display_name', 'adapter_key', 'enabled'})
        with db.connect() as connection:
            connection.execute('UPDATE users SET role = ? WHERE id = ?', ('analyst', self.user_id))
        for path, payload in routes:
            self.assertEqual(self.request(path, 'POST', payload)[0], 403)
            self.assertEqual(self.reads, 0)
        self.assertEqual(self.request('/service-clients/create-options')[0], 403)
        self.assertEqual(self.request(f'/service-clients/{client}/credentials')[0], 403)

    def test_ledger_sources_client_scope_and_deleted_cursor(self):
        one = db.create_service_client('ledger-one', 'Ledger one')
        two = db.create_service_client('ledger-two', 'Ledger two')
        manual = self.create_scan('manual-only.bin')
        api = self.create_scan('api-one.bin', source='api', service_client_id=one)
        icap = self.create_scan('icap-two.bin', source='icap', service_client_id=two, status='finalizing')
        child = self.create_scan('hidden-child.bin', source='api', scan_role='child', service_client_id=one)
        unassigned = self.create_scan('unassigned.bin', source='icap')
        ids = lambda path: [row['id'] for row in self.request(path)[1]['items']]
        self.assertEqual(ids('/api-ledger'), [unassigned, icap, api])
        self.assertEqual(ids(f'/api-ledger?client_id={one}'), [api])
        self.assertEqual(ids('/api-ledger?client_id=999999'), [])
        self.assertEqual(ids('/api-ledger?unassigned=true'), [unassigned])
        self.assertEqual(ids('/api-ledger?source=api'), [api])
        self.assertIn(icap, ids('/api-ledger?status=active'))
        page = self.request('/api-ledger?limit=1')[1]
        self.assertEqual(page['next_before'], unassigned)
        with db.connect() as connection:
            connection.execute('DELETE FROM scan_jobs WHERE id = ?', (unassigned,))
        self.assertEqual(ids(f'/api-ledger?before={unassigned}'), [icap, api])
        self.assertNotIn(child, ids('/api-ledger'))
        self.assertEqual(ids('/dashboard/scans'), [manual])
        self.assertEqual(self.request(f'/scans/{api}')[0], 404)

    def test_ledger_projection_literal_search_no_engine_hydration(self):
        client = db.create_service_client('ledger-long', 'x' * 300)
        scan = self.create_scan('literal%_!.bin' + 'x' * 600, source='api', service_client_id=client,
                                status='completed', verdict='critical', risk_score=90)
        self.create_scan('other.bin', source='api')
        with db.connect() as connection:
            connection.execute('DROP TABLE engine_results')
        status, page, _ = self.request('/api-ledger?q=%25_!&risk=critical')
        self.assertEqual(status, 200)
        row = page['items'][0]
        self.assertEqual(row['id'], scan)
        self.assertEqual(len(row['filename']), 512)
        self.assertEqual(len(row['client_name']), 100)
        self.assertEqual(row['risk_score'], 90)
        self.assertNotIn('storage_path', row)
        self.assertNotIn('profile_snapshot_json', row)
        self.assertNotIn('internal note', json.dumps(page))

    def test_ledger_browser_auth_analyst_and_invalid_filters(self):
        self.assertEqual(self.request('/api-ledger', session=False)[0], 401)
        for query in ('limit=101', 'limit=0', 'before=0', 'client_id=0', 'source=manual',
                      'status=bogus', 'risk=clean', 'client_id=1&unassigned=true', 'q=' + 'a' * 201):
            self.assertEqual(self.request('/api-ledger?' + query)[0], 422, query)
        with db.connect() as connection:
            connection.execute('UPDATE users SET role = ? WHERE id = ?', ('analyst', self.user_id))
        status, _, headers = self.request('/api-ledger')
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(self.request('/service-clients')[0], 403)

    def test_automation_report_output_scope_policy_and_permissions(self):
        scan, result = self.report_fixture()
        other, other_result = self.report_fixture()
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'icap' WHERE id = ?", (scan,))
        path = f'/api-ledger/scans/{scan}'
        self.assertEqual(self.request(path, session=False)[0], 401)
        self.assertEqual(self.request(f'/scans/{scan}')[0], 404)
        self.assertEqual(self.request(f'/api-ledger/scans/{other}')[0], 404)
        for suffix in ('', '/full'):
            self.assertEqual(self.request(f'{path}/results/{result}{suffix}')[0], 200)
            self.assertEqual(self.request(f'{path}/results/{other_result}{suffix}')[0], 404)
            self.assertEqual(self.request(f'/scans/{scan}/results/{result}{suffix}')[0], 404)
        report = self.request(path)[1]
        self.assertEqual(report['source'], 'icap')
        self.assertEqual(report['coverage_basis'], 'routing_snapshot')
        self.assertNotIn('storage_path', report)
        self.assertEqual(report['required_engines'], 1)
        with db.connect() as connection:
            connection.execute("UPDATE engine_results SET details_json = ? WHERE id = ?", ('[]', result))
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertIsNone(self.request(path)[1]['decision'])
        self.assertEqual(self.request(f'{path}/results/{result}/full')[0], 200)
        with db.connect() as connection:
            connection.execute("UPDATE engine_results SET raw_output = ? WHERE id = ?", ('x' * (2 * 1024 * 1024 + 1), result))
        self.assertEqual(self.request(f'{path}/results/{result}/full')[0], 413)

    def test_automation_batch_source_owner_cursor_and_manual_isolation(self):
        client = db.create_service_client('auto-batch', 'Batch client')
        other = db.create_service_client('other-batch', 'Other')
        batch = db.create_scan_batch(source='api', original_filename='bundle.zip', archive_mode='lazy_extract_on_detection', service_client_id=client)
        first = self.create_scan('one.bin', source='api', batch_id=batch, service_client_id=client)
        second = self.create_scan('two.bin', source='api', batch_id=batch, service_client_id=client, parent_scan_id=first, scan_role='child')
        self.create_scan('wrong-owner.bin', source='api', batch_id=batch, service_client_id=other)
        self.create_scan('wrong-source.bin', source='icap', batch_id=batch, service_client_id=client)
        self.create_scan('manual.bin', batch_id=batch)
        path = f'/api-ledger/batches/{batch}'
        self.assertEqual(self.request(path, session=False)[0], 401)
        self.assertEqual(self.request(f'/batches/{batch}')[0], 404)
        page = self.request(path + '?limit=1')[1]
        self.assertEqual([row['id'] for row in page['items']], [first])
        next_page = self.request(path + '?' + urlencode(dict(after_id=page['next_after_id'], after_created=page['next_after_created'])))[1]
        self.assertEqual([row['id'] for row in next_page['items']], [second])
        self.assertEqual(self.request(path + '?after_id=1')[0], 422)
        self.assertEqual(db.get_scan_batch(batch).total_items, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(path)[0], 200)

    def test_automation_delete_admin_csrf_fences_and_protections(self):
        body = {'attempt': 0, 'job_revision': 0}
        scan = self.create_scan(source='api', status='completed')
        path = f'/api-ledger/scans/{scan}'
        for kwargs, expected in (({'session': False}, 401), ({'csrf': False}, 403)):
            self.assertEqual(self.request(path, 'DELETE', body, **kwargs)[0], expected)
            self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(path, 'DELETE', body)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'admin' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(path, 'DELETE', {**body, 'attempt': 1})[0], 409)
        self.assertEqual(self.request(path, 'DELETE', {**body, 'job_revision': 1})[0], 409)
        self.assertEqual(self.request(path, 'DELETE', {**body, 'source': 'manual'})[0], 422)
        manual = self.create_scan(status='completed')
        self.assertEqual(self.request(f'/api-ledger/scans/{manual}', 'DELETE', body)[0], 404)
        self.assertEqual(self.request(f'/scans/{scan}', 'DELETE', body)[0], 404)
        protected = [self.create_scan(source='icap', status=state) for state in ('queued', 'running', 'finalizing')]
        parent = self.create_scan(source='api', status='completed')
        self.create_scan(source='api', parent_scan_id=parent, scan_role='child')
        shared = self.create_scan(source='api', status='completed')
        db.create_scan_job(db.get_scan(shared).sample_id, '', 'normal', '', status='completed')
        pending = self.create_scan(source='icap', status='completed')
        client = db.create_service_client('auto-outbox', 'Outbox')
        with db.connect() as connection:
            connection.execute("INSERT INTO notification_outbox (scan_job_id, service_client_id, event_type, idempotency_key, payload_json) VALUES (?, ?, 'malware.detected', 'auto-event', '{}')", (pending, client))
        with patch.object(scan_management, 'delete_sample_file', side_effect=PermissionError('private')) as cleanup:
            for blocked in [*protected, parent, shared, pending]:
                self.assertEqual(self.request(f'/api-ledger/scans/{blocked}', 'DELETE', body)[0], 409)
            cleanup.assert_not_called()
            status, result, _ = self.request(path, 'DELETE', body)
        self.assertEqual(status, 200)
        self.assertFalse(result['sample_removed'])
        self.assertIsNone(db.get_scan(scan))
        self.assertEqual(self.request(path, 'DELETE', body)[0], 404)

    def test_user_admin_permissions_csrf_and_secret_validation(self):
        body = {'username': 'new-user', 'role': 'analyst', 'password': 'new-secret-password'}
        self.assertEqual(self.request('/users', session=False)[0], 401)
        self.assertEqual(self.request('/users', 'POST', body, csrf=False)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/users')[0], 403)
        self.assertEqual(self.request('/users', 'POST', body)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'admin' WHERE id = ?", (self.user_id,))
        for invalid in ({'role': 'root'}, {'username': '   '}, {'password': 'short'}, {'password': 'x' * 4097}, {'auth_source': 'ldap'}):
            status, result, _ = self.request('/users', 'POST', body | invalid)
            self.assertEqual(status, 422, result)
            self.assertNotIn('new-secret-password', json.dumps(result))
        self.assertIsNone(db.get_user_by_username('new-user'))

    def test_user_creation_hashes_password_preserves_duplicate_and_can_login(self):
        body = {'username': ' new-user ', 'role': 'analyst', 'password': 'new-secret-password'}
        status, created, _ = self.request('/users', 'POST', body)
        self.assertEqual(status, 201, created)
        self.assertEqual(set(created), {'user_id'})
        user = db.get_user_by_id(created['user_id'])
        self.assertEqual(user.auth_source, 'local')
        self.assertEqual(user.username, 'new-user')
        self.assertTrue(auth.verify_password(body['password'], user.password_hash))
        duplicate = body | {'role': 'admin', 'password': 'different-secret'}
        self.assertEqual(self.request('/users', 'POST', duplicate)[0], 409)
        self.assertEqual(db.get_user_by_id(user.id).password_hash, user.password_hash)
        self.assertEqual(db.get_user_by_id(user.id).role, 'analyst')
        login = self.request('/session/login', 'POST', {'username': 'new-user', 'password': body['password']}, session=False, csrf=False)
        self.assertEqual(login[0], 200)
        self.assertEqual(login[1]['user']['role'], 'analyst')

    def audit_event(self, **overrides):
        fields = dict(actor_type='user', actor_id='1', actor_name='browser-admin', action='user.create',
                      target_type='user', target_id='7', outcome='success', source_ip='127.0.0.1',
                      request_id='req-1', details_json='{"role": "analyst"}')
        return db.create_audit_event(**(fields | overrides))

    def test_audit_requires_admin_and_rejects_out_of_range_cursors(self):
        self.assertEqual(self.request('/audit', session=False)[0], 401)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/audit')[0], 403)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'admin' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/audit?before=0')[0], 422)
        self.assertEqual(self.request('/audit?limit=101')[0], 422)
        self.assertEqual(self.request('/audit?outcome=deleted')[0], 422)
        self.assertEqual(self.request('/audit?q=' + 'x' * 201)[0], 422)
        # The trail is append-only through the application: no write verbs exist.
        for method in ('POST', 'PUT', 'DELETE'):
            self.assertEqual(self.request('/audit', method, {})[0], 405)

    def test_audit_page_is_descending_keyset_bounded_and_carries_no_total(self):
        ids = [self.audit_event(request_id=f'req-{index}') for index in range(21)]
        status, page, headers = self.request('/audit')
        self.assertEqual(status, 200, page)
        self.assertEqual(set(page), {'items', 'next_before'})
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual([row['id'] for row in page['items']], sorted(ids, reverse=True)[:20])
        self.assertEqual(page['next_before'], ids[1])
        tail = self.request('/audit?before=' + str(page['next_before']))[1]
        self.assertEqual([row['id'] for row in tail['items']], [ids[0]])
        self.assertIsNone(tail['next_before'])

    def test_audit_search_is_literal_and_outcome_filtered(self):
        wildcard = self.audit_event(actor_name='ops%team', outcome='denied')
        other = self.audit_event(actor_name='opsXteam', outcome='success')
        matched = self.request('/audit?q=ops%25team')[1]['items']
        self.assertEqual([row['id'] for row in matched], [wildcard])
        self.assertEqual([row['id'] for row in self.request('/audit?q=%25')[1]['items']], [wildcard])
        self.assertEqual([row['id'] for row in self.request('/audit?outcome=success')[1]['items']], [other])
        self.assertEqual(self.request('/audit?outcome=failure')[1]['items'], [])

    def test_audit_details_are_bounded_and_flagged(self):
        self.audit_event(details_json='{"marker": "' + 'y' * 8000 + '"}')
        self.audit_event(details_json='{"small": true}')
        small, large = self.request('/audit')[1]['items'][0], self.request('/audit')[1]['items'][1]
        self.assertFalse(small['details_truncated'])
        self.assertTrue(large['details_truncated'])
        self.assertEqual(len(large['details']), 4096)

    def test_hash_list_is_admin_only_and_writes_require_csrf(self):
        self.assertEqual(self.request('/hash-list', session=False)[0], 401)
        body = {'list_kind': 'block', 'hashes': ['a' * 64]}
        self.assertEqual(self.request('/hash-list', 'POST', body, csrf=False)[0], 403)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/hash-list')[0], 403)
        self.assertEqual(self.request('/hash-list', 'POST', body)[0], 403)
        self.assertEqual(self.request('/hash-list/1', 'DELETE')[0], 403)
        self.assertIsNone(db.get_hash_list_entry('a' * 64))

    def test_hash_list_add_normalizes_dedupes_and_never_reclassifies(self):
        status, added, _ = self.request('/hash-list', 'POST', {
            'list_kind': 'block', 'hashes': [' ' + 'A' * 64, 'a' * 64, 'b' * 64], 'note': 'Incident 14'})
        self.assertEqual(status, 201, added)
        self.assertEqual(added, {'added': 2, 'existing': []})
        self.assertEqual(db.get_hash_list_entry('a' * 64)['note'], 'Incident 14')
        status, again, _ = self.request('/hash-list', 'POST', {'list_kind': 'allow', 'hashes': ['a' * 64, 'c' * 64]})
        self.assertEqual(status, 201, again)
        self.assertEqual(again, {'added': 1, 'existing': [{'sha256': 'a' * 64, 'list_kind': 'block'}]})
        self.assertEqual(db.get_hash_list_entry('a' * 64)['list_kind'], 'block')

    def test_hash_list_add_validates_every_entry_before_writing(self):
        status, error, _ = self.request('/hash-list', 'POST', {'list_kind': 'block', 'hashes': ['a' * 64, 'not-a-hash']})
        self.assertEqual(status, 422)
        self.assertIn('Entry 2', error['detail'])
        self.assertIsNone(db.get_hash_list_entry('a' * 64))
        for body in ({'list_kind': 'maybe', 'hashes': ['a' * 64]}, {'list_kind': 'block', 'hashes': []},
                     {'list_kind': 'block', 'hashes': ['a' * 64] * 1001},
                     {'list_kind': 'block', 'hashes': ['a' * 64], 'note': 'x' * 257},
                     {'list_kind': 'block', 'hashes': ['a' * 64], 'extra': True}):
            with self.subTest(body=list(body)):
                self.assertEqual(self.request('/hash-list', 'POST', body)[0], 422)

    def test_hash_list_page_is_keyset_bounded_filtered_and_counts_first_page_only(self):
        digests = [f'{index:064x}' for index in range(1, 23)]
        db.add_hash_list_entries([(d, 'block' if int(d, 16) % 2 else 'allow', f'feed {int(d, 16)}') for d in digests], 'admin')
        status, page, headers = self.request('/hash-list')
        self.assertEqual(status, 200, page)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(len(page['items']), 20)
        self.assertEqual(page['counts'], {'block': 11, 'allow': 11})
        tail = self.request('/hash-list?before=' + str(page['next_before']))[1]
        self.assertEqual(len(tail['items']), 2)
        self.assertIsNone(tail['counts'])
        self.assertIsNone(tail['next_before'])
        self.assertEqual({row['list_kind'] for row in self.request('/hash-list?kind=allow')[1]['items']}, {'allow'})
        exact = self.request('/hash-list?q=' + digests[4].upper())[1]['items']
        self.assertEqual([row['sha256'] for row in exact], [digests[4]])
        self.assertEqual([row['note'] for row in self.request('/hash-list?q=feed 17')[1]['items']], ['feed 17'])
        self.assertEqual(self.request('/hash-list?q=%25')[1]['items'], [])
        self.assertEqual(self.request('/hash-list?kind=other')[0], 422)

    def test_hash_list_remove_is_explicit_and_reports_missing_entries(self):
        db.add_hash_list_entries([('a' * 64, 'block', '')], 'admin')
        entry_id = db.get_hash_list_entry('a' * 64)['id']
        self.assertEqual(self.request(f'/hash-list/{entry_id}', 'DELETE')[0], 204)
        self.assertIsNone(db.get_hash_list_entry('a' * 64))
        self.assertEqual(self.request(f'/hash-list/{entry_id}', 'DELETE')[0], 404)

    def test_intake_overview_is_admin_only_read_only_and_uncached(self):
        self.assertEqual(self.request('/system/intake', session=False)[0], 401)
        status, view, headers = self.request('/system/intake')
        self.assertEqual(status, 200, view)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(set(view), {'manifest_worker', 'manifest_record_invalid', 'queue', 'rejections',
                                     'rejections_total', 'failures', 'failures_truncated'})
        for method in ('POST', 'PUT', 'DELETE'):
            self.assertEqual(self.request('/system/intake', method, {})[0], 405)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/system/intake')[0], 403)

    def test_about_is_readable_by_analysts_and_scopes_client_counts_to_admins(self):
        db.create_service_client('integration', 'Integration')
        self.assertEqual(self.request('/about', session=False)[0], 401)
        status, admin_view, headers = self.request('/about')
        self.assertEqual(status, 200, admin_view)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(admin_view['service_client_count'], 1)
        self.assertEqual(admin_view['app_version'], APP_VERSION)
        self.assertEqual(admin_view['registered_nodes'], 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        analyst_view = self.request('/about')[1]
        self.assertEqual(status, 200)
        self.assertIsNone(analyst_view['service_client_count'])
        self.assertEqual(analyst_view['queue_mode'], admin_view['queue_mode'])

    def test_about_bounds_the_engine_name_list_and_omits_configuration(self):
        for index in range(6):
            db.create_engine_instance('static_metadata', f'Metadata {index}')
        payload = self.request('/about')[1]
        self.assertEqual(payload['enabled_engine_count'], 6)
        self.assertEqual(len(payload['enabled_engine_names']), 5)
        self.assertTrue(payload['engine_names_truncated'])
        serialized = json.dumps(payload)
        for secret in ('config_json', 'password', 'api_key', 'adapter_key', str(db.DB_PATH)):
            self.assertNotIn(secret, serialized)

    def test_user_inventory_keyset_ldap_and_secret_omission(self):
        directory = db.sync_external_user(username='directory-user', role='analyst', external_id='PRIVATE-DIRECTORY-DN', display_name='Directory user')
        for index in range(20):
            db.create_user(f'user-{index}', 'PRIVATE-HASH', 'analyst')
        status, page, headers = self.request('/users')
        self.assertEqual(status, 200)
        self.assertEqual(len(page['items']), 20)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(next(row for row in page['items'] if row['id'] == directory.id)['auth_source'], 'ldap')
        self.assertNotIn('PRIVATE-', json.dumps(page))
        self.assertNotIn('password_hash', json.dumps(page))
        next_page = self.request('/users?after=' + str(page['next_after']))[1]
        self.assertEqual(len(next_page['items']), 2)
        self.assertTrue(all(row['id'] > page['next_after'] for row in next_page['items']))
        self.assertEqual(self.request('/users?after=0')[0], 422)

    def test_automation_bulk_delete_auth_bounds_and_partial_receipts(self):
        deleted = self.create_scan(source='api', status='completed')
        active = self.create_scan(source='icap', status='running')
        manual = self.create_scan(status='completed')
        child = self.create_scan(source='api', status='completed', scan_role='child')
        stale = self.create_scan(source='api', status='completed')
        parent = self.create_scan(source='api', status='completed')
        self.create_scan(source='api', parent_scan_id=parent, scan_role='child')
        ids = [deleted, active, manual, child, stale, parent]
        body = {'scans': [{'scan_id': value, 'attempt': 1 if value == stale else 0, 'job_revision': 0} for value in ids]}
        path = '/api-ledger/scans'
        self.assertEqual(self.request(path, 'DELETE', body, session=False)[0], 401)
        self.assertEqual(self.request(path, 'DELETE', body, csrf=False)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(path, 'DELETE', body)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'admin' WHERE id = ?", (self.user_id,))
        for items in ([], [body['scans'][0]] * 2, [body['scans'][0]] * 21):
            self.assertEqual(self.request(path, 'DELETE', {'scans': items})[0], 422)
        self.assertEqual(self.request(path, 'DELETE', {'scans': [{'scan_id': deleted, 'attempt': True, 'job_revision': 0}]})[0], 422)
        with patch.object(scan_management, 'delete_sample_file', return_value=False):
            status, receipt, _ = self.request(path, 'DELETE', body)
        self.assertEqual(status, 200, receipt)
        self.assertEqual(receipt['deleted_ids'], [deleted])
        self.assertEqual(receipt['cleanup_failed_ids'], [deleted])
        self.assertEqual(receipt['blocked_ids'], ids[1:])
        self.assertIsNone(db.get_scan(deleted))
        for scan in ids[1:]:
            self.assertIsNotNone(db.get_scan(scan))

    def test_ledger_delete_fences_are_metadata_only_and_stale_revision_blocks(self):
        scan = self.create_scan(source='icap', status='completed', profile_snapshot_json='{"engines":[]}')
        page = self.request('/api-ledger')[1]
        row = next(row for row in page['items'] if row['id'] == scan)
        self.assertEqual(row['attempt_count'], 0)
        self.assertEqual(row['job_revision'], 0)
        self.assertNotIn('engine_results', row)
        body = {'scans': [{'scan_id': scan, 'attempt': row['attempt_count'], 'job_revision': 1}]}
        self.assertEqual(self.request('/api-ledger/scans', 'DELETE', body)[1]['blocked_ids'], [scan])
        self.assertIsNotNone(db.get_scan(scan))
        self.assertEqual(self.request('/scans', 'DELETE', {'scans': [{'scan_id': scan, 'attempt': 0, 'job_revision': 0}]})[1]['blocked_ids'], [scan])

    def test_automation_archive_source_owner_batch_and_nested_scope(self):
        owner = db.create_service_client('archive-owner', 'Archive owner')
        other = db.create_service_client('archive-other', 'Other')
        batch = db.create_scan_batch(source='api', original_filename='outer.zip', archive_mode='none', service_client_id=owner)
        parent = self.create_scan(source='api', batch_id=batch, service_client_id=owner)
        first = self.create_scan('100%_one.zip', source='api', batch_id=batch, service_client_id=owner, parent_scan_id=parent, scan_role='child')
        second = self.create_scan('two.bin', source='api', batch_id=batch, service_client_id=owner, parent_scan_id=parent, scan_role='child')
        for fields in ({'source': 'manual'}, {'source': 'icap'}, {'service_client_id': other}, {'service_client_id': None}, {'batch_id': None}):
            params = dict(source='api', batch_id=batch, service_client_id=owner, parent_scan_id=parent, scan_role='child') | fields
            self.create_scan(**params)
        self.create_scan(source='api', batch_id=batch, service_client_id=other, parent_scan_id=first, scan_role='child')
        path = f'/api-ledger/scans/{parent}/children'
        self.assertEqual(self.request(path, session=False)[0], 401)
        self.assertEqual(self.request(f'/scans/{parent}/children')[0], 404)
        manual = self.create_scan()
        self.assertEqual(self.request(f'/api-ledger/scans/{manual}/children')[0], 404)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        status, page, _ = self.request(path + '?limit=1')
        self.assertEqual(status, 200, page)
        self.assertEqual([row['id'] for row in page['items']], [first])
        self.assertFalse(page['items'][0]['has_children'])
        next_page = self.request(path + '?' + urlencode({'after': page['next_after'], 'attempt': page['attempt_count']}))[1]
        self.assertEqual([row['id'] for row in next_page['items']], [second])
        nested = self.create_scan(source='api', batch_id=batch, service_client_id=owner, parent_scan_id=first, scan_role='child')
        self.assertTrue(self.request(path)[1]['items'][0]['has_children'])
        nested_page = self.request(f'/api-ledger/scans/{first}/children')[1]
        self.assertEqual(nested_page['parent_scan_id'], parent)
        self.assertEqual([row['id'] for row in nested_page['items']], [nested])
        filtered = self.request(path + '?' + urlencode({'q': '100%_'}))[1]
        self.assertEqual([row['id'] for row in filtered['items']], [first])
        self.assertEqual(self.request(path + '?after=1')[0], 422)
        with db.connect() as connection:
            connection.execute('UPDATE scan_jobs SET attempt_count = attempt_count + 1 WHERE id = ?', (parent,))
        self.assertEqual(self.request(path + '?after=1&attempt=0')[0], 409)
        self.assertEqual(db.get_scan_batch(batch).total_items, 0)

    def test_automation_archive_unassigned_owner_and_cross_boundary_up_link(self):
        owner = db.create_service_client('assigned-archive', 'Assigned')
        batch = db.create_scan_batch(source='icap', original_filename='icap.zip', archive_mode='none')
        invalid_up = self.create_scan(source='manual', batch_id=batch)
        parent = self.create_scan(source='icap', batch_id=batch, parent_scan_id=invalid_up, scan_role='child')
        child = self.create_scan(source='icap', batch_id=batch, parent_scan_id=parent, scan_role='child')
        self.create_scan(source='icap', batch_id=batch, parent_scan_id=parent, scan_role='child', service_client_id=owner)
        path = f'/api-ledger/scans/{parent}/children'
        page = self.request(path)[1]
        self.assertIsNone(page['parent_scan_id'])
        self.assertEqual([row['id'] for row in page['items']], [child])
        self.create_scan(source='icap', batch_id=batch, parent_scan_id=child, scan_role='child')
        self.assertTrue(self.request(path)[1]['items'][0]['has_children'])
        with db.connect() as connection:
            connection.execute('UPDATE scan_batches SET service_client_id = ? WHERE id = ?', (owner, batch))
        self.assertEqual(self.request(path)[0], 409)

    def client_with_routing(self, *, engines=('static_metadata',), enabled=True, default=True, profile_enabled=True):
        client = db.create_service_client('connect-client', 'Connect Client')
        ids = [db.create_engine_instance(key, f'Engine {index}') for index, key in enumerate(engines)]
        profile = db.create_scan_profile(client, 'Default routing', engine_instance_ids=ids, is_default=default)
        with db.connect() as connection:
            if not enabled:
                connection.execute('UPDATE service_clients SET enabled = ? WHERE id = ?', (db.db_bool(False), client))
            if not profile_enabled:
                connection.execute('UPDATE scan_profiles SET enabled = ? WHERE id = ?', (db.db_bool(False), profile))
        return client, profile, ids

    def test_client_readiness_requires_admin_and_a_known_client(self):
        client, _, _ = self.client_with_routing()
        path = f'/service-clients/{client}/readiness'
        self.assertEqual(self.request(path, session=False)[0], 401)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(path)[0], 403)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'admin' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/service-clients/999999/readiness')[0], 404)
        self.assertEqual(self.request('/service-clients/0/readiness')[0], 422)
        for method in ('POST', 'PUT', 'DELETE'):
            self.assertEqual(self.request(path, method, {})[0], 405)

    def test_client_readiness_reports_each_blocking_step(self):
        client = db.create_service_client('bare-client', 'Bare Client')
        path = f'/service-clients/{client}/readiness'
        status, payload, headers = self.request(path)
        self.assertEqual(status, 200, payload)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertFalse(payload['ready'])
        failed = {check['key'] for check in payload['checks'] if not check['passed']}
        self.assertEqual(failed, {'default_profile', 'assigned_engines', 'eligible_engines', 'active_credential'})
        self.assertIsNone(payload['profile_id'])
        self.assertEqual(payload['engines'], [])

    def test_client_readiness_passes_once_routing_and_a_credential_exist(self):
        client, profile, _ = self.client_with_routing()
        path = f'/service-clients/{client}/readiness'
        self.assertFalse(self.request(path)[1]['ready'])
        db.create_api_client_credential(client, label='primary', token_hash='hash-only-value', token_prefix='prefix00')
        payload = self.request(path)[1]
        self.assertTrue(payload['ready'], payload['checks'])
        self.assertEqual(payload['profile_id'], profile)
        self.assertEqual(payload['active_credential_count'], 1)
        self.assertEqual(payload['eligible_engine_count'], 1)

    def test_client_readiness_explains_quota_and_disabled_exclusions(self):
        client, _, ids = self.client_with_routing(engines=('static_metadata', 'virustotal'))
        with db.connect() as connection:
            connection.execute('UPDATE engine_instances SET enabled = ? WHERE id = ?', (db.db_bool(False), ids[0]))
        payload = self.request(f'/service-clients/{client}/readiness')[1]
        reasons = {engine['adapter_key']: engine['excluded_reason'] for engine in payload['engines']}
        self.assertIn('disabled', reasons['static_metadata'].lower())
        self.assertIn('Metered', reasons['virustotal'])
        self.assertEqual(payload['eligible_engine_count'], 0)
        self.assertFalse(next(c for c in payload['checks'] if c['key'] == 'eligible_engines')['passed'])

    def test_client_readiness_ignores_a_disabled_or_non_default_profile(self):
        client, _, _ = self.client_with_routing(profile_enabled=False)
        self.assertIsNone(self.request(f'/service-clients/{client}/readiness')[1]['profile_id'])
        other = db.create_service_client('non-default', 'Non Default')
        engine = db.create_engine_instance('clamav', 'ClamAV routing')
        db.create_scan_profile(other, 'Secondary', engine_instance_ids=[engine], is_default=False)
        self.assertIsNone(self.request(f'/service-clients/{other}/readiness')[1]['profile_id'])

    def test_client_readiness_exposes_endpoints_but_never_a_credential_value(self):
        client, _, _ = self.client_with_routing()
        db.create_api_client_credential(client, label='primary', token_hash='PRIVATE-TOKEN-HASH', token_prefix='PRIVPFX0')
        payload = self.request(f'/service-clients/{client}/readiness')[1]
        self.assertTrue(payload['scan_endpoint'].endswith('/api/v1/scans'))
        self.assertTrue(payload['deferred_endpoint'].endswith('/api/v1/deferred-scans'))
        self.assertEqual(payload['icap_client_key_setting'], 'MASP_ICAP_SERVICE_CLIENT_KEY=connect-client')
        serialized = json.dumps(payload)
        for secret in ('PRIVATE-TOKEN-HASH', 'PRIVPFX0', 'token_hash', 'config_json'):
            self.assertNotIn(secret, serialized)

    def test_batch_json_contract_permissions_and_no_status_engine_hydration(self):
        from app.services.api_schemas import BatchStatusResponse, BatchResultResponse
        batch = db.create_scan_batch(source='api', original_filename='batch.zip', archive_mode='none')
        scan, _ = self.report_fixture()
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'api', batch_id = ? WHERE id = ?", (batch, scan))
            connection.execute("UPDATE scan_batches SET status = 'completed' WHERE id = ?", (batch,))
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        path = f'/api-ledger/batches/{batch}/json'
        self.assertEqual(self.request(path, session=False)[0], 401)
        self.assertEqual(self.request(path + '?kind=other')[0], 422)
        manual = db.create_scan_batch(source='manual', original_filename='manual.zip', archive_mode='none')
        self.assertEqual(self.request(f'/api-ledger/batches/{manual}/json')[0], 404)
        with patch('app.services.batch_payload._full_export_rows', side_effect=AssertionError('status must not read engine blobs')):
            status, body, headers = self.request(path)
        self.assertEqual(status, 200, body)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        payload = json.loads(body['content'])
        BatchStatusResponse.model_validate(payload)
        self.assertEqual([entry['id'] for entry in payload['scans']], [scan])
        self.assertEqual(payload['batch']['counts']['total_items'], 0)
        status, body, _ = self.request(path + '?kind=result')
        self.assertEqual(status, 200, body)
        BatchResultResponse.model_validate(json.loads(body['content']))
        for private in ('raw_output', 'storage_path', 'metadata_json', '<script>'):
            self.assertNotIn(private, body['content'])
        self.assertEqual(db.get_scan_batch(batch).total_items, 0)

    def test_batch_json_rejects_partial_owner_mismatch_and_oversized_results(self):
        batch = db.create_scan_batch(source='icap', original_filename='batch.zip', archive_mode='none')
        scan, result = self.report_fixture()
        path = f'/api-ledger/batches/{batch}/json'
        with db.connect() as connection:
            connection.execute('UPDATE scan_jobs SET batch_id = ? WHERE id = ?', (batch, scan))
        self.assertEqual(self.request(path)[0], 409)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'icap' WHERE id = ?", (scan,))
        self.assertEqual(self.request(path + '?kind=result')[0], 409)
        with db.connect() as connection:
            connection.execute("UPDATE scan_batches SET status = 'completed' WHERE id = ?", (batch,))
            connection.execute("UPDATE scan_jobs SET status = 'running' WHERE id = ?", (scan,))
        self.assertEqual(self.request(path + '?kind=result')[0], 409)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET status = 'completed' WHERE id = ?", (scan,))
            connection.execute("UPDATE engine_results SET details_json = '[]' WHERE id = ?", (result,))
        self.assertEqual(self.request(path + '?kind=result')[0], 409)
        with db.connect() as connection:
            connection.execute("UPDATE engine_results SET details_json = '{}', raw_output = ? WHERE id = ?", ('x' * (2 * 1024 * 1024 + 1), result))
        with patch('app.services.batch_payload._full_export_rows', side_effect=AssertionError('must preflight before hydration')):
            self.assertEqual(self.request(path + '?kind=result')[0], 413)
        self.assertEqual(self.request(path)[0], 200)
        with patch('app.services.batch_payload.EXPORT_LIMIT', 1):
            self.assertEqual(self.request(path)[0], 413)
        owner = db.create_service_client('batch-owner', 'Owner')
        with db.connect() as connection:
            connection.execute('UPDATE scan_jobs SET service_client_id = ? WHERE id = ?', (owner, scan))
        self.assertEqual(self.request(path)[0], 409)

    def test_batch_json_member_and_aggregate_source_limits(self):
        batch = db.create_scan_batch(source='api', original_filename='batch.zip', archive_mode='none')
        for index in range(21):
            self.create_scan(name=f'member-{index}', source='api', batch_id=batch, status='completed', profile_snapshot_json='{"engines":[]}')
        path = f'/api-ledger/batches/{batch}/json'
        for kind in ('status', 'result'):
            self.assertEqual(self.request(path + '?kind=' + kind)[0], 413)
        with db.connect() as connection:
            connection.execute('UPDATE scan_jobs SET batch_id = NULL WHERE batch_id = ?', (batch,))
            connection.execute("UPDATE scan_batches SET status = 'completed' WHERE id = ?", (batch,))
        for index in range(2):
            scan, result = self.report_fixture()
            with db.connect() as connection:
                connection.execute("UPDATE scan_jobs SET source = 'api', batch_id = ? WHERE id = ?", (batch, scan))
                connection.execute('UPDATE engine_results SET raw_output = ? WHERE id = ?', ('x' * 1100000, result))
        with patch('app.services.batch_payload._full_export_rows', side_effect=AssertionError('batch aggregate must reject before hydration')):
            self.assertEqual(self.request(path + '?kind=result')[0], 413)

    def test_batch_download_serves_members_the_inline_view_refuses(self):
        from app.services.api_schemas import BatchResultResponse
        batch = db.create_scan_batch(source='api', original_filename='batch.zip', archive_mode='none')
        for index in range(21):
            scan = self.create_scan(name=f'member-{index}', source='api', batch_id=batch,
                                    status='completed', verdict='info', risk_score=0,
                                    profile_snapshot_json='{"engines":[]}')
            db.create_engine_result(scan, EngineResultInput(engine_name='Static Metadata', status='completed',
                detected=False, severity='info', confidence=100, signature=None, raw_output='clean', duration_ms=1))
        with db.connect() as connection:
            connection.execute("UPDATE scan_batches SET status = 'completed' WHERE id = ?", (batch,))
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        inline = f'/api-ledger/batches/{batch}/json?kind=result'
        download = f'/api-ledger/batches/{batch}/download?kind=result'
        # The inline view refuses 21 members and now names the download.
        status, refusal, _ = self.request(inline)
        self.assertEqual(status, 413)
        self.assertIn('Download the complete contract', refusal['detail'])
        status, served, headers = self.request(download, raw=True)
        self.assertEqual(status, 200, served[:200])
        self.assertEqual(headers[b'content-type'], b'application/json')
        self.assertEqual(headers[b'content-disposition'],
                         f'attachment; filename="masp-batch-{batch}-result.json"'.encode())
        self.assertEqual(headers[b'cache-control'], b'no-store')
        payload = json.loads(served)
        BatchResultResponse.model_validate(payload)
        self.assertEqual(len(payload['scans']), 21)
        for private in ('raw_output', 'storage_path', 'metadata_json'):
            self.assertNotIn(private, served.decode())
        self.assertEqual(db.get_scan_batch(batch).total_items, 0)

    def test_batch_download_is_scoped_validated_and_read_only(self):
        batch = db.create_scan_batch(source='api', original_filename='batch.zip', archive_mode='none')
        scan, result = self.report_fixture()
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'api', batch_id = ? WHERE id = ?", (batch, scan))
            connection.execute("UPDATE scan_batches SET status = 'completed' WHERE id = ?", (batch,))
        path = f'/api-ledger/batches/{batch}/download'
        self.assertEqual(self.request(path, session=False)[0], 401)
        self.assertEqual(self.request(path + '?kind=other')[0], 422)
        self.assertEqual(self.request('/api-ledger/batches/0/download')[0], 422)
        manual = db.create_scan_batch(source='manual', original_filename='manual.zip', archive_mode='none')
        self.assertEqual(self.request(f'/api-ledger/batches/{manual}/download')[0], 404)
        for method in ('POST', 'PUT', 'DELETE'):
            self.assertEqual(self.request(path, method, {})[0], 405)
        # A member that cannot satisfy the public contract fails the whole
        # document explicitly; a partial download must never be served.
        with db.connect() as connection:
            connection.execute("UPDATE engine_results SET details_json = '[]' WHERE id = ?", (result,))
        self.assertEqual(self.request(path + '?kind=result')[0], 409)

    def test_batch_download_limit_is_configurable_and_clamped(self):
        batch = db.create_scan_batch(source='api', original_filename='batch.zip', archive_mode='none')
        scan, _ = self.report_fixture()
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'api', batch_id = ? WHERE id = ?", (batch, scan))
            connection.execute("UPDATE scan_batches SET status = 'completed' WHERE id = ?", (batch,))
        path = f'/api-ledger/batches/{batch}/download'
        self.assertEqual(self.request(path)[0], 200)
        with patch.dict(os.environ, {'MASP_UI_BATCH_DOWNLOAD_LIMIT': '1'}):
            # Never below the inline ceiling this download exists to exceed.
            self.assertEqual(batch_payload.download_limit(), batch_payload.EXPORT_LIMIT)
        with patch.dict(os.environ, {'MASP_UI_BATCH_DOWNLOAD_LIMIT': 'not-a-number'}):
            self.assertEqual(batch_payload.download_limit(), batch_payload.DOWNLOAD_DEFAULT_LIMIT)
        with patch.dict(os.environ, {'MASP_UI_BATCH_DOWNLOAD_LIMIT': str(10 * 1024 ** 3)}):
            self.assertEqual(batch_payload.download_limit(), batch_payload.DOWNLOAD_MAX_LIMIT)
        # A document over the configured ceiling is refused outright rather than
        # truncated: a partial contract must never reach an operator.
        with patch.object(batch_payload, 'download_limit', return_value=64):
            status, refusal, _ = self.request(path)
            self.assertEqual(status, 413)
            self.assertIn('64 byte download limit', refusal['detail'])
        # The download cap matches what an integration could actually receive.
        self.assertEqual(batch_payload.DOWNLOAD_MAX_MEMBERS, 5000)

    def test_automation_status_json_contract_queue_states_and_permissions(self):
        from app.services.api_schemas import ScanStatusResponse
        scan, result = self.report_fixture()
        path = f'/api-ledger/scans/{scan}/status-json'
        self.assertEqual(self.request(path)[0], 404)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'api' WHERE id = ?", (scan,))
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(path, session=False)[0], 401)
        db.set_setting('scan_policy.api_retry_after_seconds', '7')
        for state in ('queued', 'running', 'finalizing', 'completed', 'failed'):
            with self.subTest(state=state):
                with db.connect() as connection:
                    connection.execute('UPDATE scan_jobs SET status = ? WHERE id = ?', (state, scan))
                status, body, headers = self.request(path)
                self.assertEqual(status, 200, body)
                payload = json.loads(body['content'])
                ScanStatusResponse.model_validate(payload)
                self.assertEqual(headers[b'cache-control'], b'no-store')
                self.assertEqual(payload['queue'], db.get_queue_metrics() | {'position': db.get_scan_queue_position(scan)})
                ready = state in ('completed', 'failed')
                self.assertEqual(payload['result_ready'], ready)
                self.assertEqual(payload['recommended_poll_seconds'], None if ready else 7)
                self.assertNotIn('raw_output', body['content'])
                self.assertNotIn('<script>', body['content'])

    def test_automation_status_expected_engines_preserves_snapshot_and_source_filtering(self):
        from app.services.service_clients import engines_for_scan
        scan, _ = self.report_fixture()
        metadata = db.create_engine_instance('static_metadata', 'Accepted metadata')
        quota = db.create_engine_instance('virustotal', 'Quota')
        disabled = db.create_engine_instance('clamav', 'Disabled', enabled=False)
        db.create_engine_instance('clamav', 'New unrelated instance')
        snapshot = json.dumps({'engines': [{'id': value, 'name': 'Recorded', 'detection': False}
                                         for value in (metadata, quota, disabled, metadata)]})
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'icap', profile_snapshot_json = ? WHERE id = ?", (snapshot, scan))
        status, body, _ = self.request(f'/api-ledger/scans/{scan}/status-json')
        self.assertEqual(status, 200, body)
        expected = json.loads(body['content'])['engines']['expected']
        self.assertEqual(expected, 1)
        self.assertEqual(expected, len(engines_for_scan(db.get_scan(scan))))

    def test_automation_status_admission_invalid_policy_and_response_limit(self):
        scan, result = self.report_fixture(details='[]')
        path = f'/api-ledger/scans/{scan}/status-json'
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'api' WHERE id = ?", (scan,))
        self.assertEqual(self.request(path)[0], 409)
        with db.connect() as connection:
            connection.execute("UPDATE engine_results SET details_json = '{}' WHERE id = ?", (result,))
        with patch('app.services.automation_payload.EXPORT_LIMIT', 1):
            self.assertEqual(self.request(path)[0], 413)
        with db.connect() as connection:
            connection.execute('UPDATE engine_results SET raw_output = ? WHERE id = ?', ('x' * (2 * 1024 * 1024 + 1), result))
        self.assertEqual(self.request(path)[0], 413)
        with db.connect() as connection:
            connection.execute("UPDATE engine_results SET raw_output = '' WHERE id = ?", (result,))
            connection.execute("UPDATE scan_jobs SET profile_snapshot_json = '{}' WHERE id = ?", (scan,))
        self.assertEqual(self.request(path)[0], 413)

    def test_automation_result_json_scope_contract_and_private_field_omission(self):
        from app.services.api_schemas import ScanResultResponse
        scan, result = self.report_fixture()
        path = f'/api-ledger/scans/{scan}/result-json'
        self.assertEqual(self.request(path)[0], 404)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'icap' WHERE id = ?", (scan,))
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(path, session=False)[0], 401)
        status, body, headers = self.request(path)
        self.assertEqual(status, 200, body)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        payload = json.loads(body['content'])
        ScanResultResponse.model_validate(payload)
        self.assertTrue(payload['result_ready'])
        self.assertEqual(payload['scan']['id'], scan)
        self.assertTrue(payload['links']['result'].endswith(f'/api/v1/scans/{scan}/result'))
        for private in ('raw_output', 'details_json', 'storage_path', 'stored_filename', '<script>'):
            self.assertNotIn(private, body['content'])

    def test_automation_result_json_rejects_incomplete_invalid_and_oversized_records(self):
        scan, result = self.report_fixture(details='[]')
        path = f'/api-ledger/scans/{scan}/result-json'
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'api' WHERE id = ?", (scan,))
        self.assertEqual(self.request(path)[0], 409)
        with db.connect() as connection:
            connection.execute("UPDATE engine_results SET details_json = '{}' WHERE id = ?", (result,))
            connection.execute("UPDATE scan_jobs SET status = 'running' WHERE id = ?", (scan,))
        self.assertEqual(self.request(path)[0], 409)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET status = 'completed' WHERE id = ?", (scan,))
            connection.execute('UPDATE engine_results SET raw_output = ? WHERE id = ?', ('x' * (2 * 1024 * 1024 + 1), result))
        self.assertEqual(self.request(path)[0], 413)
        with db.connect() as connection:
            connection.execute("UPDATE engine_results SET raw_output = '' WHERE id = ?", (result,))
        with patch('app.services.automation_payload.EXPORT_LIMIT', 1):
            self.assertEqual(self.request(path)[0], 413)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET profile_snapshot_json = '{}' WHERE id = ?", (scan,))
        self.assertEqual(self.request(path)[0], 413)

    def test_automation_exports_authorization_scope_and_policy(self):
        scan, result = self.report_fixture(details='[]')
        manual, _ = self.report_fixture()
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'icap' WHERE id = ?", (scan,))
        for endpoint in ('summary-export', 'export'):
            path = f'/api-ledger/scans/{scan}/{endpoint}'
            self.assertEqual(self.request(path, session=False)[0], 401)
            self.assertEqual(self.request(f'/api-ledger/scans/{manual}/{endpoint}')[0], 404)
            self.assertEqual(self.request(f'/scans/{scan}/{endpoint}')[0], 404)
            self.assertEqual(self.request(path + '?format=html')[0], 422)
            status, exported, headers = self.request(path)
            self.assertEqual(status, 200)
            self.assertEqual(headers[b'cache-control'], b'no-store')
            self.assertNotIn('/private/storage', exported['content'])
            self.assertNotIn('stored_filename', exported['content'])
            payload = json.loads(exported['content'])
            decision = payload['report']['decision'] if endpoint == 'summary-export' else payload['summary']['decision']
            self.assertIsNone(decision)
            if endpoint == 'summary-export':
                self.assertIn('Automation', payload['scope'])
                self.assertNotIn('raw_output', payload['report'])
            else:
                self.assertIn('<script>not executable</script>', exported['content'])
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(f'/api-ledger/scans/{scan}/export?format=csv')[0], 200)
        self.assertEqual(self.request(f'/api-ledger/scans/{scan}/summary-export?format=csv')[0], 200)

    def test_automation_full_export_admission_and_missing_historical_routing(self):
        scan, result = self.report_fixture()
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'api' WHERE id = ?", (scan,))
            connection.execute('UPDATE engine_results SET raw_output = ? WHERE id = ?', ('x' * (2 * 1024 * 1024 + 1), result))
        path = f'/api-ledger/scans/{scan}/export'
        self.assertEqual(self.request(path)[0], 413)
        self.assertEqual(self.request(f'/api-ledger/scans/{scan}/summary-export')[0], 200)
        with db.connect() as connection:
            connection.execute('UPDATE engine_results SET raw_output = ? WHERE id = ?', ('\x01' * 400000, result))
        self.assertEqual(self.request(path)[0], 413)
        with db.connect() as connection:
            connection.execute("UPDATE engine_results SET raw_output = '' WHERE id = ?", (result,))
            connection.execute("UPDATE scan_jobs SET profile_snapshot_json = '{}' WHERE id = ?", (scan,))
        self.assertEqual(self.request(path)[0], 413)

    def profile_fixture(self, key='profile-client'):
        client = db.create_service_client(key, 'Profile client')
        engine = db.create_engine_instance('static_metadata', 'Metadata ' + key)
        profile = db.create_scan_profile(client, 'Default', engine_instance_ids=[engine], is_default=True, policy_json='{"private":"SECRET_POLICY"}')
        return client, profile, engine

    def test_storage_access_prebody_guards_and_strict_fences(self):
        client, _, _ = self.profile_fixture()
        path = f'/service-clients/{client}/storage'
        body = dict(mode='custom', grants=[], expected_revision=0, expected_environment_fingerprint='a' * 64)
        self.assertEqual(self.request(path, session=False)[0], 401)
        for options in ({'session': False}, {'csrf': False}, {'origin': 'http://evil'}):
            self.assertIn(self.request(path, 'PUT', body, **options)[0], (401, 403))
            self.assertEqual(self.reads, 0)
        for fields in ({'expected_revision': True}, {'expected_revision': -1}, {'unexpected': True},
                       {'expected_environment_fingerprint': 'x'}, {'grants': [{'backend_key': 'b', 'access': 'all', 'root': '/private'}]}):
            self.assertEqual(self.request(path, 'PUT', body | fields)[0], 422)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(path)[0], 403)
        self.assertEqual(self.request(path, 'PUT', body)[0], 403)
        self.assertEqual(self.reads, 0)

    def test_storage_access_http_roundtrip_no_root_disclosure_and_stale_rejection(self):
        client, _, _ = self.profile_fixture()
        path = f'/service-clients/{client}/storage'
        with patch.dict(os.environ, {
            'MASP_DEFERRED_STORAGE_BACKENDS_JSON': json.dumps({'shared': str(Path(self.temp.name) / 'private-root')}),
            'MASP_DEFERRED_BACKEND_CLIENTS_JSON': '{"shared":["profile-client"]}',
        }):
            status, current, headers = self.request(path)
            self.assertEqual(status, 200)
            self.assertEqual(headers[b'cache-control'], b'no-store')
            self.assertNotIn('private-root', json.dumps(current))
            self.assertEqual(current['mode'], 'environment')
            body = dict(mode='custom', grants=[dict(backend_key='shared', access='prefixes', prefixes=['incoming/client'])],
                expected_revision=current['revision'], expected_environment_fingerprint=current['environment_fingerprint'])
            self.assertEqual(self.request(path, 'PUT', body)[0], 204)
            self.assertEqual(self.request(path, 'PUT', body)[0], 409)
            current = self.request(path)[1]
            self.assertEqual(current['grants'][0]['prefixes'], ['incoming/client/'])
            self.assertEqual(self.request(path, 'PUT', body | {'expected_revision': current['revision'], 'grants': []})[0], 204)
            self.assertEqual(self.request(path)[1]['grants'], [])
            self.assertEqual(self.request(path, 'PUT', body | {'expected_revision': 2, 'mode': 'environment', 'grants': []})[0], 204)
            self.assertEqual(self.request(path)[1]['grants'][0]['access'], 'all')

    def test_named_profile_writes_authenticate_before_body_and_enforce_strict_contracts(self):
        client, profile, engine = self.profile_fixture()
        path = f'/service-clients/{client}/profiles'
        writes = [(path, 'POST', {'name': 'Named', 'engine_ids': [engine]}),
            (f'{path}/{profile}', 'PUT', {'name': 'Default', 'enabled': True, 'expected_revision': 0}),
            (f'{path}/{profile}', 'DELETE', {'expected_revision': 0}),
            (f'{path}/{profile}/default', 'PUT', {'expected_revision': 0, 'expected_default_profile_id': profile})]
        for endpoint, method, body in writes:
            for options in ({'session': False}, {'csrf': False}, {'origin': 'http://evil'}):
                self.assertIn(self.request(endpoint, method, body, **options)[0], (401, 403))
                self.assertEqual(self.reads, 0)
            self.assertEqual(self.request(endpoint, method, body | {'unexpected': True})[0], 422)
            if 'expected_revision' in body:
                self.assertEqual(self.request(endpoint, method, body | {'expected_revision': True})[0], 422)
        for body in ({'name': ' ', 'engine_ids': [engine]}, {'name': 'Named', 'engine_ids': [engine, engine]},
                     {'name': 'Named', 'engine_ids': []}, {'name': 'Named', 'engine_ids': [True]}):
            self.assertEqual(self.request(path, 'POST', body)[0], 422)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        for endpoint, method, body in writes:
            self.assertEqual(self.request(endpoint, method, body)[0], 403)
            self.assertEqual(self.reads, 0)

    def test_named_profile_http_lifecycle_and_deleted_names_remain_reserved(self):
        client, original, engine = self.profile_fixture()
        path = f'/service-clients/{client}/profiles'
        status, created, _ = self.request(path, 'POST', {'name': 'Fast', 'engine_ids': [engine]})
        self.assertEqual(status, 201)
        profile = created['profile_id']
        self.assertEqual(self.request(path)[1]['default_profile_id'], original)
        self.assertEqual(self.request(f'{path}/{profile}', 'PUT', {'name': 'Renamed', 'enabled': True, 'expected_revision': 0})[0], 204)
        self.assertEqual(self.request(f'{path}/{profile}/default', 'PUT', {'expected_revision': 1, 'expected_default_profile_id': original})[0], 204)
        self.assertEqual(self.request(path)[1]['default_profile_id'], profile)
        self.assertEqual(self.request(f'{path}/{profile}', 'DELETE', {'expected_revision': 2})[0], 409)
        self.assertEqual(self.request(f'{path}/{original}/default', 'PUT', {'expected_revision': 1, 'expected_default_profile_id': profile})[0], 204)
        self.assertEqual(self.request(f'{path}/{profile}', 'DELETE', {'expected_revision': 3})[0], 204)
        self.assertEqual([p['id'] for p in self.request(path)[1]['items']], [original])
        self.assertEqual(self.request(path, 'POST', {'name': 'Renamed', 'engine_ids': [engine]})[0], 409)
        managed, managed_profile, _ = self.profile_fixture('legacy-default')
        managed_path = f'/service-clients/{managed}/profiles'
        self.assertEqual(self.request(managed_path, 'POST', {'name': 'Blocked', 'engine_ids': [engine]})[0], 409)
        self.assertEqual(self.request(f'{managed_path}/{managed_profile}', 'DELETE', {'expected_revision': 0})[0], 409)

    def test_profile_routing_requires_admin_csrf_and_strict_bounded_ids(self):
        client, profile, engine = self.profile_fixture()
        path = f'/service-clients/{client}/profiles/{profile}/engines'
        body = {'engine_ids': [engine], 'expected_engine_ids': [engine]}
        self.assertEqual(self.request(f'/service-clients/{client}/profiles', session=False)[0], 401)
        self.assertEqual(self.request(path, 'PUT', body, csrf=False)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request(f'/service-clients/{client}/profiles')[0], 403)
        self.assertEqual(self.request(path, 'PUT', body)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'admin' WHERE id = ?", (self.user_id,))
        for fields in ({'engine_ids': []}, {'engine_ids': [True]}, {'engine_ids': [engine, engine]}, {'engine_ids': [engine] * 101}, {'source': 'manual'}):
            self.assertEqual(self.request(path, 'PUT', body | fields)[0], 422)

    def test_profile_routing_is_client_scoped_fenced_and_preserves_snapshots(self):
        client, profile, engine = self.profile_fixture()
        managed, managed_profile, managed_engine = self.profile_fixture('legacy-default')
        replacement = db.create_engine_instance('static_metadata', 'Replacement')
        scan = self.create_scan(source='api', status='completed', service_client_id=client, scan_profile_id=profile, profile_snapshot_json='{"immutable":true}')
        body = {'engine_ids': [replacement], 'expected_engine_ids': [engine]}
        self.assertEqual(self.request(f'/service-clients/{managed}/profiles/{profile}/engines', 'PUT', body)[0], 409)
        self.assertEqual(self.request(f'/service-clients/{managed}/profiles/{managed_profile}/engines', 'PUT', {'engine_ids': [replacement], 'expected_engine_ids': [managed_engine]})[0], 409)
        path = f'/service-clients/{client}/profiles/{profile}/engines'
        self.assertEqual(self.request(path, 'PUT', body | {'engine_ids': [999999]})[0], 409)
        self.assertEqual([e.id for e in db.list_scan_profile_engines(profile)], [engine])
        self.assertEqual(self.request(path, 'PUT', body)[0], 204)
        self.assertEqual(self.request(path, 'PUT', body)[0], 409)
        self.assertEqual([e.id for e in db.list_scan_profile_engines(profile)], [replacement])
        self.assertEqual(db.get_scan(scan).profile_snapshot_json, '{"immutable":true}')

    def test_profile_pages_hide_policy_and_use_client_scoped_id_cursors(self):
        client, profile, engine = self.profile_fixture()
        for index in range(20):
            db.create_scan_profile(client, f'Profile {index}', engine_instance_ids=[engine])
        self.profile_fixture('other-client')
        path = f'/service-clients/{client}/profiles'
        status, first, headers = self.request(path)
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(len(first['items']), 20)
        self.assertNotIn('SECRET_POLICY', json.dumps(first))
        self.assertNotIn('policy_json', json.dumps(first))
        second = self.request(path + '?after=' + str(first['next_after']))[1]
        self.assertEqual(len(second['items']), 1)
        self.assertEqual(second['default_profile_id'], profile)
        self.assertIsNone(second['next_after'])
        self.assertEqual(self.request('/service-clients/999999/profiles')[0], 404)

    def test_profile_overflow_is_marked_and_cannot_silently_drop_assignments(self):
        client, profile, engine = self.profile_fixture()
        ids = [engine] + [db.create_engine_instance('static_metadata', f'Extra {n}') for n in range(100)]
        db.set_scan_profile_engines(profile, ids)
        data = self.request(f'/service-clients/{client}/profiles')[1]
        self.assertTrue(data['engines_incomplete'])
        self.assertTrue(data['items'][0]['incomplete'])
        self.assertEqual(len(data['engines']), 100)
        self.assertEqual(len(data['items'][0]['engine_ids']), 100)
        body = {'engine_ids': [engine], 'expected_engine_ids': data['items'][0]['engine_ids']}
        self.assertEqual(self.request(f'/service-clients/{client}/profiles/{profile}/engines', 'PUT', body)[0], 409)
        self.assertEqual(len(db.list_scan_profile_engines(profile)), 101)

    def expired_scan(self, **kwargs):
        scan = self.create_scan(**kwargs)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET created_at = '2000-01-01 00:00:00' WHERE id = ?", (scan,))
        return scan

    @patch.dict('os.environ', {'MASP_RETENTION_DAYS': '30', 'MASP_RETENTION_BATCH_SIZE': '2'})
    def test_retention_authorization_before_body_and_strict_limits(self):
        item = {'scan_id': 1, 'attempt': 0, 'job_revision': 0}
        body = {'days': 30, 'batch_size': 2, 'scans': [item]}
        self.assertEqual(self.request('/system/retention', session=False)[0], 401)
        for options, expected in (({'session': False}, 401), ({'csrf': False}, 403)):
            self.assertEqual(self.request('/system/retention/run', 'POST', body, **options)[0], expected)
            self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        self.assertEqual(self.request('/system/retention')[0], 403)
        self.assertEqual(self.request('/system/retention/run', 'POST', body)[0], 403)
        self.assertEqual(self.reads, 0)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'admin' WHERE id = ?", (self.user_id,))
        for fields in ({'scans': []}, {'scans': [item, item]}, {'days': '30'}, {'cutoff': '2099-01-01'},
                       {'scans': [item] * 21}, {'scans': [dict(item, scan_id=n) for n in (1, 2, 3)]}):
            self.assertEqual(self.request('/system/retention/run', 'POST', body | fields)[0], 422)

    @patch.dict('os.environ', {'MASP_RETENTION_DAYS': '30', 'MASP_RETENTION_BATCH_SIZE': '2'})
    def test_retention_preview_is_bounded_all_source_and_skips_active(self):
        one = self.expired_scan(status='completed', source='api')
        two = self.expired_scan(status='failed', source='icap')
        three = self.expired_scan(status='completed', scan_role='child')
        for status in ('queued', 'running', 'finalizing'):
            self.expired_scan(status=status)
        self.create_scan(status='completed')
        status, first, headers = self.request('/system/retention')
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual([r['scan_id'] for r in first['items']], [one, two])
        self.assertNotIn('/private/storage', json.dumps(first))
        second = self.request('/system/retention?after=' + str(first['next_after']))[1]
        self.assertEqual([r['scan_id'] for r in second['items']], [three])
        self.assertIsNone(second['next_after'])
        self.assertEqual(self.request('/system/retention?after=0')[0], 422)

    @patch.dict('os.environ', {'MASP_RETENTION_DAYS': '30', 'MASP_RETENTION_BATCH_SIZE': '20'})
    def test_retention_rechecks_age_attempt_revision_and_protections(self):
        deleted = self.expired_scan(status='completed', source='api')
        active = self.expired_scan(status='finalizing')
        stale = self.expired_scan(status='completed')
        revision = self.expired_scan(status='completed')
        young = self.create_scan(status='completed')
        parent = self.expired_scan(status='completed')
        self.create_scan(parent_scan_id=parent, scan_role='child', status='completed')
        shared = self.expired_scan(status='completed')
        db.create_scan_job(db.get_scan(shared).sample_id, '', 'normal', '', status='completed')
        pending = self.expired_scan(status='completed', source='api')
        client = db.create_service_client('retention-client', 'Retention client')
        with db.connect() as connection:
            connection.execute('''INSERT INTO notification_outbox
                (scan_job_id, service_client_id, event_type, idempotency_key, payload_json)
                VALUES (?, ?, 'malware.detected', 'retention-event', '{}')''', (pending, client))
        ids = [deleted, active, stale, revision, young, parent, shared, pending]
        rows = [{'scan_id': n, 'attempt': 1 if n == stale else 0, 'job_revision': 1 if n == revision else 0} for n in ids]
        with patch.object(retention_admin, 'delete_sample_file', side_effect=PermissionError('private')):
            status, result, _ = self.request('/system/retention/run', 'POST', {'days': 30, 'batch_size': 20, 'scans': rows})
        self.assertEqual(status, 200)
        self.assertEqual(result['deleted_ids'], [deleted])
        self.assertEqual(result['cleanup_failed_ids'], [deleted])
        self.assertEqual(result['blocked_ids'], ids[1:])
        for scan in ids[1:]:
            self.assertIsNotNone(db.get_scan(scan))

    def test_retention_disabled_changed_policy_and_invalid_date_fail_closed(self):
        scan = self.expired_scan(status='completed')
        body = {'days': 30, 'batch_size': 20, 'scans': [{'scan_id': scan, 'attempt': 0, 'job_revision': 0}]}
        for days in ('0', '31', '999999999999999999'):
            with patch.dict('os.environ', {'MASP_RETENTION_DAYS': days, 'MASP_RETENTION_BATCH_SIZE': '20'}):
                self.assertEqual(self.request('/system/retention/run', 'POST', body)[0], 409)
                self.assertIsNotNone(db.get_scan(scan))
                if days == '0':
                    self.assertEqual(self.request('/system/retention')[1]['items'], [])

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

    def test_printable_report_is_source_scoped_for_analysts(self):
        scan, _ = self.report_fixture(detected=True)
        automation = self.create_scan(source='api', status='completed',
                                      profile_snapshot_json=json.dumps({'engines': []}))
        self.assertEqual(self.request(f'/scans/{scan}/print', session=False)[0], 401)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        status, payload, headers = self.request(f'/scans/{scan}/print')
        self.assertEqual(status, 200, payload)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(payload['scan_id'], scan)
        self.assertEqual(payload['source'], 'manual')
        # Legacy /scans/{id}/report had no source scope at all; both directions
        # must now refuse the other history.
        self.assertEqual(self.request(f'/scans/{automation}/print')[0], 404)
        self.assertEqual(self.request(f'/api-ledger/scans/{scan}/print')[0], 404)
        self.assertEqual(self.request(f'/api-ledger/scans/{automation}/print')[0], 200)
        self.assertEqual(self.request('/scans/0/print')[0], 422)
        for method in ('POST', 'PUT', 'DELETE'):
            self.assertEqual(self.request(f'/scans/{scan}/print', method, {})[0], 405)

    def test_printable_report_bounds_output_and_omits_storage_metadata(self):
        scan = self.create_scan(status='completed', verdict='info', risk_score=0,
                                profile_snapshot_json=json.dumps({'engines': []}))
        db.create_engine_result(scan, EngineResultInput(engine_name='Verbose Engine', status='completed',
            detected=False, severity='info', confidence=100, signature=None,
            raw_output='v' * 20000, duration_ms=7))
        payload = self.request(f'/scans/{scan}/print')[1]
        engine = payload['engines'][0]
        self.assertEqual(len(engine['raw_output']), scan_management.PRINT_OUTPUT_LIMIT)
        self.assertTrue(engine['output_truncated'])
        serialized = json.dumps(payload)
        for private in ('/private/storage', 'internal.bin', 'password', 'details_json'):
            self.assertNotIn(private, serialized)

    def test_printable_report_suppresses_a_decision_on_invalid_policy(self):
        scan, _ = self.report_fixture(details='not-json')
        payload = self.request(f'/scans/{scan}/print')[1]
        self.assertIsNone(payload['decision'])
        self.assertIn('Decision unavailable', payload['decision_warning'])

    def test_raw_output_download_serves_text_beyond_the_json_limit(self):
        scan, result = self.report_fixture()
        oversized = 'z' * (scan_report_read.FULL_OUTPUT_LIMIT + 1024)
        with db.connect() as connection:
            connection.execute('UPDATE engine_results SET raw_output = ? WHERE id = ?', (oversized, result))
        # The JSON reader still refuses it; the download is the browser path.
        self.assertEqual(self.request(f'/scans/{scan}/results/{result}/full')[0], 413)
        status, served, headers = self.request(f'/scans/{scan}/results/{result}/output', raw=True)
        self.assertEqual(status, 200)
        self.assertEqual(served.decode(), oversized)
        self.assertEqual(headers[b'content-type'], b'text/plain; charset=utf-8')
        self.assertEqual(headers[b'content-disposition'],
                         f'attachment; filename="masp-scan-{scan}-result-{result}-output.txt"'.encode())
        self.assertEqual(headers[b'cache-control'], b'no-store')

    def test_raw_output_download_is_scoped_bounded_and_read_only(self):
        scan, result = self.report_fixture()
        automation = self.create_scan(source='api', status='completed')
        self.assertEqual(self.request(f'/scans/{scan}/results/{result}/output', session=False)[0], 401)
        self.assertEqual(self.request(f'/api-ledger/scans/{scan}/results/{result}/output')[0], 404)
        self.assertEqual(self.request(f'/scans/{automation}/results/{result}/output')[0], 404)
        self.assertEqual(self.request(f'/scans/{scan}/results/999999/output')[0], 404)
        for method in ('POST', 'PUT', 'DELETE'):
            self.assertEqual(self.request(f'/scans/{scan}/results/{result}/output', method, {})[0], 405)
        with patch.dict(os.environ, {'MASP_UI_RAW_OUTPUT_LIMIT': '1'}):
            # Never below the JSON ceiling this download exists to exceed.
            self.assertEqual(scan_report_read.raw_output_limit(), scan_report_read.FULL_OUTPUT_LIMIT)
        with patch.dict(os.environ, {'MASP_UI_RAW_OUTPUT_LIMIT': 'not-a-number'}):
            self.assertEqual(scan_report_read.raw_output_limit(), scan_report_read.RAW_OUTPUT_DEFAULT_LIMIT)
        with patch.object(scan_report_read, 'raw_output_limit', return_value=scan_report_read.FULL_OUTPUT_LIMIT):
            with db.connect() as connection:
                connection.execute('UPDATE engine_results SET raw_output = ? WHERE id = ?',
                                   ('y' * (scan_report_read.FULL_OUTPUT_LIMIT + 1), result))
            self.assertEqual(self.request(f'/scans/{scan}/results/{result}/output')[0], 413)

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

    def test_full_output_auth_source_ownership_and_complete_plain_text(self):
        scan, result = self.report_fixture()
        text = '<script>never execute</script>' + 'İ😀' * 17000
        with db.connect() as connection:
            connection.execute('UPDATE engine_results SET raw_output = ?, details_json = ?, findings_json = ? WHERE id = ?',
                               (text, '{invalid json', '["complete findings"]', result))
        path = f'/scans/{scan}/results/{result}/full'
        self.assertEqual(self.request(path, session=False)[0], 401)
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))
        status, payload, headers = self.request(path)
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(payload, {'scan_id': scan, 'result_id': result, 'engine_name': 'Historic Defender',
            'attempt_count': 0, 'raw_output': text, 'details_json': '{invalid json', 'findings_json': '["complete findings"]'})
        self.assertEqual(self.request(f'/scans/{scan}/results/{result}')[1]['truncated'], ['raw_output'])
        self.assertEqual(self.request(f'/scans/{scan}/results/{result + 1}/full')[0], 404)
        for source in ('api', 'icap'):
            other = self.create_scan(source=source)
            self.assertEqual(self.request(f'/scans/{other}/results/{result}/full')[0], 404)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET source = 'api' WHERE id = ?", (scan,))
        self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request('/scans/0/results/1/full')[0], 422)
        self.assertEqual(self.request('/scans/1/results/9007199254740992/full')[0], 422)

    def test_full_output_preflight_and_serialized_limits_reject_without_truncation(self):
        scan, result = self.report_fixture()
        path = f'/scans/{scan}/results/{result}/full'
        original = db.connect
        statements = []
        def traced():
            connection = original()
            connection.set_trace_callback(statements.append)
            return connection
        with db.connect() as connection:
            connection.execute('UPDATE engine_results SET raw_output = ? WHERE id = ?', ('😀' * 300, result))
        with patch.object(scan_report_read, 'FULL_OUTPUT_LIMIT', 1024), patch.object(db, 'connect', side_effect=traced):
            status, payload, _ = self.request(path)
        self.assertEqual(status, 413)
        self.assertIn('source limit', payload['detail'])
        self.assertFalse(any('j.id AS scan_id' in sql for sql in statements))
        with db.connect() as connection:
            connection.execute('UPDATE engine_results SET raw_output = ?, details_json = ?, findings_json = ? WHERE id = ?',
                               ('\x01' * 300, '{}', '[]', result))
        with patch.object(scan_report_read, 'FULL_OUTPUT_LIMIT', 1024):
            status, payload, _ = self.request(path)
        self.assertEqual(status, 413)
        self.assertIn('response limit', payload['detail'])

    def test_full_output_preflight_and_hydration_share_retry_snapshot(self):
        scan, result = self.report_fixture()
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
                if 'j.id AS scan_id' in sql and not fired:
                    fired = True
                    with original() as writer:
                        writer.execute('DELETE FROM engine_results WHERE scan_job_id = ?', (scan,))
                        writer.execute('UPDATE scan_jobs SET attempt_count = 1 WHERE id = ?', (scan,))
                return self.connection.execute(sql, params)
        with patch.object(db, 'connect', return_value=Reader()):
            output = scan_report_read.full_technical_details(scan, result)
        self.assertTrue(fired)
        self.assertEqual((output.result_id, output.attempt_count, output.raw_output),
                         (result, 0, '<script>not executable</script>'))
        self.assertEqual(self.request(f'/scans/{scan}/results/{result}/full')[0], 404)

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
                                    'risk_level', 'risk_score', 'attempt_count', 'job_revision', 'created_at',
                                    'unavailable_engines'})
        self.assertEqual((row['attempt_count'], row['job_revision']), (0, 0))
        self.assertIsNone(row['unavailable_engines'])  # not recorded for this fixture
        with db.connect() as connection:
            connection.execute('UPDATE scan_jobs SET unavailable_engines = 2 WHERE id = ?', (scan,))
        self.assertEqual(next(r for r in self.request('/dashboard/scans')[1]['items'] if r['id'] == scan)['unavailable_engines'], 2)
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

    def test_dashboard_detection_filter_uses_recorded_results_without_hydration(self):
        detected, _ = self.report_fixture(detected=True)
        clean, _ = self.report_fixture(detected=False)
        failed_engine, _ = self.report_fixture(detected=False, result_status='failed')
        running = self.create_scan(status='running')
        metadata = self.create_scan(status='completed', verdict='metadata_only')
        ids = lambda query: [row['id'] for row in self.request('/dashboard/scans?' + query)[1]['items']]
        self.assertEqual(ids('detection=detected'), [detected])
        # Finished with no recorded detection; an active scan is never "undetected".
        self.assertEqual(ids('detection=undetected'), [metadata, failed_engine, clean])
        self.assertNotIn(running, ids('detection=undetected'))
        self.assertEqual(ids('risk=metadata_only'), [metadata])
        self.assertEqual(self.request('/dashboard/scans?detection=clean')[0], 422)

    def test_dashboard_query_limits_fail_closed(self):
        for query in ('limit=0', 'limit=101', 'before=0', 'before=-1', 'before=9007199254740992',
                      'before=invalid', 'status=invalid', 'risk=clean', 'detection=malicious', 'q=' + 'a' * 201):
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

    def test_new_secret_without_server_encryption_key_is_refused_and_not_stored(self):
        config = {field.key: field.default for field in ui_api.ADAPTERS['virustotal'].config_fields}
        config['api_key'] = 'synthetic-vendor-secret'
        with patch.dict('os.environ', {'MASP_SECRET_ENCRYPTION_KEY': ''}):
            status, body, _ = self.request('/engines', 'POST', {'adapter_key': 'virustotal', 'display_name': 'VT', 'config': config})
        self.assertEqual(status, 422, body)
        self.assertIn('MASP_SECRET_ENCRYPTION_KEY', body['detail'])
        self.assertNotIn('synthetic-vendor-secret', json.dumps(body))
        self.assertFalse(any(engine.adapter_key == 'virustotal' for engine in db.list_engine_instances()))

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


@unittest.skipUnless(os.getenv('MASP_TEST_POSTGRES_URL'), 'requires disposable PostgreSQL')
class BrowserReadPostgresTests(unittest.TestCase):
    """Audit and About readers on real PostgreSQL.

    SQLite returns 0/1 where PostgreSQL returns booleans, and SUBSTR/LENGTH on
    a NULL column differ enough between them that the SQLite suite cannot prove
    these projections.
    """

    def setUp(self):
        import psycopg
        url = os.environ['MASP_TEST_POSTGRES_URL']
        with psycopg.connect(url, autocommit=True) as connection:
            connection.execute('DROP SCHEMA IF EXISTS public CASCADE')
            connection.execute('CREATE SCHEMA public')
        self.original = db.DATABASE_URL, db.DB_POOL_ENABLED
        db.close_pool()
        db.DATABASE_URL, db.DB_POOL_ENABLED = url, False
        db.init_db()

    def tearDown(self):
        db.close_pool()
        db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def event(self, **overrides):
        fields = dict(actor_type='user', actor_id='1', actor_name='pg-admin', action='engine.update',
                      target_type='engine', target_id='4', outcome='success', source_ip='127.0.0.1',
                      request_id='pg-req', details_json='{"changed": true}')
        return db.create_audit_event(**(fields | overrides))

    def test_audit_projection_keyset_and_literal_search(self):
        ids = [self.event(request_id=f'pg-req-{index}') for index in range(3)]
        nulls = self.event(actor_id=None, actor_name=None, target_id=None, source_ip=None, outcome='denied')
        big = self.event(details_json='{"marker": "' + 'q' * 9000 + '"}', actor_name='ops%team')
        page = audit_read.page(limit=3, before=None, query='', outcome='all')
        self.assertEqual([row.id for row in page.items], [big, nulls, ids[2]])
        self.assertEqual(page.next_before, ids[2])
        self.assertEqual([row.id for row in audit_read.page(limit=10, before=page.next_before, query='', outcome='all').items], ids[:2][::-1])
        # PostgreSQL yields a real boolean here; the payload must stay JSON-safe.
        truncated = page.items[0]
        self.assertIs(truncated.details_truncated, True)
        self.assertEqual(len(truncated.details), audit_read.DETAILS_LIMIT)
        self.assertIs(page.items[1].details_truncated, False)
        blank = next(row for row in page.items if row.id == nulls)
        self.assertIsNone(blank.actor_id)
        self.assertIsNone(blank.actor_name)
        self.assertIsNone(blank.source_ip)
        self.assertEqual([row.id for row in audit_read.page(limit=10, before=None, query='ops%team', outcome='all').items], [big])
        self.assertEqual([row.id for row in audit_read.page(limit=10, before=None, query='%', outcome='all').items], [big])
        self.assertEqual([row.id for row in audit_read.page(limit=10, before=None, query='', outcome='denied').items], [nulls])

    def test_audit_read_honours_the_statement_budget(self):
        self.event()
        with patch.object(browser_db_budget, 'read_timeout_ms', return_value=browser_db_budget.MIN_TIMEOUT_MS):
            with patch.object(db, 'connect', wraps=db.connect) as tracked:
                audit_read.page(limit=1, before=None, query='', outcome='all')
        self.assertEqual(tracked.call_count, 1)

    def test_about_counts_nodes_and_clients_without_scan_history(self):
        db.create_service_client('pg-client', 'PostgreSQL client')
        db.upsert_worker_node_heartbeat(node_id='pg-node', display_name='PG node', hostname='pg-host',
            platform='linux', agent_version='test', labels_json='{}', capacity=1,
            advertised_engine_keys_json='[]', runtime_state='idle', active_scan_id=None,
            process_id=0, last_heartbeat_at=int(time.time()))
        admin_view = about_read.snapshot(admin=True)
        self.assertEqual(admin_view.service_client_count, 1)
        self.assertEqual(admin_view.registered_nodes, 1)
        self.assertEqual(admin_view.schedulable_nodes, 1)
        self.assertIsNone(about_read.snapshot(admin=False).service_client_count)
