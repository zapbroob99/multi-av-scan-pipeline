import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

from fastapi import HTTPException, UploadFile
from app import database as db
from app.services import profile_admin as admin
from app.services.service_clients import resolve_stored_api_client, resolve_profile_routing, profile_snapshot_json, hash_api_token, engines_for_scan
from app.models import StoredSample


class ProfileManagementTests(unittest.TestCase):
    postgres = False

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original = db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED
        db.close_pool()
        db.DB_PATH = Path(self.temp.name) / 'profiles.db'
        db.DATABASE_URL = os.environ['MASP_TEST_POSTGRES_URL'] if self.postgres else ''
        db.DB_POOL_ENABLED = False
        if self.postgres:
            import psycopg
            with psycopg.connect(db.DATABASE_URL, autocommit=True) as connection:
                connection.execute('DROP SCHEMA IF EXISTS public CASCADE')
                connection.execute('CREATE SCHEMA public')
        db.init_db()
        self.metadata = db.create_engine_instance('static_metadata', 'Metadata')
        self.clamav = db.create_engine_instance('clamav', 'ClamAV')
        self.token = 'synthetic-profile-test-token-xxxxxxxxxxxxxxxx'
        self.client, self.default, _ = db.create_service_client_bundle(client_key='profile-test', display_name='Profiles',
            profile_name='Standard', engine_instance_ids=[self.clamav], credential_label='Test',
            token_hash=hash_api_token(self.token), token_prefix='synthetic')
        self.identity = resolve_stored_api_client(self.token)

    def tearDown(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original
        self.temp.cleanup()

    def create(self, name='Metadata only'):
        return admin.create(self.client, admin.ProfileCreateBody(name=name, engine_ids=[self.metadata])).profile_id

    def http(self, path, *, method='GET', body=b'', content_type='application/json', authenticate=True):
        from app.main import app
        parsed = urlsplit(path)
        headers = [(b'host', b'testserver'), (b'content-type', content_type.encode()), (b'content-length', str(len(body)).encode())]
        if authenticate:
            headers.append((b'authorization', f'Bearer {self.token}'.encode()))
        scope = dict(type='http', asgi={'version': '3.0', 'spec_version': '2.3'}, http_version='1.1',
            method=method, scheme='http', path=parsed.path, raw_path=parsed.path.encode(), query_string=parsed.query.encode(),
            root_path='', headers=headers, server=('testserver', 80), client=('127.0.0.1', 1234))
        messages = []
        self.body_reads = 0
        async def receive():
            self.body_reads += 1
            return {'type': 'http.request', 'body': body, 'more_body': False}
        async def send(message):
            messages.append(message)
        asyncio.run(app(scope, receive, send))
        status = next(m['status'] for m in messages if m['type'] == 'http.response.start')
        payload = b''.join(m.get('body', b'') for m in messages if m['type'] == 'http.response.body')
        return status, json.loads(payload) if payload else None

    def test_http_upload_profile_binding_validation_and_prebody_auth(self):
        named = self.create()
        def submit(profile, authenticate=True):
            body = (f'--profile-test\r\nContent-Disposition: form-data; name="profile_id"\r\n\r\n{profile}\r\n'
                '--profile-test\r\nContent-Disposition: form-data; name="sample"; filename="test.txt"\r\n'
                'Content-Type: text/plain\r\n\r\nplain content\r\n--profile-test--\r\n').encode()
            return self.http('/api/v1/scans', method='POST', body=body,
                content_type='multipart/form-data; boundary=profile-test', authenticate=authenticate)
        with patch('app.services.ingest.SAMPLES_DIR', Path(self.temp.name) / 'samples'):
            status, payload = submit(named)
        self.assertEqual(status, 202, payload)
        self.assertEqual(db.get_scan(payload['scan']['id']).scan_profile_id, named)
        self.assertEqual(submit(999999)[0], 404)
        self.assertEqual(submit('invalid')[0], 422)
        self.assertEqual(submit(0)[0], 422)
        self.assertIn(submit(named, False)[0], (401, 503))
        self.assertEqual(self.body_reads, 0)

    def test_deferred_http_selection_idempotency_and_foreign_profile_rejection(self):
        named = self.create()
        payload = dict(profile_id=named, backend_key='test', object_id='sample.bin', original_filename='sample.bin', client_request_id='http-test')
        def submit(values):
            return self.http('/api/v1/deferred-scans', method='POST', body=json.dumps(values).encode())
        with patch('app.main.configured_backend_keys', return_value=['test']), patch('app.main.backend_allowed_for_client', return_value=True):
            status, response = submit(payload)
            self.assertEqual(status, 202, response)
            with db.connect() as connection:
                row = connection.execute('SELECT scan_profile_id, profile_snapshot_json FROM deferred_scan_submissions WHERE client_request_id = ?', ('http-test',)).fetchone()
            self.assertEqual(row['scan_profile_id'], named)
            self.assertEqual(json.loads(row['profile_snapshot_json'])['engines'][0]['id'], self.metadata)
            self.assertEqual(submit(payload)[0], 202)
            self.assertEqual(submit(payload | {'profile_id': self.default})[0], 409)
            self.assertEqual(submit(payload | {'profile_id': 999999})[0], 404)
            self.assertEqual(submit(payload | {'profile_id': True})[0], 422)

    def test_named_profiles_preserve_source_quota_filtering_and_legacy_scope(self):
        from dataclasses import replace
        metered = db.create_engine_instance('virustotal', 'Metered')
        disabled = db.create_engine_instance('clamav', 'Disabled', enabled=False)
        named = db.create_scan_profile(self.client, 'Mixed', engine_instance_ids=[self.metadata, metered, disabled])
        self.assertEqual([e.id for e in resolve_profile_routing(self.identity, named)[1]], [self.metadata])
        self.assertEqual(resolve_profile_routing(self.identity, named, hash_lookup=True)[1], [])
        with self.assertRaises(ValueError):
            resolve_profile_routing(replace(self.identity, legacy_credential=True), named)
        status, _ = self.http(f'/api/v1/hashes/{"0" * 64}?profile_id={named}')
        self.assertEqual(status, 503)
        self.assertEqual(self.http(f'/api/v1/hashes/{"0" * 64}?profile_id=999999')[0], 404)

    def test_legacy_seed_keeps_an_existing_differently_named_default(self):
        client = db.create_service_client('legacy-default', 'Legacy')
        profile = db.create_scan_profile(client, 'Existing default', engine_instance_ids=[self.metadata], is_default=True)
        first = db.ensure_legacy_service_client_profile([self.metadata, self.clamav])
        second = db.ensure_legacy_service_client_profile([self.metadata, self.clamav])
        self.assertEqual(first[1].id, profile)
        self.assertEqual(second[1].id, profile)
        self.assertEqual(len(db.list_scan_profiles(client)), 1)

    def test_icap_uses_the_new_bound_default_and_persists_its_routing(self):
        from app.icap import server
        from app.icap.config import IcapConfig
        named = self.create()
        self.manage(named, 'default', expected_default_profile_id=self.default)
        with patch('app.services.ingest.SAMPLES_DIR', Path(self.temp.name) / 'samples'), \
             patch.object(server, 'wait_for_terminal_scan', new=AsyncMock(return_value=None)):
            # A timeout remains fail-closed; this test exercises actual intake,
            # without waiting for or starting a scanner.
            self.assertEqual(asyncio.run(server.scan_and_decide('icap.txt', 'text/plain', b'icap content',
                IcapConfig(service_client_key='profile-test', wait_seconds=0))), 'block')
        with db.connect() as connection:
            row = connection.execute("SELECT service_client_id, scan_profile_id, profile_snapshot_json FROM scan_jobs WHERE source = 'icap'").fetchone()
        self.assertEqual(row['service_client_id'], self.client)
        self.assertEqual(row['scan_profile_id'], named)
        self.assertEqual(json.loads(row['profile_snapshot_json'])['engines'][0]['id'], self.metadata)

    def test_unknown_enabled_adapter_is_not_silently_dropped_from_required_routing(self):
        named = self.create()
        with db.connect() as connection:
            connection.execute("UPDATE engine_instances SET adapter_key = 'unregistered-test-adapter' WHERE id = ?", (self.metadata,))
        with self.assertRaises(KeyError):
            resolve_profile_routing(self.identity, named)

    def profile(self, profile_id):
        return next(p for p in admin.page(self.client, None).items if p.id == profile_id)

    def manage(self, profile_id, operation, **values):
        body_class = {'update': admin.ProfileUpdateBody, 'default': admin.ProfileDefaultBody, 'delete': admin.ProfileFence}[operation]
        body = body_class(expected_revision=self.profile(profile_id).management_revision, **values)
        admin.manage(self.client, profile_id, body, operation)

    def test_create_rename_default_and_scope_preserve_default_until_changed(self):
        named = self.create()
        self.assertEqual(db.get_default_scan_profile_for_client(self.client).id, self.default)
        selected, engines = resolve_profile_routing(self.identity, named)
        self.assertEqual(selected.profile.id, named)
        self.assertEqual([e.id for e in engines], [self.metadata])
        self.manage(named, 'update', name='Fast metadata', enabled=True)
        self.manage(named, 'default', expected_default_profile_id=self.default)
        self.assertEqual(resolve_profile_routing(self.identity)[0].profile.id, named)
        self.assertEqual(resolve_stored_api_client(self.token).profile.id, named)
        other = db.create_service_client('other', 'Other')
        other_profile = db.create_scan_profile(other, 'Other', engine_instance_ids=[self.metadata])
        for profile_id in (other_profile, 999999):
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                resolve_profile_routing(self.identity, profile_id)
        with self.assertRaises(HTTPException):
            admin.manage(other, named, admin.ProfileFence(expected_revision=self.profile(named).management_revision), 'delete')

    def test_default_cannot_be_disabled_or_deleted_and_duplicate_name_rolls_back(self):
        with self.assertRaises(HTTPException):
            self.manage(self.default, 'delete')
        with self.assertRaises(HTTPException):
            self.manage(self.default, 'update', name='Standard', enabled=False)
        named = self.create()
        with self.assertRaises(HTTPException):
            self.manage(named, 'update', name='Standard', enabled=True)
        self.assertEqual(self.profile(named).name, 'Metadata only')
        self.manage(named, 'update', name='Metadata only', enabled=False)
        with self.assertRaises(HTTPException):
            self.manage(named, 'default', expected_default_profile_id=self.default)
        with self.assertRaises(ValueError):
            resolve_profile_routing(self.identity, named)

    def test_deletion_preserves_accepted_scans_deferred_rows_and_snapshots(self):
        named = self.create()
        identity, engines = resolve_profile_routing(self.identity, named)
        snapshot = profile_snapshot_json(identity, engines)
        sample = db.create_sample(StoredSample('sample.bin', 'sample.bin', str(Path(self.temp.name) / 'sample.bin'),
            'application/octet-stream', 1, '0' * 32, '0' * 40, '0' * 64))
        scan = db.create_scan_job(sample, 'Test', 'Normal', '', source='api', service_client_id=self.client,
            scan_profile_id=named, profile_snapshot_json=snapshot)
        deferred, _ = db.create_deferred_scan_submission(service_client_id=self.client, scan_profile_id=named,
            client_request_id='immutable', backend_key='test', object_id='sample.bin', original_filename='sample.bin',
            content_type='application/octet-stream', expected_size_bytes=1, expected_sha256=None,
            archive_mode='none', case_name='Test', priority='Normal', note='', profile_snapshot_json=snapshot)
        self.manage(named, 'delete')
        self.assertNotIn(named, [p.id for p in admin.page(self.client, None).items])
        self.assertEqual(db.get_scan(scan).profile_snapshot_json, snapshot)
        self.assertEqual([e.id for e in engines_for_scan(db.get_scan(scan))], [self.metadata])
        self.assertEqual(db.get_deferred_scan_submission(deferred.id).profile_snapshot_json, snapshot)
        self.assertEqual([e.id for e in db.list_scan_profile_engines(named)], [self.metadata])
        with self.assertRaises(ValueError):
            resolve_profile_routing(self.identity, named)
        with self.assertRaises(ValueError):
            db.set_scan_profile_engines(named, [self.clamav])
        db.init_db()
        self.assertNotIn(named, [p.id for p in db.list_scan_profiles(self.client)])

    def test_revision_fences_include_legacy_engine_updates_and_old_default(self):
        named = self.create()
        old = self.profile(named).management_revision
        db.set_scan_profile_engines(named, [self.clamav])
        with self.assertRaises(HTTPException):
            admin.manage(self.client, named, admin.ProfileFence(expected_revision=old), 'delete')
        self.manage(named, 'update', name='Renamed', enabled=True)
        with self.assertRaises(HTTPException):
            admin.save(self.client, named, admin.ProfileRoutingBody(engine_ids=[self.metadata], expected_engine_ids=[self.clamav], expected_revision=old))
        with self.assertRaises(HTTPException):
            self.manage(named, 'default', expected_default_profile_id=None)

    def test_concurrent_default_switches_have_one_winner_and_one_default(self):
        one, two = self.create('One'), self.create('Two')
        barrier = threading.Barrier(2)
        def change(profile):
            barrier.wait(timeout=5)
            try:
                admin.manage(self.client, profile, admin.ProfileDefaultBody(expected_revision=0,
                    expected_default_profile_id=self.default), 'default')
                return 204
            except HTTPException as exc:
                return exc.status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(change, [one, two]))
        self.assertEqual(sorted(outcomes), [204, 409])
        self.assertEqual(len([p for p in db.list_scan_profiles(self.client) if p.is_default]), 1)

    def test_upgrade_repairs_duplicate_defaults_and_adds_fences_without_rewriting_history(self):
        named = self.create()
        with db.connect() as connection:
            connection.execute('DROP INDEX idx_scan_profiles_one_default')
            connection.execute('DROP INDEX idx_scan_profiles_client_seek')
            connection.execute('ALTER TABLE scan_profiles DROP COLUMN management_revision')
            connection.execute('ALTER TABLE scan_profiles DROP COLUMN deleted_at')
            connection.execute('UPDATE scan_profiles SET is_default = ? WHERE id = ?', (db.db_bool(True), named))
        db.init_db()
        self.assertEqual([p.id for p in db.list_scan_profiles(self.client) if p.is_default], [self.default])
        self.assertEqual(self.profile(named).management_revision, 1)
        with self.assertRaises(db.IntegrityViolation):
            with db.connect() as connection:
                connection.execute('UPDATE scan_profiles SET is_default = ? WHERE id = ?', (db.db_bool(True), named))
        db.init_db()
        self.assertEqual(self.profile(named).management_revision, 1)

    def test_upload_selection_is_recorded_and_bad_selection_does_not_store_a_sample(self):
        from app.main import enqueue_scan_from_upload
        named = self.create()
        with patch('app.services.ingest.SAMPLES_DIR', Path(self.temp.name) / 'samples'):
            scan = asyncio.run(enqueue_scan_from_upload(UploadFile(BytesIO(b'plain content'), filename='test.txt'),
                case_name='Test', priority='Normal', note='', source='api', api_identity=self.identity, requested_profile_id=named))
        self.assertEqual(scan.scan_profile_id, named)
        self.assertEqual(json.loads(scan.profile_snapshot_json)['engines'][0]['id'], self.metadata)
        with patch('app.main.store_upload') as store:
            with self.assertRaises(HTTPException) as error:
                asyncio.run(enqueue_scan_from_upload(UploadFile(BytesIO(b'bad'), filename='test.txt'),
                    case_name='Test', priority='Normal', note='', source='api', api_identity=self.identity, requested_profile_id=999999))
            self.assertEqual(error.exception.status_code, 404)
            store.assert_not_called()


@unittest.skipUnless(os.getenv('MASP_TEST_POSTGRES_URL'), 'requires disposable PostgreSQL')
class ProfileManagementPostgresTests(ProfileManagementTests):
    postgres = True

    def test_intake_profile_and_engines_share_a_snapshot_during_concurrent_edit(self):
        named = self.create()
        original_connect = db.connect
        reader_thread = threading.get_ident()
        changed = False
        def edit():
            with db.profile_write_transaction(self.client) as (connection, _):
                connection.execute("UPDATE scan_profiles SET name = 'Changed', management_revision = management_revision + 1 WHERE id = ?", (named,))
                connection.execute('DELETE FROM scan_profile_engines WHERE scan_profile_id = ?', (named,))
                connection.execute('INSERT INTO scan_profile_engines (scan_profile_id, engine_instance_id, required) VALUES (?, ?, ?)',
                    (named, self.clamav, db.db_bool(True)))
        class Reader:
            def __init__(self, connection):
                self.connection = connection
            def execute(self, query, *args):
                nonlocal changed
                result = self.connection.execute(query, *args)
                if not changed and 'SELECT * FROM scan_profiles WHERE service_client_id' in query:
                    changed = True
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        executor.submit(edit).result(timeout=10)
                return result
        @contextmanager
        def connect():
            with original_connect() as connection:
                yield Reader(connection) if threading.get_ident() == reader_thread else connection
        with patch.object(db, 'connect', connect):
            identity, engines = resolve_profile_routing(self.identity, named)
        self.assertTrue(changed)
        self.assertEqual(identity.profile.name, 'Metadata only')
        self.assertEqual([e.id for e in engines], [self.metadata])
        current, engines = resolve_profile_routing(self.identity, named)
        self.assertEqual(current.profile.name, 'Changed')
        self.assertEqual([e.id for e in engines], [self.clamav])
