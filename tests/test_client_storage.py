import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app import database as db
from app.services import client_storage_admin as admin
from app.services.client_storage_policy import StorageGrant
from app.services.deferred_storage import backend_allowed_for_client, DeferredSourceError
from app.services.service_clients import hash_api_token, resolve_stored_api_client, resolve_profile_routing, profile_snapshot_json


class ClientStorageTests(unittest.TestCase):
    postgres = False

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.temp.name)
        self.original = db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.root / 'storage.db', os.environ['MASP_TEST_POSTGRES_URL'] if self.postgres else '', False
        if self.postgres:
            import psycopg
            with psycopg.connect(db.DATABASE_URL, autocommit=True) as connection:
                connection.execute('DROP SCHEMA IF EXISTS public CASCADE')
                connection.execute('CREATE SCHEMA public')
        db.init_db()
        self.engine = db.create_engine_instance('static_metadata', 'Metadata')
        self.token = 'synthetic-storage-test-token-xxxxxxxxxxxxxxxx'
        self.client, self.profile, _ = db.create_service_client_bundle(client_key='storage-client', display_name='Storage client',
            profile_name='Default', engine_instance_ids=[self.engine], credential_label='Test',
            token_hash=hash_api_token(self.token), token_prefix='synthetic')
        self.other = db.create_service_client('other', 'Other')
        self.environment = patch.dict(os.environ, {
            'MASP_DEFERRED_STORAGE_BACKENDS_JSON': json.dumps({'shared': str(self.root / 'private-root'), 'archive': str(self.root / 'archive-root')}),
            'MASP_DEFERRED_BACKEND_CLIENTS_JSON': '{"shared":["storage-client","other"]}',
            'MASP_DEFERRED_MAX_BYTES': '0',
        })
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original
        self.temp.cleanup()

    def body(self, grants=(), mode='custom'):
        current = admin.read(self.client)
        return admin.StorageAccessUpdate(expected_revision=current.revision,
            expected_environment_fingerprint=current.environment_fingerprint, mode=mode,
            grants=[StorageGrant.model_validate(grant) for grant in grants])

    def save(self, grants=(), mode='custom'):
        admin.save(self.client, self.body(grants, mode))

    def allowed(self, backend='shared', object_id='incoming/a.bin', client='storage-client'):
        return backend_allowed_for_client(backend, client, object_id)

    def test_environment_compatibility_custom_replacement_deny_all_and_reset(self):
        current = admin.read(self.client)
        self.assertEqual(current.mode, 'environment')
        self.assertTrue(self.allowed())
        self.save([{'backend_key': 'archive', 'access': 'all'}])
        self.assertFalse(self.allowed())
        self.assertTrue(self.allowed('archive'))
        self.assertTrue(self.allowed(client='other'))
        self.save()
        self.assertFalse(self.allowed('archive'))
        self.assertFalse(self.allowed())
        self.save(mode='environment')
        self.assertTrue(self.allowed())
        self.assertEqual(admin.read(self.client).revision, 3)
        self.assertEqual(admin.read(self.client).mode, 'environment')

    def test_prefix_boundaries_and_invalid_paths_cannot_widen_a_grant(self):
        self.save([{'backend_key': 'shared', 'access': 'prefixes', 'prefixes': [' incoming/client-a/ ', 'incoming/client-a']}])
        self.assertTrue(self.allowed(object_id='incoming/client-a/a.bin'))
        self.assertFalse(self.allowed(object_id='incoming/client-ab/a.bin'))
        self.assertFalse(self.allowed(object_id='other/a.bin'))
        self.assertEqual(admin.read(self.client).grants[0].prefixes, ['incoming/client-a/'])
        for prefix in ('.', '/', '../a', 'a/../b', 'C:/private', '\\private', 'a\x00b'):
            with self.subTest(prefix=prefix), self.assertRaises(HTTPException):
                self.save([{'backend_key': 'shared', 'access': 'prefixes', 'prefixes': [prefix]}])
        with self.assertRaises(HTTPException):
            self.save([{'backend_key': 'shared', 'access': 'prefixes', 'prefixes': []}])
        self.assertEqual(admin.read(self.client).revision, 1)

    def test_revision_and_environment_fences_include_return_to_inheritance(self):
        stale = self.body()
        self.save()
        self.save(mode='environment')
        with self.assertRaises(HTTPException) as error:
            admin.save(self.client, stale)
        self.assertEqual(error.exception.status_code, 409)
        stale = self.body()
        with patch.dict(os.environ, {'MASP_DEFERRED_BACKEND_CLIENTS_JSON': '{"archive":["storage-client"]}'}):
            with self.assertRaises(HTTPException) as error:
                admin.save(self.client, stale)
            self.assertEqual(error.exception.status_code, 409)
        with patch.dict(os.environ, {'MASP_DEFERRED_STORAGE_BACKENDS_JSON': json.dumps({'shared': str(self.root)})}):
            with self.assertRaises(HTTPException):
                admin.save(self.client, stale)

    def test_two_concurrent_first_writes_have_one_winner(self):
        body = self.body([{'backend_key': 'shared', 'access': 'all'}])
        barrier = threading.Barrier(2)
        def save(_):
            barrier.wait(timeout=5)
            try:
                admin.save(self.client, body)
                return 204
            except HTTPException as exc:
                return exc.status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sorted(executor.map(save, range(2))), [204, 409])
        self.assertEqual(admin.read(self.client).revision, 1)

    def test_unknown_removed_backends_and_managed_client_cannot_gain_access(self):
        with self.assertRaises(HTTPException):
            self.save([{'backend_key': 'unknown', 'access': 'all'}])
        self.save([{'backend_key': 'shared', 'access': 'all'}])
        with patch.dict(os.environ, {'MASP_DEFERRED_STORAGE_BACKENDS_JSON': json.dumps({'archive': str(self.root)})}):
            self.assertFalse(self.allowed())
            view = admin.read(self.client)
            self.assertNotIn('shared', view.backends)
            self.assertEqual(view.grants[0].backend_key, 'shared')
        managed = db.create_service_client('legacy-default', 'Legacy')
        with self.assertRaises(HTTPException) as error:
            admin.save(managed, self.body())
        self.assertEqual(error.exception.status_code, 409)
        with self.assertRaises(HTTPException):
            admin.read(999999)

    def test_invalid_stored_policy_and_database_failure_never_fall_back_to_environment(self):
        self.save()
        for raw in ('{', '{}', '[{"backend_key":"shared","access":"prefixes","prefixes":[]}]', 'x' * 65537):
            with db.connect() as connection:
                connection.execute('UPDATE service_client_storage_policies SET grants_json = ? WHERE service_client_id = ?', (raw, self.client))
            with self.assertRaises(DeferredSourceError):
                self.allowed()
            with self.assertRaises(HTTPException):
                admin.read(self.client)
        with patch.object(db, 'connect', side_effect=sqlite3.OperationalError('Unavailable')):
            with self.assertRaises(DeferredSourceError):
                self.allowed()

    def test_bounded_metadata_omits_roots_and_rejects_incomplete_configuration(self):
        serialized = admin.read(self.client).model_dump_json()
        self.assertNotIn('private-root', serialized)
        self.assertNotIn(self.token, serialized)
        with patch.dict(os.environ, {'MASP_DEFERRED_STORAGE_BACKENDS_JSON': json.dumps({f'b{i}': str(self.root) for i in range(51)})}):
            with self.assertRaises(HTTPException) as error:
                admin.read(self.client)
            self.assertEqual(error.exception.status_code, 413)
        for raw in ('invalid', '{"shared":{"storage-client":42}}', '{"shared":{"storage-client":["../private"]}}'):
            with patch.dict(os.environ, {'MASP_DEFERRED_BACKEND_CLIENTS_JSON': raw}), self.assertRaises(HTTPException):
                admin.read(self.client)

    def test_upgrade_is_idempotent_and_does_not_import_or_broaden_environment(self):
        with db.connect() as connection:
            connection.execute('DROP TABLE service_client_storage_policies')
        db.init_db()
        self.assertEqual(admin.read(self.client).mode, 'environment')
        self.save()
        db.init_db()
        self.assertEqual(admin.read(self.client).revision, 1)
        self.assertFalse(self.allowed())

    def deferred(self):
        identity, engines = resolve_profile_routing(resolve_stored_api_client(self.token))
        return db.create_deferred_scan_submission(service_client_id=self.client, scan_profile_id=self.profile,
            client_request_id='storage-test', backend_key='shared', object_id='incoming/a.bin', original_filename='a.bin',
            content_type='application/octet-stream', expected_size_bytes=7, expected_sha256=None,
            archive_mode='none', case_name='Test', priority='Normal', note='',
            profile_snapshot_json=profile_snapshot_json(identity, engines))[0]

    def test_worker_rechecks_revoked_access_before_copy_and_keeps_accepted_routing(self):
        from app.workers import deferred_intake_worker as worker
        record = self.deferred()
        self.save()
        with patch.object(worker, 'copy_deferred_source') as copy:
            self.assertTrue(worker.process_next())
            copy.assert_not_called()
        current = db.get_deferred_scan_submission(record.id)
        self.assertEqual(current.status, 'failed')
        self.assertEqual(current.profile_snapshot_json, record.profile_snapshot_json)

    def test_worker_copies_only_an_authorized_custom_prefix(self):
        from app.workers import deferred_intake_worker as worker
        record = self.deferred()
        path = self.root / 'private-root' / 'incoming' / 'a.bin'
        path.parent.mkdir(parents=True)
        path.write_bytes(b'content')
        self.save([{'backend_key': 'shared', 'access': 'prefixes', 'prefixes': ['incoming']}])
        with patch('app.services.deferred_storage.SAMPLES_DIR', self.root / 'samples'):
            self.assertTrue(worker.process_next())
        current = db.get_deferred_scan_submission(record.id)
        self.assertIsNotNone(current.scan_job_id)
        self.assertEqual(db.get_scan(current.scan_job_id).profile_snapshot_json, record.profile_snapshot_json)

    def test_public_deferred_admission_uses_current_custom_scope(self):
        from app.main import app, api_create_deferred_scan
        from app.services.api_schemas import DeferredScanSubmitRequest
        def submit(object_id, request_id):
            request = Request(dict(type='http', scheme='http', method='POST', path='/api/v1/deferred-scans',
                headers=[(b'host', b'testserver'), (b'authorization', f'Bearer {self.token}'.encode())],
                server=('testserver', 80), router=app.router, root_path='', query_string=b''))
            return api_create_deferred_scan(request, DeferredScanSubmitRequest(backend_key='shared', object_id=object_id,
                original_filename='a.bin', client_request_id=request_id))
        self.save([{'backend_key': 'shared', 'access': 'prefixes', 'prefixes': ['incoming']}])
        self.assertEqual(submit('incoming/a.bin', 'allowed').status_code, 202)
        for object_id in ('incoming-other/a.bin', 'other/a.bin'):
            with self.assertRaises(HTTPException) as error:
                submit(object_id, 'denied')
            self.assertEqual(error.exception.status_code, 403)
        self.save()
        with self.assertRaises(HTTPException) as error:
            submit('incoming/a.bin', 'revoked')
        self.assertEqual(error.exception.status_code, 403)
        with db.connect() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) AS n FROM deferred_scan_submissions WHERE service_client_id = ?', (self.client,)).fetchone()['n'], 1)


@unittest.skipUnless(os.getenv('MASP_TEST_POSTGRES_URL'), 'requires disposable PostgreSQL')
class ClientStoragePostgresTests(ClientStorageTests):
    postgres = True
