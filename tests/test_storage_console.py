import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from fastapi import FastAPI

from app import database as db
from app.services import auth, health_read, ui_api
from app.services import storage_inventory as inventory
from app.services.storage_protection import LAST_CYCLE_SETTING, run_location_cycle
from tests import test_ui_api

PE = b"MZ" + b"\x00" * 200


class StorageConsoleTests(unittest.TestCase):
    request = test_ui_api.BrowserApiTests.request
    postgres = False

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.original = (db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED)
        db.close_pool()
        url = os.environ['MASP_TEST_POSTGRES_URL'] if self.postgres else ''
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = Path(self.temp.name) / 'storage-console.db', url, False
        self.addCleanup(self._restore)
        if self.postgres:
            import psycopg
            with psycopg.connect(url, autocommit=True) as connection:
                connection.execute('DROP SCHEMA IF EXISTS public CASCADE')
                connection.execute('CREATE SCHEMA public')
        db.init_db()
        self.user_id = db.create_user('browser-admin', auth.hash_password('test-password'), 'admin')
        self.token = 'synthetic-browser-session'
        db.create_auth_session(user_id=self.user_id, token_hash=auth.hash_session_token(self.token),
                               expires_at=int(time.time()) + 3600)
        self.app = FastAPI()
        self.app.include_router(ui_api.router)
        self.share = Path(self.temp.name) / 'share'
        (self.share / 'data').mkdir(parents=True)
        self.client_id = db.create_service_client('storage', 'Storage')
        engine = db.create_engine_instance('static_metadata', 'Metadata')
        self.profile_id = db.create_scan_profile(self.client_id, 'Default', engine_instance_ids=[engine],
                                                 is_default=True)
        env = patch.dict(os.environ, {
            'MASP_DEFERRED_STORAGE_BACKENDS_JSON': json.dumps({'share': str(self.share)}),
            'MASP_DEFERRED_BACKEND_CLIENTS_JSON': json.dumps({'share': {'storage': 'data/'}}),
        }, clear=False)
        env.start()
        self.addCleanup(env.stop)

    def _restore(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def body(self, **changes):
        base = {'name': 'Uploads', 'service_client_id': self.client_id, 'scan_profile_id': self.profile_id,
                'backend_key': 'share', 'prefix': 'data', 'mode': 'crawl', 'enabled': True,
                'policy': {'default_tier': 'light', 'stability_seconds': 5}}
        base.update(changes)
        return base

    def as_analyst(self):
        with db.connect() as connection:
            connection.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (self.user_id,))

    def test_create_requires_admin_csrf_and_a_covering_grant(self):
        self.assertEqual(self.request('/storage/locations', 'POST', self.body(), csrf=False)[0], 403)
        self.assertEqual(self.request('/storage/locations', 'POST', self.body(), session=False)[0], 401)
        status, error, _ = self.request('/storage/locations', 'POST', self.body(prefix='other'))
        self.assertEqual(status, 422)
        self.assertIn('grant', error['detail'])
        status, error, _ = self.request('/storage/locations', 'POST', self.body(prefix=''))
        self.assertEqual(status, 422)
        self.assertEqual(self.request('/storage/locations', 'POST', self.body(backend_key='missing'))[0], 422)
        self.assertEqual(self.request('/storage/locations', 'POST', self.body(mode='both'))[0], 422)
        self.assertEqual(self.request('/storage/locations', 'POST', self.body(prefix='../data'))[0], 422)
        bad_policy = self.body(policy={'type_policy': {'mode': 'denylist', 'families': ['binaries']}})
        self.assertEqual(self.request('/storage/locations', 'POST', bad_policy)[0], 422)
        status, created, _ = self.request('/storage/locations', 'POST', self.body())
        self.assertEqual(status, 201, created)
        self.assertEqual(inventory.get_location(created['id']).prefix, 'data')

    def test_names_are_unique_and_trees_do_not_overlap(self):
        self.assertEqual(self.request('/storage/locations', 'POST', self.body())[0], 201)
        self.assertEqual(self.request('/storage/locations', 'POST', self.body(prefix='data/sub'))[0], 409)
        self.assertEqual(self.request('/storage/locations', 'POST', self.body(name='Other', prefix='data/sub'))[0], 409)

    def test_foreign_or_disabled_profile_is_refused(self):
        other = db.create_service_client('other', 'Other')
        engine = db.create_engine_instance('static_metadata', 'Metadata 2')
        foreign = db.create_scan_profile(other, 'Default', engine_instance_ids=[engine], is_default=True)
        self.assertEqual(self.request('/storage/locations', 'POST', self.body(scan_profile_id=foreign))[0], 422)

    def test_update_is_fenced_and_counts_policy_revisions(self):
        created = self.request('/storage/locations', 'POST', self.body())[1]
        path = f"/storage/locations/{created['id']}"
        detail = self.request(path)[1]
        self.assertEqual((detail['management_revision'], detail['policy_revision']), (0, 1))
        update = {'expected_management_revision': 0, 'name': 'Uploads', 'scan_profile_id': self.profile_id,
                  'enabled': False, 'policy': detail['policy']}
        self.assertEqual(self.request(path, 'PUT', update)[0], 204)
        detail = self.request(path)[1]
        self.assertEqual((detail['enabled'], detail['management_revision'], detail['policy_revision']), (False, 1, 1))
        self.assertEqual(self.request(path, 'PUT', update)[0], 409)
        changed = {**update, 'expected_management_revision': 1,
                   'policy': {**detail['policy'], 'archive_action': 'detect'}}
        self.assertEqual(self.request(path, 'PUT', changed)[0], 204)
        self.assertEqual(self.request(path)[1]['policy_revision'], 2)
        self.assertEqual(self.request(path, 'PUT', {**changed, 'backend_key': 'share'})[0], 422)

    def test_analyst_reads_results_but_cannot_manage(self):
        created = self.request('/storage/locations', 'POST', self.body())[1]
        (self.share / 'data' / 'tool.exe').write_bytes(PE)
        location = inventory.get_location(created['id'])
        inventory.claim_location(location.id, 'worker-a', 300, int(time.time()))
        now = int(time.time())
        run_location_cycle(location, 'worker-a', now)
        run_location_cycle(location, 'worker-a', now + 10)
        self.as_analyst()
        overview = self.request('/storage/overview')[1]
        summary = overview['locations'][0]
        self.assertEqual(summary['counts']['light_detected'], 1)
        self.assertEqual(summary['detected_findings'], 1)
        self.assertTrue(summary['last_cycle']['ok'])
        objects = self.request(f"/storage/locations/{location.id}/objects?state=light_detected")[1]
        self.assertEqual([item['object_id'] for item in objects['items']], ['data/tool.exe'])
        self.assertEqual(self.request(f"/storage/locations/{location.id}/objects?q=nothing")[1]['items'], [])
        findings = self.request('/storage/findings?detected=detected')[1]
        self.assertEqual(findings['items'][0]['kind'], 'type_policy')
        self.assertEqual(findings['items'][0]['object_state'], 'light_detected')
        self.assertEqual(self.request('/storage/options')[0], 403)
        self.assertEqual(self.request('/storage/locations', 'POST', self.body(name='Again'))[0], 403)

    def test_paging_is_keyset_bounded(self):
        created = self.request('/storage/locations', 'POST', self.body())[1]
        for index in range(3):
            (self.share / 'data' / f'file-{index}.txt').write_bytes(b'plain text')
        location = inventory.get_location(created['id'])
        inventory.claim_location(location.id, 'worker-a', 300, int(time.time()))
        run_location_cycle(location, 'worker-a')
        first = self.request(f'/storage/locations/{location.id}/objects?limit=2')[1]
        self.assertEqual(len(first['items']), 2)
        second = self.request(f"/storage/locations/{location.id}/objects?limit=2&before={first['next_before']}")[1]
        self.assertEqual(len(second['items']), 1)
        self.assertIsNone(second['next_before'])
        self.assertEqual(self.request('/storage/locations/999/objects')[0], 404)

    def test_options_list_backends_clients_and_profiles(self):
        options = self.request('/storage/options')[1]
        self.assertEqual(options['backends'], ['share'])
        client = next(item for item in options['clients'] if item['id'] == self.client_id)
        self.assertEqual([profile['id'] for profile in client['profiles']], [self.profile_id])
        self.assertIn('executable', options['families'])

    def test_health_reports_folder_scanning(self):
        with db.connect() as connection:
            check = health_read.storage_protection_check(connection, time.time())
        self.assertEqual(check.state, 'inactive')
        self.request('/storage/locations', 'POST', self.body())
        with db.connect() as connection:
            check = health_read.storage_protection_check(connection, time.time())
        self.assertEqual(check.state, 'unknown')
        db.set_setting(LAST_CYCLE_SETTING, json.dumps({'at': int(time.time()) - 3600, 'ok': True,
                                                       'poll_seconds': 10}))
        with db.connect() as connection:
            self.assertEqual(health_read.storage_protection_check(connection, time.time()).state, 'critical')
        db.set_setting(LAST_CYCLE_SETTING, json.dumps({'at': int(time.time()), 'ok': True, 'poll_seconds': 10}))
        with db.connect() as connection:
            check = health_read.storage_protection_check(connection, time.time())
        self.assertEqual(check.state, 'warning')
        self.assertIn('never ran', check.detail)


@unittest.skipUnless(os.getenv('MASP_TEST_POSTGRES_URL'), 'requires disposable PostgreSQL')
class StorageConsolePostgresTests(StorageConsoleTests):
    postgres = True


if __name__ == '__main__':
    unittest.main()
