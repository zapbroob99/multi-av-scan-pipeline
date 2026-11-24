import os
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from fastapi import HTTPException
from app import database as db
from app.services import client_configuration as config, profile_admin


class ClientConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original = db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = Path(self.temp.name) / 'test.db', '', False
        db.init_db()
        self.engine = db.create_engine_instance('clamav', 'Local scanner')
        self.client, self.profile, _ = db.create_service_client_bundle(client_key='configuration-test', display_name='Configuration test',
            profile_name='Default', engine_instance_ids=[self.engine], credential_label='Test', token_hash='synthetic-hash', token_prefix='synthetic')
        self.other, self.other_profile, _ = db.create_service_client_bundle(client_key='configuration-other', display_name='Other',
            profile_name='Other', engine_instance_ids=[self.engine], credential_label='Other', token_hash='other-synthetic-hash', token_prefix='other')

    def tearDown(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original
        self.temp.cleanup()

    def test_default_and_selected_profile_are_client_scoped(self):
        named = profile_admin.create(self.client, profile_admin.ProfileCreateBody(name='Named', engine_ids=[self.engine], inconclusive='block')).profile_id
        result = config.read(self.client, named)
        self.assertEqual(result.profile.id, named)
        self.assertEqual(config.read(self.client).profile.id, self.profile)
        with self.assertRaises(HTTPException) as caught:
            config.read(self.client, self.other_profile)
        self.assertEqual(caught.exception.status_code, 404)
        self.assertNotIn('synthetic-hash', result.model_dump_json())
        self.assertNotIn('config', result.model_dump()['engines'][0])

    def test_invalid_http_environment_is_not_presented_as_working_default(self):
        for value in ('nonsense', '0', '-1'):
            with patch.dict(os.environ, {'MASP_HTTP_UPLOAD_MAX_BYTES': value}):
                result = config.read(self.client)
                self.assertFalse(result.http_configuration_valid)
                self.assertIsNone(result.http_body_ceiling_bytes)

    def test_missing_or_oversized_rules_never_produce_partial_policy(self):
        with db.connect() as c:
            c.execute('UPDATE scan_profiles SET policy_json = ? WHERE id = ?', ('x' * 65537, self.profile))
        result = config.read(self.client)
        self.assertIsNone(result.profile.rules)
        self.assertTrue(result.profile.rules_invalid)

    def test_disabled_pool_and_stale_worker_check_remain_separate_evidence(self):
        now = int(time.time())
        with db.connect() as c:
            c.execute("INSERT INTO worker_pools (id, name, selector_json, enabled) VALUES (99, 'Disabled pool', '{}', ?)", (db.db_bool(False),))
            c.execute('INSERT INTO engine_instance_worker_pools (engine_instance_id, worker_pool_id) VALUES (?, 99)', (self.engine,))
            c.execute('''INSERT INTO worker_nodes (node_id, display_name, hostname, platform, agent_version, last_heartbeat_at, lifecycle_state)
                VALUES ('node', 'Test', 'private-host', 'linux', 'test', ?, 'draining')''', (now,))
            c.execute('''INSERT INTO engine_node_health (node_id, engine_instance_id, ok, last_checked_at, detail)
                VALUES ('node', ?, ?, ?, '/private/path secret details')''', (self.engine, db.db_bool(True), now - 10000))
        result = config.read(self.client)
        engine = result.engines[0]
        self.assertFalse(engine.pool_enabled)
        self.assertEqual(engine.observations[0].check, 'stale')
        self.assertEqual(engine.observations[0].lifecycle, 'draining')
        self.assertTrue(engine.observations[0].online)
        self.assertNotIn('private', result.model_dump_json())

    def test_gateway_limits_are_client_scoped_and_stale_reports_remain_labelled(self):
        now = int(time.time())
        for key, port, age in [('configuration-test', 1344, 600), ('configuration-other', 1345, 0)]:
            db.set_setting(config.SETTING_PREFIX + key, json.dumps(dict(client_key=key, port=port, at=now - age,
                max_bytes=52428800, wait_seconds=30, fail_closed=True)))
        result = config.read(self.client)
        self.assertEqual(len(result.gateways), 1)
        self.assertTrue(result.gateways[0].stale)
        self.assertEqual(result.gateways[0].port, 1344)

    def test_an_excess_of_worker_evidence_is_explicit(self):
        with db.connect() as c:
            for i in range(202):
                c.execute('''INSERT INTO worker_nodes (node_id, display_name, hostname, platform, agent_version, last_heartbeat_at)
                    VALUES (?, 'Test', 'host', 'linux', 'test', 0)''', (f'node-{i:03}',))
                c.execute('INSERT INTO engine_node_health (node_id, engine_instance_id) VALUES (?, ?)', (f'node-{i:03}', self.engine))
        result = config.read(self.client)
        self.assertEqual(len(result.engines[0].observations), 20)
        self.assertTrue(result.engines[0].observations_incomplete)


if __name__ == '__main__':
    unittest.main()
