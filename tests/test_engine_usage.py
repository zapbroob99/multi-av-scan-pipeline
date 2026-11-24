import unittest

from fastapi import HTTPException

from app import database as db
from app.services import engine_usage
from tests import test_client_configuration as fixtures


class EngineUsageTests(unittest.TestCase):
    setUp = fixtures.ClientConfigurationTests.setUp
    tearDown = fixtures.ClientConfigurationTests.tearDown

    def test_pages_current_references_and_includes_disabled_but_not_deleted_profiles(self):
        created = [db.create_scan_profile(self.client, f'Profile {i}', engine_instance_ids=[self.engine]) for i in range(24)]
        with db.connect() as connection:
            connection.execute('UPDATE service_clients SET enabled = ? WHERE id = ?', (db.db_bool(False), self.other))
            connection.execute('UPDATE scan_profiles SET enabled = ? WHERE id = ?', (db.db_bool(False), created[1]))
            connection.execute('UPDATE scan_profiles SET deleted_at = 1 WHERE id = ?', (created[2],))
        first = engine_usage.read(self.engine)
        self.assertEqual(len(first.profiles), 20)
        self.assertEqual(first.next_after, first.profiles[-1].profile_id)
        second = engine_usage.read(self.engine, first.next_after)
        all_rows = first.profiles + second.profiles
        ids = [row.profile_id for row in all_rows]
        self.assertEqual(ids, sorted({self.profile, self.other_profile, *created} - {created[2]}))
        self.assertIsNone(second.next_after)
        self.assertFalse(next(row for row in all_rows if row.profile_id == self.other_profile).client_enabled)
        self.assertFalse(next(row for row in all_rows if row.profile_id == created[1]).profile_enabled)
        self.assertNotIn('synthetic', first.model_dump_json())
        self.assertNotIn('policy_json', first.model_dump_json())

    def test_instance_scope_and_explicit_missing_instance(self):
        other_engine = db.create_engine_instance('clamav', 'Other scanner')
        self.assertEqual(engine_usage.read(other_engine).profiles, [])
        with self.assertRaises(HTTPException) as caught:
            engine_usage.read(999999)
        self.assertEqual(caught.exception.status_code, 404)

    def test_seek_index_survives_reinitialization(self):
        db.init_db()
        with db.connect() as connection:
            plan = connection.execute('EXPLAIN QUERY PLAN SELECT scan_profile_id FROM scan_profile_engines WHERE engine_instance_id = ? AND scan_profile_id > ? ORDER BY scan_profile_id LIMIT 21', (self.engine, 0)).fetchall()
        self.assertTrue(any('idx_profile_engines_instance_seek' in str(dict(row)) for row in plan))
        self.assertEqual(len(engine_usage.read(self.engine).profiles), 2)
