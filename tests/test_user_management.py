from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from app import database as db
from app.services import auth, user_admin


class UserManagementChecks:
    def seed(self):
        actor = db.create_user('operator', auth.hash_password('actor-password'), 'admin', auth_source='ldap')
        target = db.create_user('target', auth.hash_password('target-password'), 'admin')
        return actor, target

    def revision(self, user_id):
        with db.connect() as connection:
            return connection.execute('SELECT management_revision FROM users WHERE id = ?', (user_id,)).fetchone()['management_revision']

    def test_last_local_admin_self_directory_and_actor_guards(self):
        actor, target = self.seed()
        for kwargs in ({'delete': True}, {'role': 'analyst'}):
            with self.assertRaises(HTTPException) as denied:
                user_admin.manage(actor, target, **kwargs)
            self.assertEqual(denied.exception.status_code, 409)
        for a, t, kwargs in ((actor, actor, {'delete': True}),
                              (target, actor, {'role': 'analyst'})):
            with self.assertRaises(HTTPException) as denied:
                user_admin.manage(a, t, **kwargs)
            self.assertEqual(denied.exception.status_code, 403)
        db.update_user(actor, 'analyst')
        with self.assertRaises(HTTPException) as denied:
            user_admin.manage(actor, target, role='admin')
        self.assertEqual(denied.exception.status_code, 403)

    def test_edit_reset_stale_revision_and_delete_session_cascade(self):
        actor, target = self.seed()
        db.create_user('other-admin', 'unused', 'admin')
        login = auth.login('target', 'target-password')
        user_admin.manage(actor, target, expected_revision=0, role='analyst')
        self.assertEqual(self.revision(target), 1)
        self.assertEqual(db.get_user_by_session(auth.hash_session_token(login.session_token), int(time.time())).role, 'analyst')
        for kwargs in ({'delete': True}, {'role': 'admin', 'password': 'reset-password'}):
            with self.assertRaises(HTTPException) as rejected:
                user_admin.manage(actor, target, expected_revision=0, **kwargs)
            self.assertEqual(rejected.exception.status_code, 409)
        user_admin.manage(actor, target, expected_revision=1, role='analyst', password='reset-password')
        self.assertIsNone(db.get_user_by_session(auth.hash_session_token(login.session_token), int(time.time())))
        self.assertIsNone(auth.login('target', 'target-password'))
        fresh = auth.login('target', 'reset-password')
        self.assertIsNotNone(fresh)
        user_admin.manage(actor, target, expected_revision=2, delete=True)
        self.assertIsNone(db.get_user_by_id(target))
        self.assertIsNone(db.get_user_by_session(auth.hash_session_token(fresh.session_token), int(time.time())))

    def test_own_password_change_invalidates_displayed_admin_revision(self):
        actor, target = self.seed()
        record = db.get_user_by_id(target)
        db.change_local_user_password(target, record.password_hash, auth.hash_password('own-new-password'))
        with self.assertRaises(HTTPException) as denied:
            user_admin.manage(actor, target, expected_revision=0, role='admin', password='stale-admin-password')
        self.assertEqual(denied.exception.status_code, 409)
        self.assertIsNotNone(auth.login('target', 'own-new-password'))

    def test_reset_revocation_failure_rolls_back_role_password_and_revision(self):
        actor, target = self.seed()
        db.create_user('remaining', 'unused', 'admin')
        old = db.get_user_by_id(target)
        session = auth.login('target', 'target-password')
        real_connect = db.connect
        class FailRevocation:
            def __init__(self, connection): self.connection = connection
            def execute(self, sql, params=()):
                if sql.startswith('DELETE FROM auth_sessions'):
                    raise RuntimeError('injected revocation failure')
                return self.connection.execute(sql, params)
        @contextmanager
        def failing_connect():
            with real_connect() as connection:
                yield FailRevocation(connection)
        with patch.object(db, 'connect', failing_connect), self.assertRaises(RuntimeError):
            user_admin.manage(actor, target, expected_revision=0, role='analyst', password='replacement-password')
        self.assertEqual(db.get_user_by_id(target).password_hash, old.password_hash)
        self.assertEqual(db.get_user_by_id(target).role, 'admin')
        self.assertEqual(self.revision(target), 0)
        self.assertIsNotNone(db.get_user_by_session(auth.hash_session_token(session.session_token), int(time.time())))

    def test_cross_demotion_rechecks_actor_after_serializing(self):
        first = db.create_user('first', 'unused', 'admin')
        second = db.create_user('second', 'unused', 'admin')
        barrier = threading.Barrier(2)
        def demote(ids):
            barrier.wait(timeout=10)
            try:
                user_admin.manage(ids[0], ids[1], expected_revision=0, role='analyst')
                return 'updated'
            except HTTPException as exc:
                return exc.status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(demote, [(first, second), (second, first)]))
        self.assertEqual(sorted(map(str, results)), ['403', 'updated'])
        self.assertEqual(db.count_users_by_role('admin', 'local'), 1)

    def test_concurrent_last_admin_removal_has_one_winner(self):
        actor, first = self.seed()
        second = db.create_user('second', 'unused', 'admin')
        barrier = threading.Barrier(2)
        def remove(user_id):
            barrier.wait(timeout=10)
            try:
                user_admin.manage(actor, user_id, expected_revision=0, delete=True)
                return 'deleted'
            except HTTPException as exc:
                return exc.status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(remove, [first, second]))
        self.assertEqual(sorted(map(str, results)), ['409', 'deleted'])
        self.assertEqual(db.count_users_by_role('admin', 'local'), 1)

    def test_directory_shadow_removal_and_revision_upgrade_preserve_local_account(self):
        actor, target = self.seed()
        db.create_auth_session(actor, 'directory-session', int(time.time()) + 3600)
        with db.connect() as connection:
            connection.execute('ALTER TABLE users DROP COLUMN management_revision')
        db.init_db()
        self.assertEqual(self.revision(target), 0)
        user_admin.manage(target, actor, expected_revision=0, delete=True)
        self.assertIsNone(db.get_user_by_session('directory-session', int(time.time())))
        self.assertIsNotNone(auth.login('target', 'target-password'))


class UserManagementSqliteTests(UserManagementChecks, unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original = db.DB_PATH, db.DATABASE_URL
        db.DB_PATH, db.DATABASE_URL = Path(self.temp.name) / 'users.db', ''
        db.init_db()

    def tearDown(self):
        db.DB_PATH, db.DATABASE_URL = self.original
        self.temp.cleanup()

    def test_legacy_routes_share_transactional_guards(self):
        from app import main
        actor, target = self.seed()
        with patch.object(main, 'require_admin', return_value=db.get_user_by_id(actor)):
            self.assertIn('/users?error=', main.delete_user_route(object(), target).headers['location'])
            self.assertIn('/users?error=', main.update_user_route(object(), target, 'analyst', '').headers['location'])
            db.create_user('remaining', 'unused', 'admin')
            self.assertIn('/users?message=', main.update_user_route(object(), target, 'analyst', 'new-password').headers['location'])
            self.assertEqual(self.revision(target), 1)
            self.assertIn('/users?message=', main.delete_user_route(object(), target).headers['location'])


@unittest.skipUnless(os.getenv('MASP_TEST_POSTGRES_URL'), 'requires disposable PostgreSQL')
class UserManagementPostgresTests(UserManagementChecks, unittest.TestCase):
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

    def test_admin_mutex_respects_lock_budget(self):
        actor, target = self.seed()
        with db.connect() as locked:
            locked.execute('SELECT pg_advisory_xact_lock(?)', (user_admin.USER_ADMIN_LOCK,))
            with patch.dict(os.environ, {'MASP_UI_WRITE_LOCK_TIMEOUT_MS': '100'}), ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(user_admin.manage, actor, target, expected_revision=0, role='admin')
                with self.assertRaises(db.psycopg.errors.LockNotAvailable):
                    pending.result(timeout=10)
        self.assertEqual(self.revision(target), 0)
