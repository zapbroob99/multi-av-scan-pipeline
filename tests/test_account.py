"""Local password/session transaction checks on SQLite and disposable PostgreSQL."""
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
from app.services import account, auth


class AccountChecks:
    def seed(self):
        user_id = db.create_user('account-user', auth.hash_password('old-password'), 'admin')
        session = auth.login('account-user', 'old-password')
        return db.get_user_by_id(user_id), session

    def test_session_index_upgrade_preserves_users_and_sessions(self):
        user, session = self.seed()
        with db.connect() as connection:
            connection.execute('DROP INDEX idx_auth_sessions_user')
        db.init_db()
        self.assertEqual(db.get_user_by_id(user.id).password_hash, user.password_hash)
        self.assertIsNotNone(db.get_user_by_session(auth.hash_session_token(session.session_token), int(time.time())))
        with db.connect() as connection:
            if db.using_postgres():
                connection.execute('SET LOCAL enable_seqscan = off')
                plan = connection.execute('EXPLAIN SELECT id FROM auth_sessions WHERE user_id = ?', (user.id,)).fetchall()
                self.assertIn('idx_auth_sessions_user', str(plan))
            else:
                indexes = connection.execute('PRAGMA index_list(auth_sessions)').fetchall()
                self.assertIn('idx_auth_sessions_user', [row['name'] for row in indexes])

    def test_password_change_preserves_concurrent_role_and_rejects_stale_credentials(self):
        user, session = self.seed()
        db.update_user(user.id, 'analyst')
        account.change_password(user, 'old-password', 'new-password', 'new-password')
        self.assertEqual(db.get_user_by_id(user.id).role, 'analyst')
        self.assertIsNone(db.get_user_by_session(auth.hash_session_token(session.session_token), int(time.time())))
        with self.assertRaises(HTTPException) as rejected:
            account.change_password(user, 'old-password', 'other-password', 'other-password')
        self.assertEqual(rejected.exception.status_code, 409)
        self.assertIsNotNone(auth.login('account-user', 'new-password'))

    def test_old_verified_login_cannot_create_session_after_own_change_or_admin_reset(self):
        user, _ = self.seed()
        for reset in ('own', 'admin'):
            with self.subTest(reset=reset):
                snapshot = db.get_user_by_id(user.id)
                if reset == 'own':
                    self.assertTrue(db.change_local_user_password(user.id, snapshot.password_hash, auth.hash_password('own-password')))
                else:
                    db.update_user(user.id, 'analyst', auth.hash_password('reset-password'))
                with patch.object(auth, 'authenticate', return_value=snapshot):
                    self.assertIsNone(auth.login('account-user', 'already-verified'))
                with db.connect() as connection:
                    self.assertEqual(connection.execute('SELECT COUNT(*) AS n FROM auth_sessions').fetchone()['n'], 0)

    def test_session_revocation_failure_rolls_back_password_and_role(self):
        user, session = self.seed()
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

        for change in (lambda: db.change_local_user_password(user.id, user.password_hash, 'replacement'),
                       lambda: db.update_user(user.id, 'analyst', 'replacement')):
            with patch.object(db, 'connect', failing_connect), self.assertRaises(RuntimeError):
                change()
            saved = db.get_user_by_id(user.id)
            self.assertEqual(saved.password_hash, user.password_hash)
            self.assertEqual(saved.role, 'admin')
            self.assertIsNotNone(db.get_user_by_session(auth.hash_session_token(session.session_token), int(time.time())))

    def test_concurrent_password_changes_have_one_winner(self):
        user, _ = self.seed()
        barrier = threading.Barrier(2)
        def change(password):
            barrier.wait(timeout=10)
            try:
                account.change_password(user, 'old-password', password, password)
                return password
            except HTTPException as exc:
                return exc.status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(change, ['first-password', 'second-password']))
        self.assertEqual(results.count(409), 1)
        self.assertIsNotNone(auth.login('account-user', next(value for value in results if isinstance(value, str))))

    def test_login_row_lock_serializes_session_insertion_with_password_revocation(self):
        user, _ = self.seed()
        selected, updating, release = threading.Event(), threading.Event(), threading.Event()
        real_connect = db.connect
        class CoordinatedConnection:
            def __init__(self, connection): self.connection = connection
            def execute(self, sql, params=()):
                if sql.startswith('UPDATE users'):
                    updating.set()
                cursor = self.connection.execute(sql, params)
                if sql.startswith('SELECT password_hash, auth_source'):
                    selected.set()
                    if not release.wait(timeout=10):
                        raise RuntimeError('lock test timed out')
                return cursor
        @contextmanager
        def coordinated_connect():
            with real_connect() as connection:
                yield CoordinatedConnection(connection)
        with patch.object(db, 'connect', coordinated_connect), ThreadPoolExecutor(max_workers=2) as executor:
            login = executor.submit(db.create_auth_session, user.id, 'race-session', int(time.time()) + 3600,
                                    expected_password_hash=user.password_hash)
            try:
                self.assertTrue(selected.wait(timeout=10))
                changed = executor.submit(db.change_local_user_password, user.id, user.password_hash, auth.hash_password('new-password'))
                self.assertTrue(updating.wait(timeout=10))
                self.assertFalse(changed.done())
            finally:
                release.set()
            self.assertIsNotNone(login.result(timeout=10))
            self.assertTrue(changed.result(timeout=10))
        self.assertIsNone(db.get_user_by_session('race-session', int(time.time())))


class AccountSqliteTests(AccountChecks, unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original = db.DB_PATH, db.DATABASE_URL
        db.DB_PATH, db.DATABASE_URL = Path(self.temp.name) / 'account.db', ''
        db.init_db()

    def tearDown(self):
        db.DB_PATH, db.DATABASE_URL = self.original
        self.temp.cleanup()

    def test_legacy_password_route_uses_shared_fenced_writer(self):
        from app import main
        user, session = self.seed()
        db.update_user(user.id, 'analyst')
        with patch.object(main, 'require_user', return_value=user):
            response = main.update_account_password_route(object(), 'old-password', 'new-password', 'new-password')
            self.assertEqual(response.status_code, 303)
            self.assertTrue(response.headers['location'].startswith('/login?'))
            self.assertIn('Max-Age=0', response.headers['set-cookie'])
            rejected = main.update_account_password_route(object(), 'old-password', 'another-password', 'another-password')
            self.assertTrue(rejected.headers['location'].startswith('/account?error='))
        self.assertEqual(db.get_user_by_id(user.id).role, 'analyst')
        self.assertIsNone(db.get_user_by_session(auth.hash_session_token(session.session_token), int(time.time())))


@unittest.skipUnless(os.getenv('MASP_TEST_POSTGRES_URL'), 'requires disposable PostgreSQL')
class AccountPostgresTests(AccountChecks, unittest.TestCase):
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

    def test_password_lock_budget_rejects_without_changing_hash_or_sessions(self):
        user, session = self.seed()
        with db.connect() as locked:
            locked.execute('SELECT id FROM users WHERE id = ? FOR UPDATE', (user.id,))
            with ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(db.change_local_user_password, user.id, user.password_hash,
                                          'replacement', lock_timeout_ms=100)
                with self.assertRaises(db.psycopg.errors.LockNotAvailable):
                    pending.result(timeout=10)
        self.assertEqual(db.get_user_by_id(user.id).password_hash, user.password_hash)
        self.assertIsNotNone(db.get_user_by_session(auth.hash_session_token(session.session_token), int(time.time())))
