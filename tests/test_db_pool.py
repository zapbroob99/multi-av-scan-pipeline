import unittest
from unittest import mock

from app import database


class FakePoolCM:
    """Mimics psycopg_pool's ``pool.connection()`` context manager."""

    def __init__(self, pool: "FakePool", raise_on_enter: BaseException | None = None):
        self.pool = pool
        self.raise_on_enter = raise_on_enter

    def __enter__(self):
        self.pool.acquired += 1
        if self.raise_on_enter is not None:
            raise self.raise_on_enter
        return self.pool.conn

    def __exit__(self, exc_type, exc, tb):
        self.pool.released += 1
        self.pool.last_exit = (exc_type, exc, tb)
        return False


class FakePool:
    def __init__(self, enter_failures: int = 0, failure: BaseException | None = None):
        self.conn = object()
        self.acquired = 0
        self.released = 0
        self.closed = False
        self.last_exit = None
        self._enter_failures = enter_failures
        self._failure = failure

    def connection(self):
        if self._enter_failures > 0:
            self._enter_failures -= 1
            return FakePoolCM(self, raise_on_enter=self._failure)
        return FakePoolCM(self)

    def close(self):
        self.closed = True


@unittest.skipIf(database.ConnectionPool is None, "psycopg_pool not installed")
class DatabasePoolTests(unittest.TestCase):
    def tearDown(self):
        database.close_pool()

    def test_pool_available_requires_enabled_and_postgres(self):
        with mock.patch.object(database, "DATABASE_URL", "postgresql://x"):
            with mock.patch.object(database, "DB_POOL_ENABLED", True):
                self.assertTrue(database.pool_available())
            with mock.patch.object(database, "DB_POOL_ENABLED", False):
                self.assertFalse(database.pool_available())
        with mock.patch.object(database, "DATABASE_URL", ""):
            with mock.patch.object(database, "DB_POOL_ENABLED", True):
                self.assertFalse(database.pool_available())

    def test_pool_timeout_caught_by_operational_error(self):
        # PoolTimeout must be catchable via DatabaseOperationalError so retry
        # and swallow paths keep working.
        self.assertTrue(
            issubclass(database.PoolTimeout, database.DatabaseOperationalError)
        )

    def test_pooled_connect_acquires_and_releases(self):
        pool = FakePool()
        with mock.patch.object(database, "get_pool", return_value=pool):
            wrapper = database.connect_postgres_pooled()
            self.assertEqual(pool.acquired, 1)
            with wrapper as conn:
                self.assertIs(conn.connection, pool.conn)
            self.assertEqual(pool.released, 1)
            self.assertIsNone(pool.last_exit[0])  # committed, no exception

    def test_pooled_connect_reuses_same_pool_across_calls(self):
        pool = FakePool()
        with mock.patch.object(database, "get_pool", return_value=pool):
            with database.connect_postgres_pooled():
                pass
            with database.connect_postgres_pooled():
                pass
        self.assertEqual(pool.acquired, 2)
        self.assertEqual(pool.released, 2)

    def test_pooled_connect_rolls_back_on_exception(self):
        pool = FakePool()
        with mock.patch.object(database, "get_pool", return_value=pool):
            wrapper = database.connect_postgres_pooled()
            with self.assertRaises(ValueError):
                with wrapper:
                    raise ValueError("boom")
        self.assertEqual(pool.released, 1)
        self.assertIs(pool.last_exit[0], ValueError)

    def test_pooled_connect_retries_until_ready(self):
        # First two acquisitions fail as if Postgres is still starting.
        pool = FakePool(
            enter_failures=2,
            failure=database.psycopg.OperationalError("starting up"),
        )
        with mock.patch.object(database, "get_pool", return_value=pool), mock.patch.object(
            database, "DATABASE_CONNECT_ATTEMPTS", 5
        ), mock.patch.object(database, "DATABASE_RETRY_DELAY_SECONDS", 0):
            wrapper = database.connect_postgres_pooled()
            with wrapper as conn:
                self.assertIs(conn.connection, pool.conn)
        self.assertEqual(pool.acquired, 3)  # 2 failed + 1 success

    def test_pooled_connect_raises_after_exhausting_retries(self):
        pool = FakePool(
            enter_failures=99,
            failure=database.psycopg.OperationalError("never ready"),
        )
        with mock.patch.object(database, "get_pool", return_value=pool), mock.patch.object(
            database, "DATABASE_CONNECT_ATTEMPTS", 3
        ), mock.patch.object(database, "DATABASE_RETRY_DELAY_SECONDS", 0):
            with self.assertRaises(database.psycopg.OperationalError):
                database.connect_postgres_pooled()
        self.assertEqual(pool.acquired, 3)

    def test_get_pool_is_lazy_and_per_pid(self):
        created = []

        class FakeConnectionPool:
            def __init__(self, *args, **kwargs):
                created.append(kwargs.get("name"))

            def close(self):
                pass

        with mock.patch.object(database, "ConnectionPool", FakeConnectionPool), mock.patch.object(
            database, "DATABASE_URL", "postgresql://x"
        ):
            database.close_pool()
            first = database.get_pool()
            self.assertIs(database.get_pool(), first)  # same PID reuses
            self.assertEqual(len(created), 1)
            database._pool_pid = -1  # simulate fork into new PID
            second = database.get_pool()
            self.assertIsNot(first, second)
            self.assertEqual(len(created), 2)


if __name__ == "__main__":
    unittest.main()
