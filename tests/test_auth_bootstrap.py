"""Bootstrap-credential safety: no hardcoded default password, hint off.

Guards the pilot-critical guarantee that a fresh deployment never has a
well-known admin password and that the login page does not disclose credentials
unless explicitly opted in.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database
from app.services import auth


class AuthBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def _env(self, **overrides: str):
        base = {
            "MASP_ADMIN_USERNAME": "admin",
            "MASP_ANALYST_USERNAME": "analyst",
            "MASP_ADMIN_PASSWORD": "",
            "MASP_ANALYST_PASSWORD": "",
            "MASP_LDAP_ENABLED": "0",
        }
        base.update(overrides)
        return patch.dict(os.environ, base, clear=False)

    def test_no_password_env_seeds_no_users(self) -> None:
        with self._env():
            auth.seed_default_users()

        self.assertIsNone(database.get_user_by_username("admin"))
        self.assertIsNone(database.get_user_by_username("analyst"))

    def test_placeholder_password_is_not_seeded(self) -> None:
        with self._env(MASP_ADMIN_PASSWORD="CHANGE_ME_STRONG_ADMIN_PASSWORD"):
            auth.seed_default_users()
        self.assertIsNone(database.get_user_by_username("admin"))

    def test_no_hardcoded_default_password_is_accepted(self) -> None:
        # Even if an operator sets a real password, the retired default must not
        # authenticate.
        with self._env(MASP_ADMIN_PASSWORD="a-strong-secret-value"):
            auth.seed_default_users()
            self.assertIsNotNone(auth.authenticate("admin", "a-strong-secret-value"))
            self.assertIsNone(auth.authenticate("admin", "admin123!"))

if __name__ == "__main__":
    unittest.main()
