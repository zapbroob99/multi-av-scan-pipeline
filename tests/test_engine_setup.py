import tempfile
import unittest
from pathlib import Path

from app import database
from app.services.engine_setup import engine_setup_from_form


class EngineInitialSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "engine-setup.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_clamav_setup_requires_explicit_runtime_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "timeout seconds is required"):
            engine_setup_from_form(
                "clamav",
                {
                    "engine_display_name": "ClamAV Istanbul",
                    "clamav_mode": "clamd",
                    "clamav_host": "clamav.internal",
                    "clamav_port": "3310",
                },
            )

    def test_clamav_setup_returns_only_submitted_configuration(self) -> None:
        display_name, config = engine_setup_from_form(
            "clamav",
            {
                "engine_display_name": "ClamAV Istanbul",
                "clamav_mode": "clamd",
                "clamav_host": "clamav.internal",
                "clamav_port": "3311",
                "clamav_timeout_seconds": "75",
                "clamav_max_file_size_bytes": "104857600",
            },
        )

        self.assertEqual(display_name, "ClamAV Istanbul")
        self.assertEqual(
            config,
            {
                "mode": "clamd",
                "host": "clamav.internal",
                "port": "3311",
                "timeout_seconds": "75",
                "max_file_size_bytes": "104857600",
            },
        )

if __name__ == "__main__":
    unittest.main()
