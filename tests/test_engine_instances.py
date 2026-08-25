import tempfile
import unittest
from pathlib import Path

from app import database
from app.services.engine_registry import (
    add_engine,
    engine_config,
    remove_engine,
    toggle_engine,
    update_engine_config,
)


class MultiEngineInstanceTests(unittest.TestCase):
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

    def test_multi_instance_adapter_gets_unique_names_and_configuration(self) -> None:
        first_id = add_engine("clamav")
        second_id = add_engine("clamav")

        first = database.get_engine_instance_by_id(first_id)
        second = database.get_engine_instance_by_id(second_id)
        assert first is not None and second is not None
        self.assertEqual(first.display_name, "ClamAV")
        self.assertEqual(second.display_name, "ClamAV 2")

        update_engine_config("clamav", {"host": "dr.example"}, second_id)
        first = database.get_engine_instance_by_id(first_id)
        second = database.get_engine_instance_by_id(second_id)
        assert first is not None and second is not None
        self.assertEqual(engine_config(first), {})
        self.assertEqual(engine_config(second), {"host": "dr.example"})

        toggle_engine("clamav", second_id)
        second = database.get_engine_instance_by_id(second_id)
        assert second is not None
        self.assertFalse(second.enabled)

        remove_engine("clamav", second_id)
        self.assertIsNone(database.get_engine_instance_by_id(second_id))
        self.assertIsNotNone(database.get_engine_instance_by_id(first_id))

    def test_single_instance_adapter_remains_idempotent(self) -> None:
        first_id = add_engine("static_metadata")
        second_id = add_engine("static_metadata")

        self.assertEqual(first_id, second_id)
        self.assertEqual(
            len(database.list_engine_instances_for_adapter("static_metadata")),
            1,
        )


if __name__ == "__main__":
    unittest.main()
