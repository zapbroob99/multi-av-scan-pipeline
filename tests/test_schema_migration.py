"""Schema migration safety for the archive-finalization columns/index.

The partial unique index on (parent_scan_id, archive_member_ordinal) must be
creatable on a database that already holds duplicate-path child scans from before
the column existed (those rows carry NULL, which the partial index excludes).
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import database
from app.models import StoredSample


class SchemaMigrationTests(unittest.TestCase):
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

    def _sample(self) -> int:
        return database.create_sample(
            StoredSample("a.bin", "a.bin", "/tmp/a.bin", "application/octet-stream", 1, "0" * 32, "0" * 40, "1" * 64)
        )

    def _child(self, parent_id: int, sample_id: int, relative_path: str) -> int:
        return database.create_scan_job(
            sample_id,
            case_name="C",
            priority="Normal",
            note="",
            parent_scan_id=parent_id,
            relative_path=relative_path,
            scan_role="child",
        )

    def test_new_columns_exist(self) -> None:
        with database.connect() as connection:
            columns = {
                str(database.row_value(row, "name"))
                for row in connection.execute("PRAGMA table_info(scan_jobs)").fetchall()
            }
        for column in (
            "finalize_worker_id",
            "finalize_generation",
            "finalize_lease_expires_at",
            "archive_member_ordinal",
        ):
            self.assertIn(column, columns)

    def test_migration_tolerates_duplicate_path_children(self) -> None:
        sample_id = self._sample()
        parent = database.create_scan_job(
            sample_id, case_name="C", priority="Normal", note="", scan_role="container"
        )
        # Two legacy children with the SAME relative_path and NULL ordinal.
        self._child(parent, sample_id, "dup.txt")
        self._child(parent, sample_id, "dup.txt")
        # Re-running init (which creates the partial unique index) must not fail.
        database.init_db()

    def test_partial_unique_index_enforces_ordinal_uniqueness(self) -> None:
        sample_id = self._sample()
        parent = database.create_scan_job(
            sample_id, case_name="C", priority="Normal", note="", scan_role="container"
        )
        c1 = self._child(parent, sample_id, "a.txt")
        c2 = self._child(parent, sample_id, "b.txt")
        with database.connect() as connection:
            connection.execute(
                "UPDATE scan_jobs SET archive_member_ordinal = 0 WHERE id = ?", (c1,)
            )
        with self.assertRaises(sqlite3.IntegrityError):
            with database.connect() as connection:
                connection.execute(
                    "UPDATE scan_jobs SET archive_member_ordinal = 0 WHERE id = ?", (c2,)
                )


if __name__ == "__main__":
    unittest.main()
