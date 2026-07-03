import unittest

from app.database import postgres_query


class DatabaseQueryTests(unittest.TestCase):
    def test_converts_sqlite_placeholders_to_postgres_placeholders(self) -> None:
        query = "SELECT * FROM scan_jobs WHERE id = ? AND status = ?"

        self.assertEqual(
            postgres_query(query),
            "SELECT * FROM scan_jobs WHERE id = %s AND status = %s",
        )

    def test_preserves_casts_for_nullable_postgres_parameters(self) -> None:
        query = "WHEN CAST(? AS TEXT) IS NOT NULL THEN CAST(? AS TEXT)"

        self.assertEqual(
            postgres_query(query),
            "WHEN CAST(%s AS TEXT) IS NOT NULL THEN CAST(%s AS TEXT)",
        )


if __name__ == "__main__":
    unittest.main()
