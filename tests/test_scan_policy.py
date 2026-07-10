import os
import unittest
from unittest.mock import patch

from app.services import scan_policy


class ResolveIntTests(unittest.TestCase):
    def test_database_override_wins(self) -> None:
        with patch("app.services.scan_policy.get_setting", return_value="42"), patch.dict(
            os.environ, {"MASP_API_MAX_WAIT_SECONDS": "99"}, clear=True
        ):
            self.assertEqual(scan_policy.resolve_int("api_max_wait_seconds"), 42)

    def test_env_used_when_no_override(self) -> None:
        with patch("app.services.scan_policy.get_setting", return_value=None), patch.dict(
            os.environ, {"MASP_API_MAX_WAIT_SECONDS": "20"}, clear=True
        ):
            self.assertEqual(scan_policy.resolve_int("api_max_wait_seconds"), 20)

    def test_default_when_no_override_and_no_env(self) -> None:
        with patch("app.services.scan_policy.get_setting", return_value=None), patch.dict(
            os.environ, {}, clear=True
        ):
            self.assertEqual(scan_policy.resolve_int("api_max_wait_seconds"), 15)

    def test_blank_override_falls_through_to_env(self) -> None:
        with patch("app.services.scan_policy.get_setting", return_value="  "), patch.dict(
            os.environ, {"MASP_API_RETRY_AFTER_SECONDS": "7"}, clear=True
        ):
            self.assertEqual(scan_policy.resolve_int("api_retry_after_seconds"), 7)

    def test_value_clamped_to_maximum_on_read(self) -> None:
        with patch("app.services.scan_policy.get_setting", return_value="99999"), patch.dict(
            os.environ, {}, clear=True
        ):
            self.assertEqual(scan_policy.resolve_int("api_max_wait_seconds"), 300)

    def test_value_clamped_to_minimum_on_read(self) -> None:
        with patch("app.services.scan_policy.get_setting", return_value="0"), patch.dict(
            os.environ, {}, clear=True
        ):
            # retry-after minimum is 1
            self.assertEqual(scan_policy.resolve_int("api_retry_after_seconds"), 1)

    def test_garbage_stored_value_falls_back_to_default(self) -> None:
        with patch("app.services.scan_policy.get_setting", return_value="not-a-number"), patch.dict(
            os.environ, {}, clear=True
        ):
            self.assertEqual(scan_policy.resolve_int("api_retry_after_seconds"), 2)

    def test_database_error_falls_back_to_env(self) -> None:
        with patch(
            "app.services.scan_policy.get_setting", side_effect=RuntimeError("db down")
        ), patch.dict(os.environ, {"MASP_UPLOAD_MAX_BYTES": "1024"}, clear=True):
            self.assertEqual(scan_policy.resolve_int("upload_max_bytes"), 1024)


class ValidateTests(unittest.TestCase):
    def test_blank_means_revert(self) -> None:
        self.assertEqual(scan_policy.validate("api_max_wait_seconds", "  "), (None, None))

    def test_non_integer_rejected(self) -> None:
        value, error = scan_policy.validate("api_max_wait_seconds", "ten")
        self.assertIsNone(value)
        self.assertIn("whole number", error)

    def test_out_of_range_rejected(self) -> None:
        value, error = scan_policy.validate("api_max_wait_seconds", "5000")
        self.assertIsNone(value)
        self.assertIn("between 0 and 300", error)

    def test_below_minimum_rejected(self) -> None:
        value, error = scan_policy.validate("api_retry_after_seconds", "0")
        self.assertIsNone(value)
        self.assertIn("between 1 and 30", error)

    def test_valid_value_accepted(self) -> None:
        self.assertEqual(scan_policy.validate("api_max_wait_seconds", "45"), (45, None))


class StoreTests(unittest.TestCase):
    def test_store_value_writes_prefixed_key(self) -> None:
        with patch("app.services.scan_policy.set_setting") as set_mock, patch(
            "app.services.scan_policy.delete_setting"
        ) as delete_mock:
            scan_policy.store("api_max_wait_seconds", 30)
            set_mock.assert_called_once_with("scan_policy.api_max_wait_seconds", "30")
            delete_mock.assert_not_called()

    def test_store_none_deletes_override(self) -> None:
        with patch("app.services.scan_policy.set_setting") as set_mock, patch(
            "app.services.scan_policy.delete_setting"
        ) as delete_mock:
            scan_policy.store("api_max_wait_seconds", None)
            delete_mock.assert_called_once_with("scan_policy.api_max_wait_seconds")
            set_mock.assert_not_called()


class SnapshotTests(unittest.TestCase):
    def test_snapshot_reports_source_provenance(self) -> None:
        with patch("app.services.scan_policy.get_setting", return_value=None), patch.dict(
            os.environ, {"MASP_API_MAX_WAIT_SECONDS": "25"}, clear=True
        ):
            rows = {row["spec"].key: row for row in scan_policy.snapshot()}
        self.assertFalse(rows["api_max_wait_seconds"]["has_override"])
        self.assertEqual(rows["api_max_wait_seconds"]["value"], 25)
        self.assertIn("environment", rows["api_max_wait_seconds"]["source"])

    def test_snapshot_flags_database_override(self) -> None:
        with patch("app.services.scan_policy.get_setting", return_value="50"), patch.dict(
            os.environ, {}, clear=True
        ):
            rows = {row["spec"].key: row for row in scan_policy.snapshot()}
        self.assertTrue(rows["api_max_wait_seconds"]["has_override"])
        self.assertEqual(rows["api_max_wait_seconds"]["override_raw"], "50")
        self.assertEqual(rows["api_max_wait_seconds"]["source"], "database override")


if __name__ == "__main__":
    unittest.main()
