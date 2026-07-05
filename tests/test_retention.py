import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from app.services.retention import retention_cutoff_value, retention_policy_from_env


class RetentionPolicyTests(unittest.TestCase):
    def test_retention_is_disabled_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            policy = retention_policy_from_env()

        self.assertFalse(policy.enabled)
        self.assertEqual(policy.days, 0)
        self.assertEqual(policy.batch_size, 100)
        self.assertIsNone(retention_cutoff_value(policy))

    def test_retention_policy_uses_env_values(self) -> None:
        with patch.dict(
            os.environ,
            {"MASP_RETENTION_DAYS": "30", "MASP_RETENTION_BATCH_SIZE": "25"},
            clear=True,
        ):
            policy = retention_policy_from_env()

        self.assertTrue(policy.enabled)
        self.assertEqual(policy.days, 30)
        self.assertEqual(policy.batch_size, 25)

    def test_retention_cutoff_is_utc_iso_value(self) -> None:
        with patch.dict(os.environ, {"MASP_RETENTION_DAYS": "7"}, clear=True):
            policy = retention_policy_from_env()

        cutoff = retention_cutoff_value(
            policy,
            now=datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(cutoff, "2026-06-28 12:00:00+00:00")

    def test_invalid_env_values_fall_back_safely(self) -> None:
        with patch.dict(
            os.environ,
            {"MASP_RETENTION_DAYS": "invalid", "MASP_RETENTION_BATCH_SIZE": "0"},
            clear=True,
        ):
            policy = retention_policy_from_env()

        self.assertFalse(policy.enabled)
        self.assertEqual(policy.days, 0)
        self.assertEqual(policy.batch_size, 1)


if __name__ == "__main__":
    unittest.main()
