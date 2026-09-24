import unittest

from cryptography.fernet import Fernet

from app.models import EngineInstanceRecord
from app.services.secret_store import encrypt_secret
from app.services.virustotal import VirusTotalNotConfiguredError, load_virustotal_config


def engine(config_json: str = "{}") -> EngineInstanceRecord:
    return EngineInstanceRecord(
        id=10,
        adapter_key="virustotal",
        display_name="VirusTotal",
        enabled=True,
        config_json=config_json,
        created_at="2026-08-17T00:00:00+00:00",
        updated_at="2026-08-17T00:00:00+00:00",
    )


def submit(**overrides: str):
    values = {
        "virustotal_api_key": "",
        "virustotal_timeout_seconds": "10",
        "virustotal_cache_seconds": "3600",
        "virustotal_unknown_cache_seconds": "300",
        "virustotal_cache_max_entries": "10000",
        "virustotal_malicious_threshold": "1",
        "virustotal_allow_undetected": "false",
        "virustotal_max_age_days": "30",
        "virustotal_clear_api_key": "false",
    }
    values.update(overrides)
    return save_virustotal_config(object(), **values)


class VirusTotalConfigUiTests(unittest.TestCase):
    def test_runtime_uses_encrypted_engine_key_and_policy_without_enabled_env(self) -> None:
        encryption_key = Fernet.generate_key().decode("ascii")
        environ = {"MASP_SECRET_ENCRYPTION_KEY": encryption_key}
        encrypted = encrypt_secret("vt-secret-value", environ)

        config = load_virustotal_config(
            environ,
            {
                "api_key_encrypted": encrypted,
                "malicious_threshold": "4",
                "allow_undetected": "true",
            },
        )

        self.assertEqual(config.api_key, "vt-secret-value")
        self.assertEqual(config.malicious_threshold, 4)
        self.assertTrue(config.allow_undetected)

    def test_wrong_server_key_fails_closed(self) -> None:
        original_key = Fernet.generate_key().decode("ascii")
        encrypted = encrypt_secret(
            "vt-secret-value", {"MASP_SECRET_ENCRYPTION_KEY": original_key}
        )
        wrong_key = Fernet.generate_key().decode("ascii")

        with self.assertRaises(VirusTotalNotConfiguredError):
            load_virustotal_config(
                {"MASP_SECRET_ENCRYPTION_KEY": wrong_key},
                {"api_key_encrypted": encrypted},
            )


if __name__ == "__main__":
    unittest.main()
