import os
import unittest
from unittest.mock import patch

from app.models import EngineInstanceRecord
from app.services.engine_registry import (
    adapter_capabilities,
    adapter_definition,
    adapter_registry_entry,
    enabled_engines,
    enabled_hash_engines,
)


class EngineRegistryTests(unittest.TestCase):
    def test_adapter_definition_exposes_category(self) -> None:
        definition = adapter_definition("clamav")

        self.assertEqual(definition.category, "detection")
        self.assertTrue(definition.detection)

    def test_adapter_capabilities_expose_runtime_contract(self) -> None:
        capabilities = adapter_capabilities("microsoft_defender")

        self.assertEqual(capabilities.deployment, "worker")
        self.assertEqual(capabilities.input_modes, ("file", "path"))
        self.assertEqual(capabilities.supported_platforms, ("windows",))
        self.assertFalse(capabilities.supports_hash_lookup)

    def test_registered_adapter_runtime_config_delegates(self) -> None:
        adapter = adapter_registry_entry("static_metadata")
        runtime = adapter.runtime_config()
        health = adapter.health_check()

        self.assertEqual(adapter.key, "static_metadata")
        self.assertEqual(runtime["mode"], "builtin")
        self.assertEqual(runtime["timeout_seconds"], 1)
        self.assertTrue(health["ok"])

    def test_virustotal_is_a_hash_reputation_engine_for_hash_and_file_scans(self) -> None:
        definition = adapter_definition("virustotal")
        capabilities = adapter_capabilities("virustotal")

        self.assertEqual(definition.category, "reputation")
        self.assertTrue(definition.detection)
        self.assertEqual(capabilities.input_modes, ("hash", "file hash"))
        self.assertEqual(capabilities.deployment, "api worker")
        self.assertTrue(capabilities.supports_hash_lookup)
        self.assertFalse(capabilities.supports_file_upload)
        self.assertTrue(capabilities.supports_file_hash_scan)
        self.assertTrue(capabilities.requires_network)
        self.assertTrue(capabilities.consumes_external_quota)

    def test_hash_reputation_engine_participates_in_file_scan_intake(self) -> None:
        virustotal = EngineInstanceRecord(
            id=4,
            adapter_key="virustotal",
            display_name="VirusTotal",
            enabled=True,
            config_json="{}",
            created_at="2026-08-17T00:00:00+00:00",
            updated_at="2026-08-17T00:00:00+00:00",
        )
        with patch(
            "app.services.engine_registry.configured_engines", return_value=[virustotal]
        ):
            self.assertEqual(enabled_engines(), [virustotal])
            self.assertEqual(enabled_hash_engines(), [virustotal])
            self.assertEqual(enabled_engines(source="api"), [])
            self.assertEqual(enabled_engines(source="icap"), [])
            self.assertEqual(enabled_hash_engines(source="api"), [])

    def test_virustotal_runtime_config_never_exposes_the_api_key(self) -> None:
        adapter = adapter_registry_entry("virustotal")
        with patch.dict(
            os.environ,
            {
                "MASP_VIRUSTOTAL_ENABLED": "1",
                "MASP_VIRUSTOTAL_API_KEY": "not-a-real-secret-for-testing",
            },
            clear=False,
        ):
            runtime = adapter.runtime_config()
            health = adapter.health_check()

        self.assertTrue(runtime["configured"])
        self.assertNotIn("api_key", runtime)
        self.assertNotIn("not-a-real-secret-for-testing", str(runtime))
        self.assertTrue(health["ok"])


if __name__ == "__main__":
    unittest.main()
