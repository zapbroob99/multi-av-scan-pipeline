import unittest

from app.services.engine_registry import (
    adapter_capabilities,
    adapter_definition,
    adapter_registry_entry,
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


if __name__ == "__main__":
    unittest.main()
