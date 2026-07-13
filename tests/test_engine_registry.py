import unittest
from unittest import mock

from app.services import engine_registry
from app.services.engine_registry import (
    adapter_capabilities,
    adapter_definition,
    adapter_registry_entry,
)


class EnabledOnAddTests(unittest.TestCase):
    def add_engine_captures_enabled(self, adapter_key: str) -> bool:
        with mock.patch.object(
            engine_registry, "get_engine_instance", return_value=None
        ), mock.patch.object(engine_registry, "create_engine_instance") as mock_create:
            engine_registry.add_engine(adapter_key)
        mock_create.assert_called_once()
        return mock_create.call_args.kwargs["enabled"]

    def test_eset_added_disabled(self) -> None:
        self.assertFalse(
            self.add_engine_captures_enabled("eset_server_security_linux_cli")
        )

    def test_existing_adapters_added_enabled(self) -> None:
        self.assertTrue(self.add_engine_captures_enabled("clamav"))

    def test_eset_definition_flags(self) -> None:
        definition = adapter_definition("eset_server_security_linux_cli")
        self.assertFalse(definition.enabled_on_add)
        self.assertEqual(definition.support_state, "research")
        capabilities = adapter_capabilities("eset_server_security_linux_cli")
        self.assertEqual(capabilities.supported_platforms, ("linux",))


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
