import os
import unittest
from unittest.mock import patch

from app.engines.clamav import get_clamav_config
from app.models import EngineInstanceRecord
from app.services.engine_registry import (
    adapter_capabilities,
    adapter_definition,
    adapter_registry_entry,
    clamav_form_values,
    enabled_engines,
    enabled_hash_engines,
)


class ClamavFormPrefillTests(unittest.TestCase):
    """The engine config form must round-trip an env-provided clamd host.

    Found live on the pilot host: the form pre-filled Host from the stored
    setting only, so an env-provided host rendered as an empty field. Saving the
    form for an unrelated reason (changing max file size) then persisted
    host="", which disabled clamd and broke every scan.
    """

    def _no_stored_settings(self):
        # Isolate from the real database: no stored clamav.* settings.
        return patch(
            "app.services.engine_registry.get_setting",
            side_effect=lambda key, fallback=None: fallback,
        )

    def test_host_field_is_prefilled_from_the_environment(self) -> None:
        with patch.dict(os.environ, {"MASP_CLAMD_HOST": "clamav"}, clear=False), \
                self._no_stored_settings():
            values = clamav_form_values(None)

        self.assertEqual(values["host"], "clamav")

    def test_saving_the_prefilled_form_preserves_the_effective_host(self) -> None:
        # The actual regression: render the form, save exactly what it showed,
        # and the engine must still resolve to clamd -- not fall into CLI mode.
        with patch.dict(os.environ, {"MASP_CLAMD_HOST": "clamav"}, clear=False), \
                self._no_stored_settings():
            rendered = clamav_form_values(None)
            saved_config = {"host": rendered["host"], "port": rendered["port"]}
            resolved = get_clamav_config(saved_config)

        self.assertEqual(resolved["mode"], "clamd")
        self.assertEqual(resolved["host"], "clamav")


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
