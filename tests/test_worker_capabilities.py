import unittest
from unittest.mock import patch

from app.models import EngineInstanceRecord
from app.services.worker_capabilities import (
    adapter_supported_on_platform,
    all_enabled_engines_have_results,
    missing_supported_engines,
    supported_engines,
    worker_engine_keys,
)


class WorkerCapabilityTests(unittest.TestCase):
    def test_filters_engines_by_worker_capability(self) -> None:
        engines = [
            engine("clamav", "ClamAV"),
            engine("microsoft_defender", "Microsoft Defender"),
            engine("yara", "YARA"),
        ]
        with patch("app.services.worker_capabilities.worker_platform", return_value="windows"):
            filtered = supported_engines(engines, {"microsoft_defender"})
        self.assertEqual([item.adapter_key for item in filtered], ["microsoft_defender"])

    def test_missing_supported_engines_ignores_other_worker_engines(self) -> None:
        engines = [
            engine("clamav", "ClamAV"),
            engine("microsoft_defender", "Microsoft Defender"),
        ]
        with patch("app.services.worker_capabilities.worker_platform", return_value="windows"):
            missing = missing_supported_engines(
                engines,
                existing_engine_names={"ClamAV"},
                engine_keys={"microsoft_defender"},
            )
        self.assertEqual([item.display_name for item in missing], ["Microsoft Defender"])

    def test_worker_engine_keys_drop_unknown_or_incompatible_entries(self) -> None:
        with patch.dict(
            "os.environ",
            {"MASP_WORKER_ENGINE_KEYS": "clamav,microsoft_defender,unknown"},
            clear=False,
        ):
            with patch("app.services.worker_capabilities.worker_platform", return_value="linux"):
                keys = worker_engine_keys()

        self.assertEqual(keys, {"clamav"})

    def test_platform_support_helper_reflects_adapter_capabilities(self) -> None:
        self.assertTrue(adapter_supported_on_platform("clamav", "linux"))
        self.assertFalse(adapter_supported_on_platform("clamav", "windows"))
        self.assertFalse(adapter_supported_on_platform("unknown", "linux"))

    def test_scan_complete_requires_all_enabled_engine_results(self) -> None:
        engines = [
            engine("clamav", "ClamAV"),
            engine("microsoft_defender", "Microsoft Defender"),
        ]
        self.assertFalse(
            all_enabled_engines_have_results(engines, {"Microsoft Defender"})
        )
        self.assertTrue(
            all_enabled_engines_have_results(
                engines,
                {"ClamAV", "Microsoft Defender"},
            )
        )


def engine(adapter_key: str, display_name: str) -> EngineInstanceRecord:
    return EngineInstanceRecord(
        id=1,
        adapter_key=adapter_key,
        display_name=display_name,
        enabled=True,
        config_json="{}",
        created_at="",
        updated_at="",
    )


if __name__ == "__main__":
    unittest.main()
