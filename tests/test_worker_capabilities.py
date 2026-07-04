import unittest

from app.models import EngineInstanceRecord
from app.services.worker_capabilities import (
    all_enabled_engines_have_results,
    missing_supported_engines,
    supported_engines,
)


class WorkerCapabilityTests(unittest.TestCase):
    def test_filters_engines_by_worker_capability(self) -> None:
        engines = [
            engine("clamav", "ClamAV"),
            engine("microsoft_defender", "Microsoft Defender"),
            engine("yara", "YARA"),
        ]
        filtered = supported_engines(engines, {"microsoft_defender"})
        self.assertEqual([item.adapter_key for item in filtered], ["microsoft_defender"])

    def test_missing_supported_engines_ignores_other_worker_engines(self) -> None:
        engines = [
            engine("clamav", "ClamAV"),
            engine("microsoft_defender", "Microsoft Defender"),
        ]
        missing = missing_supported_engines(
            engines,
            existing_engine_names={"ClamAV"},
            engine_keys={"microsoft_defender"},
        )
        self.assertEqual([item.display_name for item in missing], ["Microsoft Defender"])

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
