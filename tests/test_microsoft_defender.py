import unittest
from pathlib import Path
from unittest.mock import patch

from app.engines import microsoft_defender
from app.engines.microsoft_defender import (
    cached_microsoft_defender_health,
    classify_status_command_failure,
    clear_defender_caches,
    evaluate_status_payload,
    normalize_mpcmdrun_scan_result,
    parse_mpcmdrun_signature,
    resolve_mpcmdrun_path,
)


FIXTURE_DIR = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "engines"
    / "microsoft_defender_local_cli"
)


def fixture_output(name: str) -> tuple[int, str]:
    content = (FIXTURE_DIR / name).read_text(encoding="utf-8")
    _, _, after_code = content.partition("RETURNCODE=")
    returncode_text, _, after_returncode = after_code.partition("\n")
    _, _, after_begin = after_returncode.partition("OUTPUT_BEGIN\n")
    output, _, _ = after_begin.partition("\nOUTPUT_END")
    return int(returncode_text.strip()), output.strip()


class MicrosoftDefenderHealthTests(unittest.TestCase):
    def test_classifies_access_denied(self) -> None:
        result = classify_status_command_failure(
            "",
            "Get-MpComputerStatus : Access denied\r\nHRESULT 0x80041003",
            1,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "permission denied")

    def test_classifies_disabled_service(self) -> None:
        result = evaluate_status_payload(
            {
                "AMServiceEnabled": False,
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": True,
                "AntivirusSignatureAge": 0,
            },
            require_real_time_enabled=True,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "disabled")

    def test_classifies_realtime_disabled_as_degraded(self) -> None:
        result = evaluate_status_payload(
            {
                "AMServiceEnabled": True,
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": False,
                "AntivirusSignatureAge": 0,
            },
            require_real_time_enabled=True,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "degraded")

    def test_classifies_stale_signatures_as_degraded(self) -> None:
        result = evaluate_status_payload(
            {
                "AMServiceEnabled": True,
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": True,
                "AntivirusSignatureAge": 7,
            },
            require_real_time_enabled=False,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "degraded")

    def test_classifies_healthy_status_as_available(self) -> None:
        result = evaluate_status_payload(
            {
                "AMServiceEnabled": True,
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": True,
                "AntivirusSignatureAge": 0,
                "AMEngineVersion": "1.1.24050.5",
                "AMProductVersion": "4.18.24050.7",
                "AntivirusSignatureVersion": "1.431.10.0",
            },
            require_real_time_enabled=True,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "available")
        self.assertIn("engine 1.1.24050.5", str(result["detail"]))

    def test_parses_defender_signature_from_threat_line(self) -> None:
        signature = parse_mpcmdrun_signature("Threat Name: Virus:DOS/EICAR_Test_File")
        self.assertEqual(signature, "Virus:DOS/EICAR_Test_File")

    def test_normalizes_clean_mpcmdrun_result(self) -> None:
        result = normalize_mpcmdrun_scan_result(
            returncode=0,
            raw_output="Scan starting...\nNo threats found.",
            duration_ms=12,
        )
        self.assertEqual(result.status, "completed")
        self.assertFalse(result.detected)
        self.assertEqual(result.confidence, 100)

    def test_normalizes_detected_mpcmdrun_result(self) -> None:
        result = normalize_mpcmdrun_scan_result(
            returncode=2,
            raw_output="Threat Name: Virus:DOS/EICAR_Test_File",
            duration_ms=12,
        )
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.detected)
        self.assertEqual(result.signature, "Virus:DOS/EICAR_Test_File")
        self.assertIn("EICAR", result.findings_json)

    def test_keeps_ambiguous_code_two_as_failed(self) -> None:
        result = normalize_mpcmdrun_scan_result(
            returncode=2,
            raw_output="Scanning failed with an internal error.",
            duration_ms=12,
        )
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.detected)
        self.assertIn("without a clear detection", str(result.error_message))

    def test_normalizes_clean_fixture(self) -> None:
        returncode, output = fixture_output("scan_clean_mpcmdrun.txt")
        result = normalize_mpcmdrun_scan_result(
            returncode=returncode,
            raw_output=output,
            duration_ms=12,
        )
        self.assertEqual(result.status, "completed")
        self.assertFalse(result.detected)

    def test_normalizes_eicar_fixture(self) -> None:
        returncode, output = fixture_output("scan_detected_eicar_mpcmdrun.txt")
        result = normalize_mpcmdrun_scan_result(
            returncode=returncode,
            raw_output=output,
            duration_ms=12,
        )
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.detected)
        self.assertEqual(result.signature, "Virus:DOS/EICAR_Test_File")


def make_defender_config(**overrides: object) -> dict[str, object]:
    base = {
        "execution_mode": "powershell",
        "powershell_path": "powershell.exe",
        "mpcmdrun_path": "auto",
        "timeout_seconds": 900,
        "require_real_time_enabled": True,
    }
    base.update(overrides)
    return base


HEALTHY = {"ok": True, "status": "available", "detail": "ok"}
TRANSIENT_FAILURE = {"ok": False, "status": "unavailable", "detail": "PowerShell hiccup"}


class DefenderHealthCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_defender_caches()

    def tearDown(self) -> None:
        clear_defender_caches()

    def test_health_is_cached_within_ttl(self) -> None:
        with patch.object(
            microsoft_defender, "health_cache_seconds", return_value=30
        ), patch.object(
            microsoft_defender, "monotonic", return_value=1000.0
        ), patch.object(
            microsoft_defender, "check_microsoft_defender_health", return_value=HEALTHY
        ) as probe:
            first = cached_microsoft_defender_health(make_defender_config())
            second = cached_microsoft_defender_health(make_defender_config())

        self.assertEqual(first, HEALTHY)
        self.assertEqual(second, HEALTHY)
        self.assertEqual(probe.call_count, 1)

    def test_health_reprobes_after_ttl_expiry(self) -> None:
        with patch.object(
            microsoft_defender, "health_cache_seconds", return_value=30
        ), patch.object(
            microsoft_defender, "monotonic", side_effect=[1000.0, 1031.0]
        ), patch.object(
            microsoft_defender, "check_microsoft_defender_health", return_value=HEALTHY
        ) as probe:
            cached_microsoft_defender_health(make_defender_config())
            cached_microsoft_defender_health(make_defender_config())

        self.assertEqual(probe.call_count, 2)

    def test_health_reprobes_when_config_changes(self) -> None:
        with patch.object(
            microsoft_defender, "health_cache_seconds", return_value=30
        ), patch.object(
            microsoft_defender, "monotonic", return_value=1000.0
        ), patch.object(
            microsoft_defender, "check_microsoft_defender_health", return_value=HEALTHY
        ) as probe:
            cached_microsoft_defender_health(make_defender_config())
            cached_microsoft_defender_health(
                make_defender_config(require_real_time_enabled=False)
            )

        self.assertEqual(probe.call_count, 2)

    def test_health_cache_disabled_when_both_ttls_zero(self) -> None:
        with patch.object(
            microsoft_defender, "health_cache_seconds", return_value=0
        ), patch.object(
            microsoft_defender, "negative_health_cache_seconds", return_value=0
        ), patch.object(
            microsoft_defender, "check_microsoft_defender_health", return_value=HEALTHY
        ) as probe:
            cached_microsoft_defender_health(make_defender_config())
            cached_microsoft_defender_health(make_defender_config())

        self.assertEqual(probe.call_count, 2)

    def test_transient_failure_uses_short_negative_ttl(self) -> None:
        # ok=False cached only for the short negative window (5s), so a transient
        # failure does not skip scans for the full 30s positive TTL.
        with patch.object(
            microsoft_defender, "health_cache_seconds", return_value=30
        ), patch.object(
            microsoft_defender, "negative_health_cache_seconds", return_value=5
        ), patch.object(
            microsoft_defender, "monotonic", side_effect=[1000.0, 1003.0, 1006.0]
        ), patch.object(
            microsoft_defender,
            "check_microsoft_defender_health",
            return_value=TRANSIENT_FAILURE,
        ) as probe:
            cached_microsoft_defender_health(make_defender_config())  # probe, store exp 1005
            cached_microsoft_defender_health(make_defender_config())  # t=1003 hit
            cached_microsoft_defender_health(make_defender_config())  # t=1006 expired -> reprobe

        self.assertEqual(probe.call_count, 2)

    def test_healthy_result_uses_long_positive_ttl(self) -> None:
        with patch.object(
            microsoft_defender, "health_cache_seconds", return_value=30
        ), patch.object(
            microsoft_defender, "negative_health_cache_seconds", return_value=5
        ), patch.object(
            microsoft_defender, "monotonic", side_effect=[1000.0, 1006.0]
        ), patch.object(
            microsoft_defender, "check_microsoft_defender_health", return_value=HEALTHY
        ) as probe:
            cached_microsoft_defender_health(make_defender_config())  # store exp 1030
            cached_microsoft_defender_health(make_defender_config())  # t=1006 still cached

        self.assertEqual(probe.call_count, 1)

    def test_mpcmdrun_path_is_cached(self) -> None:
        with patch.object(
            microsoft_defender, "health_cache_seconds", return_value=30
        ), patch.object(
            microsoft_defender, "monotonic", return_value=1000.0
        ), patch.object(
            microsoft_defender,
            "_resolve_mpcmdrun_path_uncached",
            return_value="C:/Defender/MpCmdRun.exe",
        ) as resolver:
            first = resolve_mpcmdrun_path("auto")
            second = resolve_mpcmdrun_path("auto")

        self.assertEqual(first, "C:/Defender/MpCmdRun.exe")
        self.assertEqual(second, "C:/Defender/MpCmdRun.exe")
        self.assertEqual(resolver.call_count, 1)


if __name__ == "__main__":
    unittest.main()
