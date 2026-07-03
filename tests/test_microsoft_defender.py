import unittest

from app.engines.microsoft_defender import (
    classify_status_command_failure,
    evaluate_status_payload,
    normalize_mpcmdrun_scan_result,
    parse_mpcmdrun_signature,
)


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


if __name__ == "__main__":
    unittest.main()
