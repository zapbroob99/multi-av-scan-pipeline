import unittest

from app.engines.microsoft_defender import (
    classify_status_command_failure,
    evaluate_status_payload,
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


if __name__ == "__main__":
    unittest.main()
