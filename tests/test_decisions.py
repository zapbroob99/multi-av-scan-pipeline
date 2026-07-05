import unittest

from app.services.decisions import decide_scan_action


class ScanDecisionTests(unittest.TestCase):
    def test_running_scan_waits_for_final_result(self) -> None:
        decision = decide_scan_action(
            scan_status="running",
            verdict="pending",
            risk_score=0,
            detected_engines=0,
            detection_engines=3,
            unavailable_engines=[],
        )

        self.assertEqual(decision.action, "wait")
        self.assertEqual(decision.policy, "scan_in_progress")

    def test_detected_scan_blocks(self) -> None:
        decision = decide_scan_action(
            scan_status="completed",
            verdict="critical",
            risk_score=90,
            detected_engines=2,
            detection_engines=3,
            unavailable_engines=[],
        )

        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.policy, "malware_detected")

    def test_clean_full_coverage_scan_allows(self) -> None:
        decision = decide_scan_action(
            scan_status="completed",
            verdict="low",
            risk_score=10,
            detected_engines=0,
            detection_engines=3,
            unavailable_engines=[],
        )

        self.assertEqual(decision.action, "allow")
        self.assertEqual(decision.policy, "clean_full_coverage")

    def test_partial_clean_scan_requires_review(self) -> None:
        decision = decide_scan_action(
            scan_status="completed",
            verdict="low",
            risk_score=10,
            detected_engines=0,
            detection_engines=3,
            unavailable_engines=["ClamAV skipped"],
        )

        self.assertEqual(decision.action, "review")
        self.assertEqual(decision.policy, "partial_coverage")

    def test_metadata_only_scan_requires_review(self) -> None:
        decision = decide_scan_action(
            scan_status="completed",
            verdict="info",
            risk_score=0,
            detected_engines=0,
            detection_engines=0,
            unavailable_engines=[],
        )

        self.assertEqual(decision.action, "review")
        self.assertEqual(decision.policy, "metadata_only")


if __name__ == "__main__":
    unittest.main()
