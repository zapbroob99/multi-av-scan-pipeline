import unittest
from dataclasses import replace
from unittest.mock import patch

from app.models import EngineResultRecord
from app.services.decisions import decide_scan_action
from app.services.scan_assessment import (
    engine_policy_review_reasons,
    required_engine_coverage,
)


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

    def test_completed_hash_engine_review_policy_is_separate_from_coverage(self) -> None:
        result = EngineResultRecord(
            id=1,
            scan_job_id=1,
            engine_name="VirusTotal",
            engine_version="api-v3",
            signature_version=None,
            status="completed",
            detected=False,
            signature=None,
            severity="info",
            confidence=75,
            raw_output="{}",
            error_message=None,
            duration_ms=10,
            created_at="",
            details_json='{"decision":{"action":"review"}}',
            findings_json="[]",
        )
        with patch(
            "app.services.scan_assessment.detection_engine_names",
            return_value=["VirusTotal"],
        ):
            ran, required, unavailable = required_engine_coverage([result])

        self.assertEqual((ran, required), (1, 1))
        self.assertEqual(unavailable, [])
        self.assertEqual(
            engine_policy_review_reasons([result]),
            ["VirusTotal requires review under its configured policy."],
        )

        legacy_unknown = replace(
            result,
            details_json=(
                '{"source":"virustotal","found":false,"status":"unknown",'
                '"decision":{"action":"review","reason":"No report."}}'
            ),
        )
        self.assertEqual(engine_policy_review_reasons([legacy_unknown]), [])
        self.assertEqual(
            engine_policy_review_reasons([legacy_unknown], source="hash"),
            ["VirusTotal: No report."],
        )

    def test_completed_engine_policy_review_has_an_explicit_decision_reason(self) -> None:
        decision = decide_scan_action(
            scan_status="completed",
            verdict="low",
            risk_score=10,
            detected_engines=0,
            detection_engines=3,
            unavailable_engines=[],
            policy_review_reasons=[
                "VirusTotal: No malicious engines reported, but policy requires review."
            ],
        )

        self.assertEqual(decision.action, "review")
        self.assertEqual(decision.policy, "engine_policy_review")
        self.assertIn("All required engines completed", decision.reasons[0])
        self.assertIn("VirusTotal", decision.reasons[1])


if __name__ == "__main__":
    unittest.main()
