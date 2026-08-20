import unittest

from app.models import EngineInstanceRecord, EngineResultInput
from app.services.hash_scanning import (
    HashEngineExecution,
    HashEngineRun,
    build_hash_scan_payload,
)


SHA256 = "a" * 64


def run(key: str, action: str) -> HashEngineRun:
    payload = {
        "hash": SHA256,
        "status": "malicious" if action == "block" else "undetected",
        "found": True,
        "detail": f"{key} returned {action}",
        "decision": {"action": action, "reason": f"{key} returned {action}"},
    }
    return HashEngineRun(
        engine=EngineInstanceRecord(
            id=1,
            adapter_key=key,
            display_name=key.title(),
            enabled=True,
            config_json="{}",
            created_at="",
            updated_at="",
        ),
        support_state="supported",
        execution=HashEngineExecution(
            result=EngineResultInput(
                engine_name=key.title(),
                status="completed",
                detected=action == "block",
                severity="critical" if action == "block" else "info",
                confidence=90,
                signature=None,
                raw_output="{}",
                duration_ms=5,
            ),
            payload=payload,
        ),
    )


class HashScanningTests(unittest.TestCase):
    def test_block_precedes_review_and_allow_across_engines(self) -> None:
        payload = build_hash_scan_payload(
            SHA256,
            [run("allow_engine", "allow"), run("review_engine", "review"), run("block_engine", "block")],
        )

        self.assertEqual(payload["decision"]["action"], "block")
        self.assertEqual(payload["engines"], {"expected": 3, "completed": 3, "failed": 0})
        self.assertEqual([item["engine"]["key"] for item in payload["results"]], [
            "allow_engine", "review_engine", "block_engine"
        ])

    def test_all_engines_must_allow_for_aggregate_allow(self) -> None:
        payload = build_hash_scan_payload(
            SHA256,
            [run("first", "allow"), run("second", "allow")],
        )

        self.assertEqual(payload["decision"]["action"], "allow")


if __name__ == "__main__":
    unittest.main()
