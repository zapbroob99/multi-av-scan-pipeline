import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app import database as db
from app.models import StoredSample
from app.services.scoring import calculate_risk
from app.workers.scan_worker import no_engine_completed


def result(status: str, detected: bool = False, name: str = "Engine"):
    return SimpleNamespace(engine_name=name, status=status, detected=detected, signature=None)


class RecordedRiskTests(unittest.TestCase):
    def test_clean_scan_records_no_risk_points(self) -> None:
        assessment = calculate_risk([result("completed"), result("completed", name="Other")])
        self.assertEqual((assessment.score, assessment.verdict), (0, "info"))
        self.assertIn("No completed engine reported a detection.", assessment.reasons)

    def test_detection_scoring_is_unchanged(self) -> None:
        self.assertEqual(calculate_risk([result("completed", True), result("completed")]).score, 70)
        self.assertEqual(calculate_risk([result("completed", True), result("completed", True, "B")]).verdict, "critical")

    def test_no_engine_completed_only_when_every_result_failed_or_skipped(self) -> None:
        self.assertIsNone(no_engine_completed([]))
        self.assertIsNone(no_engine_completed([result("failed"), result("completed", name="B")]))
        reason = no_engine_completed([result("failed", name="ClamAV"), result("skipped", name="YARA")])
        self.assertEqual(reason, "No engine completed a scan (ClamAV failed, YARA skipped).")


class FailedOutcomeStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.original = (db.DB_PATH, db.DATABASE_URL)
        db.DB_PATH, db.DATABASE_URL = Path(self.temp.name) / "outcome.db", ""
        self.addCleanup(self._restore)
        db.init_db()

    def _restore(self) -> None:
        db.DB_PATH, db.DATABASE_URL = self.original

    def scan(self) -> int:
        sample = db.create_sample(StoredSample("x.bin", "x.bin", "/private/x", "application/octet-stream", 1,
                                              "a" * 32, "b" * 40, "c" * 64))
        return db.create_scan_job(sample, "Case", "normal", "", source="api", status="running")

    def test_failure_ends_the_scan_failed_without_risk_or_notification(self) -> None:
        scan_id = self.scan()
        self.assertTrue(db.transition_scan_to_completed(scan_id, "info", 0, failure="No engine completed a scan (ClamAV failed)."))
        scan = db.get_scan(scan_id)
        self.assertEqual(scan.status, "failed")
        self.assertIsNone(scan.risk_score)
        self.assertEqual(scan.last_error, "No engine completed a scan (ClamAV failed).")
        self.assertIsNotNone(scan.failed_at)
        with db.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) AS n FROM notification_outbox").fetchone()["n"], 0)
        # Exactly once: a second finalizer cannot turn it into a completed scan.
        self.assertFalse(db.transition_scan_to_completed(scan_id, "info", 0))

    def test_fenced_finalizer_failure_respects_the_generation(self) -> None:
        scan_id = self.scan()
        generation = db.claim_scan_finalization(scan_id, "worker-a")
        self.assertFalse(db.complete_finalizing_scan(scan_id, "worker-b", generation, "info", 0, failure="x"))
        self.assertTrue(db.complete_finalizing_scan(scan_id, "worker-a", generation, "info", 0, failure="No engine completed a scan."))
        scan = db.get_scan(scan_id)
        self.assertEqual((scan.status, scan.risk_score), ("failed", None))


if __name__ == "__main__":
    unittest.main()
