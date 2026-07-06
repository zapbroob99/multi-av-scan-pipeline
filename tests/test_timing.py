import unittest
from datetime import datetime, timezone

from app.models import ScanRecord
from app.services.timing import build_scan_timing_payload


class TimingTests(unittest.TestCase):
    def test_build_scan_timing_payload_for_completed_scan(self) -> None:
        scan = make_scan(
            created_at="2026-07-05 10:00:00+00:00",
            started_at="2026-07-05 10:00:03+00:00",
            completed_at="2026-07-05 10:00:10+00:00",
            failed_at=None,
        )

        payload = build_scan_timing_payload(scan)

        self.assertEqual(payload["queue_wait_ms"], 3000)
        self.assertEqual(payload["processing_duration_ms"], 7000)
        self.assertEqual(payload["total_duration_ms"], 10000)

    def test_build_scan_timing_payload_for_running_scan(self) -> None:
        scan = make_scan(
            created_at="2026-07-05 10:00:00+00:00",
            started_at="2026-07-05 10:00:04+00:00",
            completed_at=None,
            failed_at=None,
        )

        payload = build_scan_timing_payload(
            scan,
            now=datetime(2026, 7, 5, 10, 0, 9, tzinfo=timezone.utc),
        )

        self.assertEqual(payload["queue_wait_ms"], 4000)
        self.assertIsNone(payload["processing_duration_ms"])
        self.assertIsNone(payload["total_duration_ms"])
        self.assertEqual(payload["age_ms"], 9000)
        self.assertEqual(payload["processing_age_ms"], 5000)


def make_scan(
    *,
    created_at: str,
    started_at: str | None,
    completed_at: str | None,
    failed_at: str | None,
) -> ScanRecord:
    return ScanRecord(
        id=29,
        sample_id=29,
        case_name="IR-2026-001",
        priority="Normal",
        note="manual api test",
        status="completed" if completed_at else "running",
        verdict="critical" if completed_at else "pending",
        risk_score=90 if completed_at else None,
        created_at=created_at,
        started_at=started_at,
        completed_at=completed_at,
        failed_at=failed_at,
        attempt_count=1,
        last_error=None,
        original_filename="eicar.com",
        stored_filename="eicar.com",
        storage_path="/app/storage/samples/eicar.com",
        content_type="application/octet-stream",
        size_bytes=68,
        md5="44d88612fea8a8f36de82e1278abb02f",
        sha1="3395856ce81f2b7382dee72602f798b642f14140",
        sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    )


if __name__ == "__main__":
    unittest.main()
