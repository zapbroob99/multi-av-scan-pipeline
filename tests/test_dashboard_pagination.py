import unittest

from app.main import dashboard_query_url, paginate_scans
from app.models import ScanRecord


class DashboardPaginationTests(unittest.TestCase):
    def test_paginate_scans_returns_requested_slice(self) -> None:
        scans = [make_scan(scan_id) for scan_id in range(1, 46)]

        page_items, current_page, total_pages, total_items = paginate_scans(
            scans,
            page=2,
            page_size=20,
        )

        self.assertEqual(total_items, 45)
        self.assertEqual(total_pages, 3)
        self.assertEqual(current_page, 2)
        self.assertEqual([scan.id for scan in page_items], list(range(21, 41)))

    def test_paginate_scans_clamps_page_to_last_page(self) -> None:
        scans = [make_scan(scan_id) for scan_id in range(1, 12)]

        page_items, current_page, total_pages, total_items = paginate_scans(
            scans,
            page=9,
            page_size=5,
        )

        self.assertEqual(total_items, 11)
        self.assertEqual(total_pages, 3)
        self.assertEqual(current_page, 3)
        self.assertEqual([scan.id for scan in page_items], [11])

    def test_dashboard_query_url_preserves_filters(self) -> None:
        self.assertEqual(
            dashboard_query_url(
                page=3,
                query="eicar",
                status_filter="completed",
                verdict_filter="malicious",
            ),
            "/?page=3&q=eicar&status=completed&verdict=malicious",
        )


def make_scan(scan_id: int) -> ScanRecord:
    return ScanRecord(
        id=scan_id,
        sample_id=scan_id,
        case_name=f"Case {scan_id}",
        priority="Normal",
        note="",
        status="completed",
        verdict="undetected",
        risk_score=0,
        created_at="2026-07-04 00:00:00",
        started_at="2026-07-04 00:00:01",
        completed_at="2026-07-04 00:00:02",
        failed_at=None,
        attempt_count=1,
        last_error=None,
        original_filename=f"sample-{scan_id}.bin",
        stored_filename=f"sample-{scan_id}.bin",
        storage_path=f"storage/samples/sample-{scan_id}.bin",
        content_type="application/octet-stream",
        size_bytes=42,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


if __name__ == "__main__":
    unittest.main()
