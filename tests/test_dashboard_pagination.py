import unittest

from app.main import api_ledger_query_url, dashboard_query_url, paginate_scans, render_api_ledger_rows
from app.models import EngineResultRecord, ScanRecord


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

    def test_api_ledger_query_url_preserves_filters(self) -> None:
        self.assertEqual(
            api_ledger_query_url(
                page=2,
                query="sha256",
                status_filter="failed",
                verdict_filter="critical",
            ),
            "/api-ledger?page=2&q=sha256&status=failed&verdict=critical",
        )

    def test_api_ledger_rows_include_selection_controls_for_admins(self) -> None:
        markup = render_api_ledger_rows(
            [make_scan(7)],
            {7: [make_result(7)]},
            "empty",
            can_delete=True,
        )

        self.assertIn('data-scan-row', markup)
        self.assertIn('data-row-checkbox', markup)
        self.assertIn('/api-ledger/scans/7/delete', markup)


def make_scan(scan_id: int) -> ScanRecord:
    return ScanRecord(
        id=scan_id,
        sample_id=scan_id,
        case_name=f"Case {scan_id}",
        priority="Normal",
        note="",
        source="manual",
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


def make_result(scan_id: int) -> EngineResultRecord:
    return EngineResultRecord(
        id=scan_id,
        scan_job_id=scan_id,
        engine_name="ClamAV",
        engine_version="test",
        signature_version=None,
        status="completed",
        detected=False,
        signature=None,
        severity="info",
        confidence=100,
        raw_output="ok",
        error_message=None,
        duration_ms=10,
        created_at="2026-07-04 00:00:02",
        details_json="{}",
        findings_json="[]",
    )


if __name__ == "__main__":
    unittest.main()
