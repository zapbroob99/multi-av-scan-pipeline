import unittest
from unittest.mock import patch

from app.main import (
    api_ledger_query_url,
    dashboard_query_url,
    paginate_scans,
    render_api_ledger_rows,
    render_recent_scan_rows,
    render_scan_result,
)
from app.models import EngineResultRecord, ScanRecord, UserRecord


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

    def test_api_ledger_rows_include_batch_link_for_archive_scans(self) -> None:
        markup = render_api_ledger_rows(
            [make_scan(8, batch_id=44, scan_role="container", relative_path="bundle.zip")],
            {8: [make_result(8)]},
            "empty",
        )

        self.assertIn('/api-ledger/batches/44', markup)
        self.assertIn('Batch #44', markup)

    def test_recent_scan_rows_keep_archive_scans_on_scan_detail_flow(self) -> None:
        markup = render_recent_scan_rows(
            [make_scan(9, batch_id=51, scan_role="container", relative_path="bundle.zip")],
            can_select=False,
            results_by_scan={9: [make_result(9)]},
        )

        self.assertIn('data-scan-url="/scans/9"', markup)
        self.assertNotIn('/batches/51', markup)

    def test_scan_result_renders_archive_members_inside_container_scan(self) -> None:
        container_scan = make_scan(9, batch_id=51, scan_role="container", relative_path="bundle.zip")
        child_scan = make_scan(
            10,
            batch_id=51,
            parent_scan_id=9,
            scan_role="child",
            relative_path="docs/readme.txt",
        )
        with patch("app.main.get_worker_status", return_value={"online": True}), patch(
            "app.main.list_scan_batch_scans",
            return_value=[container_scan, child_scan],
        ), patch(
            "app.main.list_engine_results_by_scan_ids",
            return_value={10: [make_result(10, detected=True)]},
        ):
            markup = render_scan_result(
                container_scan,
                [make_result(9)],
                make_user(),
            )

        self.assertIn("Archive contents", markup)
        self.assertIn("docs/readme.txt", markup)
        self.assertIn('/scans/10', markup)
        self.assertNotIn('/batches/51', markup)

    def test_scan_result_refreshes_when_malicious_archive_children_are_pending(self) -> None:
        container_scan = make_scan(
            11,
            batch_id=61,
            scan_role="container",
            relative_path="eicar_zip.zip",
            verdict="critical",
            risk_score=90,
            completed_at="2099-07-07 10:52:30+00:00",
        )
        with patch("app.main.get_worker_status", return_value={"online": True}), patch(
            "app.main.list_scan_batch_scans",
            return_value=[container_scan],
        ):
            markup = render_scan_result(
                container_scan,
                [make_result(11, detected=True)],
                make_user(),
            )

        self.assertIn("Archive contents pending", markup)
        self.assertIn("This page will refresh automatically", markup)
        self.assertIn('<meta http-equiv="refresh" content="5">', markup)


def make_scan(
    scan_id: int,
    *,
    batch_id: int | None = None,
    parent_scan_id: int | None = None,
    scan_role: str = "standalone",
    relative_path: str | None = None,
    verdict: str = "undetected",
    risk_score: int | None = 0,
    completed_at: str = "2026-07-04 00:00:02",
) -> ScanRecord:
    return ScanRecord(
        id=scan_id,
        sample_id=scan_id,
        case_name=f"Case {scan_id}",
        priority="Normal",
        note="",
        source="manual",
        status="completed",
        verdict=verdict,
        risk_score=risk_score,
        created_at="2026-07-04 00:00:00",
        started_at="2026-07-04 00:00:01",
        completed_at=completed_at,
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
        batch_id=batch_id,
        parent_scan_id=parent_scan_id,
        relative_path=relative_path,
        scan_role=scan_role,
    )


def make_result(scan_id: int, detected: bool = False) -> EngineResultRecord:
    return EngineResultRecord(
        id=scan_id,
        scan_job_id=scan_id,
        engine_name="ClamAV",
        engine_version="test",
        signature_version=None,
        status="completed",
        detected=detected,
        signature="EICAR-Test-File" if detected else None,
        severity="high" if detected else "info",
        confidence=90 if detected else 100,
        raw_output="ok",
        error_message=None,
        duration_ms=10,
        created_at="2026-07-04 00:00:02",
        details_json="{}",
        findings_json="[]",
    )


def make_user() -> UserRecord:
    return UserRecord(
        id=1,
        username="admin",
        password_hash="hash",
        role="admin",
        created_at="2026-07-04 00:00:00",
        updated_at="2026-07-04 00:00:00",
    )


if __name__ == "__main__":
    unittest.main()
