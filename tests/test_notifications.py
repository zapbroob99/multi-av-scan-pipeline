"""The console notification bell: recent detections and each operator's read marker."""
import os
import unittest
from unittest.mock import MagicMock, patch

from app import database as db
from app.models import StoredSample
from app.services import audit, auth, notification_read
from tests import test_ui_api as browser


class NotificationTests(unittest.TestCase):
    setUp = browser.BrowserApiTests.setUp
    tearDown = browser.BrowserApiTests.tearDown
    request = browser.BrowserApiTests.request

    def scan(self, name: str, *, verdict: str = "high", completed_at: str = "2026-10-05 10:00:00",
             status: str = "completed", role: str = "standalone", source: str = "manual", relative_path=None) -> int:
        sample = db.create_sample(StoredSample(name, name, f"/tmp/{name}", "application/octet-stream", 1,
                                               "0" * 32, "0" * 40, "1" * 64))
        scan_id = db.create_scan_job(sample, case_name="C", priority="Normal", note="", source=source,
                                     scan_role=role, relative_path=relative_path)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET status = ?, verdict = ?, risk_score = 70, completed_at = ? WHERE id = ?",
                               (status, verdict, completed_at, scan_id))
        return scan_id

    def read(self):
        status, body, _ = self.request("/notifications")
        self.assertEqual(status, 200, body)
        return body

    def test_only_recorded_detections_are_listed_newest_completion_first(self):
        self.assertEqual(self.request("/notifications", session=False)[0], 401)
        self.assertEqual(self.read(), {"detections": [], "unread": 0, "unread_capped": False, "cleared": False})
        long_running = self.scan("slow.exe", completed_at="2026-10-05 12:00:00")
        early = self.scan("early.exe", verdict="critical", completed_at="2026-10-05 09:00:00")
        self.scan("clean.txt", verdict="info")
        self.scan("failed.bin", status="failed")
        member = self.scan("payload.exe", role="child", source="icap", relative_path="bundle.zip/payload.exe",
                           completed_at="2026-10-05 11:00:00")
        body = self.read()
        self.assertEqual([item["scan_id"] for item in body["detections"]], [long_running, member, early])
        self.assertEqual(body["unread"], 3)
        self.assertTrue(all(item["unread"] for item in body["detections"]))
        archive = body["detections"][1]
        self.assertEqual((archive["filename"], archive["archive_member"], archive["source"]),
                         ("bundle.zip/payload.exe", True, "icap"))

    def test_the_marker_covers_what_was_shown_and_never_moves_back(self):
        first = self.scan("a.exe", completed_at="2026-10-05 09:00:00")
        newest = self.scan("b.exe", completed_at="2026-10-05 10:00:00")
        self.assertEqual(self.request("/notifications/read", "POST", {"through_scan_id": newest}, csrf=False)[0], 403)
        self.assertEqual(self.request("/notifications/read", "POST", {"through_scan_id": newest})[0], 204)
        self.assertEqual(self.read()["unread"], 0)
        # A scan created earlier but completing after the marker is still new.
        late = self.scan("c.exe", completed_at="2026-10-05 11:00:00")
        body = self.read()
        self.assertEqual(body["unread"], 1)
        self.assertEqual([item["unread"] for item in body["detections"]], [True, False, False])
        self.assertEqual(self.request("/notifications/read", "POST", {"through_scan_id": first})[0], 204)
        self.assertEqual(self.read()["unread"], 1)
        self.assertEqual(self.request("/notifications/read", "POST", {"through_scan_id": late})[0], 204)
        self.assertEqual(self.read()["unread"], 0)

    def test_clearing_removes_what_was_shown_reads_it_and_never_brings_it_back(self):
        old = self.scan("old.exe", completed_at="2026-10-05 09:00:00")
        shown = self.scan("shown.exe", completed_at="2026-10-05 10:00:00")
        self.assertEqual(self.request("/notifications/clear", "POST", {"through_scan_id": shown}, csrf=False)[0], 403)
        self.assertEqual(self.request("/notifications/clear", "POST", {"through_scan_id": shown})[0], 204)
        self.assertEqual(self.read(), {"detections": [], "unread": 0, "unread_capped": False, "cleared": True})
        later = self.scan("later.exe", completed_at="2026-10-05 11:00:00")
        body = self.read()
        self.assertEqual(([item["scan_id"] for item in body["detections"]], body["unread"]), ([later], 1))
        # Reading keeps a detection listed but greyed; an older clear changes nothing.
        self.assertEqual(self.request("/notifications/read", "POST", {"through_scan_id": later})[0], 204)
        self.assertEqual(self.request("/notifications/clear", "POST", {"through_scan_id": old})[0], 204)
        body = self.read()
        self.assertEqual([(item["scan_id"], item["unread"]) for item in body["detections"]], [(later, False)])
        self.assertEqual(body["unread"], 0)
        # The scans themselves are untouched.
        self.assertEqual(db.get_scan(shown).verdict, "high")

    def test_the_marker_is_per_operator_and_refuses_anything_but_a_detection(self):
        detection = self.scan("a.exe")
        clean = self.scan("b.txt", verdict="info")
        self.assertEqual(self.request("/notifications/read", "POST", {"through_scan_id": clean})[0], 404)
        self.assertEqual(self.request("/notifications/read", "POST", {"through_scan_id": 999})[0], 404)
        self.assertEqual(self.request("/notifications/read", "POST", {"through_scan_id": "1"})[0], 422)
        self.assertEqual(self.request("/notifications/read", "POST", {"through_scan_id": detection, "all": True})[0], 422)
        self.assertEqual(self.request("/notifications/read", "POST", {"through_scan_id": detection})[0], 204)
        analyst = db.create_user("browser-analyst", auth.hash_password("test-password"), "analyst")
        self.token = "synthetic-analyst-session"
        db.create_auth_session(user_id=analyst, token_hash=auth.hash_session_token(self.token), expires_at=2**40)
        self.assertEqual(self.read()["unread"], 1)

    def test_the_unread_count_is_bounded(self):
        for index in range(4):
            self.scan(f"{index}.exe", completed_at=f"2026-10-05 10:0{index}:00")
        with patch.object(notification_read, "UNREAD_CAP", 2), patch.object(notification_read, "PAGE_SIZE", 3):
            body = self.read()
        self.assertEqual((body["unread"], body["unread_capped"], len(body["detections"])), (2, True, 3))

    def test_marking_read_is_not_an_audited_change(self):
        request = MagicMock(method="POST")
        for path in ("/api/ui/v1/notifications/read", "/api/ui/v1/notifications/clear"):
            request.url.path = path
            self.assertFalse(audit.should_audit_request(request))
        request.url.path = "/api/ui/v1/hash-list"
        self.assertTrue(audit.should_audit_request(request))


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class NotificationPostgresTests(unittest.TestCase):
    def test_the_detection_feed_and_marker_work_on_postgres(self):
        import psycopg
        from datetime import datetime, timezone
        original = db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED
        db.close_pool()
        db.DATABASE_URL, db.DB_POOL_ENABLED = os.environ["MASP_TEST_POSTGRES_URL"], False
        try:
            with psycopg.connect(db.DATABASE_URL, autocommit=True) as connection:
                connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
                connection.execute("CREATE SCHEMA public")
            db.init_db()
            user = db.create_user("pg-admin", auth.hash_password("test-password"), "admin")
            ids = []
            for hour in (9, 10):
                sample = db.create_sample(StoredSample(f"{hour}.exe", f"{hour}.exe", "/tmp/x", "application/octet-stream",
                                                       1, "0" * 32, "0" * 40, "1" * 64))
                scan_id = db.create_scan_job(sample, case_name="C", priority="Normal", note="", source="api")
                with db.connect() as connection:
                    connection.execute("UPDATE scan_jobs SET status = 'completed', verdict = 'critical', completed_at = ? WHERE id = ?",
                                       (datetime(2026, 10, 5, hour, tzinfo=timezone.utc), scan_id))
                ids.append(scan_id)
            self.assertEqual(notification_read.read(user).unread, 2)
            notification_read.mark_read(user, notification_read.ThroughDetection(through_scan_id=ids[0]))
            body = notification_read.read(user)
            self.assertEqual((body.unread, [item.unread for item in body.detections]), (1, [True, False]))
            notification_read.clear(user, notification_read.ThroughDetection(through_scan_id=ids[0]))
            body = notification_read.read(user)
            self.assertEqual(([item.scan_id for item in body.detections], body.unread), ([ids[1]], 1))
        finally:
            db.close_pool()
            db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = original


if __name__ == "__main__":
    unittest.main()
