"""Not allowed: one outcome for every file a client's rules refuse, kept apart from malware."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from app import database as db
from app.services import archive_extractor, ledger_read, notification_read, scan_report_read
from app.services.ingest import store_bytes
from app.services.profile_policy import (
    NOT_ALLOWED, PolicyRejectedError, apply_intake_policy, not_allowed_by_code, not_allowed_code,
)
from app.services.scan_assessment import resolve_scan_decision
from app.services.service_clients import (
    hash_api_token, identity_for_service_client_key, profile_snapshot_json, resolve_profile_routing,
)

def zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.txt", b"plain")
    return buffer.getvalue()


def snapshot(policy: dict | str) -> str:
    return json.dumps({"scan_profile": {"id": 1, "name": "Default", "policy": policy}})


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.archive = Path(self.temp.name) / "bundle.zip"
        self.archive.write_bytes(zip_bytes())
        self.text = Path(self.temp.name) / "notes.txt"
        self.text.write_bytes(b"plain")
        for target in (patch.object(archive_extractor, "STAGING_DIR", Path(self.temp.name) / "staging"),):
            target.start()
            self.addCleanup(target.stop)

    def judge(self, policy, path, **kwargs):
        return apply_intake_policy(snapshot(policy), filename=path.name, size=path.stat().st_size,
                                   storage_path=str(path), **kwargs)

    def test_the_gateway_archive_rule_is_an_intake_violation(self):
        stored = json.loads(self.judge({}, self.archive, refuse_archives=True))
        violation, = stored["intake_policy"]["violations"]
        self.assertEqual(violation["kind"], "archive_refused")
        self.assertEqual(not_allowed_code(json.dumps(stored)), "archive_refused")
        # Only archives, only when asked, only while the profile has no archive handling.
        raw = snapshot({})
        self.assertIs(apply_intake_policy(raw, filename="notes.txt", size=5, storage_path=str(self.text),
                                          refuse_archives=True), raw)
        self.assertIs(apply_intake_policy(raw, filename="bundle.zip", size=5, storage_path=str(self.archive)), raw)
        inspected = json.loads(self.judge({"archive_handling": "inspect"}, self.archive, refuse_archives=True))
        self.assertNotIn("intake_policy", inspected)

    def test_an_unreadable_policy_still_refuses_archives(self):
        stored = json.loads(self.judge({"archive_handling": "sometimes"}, self.archive, refuse_archives=True))
        self.assertEqual(stored["intake_policy"]["violations"][0]["kind"], "archive_refused")

    def test_reject_refuses_without_a_scan_and_names_the_outcome(self):
        with self.assertRaises(PolicyRejectedError) as error:
            self.judge({"violation_action": "reject"}, self.archive, refuse_archives=True)
        self.assertEqual(error.exception.not_allowed.code, "archive_refused")
        with self.assertRaises(PolicyRejectedError) as error:
            self.judge({"type_rule": {"mode": "denylist", "families": ["unrecognized"]}, "violation_action": "reject"},
                       self.text)
        self.assertEqual(error.exception.not_allowed.code, "content_type")

    def test_every_kind_has_one_code_label_and_message(self):
        for kind, entry in NOT_ALLOWED.items():
            with self.subTest(kind=kind):
                self.assertTrue(entry.code and entry.label)
                self.assertTrue(entry.message.startswith("Blocked by MASP: "))
                self.assertNotIn("malware", entry.message)
                self.assertIs(not_allowed_by_code(entry.code).code, entry.code)
        # A code written by a newer release still reads as refused, never as allowed.
        self.assertEqual(not_allowed_by_code("future_rule").code, "policy")
        self.assertIsNone(not_allowed_by_code(None))


class NotAllowedIntegrationTests(unittest.TestCase):
    postgres = False

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for target in (patch("app.services.ingest.SAMPLES_DIR", root / "samples"),
                       patch.object(archive_extractor, "STAGING_DIR", root / "staging")):
            target.start()
            self.addCleanup(target.stop)
        self.original = db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED
        db.close_pool()
        db.DB_PATH = root / "not-allowed.db"
        db.DATABASE_URL = os.environ["MASP_TEST_POSTGRES_URL"] if self.postgres else ""
        db.DB_POOL_ENABLED = False
        if self.postgres:
            import psycopg
            with psycopg.connect(db.DATABASE_URL, autocommit=True) as connection:
                connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
                connection.execute("CREATE SCHEMA public")
        db.init_db()
        self.addCleanup(self.restore)
        engine = db.create_engine_instance("clamav", "ClamAV")
        db.create_service_client_bundle(
            client_key="gate", display_name="Gate", profile_name="Standard", engine_instance_ids=[engine],
            credential_label="Test", token_hash=hash_api_token("synthetic-gate-token-" + "x" * 40),
            token_prefix="synthetic")
        self.user = db.create_user("not-allowed-admin", "x", "admin")

    def restore(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def enqueue(self, content: bytes, name: str, *, refuse_archives=False, security_events=False):
        from app.services.scan_intake import enqueue_scan_from_stored_sample
        identity, engines = resolve_profile_routing(identity_for_service_client_key("gate"), source="icap")
        routing = profile_snapshot_json(identity, engines,
                                        delivery_mode="security_events_only" if security_events else None,
                                        client_request_id="request-1" if security_events else None)
        return enqueue_scan_from_stored_sample(
            store_bytes(name, "application/octet-stream", content), case_name="T", priority="Normal", note="",
            source="icap", engines=engines, service_client_id=identity.client.id,
            scan_profile_id=identity.profile.id, profile_snapshot_json=routing, refuse_archives=refuse_archives)

    def complete_clean(self, scan_id: int) -> None:
        from app.models import EngineResultInput
        db.create_engine_result(scan_id, EngineResultInput("ClamAV", "completed", False, "info", 0, None, "", 1))
        self.assertTrue(db.transition_scan_to_completed(scan_id, "info", 0))

    def test_a_refused_archive_is_not_allowed_everywhere_but_never_malware(self):
        refused = self.enqueue(zip_bytes(), "bundle.zip", refuse_archives=True)
        allowed = self.enqueue(b"plain text", "notes.txt", refuse_archives=True)
        for scan in (refused, allowed):
            self.complete_clean(scan.id)
        decision = resolve_scan_decision(db.get_scan(refused.id))
        self.assertEqual((decision.action, decision.policy), ("block", "profile_archive_policy"))
        self.assertTrue(decision.reason.startswith("Not allowed: Archive files are not accepted"))
        self.assertEqual(resolve_scan_decision(db.get_scan(allowed.id)).action, "allow")
        # The engines' risk is untouched: not allowed is not a detection.
        self.assertEqual(db.get_scan(refused.id).verdict, "info")

        items = {item.id: item for item in ledger_read.page(limit=20, before=None, query="", source="all", status="all",
                                                            risk="all", client_id=None, unassigned=False).items}
        self.assertEqual((items[refused.id].not_allowed, items[refused.id].not_allowed_label), ("archive_refused", "Archive"))
        self.assertIsNone(items[allowed.id].not_allowed)
        filtered = ledger_read.page(limit=20, before=None, query="", source="all", status="all", risk="not_allowed",
                                    client_id=None, unassigned=False).items
        self.assertEqual([item.id for item in filtered], [refused.id])

        report = scan_report_read.report(refused.id, automation=True)
        self.assertEqual((report.not_allowed, report.not_allowed_label), ("archive_refused", "Archive"))
        self.assertEqual(report.decision.action, "block")
        # The bell lists detections only.
        self.assertEqual(notification_read.read(self.user).detections, [])

    def test_siem_receives_not_allowed_only_when_switched_on(self):
        def events():
            with db.connect() as connection:
                return [row["event_type"] for row in connection.execute(
                    "SELECT event_type FROM notification_outbox ORDER BY id").fetchall()]

        refused =self.enqueue(zip_bytes(), "one.zip", refuse_archives=True, security_events=True)
        self.complete_clean(refused.id)
        self.assertEqual(events(), [])
        db.set_setting(db.SIEM_NOT_ALLOWED_SETTING, "1")
        again = self.enqueue(zip_bytes(), "two.zip", refuse_archives=True, security_events=True)
        self.complete_clean(again.id)
        self.assertEqual(events(), ["policy.not_allowed"])
        with db.connect() as connection:
            payload = json.loads(connection.execute("SELECT payload_json FROM notification_outbox").fetchone()["payload_json"])
        self.assertEqual((payload["not_allowed"], payload["scan_id"]), ("archive_refused", again.id))
        self.assertIn("MASP_ICAP_BLOCK_ARCHIVES", payload["reasons"][0])
        # A scan without a security-events delivery sends nothing either way.
        quiet = self.enqueue(zip_bytes(), "three.zip", refuse_archives=True)
        self.complete_clean(quiet.id)
        self.assertEqual(len(events()), 1)

    def test_the_environment_switches_siem_on_when_no_override_is_saved(self):
        refused = self.enqueue(zip_bytes(), "one.zip", refuse_archives=True, security_events=True)
        with patch.dict(os.environ, {"MASP_SIEM_NOT_ALLOWED_EVENTS": "1"}):
            self.complete_clean(refused.id)
        with db.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) AS n FROM notification_outbox").fetchone()["n"], 1)


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class NotAllowedPostgresTests(NotAllowedIntegrationTests):
    postgres = True


if __name__ == "__main__":
    unittest.main()
