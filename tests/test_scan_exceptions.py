"""Exceptions let one exact file through, whatever found it, and nothing else."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from pydantic import ValidationError

import app.main  # noqa: F401  (startup runs once here, not in the middle of a test)
from app import database as db
from app.models import EngineResultInput
from app.services import archive_extractor, ledger_read, notification_read, scan_exceptions
from app.services.ingest import store_bytes
from app.services.scan_assessment import resolve_scan_decision
from app.services.service_clients import (
    hash_api_token, identity_for_service_client_key, profile_snapshot_json, resolve_profile_routing,
)

EXE = b"MZ" + b"\0" * 120
TEXT = b"harmless exception test text"


def sha256(content: bytes) -> str:
    import hashlib
    return hashlib.sha256(content).hexdigest()


class ExceptionTests(unittest.TestCase):
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
        db.DB_PATH = root / "exceptions.db"
        db.DATABASE_URL = os.environ["MASP_TEST_POSTGRES_URL"] if self.postgres else ""
        db.DB_POOL_ENABLED = False
        if self.postgres:
            import psycopg
            with psycopg.connect(db.DATABASE_URL, autocommit=True) as connection:
                connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
                connection.execute("CREATE SCHEMA public")
        db.init_db()
        self.addCleanup(self.restore)
        self.clamav = db.create_engine_instance("clamav", "ClamAV")
        rules = {"version": 2, "inconclusive": "block", "rules": [
            {"when": {"families": ["executable"]}, "action": "block"},
            {"action": "scan", "engines": [self.clamav], "archive": "whole"}]}
        self.client = self.make_client("gate", rules)
        self.other = self.make_client("other", rules)
        self.user = db.create_user("exception-admin", "x", "admin")

    def restore(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def make_client(self, key, rules):
        client, _, _ = db.create_service_client_bundle(
            client_key=key, display_name=key.title(), profile_name="Standard", engine_instance_ids=[self.clamav],
            credential_label="Test", token_hash=hash_api_token(f"synthetic-{key}-token-" + "x" * 40),
            token_prefix="synthetic", policy_json=json.dumps(rules))
        return client

    def except_file(self, content, *, client=None, days=None, reason="Known good installer"):
        return scan_exceptions.create(scan_exceptions.ExceptionCreate(
            sha256=sha256(content), service_client_id=client, reason=reason, expires_in_days=days), "admin")

    def enqueue(self, content, name, *, key="gate", security_events=False):
        from app.services.scan_intake import enqueue_scan_from_stored_sample
        identity, engines = resolve_profile_routing(identity_for_service_client_key(key), source="icap")
        routing = profile_snapshot_json(identity, engines,
                                        delivery_mode="security_events_only" if security_events else None,
                                        client_request_id="request-1" if security_events else None)
        return enqueue_scan_from_stored_sample(
            store_bytes(name, "application/octet-stream", content), case_name="T", priority="Normal", note="",
            source="icap", engines=engines, service_client_id=identity.client.id,
            scan_profile_id=identity.profile.id, profile_snapshot_json=routing)

    def complete(self, scan_id, *, detected):
        verdict, score = ("critical", 90) if detected else ("info", 0)
        db.create_engine_result(scan_id, EngineResultInput("ClamAV", "completed", detected, verdict, score,
                                                           "Eicar-Test" if detected else None, "", 1))
        self.assertTrue(db.transition_scan_to_completed(scan_id, verdict, score))

    def test_an_exception_needs_a_full_digest_and_a_reason(self):
        with self.assertRaisesRegex(ValidationError, "full SHA-256"):
            scan_exceptions.ExceptionCreate(sha256="ab" * 31, reason="x")
        with self.assertRaisesRegex(ValidationError, "reason"):
            scan_exceptions.ExceptionCreate(sha256="a" * 64, reason="   ")
        created = scan_exceptions.ExceptionCreate(sha256=" " + "A" * 64 + " ", reason="  Known   good ")
        self.assertEqual((created.sha256, created.reason), ("a" * 64, "Known good"))

    def test_an_exception_lets_a_rule_blocked_file_through_and_records_why(self):
        exception = self.except_file(EXE)
        scan = self.enqueue(EXE, "tool.exe")
        decision = resolve_scan_decision(db.get_scan(scan.id))
        self.assertEqual((decision.action, decision.policy, decision.label), ("allow", "exception_allow", "Allow (exception)"))
        self.assertIn(f"Allowed by exception #{exception}: Known good installer", decision.reason)
        self.assertIn("Without the exception: Block", decision.reasons[-1])
        item = next(row for row in ledger_read.page(limit=20, before=None, query="", source="all", status="all", risk="all",
                                                    client_id=None, unassigned=False).items if row.id == scan.id)
        self.assertEqual((item.exception_id, item.not_allowed), (exception, None))

    def test_an_exception_suppresses_an_engine_detection_in_the_decision_bell_and_siem(self):
        self.except_file(TEXT)
        scan = self.enqueue(TEXT, "flagged.txt", security_events=True)
        self.complete(scan.id, detected=True)
        decision = resolve_scan_decision(db.get_scan(scan.id))
        self.assertEqual((decision.action, decision.policy), ("allow", "exception_allow"))
        # The engine result stays recorded as evidence.
        self.assertEqual(db.get_scan(scan.id).verdict, "critical")
        self.assertEqual(notification_read.read(self.user).detections, [])
        with db.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) AS n FROM notification_outbox").fetchone()["n"], 0)
        # Without an exception the same detection reaches both.
        plain = self.enqueue(TEXT + b"!", "other.txt", security_events=True)
        self.complete(plain.id, detected=True)
        self.assertEqual([item.scan_id for item in notification_read.read(self.user).detections], [plain.id])

    def test_scope_expiry_and_revocation(self):
        mine = self.except_file(EXE, client=self.client)
        self.assertIsNotNone(json.loads(self.enqueue(EXE, "a.exe").profile_snapshot_json).get("exception"))
        self.assertIsNone(json.loads(self.enqueue(EXE, "b.exe", key="other").profile_snapshot_json).get("exception"))
        accepted = self.enqueue(EXE, "c.exe")
        self.assertTrue(scan_exceptions.revoke(mine, "admin"))
        self.assertFalse(scan_exceptions.revoke(mine, "admin"))
        self.assertIsNone(json.loads(self.enqueue(EXE, "d.exe").profile_snapshot_json).get("exception"))
        # A scan accepted under the exception keeps its decision after revocation.
        self.assertEqual(resolve_scan_decision(db.get_scan(accepted.id)).policy, "exception_allow")
        expired = self.except_file(EXE, days=1)
        with db.connect() as connection:
            connection.execute("UPDATE scan_exceptions SET expires_at = ? WHERE id = ?", (int(time.time()) - 1, expired))
        self.assertIsNone(json.loads(self.enqueue(EXE, "e.exe").profile_snapshot_json).get("exception"))
        states = {item.id: item.state for item in scan_exceptions.page(limit=20, before=None, state="all", query="").items}
        self.assertEqual(states, {mine: "revoked", expired: "expired"})
        uses = {item.id: item.uses for item in scan_exceptions.page(limit=20, before=None, state="all", query="").items}
        self.assertEqual(uses[mine], 2)

    def test_a_client_exception_wins_over_a_global_one_and_members_never_inherit(self):
        global_one = self.except_file(EXE, reason="Everyone")
        client_one = self.except_file(EXE, client=self.client, reason="This client")
        recorded = json.loads(self.enqueue(EXE, "a.exe").profile_snapshot_json)["exception"]
        self.assertEqual((recorded["id"], recorded["scope"]), (client_one, "client"))
        self.assertEqual(json.loads(self.enqueue(EXE, "b.exe", key="other").profile_snapshot_json)["exception"]["id"], global_one)
        inherited = json.dumps({"exception": recorded, "engines": []})
        member, exception_id = scan_exceptions.attach(inherited, sha256=sha256(TEXT), client_id=self.client)
        self.assertEqual((json.loads(member), exception_id), ({"engines": []}, None))


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class PostgresExceptionTests(ExceptionTests):
    postgres = True


if __name__ == "__main__":
    unittest.main()
