"""MASP's own memory of a file: kept as scans settle, never a verdict, never mixed with reputation."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

import app.main  # noqa: F401  (startup runs once here, not in the middle of a test)
from app import database as db
from app.models import EngineResultInput
from app.services import archive_extractor, file_history, scan_exceptions
from app.services.ingest import store_bytes
from app.services.service_clients import (
    hash_api_token, identity_for_service_client_key, profile_snapshot_json, resolve_profile_routing,
)

TEXT = b"file history test text"
EXE = b"MZ" + b"\0" * 120


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class FileHistoryTests(unittest.TestCase):
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
        db.DB_PATH = root / "history.db"
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
        client, _, _ = db.create_service_client_bundle(
            client_key="gate", display_name="Gate", profile_name="Standard", engine_instance_ids=[self.clamav],
            credential_label="Test", token_hash=hash_api_token("synthetic-gate-token-" + "x" * 40),
            token_prefix="synthetic", policy_json=json.dumps(rules))
        self.client = client

    def restore(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def enqueue(self, content, name="sample.txt"):
        from app.services.scan_intake import enqueue_scan_from_stored_sample
        identity, engines = resolve_profile_routing(identity_for_service_client_key("gate"), source="icap")
        return enqueue_scan_from_stored_sample(
            store_bytes(name, "application/octet-stream", content), case_name="T", priority="Normal", note="",
            source="icap", engines=engines, service_client_id=identity.client.id,
            scan_profile_id=identity.profile.id, profile_snapshot_json=profile_snapshot_json(identity, engines))

    def finish(self, scan_id, *, detected, status="completed", signature_version="27771"):
        verdict, score = ("critical", 90) if detected else ("info", 0)
        db.create_engine_result(scan_id, EngineResultInput(
            "ClamAV", status, detected, verdict if status == "completed" else "info", score, "Eicar-Test" if detected else None,
            "", 1, engine_version="1.4.2", signature_version=signature_version))
        failure = None if status == "completed" else "No engine completed a scan (ClamAV failed)."
        self.assertTrue(db.transition_scan_to_completed(scan_id, verdict, score, failure=failure))

    def facts(self, content):
        with db.connect() as connection:
            return file_history.facts(connection, sha256(content))

    def test_an_unseen_file_is_reported_as_unseen(self):
        found = self.facts(TEXT)
        self.assertEqual((found.seen, found.scan_count, found.last_engines), (False, 0, []))

    def test_settled_scans_build_the_files_history(self):
        first = self.enqueue(TEXT)
        self.finish(first.id, detected=True)
        found = self.facts(TEXT)
        self.assertEqual((found.seen, found.scan_count, found.detected_count, found.last_verdict), (True, 1, 1, "critical"))
        self.assertIsNotNone(found.last_detected_at)
        engine = found.last_engines[0]
        self.assertEqual((engine.engine_name, engine.detected, engine.signature, engine.engine_version, engine.signature_version),
                         ("ClamAV", True, "Eicar-Test", "1.4.2", "27771"))
        # Seen again later, clean: the count grows, the latest outcome changes, the detection is remembered.
        second = self.enqueue(TEXT, "again.txt")
        self.finish(second.id, detected=False)
        found = self.facts(TEXT)
        self.assertEqual((found.scan_count, found.detected_count, found.last_verdict), (2, 1, "info"))
        self.assertFalse(found.last_engines[0].detected)
        self.assertIsNotNone(found.last_detected_at)
        self.assertGreaterEqual(found.last_seen_at, found.first_seen_at)

    def test_a_retried_scan_is_not_counted_twice(self):
        scan = self.enqueue(TEXT)
        self.finish(scan.id, detected=True)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET status = 'queued' WHERE id = ?", (scan.id,))
            connection.execute("DELETE FROM engine_results WHERE scan_job_id = ?", (scan.id,))
        self.finish(scan.id, detected=False)
        found = self.facts(TEXT)
        self.assertEqual((found.scan_count, found.detected_count, found.last_verdict), (1, 1, "info"))

    def test_failed_and_rule_decided_scans_are_seen_too(self):
        failed = self.enqueue(TEXT)
        self.finish(failed.id, detected=False, status="failed")
        found = self.facts(TEXT)
        self.assertEqual((found.seen, found.last_status, found.detected_count), (True, "failed", 0))
        # The profile blocks programs at intake: no engine runs, but the file was seen.
        self.enqueue(EXE, "tool.exe")
        blocked = self.facts(EXE)
        self.assertEqual((blocked.seen, blocked.last_rule_action, blocked.last_not_allowed, blocked.last_engines),
                         (True, "block", "rule_block", []))
        page = file_history.read(sha256(EXE))
        self.assertTrue(page.last_not_allowed_label)
        self.assertEqual(page.recent_scans[0].not_allowed_label, page.last_not_allowed_label)

    def test_history_outlives_the_scans_and_holds_no_file_name(self):
        scan = self.enqueue(TEXT, "secret-name.txt")
        self.finish(scan.id, detected=True)
        with db.connect() as connection:
            connection.execute("DELETE FROM engine_results WHERE scan_job_id = ?", (scan.id,))
            connection.execute("DELETE FROM scan_jobs WHERE id = ?", (scan.id,))
            row = connection.execute("SELECT * FROM file_history WHERE sha256 = ?", (sha256(TEXT),)).fetchone()
        self.assertNotIn("secret-name", json.dumps(dict(row)))
        page = file_history.read(sha256(TEXT))
        self.assertEqual((page.seen, page.scan_count, page.detected_count, page.recent_scans), (True, 1, 1, []))
        self.assertEqual(page.last_engines[0].signature, "Eicar-Test")

    def test_paths_never_leave_as_versions(self):
        scan = self.enqueue(TEXT)
        self.finish(scan.id, detected=False, signature_version="/app/rules")
        self.assertIsNone(self.facts(TEXT).last_engines[0].signature_version)

    def test_existing_scans_are_carried_in_once(self):
        first, second = self.enqueue(TEXT), self.enqueue(TEXT, "b.txt")
        self.finish(first.id, detected=True)
        self.finish(second.id, detected=False)
        with db.connect() as connection:
            connection.execute("DELETE FROM file_history")
            file_history.backfill(connection)
            found = file_history.facts(connection, sha256(TEXT))
            # A second start finds rows already there and adds nothing.
            file_history.backfill(connection)
            rows = connection.execute("SELECT COUNT(*) AS n FROM file_history").fetchone()["n"]
        self.assertEqual((found.scan_count, found.detected_count, found.last_verdict, rows), (2, 1, "info", 1))
        self.assertEqual(found.last_engines[0].engine_name, "ClamAV")

    def test_the_file_page_joins_lists_exceptions_and_recent_scans(self):
        scan = self.enqueue(TEXT, "report.txt")
        self.finish(scan.id, detected=True)
        db.add_hash_list_entries([(sha256(TEXT), "block", "known bad")], "admin")
        scan_exceptions.create(scan_exceptions.ExceptionCreate(sha256=sha256(TEXT), service_client_id=self.client,
                                                               reason="Vendor tool"), "admin")
        page = file_history.read(sha256(TEXT).upper())
        self.assertEqual((page.sha256, page.hash_list), (sha256(TEXT), "block"))
        self.assertEqual([(e.scope, e.reason) for e in page.exceptions], [(f"#{self.client} Gate", "Vendor tool")])
        self.assertEqual([(s.id, s.source, s.filename, s.client_name) for s in page.recent_scans],
                         [(scan.id, "icap", "report.txt", "Gate")])
        with self.assertRaises(HTTPException) as refused:
            file_history.read("not-a-hash")
        self.assertEqual(refused.exception.status_code, 422)

    def reputation(self, scan_id, *, detected):
        db.create_engine_result(scan_id, EngineResultInput(
            "VirusTotal", "completed", detected, "critical" if detected else "info", 90 if detected else 0,
            "65/70 engines" if detected else None, "", 1))

    def test_external_reputation_never_enters_the_history(self):
        self.assertIn("virustotal", file_history.external_adapter_keys())
        db.create_engine_instance("virustotal", "VirusTotal")
        mixed = self.enqueue(TEXT)
        self.reputation(mixed.id, detected=True)
        # The scan's own verdict includes the provider; the history keeps only what ClamAV said.
        self.finish(mixed.id, detected=False)
        found = self.facts(TEXT)
        self.assertEqual((found.scan_count, found.detected_count, found.last_detected_at, found.last_verdict, found.last_risk_score),
                         (1, 0, None, "info", 0))
        self.assertEqual([engine.engine_name for engine in found.last_engines], ["ClamAV"])
        # A scan only a provider answered does not make the file seen.
        only = self.enqueue(b"reputation only text", "only.bin")
        self.reputation(only.id, detected=True)
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET status = 'running' WHERE id = ?", (only.id,))
        self.assertTrue(db.transition_scan_to_completed(only.id, "critical", 90))
        self.assertFalse(self.facts(b"reputation only text").seen)
        # Carrying older scans in follows the same rule.
        with db.connect() as connection:
            connection.execute("DELETE FROM file_history")
            file_history.backfill(connection)
            again = file_history.facts(connection, sha256(TEXT))
            other = file_history.facts(connection, sha256(b"reputation only text"))
        self.assertEqual((again.detected_count, again.last_verdict, other.seen), (0, "info", False))
        self.assertEqual([engine.engine_name for engine in again.last_engines], ["ClamAV"])

    def test_the_integration_view_carries_facts_only(self):
        scan = self.enqueue(TEXT, "report.txt")
        self.finish(scan.id, detected=True)
        shared = file_history.public(sha256(TEXT))
        self.assertEqual((shared["seen"], shared["scan_count"], shared["last_verdict"]), (True, 1, "critical"))
        self.assertTrue(shared["first_seen_at"].endswith("Z"))
        self.assertNotIn("report.txt", json.dumps(shared))
        self.assertNotIn("Gate", json.dumps(shared))
        from app.services.api_schemas import MaspHistoryPayload
        MaspHistoryPayload.model_validate(shared)
        MaspHistoryPayload.model_validate(file_history.public(sha256(b"never seen")))


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class PostgresFileHistoryTests(FileHistoryTests):
    postgres = True


if __name__ == "__main__":
    unittest.main()
