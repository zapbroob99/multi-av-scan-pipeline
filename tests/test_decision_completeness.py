"""A check a rule chose that did not complete is never a check that found nothing.

Every path that answers for a scan (the decision, the console report, the ICAP
gateway and the public result contract) must give the same answer.
"""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import app.main  # noqa: F401  (startup runs once here, not in the middle of a test)
from app import database as db
from app.icap.server import resolve_icap_action
from app.models import EngineResultInput
from app.services import archive_extractor, automation_payload, scan_report_read
from app.services.api_schemas import DecisionPayload
from app.services.ingest import store_bytes
from app.services.scan_assessment import resolve_scan_decision
from app.services.service_clients import (
    hash_api_token, identity_for_service_client_key, profile_snapshot_json, resolve_profile_routing,
)

TEXT = b"plain text for the completeness checks"


class DecisionCompletenessTests(unittest.TestCase):
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
        db.DB_PATH = root / "completeness.db"
        db.DATABASE_URL = os.environ["MASP_TEST_POSTGRES_URL"] if self.postgres else ""
        db.DB_POOL_ENABLED = False
        if self.postgres:
            import psycopg
            with psycopg.connect(db.DATABASE_URL, autocommit=True) as connection:
                connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
                connection.execute("CREATE SCHEMA public")
        db.init_db()
        self.addCleanup(self.restore)
        self.file_type = db.create_engine_instance("file_type", "File Type")
        self.hash_list = db.create_engine_instance("hash_list", "Hash List")
        self.clamav = db.create_engine_instance("clamav", "ClamAV")
        light = [{"action": "light", "engines": [self.file_type, self.hash_list]}]
        self.make_client("light-block", light, "block")
        self.make_client("light-allow", light, "allow")
        self.make_client("scan-block", [{"action": "scan", "engines": [self.clamav, self.hash_list], "archive": "whole"}], "block")

    def restore(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def make_client(self, key, rules, inconclusive):
        engines = sorted({engine for rule in rules for engine in rule["engines"]})
        db.create_service_client_bundle(
            client_key=key, display_name=key, profile_name="Standard", engine_instance_ids=engines,
            credential_label="Test", token_hash=hash_api_token(f"synthetic-{key}-token-" + "x" * 40),
            token_prefix="synthetic",
            policy_json=json.dumps({"version": 2, "inconclusive": inconclusive, "rules": rules}))

    def scan(self, key, results, *, verdict="info", score=0):
        from app.services.scan_intake import enqueue_scan_from_stored_sample
        identity, engines = resolve_profile_routing(identity_for_service_client_key(key), source="icap")
        scan = enqueue_scan_from_stored_sample(
            store_bytes("note.txt", "text/plain", TEXT), case_name="T", priority="Normal", note="",
            source="icap", engines=engines, service_client_id=identity.client.id,
            scan_profile_id=identity.profile.id, profile_snapshot_json=profile_snapshot_json(identity, engines))
        for name, status, result_verdict, result_score in results:
            db.create_engine_result(scan.id, EngineResultInput(name, status, False, result_verdict, result_score, None,
                                                               "", 1, error_message="unavailable" if status != "completed" else None))
        self.assertTrue(db.transition_scan_to_completed(scan.id, verdict, score))
        return db.get_scan(scan.id)

    def answers(self, scan):
        """The decision as each consumer sees it: core, console report, ICAP and public result."""
        decision = resolve_scan_decision(scan)
        report = scan_report_read.report(scan.id, automation=True)
        icap, _, _ = resolve_icap_action(scan, SimpleNamespace(fail_closed=True, block_on_review=True))
        content = json.loads(automation_payload.result_preview(scan.id, "http://masp.test").content)
        self.assertEqual(report.decision.policy, decision.policy)
        self.assertEqual(content["decision"]["policy"], decision.policy)
        self.assertEqual(content["decision"]["action"], decision.action)
        self.assertEqual(icap, decision.action)
        return decision

    def test_a_failed_hash_list_lookup_is_inconclusive_not_a_passed_light_check(self):
        failed = [("File Type", "completed", "info", 0), ("Hash List", "failed", "info", 0)]
        blocked = self.answers(self.scan("light-block", failed))
        self.assertEqual((blocked.action, blocked.policy), ("block", "profile_inconclusive_block"))
        self.assertIn("Not every check of rule 1 completed: Hash List failed.", blocked.reasons)
        allowed = self.answers(self.scan("light-allow", failed))
        self.assertEqual((allowed.action, allowed.label), ("allow", "Allow (not fully scanned)"))
        self.assertNotIn("found nothing", allowed.reason)

    def test_a_check_with_no_result_counts_as_missing(self):
        decision = self.answers(self.scan("light-block", [("File Type", "completed", "info", 0)]))
        self.assertEqual(decision.policy, "profile_inconclusive_block")
        self.assertIn("Not every check of rule 1 completed: Hash List missing.", decision.reasons)

    def test_a_complete_light_check_that_found_nothing_still_allows(self):
        clean = [("File Type", "completed", "info", 0), ("Hash List", "completed", "info", 0)]
        decision = self.answers(self.scan("light-block", clean))
        self.assertEqual((decision.action, decision.policy), ("allow", "profile_rule_light_check"))

    def test_a_light_check_finding_is_never_reported_as_finding_nothing(self):
        # A disguised non-program file is a medium finding without a detection.
        finding = [("File Type", "completed", "medium", 40), ("Hash List", "completed", "info", 0)]
        decision = self.answers(self.scan("light-block", finding, verdict="medium", score=40))
        self.assertEqual((decision.action, decision.policy), ("block", "profile_inconclusive_block"))
        self.assertIn("Risk score is 40/100 with verdict medium.", decision.reasons)

    def test_a_failed_auxiliary_check_on_a_scan_rule_is_inconclusive(self):
        results = [("ClamAV", "completed", "info", 0), ("Hash List", "failed", "info", 0)]
        decision = self.answers(self.scan("scan-block", results))
        self.assertEqual((decision.action, decision.policy), ("block", "profile_inconclusive_block"))
        self.assertIn("Not every check of rule 1 completed: Hash List failed.", decision.reasons)
        clean = [("ClamAV", "completed", "info", 0), ("Hash List", "completed", "info", 0)]
        self.assertEqual(self.answers(self.scan("scan-block", clean)).action, "allow")

    def test_the_public_contract_names_every_rule_and_exception_policy(self):
        for policy in ("profile_rule_block", "profile_rule_not_scanned", "profile_rule_light_check",
                       "profile_inconclusive_block", "profile_inconclusive_allow", "exception_allow"):
            DecisionPayload(action="allow", label="x", tone="warning", confidence="low", policy=policy, reason="r", reasons=[])


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class PostgresDecisionCompletenessTests(DecisionCompletenessTests):
    postgres = True


if __name__ == "__main__":
    unittest.main()
