"""Profile rules: the first rule a file matches decides, and nothing is implicit."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

import app.main  # noqa: F401  (startup runs once here, not in the middle of a test)
from app import database as db
from app.models import EngineResultInput
from app.services import archive_extractor, ledger_read, profile_admin, profile_rules
from app.services.content_types import classify
from app.services.decisions import decide_scan_action
from app.services.ingest import store_bytes
from app.services.profile_policy import ProfilePolicy
from app.services.scan_assessment import resolve_scan_decision
from app.services.service_clients import (
    hash_api_token, identity_for_service_client_key, profile_snapshot_json, resolve_profile_routing,
)

MB = 1024 * 1024
EXE = b"MZ" + b"\0" * 120


def zip_bytes(**members: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in (members or {"a.txt": b"plain"}).items():
            archive.writestr(name, content)
    return buffer.getvalue()


def rules(*items, inconclusive="block") -> profile_rules.RulesPolicy:
    return profile_rules.RulesPolicy.model_validate({"version": 2, "rules": list(items), "inconclusive": inconclusive})


class RuleModelTests(unittest.TestCase):
    def test_only_the_last_rule_matches_every_file(self):
        with self.assertRaisesRegex(ValidationError, "last rule must match every file"):
            rules({"when": {"families": ["pdf"]}, "action": "scan", "engines": [1]})
        with self.assertRaisesRegex(ValidationError, "Only the last rule"):
            rules({"action": "block"}, {"action": "scan", "engines": [1], "archive": "whole"})

    def test_each_action_states_its_engines_and_archive_treatment(self):
        with self.assertRaisesRegex(ValidationError, "needs at least one engine"):
            rules({"action": "scan", "engines": [], "archive": "whole"})
        with self.assertRaisesRegex(ValidationError, "runs no engine"):
            rules({"when": {"masquerade": True}, "action": "block", "engines": [1]}, {"action": "light", "engines": [2]})
        with self.assertRaisesRegex(ValidationError, "how this rule treats archives"):
            rules({"action": "scan", "engines": [1]})
        # A rule that cannot match an archive does not choose an archive treatment.
        with self.assertRaisesRegex(ValidationError, "Only a Scan rule that can match archives"):
            rules({"when": {"families": ["pdf"]}, "action": "scan", "engines": [1], "archive": "whole"},
                  {"action": "light", "engines": [2]})
        with self.assertRaisesRegex(ValidationError, "at least one rule that runs an engine"):
            rules({"when": {"masquerade": True}, "action": "block"}, {"action": "allow"})
        with self.assertRaisesRegex(ValidationError, "upper size must be larger"):
            profile_rules.RuleWhen(larger_than_bytes=10, up_to_bytes=10)
        with self.assertRaisesRegex(ValidationError, "inconclusive"):
            profile_rules.RulesPolicy.model_validate({"version": 2, "rules": [{"action": "light", "engines": [2]}]})

    def test_the_first_matching_rule_wins(self):
        policy = rules({"when": {"larger_than_bytes": 500 * MB}, "action": "light", "engines": [2]},
                       {"when": {"larger_than_bytes": 50 * MB, "up_to_bytes": 500 * MB}, "action": "scan", "engines": [1],
                        "archive": "whole"},
                       {"when": {"families": ["executable"]}, "action": "block"},
                       {"when": {"masquerade": True}, "action": "block"},
                       {"action": "scan", "engines": [1, 3], "archive": "inspect"})
        program = classify(EXE, "tool.exe")
        disguised = classify(EXE, "report.pdf")
        text = classify(b"hello", "notes.txt")
        self.assertEqual(profile_rules.match(policy, size=600 * MB, classification=program)[0], 1)
        self.assertEqual(profile_rules.match(policy, size=500 * MB, classification=text)[0], 2)
        self.assertEqual(profile_rules.match(policy, size=50 * MB, classification=program)[0], 3)
        self.assertEqual(profile_rules.match(policy, size=1, classification=disguised)[0], 3)
        self.assertEqual(profile_rules.match(policy, size=1, classification=text)[0], 5)
        self.assertEqual(profile_rules.condition_text(policy.rules[1].when), "size 50 MB to 500 MB")


class PreviousPolicyConversionTests(unittest.TestCase):
    def convert(self, policy=None, *, icap=False, review=False, detection=frozenset({1})):
        return profile_rules.from_previous_policy(ProfilePolicy.model_validate(policy or {}), [1, 2],
                                                  detection_engine_ids=set(detection), receives_icap=icap,
                                                  gateway_blocks_review=review)

    def test_an_icap_client_keeps_what_its_gateway_did(self):
        converted = self.convert(icap=True)
        self.assertEqual([(rule.when.families, rule.action) for rule in converted.rules],
                         [(["archive"], "block"), ([], "scan")])
        self.assertEqual(converted.inconclusive, "allow")
        self.assertEqual(self.convert(icap=True, review=True).inconclusive, "block")

    def test_an_api_client_scans_archives_as_one_file_and_blocks_inconclusive(self):
        converted = self.convert()
        self.assertEqual([(rule.action, rule.archive) for rule in converted.rules], [("scan", "whole")])
        self.assertEqual(converted.inconclusive, "block")

    def test_every_previous_setting_becomes_a_rule_in_order(self):
        converted = self.convert({"max_file_bytes": 100, "block_masquerade": True,
                                  "type_rule": {"mode": "denylist", "families": ["script"]},
                                  "archive_handling": "scan_members", "review_action": "block"}, icap=True)
        self.assertEqual([(profile_rules.condition_text(rule.when), rule.action, rule.archive) for rule in converted.rules], [
            ("larger than 100 bytes", "block", None), ("extension contradicts content", "block", None),
            ("scripts", "block", None), ("archives", "scan", "members"), ("every other file", "scan", "whole")])
        allow = self.convert({"type_rule": {"mode": "allowlist", "families": ["pdf"]}})
        self.assertEqual([(rule.when.families, rule.action) for rule in allow.rules], [(["pdf"], "scan"), ([], "block")])

    def test_a_profile_without_a_detection_engine_becomes_a_light_check(self):
        converted = self.convert(detection=frozenset())
        self.assertEqual([(rule.action, rule.archive) for rule in converted.rules], [("light", None)])


class RuleDecisionTests(unittest.TestCase):
    POLICY = rules({"when": {"larger_than_bytes": 10}, "action": "light", "engines": [2]},
                   {"action": "scan", "engines": [1], "archive": "whole"}, inconclusive="allow")

    def decide(self, rule, base, **snapshot):
        routed = {"rule": {"number": 1, "action": rule, "condition": "x"}, **snapshot}
        return profile_rules.apply_rules_decision(base, routed, self.POLICY)

    def base(self, **values):
        defaults = {"scan_status": "completed", "verdict": "info", "risk_score": 0, "detected_engines": 0,
                    "detection_engines": 1, "unavailable_engines": []}
        return decide_scan_action(**{**defaults, **values})

    def test_light_and_unscanned_allows_are_labelled(self):
        light = self.decide("light", self.base(detection_engines=0))
        self.assertEqual((light.action, light.policy, light.label), ("allow", "profile_rule_light_check", "Allow (light check only)"))
        unscanned = self.decide("allow", self.base(detection_engines=0))
        self.assertEqual((unscanned.action, unscanned.policy), ("allow", "profile_rule_not_scanned"))

    def test_inconclusive_follows_the_profile_and_detection_always_wins(self):
        partial = self.base(unavailable_engines=["ClamAV failed"])
        self.assertEqual(self.decide("scan", partial).policy, "profile_inconclusive_allow")
        strict = profile_rules.apply_rules_decision(partial, {"rule": {"number": 1, "action": "scan"}},
                                                    self.POLICY.model_copy(update={"inconclusive": "block"}))
        self.assertEqual((strict.action, strict.policy), ("block", "profile_inconclusive_block"))
        detected = self.decide("light", self.base(detected_engines=1, verdict="critical", risk_score=90))
        self.assertEqual((detected.action, detected.policy), ("block", "malware_detected"))

    def test_a_block_rule_is_not_allowed_never_malware(self):
        blocked = self.decide("block", self.base(detection_engines=0),
                              intake_policy={"violations": [{"kind": "rule_block", "detail": "Blocked by rule 1 (x)."}]})
        self.assertEqual((blocked.action, blocked.policy), ("block", "profile_rule_block"))
        self.assertTrue(blocked.reason.startswith("Not allowed: Blocked by rule 1"))


class RuleIntakeTests(unittest.TestCase):
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
        db.DB_PATH = root / "rules.db"
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
        self.file_type = db.create_engine_instance("file_type", "File Type")
        self.hash_list = db.create_engine_instance("hash_list", "Hash List")
        self.paid = db.create_engine_instance("virustotal", "VirusTotal")
        self.client, self.profile, _ = db.create_service_client_bundle(
            client_key="gate", display_name="Gate", profile_name="Standard",
            engine_instance_ids=[self.clamav], credential_label="Test",
            token_hash=hash_api_token("synthetic-rules-token-" + "x" * 40), token_prefix="synthetic")

    def restore(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def revision(self):
        return next(item for item in profile_admin.page(self.client, None).items if item.id == self.profile).management_revision

    def save(self, *items, inconclusive="block"):
        profile_admin.save_rules(self.client, self.profile, profile_admin.ProfileRulesBody(
            expected_revision=self.revision(), rules=rules(*items, inconclusive=inconclusive)))

    def standard(self):
        self.save({"when": {"larger_than_bytes": 1000}, "action": "light", "engines": [self.file_type, self.hash_list]},
                  {"when": {"families": ["executable"]}, "action": "block"},
                  {"when": {"families": ["script"]}, "action": "allow"},
                  {"when": {"families": ["archive"]}, "action": "scan", "engines": [self.clamav], "archive": "inspect"},
                  {"action": "scan", "engines": [self.clamav, self.file_type], "archive": "whole"})

    def enqueue(self, content: bytes, name: str, *, refuse_archives=False):
        from app.services.scan_intake import enqueue_scan_from_stored_sample
        identity, engines = resolve_profile_routing(identity_for_service_client_key("gate"), source="icap")
        return enqueue_scan_from_stored_sample(
            store_bytes(name, "application/octet-stream", content), case_name="T", priority="Normal", note="",
            source="icap", engines=engines, service_client_id=identity.client.id,
            scan_profile_id=identity.profile.id, profile_snapshot_json=profile_snapshot_json(identity, engines),
            refuse_archives=refuse_archives)

    def jobs(self, scan_id):
        return sorted(job.engine_instance_id for job in db.list_scan_engine_jobs(scan_id))

    def test_each_file_runs_only_its_rules_engines(self):
        self.standard()
        large = self.enqueue(b"x" * 2000, "big.bin")
        self.assertEqual(self.jobs(large.id), sorted([self.file_type, self.hash_list]))
        snapshot = json.loads(large.profile_snapshot_json)
        self.assertEqual(snapshot["rule"]["number"], 1)
        self.assertEqual(sorted(engine["id"] for engine in snapshot["profile_engines"]),
                         sorted([self.clamav, self.file_type, self.hash_list]))
        small = self.enqueue(b"hello", "notes.txt")
        self.assertEqual(self.jobs(small.id), sorted([self.clamav, self.file_type]))

    def test_block_and_allow_without_scanning_complete_at_intake_and_show_in_the_ledger(self):
        self.standard()
        blocked = self.enqueue(EXE, "tool.exe")
        unscanned = self.enqueue(b"#!/bin/sh\necho hi\n", "run.sh")
        for scan in (blocked, unscanned):
            self.assertEqual((scan.status, self.jobs(scan.id)), ("completed", []))
        decision = resolve_scan_decision(db.get_scan(blocked.id))
        self.assertEqual((decision.action, decision.policy), ("block", "profile_rule_block"))
        self.assertIn("Blocked by rule 2 (programs)", decision.reason)
        allowed = resolve_scan_decision(db.get_scan(unscanned.id))
        self.assertEqual((allowed.action, allowed.policy), ("allow", "profile_rule_not_scanned"))
        # The ICAP end user is told the file is not accepted, never that it could not be scanned.
        from app.icap.config import IcapConfig
        from app.icap.server import resolve_icap_action
        action, reason, message = resolve_icap_action(db.get_scan(blocked.id), IcapConfig(fail_closed=False))
        self.assertEqual((action, message), ("block", "Blocked by MASP: files like this are not accepted."))
        self.assertIn("Blocked by rule 2", reason)
        self.assertEqual(resolve_icap_action(db.get_scan(unscanned.id), IcapConfig())[0], "allow")
        rows = {item.id: item for item in ledger_read.page(limit=20, before=None, query="", source="all", status="all",
                                                            risk="all", client_id=None, unassigned=False).items}
        self.assertEqual((rows[blocked.id].not_allowed, rows[blocked.id].not_allowed_label, rows[blocked.id].rule_action),
                         ("rule_block", "Blocked by rule", "block"))
        self.assertEqual((rows[unscanned.id].not_allowed, rows[unscanned.id].rule_action), (None, "allow"))
        self.assertIsNone(rows[unscanned.id].risk_score)

    def test_a_light_check_that_finds_nothing_is_allowed_and_labelled(self):
        self.standard()
        large = self.enqueue(b"x" * 2000, "big.bin")
        for engine in ("File Type", "Hash List"):
            db.create_engine_result(large.id, EngineResultInput(engine, "completed", False, "info", 0, None, "", 1))
        self.assertTrue(db.transition_scan_to_completed(large.id, "info", 0))
        decision = resolve_scan_decision(db.get_scan(large.id))
        self.assertEqual((decision.action, decision.policy), ("allow", "profile_rule_light_check"))

    def test_the_gateway_archive_setting_does_not_apply_to_rules(self):
        self.standard()
        archive = self.enqueue(zip_bytes(), "bundle.zip", refuse_archives=True)
        snapshot = json.loads(archive.profile_snapshot_json)
        self.assertNotIn("intake_policy", snapshot)
        self.assertEqual(snapshot["archive_inspection"]["handling"], "inspect")
        # A member a rule blocks makes the inspected archive not allowed.
        hidden = self.enqueue(zip_bytes(**{"tool.exe": EXE}), "hidden.zip")
        violation, = json.loads(hidden.profile_snapshot_json)["intake_policy"]["violations"]
        self.assertEqual(violation["kind"], "member_rule")
        self.assertIn("Blocked by rule 2", violation["detail"])

    def test_saving_checks_each_rules_engines(self):
        cases = [
            ({"action": "light", "engines": [self.clamav]}, "Light check runs only"),
            ({"action": "scan", "engines": [self.file_type], "archive": "whole"}, "Scan needs at least one"),
            ({"action": "scan", "engines": [self.clamav, self.paid], "archive": "whole"}, "Paid reputation service"),
            ({"action": "scan", "engines": [999], "archive": "whole"}, "no longer exists"),
        ]
        for rule, message in cases:
            with self.subTest(message=message), self.assertRaises(HTTPException) as error:
                self.save(rule)
            self.assertEqual(error.exception.status_code, 422)
            self.assertIn(message, error.exception.detail)
        self.standard()
        item = profile_admin.page(self.client, None).items[0]
        self.assertEqual(item.engine_ids, sorted([self.clamav, self.file_type, self.hash_list]))
        self.assertEqual(item.rules.rules[1].action, "block")
        with self.assertRaises(HTTPException) as error:
            profile_admin.save_rules(self.client, self.profile, profile_admin.ProfileRulesBody(
                expected_revision=item.management_revision - 1, rules=item.rules))
        self.assertEqual(error.exception.status_code, 409)
        # A rule profile's engines are chosen per rule, not on the profile.
        with self.assertRaises(HTTPException) as error:
            profile_admin.save(self.client, self.profile, profile_admin.ProfileRoutingBody(
                engine_ids=[self.clamav], expected_engine_ids=item.engine_ids, expected_revision=item.management_revision))
        self.assertEqual(error.exception.status_code, 409)

    def test_new_profiles_start_with_one_explicit_rule(self):
        created = profile_admin.create(self.client, profile_admin.ProfileCreateBody(
            name="Light", engine_ids=[self.file_type, self.hash_list], inconclusive="allow"))
        item = next(item for item in profile_admin.page(self.client, None).items if item.id == created.profile_id)
        self.assertEqual([(rule.action, rule.engines) for rule in item.rules.rules],
                         [("light", sorted([self.file_type, self.hash_list]))])
        self.assertEqual(item.rules.inconclusive, "allow")

    def test_startup_converts_integration_profiles_once_and_leaves_legacy_default(self):
        from app.services.service_clients import seed_legacy_service_client
        seed_legacy_service_client()
        icap = db.create_scan_profile(self.client, "From ICAP", engine_instance_ids=[self.clamav],
                                      policy_json='{"archive_handling":"inherit"}')
        self.enqueue(b"hello", "notes.txt")   # the client now has ICAP traffic
        self.assertGreaterEqual(db.convert_profiles_to_rules(), 2)
        self.assertEqual(db.convert_profiles_to_rules(), 0)
        with db.connect() as connection:
            stored = {row["id"]: row["policy_json"] for row in connection.execute(
                "SELECT p.id, p.policy_json FROM scan_profiles p JOIN service_clients c ON c.id = p.service_client_id "
                "WHERE c.client_key != 'legacy-default'").fetchall()}
            legacy = connection.execute("""SELECT p.policy_json FROM scan_profiles p JOIN service_clients c
                ON c.id = p.service_client_id WHERE c.client_key = 'legacy-default'""").fetchone()["policy_json"]
        converted = profile_rules.parse_rules_policy(stored[icap])
        self.assertEqual([rule.action for rule in converted.rules], ["block", "scan"])
        self.assertEqual(converted.inconclusive, "allow")
        self.assertFalse(profile_rules.is_rules_policy(legacy))


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class PostgresRuleIntakeTests(RuleIntakeTests):
    postgres = True


if __name__ == "__main__":
    unittest.main()
