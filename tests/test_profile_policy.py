"""Per-profile scan policy: validation, intake judgement and the shared decision."""
import asyncio
from dataclasses import replace
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException, UploadFile

from app import database as db
from app.models import StoredSample
from app.services import profile_admin as admin
from app.services.decisions import decide_scan_action
from app.services.profile_policy import (
    PolicyRejectedError, ProfilePolicy, apply_intake_policy, apply_profile_policy, evaluate_intake,
    parse_profile_policy, profile_policy_json,
)
from app.services.service_clients import hash_api_token, profile_snapshot_json, resolve_profile_routing, resolve_stored_api_client

EXE = b"MZ\x90\x00" + b"\x00" * 60
PDF = b"%PDF-1.7\n"


def decision(action):
    """A decision of each kind, as the shared rules produce it."""
    base = dict(scan_status="completed", verdict="info", risk_score=0, detected_engines=0,
                detection_engines=1, unavailable_engines=[])
    if action == "block":
        base.update(detected_engines=1, verdict="high", risk_score=70)
    elif action == "review":
        base.update(unavailable_engines=["ClamAV failed"])
    elif action == "wait":
        base.update(scan_status="running")
    return decide_scan_action(**base)


def snapshot(policy=None, violations=None):
    value = {"scan_profile": {"id": 1, "name": "Default", "policy": {} if policy is None else policy}}
    if violations is not None:
        value["intake_policy"] = {"violations": violations}
    return value


class PolicyModelTests(unittest.TestCase):
    def test_an_empty_policy_inherits_everything(self):
        policy = parse_profile_policy("{}")
        self.assertEqual(policy, ProfilePolicy())
        self.assertEqual(parse_profile_policy(None), ProfilePolicy())
        self.assertEqual(json.loads(profile_policy_json(policy)), {
            "block_masquerade": False, "max_file_bytes": None, "review_action": "inherit",
            "type_rule": None, "violation_action": "scan_and_block"})

    def test_invalid_policies_are_refused_whole(self):
        for raw in ({"type_rule": {"mode": "allowlist", "families": ["documents"]}},
                    {"type_rule": {"mode": "allowlist", "families": []}},
                    {"max_file_bytes": 0}, {"max_file_bytes": "5"}, {"review_action": "allow"},
                    {"violation_action": "quarantine"}, {"unknown": True}, [], "not json"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_profile_policy(raw if not isinstance(raw, (dict, list)) else json.dumps(raw))

    def test_families_are_deduplicated_in_canonical_order(self):
        policy = parse_profile_policy({"type_rule": {"mode": "denylist", "families": ["script", "executable", "script"]}})
        self.assertEqual(policy.type_rule.families, ["executable", "script"])


class IntakeEvaluationTests(unittest.TestCase):
    def judge(self, policy, filename, header, size=100):
        return evaluate_intake(parse_profile_policy(policy), filename=filename, size=size, header=header)

    def test_size_limit_rejects_before_content_is_judged(self):
        result = self.judge({"max_file_bytes": 1024}, "a.pdf", PDF, size=2048)
        self.assertEqual(result.reject_kind, "size")
        self.assertIn("accepts at most 1.0 KiB", result.reason)
        self.assertIsNone(self.judge({"max_file_bytes": 1024}, "a.pdf", PDF, size=1024).reject_kind)

    def test_content_is_judged_from_the_header_not_the_name(self):
        allow_pdf = {"type_rule": {"mode": "allowlist", "families": ["pdf"]}}
        self.assertEqual(self.judge(allow_pdf, "report.pdf", PDF).violations, ())
        # An executable named like a PDF is still an executable.
        violation, = self.judge(allow_pdf, "report.pdf", EXE).violations
        self.assertEqual((violation["kind"], violation["violating"]), ("type", ["executable"]))
        # Plain text has no signature: it is "unrecognized" unless listed.
        self.assertEqual(self.judge(allow_pdf, "notes.txt", b"hello").violations[0]["violating"], ["unrecognized"])
        deny_code = {"type_rule": {"mode": "denylist", "families": ["executable", "script"]}}
        self.assertEqual(self.judge(deny_code, "notes.txt", b"hello").violations, ())
        # A script has no magic bytes; its extension names its family.
        self.assertEqual(self.judge(deny_code, "run.ps1", b"Write-Host hi").violations[0]["violating"], ["script"])

    def test_masquerade_and_the_chosen_action(self):
        policy = {"block_masquerade": True}
        violation, = self.judge(policy, "invoice.pdf", EXE).violations
        self.assertEqual(violation["kind"], "masquerade")
        self.assertIn("Declared .pdf content is actually pe", violation["detail"])
        self.assertEqual(self.judge(policy, "invoice.pdf", PDF).violations, ())
        self.assertIsNone(self.judge(policy, "invoice.pdf", EXE).reject_kind)
        self.assertEqual(self.judge(policy | {"violation_action": "reject"}, "invoice.pdf", EXE).reject_kind, "type")


class IntakeSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.sample = Path(self.temp.name) / "sample.bin"
        self.sample.write_bytes(EXE)

    def apply(self, policy, filename="report.pdf"):
        raw = json.dumps(snapshot(policy))
        return raw, apply_intake_policy(raw, filename=filename, size=len(EXE), storage_path=str(self.sample))

    def test_an_inheriting_policy_leaves_the_snapshot_byte_identical(self):
        raw, stored = self.apply({})
        self.assertIs(stored, raw)

    def test_a_violation_is_recorded_on_the_scan_or_rejects_it(self):
        _, stored = self.apply({"block_masquerade": True})
        self.assertEqual(json.loads(stored)["intake_policy"]["violations"][0]["kind"], "masquerade")
        with self.assertRaises(PolicyRejectedError) as error:
            self.apply({"block_masquerade": True, "violation_action": "reject"})
        self.assertEqual(error.exception.kind, "type")

    def test_an_unreadable_policy_does_not_block_intake(self):
        # The decision withholds allow instead; intake is not where that is judged.
        raw, stored = self.apply({"type_rule": "everything"})
        self.assertIs(stored, raw)


class DecisionOverlayTests(unittest.TestCase):
    VIOLATION = [{"kind": "type", "detail": "Content family not accepted by this client's profile: executable."}]

    def test_nothing_changes_without_a_policy(self):
        for action in ("allow", "review", "block", "wait"):
            with self.subTest(action=action):
                self.assertEqual(apply_profile_policy(decision(action), snapshot(), scan_role="standalone"), decision(action))
                self.assertEqual(apply_profile_policy(decision(action), {}, scan_role="standalone"), decision(action))

    def test_a_content_violation_blocks_even_a_clean_scan(self):
        result = apply_profile_policy(decision("allow"), snapshot({"type_rule": {"mode": "allowlist", "families": ["pdf"]}},
                                                                  self.VIOLATION), scan_role="standalone")
        self.assertEqual((result.action, result.policy), ("block", "profile_content_policy"))
        self.assertIn(self.VIOLATION[0]["detail"], result.reasons)
        # A detection stays the reason; the violation is added beside it.
        detected = apply_profile_policy(decision("block"), snapshot({}, self.VIOLATION), scan_role="standalone")
        self.assertEqual(detected.policy, "malware_detected")
        self.assertIn(self.VIOLATION[0]["detail"], detected.reasons)

    def test_archive_members_do_not_inherit_the_containers_verdict(self):
        member = apply_profile_policy(decision("allow"), snapshot({}, self.VIOLATION), scan_role="child")
        self.assertEqual(member.action, "allow")

    def test_review_blocks_only_when_the_profile_says_so(self):
        self.assertEqual(apply_profile_policy(decision("review"), snapshot({"review_action": "inherit"}),
                                              scan_role="standalone").action, "review")
        blocked = apply_profile_policy(decision("review"), snapshot({"review_action": "block"}), scan_role="standalone")
        self.assertEqual((blocked.action, blocked.policy), ("block", "profile_review_block"))
        self.assertIn("One or more required engines did not complete.", blocked.reasons)
        failed = decide_scan_action(scan_status="failed", verdict="info", risk_score=0, detected_engines=0,
                                    detection_engines=1, unavailable_engines=[])
        self.assertEqual(apply_profile_policy(failed, snapshot({"review_action": "block"}), scan_role="standalone").action, "block")
        # Nothing the policy does ever produces an allow.
        self.assertEqual(apply_profile_policy(decision("allow"), snapshot({"review_action": "block"}),
                                              scan_role="standalone").action, "allow")

    def test_a_running_scan_still_waits(self):
        self.assertEqual(apply_profile_policy(decision("wait"), snapshot({"review_action": "block"}, self.VIOLATION),
                                              scan_role="standalone").action, "wait")

    def test_an_unreadable_recorded_policy_withholds_allow_but_keeps_a_block(self):
        broken = snapshot({"review_action": "maybe"})
        result = apply_profile_policy(decision("allow"), broken, scan_role="standalone")
        self.assertEqual((result.action, result.policy), ("review", "profile_policy_invalid"))
        self.assertEqual(apply_profile_policy(decision("block"), broken, scan_role="standalone").action, "block")


class ProfilePolicyIntegrationTests(unittest.TestCase):
    postgres = False

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original = db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED
        db.close_pool()
        db.DB_PATH = Path(self.temp.name) / "policy.db"
        db.DATABASE_URL = os.environ["MASP_TEST_POSTGRES_URL"] if self.postgres else ""
        db.DB_POOL_ENABLED = False
        if self.postgres:
            import psycopg
            with psycopg.connect(db.DATABASE_URL, autocommit=True) as connection:
                connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
                connection.execute("CREATE SCHEMA public")
        db.init_db()
        self.samples = Path(self.temp.name) / "samples"
        self.engine = db.create_engine_instance("static_metadata", "Metadata")
        self.token = "synthetic-policy-test-token-xxxxxxxxxxxxxxxxx"
        self.client, self.profile, _ = db.create_service_client_bundle(
            client_key="policy-test", display_name="Policy", profile_name="Standard",
            engine_instance_ids=[self.engine], credential_label="Test",
            token_hash=hash_api_token(self.token), token_prefix="synthetic")

    def tearDown(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original
        self.temp.cleanup()

    def revision(self):
        return next(item for item in admin.page(self.client, None).items if item.id == self.profile).management_revision

    def set_policy(self, policy):
        admin.save_policy(self.client, self.profile, admin.ProfilePolicyBody(
            expected_revision=self.revision(), policy=parse_profile_policy(policy)))

    def upload(self, content, filename):
        from app.main import enqueue_scan_from_upload
        identity = resolve_stored_api_client(self.token)
        with patch("app.services.ingest.SAMPLES_DIR", self.samples):
            return asyncio.run(enqueue_scan_from_upload(UploadFile(BytesIO(content), filename=filename),
                case_name="Test", priority="Normal", note="", source="api", api_identity=identity))

    def stored_files(self):
        return [path for path in self.samples.rglob("*") if path.is_file()] if self.samples.exists() else []

    def test_the_console_reads_and_fences_policy_writes(self):
        item = next(item for item in admin.page(self.client, None).items if item.id == self.profile)
        self.assertEqual((item.policy, item.policy_invalid), (ProfilePolicy(), False))
        self.set_policy({"max_file_bytes": 2048, "review_action": "block"})
        item = next(item for item in admin.page(self.client, None).items if item.id == self.profile)
        self.assertEqual((item.policy.max_file_bytes, item.policy.review_action), (2048, "block"))
        # A stale revision is refused, as for every other profile write.
        with self.assertRaises(HTTPException) as error:
            admin.save_policy(self.client, self.profile, admin.ProfilePolicyBody(
                expected_revision=item.management_revision - 1, policy=ProfilePolicy()))
        self.assertEqual(error.exception.status_code, 409)
        # The compatibility client's routing is deployment-managed.
        legacy = db.get_service_client_by_key("legacy-default")
        if legacy is None:
            from app.services.service_clients import seed_legacy_service_client
            seed_legacy_service_client()
            legacy = db.get_service_client_by_key("legacy-default")
        legacy_profile = admin.page(legacy.id, None).items[0]
        with self.assertRaises(HTTPException) as error:
            admin.save_policy(legacy.id, legacy_profile.id, admin.ProfilePolicyBody(
                expected_revision=legacy_profile.management_revision, policy=ProfilePolicy()))
        self.assertIn("deployment-managed", error.exception.detail)
        # A stored policy that cannot be read is reported, never guessed.
        with db.connect() as connection:
            connection.execute("UPDATE scan_profiles SET policy_json = ? WHERE id = ?", ('{"review_action":"maybe"}', self.profile))
        item = next(item for item in admin.page(self.client, None).items if item.id == self.profile)
        self.assertEqual((item.policy, item.policy_invalid), (None, True))

    def test_api_uploads_are_rejected_or_blocked_as_the_profile_says(self):
        self.set_policy({"max_file_bytes": 32})
        with self.assertRaises(HTTPException) as error:
            self.upload(b"x" * 64, "big.bin")
        self.assertEqual(error.exception.status_code, 413)
        self.assertEqual(self.stored_files(), [])
        self.set_policy({"type_rule": {"mode": "denylist", "families": ["executable"]}, "violation_action": "reject"})
        with self.assertRaises(HTTPException) as error:
            self.upload(EXE, "tool.exe")
        self.assertEqual(error.exception.status_code, 415)
        self.assertIn("executable", error.exception.detail)
        self.assertEqual(self.stored_files(), [])
        with db.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) AS n FROM scan_jobs").fetchone()["n"], 0)
        # Scan-and-block: the scan exists, carries the verdict, and is blocked
        # even though every engine reports it clean.
        self.set_policy({"type_rule": {"mode": "denylist", "families": ["executable"]}})
        scan = self.upload(EXE, "tool.exe")
        self.assertEqual(json.loads(scan.profile_snapshot_json)["intake_policy"]["violations"][0]["violating"], ["executable"])
        from app.services.scan_assessment import scan_decision
        result = scan_decision(replace(scan, status="completed", verdict="info", risk_score=0), [])
        self.assertEqual((result.action, result.policy), ("block", "profile_content_policy"))
        # An accepted scan keeps the policy it was frozen with.
        self.set_policy({})
        self.assertEqual(scan_decision(replace(db.get_scan(scan.id), status="completed", verdict="info", risk_score=0), []).action, "block")

    def post_json(self, path, payload):
        from app.main import app
        body = json.dumps(payload).encode()
        scope = dict(type="http", asgi={"version": "3.0", "spec_version": "2.3"}, http_version="1.1",
                     method="POST", scheme="http", path=path, raw_path=path.encode(), query_string=b"", root_path="",
                     headers=[(b"host", b"testserver"), (b"content-type", b"application/json"),
                              (b"content-length", str(len(body)).encode()),
                              (b"authorization", f"Bearer {self.token}".encode())],
                     server=("testserver", 80), client=("127.0.0.1", 1234))
        messages = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            messages.append(message)
        asyncio.run(app(scope, receive, send))
        status = next(m["status"] for m in messages if m["type"] == "http.response.start")
        return status, json.loads(b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body"))

    def test_deferred_expected_size_is_checked_at_submission(self):
        self.set_policy({"max_file_bytes": 1000})
        payload = dict(backend_key="test", object_id="sample.bin", original_filename="sample.bin",
                       client_request_id="policy-1", expected_size_bytes=5000)
        with patch("app.main.configured_backend_keys", return_value=["test"]),              patch("app.main.backend_allowed_for_client", return_value=True):
            status, response = self.post_json("/api/v1/deferred-scans", payload)
            self.assertEqual(status, 413, response)
            self.assertIn("profile", response["detail"])
            status, response = self.post_json("/api/v1/deferred-scans", payload | {"expected_size_bytes": 900})
            self.assertEqual(status, 202, response)

    def test_icap_blocks_a_rejected_upload_whatever_its_fail_mode(self):
        from app.icap import activity, server
        from app.icap.config import IcapConfig
        self.set_policy({"block_masquerade": True, "violation_action": "reject",
                         "type_rule": {"mode": "denylist", "families": ["executable"]}})
        config = IcapConfig(service_client_key="policy-test", wait_seconds=0, fail_closed=False)
        recorder = activity.IcapActivity(config)
        with patch("app.services.ingest.SAMPLES_DIR", self.samples), patch.object(activity, "ACTIVITY", recorder), \
             patch.object(server, "wait_for_terminal_scan", new=AsyncMock(return_value=None)):
            self.assertEqual(asyncio.run(server.scan_and_decide("invoice.pdf", "application/pdf", EXE, config)), "block")
        self.assertEqual(recorder.counters["policy_rejected"], 1)
        self.assertEqual(recorder.events[0]["kind"], "policy_rejected")
        self.assertIn("Declared .pdf content is actually pe", recorder.events[0]["detail"])
        self.assertNotIn(".;", recorder.events[0]["detail"])
        self.assertEqual(self.stored_files(), [])

    def test_the_deferred_worker_fails_a_rejected_object_permanently(self):
        from app.workers import deferred_intake_worker
        self.set_policy({"type_rule": {"mode": "allowlist", "families": ["pdf"]}, "violation_action": "reject"})
        identity, engines = resolve_profile_routing(resolve_stored_api_client(self.token), source="api")
        request, _ = db.create_deferred_scan_submission(
            service_client_id=self.client, scan_profile_id=self.profile, client_request_id="deferred-policy",
            backend_key="drive", object_id="uploads/tool.exe", original_filename="tool.exe",
            content_type="application/octet-stream", expected_size_bytes=None, expected_sha256=None,
            archive_mode="lazy_extract_on_detection", case_name="Upload", priority="Normal", note="",
            profile_snapshot_json=profile_snapshot_json(identity, engines))
        copied = Path(self.temp.name) / "copied.bin"
        copied.write_bytes(EXE)
        stored = StoredSample("tool.exe", "copied.bin", str(copied), "application/octet-stream", len(EXE),
                              "0" * 32, "0" * 40, "1" * 64)
        with patch.object(deferred_intake_worker, "configured_backend_keys", return_value={"drive"}), \
             patch.object(deferred_intake_worker, "backend_allowed_for_client", return_value=True), \
             patch.object(deferred_intake_worker, "copy_deferred_source", return_value=stored):
            self.assertTrue(deferred_intake_worker.process_next())
        updated = db.get_deferred_scan_submission(request.id)
        self.assertEqual(updated.status, "failed")
        self.assertIsNone(updated.scan_job_id)
        self.assertIn("Rejected by the client's profile policy", updated.last_error)
        self.assertFalse(copied.exists())


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class ProfilePolicyPostgresTests(ProfilePolicyIntegrationTests):
    postgres = True


if __name__ == "__main__":
    unittest.main()
