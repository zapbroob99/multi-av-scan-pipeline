"""A profile's archive handling: inspection at intake, member scanning and the ICAP gate."""
import asyncio
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from fastapi import HTTPException

import app.main  # noqa: F401  (startup runs once here, not in the middle of a test)
from app import database as db
from app.icap.config import IcapConfig
from app.models import EngineResultInput, StoredSample
from app.services import archive_extractor
from app.services import profile_admin as admin
from app.services.decisions import ScanDecision
from app.services.ingest import store_bytes
from app.services.profile_policy import (
    PolicyRejectedError, apply_intake_policy, parse_profile_policy, profile_policy_json, scans_every_member,
)
from app.services.scoring import RiskAssessment
from app.services.service_clients import (
    hash_api_token, identity_for_service_client_key, profile_snapshot_json, resolve_profile_routing,
)

EXE = b"MZ\x90\x00" + b"\x00" * 60
TEXT = b"plain text member"


def zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def encrypted_zip() -> bytes:
    """A ZIP whose member carries the encryption flag, as a password-protected one does."""
    data = bytearray(zip_bytes({"secret.txt": TEXT}))
    data[6] |= 0x01  # local file header: general purpose flags
    central = data.index(b"PK\x01\x02")
    data[central + 8] |= 0x01  # central directory: general purpose flags
    return bytes(data)


def docx() -> bytes:
    return zip_bytes({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>"})


def snapshot(policy: dict, *, hash_list: bool = False) -> str:
    engines = [{"id": 1, "adapter_key": "clamav", "name": "ClamAV", "detection": True, "required": True}]
    if hash_list:
        engines.append({"id": 2, "adapter_key": "hash_list", "name": "Hash List", "detection": False, "required": True})
    return json.dumps({"scan_profile": {"id": 1, "name": "Default", "policy": policy}, "engines": engines})


class _Storage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.samples = root / "samples"
        self.samples.mkdir()
        self.staging = root / "staging"
        for target in (patch.object(archive_extractor, "SAMPLES_DIR", self.samples),
                       patch.object(archive_extractor, "STAGING_DIR", self.staging),
                       patch("app.services.ingest.SAMPLES_DIR", self.samples)):
            target.start()
            self.addCleanup(target.stop)

    def write(self, name: str, content: bytes) -> Path:
        path = Path(self.temp.name) / name
        path.write_bytes(content)
        return path

    def judge(self, policy: dict, content: bytes, filename: str = "upload.zip", **kwargs) -> dict:
        path = self.write(filename, content)
        stored = apply_intake_policy(snapshot(policy, **kwargs), filename=filename, size=len(content),
                                     storage_path=str(path))
        return json.loads(stored)


class InspectionTests(_Storage):
    INSPECT = {"archive_handling": "inspect"}

    def kinds(self, result: dict) -> list[str]:
        return [item["kind"] for item in result.get("intake_policy", {}).get("violations", [])]

    def test_a_clean_archive_is_counted_and_passes(self):
        result = self.judge(self.INSPECT, zip_bytes({"a.txt": TEXT, "docs/b.txt": TEXT}))
        self.assertNotIn("intake_policy", result)
        self.assertEqual(result["archive_inspection"], {
            "handling": "inspect", "format": "zip", "members": 2, "bytes": 2 * len(TEXT),
            "nested_archives": 0, "violation_total": 0})
        # Nothing is left behind in staging.
        self.assertEqual([path for path in self.staging.rglob("*") if path.is_file()], [])

    def test_an_inheriting_policy_never_opens_the_archive(self):
        raw = snapshot({})
        path = self.write("upload.zip", encrypted_zip())
        with patch("app.services.profile_policy.inspect_archive") as inspect:
            self.assertIs(apply_intake_policy(raw, filename="upload.zip", size=1, storage_path=str(path)), raw)
        inspect.assert_not_called()

    def test_what_engines_cannot_see_is_a_violation(self):
        cases = {
            "archive_encrypted": encrypted_zip(),
            "archive_unsupported": b"Rar!\x1a\x07\x00" + b"\x00" * 64,
            "archive_unreadable": b"PK\x03\x04" + b"\x00" * 64,
        }
        for kind, content in cases.items():
            with self.subTest(kind=kind):
                result = self.judge(self.INSPECT, content)
                self.assertEqual(self.kinds(result), [kind])
                self.assertEqual(result["archive_inspection"]["violation_total"], 1)
        rar = self.judge(self.INSPECT, cases["archive_unsupported"])
        self.assertIn("RAR archive, which MASP cannot open", rar["intake_policy"]["violations"][0]["detail"])

    def test_an_office_document_is_not_an_archive(self):
        result = self.judge(self.INSPECT, docx(), filename="report.docx")
        self.assertEqual(result.get("archive_inspection"), None)
        self.assertNotIn("intake_policy", result)

    def test_member_content_is_judged_by_the_profiles_rules(self):
        policy = self.INSPECT | {"type_rule": {"mode": "denylist", "families": ["executable"]},
                                 "block_masquerade": True}
        result = self.judge(policy, zip_bytes({"tools/setup.exe": EXE, "invoice.pdf": EXE, "notes.txt": TEXT}))
        details = [item["detail"] for item in result["intake_policy"]["violations"]]
        self.assertEqual(self.kinds(result), ["member_type", "member_type", "member_masquerade"])
        self.assertTrue(details[0].startswith("Archive member tools/setup.exe: Content family not accepted"))
        self.assertIn("Archive member invoice.pdf: Declared .pdf content is actually pe", details[2])

    def test_nested_archives_are_opened_within_the_nesting_limit(self):
        inner = zip_bytes({"deep.exe": EXE})
        policy = self.INSPECT | {"type_rule": {"mode": "denylist", "families": ["executable"]}}
        result = self.judge(policy, zip_bytes({"outer.txt": TEXT, "inner.zip": inner}))
        self.assertEqual(result["archive_inspection"]["members"], 3)
        self.assertEqual(result["archive_inspection"]["nested_archives"], 1)
        self.assertEqual(result["intake_policy"]["violations"][0]["member"], "inner.zip/deep.exe")
        with patch.dict(os.environ, {"MASP_ARCHIVE_MAX_NESTED_LEVELS": "1"}):
            result = self.judge(self.INSPECT, zip_bytes({"inner.zip": zip_bytes({"a.txt": TEXT})}))
        self.assertEqual(self.kinds(result), ["archive_nesting"])

    def test_limits_apply_across_every_level(self):
        nested = zip_bytes({"a.txt": TEXT, "inner.zip": zip_bytes({"b.txt": TEXT, "c.txt": TEXT})})
        with patch.dict(os.environ, {"MASP_ARCHIVE_MAX_FILES": "3"}):
            result = self.judge(self.INSPECT, nested)
        self.assertEqual(self.kinds(result), ["archive_limit"])
        self.assertIn("more than 3 files across all levels", result["intake_policy"]["violations"][0]["detail"])

    def test_reject_refuses_the_archive_without_a_scan(self):
        policy = self.INSPECT | {"violation_action": "reject"}
        with self.assertRaises(PolicyRejectedError) as error:
            self.judge(policy, encrypted_zip())
        self.assertEqual(error.exception.kind, "archive")
        self.assertIn("is encrypted", error.exception.reason)

    def test_only_a_clean_inspected_archive_is_opened_for_member_scanning(self):
        clean = json.dumps(self.judge({"archive_handling": "scan_members"}, zip_bytes({"a.txt": TEXT})))
        self.assertTrue(scans_every_member(clean))
        encrypted = json.dumps(self.judge({"archive_handling": "scan_members"}, encrypted_zip()))
        self.assertFalse(scans_every_member(encrypted))
        inspected = json.dumps(self.judge(self.INSPECT, zip_bytes({"a.txt": TEXT})))
        self.assertFalse(scans_every_member(inspected))
        self.assertFalse(scans_every_member("not json"))


class DecisionTests(unittest.TestCase):
    def test_archive_violations_block_with_their_own_policy(self):
        from app.services.decisions import decide_scan_action
        from app.services.profile_policy import apply_profile_policy

        allow = decide_scan_action(scan_status="completed", verdict="info", risk_score=0, detected_engines=0,
                                   detection_engines=1, unavailable_engines=[])
        recorded = json.loads(snapshot({"archive_handling": "inspect"}))
        recorded["intake_policy"] = {"violations": [{"kind": "archive_encrypted", "detail": "The archive is encrypted."}]}
        result = apply_profile_policy(allow, recorded, scan_role="container")
        self.assertEqual((result.action, result.policy), ("block", "profile_archive_policy"))
        self.assertEqual(result.reason, "Not allowed: The archive is encrypted.")


class IcapGateTests(unittest.TestCase):
    def scan(self, policy: dict | None, batch_id: int | None = 3):
        from tests.test_icap_server import FakeScan
        scan = FakeScan(status="completed", batch_id=batch_id)
        scan.scan_role = "container" if batch_id else "standalone"
        scan.profile_snapshot_json = snapshot(policy) if policy is not None else "{}"
        return scan

    def decide(self, scan, action="allow", policy="test", reason="test"):
        from app.icap import server
        decision = ScanDecision(action=action, label="x", tone="neutral", confidence="high", policy=policy,
                                reason=reason, reasons=[])
        return server.resolve_icap_action(scan, IcapConfig(), decision)

    def test_the_gateway_adds_no_rule_after_the_scan(self):
        # MASP_ICAP_BLOCK_ARCHIVES is recorded at intake; here only the decision counts.
        self.assertEqual(self.decide(self.scan({}))[0], "allow")

    def test_an_archive_policy_lets_the_decision_decide(self):
        for handling in ("inspect", "scan_members"):
            with self.subTest(handling=handling):
                self.assertEqual(self.decide(self.scan({"archive_handling": handling})), ("allow", "", ""))
                action, reason, message = self.decide(self.scan({"archive_handling": handling}), "block",
                                                      "profile_archive_policy", "The archive could not be fully checked.")
                self.assertEqual((action, reason), ("block", "Blocked: The archive could not be fully checked."))
                self.assertNotIn("malware", message)

    def test_unfinished_members_follow_the_fail_mode(self):
        from app.icap import server
        wait = ScanDecision(action="wait", label="Wait", tone="neutral", confidence="low",
                            policy="archive_members_in_progress", reason="r", reasons=[])
        scan = self.scan({"archive_handling": "scan_members"})
        self.assertEqual(server.resolve_icap_action(scan, IcapConfig(), wait)[0], "block")
        self.assertEqual(server.resolve_icap_action(scan, IcapConfig(fail_closed=False), wait)[0], "allow")
        self.assertTrue(server.judges_every_member(scan))
        self.assertFalse(server.judges_every_member(self.scan({"archive_handling": "inspect"})))


class ArchiveHandlingIntegrationTests(_Storage):
    postgres = False

    def setUp(self):
        super().setUp()
        self.original = db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED
        db.close_pool()
        db.DB_PATH = Path(self.temp.name) / "archive.db"
        db.DATABASE_URL = os.environ["MASP_TEST_POSTGRES_URL"] if self.postgres else ""
        db.DB_POOL_ENABLED = False
        if self.postgres:
            import psycopg
            with psycopg.connect(db.DATABASE_URL, autocommit=True) as connection:
                connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
                connection.execute("CREATE SCHEMA public")
        db.init_db()
        self.addCleanup(self.restore_db)
        from app.workers import scan_worker
        worker_samples = patch.object(scan_worker, "SAMPLES_DIR", self.samples)
        worker_samples.start()
        self.addCleanup(worker_samples.stop)
        self.engine = db.create_engine_instance("clamav", "ClamAV")
        self.client, self.profile, _ = db.create_service_client_bundle(
            client_key="archive-test", display_name="Archive", profile_name="Standard",
            engine_instance_ids=[self.engine], credential_label="Test",
            token_hash=hash_api_token("synthetic-archive-test-token-xxxxxxxxxxxxxx"), token_prefix="synthetic")

    def restore_db(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def set_policy(self, policy):
        # A profile written before rules, as an upgrade finds it; scans keep this logic.
        with db.connect() as connection:
            connection.execute("""UPDATE scan_profiles SET policy_json = ?,
                management_revision = management_revision + 1 WHERE id = ?""",
                (profile_policy_json(parse_profile_policy(policy)), self.profile))

    def enqueue(self, content: bytes, filename: str = "bundle.zip", source: str = "icap"):
        from app.services.scan_intake import enqueue_scan_from_stored_sample
        identity, engines = resolve_profile_routing(identity_for_service_client_key("archive-test"), source=source)
        stored = store_bytes(filename, "application/zip", content)
        return enqueue_scan_from_stored_sample(
            stored, case_name="T", priority="Normal", note="", source=source, engines=engines,
            service_client_id=identity.client.id, scan_profile_id=identity.profile.id,
            profile_snapshot_json=profile_snapshot_json(identity, engines))

    def finish(self, scan_id: int, *, detected: bool = False) -> None:
        db.create_engine_result(scan_id, EngineResultInput(
            engine_name="ClamAV", status="completed", detected=detected, severity="high" if detected else "info",
            confidence=90 if detected else 0, signature="Test.Detection" if detected else None,
            raw_output="", duration_ms=1))
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET status = 'completed', verdict = ?, risk_score = ? WHERE id = ?",
                               ("high" if detected else "info", 70 if detected else 0, scan_id))

    def register_members(self, scan) -> int:
        from app.workers import scan_worker
        db.update_scan_status(scan.id, "running")
        generation = db.claim_scan_finalization(scan.id, scan_worker.WORKER_ID, lease_seconds=120)
        return scan_worker.maybe_enqueue_lazy_archive_children(
            db.get_scan(scan.id), RiskAssessment(score=0, verdict="info", reasons=[]), [],
            db.list_engine_instances(), set(), finalize_generation=generation)

    def members(self, scan):
        return {member.relative_path: member for member in db.list_scan_batch_scans(scan.batch_id, limit=50)
                if member.scan_role == "child"}

    def test_scan_members_scans_every_member_and_decides_on_all_of_them(self):
        from app.services.scan_assessment import archive_decision
        self.set_policy({"archive_handling": "scan_members"})
        container = self.enqueue(zip_bytes({"a.txt": TEXT, "inner.zip": zip_bytes({"c.txt": TEXT})}))
        self.assertEqual(db.get_scan_batch(container.batch_id).archive_mode, "extract_all")
        self.assertEqual(json.loads(container.profile_snapshot_json)["archive_inspection"]["members"], 3)

        # A clean container is opened anyway: no detection is needed.
        self.assertEqual(self.register_members(container), 2)
        self.finish(container.id)
        self.assertEqual(archive_decision(db.get_scan(container.id)).action, "wait")
        for member in self.members(container).values():
            if member.relative_path == "a.txt":
                self.finish(member.id)
        # inner.zip has not registered its own member yet: the archive is incomplete.
        self.finish(self.members(container)["inner.zip"].id)
        incomplete = archive_decision(db.get_scan(container.id))
        self.assertEqual((incomplete.action, incomplete.policy), ("block", "archive_incomplete"))
        self.assertIn("Only 2 of the archive's 3 members", incomplete.reason)

        with db.connect() as connection:
            connection.execute("DELETE FROM engine_results WHERE scan_job_id = ?", (self.members(container)["inner.zip"].id,))
        self.assertEqual(self.register_members(self.members(container)["inner.zip"]), 1)
        self.finish(self.members(container)["inner.zip"].id)
        deep = self.members(container)["inner.zip/c.txt"]
        self.finish(deep.id)
        self.assertEqual(archive_decision(db.get_scan(container.id)).action, "allow")

        with db.connect() as connection:
            connection.execute("DELETE FROM engine_results WHERE scan_job_id = ?", (deep.id,))
        self.finish(deep.id, detected=True)
        blocked = archive_decision(db.get_scan(container.id))
        self.assertEqual((blocked.action, blocked.policy), ("block", "archive_member_blocked"))
        self.assertTrue(blocked.reason.startswith("Archive member inner.zip/c.txt:"))

        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET status = 'failed' WHERE id = ?", (deep.id,))
        unscanned = archive_decision(db.get_scan(container.id))
        self.assertEqual((unscanned.action, unscanned.policy), ("block", "archive_member_unscanned"))

    def test_inspect_keeps_the_lazy_mode_and_an_unknown_archive_keeps_the_request(self):
        self.set_policy({"archive_handling": "inspect"})
        container = self.enqueue(zip_bytes({"a.txt": TEXT}))
        self.assertEqual(db.get_scan_batch(container.batch_id).archive_mode, "lazy_extract_on_detection")
        self.assertEqual(self.register_members(container), 0)
        self.set_policy({"archive_handling": "scan_members"})
        blocked = self.enqueue(encrypted_zip())
        self.assertEqual(db.get_scan_batch(blocked.batch_id).archive_mode, "lazy_extract_on_detection")

    def ready_archive(self, *, detected=False):
        self.set_policy({"archive_handling": "scan_members"})
        container = self.enqueue(zip_bytes({"member.txt": TEXT}), source="api")
        self.register_members(container)
        self.finish(container.id)
        member = self.members(container)["member.txt"]
        self.finish(member.id, detected=detected)
        return db.get_scan(container.id), member

    def test_archive_decision_agrees_across_reports_exports_and_public_contracts(self):
        from app import main
        from app.services import automation_payload, batch_payload, scan_management, scan_report_read
        from app.services.api_schemas import ScanResultResponse, ScanStatusResponse
        from tests.test_api_contract import make_request
        for detected, expected in [(False, 'allow'), (True, 'block')]:
            container, _ = self.ready_archive(detected=detected)
            with self.subTest(detected=detected):
                compact = scan_report_read.report(container.id, automation=True)
                printed = scan_management.printable_report(container.id, automation=True)
                exported = json.loads(scan_management.full_export(container.id, 'json', automation=True).content)
                preview = json.loads(automation_payload.result_preview(container.id, 'http://localhost/').content)
                result = main.build_api_scan_result_payload(make_request(), container)
                status = main.build_api_scan_status_payload(make_request(), container)
                ScanResultResponse.model_validate(result)
                ScanResultResponse.model_validate(preview)
                ScanStatusResponse.model_validate(status)
                decisions = [compact.decision.model_dump(), printed.decision.model_dump(),
                             exported['summary']['decision'], preview['decision'], result['decision'], status['decision']]
                self.assertTrue(all(item == decisions[0] for item in decisions))
                self.assertEqual(decisions[0]['action'], expected)
                self.assertEqual(compact.risk_score, 0)  # The recorded container risk is unchanged.
                self.assertTrue(result['result_ready'])
                db.refresh_scan_batch_counts(container.batch_id)
                batch = json.loads(batch_payload.preview(container.batch_id, 'result', 'http://localhost/').content)
                root = next(item for item in batch['scans'] if item['id'] == container.id)
                self.assertEqual(root['result']['summary']['decision'], decisions[0])
                with self.assertRaises(HTTPException) as error:
                    scan_report_read.report(container.id)
                self.assertEqual(error.exception.status_code, 404)

    def test_waiting_members_keep_status_pending_and_result_endpoint_returns_409(self):
        from app import main
        from app.services import automation_payload, scan_report_read
        from app.services.api_schemas import ScanResultNotReadyResponse
        from app.services.service_clients import resolve_stored_api_client
        from tests.test_api_contract import make_request
        container, member = self.ready_archive()
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET status = 'running' WHERE id = ?", (member.id,))
        self.assertEqual(scan_report_read.report(container.id, automation=True).decision.action, 'wait')
        status = main.build_api_scan_status_payload(make_request(), container)
        self.assertFalse(status['result_ready'])
        self.assertIsNotNone(status['recommended_poll_seconds'])
        preview = json.loads(automation_payload.status_preview(container.id, 'http://localhost/').content)
        self.assertEqual(preview['decision'], status['decision'])
        self.assertFalse(preview['result_ready'])
        with self.assertRaises(HTTPException) as error:
            automation_payload.result_preview(container.id, 'http://localhost/')
        self.assertEqual(error.exception.status_code, 409)
        identity = resolve_stored_api_client('synthetic-archive-test-token-xxxxxxxxxxxxxx')
        with patch.object(main, 'require_api_token'), patch.object(main, 'api_client_identity', return_value=identity):
            response = main.api_scan_result(make_request(), container.id)
        self.assertEqual(response.status_code, 409)
        ScanResultNotReadyResponse.model_validate_json(response.body)

    def test_invalid_or_oversized_member_policy_never_uses_container_allow(self):
        from app import main
        from app.services import archive_assessment, scan_management, scan_report_read
        from app.services.scan_assessment import archive_decision
        from tests.test_api_contract import make_request
        container, member = self.ready_archive()
        for details in ['[1]', '{broken', '{"padding":"' + ('x' * archive_assessment.POLICY_LIMIT) + '"}']:
            with self.subTest(details=details[:20]):
                with db.connect() as connection:
                    connection.execute('UPDATE engine_results SET details_json = ? WHERE scan_job_id = ?', (details, member.id))
                report = scan_report_read.report(container.id, automation=True)
                self.assertIsNone(report.decision)
                self.assertIn('Archive decision unavailable', report.warning)
                self.assertIsNone(scan_management.printable_report(container.id, automation=True).decision)
                exported = json.loads(scan_management.full_export(container.id, 'json', automation=True).content)
                self.assertIsNone(exported['summary']['decision'])
                self.assertEqual(archive_decision(container).policy, 'archive_unassessed')
                with self.assertRaises(HTTPException) as error:
                    main.build_api_scan_result_payload(make_request(), container)
                self.assertEqual(error.exception.status_code, 503)

    def test_foreign_members_missing_ancestry_and_missing_routing_withhold_decision(self):
        from app.services import scan_report_read
        for column, value in [('source', 'manual'), ('service_client_id', None),
                              ('parent_scan_id', None), ('profile_snapshot_json', '{}')]:
            container, member = self.ready_archive()
            with self.subTest(column=column):
                with db.connect() as connection:
                    connection.execute(f'UPDATE scan_jobs SET {column} = ? WHERE id = ?', (value, member.id))
                report = scan_report_read.report(container.id, automation=True)
                self.assertIsNone(report.decision)
                self.assertIn('Archive decision unavailable', report.warning)

    def test_member_count_and_policy_budgets_are_enforced_before_hydration(self):
        from app.services import archive_assessment, scan_report_read
        container, _ = self.ready_archive()
        for limit in ['MAX_MEMBERS', 'MAX_RESULTS', 'SOURCE_LIMIT']:
            with self.subTest(limit=limit), patch.object(archive_assessment, limit, 0):
                report = scan_report_read.report(container.id, automation=True)
                self.assertIsNone(report.decision)
        # Huge output/findings do not enter the compact archive decision reader.
        with db.connect() as connection:
            connection.execute('UPDATE engine_results SET raw_output = ?, findings_json = ?',
                               ('x' * (archive_assessment.SOURCE_LIMIT + 1), 'not-json'))
        self.assertEqual(scan_report_read.report(container.id, automation=True).decision.action, 'allow')

    def test_member_review_and_incomplete_counts_never_allow(self):
        from app import main
        from app.services import scan_report_read
        from app.services.api_schemas import ScanResultResponse
        from tests.test_api_contract import make_request
        container, member = self.ready_archive()
        with db.connect() as connection:
            connection.execute('UPDATE engine_results SET details_json = ? WHERE scan_job_id = ?',
                               (json.dumps({'decision': {'action': 'review', 'reason': 'Review container'}}), container.id))
        result = main.build_api_scan_result_payload(make_request(), container)
        ScanResultResponse.model_validate(result)
        self.assertEqual(result['decision']['policy'], 'engine_policy_review')
        with db.connect() as connection:
            connection.execute("UPDATE engine_results SET details_json = '{}' WHERE scan_job_id = ?", (container.id,))
            connection.execute('UPDATE engine_results SET details_json = ? WHERE scan_job_id = ?',
                               (json.dumps({'decision': {'action': 'review', 'reason': 'Needs review'}}), member.id))
        report = scan_report_read.report(container.id, automation=True)
        self.assertEqual(report.decision.policy, 'archive_member_review')
        with db.connect() as connection:
            connection.execute('UPDATE scan_jobs SET batch_id = NULL WHERE id = ?', (member.id,))
        report = scan_report_read.report(container.id, automation=True)
        self.assertEqual(report.decision.policy, 'archive_incomplete')

    def test_inspection_block_is_a_valid_public_result_contract(self):
        from app import main
        from app.services.api_schemas import ScanResultResponse
        from tests.test_api_contract import make_request
        self.set_policy({'archive_handling': 'inspect'})
        container = self.enqueue(encrypted_zip(), source='api')
        self.finish(container.id)
        result = main.build_api_scan_result_payload(make_request(), db.get_scan(container.id))
        ScanResultResponse.model_validate(result)
        self.assertEqual(result['decision']['policy'], 'profile_archive_policy')

    def test_a_blocklisted_member_blocks_and_is_never_rejected_unscanned(self):
        hash_engine = db.create_engine_instance("hash_list", "Hash List")
        with db.connect() as connection:
            connection.execute("INSERT INTO scan_profile_engines (scan_profile_id, engine_instance_id) VALUES (?, ?)",
                               (self.profile, hash_engine))
        db.add_hash_list_entries([(hashlib.sha256(EXE).hexdigest(), "block", "test entry")], None)
        self.set_policy({"archive_handling": "inspect", "violation_action": "reject"})
        scan = self.enqueue(zip_bytes({"payload.bin": EXE, "a.txt": TEXT}))
        violation, = json.loads(scan.profile_snapshot_json)["intake_policy"]["violations"]
        self.assertEqual(violation["kind"], "member_blocklisted")
        self.assertIn("payload.bin is on the institution hash blocklist", violation["detail"])

    def test_the_api_answers_415_for_a_refused_archive(self):
        from app.main import enqueue_scan_from_upload
        from fastapi import UploadFile
        from app.services.service_clients import resolve_stored_api_client
        self.set_policy({"archive_handling": "inspect", "violation_action": "reject"})
        identity = resolve_stored_api_client("synthetic-archive-test-token-xxxxxxxxxxxxxx")
        with self.assertRaises(HTTPException) as error:
            asyncio.run(enqueue_scan_from_upload(UploadFile(io.BytesIO(encrypted_zip()), filename="secret.zip"),
                                                 case_name="T", priority="Normal", note="", source="api",
                                                 api_identity=identity))
        self.assertEqual(error.exception.status_code, 415)
        self.assertIn("encrypted", error.exception.detail)

    def test_icap_blocks_an_encrypted_archive_and_names_why(self):
        from app.icap import activity, server
        self.set_policy({"archive_handling": "inspect"})
        config = IcapConfig(service_client_key="archive-test", wait_seconds=1)
        recorder = activity.IcapActivity(config)

        async def finished(scan_id, _wait):
            return replace(db.get_scan(scan_id), status="completed", verdict="info", risk_score=0)
        with patch.object(activity, "ACTIVITY", recorder), patch.object(server, "wait_for_terminal_scan", new=finished):
            self.assertEqual(asyncio.run(server.scan_and_decide("secret.zip", "application/zip", encrypted_zip(), config)),
                             ("block", "Blocked by MASP: the archive could not be fully checked."))
        self.assertIn("Not allowed: The archive is encrypted", recorder.events[0]["detail"])

    def test_the_deferred_worker_opens_every_member_under_scan_members(self):
        from app.workers import deferred_intake_worker
        self.set_policy({"archive_handling": "scan_members"})
        identity, engines = resolve_profile_routing(identity_for_service_client_key("archive-test"), source="api")
        request, _ = db.create_deferred_scan_submission(
            service_client_id=self.client, scan_profile_id=self.profile, client_request_id="deferred-archive",
            backend_key="drive", object_id="uploads/bundle.zip", original_filename="bundle.zip",
            content_type="application/zip", expected_size_bytes=None, expected_sha256=None,
            archive_mode="lazy_extract_on_detection", case_name="Upload", priority="Normal", note="",
            profile_snapshot_json=profile_snapshot_json(identity, engines))
        content = zip_bytes({"a.txt": TEXT})
        copied = self.samples / "copied.zip"
        copied.write_bytes(content)
        stored = StoredSample("bundle.zip", "copied.zip", str(copied), "application/zip", len(content),
                              "0" * 32, "0" * 40, hashlib.sha256(content).hexdigest())
        with patch.object(deferred_intake_worker, "configured_backend_keys", return_value={"drive"}), \
             patch.object(deferred_intake_worker, "backend_allowed_for_client", return_value=True), \
             patch.object(deferred_intake_worker, "copy_deferred_source", return_value=stored):
            self.assertTrue(deferred_intake_worker.process_next())
        updated = db.get_deferred_scan_submission(request.id)
        scan = db.get_scan(updated.scan_job_id)
        self.assertEqual(db.get_scan_batch(scan.batch_id).archive_mode, "extract_all")
        # The request keeps what the client asked for, so a retry still compares equal.
        self.assertEqual(updated.archive_mode, "lazy_extract_on_detection")


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class ArchiveHandlingPostgresTests(ArchiveHandlingIntegrationTests):
    postgres = True

    def test_container_and_members_share_the_report_snapshot(self):
        from app.services import archive_assessment, scan_report_read, scan_management
        original = archive_assessment.read
        for load in [lambda identifier: scan_report_read.report(identifier, automation=True).decision.action,
                     lambda identifier: scan_management.printable_report(identifier, automation=True).decision.action]:
            container, member = self.ready_archive()

            def concurrent_detection(connection, scan, decision):
                with db.connect() as writer:
                    writer.execute('UPDATE engine_results SET detected = ? WHERE scan_job_id = ?', (True, member.id))
                    writer.execute("UPDATE scan_jobs SET verdict = 'high', risk_score = 70 WHERE id = ?", (member.id,))
                return original(connection, scan, decision)

            with patch.object(archive_assessment, 'read', side_effect=concurrent_detection):
                self.assertEqual(load(container.id), 'allow')
            self.assertEqual(load(container.id), 'block')


if __name__ == "__main__":
    unittest.main()
