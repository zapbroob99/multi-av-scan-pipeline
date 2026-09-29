import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database as db
from app.services import storage_inventory as inventory
from app.services.content_types import classify
from app.services.deferred_storage import BackendScope, backend_allowed_for_client
from app.services.notification_delivery import deliver_next
from app.services.storage_policy import StoragePolicy, choose_tier, evaluate_light, parse_policy
from app.services import storage_protection
from app.services.storage_protection import run_location_cycle

PE = b"MZ" + b"\x00" * 200
PDF = b"%PDF-1.7\n" + b"x" * 200
LNK = b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F" + b"\x00" * 60
OOXML = b"PK\x03\x04" + b"\x00" * 26 + b"[Content_Types].xml" + b"\x00" * 50
ZIP = b"PK\x03\x04" + b"\x00" * 26 + b"readme.txt" + b"\x00" * 50


class ClassificationTests(unittest.TestCase):
    def test_families_from_header_and_extension(self) -> None:
        self.assertEqual(classify(PE, "tool.exe").content_family, "executable")
        self.assertEqual(classify(LNK, "invoice.lnk").detected_type, "lnk")
        self.assertEqual(classify(b"\xcf\xfa\xed\xfe" + b"\x00" * 20, "a").content_family, "executable")
        self.assertEqual(classify(OOXML, "report.docx").detected_type, "ooxml")
        self.assertFalse(classify(OOXML, "report.docx").mismatch)
        self.assertEqual(classify(ZIP, "bundle.zip").content_family, "archive")

    def test_scripts_are_known_only_by_extension_or_shebang(self) -> None:
        batch = classify(b"@echo off\r\n", "run.bat")
        self.assertEqual(batch.content_family, "unrecognized")
        self.assertIn("script", batch.families)
        self.assertIn("script", classify(b"#!/bin/sh\n", "setup").families)
        self.assertEqual(classify(b"@echo off\r\n", "run.txt").families, frozenset({"unrecognized"}))

    def test_disguised_executable_is_a_mismatch(self) -> None:
        disguised = classify(PE, "contract.pdf")
        self.assertTrue(disguised.mismatch)
        self.assertEqual(disguised.content_family, "executable")


class PolicyTests(unittest.TestCase):
    def test_defaults_and_validation(self) -> None:
        policy = parse_policy(None)
        self.assertEqual(policy.default_tier, "full")
        self.assertEqual(policy.type_policy.families, ["executable", "script"])
        with self.assertRaises(ValueError):
            parse_policy({"type_policy": {"mode": "denylist", "families": ["binaries"]}})
        with self.assertRaises(ValueError):
            parse_policy({"tier_rules": [{"tier": "light", "min_bytes": 10, "max_bytes": 5}]})
        with self.assertRaises(ValueError):
            parse_policy({"unexpected": True})

    def test_first_matching_rule_wins(self) -> None:
        policy = StoragePolicy.model_validate({"default_tier": "full", "tier_rules": [
            {"pattern": "bulk/*", "tier": "light"},
            {"pattern": "*", "min_bytes": 100, "tier": "light"},
        ]})
        self.assertEqual(choose_tier(policy, "bulk/a.csv", 5), "light")
        self.assertEqual(choose_tier(policy, "docs/a.pdf", 500), "light")
        self.assertEqual(choose_tier(policy, "docs/a.pdf", 5), "full")
        self.assertEqual(choose_tier(policy, "docs/deep/a.pdf", 500), "light")

    def test_denylist_detects_code_at_high_severity(self) -> None:
        outcome = evaluate_light(StoragePolicy(), classify(PE, "tool.exe"), None)
        self.assertTrue(outcome.detected)
        self.assertEqual([(f.kind, f.severity) for f in outcome.findings], [("type_policy", "high")])

    def test_allowlist_rejects_anything_not_listed(self) -> None:
        policy = StoragePolicy.model_validate({"type_policy": {"mode": "allowlist", "families": ["pdf", "office"]}})
        self.assertFalse(evaluate_light(policy, classify(PDF, "a.pdf"), None).findings)
        image = evaluate_light(policy, classify(b"\x89PNG\r\n\x1a\n", "a.png"), None)
        self.assertEqual([(f.kind, f.severity, f.detected) for f in image.findings],
                         [("type_policy", "medium", True)])

    def test_archive_actions(self) -> None:
        classification = classify(ZIP, "bundle.zip")
        self.assertTrue(evaluate_light(StoragePolicy(), classification, None).escalate_to_full)
        allow = StoragePolicy.model_validate({"archive_action": "allow"})
        self.assertEqual(evaluate_light(allow, classification, None).findings, ())
        detect = StoragePolicy.model_validate({"archive_action": "detect"})
        self.assertEqual([f.kind for f in evaluate_light(detect, classification, None).findings], ["archive_policy"])

    def test_non_code_mismatch_is_a_finding_not_a_detection(self) -> None:
        policy = StoragePolicy.model_validate({"type_policy": {"mode": "denylist", "families": []}})
        outcome = evaluate_light(policy, classify(PDF, "photo.png"), None)
        self.assertEqual([(f.kind, f.detected) for f in outcome.findings], [("type_mismatch", False)])
        self.assertFalse(outcome.detected)

    def test_hash_block_detects_and_allow_is_silent(self) -> None:
        policy = StoragePolicy.model_validate({"type_policy": {"mode": "denylist", "families": []}})
        self.assertEqual([f.kind for f in evaluate_light(policy, classify(PDF, "a.pdf"), "block").findings],
                         ["hash_block"])
        self.assertEqual(evaluate_light(policy, classify(PDF, "a.pdf"), "allow").findings, ())


class BackendScopeTests(unittest.TestCase):
    def test_prefix_coverage(self) -> None:
        scope = BackendScope(False, ("uploads/",), "environment")
        self.assertTrue(scope.covers_prefix("uploads"))
        self.assertTrue(scope.covers_prefix("uploads/2026"))
        self.assertFalse(scope.covers_prefix("up"))
        self.assertFalse(scope.covers_prefix(""))
        self.assertTrue(BackendScope(True, (), "custom").covers_prefix(""))


class StorageCycleCase(unittest.TestCase):
    postgres = False

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.share = self.root / "share"
        (self.share / "data" / "sub").mkdir(parents=True)
        self.original = (db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED)
        db.close_pool()
        url = os.environ["MASP_TEST_POSTGRES_URL"] if self.postgres else ""
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.root / "storage.db", url, False
        self.addCleanup(self._restore)
        if self.postgres:
            import psycopg
            with psycopg.connect(url, autocommit=True) as connection:
                connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
                connection.execute("CREATE SCHEMA public")
        db.init_db()
        self.client_id = db.create_service_client("storage", "Storage")
        engine = db.create_engine_instance("static_metadata", "Metadata")
        self.profile_id = db.create_scan_profile(self.client_id, "Default", engine_instance_ids=[engine],
                                                 is_default=True)
        self.env = patch.dict(os.environ, {
            "MASP_DEFERRED_STORAGE_BACKENDS_JSON": json.dumps({"share": str(self.share)}),
            "MASP_DEFERRED_BACKEND_CLIENTS_JSON": json.dumps({"share": {"storage": "data/"}}),
        }, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.now = int(time.time())

    def _restore(self) -> None:
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def location(self, policy: dict | None = None, *, prefix: str = "data") -> inventory.StorageLocation:
        base = {"default_tier": "light", "stability_seconds": 60}
        location_id = inventory.create_location(
            name=f"Location {prefix}", service_client_id=self.client_id, scan_profile_id=self.profile_id,
            backend_key="share", prefix=prefix, mode="crawl", policy=parse_policy({**base, **(policy or {})}))
        self.assertTrue(inventory.claim_location(location_id, "worker-a", 300, self.now))
        return inventory.get_location(location_id)

    def cycle(self, location: inventory.StorageLocation, offset: int = 0):
        return run_location_cycle(location, "worker-a", self.now + offset)

    def objects(self) -> dict[str, dict]:
        with db.connect() as connection:
            return {str(row["object_id"]): dict(row) for row in connection.execute(
                "SELECT * FROM storage_objects ORDER BY id").fetchall()}

    def findings(self) -> list[dict]:
        with db.connect() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM storage_findings ORDER BY id").fetchall()]

    def outbox(self) -> list[dict]:
        with db.connect() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM storage_notification_outbox ORDER BY id").fetchall()]

    def write(self, relative: str, body: bytes) -> Path:
        path = self.share.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return path


class StorageCycleTests(StorageCycleCase):
    def test_crawl_waits_for_stability_then_inspects(self) -> None:
        self.write("data/report.pdf", PDF)
        self.write("data/sub/tool.exe", PE)
        self.write("data/contract.pdf", PE)
        self.write("data/upload.tmp", PE)
        location = self.location()

        first = self.cycle(location)
        self.assertEqual((first.new, first.inspected), (3, 0))
        self.assertEqual({row["state"] for row in self.objects().values()}, {"waiting"})
        self.assertNotIn("data/upload.tmp", self.objects())

        second = self.cycle(location, 61)
        self.assertEqual((second.crawled, second.inspected), (0, 3))
        objects = self.objects()
        self.assertEqual(objects["data/report.pdf"]["state"], "light_passed")
        self.assertEqual(objects["data/report.pdf"]["finding_count"], 0)
        self.assertEqual(objects["data/sub/tool.exe"]["state"], "light_detected")
        self.assertEqual(objects["data/contract.pdf"]["state"], "light_detected")
        self.assertEqual(len(objects["data/report.pdf"]["sha256"]), 64)
        kinds = sorted((row["object_id"], row["kind"]) for row in self.findings())
        self.assertEqual(kinds, [("data/contract.pdf", "type_mismatch"), ("data/contract.pdf", "type_policy"),
                                 ("data/sub/tool.exe", "type_policy")])
        self.assertEqual(len(self.outbox()), 3)
        payload = json.loads(self.outbox()[0]["payload_json"])
        self.assertEqual(payload["event_type"], "storage.finding")
        self.assertEqual(payload["inspection"], "light")
        self.assertEqual(payload["client"]["key"], "storage")

        # Nothing new: no crawl before the interval, no duplicate findings.
        third = self.cycle(location, 120)
        self.assertEqual((third.crawled, third.inspected, third.findings), (0, 0, 0))

    def test_change_after_inspection_is_inspected_again(self) -> None:
        path = self.write("data/report.pdf", PDF)
        location = self.location({"crawl_interval_seconds": 10})
        self.cycle(location)
        self.cycle(location, 61)
        path.write_bytes(PE)
        os.utime(path, ns=(time.time_ns(), time.time_ns() + 5_000_000_000))
        changed = self.cycle(location, 80)
        self.assertEqual(changed.changed, 1)
        self.assertEqual(self.objects()["data/report.pdf"]["state"], "changed")
        self.assertIsNone(self.objects()["data/report.pdf"]["sha256"])
        self.cycle(location, 80 + 61)
        self.assertEqual(self.objects()["data/report.pdf"]["state"], "light_detected")

    def test_file_changed_since_crawl_is_not_judged(self) -> None:
        path = self.write("data/report.pdf", PDF)
        location = self.location()
        self.cycle(location)
        path.write_bytes(PDF + b"more")
        self.cycle(location, 61)
        row = self.objects()["data/report.pdf"]
        self.assertEqual(row["state"], "changed")
        self.assertEqual(row["size_bytes"], len(PDF) + 4)
        self.assertEqual(self.findings(), [])

    def test_removal_needs_a_complete_pass(self) -> None:
        self.write("data/report.pdf", PDF)
        path = self.write("data/sub/old.pdf", PDF)
        location = self.location({"crawl_interval_seconds": 10})
        self.cycle(location)
        path.unlink()
        real_scandir = os.scandir

        def failing(directory):
            if str(directory).endswith("sub"):
                raise PermissionError("denied")
            return real_scandir(directory)

        (self.share / "data" / "sub").mkdir(exist_ok=True)
        with patch.object(storage_protection.os, "scandir", side_effect=failing):
            incomplete = self.cycle(location, 20)
        self.assertEqual((incomplete.directory_errors, incomplete.removed), (1, 0))
        self.assertNotEqual(self.objects()["data/sub/old.pdf"]["state"], "removed")
        complete = self.cycle(location, 40)
        self.assertEqual(complete.removed, 1)
        self.assertEqual(self.objects()["data/sub/old.pdf"]["state"], "removed")

    def test_full_tier_and_archives_wait_without_being_read(self) -> None:
        self.write("data/big.pdf", PDF)
        self.write("data/small/bundle.zip", ZIP)
        location = self.location({"tier_rules": [{"pattern": "big.pdf", "tier": "full"}]})
        self.cycle(location)
        opened = []
        real_open = storage_protection.open_deferred_source

        def tracking(backend, object_id):
            opened.append(object_id)
            return real_open(backend, object_id)

        with patch.object(storage_protection, "open_deferred_source", side_effect=tracking):
            self.cycle(location, 61)
        objects = self.objects()
        self.assertEqual(objects["data/big.pdf"]["state"], "full_pending")
        self.assertEqual(objects["data/small/bundle.zip"]["state"], "full_pending")
        self.assertEqual(opened, ["data/small/bundle.zip"])

    def test_hash_blocklist_match_is_a_detection(self) -> None:
        import hashlib
        self.write("data/report.pdf", PDF)
        db.add_hash_list_entries([(hashlib.sha256(PDF).hexdigest(), "block", "known bad")], "admin")
        location = self.location({"type_policy": {"mode": "denylist", "families": []}})
        self.cycle(location)
        self.cycle(location, 61)
        self.assertEqual([row["kind"] for row in self.findings()], ["hash_block"])
        self.assertEqual(self.objects()["data/report.pdf"]["hash_list_kind"], "block")

    def test_large_files_skip_hashing_when_configured(self) -> None:
        self.write("data/report.pdf", PDF)
        location = self.location({"hash_check": {"enabled": True, "max_bytes": 10}})
        self.cycle(location)
        self.cycle(location, 61)
        row = self.objects()["data/report.pdf"]
        self.assertEqual(row["state"], "light_passed")
        self.assertIsNone(row["sha256"])

    def test_location_outside_the_grant_does_nothing(self) -> None:
        self.write("other/tool.exe", PE)
        location = self.location(prefix="other")
        result = self.cycle(location)
        self.assertEqual((result.crawled, result.inspected), (0, 0))
        self.assertEqual(self.objects(), {})
        runtime = inventory.get_runtime(location.id)
        self.assertIsNone(runtime.pass_id)
        with db.connect() as connection:
            record = json.loads(connection.execute(
                "SELECT last_cycle_json FROM storage_location_runtime WHERE location_id = ?",
                (location.id,)).fetchone()["last_cycle_json"])
        self.assertFalse(record["ok"])
        self.assertIn("grant", record["error"])

    def test_disabled_client_stops_the_location(self) -> None:
        self.write("data/tool.exe", PE)
        location = self.location()
        db.update_service_client(self.client_id, display_name="Storage", enabled=False)
        self.assertEqual(self.cycle(location).crawled, 0)

    def test_invalid_stored_policy_stops_only_its_location(self) -> None:
        self.write("data/tool.exe", PE)
        location = self.location()
        with db.connect() as connection:
            connection.execute("UPDATE storage_locations SET policy_json = ? WHERE id = ?",
                               ('{"default_tier": "sideways"}', location.id))
        broken = inventory.get_location(location.id)
        self.assertIn("invalid", broken.policy_error)
        self.assertEqual([item.id for item in inventory.enabled_locations(["share"])], [location.id])
        self.assertEqual(self.cycle(broken).crawled, 0)
        self.assertEqual(self.objects(), {})

    def test_lease_keeps_a_second_worker_out(self) -> None:
        location = self.location()
        self.assertFalse(inventory.claim_location(location.id, "worker-b", 300, self.now + 10))
        self.assertTrue(inventory.claim_location(location.id, "worker-b", 300, self.now + 301))

    def test_storage_finding_is_delivered_to_the_webhook(self) -> None:
        self.write("data/tool.exe", PE)
        location = self.location()
        self.cycle(location)
        self.cycle(location, 61)
        sent = []

        class Response:
            status = 204

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_urlopen(request, timeout):
            sent.append(json.loads(request.data))
            return Response()

        with patch.dict(os.environ, {"MASP_SIEM_WEBHOOK_URL": "https://siem.example/hook"}), \
                patch("app.services.notification_delivery.urlopen", side_effect=fake_urlopen):
            self.assertTrue(deliver_next("notify-1"))
            self.assertFalse(deliver_next("notify-1"))
        self.assertEqual(sent[0]["event_type"], "storage.finding")
        self.assertEqual(self.outbox()[0]["status"], "delivered")

    def test_scope_allows_the_prefix_objects_only(self) -> None:
        self.assertTrue(backend_allowed_for_client("share", "storage", "data/a.pdf"))
        self.assertFalse(backend_allowed_for_client("share", "storage", "other/a.pdf"))


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class StorageCyclePostgresTests(StorageCycleTests):
    postgres = True


if __name__ == "__main__":
    unittest.main()
