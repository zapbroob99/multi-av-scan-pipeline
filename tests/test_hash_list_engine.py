import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app import database as db
from app.engines.hash_list import check_hash_list_health, run_hash_list_engine
from app.models import ScanRecord
from app.services import engine_registry, hash_list_admin
from app.services.engine_setup import engine_setup_from_form
from app.services.scoring import calculate_risk
from app.services.worker_capabilities import control_api_engine_keys


BLOCKED = "a" * 64
ALLOWED = "b" * 64
UNLISTED = "c" * 64


def make_scan(sha256: str) -> ScanRecord:
    return ScanRecord(
        id=1, sample_id=1, case_name="Case", priority="Normal", note="", source="api",
        batch_id=None, parent_scan_id=None, relative_path=None, scan_role="standalone",
        service_client_id=None, scan_profile_id=None, profile_snapshot_json="",
        status="running", verdict="pending", risk_score=None,
        created_at="2026-09-23 00:00:00+00:00", started_at=None, completed_at=None,
        failed_at=None, attempt_count=0, last_error=None,
        original_filename="invoice.pdf", stored_filename="stored", storage_path="missing",
        content_type="application/pdf", size_bytes=10, md5="md5", sha1="sha1", sha256=sha256,
    )


class HashListDatabaseCase(unittest.TestCase):
    postgres = False

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.original = (db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED)
        db.close_pool()
        url = os.environ["MASP_TEST_POSTGRES_URL"] if self.postgres else ""
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = Path(self.temp.name) / "hash-list.db", url, False
        self.addCleanup(self._restore)
        if self.postgres:
            import psycopg
            with psycopg.connect(url, autocommit=True) as connection:
                connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
                connection.execute("CREATE SCHEMA public")
        db.init_db()
        self.assertEqual(db.add_hash_list_entries(
            [(BLOCKED, "block", "Incident 14 dropper"), (ALLOWED, "allow", "Signed internal installer")],
            "admin"), [])

    def _restore(self) -> None:
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def run_engine(self, sha256: str):
        result = run_hash_list_engine(make_scan(sha256))
        return result, json.loads(result.details_json), json.loads(result.findings_json)


class HashListEngineTests(HashListDatabaseCase):
    def test_unlisted_hash_completes_without_claiming_clean(self) -> None:
        result, details, findings = self.run_engine(UNLISTED)
        self.assertEqual(result.status, "completed")
        self.assertFalse(result.detected)
        self.assertEqual(details["outcome"], "no_match")
        self.assertEqual(findings, [])
        self.assertIn("not evidence that the file is clean", result.raw_output)

    def test_blocklist_match_is_a_detection(self) -> None:
        result, details, findings = self.run_engine(BLOCKED)
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.detected)
        self.assertEqual(result.severity, "high")
        self.assertEqual(result.signature, "HashList.Blocked")
        self.assertEqual(details["outcome"], "block_match")
        self.assertEqual(details["note"], "Incident 14 dropper")
        self.assertEqual([f["type"] for f in findings], ["hash_blocklist_match"])
        self.assertEqual(findings[0]["category"], "known_bad")

    def test_allowlist_match_is_informational_only(self) -> None:
        result, details, findings = self.run_engine(ALLOWED)
        self.assertEqual(result.status, "completed")
        self.assertFalse(result.detected)
        self.assertEqual(result.severity, "info")
        self.assertEqual(details["outcome"], "allow_match")
        self.assertEqual([f["type"] for f in findings], ["hash_allowlist_match"])
        self.assertEqual(findings[0]["severity"], "info")
        self.assertIn("does not suppress", result.raw_output)

    def test_allowlist_match_does_not_suppress_another_engines_detection(self) -> None:
        allowed, _, _ = self.run_engine(ALLOWED)
        results = [
            SimpleNamespace(engine_name=allowed.engine_name, status=allowed.status,
                            detected=allowed.detected, signature=allowed.signature),
            SimpleNamespace(engine_name="ClamAV", status="completed", detected=True, signature="Eicar"),
        ]
        self.assertIn(calculate_risk(results).verdict, {"high", "critical"})

    def test_lookup_uses_normalized_masp_digest(self) -> None:
        result, details, _ = self.run_engine(f"  {BLOCKED.upper()} ")
        self.assertTrue(result.detected)
        self.assertEqual(details["sha256"], BLOCKED)

    def test_malformed_digest_fails_instead_of_reporting_no_match(self) -> None:
        for value in ("", "sha256", "z" * 64, "a" * 63):
            with self.subTest(value=value):
                result, _, _ = self.run_engine(value)
                self.assertEqual(result.status, "failed")
                self.assertFalse(result.detected)

    def test_unreadable_list_fails_instead_of_reporting_no_match(self) -> None:
        with patch("app.engines.hash_list.get_hash_list_entry", side_effect=RuntimeError("db down")):
            result, _, _ = self.run_engine(BLOCKED)
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.detected)
        self.assertNotIn("db down", result.raw_output)

    def test_health_reports_list_sizes(self) -> None:
        health = check_hash_list_health()
        self.assertTrue(health["ok"])
        self.assertIn("1 blocked and 1 allowed", health["detail"])
        with patch("app.engines.hash_list.hash_list_counts", side_effect=RuntimeError("db down")):
            self.assertFalse(check_hash_list_health()["ok"])

    def test_registered_instance_runs_through_the_registry(self) -> None:
        instance_id = db.create_engine_instance("hash_list", "Hash List")
        instance = db.get_engine_instance_by_id(instance_id)
        self.assertTrue(engine_registry.run_engine(instance, make_scan(BLOCKED)).detected)
        # Never detection coverage: "not listed" proves nothing about the file.
        self.assertNotIn("Hash List", engine_registry.detection_engine_names(source="api"))


class HashListStorageTests(HashListDatabaseCase):
    def test_existing_hash_is_reported_and_never_reclassified(self) -> None:
        existing = db.add_hash_list_entries(
            [(BLOCKED, "allow", "mistake"), (UNLISTED, "block", "")], "admin")
        self.assertEqual(existing, [(BLOCKED, "block")])
        self.assertEqual(db.get_hash_list_entry(BLOCKED)["list_kind"], "block")
        self.assertEqual(db.get_hash_list_entry(UNLISTED)["list_kind"], "block")
        self.assertEqual(db.hash_list_counts(), {"block": 2, "allow": 1})

    def test_list_kind_is_constrained(self) -> None:
        # The API validates the kind first; this CHECK is the backstop. Its
        # exception class differs by database (PostgreSQL raises CheckViolation).
        with self.assertRaises(Exception):
            db.add_hash_list_entries([(UNLISTED, "maybe", "")], "admin")
        self.assertIsNone(db.get_hash_list_entry(UNLISTED))

    def test_schema_upgrade_is_repeatable(self) -> None:
        db.init_db()
        self.assertEqual(db.hash_list_counts(), {"block": 1, "allow": 1})


class HashListAdminReadTests(HashListDatabaseCase):
    def test_page_filters_escape_and_count_on_first_page_only(self) -> None:
        db.add_hash_list_entries([(UNLISTED, "block", "100% feed_x")], "admin")
        first = hash_list_admin.page(limit=2, before=None, kind="all", query="")
        self.assertEqual([row.sha256 for row in first.items], [UNLISTED, ALLOWED])
        self.assertEqual(first.counts.model_dump(), {"block": 2, "allow": 1})
        tail = hash_list_admin.page(limit=2, before=first.next_before, kind="all", query="")
        self.assertEqual([row.sha256 for row in tail.items], [BLOCKED])
        self.assertIsNone(tail.counts)
        self.assertIsInstance(tail.items[0].created_at, int)
        self.assertEqual([row.sha256 for row in hash_list_admin.page(
            limit=5, before=None, kind="all", query=BLOCKED.upper()).items], [BLOCKED])
        self.assertEqual([row.sha256 for row in hash_list_admin.page(
            limit=5, before=None, kind="all", query="% feed_").items], [UNLISTED])
        self.assertEqual(hash_list_admin.page(limit=5, before=None, kind="all", query="_").items[0].sha256, UNLISTED)
        self.assertEqual([row.sha256 for row in hash_list_admin.page(
            limit=5, before=None, kind="allow", query="").items], [ALLOWED])

    def test_remove_reports_a_missing_entry(self) -> None:
        entry_id = db.get_hash_list_entry(BLOCKED)["id"]
        hash_list_admin.remove(entry_id)
        self.assertIsNone(db.get_hash_list_entry(BLOCKED))
        with self.assertRaises(HTTPException) as raised:
            hash_list_admin.remove(entry_id)
        self.assertEqual(raised.exception.status_code, 404)


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class HashListEnginePostgresTests(HashListEngineTests):
    postgres = True


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class HashListStoragePostgresTests(HashListStorageTests):
    postgres = True


@unittest.skipUnless(os.getenv("MASP_TEST_POSTGRES_URL"), "requires disposable PostgreSQL")
class HashListAdminReadPostgresTests(HashListAdminReadTests):
    postgres = True


class HashListPlacementTests(unittest.TestCase):
    def test_adapter_is_a_single_database_bound_non_detection_engine(self) -> None:
        definition = engine_registry.adapter_definition("hash_list")
        capabilities = engine_registry.adapter_capabilities("hash_list")
        self.assertFalse(definition.detection)
        self.assertFalse(definition.configurable)
        self.assertTrue(capabilities.requires_database)
        self.assertFalse(capabilities.allows_multiple_instances)
        self.assertFalse(capabilities.consumes_external_quota)

    def test_control_api_worker_never_advertises_database_bound_adapters(self) -> None:
        with patch.dict(os.environ, {"MASP_WORKER_ENGINE_KEYS": "static_metadata,hash_list,file_type"}):
            self.assertEqual(control_api_engine_keys(), {"static_metadata", "file_type"})

    def test_default_linux_worker_runs_builtin_inspection_adapters(self) -> None:
        from app.services import worker_capabilities
        self.assertIn("file_type", worker_capabilities.POSIX_DEFAULT_ENGINE_KEYS)
        self.assertIn("hash_list", worker_capabilities.POSIX_DEFAULT_ENGINE_KEYS)


class BuiltinEngineSetupTests(unittest.TestCase):
    def test_hash_list_needs_only_a_name(self) -> None:
        self.assertEqual(engine_setup_from_form("hash_list", {"engine_display_name": "Hashes"}), ("Hashes", {}))

    def test_file_type_setup_is_creatable_and_validated(self) -> None:
        form = {"engine_display_name": "File Type", "file_type_header_bytes": "4096",
                "file_type_mismatch_action": "detect"}
        self.assertEqual(engine_setup_from_form("file_type", form),
                         ("File Type", {"header_bytes": "4096", "mismatch_action": "detect"}))
        for key, value in (("file_type_header_bytes", "100"), ("file_type_mismatch_action", "block")):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    engine_setup_from_form("file_type", {**form, key: value})


if __name__ == "__main__":
    unittest.main()
