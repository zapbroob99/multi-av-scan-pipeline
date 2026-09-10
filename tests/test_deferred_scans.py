import tempfile
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database
from app.models import ApiClientIdentity, StoredSample
from app.services.deferred_storage import (
    DeferredSourceChangedError,
    DeferredSourceError,
    DeferredSourcePolicyError,
    backend_allowed_for_client,
    copy_deferred_source,
    open_deferred_source,
    resolve_source_path,
    validate_object_id,
)
from app.services.notification_delivery import deliver_next, validate_webhook_url
from app.services.service_clients import (
    engines_for_profile,
    engines_for_snapshot_json,
    profile_snapshot_json,
)


class DeferredScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.temp_dir.name)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = self.root / "deferred.db"
        database.DATABASE_URL = ""
        database.init_db()
        self.engine_id = database.create_engine_instance("static_metadata", "Metadata")
        self.client_id, self.profile_id, _ = database.create_service_client_bundle(
            client_key="drive",
            display_name="Drive",
            profile_name="Deferred",
            engine_instance_ids=[self.engine_id],
            credential_label="test",
            token_hash="a" * 64,
            token_prefix="aaaaaaaa",
        )
        client = database.get_service_client(self.client_id)
        profile = database.get_scan_profile(self.profile_id)
        assert client is not None and profile is not None
        identity = ApiClientIdentity(client, profile)
        self.engines = engines_for_profile(self.profile_id, source="api")
        self.snapshot = profile_snapshot_json(
            identity,
            self.engines,
            delivery_mode="security_events_only",
            client_request_id="drive-1",
        )

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def create_request(self, object_id: str = "folder/sample.bin"):
        return database.create_deferred_scan_submission(
            service_client_id=self.client_id,
            scan_profile_id=self.profile_id,
            client_request_id="drive-1",
            backend_key="drive",
            object_id=object_id,
            original_filename="sample.bin",
            content_type="application/octet-stream",
            expected_size_bytes=7,
            expected_sha256=None,
            archive_mode="container",
            case_name="Drive",
            priority="Normal",
            note="",
            profile_snapshot_json=self.snapshot,
        )

    def test_submission_is_idempotent_but_object_reference_is_immutable(self) -> None:
        first, created = self.create_request()
        duplicate, duplicate_created = self.create_request()

        self.assertTrue(created)
        self.assertFalse(duplicate_created)
        self.assertEqual(first.id, duplicate.id)
        with self.assertRaises(ValueError):
            self.create_request("folder/other.bin")

    def test_object_id_rejects_absolute_and_parent_paths(self) -> None:
        self.assertEqual(validate_object_id("folder/sample.bin"), "folder/sample.bin")
        for unsafe in ("../secret", "/etc/passwd", "folder/../../secret", "C:/file", "folder/file:secret", "bad\x00name"):
            with self.subTest(unsafe=unsafe), self.assertRaises(DeferredSourceError):
                validate_object_id(unsafe)

    def test_hardlink_cannot_alias_another_clients_object(self) -> None:
        source = self.root / "other.bin"
        source.write_bytes(b"payload")
        alias = self.root / "allowed.bin"
        try:
            os.link(source, alias)
        except OSError as exc:
            self.skipTest(f"Hardlinks unavailable: {exc}")
        with patch("app.services.deferred_storage.configured_backends", return_value={"drive": self.root}):
            with self.assertRaises(DeferredSourcePolicyError):
                with open_deferred_source("drive", "allowed.bin"):
                    self.fail("A hardlinked source must never be readable")

    def test_symlink_inside_same_backend_cannot_cross_client_prefix(self) -> None:
        source = self.root / "other.bin"
        source.write_bytes(b"payload")
        alias = self.root / "allowed.bin"
        try:
            alias.symlink_to(source)
        except OSError as exc:
            self.skipTest(f"Symlink creation unavailable: {exc}")
        with patch("app.services.deferred_storage.configured_backends", return_value={"drive": self.root}):
            with self.assertRaises(DeferredSourcePolicyError):
                resolve_source_path("drive", "allowed.bin")

    @unittest.skipUnless(os.name == "nt", "Windows opened-handle validation")
    def test_windows_opened_handle_must_match_authorized_path(self) -> None:
        (self.root / "allowed.bin").write_bytes(b"payload")
        with patch("app.services.deferred_storage.configured_backends", return_value={"drive": self.root}), \
             patch("app.services.deferred_storage._windows_opened_path", return_value=self.root / "other.bin"):
            with self.assertRaises(DeferredSourcePolicyError):
                with open_deferred_source("drive", "allowed.bin"):
                    self.fail("A substituted opened handle must never be readable")

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-relative validation")
    def test_posix_symlink_swap_after_validation_is_rejected(self) -> None:
        source = self.root / "other.bin"
        source.write_bytes(b"payload")
        alias = self.root / "allowed.bin"
        alias.symlink_to(source)
        with patch("app.services.deferred_storage.configured_backends", return_value={"drive": self.root}), \
             patch("app.services.deferred_storage.resolve_source_path", return_value=alias):
            with self.assertRaises(DeferredSourcePolicyError):
                with open_deferred_source("drive", "allowed.bin"):
                    self.fail("A post-validation symlink swap must never be readable")

    def test_unavailable_snapshot_fails_permanently_before_copy(self) -> None:
        from app.workers import deferred_intake_worker

        request, _ = self.create_request()
        with database.connect() as connection:
            connection.execute("UPDATE engine_instances SET enabled = 0 WHERE id = ?", (self.engine_id,))
        with patch.object(deferred_intake_worker, "configured_backend_keys", return_value={"drive"}), \
             patch.object(deferred_intake_worker, "backend_allowed_for_client", return_value=True), \
             patch.object(deferred_intake_worker, "copy_deferred_source") as copy:
            self.assertTrue(deferred_intake_worker.process_next())
        copy.assert_not_called()
        with database.connect() as connection:
            row = connection.execute("SELECT status FROM deferred_scan_submissions WHERE id = ?", (request.id,)).fetchone()
        self.assertEqual(row["status"], "failed")

    def test_multiple_backends_fail_closed_across_service_clients(self) -> None:
        environment = {
            "MASP_DEFERRED_STORAGE_BACKENDS_JSON": (
                '{"drive":"C:/drive","transfer":"C:/transfer"}'
            ),
            "MASP_DEFERRED_BACKEND_CLIENTS_JSON": "",
        }
        with patch.dict("os.environ", environment, clear=False):
            self.assertFalse(backend_allowed_for_client("drive", "drive"))
            self.assertFalse(backend_allowed_for_client("transfer", "drive"))

    def test_single_backend_requires_explicit_client_mapping(self) -> None:
        environment = {
            "MASP_DEFERRED_STORAGE_BACKENDS_JSON": '{"shared":"C:/shared"}',
            "MASP_DEFERRED_BACKEND_CLIENTS_JSON": "",
        }
        with patch.dict("os.environ", environment, clear=False):
            self.assertFalse(backend_allowed_for_client("shared", "drive"))

    def test_explicit_backend_client_mapping_allows_shared_backend(self) -> None:
        environment = {
            "MASP_DEFERRED_STORAGE_BACKENDS_JSON": '{"shared":"C:/shared"}',
            "MASP_DEFERRED_BACKEND_CLIENTS_JSON": '{"shared":["drive"]}',
        }
        with patch.dict("os.environ", environment, clear=False):
            self.assertTrue(backend_allowed_for_client("shared", "drive"))
            self.assertFalse(backend_allowed_for_client("shared", "transfer"))

    def test_backend_client_mapping_can_constrain_object_prefix(self) -> None:
        environment = {
            "MASP_DEFERRED_STORAGE_BACKENDS_JSON": '{"shared":"C:/shared"}',
            "MASP_DEFERRED_BACKEND_CLIENTS_JSON": (
                '{"shared":{"drive":["drive/inbox"],"transfer":["transfer"]}}'
            ),
        }
        with patch.dict("os.environ", environment, clear=False):
            self.assertTrue(
                backend_allowed_for_client("shared", "drive", "drive/inbox/a.bin")
            )
            self.assertFalse(
                backend_allowed_for_client("shared", "drive", "transfer/a.bin")
            )

    def test_existing_non_file_source_is_a_permanent_policy_failure(self) -> None:
        source_root = self.root / "source"
        (source_root / "folder").mkdir(parents=True)
        with patch.dict(
            "os.environ",
            {
                "MASP_DEFERRED_STORAGE_BACKENDS_JSON": (
                    f'{{"drive":"{source_root.as_posix()}"}}'
                )
            },
            clear=False,
        ):
            with self.assertRaises(DeferredSourcePolicyError):
                resolve_source_path("drive", "folder")

    def test_intake_copies_and_hash_verifies_source_then_creates_scan(self) -> None:
        source_root = self.root / "source"
        source = source_root / "folder" / "sample.bin"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"payload")
        request, _ = self.create_request()
        claimed = database.claim_next_deferred_scan_submission(
            {"drive"}, "intake-1", lease_seconds=60, now=100
        )
        assert claimed is not None

        samples = self.root / "samples"
        with (
            patch.dict(
                "os.environ",
                {"MASP_DEFERRED_STORAGE_BACKENDS_JSON": f'{{"drive":"{source_root.as_posix()}"}}'},
                clear=False,
            ),
            patch("app.services.deferred_storage.SAMPLES_DIR", samples),
        ):
            stored = copy_deferred_source(claimed)

        self.assertEqual(Path(stored.storage_path).read_bytes(), b"payload")
        scan_id = database.complete_deferred_scan_intake(
            submission_id=request.id,
            worker_id="intake-1",
            generation=claimed.attempt_count,
            sample=stored,
            engines=self.engines,
            archive_format=None,
        )
        self.assertIsNotNone(scan_id)
        updated = database.get_deferred_scan_submission(request.id)
        assert updated is not None
        self.assertEqual(updated.status, "queued")
        self.assertEqual(updated.scan_job_id, scan_id)

    def test_expected_hash_mismatch_removes_copied_file(self) -> None:
        source_root = self.root / "source"
        source = source_root / "folder" / "sample.bin"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"payload")
        request, _ = self.create_request()
        request = request.__class__(
            **{**request.__dict__, "expected_sha256": "0" * 64}
        )
        samples = self.root / "samples"
        with (
            patch.dict(
                "os.environ",
                {"MASP_DEFERRED_STORAGE_BACKENDS_JSON": f'{{"drive":"{source_root.as_posix()}"}}'},
                clear=False,
            ),
            patch("app.services.deferred_storage.SAMPLES_DIR", samples),
        ):
            with self.assertRaises(DeferredSourceChangedError):
                copy_deferred_source(request)
        self.assertEqual(list(samples.glob("*")), [])

    def test_max_bytes_policy_violation_is_permanent(self) -> None:
        source_root = self.root / "source"
        source = source_root / "folder" / "sample.bin"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"payload")
        request, _ = self.create_request()
        samples = self.root / "samples"
        with (
            patch.dict(
                "os.environ",
                {
                    "MASP_DEFERRED_STORAGE_BACKENDS_JSON": f'{{"drive":"{source_root.as_posix()}"}}',
                    "MASP_DEFERRED_MAX_BYTES": "3",
                },
                clear=False,
            ),
            patch("app.services.deferred_storage.SAMPLES_DIR", samples),
        ):
            with self.assertRaises(DeferredSourcePolicyError):
                copy_deferred_source(request)
        self.assertEqual(list(samples.glob("*")), [])

    def test_idempotency_key_rejects_changed_metadata_payload(self) -> None:
        self.create_request()
        with self.assertRaises(ValueError):
            database.create_deferred_scan_submission(
                service_client_id=self.client_id,
                scan_profile_id=self.profile_id,
                client_request_id="drive-1",
                backend_key="drive",
                object_id="folder/sample.bin",
                original_filename="renamed.bin",
                content_type="application/octet-stream",
                expected_size_bytes=7,
                expected_sha256=None,
                archive_mode="container",
                case_name="Drive",
                priority="Normal",
                note="",
                profile_snapshot_json=self.snapshot,
            )

    def test_strict_snapshot_resolution_rejects_disabled_engine(self) -> None:
        database.update_engine_instance_by_id(self.engine_id, enabled=False)
        with self.assertRaises(ValueError):
            engines_for_snapshot_json(self.snapshot, source="api", strict=True)

    def test_intake_keeps_snapshot_engine_name_after_instance_rename(self) -> None:
        database.update_engine_instance_by_id(
            self.engine_id, display_name="Metadata Renamed Later"
        )

        engines = engines_for_snapshot_json(self.snapshot, source="api", strict=True)

        self.assertEqual([engine.display_name for engine in engines], ["Metadata"])
        request, _ = self.create_request()
        claimed = database.claim_next_deferred_scan_submission(
            {"drive"}, "intake-1", lease_seconds=60, now=100
        )
        assert claimed is not None
        stored_path = self.root / "snapshot-name.bin"
        stored_path.write_bytes(b"payload")
        scan_id = database.complete_deferred_scan_intake(
            submission_id=request.id,
            worker_id="intake-1",
            generation=claimed.attempt_count,
            sample=StoredSample(
                "sample.bin",
                "snapshot-name.bin",
                str(stored_path),
                "application/octet-stream",
                7,
                "0" * 32,
                "0" * 40,
                "1" * 64,
            ),
            engines=engines,
            archive_format=None,
        )

        assert scan_id is not None
        jobs = database.list_scan_engine_jobs(scan_id)
        self.assertEqual([job.engine_name for job in jobs], ["Metadata"])

    def test_intake_revalidates_backend_acl_before_copy(self) -> None:
        request, _ = self.create_request()
        source_root = self.root / "source"
        source_root.mkdir()
        from app.workers import deferred_intake_worker

        with patch.dict(
            "os.environ",
            {
                "MASP_DEFERRED_STORAGE_BACKENDS_JSON": f'{{"drive":"{source_root.as_posix()}"}}',
                "MASP_DEFERRED_BACKEND_CLIENTS_JSON": "{}",
            },
            clear=False,
        ):
            self.assertTrue(deferred_intake_worker.process_next())
        updated = database.get_deferred_scan_submission(request.id)
        assert updated is not None
        self.assertEqual(updated.status, "failed")
        self.assertIn("no longer authorized", updated.last_error or "")

    def test_completion_writes_and_delivers_idempotent_outbox_event(self) -> None:
        source_path = self.root / "stored.bin"
        source_path.write_bytes(b"payload")
        request, _ = self.create_request()
        claimed = database.claim_next_deferred_scan_submission(
            {"drive"}, "intake-1", lease_seconds=60, now=100
        )
        assert claimed is not None
        scan_id = database.complete_deferred_scan_intake(
            submission_id=request.id,
            worker_id="intake-1",
            generation=claimed.attempt_count,
            sample=StoredSample(
                "sample.bin", "stored.bin", str(source_path),
                "application/octet-stream", 7, "0" * 32, "0" * 40, "1" * 64,
            ),
            engines=self.engines,
            archive_format=None,
        )
        assert scan_id is not None
        self.assertTrue(database.transition_scan_to_completed(scan_id, "high", 70))
        event = database.claim_next_notification_outbox(
            "notify-1", lease_seconds=60, now=200
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.event_type, "malware.detected")
        self.assertIn('"client_request_id":"drive-1"', event.payload_json)
        self.assertTrue(
            database.mark_notification_delivered(
                event.id, "notify-1", event.attempt_count
            )
        )
        self.assertIsNone(
            database.claim_next_notification_outbox(
                "notify-2", lease_seconds=60, now=300
            )
        )

    def test_undelivered_outbox_blocks_retention_and_delete(self) -> None:
        source_path = self.root / "stored.bin"
        source_path.write_bytes(b"payload")
        request, _ = self.create_request()
        claimed = database.claim_next_deferred_scan_submission(
            {"drive"}, "intake-1", lease_seconds=60, now=100
        )
        assert claimed is not None

        scan_id = database.complete_deferred_scan_intake(
            submission_id=request.id,
            worker_id="intake-1",
            generation=claimed.attempt_count,
            sample=StoredSample(
                "sample.bin", "stored.bin", str(source_path),
                "application/octet-stream", 7, "0" * 32, "0" * 40, "1" * 64,
            ),
            engines=self.engines,
            archive_format=None,
        )
        assert scan_id is not None
        self.assertTrue(database.transition_scan_to_completed(scan_id, "critical", 95))
        with database.connect() as connection:
            connection.execute(
                """UPDATE scan_jobs
                   SET completed_at = '2020-01-01 00:00:00'
                   WHERE id = ?""",
                (scan_id,),
            )
        self.assertEqual(database.count_scans_older_than("2021-01-01 00:00:00"), 0)
        self.assertEqual(database.list_scans_older_than("2021-01-01 00:00:00"), [])
        self.assertIsNone(database.delete_scan(scan_id))

    def test_retention_never_selects_long_lived_queued_scan(self) -> None:
        source_path = self.root / "queued.bin"
        source_path.write_bytes(b"payload")
        queued_id = database.create_scan_job(
            database.create_sample(
                StoredSample(
                    "queued.bin", "queued.bin", str(source_path),
                    "application/octet-stream", 7, "0" * 32, "0" * 40, "1" * 64,
                )
            ),
            case_name="Deferred",
            priority="Normal",
            note="",
            source="api",
            service_client_id=self.client_id,
            scan_profile_id=self.profile_id,
            profile_snapshot_json=self.snapshot,
        )
        with database.connect() as connection:
            connection.execute(
                "UPDATE scan_jobs SET created_at = '2020-01-01 00:00:00' WHERE id = ?",
                (queued_id,),
            )
        self.assertEqual(database.count_scans_older_than("2021-01-01 00:00:00"), 0)
        self.assertEqual(database.list_scans_older_than("2021-01-01 00:00:00"), [])

    def test_retention_age_starts_when_deferred_scan_finishes(self) -> None:
        source_path = self.root / "completed.bin"
        source_path.write_bytes(b"payload")
        scan_id = database.create_scan_job(
            database.create_sample(
                StoredSample(
                    "completed.bin", "completed.bin", str(source_path),
                    "application/octet-stream", 7, "0" * 32, "0" * 40, "1" * 64,
                )
            ),
            case_name="Deferred",
            priority="Normal",
            note="",
            source="api",
            service_client_id=self.client_id,
            scan_profile_id=self.profile_id,
            profile_snapshot_json=self.snapshot,
        )
        with database.connect() as connection:
            connection.execute(
                """UPDATE scan_jobs
                   SET status = 'completed',
                       created_at = '2020-01-01 00:00:00',
                       completed_at = '2026-01-01 00:00:00'
                   WHERE id = ?""",
                (scan_id,),
            )
        self.assertEqual(database.count_scans_older_than("2025-01-01 00:00:00"), 0)

    def test_notification_delivery_requires_https_and_signs_payload(self) -> None:
        source_path = self.root / "stored.bin"
        source_path.write_bytes(b"payload")
        request, _ = self.create_request()
        claimed = database.claim_next_deferred_scan_submission(
            {"drive"}, "intake-1", lease_seconds=60, now=100
        )
        assert claimed is not None
        scan_id = database.complete_deferred_scan_intake(
            submission_id=request.id,
            worker_id="intake-1",
            generation=claimed.attempt_count,
            sample=StoredSample(
                "sample.bin", "stored.bin", str(source_path),
                "application/octet-stream", 7, "0" * 32, "0" * 40, "1" * 64,
            ),
            engines=self.engines,
            archive_format=None,
        )
        assert scan_id is not None
        self.assertTrue(database.transition_scan_to_completed(scan_id, "high", 70))
        with self.assertRaises(RuntimeError):
            validate_webhook_url("http://siem.example/events")

        class Response:
            status = 204

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return Response()

        with (
            patch.dict(
                "os.environ",
                {
                    "MASP_SIEM_WEBHOOK_URL": "https://siem.example/events",
                    "MASP_SIEM_WEBHOOK_SECRET": "secret",
                },
                clear=False,
            ),
            patch("app.services.notification_delivery.urlopen", side_effect=fake_urlopen),
        ):
            self.assertTrue(deliver_next("notify-1"))
        event = database.claim_next_notification_outbox(
            "notify-2", lease_seconds=60, now=300
        )
        self.assertIsNone(event)
        request_obj = captured["request"]
        self.assertEqual(request_obj.get_method(), "POST")
        self.assertEqual(request_obj.get_header("Idempotency-key"), "scan:%d:malware.detected" % scan_id)
        self.assertIsNotNone(request_obj.get_header("X-masp-signature-sha256"))


if __name__ == "__main__":
    unittest.main()
