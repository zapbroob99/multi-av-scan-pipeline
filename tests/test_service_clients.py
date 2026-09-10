import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database
from app.models import ApiClientIdentity, EngineResultInput, StoredSample
from app.services.scan_assessment import detection_summary, required_engine_coverage
from app.services.service_clients import (
    engines_for_profile,
    engines_for_scan,
    hash_api_token,
    identity_for_service_client_key,
    identity_can_access_scan,
    profile_snapshot_json,
    required_detection_engine_names,
    resolve_stored_api_client,
)


class ServiceClientIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "service-clients.db"
        database.DATABASE_URL = ""
        database.init_db()
        self.metadata_id = database.create_engine_instance(
            "static_metadata", "Metadata A"
        )
        self.clamav_id = database.create_engine_instance("clamav", "ClamAV B")

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def create_bundle(
        self, key: str, token: str, engine_ids: list[int]
    ) -> tuple[int, int, int]:
        return database.create_service_client_bundle(
            client_key=key,
            display_name=key.title(),
            profile_name="Default",
            engine_instance_ids=engine_ids,
            credential_label="Test token",
            token_hash=hash_api_token(token),
            token_prefix=token[:8],
        )

    def sample_id(self, name: str = "sample.bin") -> int:
        return database.create_sample(
            StoredSample(
                name,
                name,
                str(Path(self.temp_dir.name) / name),
                "application/octet-stream",
                7,
                "0" * 32,
                "0" * 40,
                "1" * 64,
            )
        )

    def test_bundle_stores_token_hash_and_profile_engine_set(self) -> None:
        token = "client-a-token-that-is-longer-than-32-characters"
        client_id, profile_id, credential_id = self.create_bundle(
            "client-a", token, [self.metadata_id]
        )

        credentials = database.list_api_client_credentials(client_id)
        self.assertEqual([item.id for item in credentials], [credential_id])
        self.assertEqual(credentials[0].token_hash, hash_api_token(token))
        self.assertNotEqual(credentials[0].token_hash, token)
        self.assertEqual(credentials[0].token_prefix, token[:8])
        self.assertEqual(
            [engine.id for engine in database.list_scan_profile_engines(profile_id)],
            [self.metadata_id],
        )
        with database.connect() as connection:
            stored = connection.execute(
                "SELECT token_hash, token_prefix FROM api_client_credentials WHERE id = ?",
                (credential_id,),
            ).fetchone()
        self.assertNotIn(token, tuple(stored))

    def test_stored_token_resolves_to_own_client_and_profile(self) -> None:
        token = "client-b-token-that-is-longer-than-32-characters"
        client_id, profile_id, _ = self.create_bundle(
            "client-b", token, [self.clamav_id]
        )

        identity = resolve_stored_api_client(token)

        self.assertIsNotNone(identity)
        assert identity is not None
        self.assertEqual(identity.client.id, client_id)
        self.assertEqual(identity.profile.id, profile_id)
        self.assertFalse(identity.legacy_credential)

    def test_icap_client_key_resolves_same_default_profile(self) -> None:
        token = "client-icap-token-that-is-longer-than-32-characters"
        client_id, profile_id, _ = self.create_bundle(
            "icap-client", token, [self.clamav_id]
        )

        identity = identity_for_service_client_key("ICAP-CLIENT")

        self.assertEqual(identity.client.id, client_id)
        self.assertEqual(identity.profile.id, profile_id)
        self.assertFalse(identity.legacy_credential)

    def test_scan_uses_immutable_engine_snapshot_after_profile_changes(self) -> None:
        token = "client-c-token-that-is-longer-than-32-characters"
        client_id, profile_id, credential_id = self.create_bundle(
            "client-c", token, [self.metadata_id]
        )
        client = database.get_service_client(client_id)
        profile = database.get_scan_profile(profile_id)
        assert client is not None and profile is not None
        identity = ApiClientIdentity(client, profile, credential_id, False)
        selected = engines_for_profile(profile_id, source="api")
        snapshot = profile_snapshot_json(identity, selected)
        scan_id = database.create_scan_job(
            self.sample_id(),
            case_name="Client C",
            priority="Normal",
            note="",
            source="api",
            service_client_id=client_id,
            scan_profile_id=profile_id,
            profile_snapshot_json=snapshot,
        )
        database.set_scan_profile_engines(profile_id, [self.clamav_id])
        with database.connect() as connection:
            connection.execute("UPDATE engine_instances SET display_name = ? WHERE id = ?",
                               ("Renamed Metadata", self.metadata_id))

        scan = database.get_scan(scan_id)
        assert scan is not None
        self.assertEqual([engine.id for engine in engines_for_scan(scan)], [self.metadata_id])
        self.assertEqual([engine.display_name for engine in engines_for_scan(scan)], ["Metadata A"])

    def test_explicit_empty_snapshot_does_not_use_current_global_engines(self) -> None:
        scan_id = database.create_scan_job(
            self.sample_id(), case_name="Empty", priority="Normal", note="", source="api",
            profile_snapshot_json='{"engines":[]}',
        )
        self.assertEqual(engines_for_scan(database.get_scan(scan_id)), [])

    def test_manual_scan_coverage_uses_immutable_job_identity(self) -> None:
        scan_id = database.create_scan_job(
            self.sample_id("metadata.bin"),
            case_name="Metadata",
            priority="Normal",
            note="",
            source="manual",
        )
        metadata = database.get_engine_instance_by_id(self.metadata_id)
        assert metadata is not None
        database.create_scan_engine_jobs(scan_id, [metadata])
        database.create_engine_result(
            scan_id,
            EngineResultInput(
                engine_name=metadata.display_name,
                status="completed",
                detected=False,
                severity="info",
                confidence=100,
                signature=None,
                raw_output="{}",
                duration_ms=1,
            ),
        )

        scan = database.get_scan(scan_id)
        assert scan is not None
        results = database.list_engine_results(scan_id)

        # ClamAV is currently enabled globally, but it was not assigned to this
        # scan. The custom-named metadata adapter must not be misclassified as a
        # detection engine merely because its name differs from the built-in.
        self.assertEqual(required_detection_engine_names(scan), [])
        self.assertEqual(detection_summary(results, scan=scan), (0, 0))
        self.assertEqual(required_engine_coverage(results, scan=scan), (0, 0, []))

    def test_manual_scan_coverage_keeps_job_name_after_instance_rename(self) -> None:
        scan_id = database.create_scan_job(
            self.sample_id("clamav.bin"),
            case_name="ClamAV",
            priority="Normal",
            note="",
            source="manual",
        )
        clamav = database.get_engine_instance_by_id(self.clamav_id)
        assert clamav is not None
        database.create_scan_engine_jobs(scan_id, [clamav])
        database.update_engine_instance_by_id(
            self.clamav_id, display_name="ClamAV Current"
        )
        database.create_engine_result(
            scan_id,
            EngineResultInput(
                engine_name=clamav.display_name,
                status="completed",
                detected=False,
                severity="info",
                confidence=100,
                signature=None,
                raw_output="clean",
                duration_ms=1,
            ),
        )

        scan = database.get_scan(scan_id)
        assert scan is not None
        results = database.list_engine_results(scan_id)

        self.assertEqual(required_detection_engine_names(scan), ["ClamAV B"])
        self.assertEqual(required_engine_coverage(results, scan=scan), (1, 1, []))

    def test_client_cannot_access_another_clients_scan(self) -> None:
        token_a = "client-d-token-that-is-longer-than-32-characters"
        token_b = "client-e-token-that-is-longer-than-32-characters"
        client_a, profile_a, credential_a = self.create_bundle(
            "client-d", token_a, [self.metadata_id]
        )
        client_b, profile_b, _ = self.create_bundle(
            "client-e", token_b, [self.clamav_id]
        )
        record_a = database.get_service_client(client_a)
        scan_profile_a = database.get_scan_profile(profile_a)
        assert record_a is not None and scan_profile_a is not None
        identity_a = ApiClientIdentity(record_a, scan_profile_a, credential_a, False)
        scan_id = database.create_scan_job(
            self.sample_id("other.bin"),
            case_name="Client E",
            priority="Normal",
            note="",
            source="api",
            service_client_id=client_b,
            scan_profile_id=profile_b,
            profile_snapshot_json="{}",
        )

        scan = database.get_scan(scan_id)
        assert scan is not None
        self.assertFalse(identity_can_access_scan(identity_a, scan))
        self.assertEqual(database.count_scan_history(service_client_id=client_a), 0)
        self.assertEqual(database.count_scan_history(service_client_id=client_b), 1)

    def test_intake_persists_client_profile_and_snapshot_on_archive_batch(self) -> None:
        token = "client-f-token-that-is-longer-than-32-characters"
        client_id, profile_id, credential_id = self.create_bundle(
            "client-f", token, [self.metadata_id]
        )
        client = database.get_service_client(client_id)
        profile = database.get_scan_profile(profile_id)
        assert client is not None and profile is not None
        identity = ApiClientIdentity(client, profile, credential_id, False)
        engines = engines_for_profile(profile_id, source="api")
        snapshot = profile_snapshot_json(identity, engines)
        stored = StoredSample(
            "archive.zip",
            "archive.zip",
            str(Path(self.temp_dir.name) / "archive.zip"),
            "application/zip",
            7,
            "0" * 32,
            "0" * 40,
            "2" * 64,
        )
        Path(stored.storage_path).write_bytes(b"payload")
        from app.services.scan_intake import enqueue_scan_from_stored_sample

        with patch("app.services.scan_intake.detect_archive_format", return_value="zip"):
            scan = enqueue_scan_from_stored_sample(
                stored,
                case_name="Client F",
                priority="Normal",
                note="",
                source="api",
                engines=engines,
                service_client_id=client_id,
                scan_profile_id=profile_id,
                profile_snapshot_json=snapshot,
            )

        self.assertEqual(scan.service_client_id, client_id)
        self.assertEqual(scan.scan_profile_id, profile_id)
        self.assertEqual(scan.profile_snapshot_json, snapshot)
        assert scan.batch_id is not None
        batch = database.get_scan_batch(scan.batch_id)
        assert batch is not None
        self.assertEqual(batch.service_client_id, client_id)
        self.assertEqual(batch.scan_profile_id, profile_id)
        self.assertEqual(batch.profile_snapshot_json, snapshot)


if __name__ == "__main__":
    unittest.main()
