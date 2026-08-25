import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app import database
from app.services import worker_control
from app.models import EngineResultInput, StoredSample
from app.workers import control_api_worker


def make_request(token: str | None = None, *, scheme: str = "http") -> Request:
    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode("ascii")))
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": scheme,
            "path": "/api/v1/worker-control/enroll",
            "raw_path": b"/api/v1/worker-control/enroll",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
        }
    )
    request.state.audit_request_id = "test"
    return request


def identity(node_id: str = "defender-01") -> worker_control.WorkerIdentityPayload:
    return worker_control.WorkerIdentityPayload(
        node_id=node_id,
        display_name="Defender 01",
        hostname="win-av-01",
        platform="windows",
        agent_version="0.5.0",
        labels={"site": "istanbul"},
        capacity=2,
        engine_keys=["microsoft_defender"],
        process_id=101,
    )


class WorkerCredentialDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "worker-control.db"
        database.DATABASE_URL = ""
        database.init_db()
        database.upsert_worker_node_heartbeat(
            node_id="defender-01",
            display_name="Defender 01",
            hostname="win-av-01",
            platform="windows",
            agent_version="0.5.0",
            labels_json="{}",
            capacity=1,
            advertised_engine_keys_json='["microsoft_defender"]',
            runtime_state="enrolled",
            active_scan_id=None,
            process_id=0,
            last_heartbeat_at=1000,
        )

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_plaintext_is_never_stored_and_expired_token_is_rejected(self) -> None:
        token = "masp_wa_high_entropy_test_token"
        digest = hashlib.sha256(token.encode()).hexdigest()
        credential = database.create_worker_agent_credential(
            node_id="defender-01",
            token_hash=digest,
            token_prefix=token[:16],
            expires_at=1100,
        )

        self.assertEqual(credential.token_hash, digest)
        self.assertNotEqual(credential.token_hash, token)
        self.assertIsNotNone(
            database.authenticate_worker_agent_credential(digest, now=1099)
        )
        self.assertIsNone(
            database.authenticate_worker_agent_credential(digest, now=1100)
        )

    def test_rotation_revokes_previous_credential(self) -> None:
        first_hash = hashlib.sha256(b"first").hexdigest()
        second_hash = hashlib.sha256(b"second").hexdigest()
        database.create_worker_agent_credential(
            node_id="defender-01",
            token_hash=first_hash,
            token_prefix="first",
        )
        database.create_worker_agent_credential(
            node_id="defender-01",
            token_hash=second_hash,
            token_prefix="second",
        )

        self.assertIsNone(database.authenticate_worker_agent_credential(first_hash))
        self.assertIsNotNone(database.authenticate_worker_agent_credential(second_hash))
        credentials = database.list_worker_agent_credentials("defender-01")
        self.assertEqual(len(credentials), 2)
        self.assertIsNotNone(next(item for item in credentials if item.token_hash == first_hash).revoked_at)


class WorkerControlEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "worker-control-endpoints.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_enrollment_returns_one_time_agent_token_and_rotates(self) -> None:
        environment = {
            "MASP_WORKER_ENROLLMENT_TOKEN": "bootstrap-secret",
            "MASP_WORKER_CONTROL_REQUIRE_HTTPS": "0",
        }
        with patch.dict("os.environ", environment, clear=False):
            first = worker_control.enroll_worker(
                make_request("bootstrap-secret"), identity()
            )
            second = worker_control.enroll_worker(
                make_request("bootstrap-secret"), identity()
            )

        self.assertTrue(str(first["agent_token"]).startswith("masp_wa_"))
        self.assertNotEqual(first["agent_token"], second["agent_token"])
        first_hash = hashlib.sha256(str(first["agent_token"]).encode()).hexdigest()
        second_hash = hashlib.sha256(str(second["agent_token"]).encode()).hexdigest()
        self.assertIsNone(database.authenticate_worker_agent_credential(first_hash))
        self.assertIsNotNone(database.authenticate_worker_agent_credential(second_hash))

    def test_agent_cannot_heartbeat_as_another_node(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "MASP_WORKER_ENROLLMENT_TOKEN": "bootstrap-secret",
                "MASP_WORKER_CONTROL_REQUIRE_HTTPS": "0",
            },
            clear=False,
        ):
            enrolled = worker_control.enroll_worker(
                make_request("bootstrap-secret"), identity()
            )
            payload = worker_control.WorkerHeartbeatPayload(
                **identity("other-node").model_dump(),
                runtime_state="idle",
            )
            with self.assertRaises(HTTPException) as context:
                worker_control.worker_heartbeat(
                    make_request(str(enrolled["agent_token"])), payload
                )

        self.assertEqual(context.exception.status_code, 403)

    def test_https_can_be_required_for_agent_calls(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "MASP_WORKER_ENROLLMENT_TOKEN": "bootstrap-secret",
                "MASP_WORKER_CONTROL_REQUIRE_HTTPS": "0",
            },
            clear=False,
        ):
            enrolled = worker_control.enroll_worker(
                make_request("bootstrap-secret"), identity()
            )
        with patch.dict(
            "os.environ", {"MASP_WORKER_CONTROL_REQUIRE_HTTPS": "1"}, clear=False
        ):
            with self.assertRaises(HTTPException) as context:
                worker_control.require_worker_agent(
                    make_request(str(enrolled["agent_token"]), scheme="http")
                )
        self.assertEqual(context.exception.status_code, 400)

    def test_claim_download_and_result_use_same_fenced_owner(self) -> None:
        content = b"control plane sample"
        sample_path = Path(self.temp_dir.name) / "sample.bin"
        sample_path.write_bytes(content)
        engine_id = database.create_engine_instance(
            "static_metadata", "Remote Static Metadata"
        )
        sample_id = database.create_sample(
            StoredSample(
                original_filename="sample.bin",
                stored_filename="sample.bin",
                storage_path=str(sample_path),
                content_type="application/octet-stream",
                size_bytes=len(content),
                md5=hashlib.md5(content).hexdigest(),
                sha1=hashlib.sha1(content).hexdigest(),
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
        scan_id = database.create_scan_job(
            sample_id, "Control API", "Normal", "", source="manual"
        )
        engine = database.get_engine_instance_by_id(engine_id)
        assert engine is not None
        database.create_scan_engine_jobs(scan_id, [engine])
        environment = {
            "MASP_WORKER_ENROLLMENT_TOKEN": "bootstrap-secret",
            "MASP_WORKER_CONTROL_REQUIRE_HTTPS": "0",
        }
        with patch.dict("os.environ", environment, clear=False):
            enrolled = worker_control.enroll_worker(
                make_request("bootstrap-secret"),
                worker_control.WorkerIdentityPayload(
                    **{
                        **identity("static-01").model_dump(),
                        "engine_keys": ["static_metadata"],
                    }
                ),
            )
            agent_request = make_request(str(enrolled["agent_token"]))
            claimed = worker_control.claim_worker_job(
                agent_request,
                worker_control.WorkerProcessPayload(
                    process_id=101, lease_seconds=120
                ),
            )
            self.assertIsInstance(claimed, dict)
            assert isinstance(claimed, dict)
            job = claimed["job"]
            assert isinstance(job, dict)
            ownership = worker_control.WorkerLeasePayload(
                process_id=101,
                attempt_generation=int(job["attempt_generation"]),
                lease_seconds=120,
            )
            response = worker_control.download_worker_job_sample(
                agent_request, int(job["id"]), ownership
            )
            self.assertEqual(Path(response.path), sample_path)
            with self.assertRaises(HTTPException) as wrong_owner:
                worker_control.download_worker_job_sample(
                    agent_request,
                    int(job["id"]),
                    worker_control.WorkerLeasePayload(
                        process_id=999,
                        attempt_generation=int(job["attempt_generation"]),
                        lease_seconds=120,
                    ),
                )
            self.assertEqual(wrong_owner.exception.status_code, 409)
            result = worker_control.submit_worker_job_result(
                agent_request,
                int(job["id"]),
                worker_control.WorkerEngineResultPayload(
                    process_id=101,
                    attempt_generation=int(job["attempt_generation"]),
                    lease_seconds=120,
                    status="completed",
                    detected=False,
                    severity="info",
                    confidence=100,
                    raw_output="ok",
                    duration_ms=1,
                ),
            )

        self.assertTrue(result["committed"])
        self.assertEqual(database.get_scan(scan_id).status, "completed")  # type: ignore[union-attr]


class ControlApiWorkerClientTests(unittest.TestCase):
    def test_operation_urls_support_api_and_origin_relative_paths(self) -> None:
        client = control_api_worker.WorkerControlClient(
            "https://masp.example/api/v1/worker-control", "agent-token"
        )

        self.assertEqual(
            client._url("jobs/claim"),
            "https://masp.example/api/v1/worker-control/jobs/claim",
        )
        self.assertEqual(
            client._url("/api/v1/worker-control/jobs/8514/sample"),
            "https://masp.example/api/v1/worker-control/jobs/8514/sample",
        )

    def test_operation_url_cannot_leave_configured_origin(self) -> None:
        client = control_api_worker.WorkerControlClient(
            "https://masp.example/api/v1/worker-control", "agent-token"
        )

        for path in (
            "https://attacker.example/jobs/claim",
            "//attacker.example/jobs/claim",
            "https://masp.example:invalid/jobs/claim",
        ):
            with self.subTest(path=path):
                with self.assertRaises(control_api_worker.WorkerControlError):
                    client._url(path)

    def test_plain_http_requires_explicit_development_opt_in(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "MASP_WORKER_CONTROL_URL": "http://127.0.0.1:8000/api/v1/worker-control",
                "MASP_WORKER_CONTROL_ALLOW_INSECURE_HTTP": "0",
            },
            clear=False,
        ):
            with self.assertRaises(control_api_worker.WorkerControlError):
                control_api_worker.control_url()
        with patch.dict(
            "os.environ",
            {
                "MASP_WORKER_CONTROL_URL": "http://127.0.0.1:8000/api/v1/worker-control",
                "MASP_WORKER_CONTROL_ALLOW_INSECURE_HTTP": "1",
            },
            clear=False,
        ):
            self.assertEqual(
                control_api_worker.control_url(),
                "http://127.0.0.1:8000/api/v1/worker-control",
            )

    def test_remote_run_uses_verified_temporary_copy_and_submits_result(self) -> None:
        content = b"remote sample"
        sha256 = hashlib.sha256(content).hexdigest()

        class FakeClient:
            def __init__(self) -> None:
                self.downloaded_path: Path | None = None
                self.posts: list[tuple[str, dict[str, object]]] = []

            def download_sample(self, _path, _payload, **_kwargs):
                handle = tempfile.NamedTemporaryFile(delete=False)
                handle.write(content)
                handle.close()
                self.downloaded_path = Path(handle.name)
                return self.downloaded_path

            def post_json(self, path, payload):
                self.posts.append((path, payload))
                return {"committed": True}

        claim = {
            "job": {
                "id": 7,
                "scan_id": 8,
                "attempt_generation": 2,
                "lease_seconds": 120,
            },
            "engine": {
                "id": 3,
                "adapter_key": "static_metadata",
                "display_name": "Static Metadata",
                "config": {},
            },
            "sample": {
                "original_filename": "sample.bin",
                "stored_filename": "stored.bin",
                "content_type": "application/octet-stream",
                "size_bytes": len(content),
                "md5": "0" * 32,
                "sha1": "0" * 40,
                "sha256": sha256,
                "download_path": "/api/v1/worker-control/jobs/7/sample",
            },
            "scan": {"source": "manual", "role": "standalone", "relative_path": None},
        }
        result = EngineResultInput(
            engine_name="Static Metadata",
            status="completed",
            detected=False,
            severity="info",
            confidence=100,
            signature=None,
            raw_output="ok",
            duration_ms=1,
        )
        client = FakeClient()
        with patch("app.workers.control_api_worker.run_engine", return_value=result):
            control_api_worker.run_claim(client, claim, 101)  # type: ignore[arg-type]

        assert client.downloaded_path is not None
        self.assertFalse(client.downloaded_path.exists())
        self.assertEqual(client.posts[-1][0], "jobs/7/result")
        self.assertEqual(client.posts[-1][1]["attempt_generation"], 2)


if __name__ == "__main__":
    unittest.main()
