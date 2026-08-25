import json
from pathlib import Path
import tempfile
import unittest

from app import database
from starlette.requests import Request

from app.services.audit import (
    details_json,
    request_id_for,
    sanitize_details,
    should_audit_request,
    token_fingerprint,
)


def request_for(path: str, *, method: str = "GET", request_id: str | None = None) -> Request:
    headers = [] if request_id is None else [(b"x-request-id", request_id.encode("ascii"))]
    return Request(
        {
            "type": "http",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
        }
    )


class AuditDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "audit-test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def append(self, **overrides: object) -> int:
        values: dict[str, object] = {
            "actor_type": "user",
            "actor_id": "7",
            "actor_name": "operator",
            "action": "scan.delete",
            "target_type": "scan",
            "target_id": "42",
            "outcome": "success",
            "source_ip": "127.0.0.1",
            "request_id": "request-1",
            "details_json": '{"method":"POST"}',
        }
        values.update(overrides)
        return database.create_audit_event(**values)  # type: ignore[arg-type]

    def test_append_list_count_and_filters(self) -> None:
        first_id = self.append()
        second_id = self.append(
            actor_name="api-client",
            action="hash.lookup",
            outcome="denied",
            request_id="request-2",
        )

        self.assertGreater(second_id, first_id)
        self.assertEqual(database.count_audit_events(), 2)
        self.assertEqual(database.count_audit_events(query="HASH", outcome="denied"), 1)
        events = database.list_audit_events(query="api-client", outcome="denied")
        self.assertEqual([event.id for event in events], [second_id])
        self.assertEqual(events[0].request_id, "request-2")

    def test_event_survives_target_user_deletion(self) -> None:
        user_id = database.create_user("temporary", "not-a-real-hash", "analyst")
        event_id = self.append(
            action="user.delete",
            target_type="user",
            target_id=str(user_id),
        )

        database.delete_user(user_id)

        events = database.list_audit_events(query=str(user_id))
        self.assertEqual([event.id for event in events], [event_id])

    def test_application_data_layer_has_no_mutation_api_for_audit_rows(self) -> None:
        self.assertFalse(hasattr(database, "update_audit_event"))
        self.assertFalse(hasattr(database, "delete_audit_event"))


class AuditSanitizationTests(unittest.TestCase):
    def test_sensitive_values_are_redacted_recursively(self) -> None:
        value = sanitize_details(
            {
                "password": "hunter2",
                "nested": {
                    "api-key": "vt-secret",
                    "Authorization": "Bearer raw-token",
                    "safe": "visible",
                },
                "raw_output": "malware engine response",
            }
        )

        encoded = json.dumps(value)
        self.assertNotIn("hunter2", encoded)
        self.assertNotIn("vt-secret", encoded)
        self.assertNotIn("raw-token", encoded)
        self.assertNotIn("malware engine response", encoded)
        self.assertEqual(value["nested"]["safe"], "visible")

    def test_details_are_bounded(self) -> None:
        encoded = details_json({f"field_{index}": "x" * 500 for index in range(40)})
        self.assertLessEqual(len(encoded), 8_000)
        self.assertTrue(json.loads(encoded)["_truncated"])

    def test_token_fingerprint_is_stable_and_does_not_expose_token(self) -> None:
        token = "highly-sensitive-bearer-token"
        fingerprint = token_fingerprint(token)
        self.assertEqual(fingerprint, token_fingerprint(token))
        self.assertNotIn(token, fingerprint)
        self.assertTrue(fingerprint.startswith("sha256:"))

    def test_request_id_accepts_safe_value_and_replaces_unsafe_value(self) -> None:
        self.assertEqual(request_id_for(request_for("/", request_id="gateway-123")), "gateway-123")
        generated = request_id_for(request_for("/", request_id="bad value"))
        self.assertNotEqual(generated, "bad value")
        self.assertEqual(len(generated), 32)

    def test_audit_policy_covers_security_and_administrative_changes(self) -> None:
        self.assertTrue(should_audit_request(request_for("/login", method="POST")))
        self.assertTrue(should_audit_request(request_for("/account/password", method="POST")))
        self.assertTrue(should_audit_request(request_for("/users/4/delete", method="POST")))
        self.assertTrue(should_audit_request(request_for("/engines/clamav/config", method="POST")))
        self.assertTrue(should_audit_request(request_for("/workers/state", method="POST")))
        self.assertTrue(should_audit_request(request_for("/scan-policy", method="POST")))
        self.assertTrue(should_audit_request(request_for("/scans/4/delete", method="POST")))

    def test_audit_policy_excludes_navigation_scans_and_api_polling(self) -> None:
        self.assertFalse(should_audit_request(request_for("/audit")))
        self.assertFalse(should_audit_request(request_for("/scans/4/export.json")))
        self.assertFalse(should_audit_request(request_for("/scans", method="POST")))
        self.assertFalse(should_audit_request(request_for("/hash-scan", method="POST")))
        self.assertFalse(should_audit_request(request_for("/engines/clamav/test", method="POST")))
        self.assertFalse(should_audit_request(request_for("/api/v1/hashes/abc")))
        self.assertFalse(should_audit_request(request_for("/api/v1/scans/4")))
        self.assertFalse(should_audit_request(request_for("/health")))


if __name__ == "__main__":
    unittest.main()
