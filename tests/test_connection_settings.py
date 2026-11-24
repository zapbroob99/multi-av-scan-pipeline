import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi import HTTPException

from app import database as db
from app.services import aselix, connection_settings as settings, ldap_auth


class ConnectionSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.enterContext(patch.object(db, "DB_PATH", Path(self.tmp.name) / "test.db"))
        self.enterContext(patch.object(db, "DATABASE_URL", ""))
        self.enterContext(patch.dict(os.environ, MASP_SECRET_ENCRYPTION_KEY=Fernet.generate_key().decode(),
            MASP_LDAP_ENABLED="0", MASP_LDAP_CA_PEM_B64="", MASP_ASELIX_ENABLED="0",
            MASP_ASELIX_CA_PEM_B64="", MASP_ASELIX_API_KEY="", MASP_LDAP_BIND_PASSWORD=""))
        db.init_db()

    def body(self, provider, **kwargs):
        snapshot = settings.read(provider)
        values = {field.key: field.value for field in snapshot.fields}
        return settings.ConnectionSave(expected_revision=snapshot.revision, enabled=False, values=values, **kwargs)

    def test_encrypted_ldap_password_runtime_precedence_and_replacement(self):
        body = self.body("ldap", secret=" password with spaces ")
        body.enabled = True
        body.values.update(HOST="directory.test", BIND_DN="CN=reader,DC=test", BASE_DN="DC=test",
                           ADMIN_GROUP_DN="CN=admins,DC=test")
        settings.save("ldap", body)
        raw = db.get_setting("connection.ldap")
        self.assertNotIn("password with spaces", raw)
        snapshot = settings.read("ldap")
        self.assertTrue(snapshot.has_secret)
        self.assertNotIn("password with spaces", snapshot.model_dump_json())
        config = ldap_auth.load_ldap_config()
        self.assertEqual(config.bind_password, " password with spaces ")
        self.assertEqual(config.host, "directory.test")
        with patch.dict(os.environ, MASP_LDAP_BIND_PASSWORD="different-environment-password"):
            replacement = self.body("ldap")
            replacement.enabled = True
            replacement.values["BIND_DN"] = "CN=new-reader,DC=test"
            settings.save("ldap", replacement)
            self.assertEqual(ldap_auth.load_ldap_config().bind_password, " password with spaces ")
        replacement = self.body("ldap", secret="new password")
        replacement.enabled = True
        settings.save("ldap", replacement)
        self.assertEqual(ldap_auth.load_ldap_config().bind_password, "new password")
        with self.assertRaises(HTTPException) as stale:
            settings.save("ldap", body)
        self.assertEqual(stale.exception.status_code, 409)

    def test_first_save_imports_environment_secret_and_disable_survives_key_loss(self):
        with patch.dict(os.environ, MASP_ASELIX_ENABLED="1", MASP_ASELIX_URL="https://ai.test/v1/chat/completions",
                        MASP_ASELIX_MODEL="first-model", MASP_ASELIX_API_KEY="environment-key"):
            initial = settings.read("aselix")
            self.assertEqual(initial.source, "environment")
            body = self.body("aselix")
            body.enabled = True
            settings.save("aselix", body)
        self.assertEqual(aselix.settings()[1:3], ("environment-key", "first-model"))
        with patch.dict(os.environ, MASP_SECRET_ENCRYPTION_KEY=Fernet.generate_key().decode()):
            with self.assertRaises(HTTPException):
                aselix.settings()
            body = self.body("aselix")
            settings.save("aselix", body)
            self.assertFalse(aselix.enabled())
            self.assertEqual(settings.effective_environment("aselix")["MASP_ASELIX_ENABLED"], "0")

    def test_bad_ca_tls_missing_groups_and_fields_are_atomic(self):
        baseline = self.body("ldap", secret="secret")
        for key, value in (("TLS_MODE", "plain"), ("CA_PEM", "bad pem"), ("PORT", "0"), ("CONNECT_TIMEOUT", "nan")):
            body = baseline.model_copy(deep=True)
            body.values[key] = value
            with self.assertRaises(HTTPException):
                settings.save("ldap", body)
            self.assertIsNone(db.get_setting("connection.ldap"))
        baseline.enabled = True
        baseline.values.update(HOST="directory.test", BIND_DN="CN=reader", BASE_DN="DC=test")
        with self.assertRaises(HTTPException):
            settings.save("ldap", baseline)
        self.assertIsNone(db.get_setting("connection.ldap"))

    def test_saved_aselix_test_uses_exact_snapshot_and_hides_reply(self):
        body = self.body("aselix", secret="private-api-key")
        body.values.update(URL="https://ai.test/v1/chat/completions", MODEL="saved-model")
        settings.save("aselix", body)
        self.assertFalse(aselix.enabled())
        test_body = settings.ConnectionTest(expected_revision=settings.read("aselix").revision)
        with patch("app.services.http_transport.open_without_redirects",
                   return_value=io.BytesIO(b'{"choices":[{"message":{"content":"private provider reply"}}]}')) as send:
            result = settings.test("aselix", test_body)
            req = send.call_args.args[0]
            self.assertEqual(json.loads(req.data)["model"], "saved-model")
            self.assertEqual(req.get_header("Authorization"), "Bearer private-api-key")
            self.assertNotIn("private provider reply", result.model_dump_json())
        body = self.body("aselix")
        body.values["MODEL"] = "second-model"
        settings.save("aselix", body)
        with self.assertRaises(HTTPException) as stale:
            settings.test("aselix", test_body)
        self.assertEqual(stale.exception.status_code, 409)

    def test_malformed_or_missing_store_never_falls_back_to_environment(self):
        with patch.dict(os.environ, MASP_LDAP_ENABLED="1", MASP_ASELIX_ENABLED="1"):
            for provider in ("ldap", "aselix"):
                db.set_setting("connection." + provider, "{invalid")
                with self.assertRaises(HTTPException):
                    settings.read(provider)
            with self.assertRaises(ldap_auth.LdapConfigurationError):
                ldap_auth.load_ldap_config()
            self.assertFalse(aselix.enabled())
