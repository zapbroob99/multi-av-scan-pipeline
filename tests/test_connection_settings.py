import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi import HTTPException

from app import database as db
from app.services import connection_settings as settings, ldap_auth


class ConnectionSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.enterContext(patch.object(db, "DB_PATH", Path(self.tmp.name) / "test.db"))
        self.enterContext(patch.object(db, "DATABASE_URL", ""))
        self.enterContext(patch.dict(os.environ, MASP_SECRET_ENCRYPTION_KEY=Fernet.generate_key().decode(),
            MASP_LDAP_ENABLED="0", MASP_LDAP_CA_PEM_B64="", MASP_LDAP_BIND_PASSWORD=""))
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

    def test_malformed_or_missing_store_never_falls_back_to_environment(self):
        with patch.dict(os.environ, MASP_LDAP_ENABLED="1"):
            db.set_setting("connection.ldap", "{invalid")
            with self.assertRaises(HTTPException):
                settings.read("ldap")
            with self.assertRaises(ldap_auth.LdapConfigurationError):
                ldap_auth.load_ldap_config()
