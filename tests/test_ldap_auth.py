import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database
from app.models import UserRecord
from app.services import auth, ldap_auth
from app.services.auth_roles import ROLE_ADMIN, ROLE_ANALYST


def enabled_env(**overrides: str) -> dict[str, str]:
    values = {
        "MASP_LDAP_ENABLED": "1",
        "MASP_LDAP_HOST": "directory.example.test",
        "MASP_LDAP_TLS_MODE": "ldaps",
        "MASP_LDAP_BIND_DN": "CN=masp-reader,OU=Svc,DC=example,DC=test",
        "MASP_LDAP_BIND_PASSWORD": "reader-secret",
        "MASP_LDAP_BASE_DN": "OU=People,DC=example,DC=test",
        "MASP_LDAP_USER_FILTER": "(sAMAccountName={username})",
        "MASP_LDAP_USERNAME_ATTRIBUTE": "sAMAccountName",
        "MASP_LDAP_DISPLAY_NAME_ATTRIBUTE": "displayName",
        "MASP_LDAP_GROUP_ATTRIBUTE": "memberOf",
        "MASP_LDAP_ADMIN_GROUP_DN": "CN=MASP Admins,OU=Groups,DC=example,DC=test",
        "MASP_LDAP_ANALYST_GROUP_DN": "CN=MASP Analysts,OU=Groups,DC=example,DC=test",
    }
    values.update(overrides)
    return values


class LdapConfigTests(unittest.TestCase):
    def test_disabled_configuration_needs_no_directory_settings(self) -> None:
        self.assertFalse(ldap_auth.load_ldap_config({"MASP_LDAP_ENABLED": "0"}).enabled)

    def test_enabled_configuration_requires_tls_and_group_mapping(self) -> None:
        values = enabled_env(MASP_LDAP_TLS_MODE="plain")
        with self.assertRaises(ldap_auth.LdapConfigurationError):
            ldap_auth.load_ldap_config(values)

        values = enabled_env(MASP_LDAP_ADMIN_GROUP_DN="", MASP_LDAP_ANALYST_GROUP_DN="")
        with self.assertRaises(ldap_auth.LdapConfigurationError):
            ldap_auth.load_ldap_config(values)

    def test_user_filter_requires_escaped_username_placeholder(self) -> None:
        with self.assertRaises(ldap_auth.LdapConfigurationError):
            ldap_auth.load_ldap_config(enabled_env(MASP_LDAP_USER_FILTER="(uid=static)"))

        with self.assertRaises(ldap_auth.LdapConfigurationError):
            ldap_auth.load_ldap_config(enabled_env(MASP_LDAP_PORT="65536"))

    def test_group_mapping_is_exact_case_insensitive_and_admin_wins(self) -> None:
        config = ldap_auth.load_ldap_config(enabled_env())
        self.assertEqual(
            ldap_auth._mapped_role(
                [config.analyst_group_dn.upper(), config.admin_group_dn.lower()], config
            ),
            ROLE_ADMIN,
        )
        self.assertIsNone(
            ldap_auth._mapped_role(["CN=Other,OU=Groups,DC=example,DC=test"], config)
        )


class FakeLdapException(Exception):
    pass


class FakeLdapBindError(FakeLdapException):
    pass


class FakeExceptions:
    LDAPException = FakeLdapException
    LDAPBindError = FakeLdapBindError


class FakeLdap:
    AUTO_BIND_TLS_BEFORE_BIND = "starttls"
    AUTO_BIND_NO_TLS = "ldaps"
    SUBTREE = "subtree"
    SAFE_SYNC = "safe_sync"

    response = []
    filters: list[str] = []
    connections: list[dict[str, object]] = []
    invalid_password = False
    search_error = False

    class Tls:
        def __init__(self, **kwargs):
            self.options = kwargs

    class Server:
        def __init__(self, host, **kwargs):
            self.host = host
            self.options = kwargs

    class Connection:
        def __init__(self, server, **kwargs):
            FakeLdap.connections.append(kwargs)
            self.response = FakeLdap.response
            if kwargs.get("user", "").startswith("CN=Alice") and FakeLdap.invalid_password:
                raise FakeLdapBindError("invalid credentials")

        def search(self, **kwargs):
            if FakeLdap.search_error:
                raise FakeLdapException("directory unavailable")
            FakeLdap.filters.append(kwargs["search_filter"])
            return True

        def unbind(self):
            return True


def fake_escape_filter_chars(value: str) -> str:
    return value.replace("*", r"\2a").replace("(", r"\28").replace(")", r"\29")


class LdapProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeLdap.response = [
            {
                "type": "searchResEntry",
                "dn": "CN=Alice,OU=People,DC=example,DC=test",
                "attributes": {
                    "sAMAccountName": "alice",
                    "displayName": "Alice Example",
                    "memberOf": ["CN=MASP Analysts,OU=Groups,DC=example,DC=test"],
                },
            }
        ]
        FakeLdap.filters = []
        FakeLdap.connections = []
        FakeLdap.invalid_password = False
        FakeLdap.search_error = False
        self.config = ldap_auth.load_ldap_config(enabled_env())
        self.loader = patch.object(
            ldap_auth,
            "_load_ldap3",
            return_value=(FakeLdap, FakeExceptions, fake_escape_filter_chars),
        )

    def test_searches_with_service_account_then_binds_as_user(self) -> None:
        with self.loader:
            identity = ldap_auth.authenticate_ldap("alice*)(uid=*)", "user-secret", self.config)

        self.assertIsNotNone(identity)
        self.assertEqual(identity.username, "alice")
        self.assertEqual(identity.role, ROLE_ANALYST)
        self.assertIn(r"\2a\29\28uid=\2a\29", FakeLdap.filters[0])
        self.assertEqual(len(FakeLdap.connections), 2)
        self.assertEqual(FakeLdap.connections[1]["user"], identity.external_id)
        self.assertEqual(FakeLdap.connections[1]["password"], "user-secret")

    def test_invalid_user_bind_is_rejected(self) -> None:
        FakeLdap.invalid_password = True
        with self.loader:
            self.assertIsNone(ldap_auth.authenticate_ldap("alice", "wrong", self.config))

    def test_ambiguous_or_unauthorized_user_is_rejected_without_user_bind(self) -> None:
        FakeLdap.response = FakeLdap.response * 2
        with self.loader:
            self.assertIsNone(ldap_auth.authenticate_ldap("alice", "secret", self.config))
        self.assertEqual(len(FakeLdap.connections), 1)

    def test_directory_search_failure_is_reported_as_unavailable(self) -> None:
        FakeLdap.search_error = True
        with self.loader, self.assertRaises(ldap_auth.LdapUnavailableError):
            ldap_auth.authenticate_ldap("alice", "secret", self.config)


class LdapShadowUserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_successful_login_creates_and_updates_passwordless_shadow_user(self) -> None:
        first = ldap_auth.LdapIdentity(
            username="alice",
            external_id="CN=Alice,OU=People,DC=example,DC=test",
            display_name="Alice Example",
            role=ROLE_ANALYST,
        )
        with patch.object(auth, "authenticate_ldap", return_value=first):
            user = auth.authenticate("alice", "directory-password")
        self.assertIsNotNone(user)
        self.assertEqual(user.auth_source, "ldap")
        self.assertEqual(user.password_hash, "!ldap")
        self.assertEqual(user.role, ROLE_ANALYST)
        self.assertIsNotNone(user.last_login_at)

        promoted = ldap_auth.LdapIdentity(**{**first.__dict__, "role": ROLE_ADMIN})
        with patch.object(auth, "authenticate_ldap", return_value=promoted):
            updated = auth.authenticate("alice", "directory-password")
        self.assertEqual(updated.id, user.id)
        self.assertEqual(updated.role, ROLE_ADMIN)

    def test_wrong_local_password_never_falls_through_to_ldap(self) -> None:
        database.create_user("local-admin", auth.hash_password("correct-password"), ROLE_ADMIN)
        with patch.object(auth, "authenticate_ldap") as directory_auth:
            self.assertIsNone(auth.authenticate("local-admin", "wrong-password"))
        directory_auth.assert_not_called()

    def test_directory_identity_cannot_claim_case_insensitive_local_username(self) -> None:
        database.create_user("Alice", auth.hash_password("local-password"), ROLE_ADMIN)
        identity = ldap_auth.LdapIdentity(
            username="alice",
            external_id="CN=Alice,OU=People,DC=example,DC=test",
            display_name="Alice Example",
            role=ROLE_ADMIN,
        )
        with patch.object(auth, "authenticate_ldap", return_value=identity):
            self.assertIsNone(auth.authenticate("alice", "directory-password"))
        self.assertEqual(database.get_user_by_username("Alice").auth_source, "local")

    def test_session_round_trip_includes_directory_metadata(self) -> None:
        user = database.sync_external_user(
            username="alice",
            role=ROLE_ANALYST,
            external_id="CN=Alice,OU=People,DC=example,DC=test",
            display_name="Alice Example",
        )
        database.create_auth_session(user.id, "token-hash", 2_000_000_000)
        loaded = database.get_user_by_session("token-hash", 1_900_000_000)
        self.assertEqual(loaded.auth_source, "ldap")
        self.assertEqual(loaded.display_name, "Alice Example")


class LdapUiTests(unittest.TestCase):
    @staticmethod
    def directory_user() -> UserRecord:
        return UserRecord(
            id=8,
            username="alice",
            password_hash="!ldap",
            role=ROLE_ANALYST,
            created_at="2026-08-21 10:00:00",
            updated_at="2026-08-21 10:00:00",
            auth_source="ldap",
            external_id="CN=Alice,OU=People,DC=example,DC=test",
            display_name="Alice Example",
            last_login_at="2026-08-21 10:00:00",
        )

    def test_directory_account_page_has_no_local_password_form(self) -> None:
        from app import main

        page = main.render_account_page(self.directory_user())
        self.assertIn("Directory-managed account", page)
        self.assertNotIn('action="/account/password"', page)
        self.assertIn("Alice Example", page)

    def test_directory_user_row_has_no_role_or_password_form(self) -> None:
        from app import main

        user = self.directory_user()
        admin = UserRecord(
            id=1,
            username="admin",
            password_hash="hash",
            role=ROLE_ADMIN,
            created_at="2026-08-21 09:00:00",
            updated_at="2026-08-21 09:00:00",
        )
        with patch.object(main, "list_users", return_value=[user]):
            rows = main.render_user_rows(admin)
        self.assertIn("Directory managed", rows)
        self.assertIn("Alice Example", rows)
        self.assertNotIn(f'action="/users/{user.id}"', rows)

    def test_login_page_announces_directory_sign_in_when_enabled(self) -> None:
        from app import main

        with patch.dict(os.environ, enabled_env(), clear=False):
            page = main.render_login_page()
        self.assertIn("Directory sign-in enabled", page)


if __name__ == "__main__":
    unittest.main()
