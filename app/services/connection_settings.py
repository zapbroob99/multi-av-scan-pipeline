"""Versioned operator connection settings, with deployment fallback and encrypted secrets."""

import base64
import hashlib
import json
import os
import ssl
from threading import BoundedSemaphore
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app import database as db
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms
from app.services.secret_store import decrypt_secret, encrypt_secret, secret_encryption_available


Provider = Literal["ldap", "aselix"]
MAX_RECORD = 98304
_test_slots = BoundedSemaphore(2)


class ConnectionField(BaseModel):
    key: str
    label: str
    help: str
    value: str = ""
    advanced: bool = False
    choices: list[str] = Field(default_factory=list)


# The keys are the supported environment suffixes. Transport URLs are deployment
# administration, never input accepted by chat or sign-in callers.
LDAP_FIELDS = [
    ConnectionField(key="HOST", label="Directory host", help="DNS name matching the directory TLS certificate."),
    ConnectionField(key="PORT", label="Directory port", help="Usually 636 for LDAPS or 389 for StartTLS.", value="636"),
    ConnectionField(key="TLS_MODE", label="TLS method", help="Use the method enabled by your directory team.", value="ldaps", choices=["ldaps", "starttls"]),
    ConnectionField(key="BIND_DN", label="Search account", help="Full distinguishedName of a real account that can read users and group membership."),
    ConnectionField(key="BASE_DN", label="User search base", help="OU or domain under which MASP searches for users."),
    ConnectionField(key="ADMIN_GROUP_DN", label="Administrator group DN", help="Members receive MASP administrator access. At least one role group is required."),
    ConnectionField(key="ANALYST_GROUP_DN", label="Analyst group DN", help="Members receive analyst access. Use the group's full distinguishedName."),
    ConnectionField(key="USER_FILTER", label="User filter", help="Must contain {username}. OpenLDAP commonly uses (uid={username}).", value="(sAMAccountName={username})", advanced=True),
    ConnectionField(key="USERNAME_ATTRIBUTE", label="Username attribute", help="sAMAccountName for Active Directory, commonly uid for OpenLDAP.", value="sAMAccountName", advanced=True),
    ConnectionField(key="DISPLAY_NAME_ATTRIBUTE", label="Display name attribute", help="Commonly displayName or cn.", value="displayName", advanced=True),
    ConnectionField(key="GROUP_ATTRIBUTE", label="Group attribute", help="Direct group membership attribute. Nested group expansion is unsupported.", value="memberOf", advanced=True),
    ConnectionField(key="CONNECT_TIMEOUT", label="Connect timeout (seconds)", help="From 1 to 15 seconds.", value="5", advanced=True),
    ConnectionField(key="RECEIVE_TIMEOUT", label="Receive timeout (seconds)", help="From 1 to 30 seconds.", value="8", advanced=True),
]
ASELIX_FIELDS = [
    ConnectionField(key="URL", label="Chat completion URL", help="Full HTTPS address ending in /v1/chat/completions."),
    ConnectionField(key="MODEL", label="Model ID", help="Exact model ID supplied by your internal Aselix service."),
]
SECRET_SUFFIX = {"ldap": "BIND_PASSWORD", "aselix": "API_KEY"}


class ConnectionSnapshot(BaseModel):
    provider: Provider
    revision: str
    source: Literal["environment", "console"]
    enabled: bool
    fields: list[ConnectionField]
    has_secret: bool
    secret_storage_available: bool
    deployment_ca_file: bool = False


class ConnectionSave(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: str = Field(min_length=1, max_length=64)
    enabled: bool
    values: dict[str, str]
    secret: SecretStr | None = Field(default=None, max_length=4096)


class ConnectionSaved(BaseModel):
    saved: bool = True


class ConnectionTest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: str = Field(min_length=1, max_length=64)
    username: str = Field(default="", max_length=255)
    password: SecretStr | None = Field(default=None, max_length=4096)
    expected_role: Literal["admin", "analyst"] | None = None


class ConnectionTestResult(BaseModel):
    success: bool = True
    message: str
    role: Literal["admin", "analyst"] | None = None


def field_specs(provider: Provider):
    return (LDAP_FIELDS if provider == "ldap" else ASELIX_FIELDS) + [
        ConnectionField(key="CA_PEM", label="CA certificate chain (PEM)",
                        help="Public CA certificates for this connection. Leave blank to use system trust.",
                        advanced=True)]


def record(provider: Provider):
    with db.connect() as connection:
        apply_read_budget(connection)
        row = connection.execute("SELECT SUBSTR(value, 1, ?) AS value FROM app_settings WHERE key = ?",
                                 (MAX_RECORD + 1, "connection." + provider)).fetchone()
    raw = row["value"] if row else None
    if raw is None:
        return None, None
    try:
        data = json.loads(raw)
        keys = {field.key for field in field_specs(provider)}
        if (len(raw) > MAX_RECORD or not isinstance(data, dict)
                or set(data) != {"version", "enabled", "values", "secret_encrypted"}
                or data["version"] != 1 or type(data["enabled"]) is not bool
                or not isinstance(data["values"], dict) or set(data["values"]) != keys
                or any(not isinstance(v, str) for v in data["values"].values())
                or not isinstance(data["secret_encrypted"], str)):
            raise ValueError()
        return raw, data
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(503, "Stored connection settings are unreadable. Restore a valid configuration.") from None


def revision(raw):
    return hashlib.sha256(raw.encode()).hexdigest() if raw is not None else "environment"


def environment_values(provider: Provider):
    prefix = "MASP_" + provider.upper() + "_"
    values = {field.key: os.getenv(prefix + field.key, field.value) for field in field_specs(provider)}
    if provider == "ldap" and not os.getenv(prefix + "PORT"):
        values["PORT"] = "389" if values["TLS_MODE"] == "starttls" else "636"
    ca = os.getenv(prefix + "CA_PEM_B64", "")
    try:
        values["CA_PEM"] = base64.b64decode(ca, validate=True).decode("ascii") if ca else ""
    except (ValueError, UnicodeError):
        raise HTTPException(503, "Deployment CA settings are invalid. Correct the server configuration.") from None
    if any(len(v) > (64000 if k == "CA_PEM" else 2048) for k, v in values.items()):
        raise HTTPException(503, "Deployment connection settings exceed the console field limits.")
    return values


def enabled_from_environment(provider):
    raw = os.getenv("MASP_" + provider.upper() + "_ENABLED", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"} if provider == "ldap" else raw == "1"


def read(provider: Provider):
    raw, data = record(provider)
    values = data["values"] if data else environment_values(provider)
    return ConnectionSnapshot(provider=provider, revision=revision(raw),
        source="console" if data else "environment",
        enabled=data["enabled"] if data else enabled_from_environment(provider),
        fields=[field.model_copy(update={"value": values[field.key]}) for field in field_specs(provider)],
        has_secret=bool(data["secret_encrypted"]) if data else bool(os.getenv("MASP_" + provider.upper() + "_" + SECRET_SUFFIX[provider], "")),
        secret_storage_available=secret_encryption_available(),
        deployment_ca_file=provider == "ldap" and bool(os.getenv("MASP_LDAP_CA_CERT_FILE")))


def configuration_environment(provider: Provider, data, *, include_secret=True):
    prefix = "MASP_" + provider.upper() + "_"
    env = dict(os.environ)
    if data is None:
        return env
    env.update({prefix + key: value for key, value in data["values"].items() if key != "CA_PEM"})
    env[prefix + "CA_PEM_B64"] = base64.b64encode(data["values"]["CA_PEM"].encode("ascii")).decode()
    env[prefix + "ENABLED"] = "1" if data["enabled"] else "0"
    env[prefix + SECRET_SUFFIX[provider]] = ""
    if data["secret_encrypted"] and include_secret:
        secret = json.loads(decrypt_secret(data["secret_encrypted"]))
        if not isinstance(secret, str):
            raise HTTPException(503, "Stored connection credential is unreadable.")
        env[prefix + SECRET_SUFFIX[provider]] = secret
    return env


def effective_environment(provider: Provider):
    _, data = record(provider)
    return configuration_environment(provider, data, include_secret=data["enabled"] if data else True)


def is_enabled(provider: Provider):
    _, data = record(provider)
    return data["enabled"] if data else enabled_from_environment(provider)


def validate(provider, data):
    values = data["values"]
    specs = field_specs(provider)
    if set(values) != {field.key for field in specs}:
        raise HTTPException(422, "Supply every connection field shown by the editor.")
    for field in specs:
        value = values[field.key]
        if len(value) > (64000 if field.key == "CA_PEM" else 2048) or "\x00" in value:
            raise HTTPException(422, f"{field.label} exceeds its limit or contains a null character.")
        if field.choices and value not in field.choices:
            raise HTTPException(422, f"Select a supported {field.label}.")
    ca = values["CA_PEM"]
    if ca:
        try:
            if "PRIVATE KEY" in ca:
                raise ValueError()
            ssl.create_default_context(cadata=ca)
            ca.encode("ascii")
        except (ValueError, OSError, UnicodeError):
            raise HTTPException(422, "Provide a valid public CA certificate chain in PEM format.") from None
    if provider == "ldap":
        try:
            port = int(values["PORT"])
            connect = float(values["CONNECT_TIMEOUT"])
            receive = float(values["RECEIVE_TIMEOUT"])
            if not (1 <= port <= 65535 and 1 <= connect <= 15 and 1 <= receive <= 30):
                raise ValueError()
        except ValueError:
            raise HTTPException(422, "Directory port or timeout is outside the supported range.") from None
    if not data["enabled"]:
        return
    env = configuration_environment(provider, data)
    if provider == "ldap":
        from app.services.ldap_auth import LdapConfigurationError, load_ldap_config
        try:
            load_ldap_config(env)
        except LdapConfigurationError as exc:
            raise HTTPException(422, str(exc)) from None
    else:
        from app.services.aselix import settings
        settings(env)


def save(provider: Provider, body: ConnectionSave):
    raw, current = record(provider)
    if body.expected_revision != revision(raw):
        raise HTTPException(409, "Connection settings changed. Reload before saving.")
    secret = body.secret.get_secret_value() if body.secret else ""
    encrypted = current["secret_encrypted"] if current else ""
    if not current and not secret:
        secret = os.getenv("MASP_" + provider.upper() + "_" + SECRET_SUFFIX[provider], "")
    if secret:
        encrypted = encrypt_secret(json.dumps(secret))
    data = dict(version=1, enabled=body.enabled, values=body.values, secret_encrypted=encrypted)
    validate(provider, data)
    serialized = json.dumps(data, sort_keys=True)
    if len(serialized) > MAX_RECORD:
        raise HTTPException(413, "Connection settings exceed the storage limit.")
    with db.connect() as connection:
        apply_read_budget(connection)
        if db.using_postgres():
            connection.execute("SELECT set_config('lock_timeout', ?, true)", (f"{write_lock_timeout_ms()}ms",))
        if raw is None:
            result = connection.execute("""INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO NOTHING""", ("connection." + provider, serialized))
        else:
            result = connection.execute("""UPDATE app_settings SET value = ?, updated_at = CURRENT_TIMESTAMP
                WHERE key = ? AND value = ?""", (serialized, "connection." + provider, raw))
        if result.rowcount != 1:
            raise HTTPException(409, "Connection settings changed. Reload before saving.")


def test(provider: Provider, body: ConnectionTest, *, address: str | None = None):
    raw, data = record(provider)
    if body.expected_revision != revision(raw):
        raise HTTPException(409, "Connection settings changed. Reload before testing.")
    if not _test_slots.acquire(blocking=False):
        raise HTTPException(429, "Connection tests are busy. Try again later.")
    try:
        env = configuration_environment(provider, data)
        env["MASP_" + provider.upper() + "_ENABLED"] = "1"
        if provider == "aselix":
            from app.services.aselix import ask, ChatQuestion
            ask(ChatQuestion(question="Connection test. Reply OK."), environment=env)
            return ConnectionTestResult(message="Aselix answered a test question using the saved endpoint, credential and model.")
        from app.services.ldap_auth import authenticate_ldap, load_ldap_config, LdapConfigurationError, LdapUnavailableError
        from app.services import login_throttle
        if not body.username.strip() or not body.password or not body.expected_role:
            raise HTTPException(422, "Provide a test username, password and expected role.")
        wait = login_throttle.locked_for(body.username, address)
        if wait:
            raise HTTPException(429, login_throttle.message(wait))
        try:
            config = load_ldap_config(env)
            identity = authenticate_ldap(body.username, body.password.get_secret_value(), config)
        except (LdapConfigurationError, LdapUnavailableError):
            raise HTTPException(502, "LDAP test failed. Check DNS, TLS, search account, filter and group settings.") from None
        if identity is None:
            login_throttle.record_failure(body.username, address)
            raise HTTPException(422, "LDAP login or expected role could not be verified.")
        login_throttle.record_success(body.username)
        if identity.role != body.expected_role:
            raise HTTPException(422, "LDAP login or expected role could not be verified.")
        with db.connect() as connection:
            apply_read_budget(connection)
            local = connection.execute("""SELECT 1 FROM users WHERE auth_source = 'local'
                AND LOWER(username) IN (LOWER(?), LOWER(?)) LIMIT 1""", (body.username, identity.username)).fetchone()
        if local:
            raise HTTPException(409, "The directory username conflicts with a local MASP account.")
        return ConnectionTestResult(message="LDAP credentials and expected role verified.", role=identity.role)
    finally:
        _test_slots.release()
