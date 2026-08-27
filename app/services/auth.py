from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass
from urllib.parse import quote

from fastapi import HTTPException, Request

from app.database import (
    create_auth_session,
    create_user,
    delete_auth_session,
    delete_auth_sessions_for_user,
    delete_expired_auth_sessions,
    get_setting,
    has_active_api_client_credentials,
    get_user_by_session,
    get_user_by_username,
    sync_external_user,
)
from app.models import ApiClientIdentity, UserRecord
from app.services.auth_roles import ROLE_ADMIN, ROLE_ANALYST
from app.services.ldap_auth import (
    LdapConfigurationError,
    LdapUnavailableError,
    authenticate_ldap,
)
from app.services.service_clients import (
    legacy_service_client_identity,
    resolve_stored_api_client,
)


SESSION_COOKIE = "masp_session"
SESSION_TTL_SECONDS = 12 * 60 * 60
PASSWORD_ITERATIONS = 260_000
API_TOKENS_SETTING_KEY = "api.tokens"
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class LoginResult:
    user: UserRecord
    session_token: str
    expires_at: int


def seed_default_users() -> None:
    # No hardcoded default passwords: a user is seeded only when its password is
    # provided via the environment. This keeps a fresh deployment from ever
    # having a well-known credential. The pilot compose makes MASP_ADMIN_PASSWORD
    # a required variable, so the stack refuses to start without one.
    default_users = [
        (
            os.getenv("MASP_ADMIN_USERNAME", "admin"),
            os.getenv("MASP_ADMIN_PASSWORD", ""),
            ROLE_ADMIN,
        ),
        (
            os.getenv("MASP_ANALYST_USERNAME", "analyst"),
            os.getenv("MASP_ANALYST_PASSWORD", ""),
            ROLE_ANALYST,
        ),
    ]

    for username, password, role in default_users:
        if not username or get_user_by_username(username) is not None:
            continue
        if not password:
            print(
                f"[auth] {role} user '{username}' not seeded: set "
                f"MASP_{role.upper()}_PASSWORD to create it.",
                flush=True,
            )
            continue
        if password.startswith("CHANGE_ME"):
            # Defense in depth if the installer's placeholder check is bypassed.
            print(
                f"[auth] {role} user '{username}' not seeded: "
                f"MASP_{role.upper()}_PASSWORD is still a placeholder.",
                flush=True,
            )
            continue
        create_user(username, hash_password(password), role)


def dev_login_hint() -> str | None:
    # Off by default; opt-in only, and never invents a password — it can only
    # reflect credentials explicitly configured in the environment. There are no
    # hardcoded defaults left to leak.
    show_hint = os.getenv("MASP_SHOW_DEV_LOGIN_HINTS", "0").strip().lower()
    if show_hint not in {"1", "true", "yes", "on"}:
        return None

    admin_username = os.getenv("MASP_ADMIN_USERNAME", "admin")
    admin_password = os.getenv("MASP_ADMIN_PASSWORD", "")
    analyst_username = os.getenv("MASP_ANALYST_USERNAME", "analyst")
    analyst_password = os.getenv("MASP_ANALYST_PASSWORD", "")
    parts = []
    if admin_password:
        parts.append(f"{admin_username} / {admin_password}")
    if analyst_password:
        parts.append(f"{analyst_username} / {analyst_password}")
    return " | ".join(parts) or None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return "$".join(
        [
            "pbkdf2_sha256",
            str(PASSWORD_ITERATIONS),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        ]
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        salt = base64.b64decode(salt_text.encode("ascii"))
        expected_digest = base64.b64decode(digest_text.encode("ascii"))
    except (ValueError, TypeError):
        return False

    actual_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual_digest, expected_digest)


def authenticate(username: str, password: str) -> UserRecord | None:
    clean_username = username.strip()
    if (
        not clean_username
        or not password
        or len(clean_username) > 255
        or len(password) > 4_096
    ):
        return None

    user = get_user_by_username(clean_username)
    if user is not None and user.auth_source == "local":
        if not verify_password(password, user.password_hash):
            return None
        return user

    try:
        identity = authenticate_ldap(clean_username, password)
    except (LdapConfigurationError, LdapUnavailableError) as exc:
        LOGGER.error("LDAP authentication unavailable: %s", exc)
        return None
    if identity is None:
        return None
    try:
        return sync_external_user(
            username=identity.username,
            role=identity.role,
            external_id=identity.external_id,
            display_name=identity.display_name,
        )
    except ValueError:
        # A directory identity must never claim an existing local account.
        LOGGER.warning(
            "LDAP login rejected because the directory username conflicts "
            "with a local account."
        )
        return None


def login(username: str, password: str) -> LoginResult | None:
    user = authenticate(username, password)
    if user is None:
        return None

    now = int(time.time())
    delete_expired_auth_sessions(now)
    session_token = secrets.token_urlsafe(32)
    create_auth_session(
        user_id=user.id,
        token_hash=hash_session_token(session_token),
        expires_at=now + SESSION_TTL_SECONDS,
    )
    return LoginResult(
        user=user,
        session_token=session_token,
        expires_at=now + SESSION_TTL_SECONDS,
    )


def logout(session_token: str | None) -> None:
    if session_token:
        delete_auth_session(hash_session_token(session_token))


def revoke_user_sessions(user_id: int) -> None:
    delete_auth_sessions_for_user(user_id)


def current_user(request: Request) -> UserRecord | None:
    session_token = request.cookies.get(SESSION_COOKIE)
    if not session_token:
        return None
    return get_user_by_session(hash_session_token(session_token), int(time.time()))


def require_user(request: Request) -> UserRecord:
    user = current_user(request)
    if user is None:
        next_path = request.url.path
        if request.url.query:
            next_path = f"{next_path}?{request.url.query}"
        raise HTTPException(
            status_code=303,
            headers={"Location": f"/login?next={quote(next_path, safe='/')}"}
        )
    return user


def require_admin(request: Request) -> UserRecord:
    user = require_user(request)
    if user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Admin permission is required.")
    return user


def hash_session_token(session_token: str) -> str:
    return hashlib.sha256(session_token.encode("utf-8")).hexdigest()


def session_cookie_secure(request: Request) -> bool:
    configured = os.getenv("MASP_SESSION_SECURE", "").strip().lower()
    if configured in {"1", "true", "yes", "on"}:
        return True
    if configured in {"0", "false", "no", "off"}:
        return False
    return request.url.scheme == "https"


def configured_api_tokens() -> list[str]:
    seen: set[str] = set()
    tokens: list[str] = []
    raw_values = [
        os.getenv("MASP_API_TOKENS", ""),
        os.getenv("MASP_API_TOKEN", ""),
        get_setting(API_TOKENS_SETTING_KEY, "") or "",
    ]
    for raw_value in raw_values:
        for candidate in raw_value.replace("\n", ",").split(","):
            token = candidate.strip()
            if not token or token in seen:
                continue
            seen.add(token)
            tokens.append(token)
    return tokens


def bearer_token_from_request(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "").strip()
    if not authorization:
        return None
    scheme, _, credentials = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = credentials.strip()
    return token or None


def require_api_token(request: Request) -> str:
    tokens = configured_api_tokens()
    provided_token = bearer_token_from_request(request)
    if provided_token and any(
        hmac.compare_digest(provided_token, token) for token in tokens
    ):
        identity = legacy_service_client_identity()
        request.state.api_client = identity
        return provided_token

    if provided_token:
        identity = resolve_stored_api_client(provided_token)
        if identity is not None:
            request.state.api_client = identity
            return provided_token

    if not tokens and not has_active_api_client_credentials():
        raise HTTPException(
            status_code=503,
            detail="API token authentication is not configured.",
        )

    raise HTTPException(
        status_code=401,
        detail="Bearer token required.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def api_client_identity(request: Request) -> ApiClientIdentity:
    identity = getattr(request.state, "api_client", None)
    if not isinstance(identity, ApiClientIdentity):
        require_api_token(request)
        identity = getattr(request.state, "api_client", None)
    if not isinstance(identity, ApiClientIdentity):
        raise HTTPException(status_code=401, detail="Bearer token required.")
    return identity
