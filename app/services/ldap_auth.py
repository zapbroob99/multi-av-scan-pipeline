from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from typing import Any, Mapping

from app.services.auth_roles import ROLE_ADMIN, ROLE_ANALYST


TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


class LdapConfigurationError(RuntimeError):
    """LDAP authentication is enabled but its settings are invalid."""


class LdapUnavailableError(RuntimeError):
    """The configured LDAP directory cannot currently be reached or queried."""


@dataclass(frozen=True)
class LdapConfig:
    enabled: bool
    host: str = ""
    port: int = 636
    tls_mode: str = "ldaps"
    ca_cert_file: str | None = None
    connect_timeout: float = 5.0
    receive_timeout: float = 8.0
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    user_filter: str = "(sAMAccountName={username})"
    username_attribute: str = "sAMAccountName"
    display_name_attribute: str = "displayName"
    group_attribute: str = "memberOf"
    admin_group_dn: str = ""
    analyst_group_dn: str = ""


@dataclass(frozen=True)
class LdapIdentity:
    username: str
    external_id: str
    display_name: str | None
    role: str


def _env_bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in TRUE_VALUES:
        return True
    if raw in FALSE_VALUES:
        return False
    raise LdapConfigurationError(f"{name} must be true or false.")


def _positive_number(
    env: Mapping[str, str],
    name: str,
    default: float,
    converter: type[int] | type[float],
) -> int | float:
    raw = env.get(name, "").strip()
    if not raw:
        return converter(default)
    try:
        value = converter(raw)
    except ValueError as exc:
        raise LdapConfigurationError(f"{name} must be a number.") from exc
    if value <= 0:
        raise LdapConfigurationError(f"{name} must be greater than zero.")
    return value


def load_ldap_config(env: Mapping[str, str] | None = None) -> LdapConfig:
    source = os.environ if env is None else env
    enabled = _env_bool(source, "MASP_LDAP_ENABLED")
    if not enabled:
        return LdapConfig(enabled=False)

    tls_mode = source.get("MASP_LDAP_TLS_MODE", "ldaps").strip().lower()
    if tls_mode not in {"ldaps", "starttls"}:
        raise LdapConfigurationError(
            "MASP_LDAP_TLS_MODE must be 'ldaps' or 'starttls'; insecure LDAP is not supported."
        )

    default_port = 636 if tls_mode == "ldaps" else 389
    config = LdapConfig(
        enabled=True,
        host=source.get("MASP_LDAP_HOST", "").strip(),
        port=int(_positive_number(source, "MASP_LDAP_PORT", default_port, int)),
        tls_mode=tls_mode,
        ca_cert_file=source.get("MASP_LDAP_CA_CERT_FILE", "").strip() or None,
        connect_timeout=float(
            _positive_number(source, "MASP_LDAP_CONNECT_TIMEOUT", 5.0, float)
        ),
        receive_timeout=float(
            _positive_number(source, "MASP_LDAP_RECEIVE_TIMEOUT", 8.0, float)
        ),
        bind_dn=source.get("MASP_LDAP_BIND_DN", "").strip(),
        bind_password=source.get("MASP_LDAP_BIND_PASSWORD", ""),
        base_dn=source.get("MASP_LDAP_BASE_DN", "").strip(),
        user_filter=(
            source.get("MASP_LDAP_USER_FILTER", "").strip()
            or "(sAMAccountName={username})"
        ),
        username_attribute=(
            source.get("MASP_LDAP_USERNAME_ATTRIBUTE", "").strip()
            or "sAMAccountName"
        ),
        display_name_attribute=(
            source.get("MASP_LDAP_DISPLAY_NAME_ATTRIBUTE", "").strip()
            or "displayName"
        ),
        group_attribute=(
            source.get("MASP_LDAP_GROUP_ATTRIBUTE", "").strip()
            or "memberOf"
        ),
        admin_group_dn=source.get("MASP_LDAP_ADMIN_GROUP_DN", "").strip(),
        analyst_group_dn=source.get("MASP_LDAP_ANALYST_GROUP_DN", "").strip(),
    )

    required = {
        "MASP_LDAP_HOST": config.host,
        "MASP_LDAP_BIND_DN": config.bind_dn,
        "MASP_LDAP_BIND_PASSWORD": config.bind_password,
        "MASP_LDAP_BASE_DN": config.base_dn,
        "MASP_LDAP_USER_FILTER": config.user_filter,
        "MASP_LDAP_USERNAME_ATTRIBUTE": config.username_attribute,
        "MASP_LDAP_GROUP_ATTRIBUTE": config.group_attribute,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise LdapConfigurationError(
            "Missing required LDAP settings: " + ", ".join(missing) + "."
        )
    if "{username}" not in config.user_filter:
        raise LdapConfigurationError(
            "MASP_LDAP_USER_FILTER must contain the {username} placeholder."
        )
    if config.port > 65_535:
        raise LdapConfigurationError("MASP_LDAP_PORT must be at most 65535.")
    if not config.admin_group_dn and not config.analyst_group_dn:
        raise LdapConfigurationError(
            "At least one LDAP admin or analyst group DN must be configured."
        )
    return config


def ldap_enabled(env: Mapping[str, str] | None = None) -> bool:
    try:
        return load_ldap_config(env).enabled
    except LdapConfigurationError:
        return True


def authenticate_ldap(
    username: str,
    password: str,
    config: LdapConfig | None = None,
) -> LdapIdentity | None:
    clean_username = username.strip()
    if (
        not clean_username
        or not password
        or len(clean_username) > 255
        or len(password) > 4_096
    ):
        return None
    active_config = config or load_ldap_config()
    if not active_config.enabled:
        return None

    ldap3, ldap_exceptions, escape_filter_chars = _load_ldap3()
    tls = ldap3.Tls(
        validate=ssl.CERT_REQUIRED,
        ca_certs_file=active_config.ca_cert_file,
        valid_names=[active_config.host],
    )
    server = ldap3.Server(
        active_config.host,
        port=active_config.port,
        use_ssl=active_config.tls_mode == "ldaps",
        tls=tls,
        connect_timeout=active_config.connect_timeout,
    )
    auto_bind = (
        ldap3.AUTO_BIND_TLS_BEFORE_BIND
        if active_config.tls_mode == "starttls"
        else ldap3.AUTO_BIND_NO_TLS
    )
    attributes = [
        active_config.username_attribute,
        active_config.group_attribute,
    ]
    if active_config.display_name_attribute:
        attributes.append(active_config.display_name_attribute)

    service_connection = None
    try:
        service_connection = ldap3.Connection(
            server,
            user=active_config.bind_dn,
            password=active_config.bind_password,
            auto_bind=auto_bind,
            auto_referrals=False,
            client_strategy=ldap3.SAFE_SYNC,
            read_only=True,
            raise_exceptions=True,
            receive_timeout=active_config.receive_timeout,
        )
        escaped_username = escape_filter_chars(clean_username)
        search_filter = active_config.user_filter.replace(
            "{username}", escaped_username
        )
        search_result = service_connection.search(
            search_base=active_config.base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            size_limit=2,
        )
        if isinstance(search_result, tuple) and len(search_result) >= 3:
            if not search_result[0]:
                raise LdapUnavailableError("LDAP search did not complete successfully.")
            response = search_result[2]
        else:
            response = service_connection.response
        entries = [
            item
            for item in (response or [])
            if isinstance(item, dict) and item.get("type") == "searchResEntry"
        ]
        if len(entries) != 1:
            return None
        entry = entries[0]
        user_dn = str(entry.get("dn", "")).strip()
        values = entry.get("attributes") or {}
        if not user_dn or not isinstance(values, dict):
            return None
        raw_groups = values.get(active_config.group_attribute)
        directory_username = _first_text(
            values.get(active_config.username_attribute)
        ) or clean_username
        if len(directory_username) > 255:
            return None
        display_name = _first_text(
            values.get(active_config.display_name_attribute)
        )
    except ldap_exceptions.LDAPException as exc:
        raise LdapUnavailableError("LDAP search failed.") from exc
    finally:
        if service_connection is not None:
            service_connection.unbind()

    user_connection = None
    try:
        user_connection = ldap3.Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=auto_bind,
            auto_referrals=False,
            client_strategy=ldap3.SAFE_SYNC,
            read_only=True,
            raise_exceptions=True,
            receive_timeout=active_config.receive_timeout,
        )
    except ldap_exceptions.LDAPBindError:
        return None
    except ldap_exceptions.LDAPException as exc:
        raise LdapUnavailableError("LDAP user bind failed.") from exc
    finally:
        if user_connection is not None:
            user_connection.unbind()

    role = _mapped_role(raw_groups, active_config)
    if role is None:
        return None

    return LdapIdentity(
        username=directory_username,
        external_id=user_dn,
        display_name=display_name,
        role=role,
    )


def _mapped_role(raw_groups: Any, config: LdapConfig) -> str | None:
    if isinstance(raw_groups, str):
        groups = [raw_groups]
    elif isinstance(raw_groups, (list, tuple, set)):
        groups = [str(value) for value in raw_groups]
    elif raw_groups is None:
        groups = []
    else:
        groups = [str(raw_groups)]
    normalized = {group.strip().casefold() for group in groups if group.strip()}
    if config.admin_group_dn and config.admin_group_dn.casefold() in normalized:
        return ROLE_ADMIN
    if config.analyst_group_dn and config.analyst_group_dn.casefold() in normalized:
        return ROLE_ANALYST
    return None


def _first_text(value: Any) -> str | None:
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _load_ldap3() -> tuple[Any, Any, Any]:
    try:
        import ldap3
        from ldap3.core import exceptions as ldap_exceptions
        from ldap3.utils.conv import escape_filter_chars
    except ImportError as exc:
        raise LdapUnavailableError(
            "LDAP support is enabled but the ldap3 dependency is not installed."
        ) from exc
    return ldap3, ldap_exceptions, escape_filter_chars
