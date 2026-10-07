"""Runtime-editable scan policy settings for the REST scan API.

Single source of truth for the operational knobs that govern the REST scan
API. Each value resolves in three tiers:

1. an admin-set database override (``app_settings``), else
2. the environment variable, else
3. a hardcoded default.

Values are clamped to a safe range on read and validated on write, so the
admin panel can never store — and the API can never act on — an out-of-range
value (defence in depth: a bad stored value is still bounded on read).

Deployment/wiring config (``MASP_DATABASE_URL``, bind host/port, worker engine
keys, ...) is deliberately NOT here: those are read once at process boot and
cannot be changed from a running web process. ICAP gateway tuning
(``MASP_ICAP_*``) is also out of scope for now because the ICAP process caches
its config at startup; see docs/integrations/ICAP_GATEWAY.md.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from app.database import delete_setting, get_setting, set_setting

SETTING_PREFIX = "scan_policy."


@dataclass(frozen=True)
class PolicySpec:
    key: str
    env_var: str
    default: int
    minimum: int
    maximum: int
    label: str
    help: str
    unit: str = ""
    # How the console edits it: "number", "size" (bytes, edited in MiB) or
    # "switch" (0 off, 1 on).
    control: str = "number"


# 5 GiB upper bound on the upload cap is a sanity ceiling, not a product limit;
# 0 means "unlimited" for this knob.
_MAX_UPLOAD_CEILING = 5 * 1024 * 1024 * 1024

SPECS: tuple[PolicySpec, ...] = (
    PolicySpec(
        key="api_max_wait_seconds",
        env_var="MASP_API_MAX_WAIT_SECONDS",
        default=15,
        minimum=0,
        maximum=300,
        label="API wait for a result",
        help=(
            "How long an API upload waits for the finished verdict before answering "
            "\"accepted, ask again later\". 0 = always answer at once."
        ),
        unit="seconds",
    ),
    PolicySpec(
        key="api_retry_after_seconds",
        env_var="MASP_API_RETRY_AFTER_SECONDS",
        default=2,
        minimum=1,
        maximum=30,
        label="API poll interval",
        help="How often API clients are told to ask again while a scan is still running.",
        unit="seconds",
    ),
    PolicySpec(
        key="upload_max_bytes",
        env_var="MASP_UPLOAD_MAX_BYTES",
        default=0,
        minimum=0,
        maximum=_MAX_UPLOAD_CEILING,
        label="Largest upload",
        help=(
            "Largest file the API and the console accept. 0 = no limit here; the server's "
            "request size limit still applies. The ICAP gateway has its own limit."
        ),
        unit="bytes",
        control="size",
    ),
    PolicySpec(
        key="siem_not_allowed_events",
        env_var="MASP_SIEM_NOT_ALLOWED_EVENTS",
        default=0,
        minimum=0,
        maximum=1,
        label="Send not-allowed files to SIEM",
        help=(
            "Also send an event when a client's rules refuse a file that no engine detected, "
            "wherever malware detections are sent. Off: only malware is reported. "
            "Not-allowed files never appear in the notification bell."
        ),
        control="switch",
    ),
)

_SPEC_BY_KEY = {spec.key: spec for spec in SPECS}


def spec_for(key: str) -> PolicySpec:
    return _SPEC_BY_KEY[key]


def _clamp(value: int, spec: PolicySpec) -> int:
    return max(spec.minimum, min(value, spec.maximum))


def resolve_int(key: str) -> int:
    """Effective value for ``key`` (DB override -> env -> default), clamped.

    Resilient by design: any database problem falls back to the env/default so
    the scan API never fails because a settings read did.
    """
    spec = _SPEC_BY_KEY[key]
    raw: str | None = None
    try:
        raw = get_setting(SETTING_PREFIX + key, None)
    except Exception:  # noqa: BLE001 - never let a settings read break the API
        raw = None

    return resolve_raw(key, raw)


def resolve_raw(key: str, raw: str | None) -> int:
    """Resolve a previously read override with the same runtime fallback rules."""
    spec = _SPEC_BY_KEY[key]
    if raw is None or raw.strip() == "":
        raw = os.getenv(spec.env_var, "").strip()

    if raw == "":
        return spec.default
    try:
        return _clamp(int(raw), spec)
    except ValueError:
        return spec.default


def validate(key: str, raw: str) -> tuple[int | None, str | None]:
    """Validate a submitted value.

    Returns ``(value, error)``. A blank ``raw`` means "revert to default" and
    yields ``(None, None)``. On a bad value, returns ``(None, error_message)``.
    """
    spec = _SPEC_BY_KEY[key]
    raw = raw.strip()
    if raw == "":
        return None, None
    try:
        value = int(raw)
    except ValueError:
        return None, f"{spec.label}: '{raw}' is not a whole number."
    if value < spec.minimum or value > spec.maximum:
        return (
            None,
            f"{spec.label}: must be between {spec.minimum} and {spec.maximum}.",
        )
    return value, None


def store(key: str, value: int | None) -> None:
    """Persist an override. ``None`` deletes it (revert to env/default)."""
    full_key = SETTING_PREFIX + key
    if value is None:
        delete_setting(full_key)
    else:
        set_setting(full_key, str(value))


def override_raw(key: str) -> str:
    """The stored override string for ``key`` (empty when none is set)."""
    try:
        raw = get_setting(SETTING_PREFIX + key, None)
    except Exception:  # noqa: BLE001
        return ""
    return (raw or "").strip()


def has_override(key: str) -> bool:
    return override_raw(key) != ""


def env_value(key: str) -> str:
    return os.getenv(_SPEC_BY_KEY[key].env_var, "").strip()


def snapshot() -> list[dict]:
    """Per-field effective value + provenance, for the admin panel."""
    rows: list[dict] = []
    for spec in SPECS:
        raw = override_raw(spec.key)
        override = raw != ""
        env = env_value(spec.key)
        if override:
            source = "database override"
        elif env != "":
            source = f"environment ({spec.env_var})"
        else:
            source = "default"
        rows.append(
            {
                "spec": spec,
                "value": resolve_int(spec.key),
                "has_override": override,
                "override_raw": raw,
                "env_value": env,
                "source": source,
            }
        )
    return rows
