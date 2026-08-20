"""VirusTotal file-hash reputation lookup.

Only a SHA-256 digest is sent to VirusTotal. This module never uploads file
content and never requests a re-analysis. Unknown or unavailable reputation is
therefore not equivalent to a clean result.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from app.services.hash_scanning import (
    HashEngineError,
    HashEngineNotConfiguredError,
    HashEngineQuotaError,
)
from app.services.secret_store import SecretStoreError, decrypt_secret


VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
VIRUSTOTAL_PROBE_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855"
)
MAX_RESPONSE_BYTES = 1024 * 1024
STAT_KEYS = (
    "malicious",
    "suspicious",
    "undetected",
    "harmless",
    "timeout",
    "failure",
    "type-unsupported",
    "confirmed-timeout",
)


class InvalidSha256Error(ValueError):
    pass


class VirusTotalNotConfiguredError(HashEngineNotConfiguredError):
    pass


class VirusTotalUnavailableError(HashEngineError):
    pass


class VirusTotalQuotaError(VirusTotalUnavailableError, HashEngineQuotaError):
    status_code = 503
    def __init__(self, retry_after: int | None = None) -> None:
        super().__init__("VirusTotal quota or rate limit was exceeded.")
        self.retry_after = retry_after


@dataclass(frozen=True)
class VirusTotalConfig:
    api_key: str
    timeout_seconds: int
    cache_seconds: int
    unknown_cache_seconds: int
    cache_max_entries: int
    malicious_threshold: int
    allow_undetected: bool
    max_age_days: int


@dataclass(frozen=True)
class VirusTotalReport:
    sha256: str
    stats: dict[str, int]
    last_analysis_date: datetime | None


@dataclass(frozen=True)
class _CacheEntry:
    report: VirusTotalReport | None
    expires_at: float


class _NoRedirectHandler(HTTPRedirectHandler):
    """Never forward the API-key-bearing request to a redirected host."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


_URL_OPENER = build_opener(_NoRedirectHandler())
_CACHE: OrderedDict[str, _CacheEntry] = OrderedDict()
_CACHE_LOCK = threading.Lock()


def normalize_sha256(raw_value: str) -> str:
    normalized = raw_value.strip().lower()
    if len(normalized) != 64:
        raise InvalidSha256Error("Hash must be a 64-character SHA-256 hex digest.")
    if any(char not in "0123456789abcdef" for char in normalized):
        raise InvalidSha256Error("Hash must contain only hexadecimal characters.")
    return normalized


def load_virustotal_config(
    environ: Mapping[str, str] | None = None,
    config_override: Mapping[str, str] | None = None,
) -> VirusTotalConfig:
    values = os.environ if environ is None else environ
    # Registry-backed execution is enabled/disabled by the engine instance.
    # Direct callers retain the legacy environment switch for compatibility.
    if config_override is None and not _bool_value(
        values.get("MASP_VIRUSTOTAL_ENABLED", "0"), default=False
    ):
        raise VirusTotalNotConfiguredError("VirusTotal hash lookup is not enabled.")

    encrypted_key = _override_value(config_override, "api_key_encrypted")
    if encrypted_key:
        try:
            api_key = decrypt_secret(encrypted_key, values)
        except SecretStoreError as exc:
            raise VirusTotalNotConfiguredError(str(exc)) from exc
    else:
        api_key = values.get("MASP_VIRUSTOTAL_API_KEY", "").strip()
    if not api_key or api_key.startswith("CHANGE_ME"):
        raise VirusTotalNotConfiguredError(
            "VirusTotal API key is not configured."
        )

    return VirusTotalConfig(
        api_key=api_key,
        timeout_seconds=_bounded_int(
            _override_or_env(
                config_override, "timeout_seconds", values, "MASP_VIRUSTOTAL_TIMEOUT_SECONDS"
            ),
            default=10,
            minimum=1,
            maximum=60,
        ),
        cache_seconds=_bounded_int(
            _override_or_env(
                config_override, "cache_seconds", values, "MASP_VIRUSTOTAL_CACHE_SECONDS"
            ),
            default=3600,
            minimum=0,
            maximum=86400,
        ),
        unknown_cache_seconds=_bounded_int(
            _override_or_env(
                config_override,
                "unknown_cache_seconds",
                values,
                "MASP_VIRUSTOTAL_UNKNOWN_CACHE_SECONDS",
            ),
            default=300,
            minimum=0,
            maximum=3600,
        ),
        cache_max_entries=_bounded_int(
            _override_or_env(
                config_override,
                "cache_max_entries",
                values,
                "MASP_VIRUSTOTAL_CACHE_MAX_ENTRIES",
            ),
            default=10000,
            minimum=1,
            maximum=100000,
        ),
        malicious_threshold=_bounded_int(
            _override_or_env(
                config_override,
                "malicious_threshold",
                values,
                "MASP_VIRUSTOTAL_MALICIOUS_THRESHOLD",
            ),
            default=1,
            minimum=1,
            maximum=100,
        ),
        allow_undetected=_bool_value(
            _override_or_env(
                config_override,
                "allow_undetected",
                values,
                "MASP_VIRUSTOTAL_ALLOW_UNDETECTED",
            ),
            default=False,
        ),
        max_age_days=_bounded_int(
            _override_or_env(
                config_override, "max_age_days", values, "MASP_VIRUSTOTAL_MAX_AGE_DAYS"
            ),
            default=30,
            minimum=1,
            maximum=3650,
        ),
    )


def lookup_virustotal_hash(
    raw_hash: str,
    config_override: Mapping[str, str] | None = None,
) -> dict[str, object]:
    sha256 = normalize_sha256(raw_hash)
    config = load_virustotal_config(config_override=config_override)
    report, cached = _cached_report(sha256, config)
    return build_reputation_payload(sha256, report, config, cached=cached)


def probe_virustotal_connection(
    config_override: Mapping[str, str] | None = None,
) -> dict[str, str | bool]:
    """Perform an explicit, uncached credential/connectivity check."""
    try:
        config = load_virustotal_config(config_override=config_override)
        _fetch_report(VIRUSTOTAL_PROBE_SHA256, config)
    except (VirusTotalNotConfiguredError, VirusTotalUnavailableError) as exc:
        return {"ok": False, "status": "unavailable", "detail": str(exc)}
    return {
        "ok": True,
        "status": "available",
        "detail": "VirusTotal credentials and HTTPS connectivity are working.",
    }


def build_reputation_payload(
    sha256: str,
    report: VirusTotalReport | None,
    config: VirusTotalConfig,
    *,
    cached: bool,
    now: datetime | None = None,
) -> dict[str, object]:
    policy = {
        "malicious_threshold": config.malicious_threshold,
        "allow_undetected": config.allow_undetected,
        "max_age_days": config.max_age_days,
    }
    if report is None:
        return {
            "hash": sha256,
            "algorithm": "sha256",
            "source": "virustotal",
            "found": False,
            "status": "unknown",
            "detail": "VirusTotal has no report for this hash; it must not be treated as clean.",
            "decision": {
                "action": "review",
                "reason": "No VirusTotal reputation is available for this hash.",
            },
            "stats": None,
            "last_analysis_date": None,
            "permalink": None,
            "cached": cached,
            "policy": policy,
        }

    stats = report.stats
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    total = sum(stats.values())
    if malicious >= config.malicious_threshold:
        status = "malicious"
        action = "block"
        reason = (
            f"{malicious} VirusTotal engine(s) reported malicious, meeting the "
            f"configured threshold of {config.malicious_threshold}."
        )
    elif malicious > 0 or suspicious > 0:
        status = "suspicious"
        action = "review"
        reason = (
            "VirusTotal reported a suspicious or below-threshold malicious signal; "
            "manual review is required."
        )
    elif total == 0:
        status = "unknown"
        action = "review"
        reason = "The VirusTotal report contains no completed engine statistics."
    elif not _report_is_fresh(report, config, now=now):
        status = "stale"
        action = "review"
        reason = (
            "VirusTotal reported no malicious or suspicious engines, but the analysis "
            f"is missing or older than the configured {config.max_age_days}-day limit."
        )
    else:
        status = "undetected"
        action = "allow" if config.allow_undetected else "review"
        reason = (
            "VirusTotal reported no malicious or suspicious engines; policy allows "
            "undetected hashes."
            if config.allow_undetected
            else "VirusTotal reported no malicious or suspicious engines, but policy "
            "requires review because an undetected result is not proof that a file is clean."
        )

    public_stats = {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "undetected": stats["undetected"],
        "harmless": stats["harmless"],
        "timeout": stats["timeout"],
        "failure": stats["failure"],
        "type_unsupported": stats["type-unsupported"],
        "confirmed_timeout": stats["confirmed-timeout"],
        "total": total,
    }
    return {
        "hash": sha256,
        "algorithm": "sha256",
        "source": "virustotal",
        "found": True,
        "status": status,
        "detail": reason,
        "decision": {"action": action, "reason": reason},
        "stats": public_stats,
        "last_analysis_date": (
            report.last_analysis_date.isoformat() if report.last_analysis_date else None
        ),
        "permalink": f"https://www.virustotal.com/gui/file/{report.sha256}",
        "cached": cached,
        "policy": policy,
    }


def clear_virustotal_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def _cached_report(
    sha256: str,
    config: VirusTotalConfig,
) -> tuple[VirusTotalReport | None, bool]:
    now = time.monotonic()
    with _CACHE_LOCK:
        entry = _CACHE.get(sha256)
        if entry is not None and entry.expires_at > now:
            _CACHE.move_to_end(sha256)
            return entry.report, True
        if entry is not None:
            _CACHE.pop(sha256, None)

    report = _fetch_report(sha256, config)
    ttl = config.cache_seconds if report is not None else config.unknown_cache_seconds
    if ttl > 0:
        with _CACHE_LOCK:
            _CACHE[sha256] = _CacheEntry(
                report=report,
                expires_at=time.monotonic() + ttl,
            )
            _CACHE.move_to_end(sha256)
            while len(_CACHE) > config.cache_max_entries:
                _CACHE.popitem(last=False)
    return report, False


def _fetch_report(
    sha256: str,
    config: VirusTotalConfig,
) -> VirusTotalReport | None:
    request = Request(
        VIRUSTOTAL_FILE_URL.format(sha256=sha256),
        headers={
            "Accept": "application/json",
            "User-Agent": "MASP/0.1.0",
            "x-apikey": config.api_key,
        },
        method="GET",
    )
    try:
        with _URL_OPENER.open(request, timeout=config.timeout_seconds) as response:
            raw_body = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code == 429:
            raise VirusTotalQuotaError(_retry_after_seconds(exc.headers.get("Retry-After"))) from exc
        if exc.code in {401, 403}:
            raise VirusTotalNotConfiguredError(
                "VirusTotal rejected the configured API credentials or license."
            ) from exc
        raise VirusTotalUnavailableError("VirusTotal returned an upstream HTTP error.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise VirusTotalUnavailableError("VirusTotal could not be reached.") from exc

    if len(raw_body) > MAX_RESPONSE_BYTES:
        raise VirusTotalUnavailableError("VirusTotal returned an unexpectedly large response.")
    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VirusTotalUnavailableError("VirusTotal returned malformed JSON.") from exc
    return _parse_report(payload, sha256)


def _parse_report(payload: object, requested_sha256: str) -> VirusTotalReport:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        raise VirusTotalUnavailableError("VirusTotal returned an invalid file report.")
    data = payload["data"]
    response_sha256 = str(data.get("id", "")).strip().lower()
    if response_sha256 != requested_sha256:
        raise VirusTotalUnavailableError("VirusTotal returned a report for a different hash.")
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        raise VirusTotalUnavailableError("VirusTotal returned a file report without attributes.")
    raw_stats = attributes.get("last_analysis_stats", {})
    if not isinstance(raw_stats, dict):
        raise VirusTotalUnavailableError("VirusTotal returned invalid analysis statistics.")
    stats = {key: _nonnegative_stat(raw_stats.get(key, 0)) for key in STAT_KEYS}
    return VirusTotalReport(
        sha256=response_sha256,
        stats=stats,
        last_analysis_date=_timestamp_value(attributes.get("last_analysis_date")),
    )


def _nonnegative_stat(raw_value: object) -> int:
    if isinstance(raw_value, bool):
        raise VirusTotalUnavailableError("VirusTotal returned invalid analysis statistics.")
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise VirusTotalUnavailableError("VirusTotal returned invalid analysis statistics.") from exc
    if value < 0:
        raise VirusTotalUnavailableError("VirusTotal returned invalid analysis statistics.")
    return value


def _timestamp_value(raw_value: object) -> datetime | None:
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        raise VirusTotalUnavailableError("VirusTotal returned an invalid analysis date.")
    try:
        value = int(raw_value)
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError) as exc:
        raise VirusTotalUnavailableError("VirusTotal returned an invalid analysis date.") from exc


def _retry_after_seconds(raw_value: str | None) -> int | None:
    try:
        value = int(raw_value or "")
    except ValueError:
        return None
    return value if value > 0 else None


def _report_is_fresh(
    report: VirusTotalReport,
    config: VirusTotalConfig,
    *,
    now: datetime | None,
) -> bool:
    if report.last_analysis_date is None:
        return False
    current = now or datetime.now(timezone.utc)
    return report.last_analysis_date >= current - timedelta(days=config.max_age_days)


def _override_value(
    config_override: Mapping[str, str] | None,
    key: str,
) -> str:
    if config_override is None:
        return ""
    return str(config_override.get(key, "")).strip()


def _override_or_env(
    config_override: Mapping[str, str] | None,
    key: str,
    environ: Mapping[str, str],
    env_key: str,
) -> str:
    override = _override_value(config_override, key)
    return override if override else environ.get(env_key, "").strip()


def _bounded_int(
    raw_value: str | None,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        value = int(raw_value) if raw_value not in {None, ""} else default
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _bool_value(raw_value: str, *, default: bool) -> bool:
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default
