"""Environment-driven configuration for the ICAP gateway."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int_env(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _ip_allowlist(name: str) -> frozenset[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return frozenset()
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class IcapConfig:
    host: str = "0.0.0.0"
    port: int = 1344
    service_name: str = "masp"
    wait_seconds: int = 30
    max_bytes: int | None = None
    fail_closed: bool = True
    block_on_review: bool = False
    block_archives: bool = True
    allowed_ips: frozenset[str] = field(default_factory=frozenset)
    preview_bytes: int = 0
    read_timeout_seconds: int = 60
    body_timeout_seconds: int = 300
    max_connections: int = 100
    admission_timeout_seconds: float = 10.0

    @property
    def uri(self) -> str:
        return f"icap://{self.host}:{self.port}/{self.service_name}"


def load_icap_config() -> IcapConfig:
    upload_cap = _int_env("MASP_UPLOAD_MAX_BYTES", 0)
    icap_cap = _int_env("MASP_ICAP_MAX_BYTES", 0)
    effective_cap = icap_cap or upload_cap
    return IcapConfig(
        host=os.getenv("MASP_ICAP_HOST", "0.0.0.0").strip() or "0.0.0.0",
        port=_int_env("MASP_ICAP_PORT", 1344, minimum=1),
        service_name=os.getenv("MASP_ICAP_SERVICE_NAME", "masp").strip() or "masp",
        wait_seconds=_int_env("MASP_ICAP_WAIT_SECONDS", 30),
        max_bytes=effective_cap or None,
        fail_closed=_bool_env("MASP_ICAP_FAIL_MODE_CLOSED", True),
        block_on_review=_bool_env("MASP_ICAP_BLOCK_ON_REVIEW", False),
        block_archives=_bool_env("MASP_ICAP_BLOCK_ARCHIVES", True),
        allowed_ips=_ip_allowlist("MASP_ICAP_ALLOWED_IPS"),
        preview_bytes=_int_env("MASP_ICAP_PREVIEW_BYTES", 0),
        read_timeout_seconds=_int_env("MASP_ICAP_READ_TIMEOUT_SECONDS", 60),
        body_timeout_seconds=_int_env("MASP_ICAP_BODY_TIMEOUT_SECONDS", 300),
        max_connections=_int_env("MASP_ICAP_MAX_CONNECTIONS", 100, minimum=1),
        admission_timeout_seconds=_int_env("MASP_ICAP_ADMISSION_TIMEOUT_SECONDS", 10),
    )
