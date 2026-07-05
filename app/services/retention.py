import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


DEFAULT_RETENTION_DAYS = 0
DEFAULT_RETENTION_BATCH_SIZE = 100


@dataclass(frozen=True)
class RetentionPolicy:
    days: int
    batch_size: int

    @property
    def enabled(self) -> bool:
        return self.days > 0


def _env_int(name: str, default: int, minimum: int) -> int:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return max(minimum, parsed)


def retention_policy_from_env() -> RetentionPolicy:
    return RetentionPolicy(
        days=_env_int("MASP_RETENTION_DAYS", DEFAULT_RETENTION_DAYS, 0),
        batch_size=_env_int("MASP_RETENTION_BATCH_SIZE", DEFAULT_RETENTION_BATCH_SIZE, 1),
    )


def retention_cutoff(policy: RetentionPolicy, now: datetime | None = None) -> datetime | None:
    if not policy.enabled:
        return None

    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)

    return current_time.astimezone(timezone.utc) - timedelta(days=policy.days)


def retention_cutoff_value(policy: RetentionPolicy, now: datetime | None = None) -> str | None:
    cutoff = retention_cutoff(policy, now=now)
    if cutoff is None:
        return None
    return cutoff.isoformat(sep=" ")
