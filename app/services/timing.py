from __future__ import annotations

from datetime import datetime, timezone

from app.models import ScanRecord


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    if " " in normalized and "T" not in normalized:
        normalized = normalized.replace(" ", "T", 1)
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def duration_ms(started_at: datetime | None, ended_at: datetime | None) -> int | None:
    if started_at is None or ended_at is None:
        return None
    return max(0, int((ended_at - started_at).total_seconds() * 1000))


def terminal_scan_timestamp(scan: ScanRecord) -> datetime | None:
    return parse_timestamp(scan.completed_at or scan.failed_at)


def build_scan_timing_payload(
    scan: ScanRecord,
    *,
    now: datetime | None = None,
) -> dict[str, int | None]:
    current_time = datetime.now(timezone.utc) if now is None else now
    created_at = parse_timestamp(scan.created_at)
    started_at = parse_timestamp(scan.started_at)
    terminal_at = terminal_scan_timestamp(scan)

    queue_wait_ms = duration_ms(created_at, started_at)
    processing_duration_ms = duration_ms(started_at, terminal_at)
    total_duration_ms = duration_ms(created_at, terminal_at)

    return {
        "queue_wait_ms": queue_wait_ms,
        "processing_duration_ms": processing_duration_ms,
        "total_duration_ms": total_duration_ms,
        "age_ms": duration_ms(created_at, current_time),
        "processing_age_ms": duration_ms(started_at, current_time),
    }
