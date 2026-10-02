"""ICAP gateway activity and SIEM notification delivery for administrators.

Both are outbound paths an operator cannot otherwise see from the console: the
ICAP gateway only logs to its container, and the notification outbox retries
silently with backoff. Reads are bounded; the one write here moves failed
notifications forward in time and never marks anything delivered.
"""
from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel

from app import database as db
from app.icap.activity import SETTING_PREFIX as ICAP_SETTING_PREFIX
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms
from app.services.deferred_storage import redact_paths
from app.services.health_read import ICAP_FORGOTTEN_SECONDS, ICAP_STALE_SECONDS, icap_gateways, with_icap_bindings


FAILURE_LIMIT = 20
TEXT_LIMIT = 500


class IcapEvent(BaseModel):
    at: int
    kind: str
    detail: str
    peer: str | None = None
    scan_id: int | None = None


class IcapGateway(BaseModel):
    key: str
    client_key: str
    service_name: str
    port: int
    fail_closed: bool
    block_on_review: bool
    allowlist_entries: int
    started_at: int
    at: int
    age_seconds: int
    stale: bool
    counters: dict[str, int]
    last_request_at: int | None
    events: list[IcapEvent]
    # How MASP_ICAP_SERVICE_CLIENT_KEY resolves: an integration's own client,
    # the compatibility client, or nothing, in which case every request fails.
    binding: Literal['client', 'legacy_default', 'unresolved']
    client_id: int | None = None
    client_name: str | None = None
    binding_detail: str | None = None


class NotificationFailure(BaseModel):
    id: int
    scan_job_id: int
    client_name: str | None
    event_type: str
    attempt_count: int
    last_error: str
    next_attempt_at: int
    created_at: str


class NotificationSummary(BaseModel):
    pending: int
    delivering: int
    delivered: int
    retrying: int
    oldest_pending_at: str | None
    last_delivered_at: str | None
    failures: list[NotificationFailure]


class DeliveryOverview(BaseModel):
    gateways: list[IcapGateway]
    notifications: NotificationSummary
    generated_at: str


class RetryNow(BaseModel):
    rescheduled: int


def _text(value: object) -> str | None:
    return None if value is None else str(value)


def overview(now: float | None = None) -> DeliveryOverview:
    current = time.time() if now is None else now
    records = [record for record in icap_gateways(db.list_settings_by_prefix(ICAP_SETTING_PREFIX), current)
               if current - int(record['at']) < ICAP_FORGOTTEN_SECONDS]
    gateways = []
    with db.connect() as connection:
        apply_read_budget(connection)
        for record in with_icap_bindings(connection, records):
            age = max(0, int(current - int(record['at'])))
            try:
                gateways.append(IcapGateway(**{**record, 'age_seconds': age, 'stale': age >= ICAP_STALE_SECONDS,
                                               'events': [e for e in record.get('events') or [] if isinstance(e, dict)]}))
            except (TypeError, ValueError):
                continue  # a record from another version must not break the page
        counts = {str(row['status']): int(row['n']) for row in connection.execute(
            'SELECT status, COUNT(*) AS n FROM notification_outbox GROUP BY status').fetchall()}
        pending = connection.execute('''SELECT MIN(created_at) AS oldest,
            SUM(CASE WHEN attempt_count > 0 THEN 1 ELSE 0 END) AS retrying
            FROM notification_outbox WHERE status = 'pending' ''').fetchone()
        delivered = connection.execute(
            "SELECT MAX(delivered_at) AS last FROM notification_outbox WHERE status = 'delivered'").fetchone()
        failures = connection.execute(f'''SELECT o.id, o.scan_job_id, SUBSTR(c.display_name, 1, 256) AS client_name,
            o.event_type, o.attempt_count, SUBSTR(COALESCE(o.last_error, ''), 1, {TEXT_LIMIT}) AS last_error,
            o.available_at AS next_attempt_at, o.created_at
            FROM notification_outbox o LEFT JOIN service_clients c ON c.id = o.service_client_id
            WHERE o.status = 'pending' AND o.attempt_count > 0 ORDER BY o.id LIMIT ?''', (FAILURE_LIMIT,)).fetchall()
    return DeliveryOverview(
        gateways=gateways,
        notifications=NotificationSummary(
            pending=counts.get('pending', 0), delivering=counts.get('delivering', 0),
            delivered=counts.get('delivered', 0), retrying=int((pending['retrying'] if pending else 0) or 0),
            oldest_pending_at=_text(pending['oldest'] if pending else None),
            last_delivered_at=_text(delivered['last'] if delivered else None),
            failures=[NotificationFailure(**{**dict(row), 'last_error': redact_paths(row['last_error']),
                                             'created_at': str(row['created_at'])}) for row in failures],
        ),
        generated_at=datetime.fromtimestamp(current, timezone.utc).isoformat(),
    )


def retry_notifications_now(now: int | None = None) -> RetryNow:
    """Bring forward notifications waiting in backoff after a failure.

    Only rows the delivery worker already failed are touched, and only their
    next attempt time: attempt counts, payloads and delivered rows stay as they
    are, so the worker's fencing is unaffected.
    """
    current = int(time.time()) if now is None else now
    with db.connect() as connection:
        apply_read_budget(connection)
        if db.using_postgres():
            connection.execute("SELECT set_config('lock_timeout', ?, true)", (f'{write_lock_timeout_ms()}ms',))
        cursor = connection.execute('''UPDATE notification_outbox SET available_at = ?, updated_at = CURRENT_TIMESTAMP
            WHERE status = 'pending' AND attempt_count > 0 AND available_at > ?''', (current, current))
        changed = int(cursor.rowcount or 0)
    if not changed:
        raise HTTPException(409, 'No failed notification is waiting for a retry.')
    return RetryNow(rescheduled=changed)
