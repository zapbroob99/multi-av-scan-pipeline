from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlparse
from urllib.request import Request

from app.services.http_transport import open_without_redirects as urlopen

from app.database import (
    claim_next_notification_outbox,
    mark_notification_delivered,
    retry_notification_outbox,
)


def webhook_url() -> str:
    return os.getenv("MASP_SIEM_WEBHOOK_URL", "").strip()


def validate_webhook_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return
    allow_http = os.getenv("MASP_SIEM_WEBHOOK_ALLOW_HTTP", "").strip().lower()
    if parsed.scheme == "http" and allow_http in {"1", "true", "yes"}:
        return
    raise RuntimeError("MASP_SIEM_WEBHOOK_URL must use HTTPS.")


def deliver_next(worker_id: str) -> bool:
    url = webhook_url()
    if not url:
        return False
    validate_webhook_url(url)
    lease_seconds = max(30, int(os.getenv("MASP_NOTIFICATION_LEASE_SECONDS", "120")))
    event = claim_next_notification_outbox(worker_id, lease_seconds=lease_seconds)
    if event is None:
        return False
    try:
        payload = event.payload_json.encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": event.idempotency_key,
            "User-Agent": "MASP-notification-worker/1",
        }
        secret = os.getenv("MASP_SIEM_WEBHOOK_SECRET", "").encode("utf-8")
        if secret:
            headers["X-MASP-Signature-SHA256"] = hmac.new(
                secret, payload, hashlib.sha256
            ).hexdigest()
        request = Request(url, data=payload, headers=headers, method="POST")
        timeout = max(1, int(os.getenv("MASP_SIEM_WEBHOOK_TIMEOUT_SECONDS", "10")))
        with urlopen(request, timeout=timeout) as response:
            if not 200 <= int(response.status) < 300:
                raise RuntimeError(f"SIEM webhook returned HTTP {response.status}.")
        mark_notification_delivered(event.id, worker_id, event.attempt_count)
    except Exception as exc:
        max_backoff = max(60, int(os.getenv("MASP_NOTIFICATION_MAX_BACKOFF_SECONDS", "3600")))
        backoff = min(max_backoff, 15 * (2 ** min(event.attempt_count - 1, 8)))
        retry_notification_outbox(
            event.id,
            worker_id,
            event.attempt_count,
            str(exc),
            retry_at=int(time.time()) + backoff,
        )
    return True
