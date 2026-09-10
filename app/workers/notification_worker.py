from __future__ import annotations

import os
import socket
import time

from app.database import init_db, recover_expired_notification_deliveries
from app.services.notification_delivery import deliver_next, webhook_url


WORKER_ID = os.getenv(
    "MASP_NOTIFICATION_WORKER_ID",
    f"notification-{socket.gethostname()}-{os.getpid()}",
)
POLL_SECONDS = float(os.getenv("MASP_NOTIFICATION_POLL_SECONDS", "2"))


def run_forever() -> None:
    init_db()
    if not webhook_url():
        raise SystemExit("MASP_SIEM_WEBHOOK_URL is not configured.")
    recover_expired_notification_deliveries()
    print("MASP notification worker started", flush=True)
    last_recovery = time.monotonic()
    while True:
        if not deliver_next(WORKER_ID):
            time.sleep(POLL_SECONDS)
        if time.monotonic() - last_recovery >= 60:
            recover_expired_notification_deliveries()
            last_recovery = time.monotonic()


if __name__ == "__main__":
    run_forever()
