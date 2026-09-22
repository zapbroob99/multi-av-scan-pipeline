"""Non-sensitive product and runtime snapshot for the browser About screen.

Readable by analysts and admins. Deployment secrets, hostnames, file paths and
engine configuration never appear here; only capability state does.
"""
from datetime import datetime, timezone
import time

from pydantic import BaseModel

from app import APP_VERSION
from app import database as db
from app.services.browser_db_budget import apply_read_budget
from app.services.engine_registry import configured_engines, enabled_hash_engines
from app.services.ldap_auth import ldap_enabled
from app.services.secret_store import secret_encryption_available
from app.services.worker_runtime import worker_stale_seconds


ENGINE_NAME_LIMIT = 5


class AboutPayload(BaseModel):
    app_version: str
    queue_mode: str
    worker_transport: str
    directory_login_enabled: bool
    secret_encryption_available: bool
    enabled_engine_count: int
    enabled_engine_names: list[str]
    engine_names_truncated: bool
    hash_engine_count: int
    registered_nodes: int
    schedulable_nodes: int
    service_client_count: int | None
    generated_at: str


def snapshot(*, admin: bool) -> AboutPayload:
    engines = configured_engines()
    enabled = [engine for engine in engines if engine.enabled]
    now = int(time.time())
    stale = worker_stale_seconds()
    with db.connect() as connection:
        apply_read_budget(connection)
        # Small configuration tables only. Scan history is never aggregated for
        # this screen, so it stays cheap enough to read without a cache.
        nodes = connection.execute('''SELECT COUNT(*) AS registered_nodes,
            COALESCE(SUM(CASE WHEN last_heartbeat_at > 0 AND last_heartbeat_at >= ?
                AND lifecycle_state = 'active' THEN 1 ELSE 0 END), 0) AS schedulable_nodes
            FROM worker_nodes''', (now - stale,)).fetchone()
        clients = connection.execute('SELECT COUNT(*) AS total FROM service_clients').fetchone() if admin else None
    return AboutPayload(
        app_version=APP_VERSION,
        queue_mode='Durable engine job queue',
        worker_transport='Database or HTTPS control API',
        directory_login_enabled=ldap_enabled(),
        secret_encryption_available=secret_encryption_available(),
        enabled_engine_count=len(enabled),
        enabled_engine_names=[engine.display_name[:128] for engine in enabled[:ENGINE_NAME_LIMIT]],
        engine_names_truncated=len(enabled) > ENGINE_NAME_LIMIT,
        hash_engine_count=len(enabled_hash_engines()),
        registered_nodes=int(nodes['registered_nodes']),
        schedulable_nodes=int(nodes['schedulable_nodes']),
        service_client_count=None if clients is None else int(clients['total']),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
