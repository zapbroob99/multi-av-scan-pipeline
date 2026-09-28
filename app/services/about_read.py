"""Non-sensitive product and runtime snapshot for the browser About screen.

Readable by analysts and admins. Deployment secrets, hostnames, file paths and
engine configuration never appear here; only capability state does.
"""
from datetime import datetime, timezone
import os
import platform
import time

from pydantic import BaseModel

from app import APP_VERSION
from app import database as db
from app.services.browser_db_budget import apply_read_budget
from app.services.engine_registry import ADAPTERS, configured_engines, enabled_hash_engines
from app.services.ldap_auth import ldap_enabled
from app.services.secret_store import secret_encryption_available
from app.services.worker_runtime import worker_stale_seconds


ENGINE_NAME_LIMIT = 5
ENGINE_LIST_LIMIT = 20
AGENT_VERSION_LIMIT = 10


class AboutEngine(BaseModel):
    """Versions an enabled engine last reported from a worker health check."""
    name: str
    kind: str
    product_version: str | None
    engine_version: str | None
    signature_version: str | None
    last_checked_at: str | None


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
    release: str | None
    python_version: str
    database: str
    engines: list[AboutEngine]
    engines_truncated: bool
    worker_agent_versions: list[str]
    generated_at: str


def _release() -> str | None:
    # The deployed image reference, without any registry host: hosts stay off this screen.
    value = os.getenv('MASP_RELEASE', '').strip()
    return value.rsplit('/', 1)[-1][:128] or None


def _iso(epoch: object) -> str | None:
    return datetime.fromtimestamp(int(epoch), timezone.utc).isoformat() if epoch else None


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
        listed = enabled[:ENGINE_LIST_LIMIT]
        health: dict[int, object] = {}
        if listed:
            marks = ', '.join('?' for _ in listed)
            # Newest successful check first; one row per node and engine, so this stays small.
            for row in connection.execute(f'''SELECT engine_instance_id, product_version, engine_version,
                    signature_version, last_checked_at FROM engine_node_health
                WHERE engine_instance_id IN ({marks})
                ORDER BY COALESCE(last_success_at, 0) DESC, COALESCE(last_checked_at, 0) DESC LIMIT 500''',
                    tuple(engine.id for engine in listed)).fetchall():
                health.setdefault(int(row['engine_instance_id']), row)
        agents = [row['agent_version'][:64] for row in connection.execute(
            'SELECT DISTINCT agent_version FROM worker_nodes ORDER BY agent_version LIMIT ?',
            (AGENT_VERSION_LIMIT,)).fetchall()]
        # PostgreSQL rows are dicts, so the version is read by alias on both backends.
        if db.using_postgres():
            version = connection.execute("SELECT current_setting('server_version') AS v").fetchone()['v']
            database = 'PostgreSQL ' + str(version).split(' ', 1)[0]
        else:
            database = 'SQLite ' + str(connection.execute('SELECT sqlite_version() AS v').fetchone()['v'])
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
        release=_release(),
        python_version=platform.python_version(),
        database=database,
        engines=[AboutEngine(
            name=engine.display_name[:128],
            kind=ADAPTERS[engine.adapter_key].label if engine.adapter_key in ADAPTERS else 'Unregistered adapter',
            product_version=(health[engine.id]['product_version'] or None) if engine.id in health else None,
            engine_version=(health[engine.id]['engine_version'] or None) if engine.id in health else None,
            signature_version=(health[engine.id]['signature_version'] or None) if engine.id in health else None,
            last_checked_at=_iso(health[engine.id]['last_checked_at']) if engine.id in health else None,
        ) for engine in listed],
        engines_truncated=len(enabled) > ENGINE_LIST_LIMIT,
        worker_agent_versions=agents,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
