from contextlib import contextmanager
from pathlib import Path
import atexit
import json
import os
import sqlite3
import threading
import time
from typing import Any, Callable, Iterable

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - exercised only when Postgres is configured.
    psycopg = None  # type: ignore[assignment]
    dict_row = None  # type: ignore[assignment]

try:
    from psycopg_pool import ConnectionPool
    from psycopg_pool import PoolTimeout
except ImportError:  # pragma: no cover - pool is optional; falls back to direct connect.
    ConnectionPool = None  # type: ignore[assignment]
    PoolTimeout = None  # type: ignore[assignment]

from app.models import (
    ACTIVE_SCAN_STATUSES,
    AuditEventRecord,
    EngineNodeHealthRecord,
    EngineInstanceRecord,
    EngineResultInput,
    EngineResultRecord,
    ScanBatchRecord,
    ScanEngineJobRecord,
    ScanRecord,
    ScanWorkerEventRecord,
    StoredSample,
    TERMINAL_SCAN_STATUSES,
    UserRecord,
    WorkerAgentCredentialRecord,
    WorkerNodeRecord,
    WorkerPoolRecord,
)


ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DB_PATH = DATA_DIR / "app.db"
DATABASE_URL = os.getenv("MASP_DATABASE_URL", "").strip()
SQLITE_TIMEOUT_SECONDS = float(os.getenv("MASP_SQLITE_TIMEOUT_SECONDS", "30"))
SQLITE_CONNECT_ATTEMPTS = int(os.getenv("MASP_SQLITE_CONNECT_ATTEMPTS", "5"))
SQLITE_RETRY_DELAY_SECONDS = float(os.getenv("MASP_SQLITE_RETRY_DELAY_SECONDS", "0.25"))
DATABASE_CONNECT_ATTEMPTS = int(os.getenv("MASP_DATABASE_CONNECT_ATTEMPTS", "20"))
DATABASE_RETRY_DELAY_SECONDS = float(os.getenv("MASP_DATABASE_RETRY_DELAY_SECONDS", "1"))


def _env_flag(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() not in {"0", "false", "no", "off"}


DB_POOL_ENABLED = _env_flag("MASP_DB_POOL_ENABLED", "1")
DB_POOL_MIN = int(os.getenv("MASP_DB_POOL_MIN", "0"))
DB_POOL_MAX = int(os.getenv("MASP_DB_POOL_MAX", "4"))
DB_POOL_TIMEOUT_SECONDS = float(os.getenv("MASP_DB_POOL_TIMEOUT_SECONDS", "30"))


if psycopg is None:
    DatabaseOperationalError = (sqlite3.Error,)
    IntegrityViolation: tuple[type[BaseException], ...] = (sqlite3.IntegrityError,)
else:
    DatabaseOperationalError = (sqlite3.Error, psycopg.Error)
    IntegrityViolation = (sqlite3.IntegrityError, psycopg.errors.UniqueViolation)

# psycopg_pool.PoolTimeout subclasses psycopg.OperationalError, so the tuple above
# already catches it; include it defensively in case that ever changes upstream.
if PoolTimeout is not None and psycopg is not None and not issubclass(PoolTimeout, psycopg.Error):
    DatabaseOperationalError = DatabaseOperationalError + (PoolTimeout,)


# Process-local connection pool. Created lazily on first Postgres connect (never at
# import time) and rebuilt if the PID changes, so a forked child never shares a
# parent's pool. Guarded by a lock because worker/app processes are multi-threaded.
_pool_lock = threading.Lock()
_pool: Any = None
_pool_pid: int | None = None


class PostgresConnection:
    def __init__(self, connection: Any, pool_cm: Any = None):
        self.connection = connection
        # When set, this is the pool's ``connection()`` context manager already
        # entered in ``connect_postgres``; exiting it commits/rolls back and
        # returns the connection to the pool instead of closing it.
        self._pool_cm = pool_cm

    def __enter__(self) -> "PostgresConnection":
        if self._pool_cm is None:
            self.connection.__enter__()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> object:
        if self._pool_cm is not None:
            return self._pool_cm.__exit__(exc_type, exc, traceback)
        return self.connection.__exit__(exc_type, exc, traceback)

    def execute(self, query: str, params: Iterable[object] | None = None) -> Any:
        return self.connection.execute(postgres_query(query), tuple(params or ()))

    def executescript(self, script: str) -> None:
        for statement in split_sql_script(script):
            self.execute(statement)


def using_postgres() -> bool:
    return bool(DATABASE_URL)


def pool_available() -> bool:
    return DB_POOL_ENABLED and ConnectionPool is not None and using_postgres()


def get_pool() -> Any:
    """Return this process's connection pool, creating it lazily and per-PID."""
    global _pool, _pool_pid
    pid = os.getpid()
    if _pool is not None and _pool_pid == pid:
        return _pool
    with _pool_lock:
        if _pool is not None and _pool_pid == pid:
            return _pool
        # A pool object inherited across fork belongs to the parent; drop the
        # reference without closing it (the parent still owns those sockets).
        _pool = ConnectionPool(
            DATABASE_URL,
            min_size=DB_POOL_MIN,
            max_size=DB_POOL_MAX,
            timeout=DB_POOL_TIMEOUT_SECONDS,
            kwargs={"row_factory": dict_row},
            name=f"masp-{pid}",
            open=True,
        )
        _pool_pid = pid
        print(
            f"MASP DB pool enabled (min={DB_POOL_MIN}, max={DB_POOL_MAX})",
            flush=True,
        )
        return _pool


def close_pool() -> None:
    global _pool, _pool_pid
    with _pool_lock:
        if _pool is not None and _pool_pid == os.getpid():
            try:
                _pool.close()
            except Exception:  # pragma: no cover - best-effort shutdown.
                pass
        _pool = None
        _pool_pid = None


atexit.register(close_pool)


def connect() -> Any:
    if using_postgres():
        return connect_postgres()
    return connect_sqlite()


def connect_postgres() -> PostgresConnection:
    if psycopg is None or dict_row is None:
        raise RuntimeError(
            "MASP_DATABASE_URL is set, but psycopg is not installed. "
            "Install requirements.txt before using PostgreSQL."
        )

    if pool_available():
        return connect_postgres_pooled()

    last_error: Exception | None = None
    for attempt in range(max(1, DATABASE_CONNECT_ATTEMPTS)):
        try:
            connection = psycopg.connect(DATABASE_URL, row_factory=dict_row)
            return PostgresConnection(connection)
        except psycopg.OperationalError as exc:
            last_error = exc
            if attempt >= DATABASE_CONNECT_ATTEMPTS - 1:
                raise
            time.sleep(DATABASE_RETRY_DELAY_SECONDS)

    if last_error is not None:
        raise last_error
    raise RuntimeError("PostgreSQL connection could not be opened.")


def connect_postgres_pooled() -> PostgresConnection:
    # Acquisition is wrapped in the same retry loop as the direct path so a
    # not-yet-ready Postgres (pool empty, backend still starting) is tolerated.
    pool_errors: tuple[type[BaseException], ...] = (psycopg.OperationalError,)
    if PoolTimeout is not None:
        pool_errors = pool_errors + (PoolTimeout,)

    last_error: Exception | None = None
    for attempt in range(max(1, DATABASE_CONNECT_ATTEMPTS)):
        pool = get_pool()
        pool_cm = pool.connection()
        try:
            connection = pool_cm.__enter__()
            return PostgresConnection(connection, pool_cm=pool_cm)
        except pool_errors as exc:
            last_error = exc
            if attempt >= DATABASE_CONNECT_ATTEMPTS - 1:
                raise
            time.sleep(DATABASE_RETRY_DELAY_SECONDS)

    if last_error is not None:
        raise last_error
    raise RuntimeError("PostgreSQL connection could not be opened.")


def connect_sqlite() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    last_error: sqlite3.OperationalError | None = None
    for attempt in range(max(1, SQLITE_CONNECT_ATTEMPTS)):
        try:
            connection = sqlite3.connect(str(DB_PATH), timeout=SQLITE_TIMEOUT_SECONDS)
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {int(SQLITE_TIMEOUT_SECONDS * 1000)}")
            connection.execute("PRAGMA foreign_keys = ON")
            return connection
        except sqlite3.OperationalError as exc:
            last_error = exc
            if not is_transient_sqlite_error(exc) or attempt >= SQLITE_CONNECT_ATTEMPTS - 1:
                raise
            time.sleep(SQLITE_RETRY_DELAY_SECONDS * (attempt + 1))

    if last_error is not None:
        raise last_error
    raise RuntimeError("SQLite connection could not be opened.")


def postgres_query(query: str) -> str:
    return query.replace("?", "%s").replace("BEGIN IMMEDIATE", "BEGIN")


def split_sql_script(script: str) -> list[str]:
    return [
        statement.strip()
        for statement in script.split(";")
        if statement.strip()
    ]


def is_transient_sqlite_error(exc: sqlite3.OperationalError) -> bool:
    message = str(exc).lower()
    return any(
        marker in message
        for marker in (
            "database is locked",
            "database is busy",
            "disk i/o error",
            "unable to open database file",
        )
    )


def require_lastrowid(cursor: Any) -> int:
    if using_postgres():
        row = cursor.fetchone()
        if row is None:
            raise RuntimeError("Database insert did not return a row id.")
        return int(row_value(row, "id"))
    if cursor.lastrowid is None:
        raise RuntimeError("Database insert did not return a row id.")
    return int(cursor.lastrowid)


def fetch_count(connection: Any, query: str) -> int:
    row = connection.execute(query).fetchone()
    if row is None:
        return 0
    if isinstance(row, dict):
        return int(next(iter(row.values())))
    return int(row[0])


def row_value(row: Any, key: str) -> Any:
    return row[key]


def returning_id_clause() -> str:
    return "RETURNING id" if using_postgres() else ""


def db_bool(value: bool) -> bool | int:
    return value if using_postgres() else 1 if value else 0


def is_missing_settings_table(exc: sqlite3.OperationalError) -> bool:
    return "no such table: app_settings" in str(exc)


def is_missing_engine_instances_table(exc: sqlite3.OperationalError) -> bool:
    return "no such table: engine_instances" in str(exc)


def is_missing_users_table(exc: sqlite3.OperationalError) -> bool:
    return "no such table: users" in str(exc) or "no such table: auth_sessions" in str(exc)


def init_db() -> None:
    if using_postgres():
        init_postgres_db()
        return
    init_sqlite_db()


def init_sqlite_db() -> None:
    with connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                content_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                md5 TEXT NOT NULL,
                sha1 TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scan_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL DEFAULT 'manual',
                original_filename TEXT NOT NULL,
                archive_mode TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                total_items INTEGER NOT NULL DEFAULT 0,
                queued_items INTEGER NOT NULL DEFAULT 0,
                running_items INTEGER NOT NULL DEFAULT 0,
                completed_items INTEGER NOT NULL DEFAULT 0,
                failed_items INTEGER NOT NULL DEFAULT 0,
                malicious_items INTEGER NOT NULL DEFAULT 0,
                skipped_items INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id INTEGER NOT NULL,
                batch_id INTEGER,
                parent_scan_id INTEGER,
                case_name TEXT NOT NULL,
                priority TEXT NOT NULL,
                note TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual',
                relative_path TEXT,
                scan_role TEXT NOT NULL DEFAULT 'standalone',
                status TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                started_at TEXT,
                completed_at TEXT,
                failed_at TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                FOREIGN KEY (sample_id) REFERENCES samples (id) ON DELETE CASCADE,
                FOREIGN KEY (batch_id) REFERENCES scan_batches (id) ON DELETE SET NULL,
                FOREIGN KEY (parent_scan_id) REFERENCES scan_jobs (id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS engine_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_job_id INTEGER NOT NULL,
                engine_name TEXT NOT NULL,
                engine_version TEXT,
                signature_version TEXT,
                status TEXT NOT NULL,
                detected INTEGER NOT NULL,
                signature TEXT,
                severity TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                raw_output TEXT NOT NULL,
                error_message TEXT,
                duration_ms INTEGER NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                findings_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_job_id) REFERENCES scan_jobs (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_worker_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_job_id INTEGER NOT NULL,
                event_name TEXT NOT NULL,
                worker_id TEXT NOT NULL,
                worker_engine_keys TEXT NOT NULL,
                engine_name TEXT,
                duration_ms INTEGER,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_job_id) REFERENCES scan_jobs (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_engine_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_job_id INTEGER NOT NULL,
                engine_instance_id INTEGER,
                engine_key TEXT NOT NULL,
                engine_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                worker_id TEXT,
                claimed_at TEXT,
                started_at TEXT,
                finished_at TEXT,
                lease_expires_at INTEGER,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_job_id) REFERENCES scan_jobs (id) ON DELETE CASCADE,
                FOREIGN KEY (engine_instance_id) REFERENCES engine_instances (id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS engine_instances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                adapter_key TEXT NOT NULL,
                display_name TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                config_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS worker_nodes (
                node_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                hostname TEXT NOT NULL,
                platform TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                labels_json TEXT NOT NULL DEFAULT '{}',
                capacity INTEGER NOT NULL DEFAULT 1 CHECK (capacity > 0),
                advertised_engine_keys_json TEXT NOT NULL DEFAULT '[]',
                lifecycle_state TEXT NOT NULL DEFAULT 'active'
                    CHECK (lifecycle_state IN ('active', 'draining', 'disabled')),
                runtime_state TEXT NOT NULL DEFAULT 'starting',
                active_scan_id INTEGER,
                process_id INTEGER,
                last_heartbeat_at INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_worker_nodes_lifecycle_heartbeat
            ON worker_nodes (lifecycle_state, last_heartbeat_at);

            CREATE TABLE IF NOT EXISTS worker_agent_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_used_at INTEGER,
                expires_at INTEGER,
                revoked_at INTEGER,
                FOREIGN KEY (node_id) REFERENCES worker_nodes (node_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_worker_agent_credentials_node_active
            ON worker_agent_credentials (node_id, revoked_at, expires_at);

            CREATE TABLE IF NOT EXISTS worker_pools (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                selector_json TEXT NOT NULL DEFAULT '{}',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS engine_instance_worker_pools (
                engine_instance_id INTEGER PRIMARY KEY,
                worker_pool_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (engine_instance_id) REFERENCES engine_instances (id) ON DELETE CASCADE,
                FOREIGN KEY (worker_pool_id) REFERENCES worker_pools (id) ON DELETE RESTRICT
            );

            CREATE INDEX IF NOT EXISTS idx_engine_instance_worker_pools_pool
            ON engine_instance_worker_pools (worker_pool_id, engine_instance_id);

            CREATE TABLE IF NOT EXISTS engine_node_health (
                node_id TEXT NOT NULL,
                engine_instance_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'unknown',
                ok INTEGER NOT NULL DEFAULT 0,
                health_status TEXT NOT NULL DEFAULT 'unknown',
                detail TEXT NOT NULL DEFAULT '',
                product_version TEXT,
                engine_version TEXT,
                signature_version TEXT,
                service_state TEXT,
                storage_readable INTEGER,
                storage_writable INTEGER,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                last_checked_at INTEGER,
                last_success_at INTEGER,
                last_scan_success_at INTEGER,
                details_json TEXT NOT NULL DEFAULT '{}',
                check_worker_id TEXT,
                check_generation INTEGER NOT NULL DEFAULT 0,
                check_lease_expires_at INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (node_id, engine_instance_id),
                FOREIGN KEY (node_id) REFERENCES worker_nodes (node_id) ON DELETE CASCADE,
                FOREIGN KEY (engine_instance_id) REFERENCES engine_instances (id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_engine_node_health_due
            ON engine_node_health (node_id, check_lease_expires_at, last_checked_at);

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
                auth_source TEXT NOT NULL DEFAULT 'local',
                external_id TEXT,
                display_name TEXT,
                last_login_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                actor_name TEXT,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
                source_ip TEXT,
                request_id TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_audit_events_created
            ON audit_events (created_at DESC, id DESC);

            CREATE INDEX IF NOT EXISTS idx_audit_events_action
            ON audit_events (action, outcome, id DESC);
            """
        )
        ensure_column(connection, "scan_jobs", "started_at", "TEXT")
        ensure_column(connection, "scan_jobs", "failed_at", "TEXT")
        ensure_column(connection, "scan_jobs", "attempt_count", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "scan_jobs", "last_error", "TEXT")
        ensure_column(connection, "scan_jobs", "source", "TEXT NOT NULL DEFAULT 'manual'")
        ensure_column(connection, "scan_jobs", "batch_id", "INTEGER")
        ensure_column(connection, "scan_jobs", "parent_scan_id", "INTEGER")
        ensure_column(connection, "scan_jobs", "relative_path", "TEXT")
        ensure_column(connection, "scan_jobs", "scan_role", "TEXT NOT NULL DEFAULT 'standalone'")
        ensure_column(connection, "scan_jobs", "finalize_worker_id", "TEXT")
        ensure_column(connection, "scan_jobs", "finalize_generation", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "scan_jobs", "finalize_lease_expires_at", "INTEGER")
        ensure_column(connection, "scan_jobs", "archive_member_ordinal", "INTEGER")
        ensure_column(connection, "engine_results", "details_json", "TEXT NOT NULL DEFAULT '{}'")
        ensure_column(connection, "engine_results", "findings_json", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column(connection, "scan_engine_jobs", "worker_node_id", "TEXT")
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_engine_jobs_worker_node_status
            ON scan_engine_jobs (worker_node_id, status, id)
            """
        )
        ensure_column(connection, "users", "auth_source", "TEXT NOT NULL DEFAULT 'local'")
        ensure_column(connection, "users", "external_id", "TEXT")
        ensure_column(connection, "users", "display_name", "TEXT")
        ensure_column(connection, "users", "last_login_at", "TEXT")
        migrate_engine_instances_for_multiple_instances(connection)
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id
            ON users (external_id) WHERE external_id IS NOT NULL
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_engine_results_scan_engine
            ON engine_results (scan_job_id, engine_name)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_source_created
            ON scan_jobs (source, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_source_status_created
            ON scan_jobs (source, status, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_batch_created
            ON scan_jobs (batch_id, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_parent
            ON scan_jobs (parent_scan_id, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_role_created
            ON scan_jobs (scan_role, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_batches_source_created
            ON scan_batches (source, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_worker_events_scan_created
            ON scan_worker_events (scan_job_id, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_engine_jobs_scan_instance
            ON scan_engine_jobs (scan_job_id, engine_instance_id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_engine_jobs_claim
            ON scan_engine_jobs (status, engine_key, lease_expires_at, id)
            """
        )
        # Partial unique index makes archive-child registration idempotent by
        # ordinal (member names can repeat within an archive). Legacy children
        # predate the column and carry NULL, which the WHERE clause excludes, so
        # this is safe to create on a DB that already has duplicate child paths.
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_jobs_archive_member
            ON scan_jobs (parent_scan_id, archive_member_ordinal)
            WHERE archive_member_ordinal IS NOT NULL
            """
        )


# Application-wide constant so every process contends for the same lock.
SCHEMA_INIT_ADVISORY_LOCK_KEY = 8147326905413


@contextmanager
def postgres_schema_init_lock(connection: Any):
    """Serialize concurrent schema bootstrap across processes.

    ``CREATE TABLE IF NOT EXISTS`` is NOT concurrency-safe on PostgreSQL: two
    sessions (e.g. app and worker starting together on a fresh database) can
    both pass the existence check and then collide, raising a duplicate
    ``pg_type``/relation error. A transaction-level advisory lock held on THIS
    connection serializes initialization. PostgreSQL releases it atomically
    with the schema transaction on commit or rollback, so a failed bootstrap
    cannot leak a session lock into the connection pool. SQLite never enters
    here (see ``init_db``), so its behavior is unchanged.
    """
    connection.execute("SELECT pg_advisory_xact_lock(?)", (SCHEMA_INIT_ADVISORY_LOCK_KEY,))
    yield


def init_postgres_db() -> None:
    with connect() as connection, postgres_schema_init_lock(connection):
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                content_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                md5 TEXT NOT NULL,
                sha1 TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scan_batches (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                source TEXT NOT NULL DEFAULT 'manual',
                original_filename TEXT NOT NULL,
                archive_mode TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                total_items INTEGER NOT NULL DEFAULT 0,
                queued_items INTEGER NOT NULL DEFAULT 0,
                running_items INTEGER NOT NULL DEFAULT 0,
                completed_items INTEGER NOT NULL DEFAULT 0,
                failed_items INTEGER NOT NULL DEFAULT 0,
                malicious_items INTEGER NOT NULL DEFAULT 0,
                skipped_items INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMPTZ,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_jobs (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                sample_id INTEGER NOT NULL,
                batch_id INTEGER,
                parent_scan_id INTEGER,
                case_name TEXT NOT NULL,
                priority TEXT NOT NULL,
                note TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual',
                relative_path TEXT,
                scan_role TEXT NOT NULL DEFAULT 'standalone',
                status TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMPTZ,
                completed_at TIMESTAMPTZ,
                failed_at TIMESTAMPTZ,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                FOREIGN KEY (sample_id) REFERENCES samples (id) ON DELETE CASCADE,
                FOREIGN KEY (batch_id) REFERENCES scan_batches (id) ON DELETE SET NULL,
                FOREIGN KEY (parent_scan_id) REFERENCES scan_jobs (id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS engine_results (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                scan_job_id INTEGER NOT NULL,
                engine_name TEXT NOT NULL,
                engine_version TEXT,
                signature_version TEXT,
                status TEXT NOT NULL,
                detected BOOLEAN NOT NULL,
                signature TEXT,
                severity TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                raw_output TEXT NOT NULL,
                error_message TEXT,
                duration_ms INTEGER NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                findings_json TEXT NOT NULL DEFAULT '[]',
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_job_id) REFERENCES scan_jobs (id) ON DELETE CASCADE
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_engine_results_scan_engine
            ON engine_results (scan_job_id, engine_name);

            CREATE TABLE IF NOT EXISTS scan_worker_events (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                scan_job_id INTEGER NOT NULL,
                event_name TEXT NOT NULL,
                worker_id TEXT NOT NULL,
                worker_engine_keys TEXT NOT NULL,
                engine_name TEXT,
                duration_ms INTEGER,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_job_id) REFERENCES scan_jobs (id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_scan_worker_events_scan_created
            ON scan_worker_events (scan_job_id, created_at, id);

            -- engine_instances must exist before scan_engine_jobs: PostgreSQL
            -- validates foreign keys at CREATE TABLE time (SQLite does not),
            -- so a fresh database fails to bootstrap with the reverse order.
            CREATE TABLE IF NOT EXISTS engine_instances (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                adapter_key TEXT NOT NULL,
                display_name TEXT NOT NULL UNIQUE,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                config_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS worker_nodes (
                node_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                hostname TEXT NOT NULL,
                platform TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                labels_json TEXT NOT NULL DEFAULT '{}',
                capacity INTEGER NOT NULL DEFAULT 1 CHECK (capacity > 0),
                advertised_engine_keys_json TEXT NOT NULL DEFAULT '[]',
                lifecycle_state TEXT NOT NULL DEFAULT 'active'
                    CHECK (lifecycle_state IN ('active', 'draining', 'disabled')),
                runtime_state TEXT NOT NULL DEFAULT 'starting',
                active_scan_id INTEGER,
                process_id INTEGER,
                last_heartbeat_at INTEGER NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_worker_nodes_lifecycle_heartbeat
            ON worker_nodes (lifecycle_state, last_heartbeat_at);

            CREATE TABLE IF NOT EXISTS worker_agent_credentials (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                node_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_used_at INTEGER,
                expires_at INTEGER,
                revoked_at INTEGER,
                FOREIGN KEY (node_id) REFERENCES worker_nodes (node_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_worker_agent_credentials_node_active
            ON worker_agent_credentials (node_id, revoked_at, expires_at);

            CREATE TABLE IF NOT EXISTS worker_pools (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                selector_json TEXT NOT NULL DEFAULT '{}',
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS engine_instance_worker_pools (
                engine_instance_id INTEGER PRIMARY KEY,
                worker_pool_id INTEGER NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (engine_instance_id) REFERENCES engine_instances (id) ON DELETE CASCADE,
                FOREIGN KEY (worker_pool_id) REFERENCES worker_pools (id) ON DELETE RESTRICT
            );

            CREATE INDEX IF NOT EXISTS idx_engine_instance_worker_pools_pool
            ON engine_instance_worker_pools (worker_pool_id, engine_instance_id);

            CREATE TABLE IF NOT EXISTS engine_node_health (
                node_id TEXT NOT NULL,
                engine_instance_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'unknown',
                ok BOOLEAN NOT NULL DEFAULT FALSE,
                health_status TEXT NOT NULL DEFAULT 'unknown',
                detail TEXT NOT NULL DEFAULT '',
                product_version TEXT,
                engine_version TEXT,
                signature_version TEXT,
                service_state TEXT,
                storage_readable BOOLEAN,
                storage_writable BOOLEAN,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                last_checked_at INTEGER,
                last_success_at INTEGER,
                last_scan_success_at INTEGER,
                details_json TEXT NOT NULL DEFAULT '{}',
                check_worker_id TEXT,
                check_generation INTEGER NOT NULL DEFAULT 0,
                check_lease_expires_at INTEGER,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (node_id, engine_instance_id),
                FOREIGN KEY (node_id) REFERENCES worker_nodes (node_id) ON DELETE CASCADE,
                FOREIGN KEY (engine_instance_id) REFERENCES engine_instances (id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_engine_node_health_due
            ON engine_node_health (node_id, check_lease_expires_at, last_checked_at);

            CREATE TABLE IF NOT EXISTS scan_engine_jobs (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                scan_job_id INTEGER NOT NULL,
                engine_instance_id INTEGER,
                engine_key TEXT NOT NULL,
                engine_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                worker_id TEXT,
                claimed_at TIMESTAMPTZ,
                started_at TIMESTAMPTZ,
                finished_at TIMESTAMPTZ,
                lease_expires_at INTEGER,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_job_id) REFERENCES scan_jobs (id) ON DELETE CASCADE,
                FOREIGN KEY (engine_instance_id) REFERENCES engine_instances (id) ON DELETE SET NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_engine_jobs_scan_instance
            ON scan_engine_jobs (scan_job_id, engine_instance_id);

            CREATE INDEX IF NOT EXISTS idx_scan_engine_jobs_claim
            ON scan_engine_jobs (status, engine_key, lease_expires_at, id);

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
                auth_source TEXT NOT NULL DEFAULT 'local',
                external_id TEXT,
                display_name TEXT,
                last_login_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                actor_name TEXT,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
                source_ip TEXT,
                request_id TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_audit_events_created
            ON audit_events (created_at DESC, id DESC);

            CREATE INDEX IF NOT EXISTS idx_audit_events_action
            ON audit_events (action, outcome, id DESC);
            """
        )
        ensure_column(connection, "scan_jobs", "started_at", "TIMESTAMPTZ")
        ensure_column(connection, "scan_jobs", "failed_at", "TIMESTAMPTZ")
        ensure_column(connection, "scan_jobs", "attempt_count", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "scan_jobs", "last_error", "TEXT")
        ensure_column(connection, "scan_jobs", "source", "TEXT NOT NULL DEFAULT 'manual'")
        ensure_column(connection, "scan_jobs", "batch_id", "INTEGER")
        ensure_column(connection, "scan_jobs", "parent_scan_id", "INTEGER")
        ensure_column(connection, "scan_jobs", "relative_path", "TEXT")
        ensure_column(connection, "scan_jobs", "scan_role", "TEXT NOT NULL DEFAULT 'standalone'")
        ensure_column(connection, "scan_jobs", "finalize_worker_id", "TEXT")
        ensure_column(connection, "scan_jobs", "finalize_generation", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "scan_jobs", "finalize_lease_expires_at", "INTEGER")
        ensure_column(connection, "scan_jobs", "archive_member_ordinal", "INTEGER")
        ensure_column(connection, "engine_results", "details_json", "TEXT NOT NULL DEFAULT '{}'")
        ensure_column(connection, "engine_results", "findings_json", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column(connection, "scan_engine_jobs", "worker_node_id", "TEXT")
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_engine_jobs_worker_node_status
            ON scan_engine_jobs (worker_node_id, status, id)
            """
        )
        ensure_column(connection, "users", "auth_source", "TEXT NOT NULL DEFAULT 'local'")
        ensure_column(connection, "users", "external_id", "TEXT")
        ensure_column(connection, "users", "display_name", "TEXT")
        ensure_column(connection, "users", "last_login_at", "TIMESTAMPTZ")
        migrate_engine_instances_for_multiple_instances(connection)
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id
            ON users (external_id) WHERE external_id IS NOT NULL
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_engine_results_scan_engine
            ON engine_results (scan_job_id, engine_name)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_source_created
            ON scan_jobs (source, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_source_status_created
            ON scan_jobs (source, status, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_batch_created
            ON scan_jobs (batch_id, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_parent
            ON scan_jobs (parent_scan_id, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_role_created
            ON scan_jobs (scan_role, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_batches_source_created
            ON scan_batches (source, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_worker_events_scan_created
            ON scan_worker_events (scan_job_id, created_at, id)
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_engine_jobs_scan_instance
            ON scan_engine_jobs (scan_job_id, engine_instance_id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_engine_jobs_claim
            ON scan_engine_jobs (status, engine_key, lease_expires_at, id)
            """
        )
        # Partial unique index makes archive-child registration idempotent by
        # ordinal (member names can repeat within an archive). Legacy children
        # predate the column and carry NULL, which the WHERE clause excludes, so
        # this is safe to create on a DB that already has duplicate child paths.
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_jobs_archive_member
            ON scan_jobs (parent_scan_id, archive_member_ordinal)
            WHERE archive_member_ordinal IS NOT NULL
            """
        )


def ensure_column(
    connection: Any,
    table_name: str,
    column_name: str,
    definition: str,
) -> None:
    if using_postgres():
        rows = connection.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = ?
            """,
            (table_name,),
        ).fetchall()
        columns = {str(row_value(row, "column_name")) for row in rows}
    else:
        columns = {
            str(row_value(row, "name"))
            for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
    if column_name not in columns:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def migrate_engine_instances_for_multiple_instances(connection: Any) -> None:
    """Lift the legacy one-row-per-adapter constraint without losing instances.

    ``adapter_key`` describes executable behavior, not a configured deployment.
    Multiple deployments may therefore share one adapter while retaining distinct
    names and configuration. Existing jobs are backfilled to their legacy instance
    before the queue uniqueness rule moves from adapter key to instance id.
    """
    if using_postgres():
        connection.execute(
            "ALTER TABLE engine_instances "
            "DROP CONSTRAINT IF EXISTS engine_instances_adapter_key_key"
        )
    elif sqlite_engine_instances_has_legacy_adapter_uniqueness(connection):
        # SQLite cannot drop a UNIQUE table constraint. Rebuild only this small
        # configuration table, preserving ids so existing job foreign keys remain
        # valid. PRAGMA foreign_keys must be changed outside an active transaction.
        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.executescript(
                """
                CREATE TABLE engine_instances_multi (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    adapter_key TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    config_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO engine_instances_multi (
                    id, adapter_key, display_name, enabled, config_json,
                    created_at, updated_at
                )
                SELECT
                    id, adapter_key, display_name, enabled, config_json,
                    created_at, updated_at
                FROM engine_instances;
                DROP TABLE engine_instances;
                ALTER TABLE engine_instances_multi RENAME TO engine_instances;
                """
            )
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    make_engine_display_names_unique(connection)
    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_engine_instances_display_name
        ON engine_instances (display_name)
        """
    )
    connection.execute(
        """
        UPDATE scan_engine_jobs
        SET engine_instance_id = (
            SELECT MIN(engine_instances.id)
            FROM engine_instances
            WHERE engine_instances.adapter_key = scan_engine_jobs.engine_key
              AND engine_instances.display_name = scan_engine_jobs.engine_name
        )
        WHERE engine_instance_id IS NULL
          AND EXISTS (
              SELECT 1
              FROM engine_instances
              WHERE engine_instances.adapter_key = scan_engine_jobs.engine_key
                AND engine_instances.display_name = scan_engine_jobs.engine_name
          )
        """
    )
    connection.execute("DROP INDEX IF EXISTS idx_scan_engine_jobs_scan_engine")
    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_engine_jobs_scan_instance
        ON scan_engine_jobs (scan_job_id, engine_instance_id)
        """
    )


def sqlite_engine_instances_has_legacy_adapter_uniqueness(connection: Any) -> bool:
    for index_row in connection.execute("PRAGMA index_list(engine_instances)").fetchall():
        if not bool(row_value(index_row, "unique")):
            continue
        index_name = str(row_value(index_row, "name"))
        quoted_name = index_name.replace('"', '""')
        columns = tuple(
            str(row_value(column_row, "name"))
            for column_row in connection.execute(
                f'PRAGMA index_info("{quoted_name}")'
            ).fetchall()
        )
        if columns == ("adapter_key",):
            return True
    return False


def make_engine_display_names_unique(connection: Any) -> None:
    """Deterministically repair legacy duplicate labels before adding uniqueness."""
    rows = connection.execute(
        "SELECT id, display_name FROM engine_instances ORDER BY id ASC"
    ).fetchall()
    used: set[str] = set()
    for row in rows:
        instance_id = int(row_value(row, "id"))
        base_name = str(row_value(row, "display_name")).strip() or f"Engine {instance_id}"
        candidate = base_name
        suffix = 2
        while candidate.casefold() in used:
            candidate = f"{base_name} {suffix}"
            suffix += 1
        used.add(candidate.casefold())
        if candidate != str(row_value(row, "display_name")):
            connection.execute(
                "UPDATE engine_instances SET display_name = ? WHERE id = ?",
                (candidate, instance_id),
            )


def create_user(
    username: str,
    password_hash: str,
    role: str,
    *,
    auth_source: str = "local",
    external_id: str | None = None,
    display_name: str | None = None,
) -> int:
    try:
        with connect() as connection:
            cursor = connection.execute(
                f"""
                INSERT INTO users (
                    username, password_hash, role, auth_source, external_id, display_name
                )
                VALUES (?, ?, ?, ?, ?, ?)
                {returning_id_clause()}
                """,
                (
                    username,
                    password_hash,
                    role,
                    auth_source,
                    external_id,
                    display_name,
                ),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()
        return create_user(
            username,
            password_hash,
            role,
            auth_source=auth_source,
            external_id=external_id,
            display_name=display_name,
        )
    return require_lastrowid(cursor)


def list_users() -> list[UserRecord]:
    try:
        with connect() as connection:
            rows = connection.execute(
                """
                SELECT id, username, password_hash, role, auth_source,
                       external_id, display_name, last_login_at,
                       created_at, updated_at
                FROM users
                ORDER BY username ASC
                """
            ).fetchall()
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()
        return []
    return [row_to_user_record(row) for row in rows]


def get_user_by_username(username: str) -> UserRecord | None:
    try:
        with connect() as connection:
            row = connection.execute(
                """
                SELECT id, username, password_hash, role, auth_source,
                       external_id, display_name, last_login_at,
                       created_at, updated_at
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()
        return None
    return row_to_user_record(row) if row is not None else None


def get_user_by_id(user_id: int) -> UserRecord | None:
    try:
        with connect() as connection:
            row = connection.execute(
                """
                SELECT id, username, password_hash, role, auth_source,
                       external_id, display_name, last_login_at,
                       created_at, updated_at
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()
        return None
    return row_to_user_record(row) if row is not None else None


def update_user(
    user_id: int,
    role: str,
    password_hash: str | None = None,
) -> None:
    try:
        with connect() as connection:
            if password_hash is None:
                connection.execute(
                    """
                    UPDATE users
                    SET role = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (role, user_id),
                )
            else:
                connection.execute(
                    """
                    UPDATE users
                    SET role = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (role, password_hash, user_id),
                )
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()


def sync_external_user(
    *,
    username: str,
    role: str,
    external_id: str,
    display_name: str | None,
) -> UserRecord:
    """Create/update a passwordless LDAP shadow user after a successful bind.

    A local username collision is rejected so directory authentication can
    never claim or upgrade a break-glass/local account.
    """
    normalized_external_id = external_id.strip()
    if not normalized_external_id:
        raise ValueError("External user identity is required.")
    with connect() as connection:
        row = connection.execute(
            """
            SELECT id, username, auth_source
            FROM users
            WHERE external_id = ? OR LOWER(username) = LOWER(?)
            ORDER BY CASE WHEN external_id = ? THEN 0 ELSE 1 END
            LIMIT 1
            """,
            (normalized_external_id, username, normalized_external_id),
        ).fetchone()
        if row is None:
            cursor = connection.execute(
                f"""
                INSERT INTO users (
                    username, password_hash, role, auth_source, external_id,
                    display_name, last_login_at
                )
                VALUES (?, '!ldap', ?, 'ldap', ?, ?, CURRENT_TIMESTAMP)
                {returning_id_clause()}
                """,
                (username, role, normalized_external_id, display_name),
            )
            user_id = require_lastrowid(cursor)
        else:
            if str(row_value(row, "auth_source")) != "ldap":
                raise ValueError("Directory username conflicts with a local account.")
            user_id = int(row_value(row, "id"))
            connection.execute(
                """
                UPDATE users
                SET role = ?, external_id = ?, display_name = ?,
                    last_login_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (role, normalized_external_id, display_name, user_id),
            )
    user = get_user_by_id(user_id)
    if user is None:
        raise RuntimeError("LDAP shadow user could not be loaded after synchronization.")
    return user


def delete_user(user_id: int) -> None:
    try:
        with connect() as connection:
            connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()


def count_users_by_role(role: str, auth_source: str | None = None) -> int:
    try:
        with connect() as connection:
            if auth_source is None:
                row = connection.execute(
                    "SELECT COUNT(*) FROM users WHERE role = ?",
                    (role,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) FROM users WHERE role = ? AND auth_source = ?",
                    (role, auth_source),
                ).fetchone()
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()
        return 0
    if row is None:
        return 0
    return int(row[0])


def create_audit_event(
    *,
    actor_type: str,
    actor_id: str | None,
    actor_name: str | None,
    action: str,
    target_type: str,
    target_id: str | None,
    outcome: str,
    source_ip: str | None,
    request_id: str,
    details_json: str = "{}",
) -> int:
    """Append an audit event.

    Deliberately paired with read APIs only: audit rows are not mutable or
    deletable through the application data layer.
    """
    with connect() as connection:
        cursor = connection.execute(
            f"""
            INSERT INTO audit_events (
                actor_type, actor_id, actor_name, action, target_type,
                target_id, outcome, source_ip, request_id, details_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            {returning_id_clause()}
            """,
            (
                actor_type,
                actor_id,
                actor_name,
                action,
                target_type,
                target_id,
                outcome,
                source_ip,
                request_id,
                details_json,
            ),
        )
    return require_lastrowid(cursor)


def _audit_filter_clause(query: str, outcome: str) -> tuple[str, list[object]]:
    clauses: list[str] = []
    params: list[object] = []
    normalized_query = query.strip().lower()
    if normalized_query:
        clauses.append(
            "(" + " OR ".join(
                f"LOWER(COALESCE({column}, '')) LIKE ?"
                for column in (
                    "actor_name",
                    "actor_id",
                    "action",
                    "target_type",
                    "target_id",
                    "request_id",
                )
            ) + ")"
        )
        params.extend([f"%{normalized_query}%"] * 6)
    if outcome in {"success", "failure", "denied"}:
        clauses.append("outcome = ?")
        params.append(outcome)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


def list_audit_events(
    *, query: str = "", outcome: str = "all", limit: int = 50, offset: int = 0
) -> list[AuditEventRecord]:
    where_sql, params = _audit_filter_clause(query, outcome)
    safe_limit = max(1, min(limit, 200))
    safe_offset = max(0, offset)
    with connect() as connection:
        rows = connection.execute(
            f"""
            SELECT id, created_at, actor_type, actor_id, actor_name, action,
                   target_type, target_id, outcome, source_ip, request_id, details_json
            FROM audit_events
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, safe_limit, safe_offset),
        ).fetchall()
    return [row_to_audit_event_record(row) for row in rows]


def count_audit_events(*, query: str = "", outcome: str = "all") -> int:
    where_sql, params = _audit_filter_clause(query, outcome)
    with connect() as connection:
        row = connection.execute(
            f"SELECT COUNT(*) AS event_count FROM audit_events{where_sql}",
            params,
        ).fetchone()
    return 0 if row is None else int(row_value(row, "event_count"))


def create_auth_session(user_id: int, token_hash: str, expires_at: int) -> int:
    try:
        with connect() as connection:
            cursor = connection.execute(
                f"""
                INSERT INTO auth_sessions (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)
                {returning_id_clause()}
                """,
                (user_id, token_hash, expires_at),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()
        return create_auth_session(user_id, token_hash, expires_at)
    return require_lastrowid(cursor)


def get_user_by_session(token_hash: str, now: int) -> UserRecord | None:
    try:
        with connect() as connection:
            row = connection.execute(
                """
                SELECT
                    users.id,
                    users.username,
                    users.password_hash,
                    users.role,
                    users.auth_source,
                    users.external_id,
                    users.display_name,
                    users.last_login_at,
                    users.created_at,
                    users.updated_at
                FROM auth_sessions
                JOIN users ON users.id = auth_sessions.user_id
                WHERE auth_sessions.token_hash = ?
                  AND auth_sessions.expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()
        return None
    return row_to_user_record(row) if row is not None else None


def delete_auth_session(token_hash: str) -> None:
    try:
        with connect() as connection:
            connection.execute(
                "DELETE FROM auth_sessions WHERE token_hash = ?",
                (token_hash,),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()


def delete_auth_sessions_for_user(user_id: int) -> None:
    try:
        with connect() as connection:
            connection.execute(
                "DELETE FROM auth_sessions WHERE user_id = ?",
                (user_id,),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()


def delete_expired_auth_sessions(now: int) -> None:
    try:
        with connect() as connection:
            connection.execute(
                "DELETE FROM auth_sessions WHERE expires_at <= ?",
                (now,),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()


def get_setting(key: str, default: str | None = None) -> str | None:
    try:
        with connect() as connection:
            row = connection.execute(
                "SELECT value FROM app_settings WHERE key = ?",
                (key,),
            ).fetchone()
    except sqlite3.OperationalError as exc:
        if not is_missing_settings_table(exc):
            raise
        init_db()
        with connect() as connection:
            row = connection.execute(
                "SELECT value FROM app_settings WHERE key = ?",
                (key,),
            ).fetchone()
    if row is None:
        return default
    return str(row_value(row, "value"))


def get_settings(defaults: dict[str, str]) -> dict[str, str]:
    values = dict(defaults)
    if not defaults:
        return values

    placeholders = ",".join("?" for _ in defaults)
    try:
        with connect() as connection:
            rows = connection.execute(
                f"SELECT key, value FROM app_settings WHERE key IN ({placeholders})",
                tuple(defaults.keys()),
            ).fetchall()
    except sqlite3.OperationalError as exc:
        if not is_missing_settings_table(exc):
            raise
        init_db()
        with connect() as connection:
            rows = connection.execute(
                f"SELECT key, value FROM app_settings WHERE key IN ({placeholders})",
                tuple(defaults.keys()),
            ).fetchall()

    for row in rows:
        values[str(row_value(row, "key"))] = str(row_value(row, "value"))
    return values


def set_setting(key: str, value: str) -> None:
    try:
        with connect() as connection:
            connection.execute(
                """
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (key, value),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_settings_table(exc):
            raise
        init_db()
        with connect() as connection:
            connection.execute(
                """
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (key, value),
            )


def delete_setting(key: str) -> None:
    """Remove a stored setting, reverting it to its env/hardcoded default."""
    try:
        with connect() as connection:
            connection.execute("DELETE FROM app_settings WHERE key = ?", (key,))
    except sqlite3.OperationalError as exc:
        if not is_missing_settings_table(exc):
            raise
        # No table yet means there is nothing to delete.


def list_settings_by_prefix(prefix: str) -> dict[str, str]:
    """Return every ``app_settings`` row whose key starts with ``prefix``.

    A single query fetches the whole set (no per-key round trips). ``LIKE``
    wildcards (``%``, ``_``) and the escape char in ``prefix`` are escaped so an
    arbitrary prefix is matched literally on both SQLite and PostgreSQL.
    """
    escaped = (
        prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    pattern = f"{escaped}%"
    query = "SELECT key, value FROM app_settings WHERE key LIKE ? ESCAPE '\\'"
    try:
        with connect() as connection:
            rows = connection.execute(query, (pattern,)).fetchall()
    except sqlite3.OperationalError as exc:
        if not is_missing_settings_table(exc):
            raise
        init_db()
        with connect() as connection:
            rows = connection.execute(query, (pattern,)).fetchall()
    return {str(row_value(row, "key")): str(row_value(row, "value")) for row in rows}


def delete_settings_if_values_match(settings: dict[str, str]) -> int:
    """Delete settings only if their values are unchanged since they were read.

    The value comparison makes read-then-cleanup callers safe against a
    concurrent UPSERT refreshing the same key between their SELECT and DELETE.
    Missing or concurrently updated rows are ignored.
    """
    items = [(str(key), str(value)) for key, value in settings.items()]
    if not items:
        return 0
    predicates = " OR ".join("(key = ? AND value = ?)" for _ in items)
    params = tuple(part for item in items for part in item)
    query = f"DELETE FROM app_settings WHERE {predicates}"
    try:
        with connect() as connection:
            cursor = connection.execute(query, params)
            return max(0, int(cursor.rowcount))
    except sqlite3.OperationalError as exc:
        if not is_missing_settings_table(exc):
            raise
        # No table yet means there is nothing to delete.
        return 0


def list_engine_instances() -> list[EngineInstanceRecord]:
    try:
        with connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    adapter_key,
                    display_name,
                    enabled,
                    config_json,
                    created_at,
                    updated_at
                FROM engine_instances
                ORDER BY created_at ASC, id ASC
                """
            ).fetchall()
    except sqlite3.OperationalError as exc:
        if not is_missing_engine_instances_table(exc):
            raise
        init_db()
        with connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    adapter_key,
                    display_name,
                    enabled,
                    config_json,
                    created_at,
                    updated_at
                FROM engine_instances
                ORDER BY created_at ASC, id ASC
                """
            ).fetchall()
    return [row_to_engine_instance_record(row) for row in rows]


def get_engine_instance(adapter_key: str) -> EngineInstanceRecord | None:
    try:
        with connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    adapter_key,
                    display_name,
                    enabled,
                    config_json,
                    created_at,
                    updated_at
                FROM engine_instances
                WHERE adapter_key = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (adapter_key,),
            ).fetchone()
    except sqlite3.OperationalError as exc:
        if not is_missing_engine_instances_table(exc):
            raise
        init_db()
        with connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    adapter_key,
                    display_name,
                    enabled,
                    config_json,
                    created_at,
                    updated_at
                FROM engine_instances
                WHERE adapter_key = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (adapter_key,),
            ).fetchone()
    if row is None:
        return None
    return row_to_engine_instance_record(row)


def get_engine_instance_by_id(instance_id: int) -> EngineInstanceRecord | None:
    with connect() as connection:
        row = connection.execute(
            """
            SELECT
                id,
                adapter_key,
                display_name,
                enabled,
                config_json,
                created_at,
                updated_at
            FROM engine_instances
            WHERE id = ?
            """,
            (instance_id,),
        ).fetchone()
    return None if row is None else row_to_engine_instance_record(row)


def list_engine_instances_for_adapter(adapter_key: str) -> list[EngineInstanceRecord]:
    return [
        instance
        for instance in list_engine_instances()
        if instance.adapter_key == adapter_key
    ]


def create_engine_instance(
    adapter_key: str,
    display_name: str,
    enabled: bool = True,
    config_json: str = "{}",
) -> int:
    try:
        with connect() as connection:
            cursor = connection.execute(
                f"""
                INSERT INTO engine_instances (
                    adapter_key,
                    display_name,
                    enabled,
                    config_json,
                    updated_at
                )
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                {returning_id_clause()}
                """,
                (adapter_key, display_name, db_bool(enabled), config_json),
            )
            return require_lastrowid(cursor)
    except sqlite3.OperationalError as exc:
        if not is_missing_engine_instances_table(exc):
            raise
        init_db()
        return create_engine_instance(adapter_key, display_name, enabled, config_json)


def update_engine_instance(
    adapter_key: str,
    display_name: str | None = None,
    enabled: bool | None = None,
    config_json: str | None = None,
) -> None:
    instance = get_engine_instance(adapter_key)
    if instance is None:
        return

    try:
        with connect() as connection:
            connection.execute(
                """
                UPDATE engine_instances
                SET
                    display_name = ?,
                    enabled = ?,
                    config_json = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    display_name if display_name is not None else instance.display_name,
                    db_bool(enabled if enabled is not None else instance.enabled),
                    config_json if config_json is not None else instance.config_json,
                    instance.id,
                ),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_engine_instances_table(exc):
            raise
        init_db()
        update_engine_instance(adapter_key, display_name, enabled, config_json)


def update_engine_instance_by_id(
    instance_id: int,
    display_name: str | None = None,
    enabled: bool | None = None,
    config_json: str | None = None,
) -> None:
    instance = get_engine_instance_by_id(instance_id)
    if instance is None:
        return
    with connect() as connection:
        connection.execute(
            """
            UPDATE engine_instances
            SET
                display_name = ?,
                enabled = ?,
                config_json = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                display_name if display_name is not None else instance.display_name,
                db_bool(enabled if enabled is not None else instance.enabled),
                config_json if config_json is not None else instance.config_json,
                instance_id,
            ),
        )


def delete_engine_instance(adapter_key: str) -> None:
    instance = get_engine_instance(adapter_key)
    if instance is None:
        return
    try:
        with connect() as connection:
            connection.execute(
                "DELETE FROM engine_instances WHERE id = ?",
                (instance.id,),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_engine_instances_table(exc):
            raise
        init_db()
        delete_engine_instance(adapter_key)


def delete_engine_instance_by_id(instance_id: int) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM engine_instances WHERE id = ?", (instance_id,))


WORKER_NODE_LIFECYCLE_STATES = frozenset({"active", "draining", "disabled"})


def upsert_worker_node_heartbeat(
    *,
    node_id: str,
    display_name: str,
    hostname: str,
    platform: str,
    agent_version: str,
    labels_json: str,
    capacity: int,
    advertised_engine_keys_json: str,
    runtime_state: str,
    active_scan_id: int | None,
    process_id: int,
    last_heartbeat_at: int,
) -> WorkerNodeRecord:
    """Register or refresh a node without overriding an admin lifecycle choice."""
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO worker_nodes (
                node_id, display_name, hostname, platform, agent_version,
                labels_json, capacity, advertised_engine_keys_json,
                lifecycle_state, runtime_state, active_scan_id, process_id,
                last_heartbeat_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT (node_id) DO UPDATE SET
                display_name = excluded.display_name,
                hostname = excluded.hostname,
                platform = excluded.platform,
                agent_version = excluded.agent_version,
                labels_json = excluded.labels_json,
                capacity = excluded.capacity,
                advertised_engine_keys_json = excluded.advertised_engine_keys_json,
                runtime_state = excluded.runtime_state,
                active_scan_id = excluded.active_scan_id,
                process_id = excluded.process_id,
                last_heartbeat_at = excluded.last_heartbeat_at,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                node_id,
                display_name,
                hostname,
                platform,
                agent_version,
                labels_json,
                capacity,
                advertised_engine_keys_json,
                runtime_state,
                active_scan_id,
                process_id,
                last_heartbeat_at,
            ),
        )
        row = connection.execute(
            "SELECT * FROM worker_nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
    if row is None:
        raise RuntimeError("Worker node heartbeat was not persisted.")
    return row_to_worker_node_record(row)


def get_worker_node(node_id: str) -> WorkerNodeRecord | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM worker_nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
    return None if row is None else row_to_worker_node_record(row)


def create_worker_agent_credential(
    *,
    node_id: str,
    token_hash: str,
    token_prefix: str,
    expires_at: int | None = None,
    revoke_existing: bool = True,
) -> WorkerAgentCredentialRecord:
    """Persist a high-entropy agent credential hash, never its plaintext token."""
    with connect() as connection:
        if not using_postgres():
            connection.execute("BEGIN IMMEDIATE")
        node = connection.execute(
            "SELECT 1 FROM worker_nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        if node is None:
            raise ValueError("Worker node must be registered before issuing a credential.")
        if revoke_existing:
            connection.execute(
                """
                UPDATE worker_agent_credentials
                SET revoked_at = ?
                WHERE node_id = ? AND revoked_at IS NULL
                """,
                (int(time.time()), node_id),
            )
        cursor = connection.execute(
            f"""
            INSERT INTO worker_agent_credentials (
                node_id, token_hash, token_prefix, expires_at
            )
            VALUES (?, ?, ?, ?)
            {returning_id_clause()}
            """,
            (node_id, token_hash, token_prefix, expires_at),
        )
        credential_id = require_lastrowid(cursor)
        row = connection.execute(
            "SELECT * FROM worker_agent_credentials WHERE id = ?",
            (credential_id,),
        ).fetchone()
    if row is None:  # pragma: no cover - the row was just inserted
        raise RuntimeError("Worker credential was not persisted.")
    return row_to_worker_agent_credential_record(row)


def authenticate_worker_agent_credential(
    token_hash: str,
    *,
    now: int | None = None,
) -> WorkerAgentCredentialRecord | None:
    """Resolve and touch an active credential by its deterministic token hash."""
    current_time = int(time.time()) if now is None else now
    with connect() as connection:
        row = connection.execute(
            """
            SELECT * FROM worker_agent_credentials
            WHERE token_hash = ?
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (token_hash, current_time),
        ).fetchone()
        if row is not None:
            last_used = row_value(row, "last_used_at")
            # Credential use is operational metadata, not an access log. Touch
            # it at most once per minute so heartbeat/lease polling does not
            # create a database write for every control-plane request.
            if last_used is None or int(last_used) <= current_time - 60:
                connection.execute(
                    """
                    UPDATE worker_agent_credentials
                    SET last_used_at = ?
                    WHERE id = ?
                    """,
                    (current_time, int(row_value(row, "id"))),
                )
    return None if row is None else row_to_worker_agent_credential_record(row)


def revoke_worker_agent_credentials(node_id: str, *, now: int | None = None) -> int:
    current_time = int(time.time()) if now is None else now
    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE worker_agent_credentials
            SET revoked_at = ?
            WHERE node_id = ? AND revoked_at IS NULL
            """,
            (current_time, node_id),
        )
    return max(0, int(cursor.rowcount or 0))


def list_worker_agent_credentials(node_id: str) -> list[WorkerAgentCredentialRecord]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT * FROM worker_agent_credentials
            WHERE node_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            (node_id,),
        ).fetchall()
    return [row_to_worker_agent_credential_record(row) for row in rows]


def list_worker_nodes() -> list[WorkerNodeRecord]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM worker_nodes
            ORDER BY display_name ASC, node_id ASC
            """
        ).fetchall()
    return [row_to_worker_node_record(row) for row in rows]


def update_worker_node_lifecycle(node_id: str, lifecycle_state: str) -> bool:
    normalized_state = lifecycle_state.strip().lower()
    if normalized_state not in WORKER_NODE_LIFECYCLE_STATES:
        raise ValueError(f"Unsupported worker lifecycle state: {lifecycle_state}")
    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE worker_nodes
            SET lifecycle_state = ?, updated_at = CURRENT_TIMESTAMP
            WHERE node_id = ?
            """,
            (normalized_state, node_id),
        )
    return int(cursor.rowcount or 0) > 0


def create_worker_pool(name: str, selector_json: str = "{}") -> int:
    with connect() as connection:
        duplicate = connection.execute(
            "SELECT id FROM worker_pools WHERE LOWER(name) = LOWER(?) LIMIT 1",
            (name,),
        ).fetchone()
        if duplicate is not None:
            raise ValueError("A worker pool with this name already exists.")
        cursor = connection.execute(
            f"""
            INSERT INTO worker_pools (name, selector_json, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            {returning_id_clause()}
            """,
            (name, selector_json),
        )
        return require_lastrowid(cursor)


def get_worker_pool(pool_id: int) -> WorkerPoolRecord | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM worker_pools WHERE id = ?",
            (pool_id,),
        ).fetchone()
    return None if row is None else row_to_worker_pool_record(row)


def list_worker_pools() -> list[WorkerPoolRecord]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM worker_pools ORDER BY name ASC, id ASC"
        ).fetchall()
    return [row_to_worker_pool_record(row) for row in rows]


def update_worker_pool(
    pool_id: int,
    *,
    name: str,
    selector_json: str,
    enabled: bool,
) -> bool:
    with connect() as connection:
        duplicate = connection.execute(
            """
            SELECT id FROM worker_pools
            WHERE LOWER(name) = LOWER(?) AND id <> ?
            LIMIT 1
            """,
            (name, pool_id),
        ).fetchone()
        if duplicate is not None:
            raise ValueError("A worker pool with this name already exists.")
        cursor = connection.execute(
            """
            UPDATE worker_pools
            SET name = ?, selector_json = ?, enabled = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (name, selector_json, db_bool(enabled), pool_id),
        )
    return int(cursor.rowcount or 0) > 0


def delete_worker_pool(pool_id: int) -> bool:
    """Delete an unused pool; bindings must be removed explicitly first."""
    with connect() as connection:
        binding = connection.execute(
            """
            SELECT engine_instance_id
            FROM engine_instance_worker_pools
            WHERE worker_pool_id = ?
            LIMIT 1
            """,
            (pool_id,),
        ).fetchone()
        if binding is not None:
            raise ValueError("Worker pool is still assigned to an engine instance.")
        cursor = connection.execute("DELETE FROM worker_pools WHERE id = ?", (pool_id,))
    return int(cursor.rowcount or 0) > 0


def set_engine_instance_worker_pool(
    engine_instance_id: int,
    worker_pool_id: int | None,
) -> None:
    with connect() as connection:
        engine = connection.execute(
            "SELECT id FROM engine_instances WHERE id = ?",
            (engine_instance_id,),
        ).fetchone()
        if engine is None:
            raise ValueError("Engine instance not found.")
        if worker_pool_id is None:
            connection.execute(
                "DELETE FROM engine_instance_worker_pools WHERE engine_instance_id = ?",
                (engine_instance_id,),
            )
            return
        pool = connection.execute(
            "SELECT id FROM worker_pools WHERE id = ?",
            (worker_pool_id,),
        ).fetchone()
        if pool is None:
            raise ValueError("Worker pool not found.")
        connection.execute(
            """
            INSERT INTO engine_instance_worker_pools (
                engine_instance_id, worker_pool_id, updated_at
            )
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT (engine_instance_id) DO UPDATE SET
                worker_pool_id = excluded.worker_pool_id,
                updated_at = CURRENT_TIMESTAMP
            """,
            (engine_instance_id, worker_pool_id),
        )


def list_engine_instance_worker_pool_bindings() -> dict[int, int]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT engine_instance_id, worker_pool_id
            FROM engine_instance_worker_pools
            ORDER BY engine_instance_id ASC
            """
        ).fetchall()
    return {
        int(row_value(row, "engine_instance_id")): int(row_value(row, "worker_pool_id"))
        for row in rows
    }


def ensure_engine_node_health_rows(node_id: str, engine_instance_ids: set[int]) -> None:
    if not engine_instance_ids:
        return
    with connect() as connection:
        for instance_id in sorted(engine_instance_ids):
            connection.execute(
                """
                INSERT INTO engine_node_health (node_id, engine_instance_id)
                VALUES (?, ?)
                ON CONFLICT (node_id, engine_instance_id) DO NOTHING
                """,
                (node_id, instance_id),
            )


def claim_due_engine_node_health(
    node_id: str,
    worker_id: str,
    engine_instance_ids: set[int],
    *,
    interval_seconds: int,
    lease_seconds: int,
    now: int | None = None,
) -> EngineNodeHealthRecord | None:
    if not engine_instance_ids:
        return None
    current_time = int(time.time()) if now is None else now
    due_before = current_time - max(1, interval_seconds)
    lease_expires_at = current_time + max(5, lease_seconds)
    sorted_ids = sorted(engine_instance_ids)
    placeholders = ", ".join("?" for _ in sorted_ids)
    with connect() as connection:
        if not using_postgres():
            connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            f"""
            SELECT node_id, engine_instance_id
            FROM engine_node_health
            WHERE node_id = ?
              AND engine_instance_id IN ({placeholders})
              AND (last_checked_at IS NULL OR last_checked_at <= ?)
              AND (check_lease_expires_at IS NULL OR check_lease_expires_at <= ?)
            ORDER BY last_checked_at ASC, engine_instance_id ASC
            LIMIT 1
            {"FOR UPDATE SKIP LOCKED" if using_postgres() else ""}
            """,
            (node_id, *sorted_ids, due_before, current_time),
        ).fetchone()
        if row is None:
            return None
        instance_id = int(row_value(row, "engine_instance_id"))
        connection.execute(
            """
            UPDATE engine_node_health
            SET status = 'checking', check_worker_id = ?,
                check_generation = check_generation + 1,
                check_lease_expires_at = ?, updated_at = CURRENT_TIMESTAMP
            WHERE node_id = ? AND engine_instance_id = ?
            """,
            (worker_id, lease_expires_at, node_id, instance_id),
        )
        claimed = connection.execute(
            """
            SELECT * FROM engine_node_health
            WHERE node_id = ? AND engine_instance_id = ?
            """,
            (node_id, instance_id),
        ).fetchone()
    return None if claimed is None else row_to_engine_node_health_record(claimed)


def commit_engine_node_health_if_owned(
    *,
    node_id: str,
    engine_instance_id: int,
    worker_id: str,
    check_generation: int,
    ok: bool,
    health_status: str,
    detail: str,
    product_version: str | None,
    engine_version: str | None,
    signature_version: str | None,
    service_state: str | None,
    storage_readable: bool | None,
    storage_writable: bool | None,
    details_json: str,
    now: int | None = None,
) -> bool:
    current_time = int(time.time()) if now is None else now
    normalized_status = "healthy" if ok else "unhealthy"
    if ok and health_status.strip().lower() == "degraded":
        normalized_status = "degraded"
    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE engine_node_health
            SET status = ?, ok = ?, health_status = ?, detail = ?,
                product_version = ?, engine_version = ?, signature_version = ?,
                service_state = ?, storage_readable = ?, storage_writable = ?,
                consecutive_failures = CASE WHEN ? THEN 0 ELSE consecutive_failures + 1 END,
                last_checked_at = ?,
                last_success_at = CASE WHEN ? THEN ? ELSE last_success_at END,
                details_json = ?, check_worker_id = NULL,
                check_lease_expires_at = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE node_id = ? AND engine_instance_id = ?
              AND check_worker_id = ? AND check_generation = ?
            """,
            (
                normalized_status,
                db_bool(ok),
                health_status,
                detail,
                product_version,
                engine_version,
                signature_version,
                service_state,
                None if storage_readable is None else db_bool(storage_readable),
                None if storage_writable is None else db_bool(storage_writable),
                db_bool(ok),
                current_time,
                db_bool(ok),
                current_time,
                details_json,
                node_id,
                engine_instance_id,
                worker_id,
                check_generation,
            ),
        )
    return int(cursor.rowcount or 0) > 0


def record_engine_node_scan_success(
    node_id: str,
    engine_instance_id: int,
    *,
    engine_version: str | None,
    signature_version: str | None,
    now: int | None = None,
) -> None:
    current_time = int(time.time()) if now is None else now
    with connect() as connection:
        node_exists = connection.execute(
            "SELECT 1 FROM worker_nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        engine_exists = connection.execute(
            "SELECT 1 FROM engine_instances WHERE id = ?",
            (engine_instance_id,),
        ).fetchone()
        if node_exists is None or engine_exists is None:
            return
        connection.execute(
            """
            INSERT INTO engine_node_health (
                node_id, engine_instance_id, engine_version, signature_version,
                last_scan_success_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT (node_id, engine_instance_id) DO UPDATE SET
                engine_version = COALESCE(excluded.engine_version, engine_node_health.engine_version),
                signature_version = COALESCE(excluded.signature_version, engine_node_health.signature_version),
                last_scan_success_at = excluded.last_scan_success_at,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                node_id,
                engine_instance_id,
                engine_version,
                signature_version,
                current_time,
            ),
        )


def request_engine_node_health_check(engine_instance_id: int) -> int:
    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE engine_node_health
            SET last_checked_at = NULL, check_worker_id = NULL,
                check_lease_expires_at = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE engine_instance_id = ?
            """,
            (engine_instance_id,),
        )
    return max(0, int(cursor.rowcount or 0))


def list_engine_node_health(
    *,
    node_id: str | None = None,
    engine_instance_id: int | None = None,
) -> list[EngineNodeHealthRecord]:
    clauses: list[str] = []
    params: list[object] = []
    if node_id is not None:
        clauses.append("node_id = ?")
        params.append(node_id)
    if engine_instance_id is not None:
        clauses.append("engine_instance_id = ?")
        params.append(engine_instance_id)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as connection:
        rows = connection.execute(
            f"""
            SELECT * FROM engine_node_health
            {where_sql}
            ORDER BY node_id ASC, engine_instance_id ASC
            """,
            tuple(params),
        ).fetchall()
    return [row_to_engine_node_health_record(row) for row in rows]


def _insert_sample(connection: Any, sample: StoredSample) -> int:
    cursor = connection.execute(
        f"""
        INSERT INTO samples (
            original_filename,
            stored_filename,
            storage_path,
            content_type,
            size_bytes,
            md5,
            sha1,
            sha256
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        {returning_id_clause()}
        """,
        (
            sample.original_filename,
            sample.stored_filename,
            sample.storage_path,
            sample.content_type,
            sample.size_bytes,
            sample.md5,
            sample.sha1,
            sample.sha256,
        ),
    )
    return require_lastrowid(cursor)


def create_sample(sample: StoredSample) -> int:
    with connect() as connection:
        return _insert_sample(connection, sample)


def _insert_scan_batch(
    connection: Any,
    *,
    source: str,
    original_filename: str,
    archive_mode: str,
    status: str = "queued",
    total_items: int = 0,
    metadata_json: str = "{}",
) -> int:
    cursor = connection.execute(
        f"""
        INSERT INTO scan_batches (
            source,
            original_filename,
            archive_mode,
            status,
            total_items,
            metadata_json,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        {returning_id_clause()}
        """,
        (
            source,
            original_filename,
            archive_mode,
            status,
            max(0, total_items),
            metadata_json,
        ),
    )
    return require_lastrowid(cursor)


def create_scan_batch(
    *,
    source: str,
    original_filename: str,
    archive_mode: str,
    status: str = "queued",
    total_items: int = 0,
    metadata_json: str = "{}",
) -> int:
    with connect() as connection:
        return _insert_scan_batch(
            connection,
            source=source,
            original_filename=original_filename,
            archive_mode=archive_mode,
            status=status,
            total_items=total_items,
            metadata_json=metadata_json,
        )


def get_scan_batch(batch_id: int) -> ScanBatchRecord | None:
    with connect() as connection:
        row = connection.execute(
            """
            SELECT
                id,
                source,
                original_filename,
                archive_mode,
                status,
                total_items,
                queued_items,
                running_items,
                completed_items,
                failed_items,
                malicious_items,
                skipped_items,
                metadata_json,
                created_at,
                updated_at,
                completed_at,
                last_error
            FROM scan_batches
            WHERE id = ?
            """,
            (batch_id,),
        ).fetchone()
    if row is None:
        return None
    return row_to_scan_batch_record(row)


def list_scan_batches_by_ids(batch_ids: list[int]) -> dict[int, ScanBatchRecord]:
    if not batch_ids:
        return {}

    placeholders = ", ".join("?" for _ in batch_ids)
    with connect() as connection:
        rows = connection.execute(
            f"""
            SELECT
                id,
                source,
                original_filename,
                archive_mode,
                status,
                total_items,
                queued_items,
                running_items,
                completed_items,
                failed_items,
                malicious_items,
                skipped_items,
                metadata_json,
                created_at,
                updated_at,
                completed_at,
                last_error
            FROM scan_batches
            WHERE id IN ({placeholders})
            """,
            tuple(batch_ids),
        ).fetchall()
    return {int(row_value(row, "id")): row_to_scan_batch_record(row) for row in rows}


def list_scan_batch_scans(
    batch_id: int,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[ScanRecord]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                scan_jobs.id,
                scan_jobs.sample_id,
                scan_jobs.case_name,
                scan_jobs.priority,
                scan_jobs.note,
                scan_jobs.source,
                scan_jobs.batch_id,
                scan_jobs.parent_scan_id,
                scan_jobs.relative_path,
                scan_jobs.scan_role,
                scan_jobs.status,
                scan_jobs.verdict,
                scan_jobs.risk_score,
                scan_jobs.created_at,
                scan_jobs.started_at,
                scan_jobs.completed_at,
                scan_jobs.failed_at,
                scan_jobs.attempt_count,
                scan_jobs.last_error,
                samples.original_filename,
                samples.stored_filename,
                samples.storage_path,
                samples.content_type,
                samples.size_bytes,
                samples.md5,
                samples.sha1,
                samples.sha256
            FROM scan_jobs
            JOIN samples ON samples.id = scan_jobs.sample_id
            WHERE scan_jobs.batch_id = ?
            ORDER BY scan_jobs.created_at ASC, scan_jobs.id ASC
            LIMIT ?
            OFFSET ?
            """,
            (batch_id, max(1, limit), max(0, offset)),
        ).fetchall()
    return [row_to_scan_record(row) for row in rows]


def refresh_scan_batch_counts(batch_id: int) -> bool:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT status, verdict
            FROM scan_jobs
            WHERE batch_id = ?
            """,
            (batch_id,),
        ).fetchall()
        if not rows:
            return False

        statuses = [str(row_value(row, "status")) for row in rows]
        verdicts = [str(row_value(row, "verdict")) for row in rows]
        total_items = len(rows)
        queued_items = sum(1 for status in statuses if status == "queued")
        # 'finalizing' is a non-terminal in-progress state; count it as running.
        running_items = sum(1 for status in statuses if status in {"running", "finalizing"})
        completed_items = sum(1 for status in statuses if status == "completed")
        failed_items = sum(1 for status in statuses if status == "failed")
        skipped_items = sum(1 for status in statuses if status == "skipped")
        malicious_items = sum(1 for verdict in verdicts if verdict in {"high", "critical"})
        terminal_items = completed_items + failed_items + skipped_items

        if terminal_items == total_items:
            batch_status = "completed"
        elif running_items:
            batch_status = "running"
        else:
            batch_status = "queued"

        connection.execute(
            """
            UPDATE scan_batches
            SET
                status = ?,
                total_items = ?,
                queued_items = ?,
                running_items = ?,
                completed_items = ?,
                failed_items = ?,
                malicious_items = ?,
                skipped_items = ?,
                updated_at = CURRENT_TIMESTAMP,
                completed_at = CASE
                    WHEN ? = 'completed' THEN CURRENT_TIMESTAMP
                    ELSE NULL
                END
            WHERE id = ?
            """,
            (
                batch_status,
                total_items,
                queued_items,
                running_items,
                completed_items,
                failed_items,
                malicious_items,
                skipped_items,
                batch_status,
                batch_id,
            ),
        )
    return True


def _insert_scan_job(
    connection: Any,
    *,
    sample_id: int,
    case_name: str,
    priority: str,
    note: str,
    source: str = "manual",
    batch_id: int | None = None,
    parent_scan_id: int | None = None,
    relative_path: str | None = None,
    scan_role: str = "standalone",
    status: str = "queued",
    verdict: str = "pending",
    risk_score: int | None = None,
    archive_member_ordinal: int | None = None,
) -> int:
    cursor = connection.execute(
        f"""
        INSERT INTO scan_jobs (
            sample_id,
            batch_id,
            parent_scan_id,
            case_name,
            priority,
            note,
            source,
            relative_path,
            scan_role,
            status,
            verdict,
            risk_score,
            archive_member_ordinal,
            started_at,
            completed_at
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL,
            CASE
                WHEN ? IN ('completed', 'failed') THEN CURRENT_TIMESTAMP
                ELSE NULL
            END
        )
        {returning_id_clause()}
        """,
        (
            sample_id,
            batch_id,
            parent_scan_id,
            case_name,
            priority,
            note,
            source,
            relative_path,
            scan_role,
            status,
            verdict,
            risk_score,
            archive_member_ordinal,
            status,
        ),
    )
    return require_lastrowid(cursor)


def create_scan_job(
    sample_id: int,
    case_name: str,
    priority: str,
    note: str,
    source: str = "manual",
    batch_id: int | None = None,
    parent_scan_id: int | None = None,
    relative_path: str | None = None,
    scan_role: str = "standalone",
    status: str = "queued",
    verdict: str = "pending",
    risk_score: int | None = None,
) -> int:
    with connect() as connection:
        return _insert_scan_job(
            connection,
            sample_id=sample_id,
            case_name=case_name,
            priority=priority,
            note=note,
            source=source,
            batch_id=batch_id,
            parent_scan_id=parent_scan_id,
            relative_path=relative_path,
            scan_role=scan_role,
            status=status,
            verdict=verdict,
            risk_score=risk_score,
        )


def create_engine_result(scan_job_id: int, result: EngineResultInput) -> int:
    with connect() as connection:
        cursor = connection.execute(
            f"""
            INSERT INTO engine_results (
                scan_job_id,
                engine_name,
                engine_version,
                signature_version,
                status,
                detected,
                signature,
                severity,
                confidence,
                raw_output,
                error_message,
                duration_ms,
                details_json,
                findings_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            {returning_id_clause()}
            """,
            (
                scan_job_id,
                result.engine_name,
                result.engine_version,
                result.signature_version,
                result.status,
                db_bool(result.detected),
                result.signature,
                result.severity,
                result.confidence,
                result.raw_output,
                result.error_message,
                result.duration_ms,
                result.details_json,
                result.findings_json,
            ),
        )
        return require_lastrowid(cursor)


def _insert_engine_result_if_missing(
    connection: Any, scan_job_id: int, result: EngineResultInput
) -> int | None:
    """Insert an engine result unless one already exists for the same engine.

    Runs inside the caller's transaction (no commit of its own), so it can be
    composed atomically with a fenced job-status update.
    """
    if using_postgres():
        cursor = connection.execute(
            """
            INSERT INTO engine_results (
                scan_job_id, engine_name, engine_version, signature_version,
                status, detected, signature, severity, confidence, raw_output,
                error_message, duration_ms, details_json, findings_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (scan_job_id, engine_name) DO NOTHING
            RETURNING id
            """,
            (
                scan_job_id,
                result.engine_name,
                result.engine_version,
                result.signature_version,
                result.status,
                result.detected,
                result.signature,
                result.severity,
                result.confidence,
                result.raw_output,
                result.error_message,
                result.duration_ms,
                result.details_json,
                result.findings_json,
            ),
        )
        row = cursor.fetchone()
        return None if row is None else int(row_value(row, "id"))

    existing_row = connection.execute(
        "SELECT id FROM engine_results WHERE scan_job_id = ? AND engine_name = ? LIMIT 1",
        (scan_job_id, result.engine_name),
    ).fetchone()
    if existing_row is not None:
        return None
    cursor = connection.execute(
        f"""
        INSERT INTO engine_results (
            scan_job_id, engine_name, engine_version, signature_version,
            status, detected, signature, severity, confidence, raw_output,
            error_message, duration_ms, details_json, findings_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        {returning_id_clause()}
        """,
        (
            scan_job_id,
            result.engine_name,
            result.engine_version,
            result.signature_version,
            result.status,
            db_bool(result.detected),
            result.signature,
            result.severity,
            result.confidence,
            result.raw_output,
            result.error_message,
            result.duration_ms,
            result.details_json,
            result.findings_json,
        ),
    )
    return require_lastrowid(cursor)


def create_engine_result_if_missing(scan_job_id: int, result: EngineResultInput) -> int | None:
    with connect() as connection:
        if not using_postgres():
            connection.execute("BEGIN IMMEDIATE")
        return _insert_engine_result_if_missing(connection, scan_job_id, result)


class StaleFinalizerError(RuntimeError):
    """A finalization side effect was attempted by a superseded finalizer.

    Raised when create_archive_child's caller is no longer the parent scan's
    finalization owner (different worker/generation, or the scan left
    ``finalizing``), so it must not create children or move files.
    """


class EngineResultConflictError(RuntimeError):
    """A fenced commit won the terminal transition but a result already existed.

    The winner of the terminal transition is the authoritative writer, so no
    prior result should exist for this engine. A conflict means an unexpected
    duplicate; the commit rolls back rather than silently attributing a stale
    result to this generation.
    """


def _terminal_fence(job_id: int, worker_id: str, attempt_generation: int) -> tuple[str, tuple[object, ...]]:
    return (
        "id = ? AND worker_id = ? AND attempt_count = ? AND status IN ('claimed', 'running')",
        (job_id, worker_id, attempt_generation),
    )


def commit_engine_job_result_if_owned(
    *,
    job_id: int,
    worker_id: str,
    attempt_generation: int,
    result: EngineResultInput,
    terminal_status: str,
    last_error: str | None = None,
) -> bool:
    """Write the engine result AND mark the job terminal, atomically, only if the
    worker still owns the job.

    Ownership = the job is still ``claimed``/``running`` for this ``worker_id``
    at this ``attempt_generation`` (the ``attempt_count`` captured at claim time).
    ``worker_id`` alone is insufficient — processes on one host can share it — so
    ``attempt_count`` is the fencing token: a re-claim bumps it, invalidating a
    superseded worker. If ownership is lost, NOTHING is written (no result, no
    status change). Returns whether the commit was applied.

    The result's target scan and engine are derived FROM the job row inside the
    transaction (not trusted from the caller), so a caller cannot write a result
    onto a different scan/engine. A pre-existing result for the engine raises
    :class:`EngineResultConflictError` (rollback).
    """
    if terminal_status not in {"completed", "failed", "skipped"}:
        raise ValueError("terminal status must be completed, failed, or skipped")

    fence_where, fence_params = _terminal_fence(job_id, worker_id, attempt_generation)
    with connect() as connection:
        if not using_postgres():
            connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            f"""
            UPDATE scan_engine_jobs
            SET
                status = ?,
                finished_at = CURRENT_TIMESTAMP,
                lease_expires_at = NULL,
                last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE {fence_where}
            """,
            (terminal_status, last_error, *fence_params),
        )
        if int(cursor.rowcount) <= 0:
            return False  # ownership lost; the transaction commits no changes

        job = get_scan_engine_job_with_connection(connection, job_id)
        if job is None:  # pragma: no cover - the row was just updated
            raise EngineResultConflictError(f"engine job {job_id} vanished mid-commit")
        if result.engine_name != job.engine_name:
            raise ValueError(
                f"result engine {result.engine_name!r} does not match job engine "
                f"{job.engine_name!r}"
            )
        inserted = _insert_engine_result_if_missing(connection, job.scan_job_id, result)
        if inserted is None:
            raise EngineResultConflictError(
                f"a result already exists for engine {job.engine_name!r} on scan "
                f"{job.scan_job_id}; refusing to attribute it to this run"
            )
        return True


def mark_scan_engine_job_terminal_if_owned(
    job_id: int,
    worker_id: str,
    attempt_generation: int,
    status: str,
    *,
    last_error: str | None = None,
) -> bool:
    """Mark a job terminal only if the worker still owns it (same fence as the
    result commit). For terminal transitions that carry no result — a crashed
    adapter, a missing scan, an engine no longer enabled, a non-runnable route.
    A superseded worker changes nothing."""
    if status not in {"completed", "failed", "skipped"}:
        raise ValueError("terminal status must be completed, failed, or skipped")
    fence_where, fence_params = _terminal_fence(job_id, worker_id, attempt_generation)
    with connect() as connection:
        cursor = connection.execute(
            f"""
            UPDATE scan_engine_jobs
            SET
                status = ?,
                finished_at = CURRENT_TIMESTAMP,
                lease_expires_at = NULL,
                last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE {fence_where}
            """,
            (status, last_error, *fence_params),
        )
        return int(cursor.rowcount) > 0


def renew_scan_engine_job_lease(
    job_id: int,
    worker_id: str,
    attempt_generation: int,
    lease_seconds: int,
    *,
    now: int | None = None,
) -> bool:
    """Extend a running job's lease, fenced to the owner + generation.

    Called periodically by a background thread while an engine runs, so a
    legitimately long run (chained engine timeouts) is not mistaken for an
    orphan. Returns False if ownership was lost, letting the renewer stop; the
    eventual result commit is fenced the same way and would be rejected too."""
    current_time = int(time.time()) if now is None else now
    lease_expires_at = current_time + max(1, lease_seconds)
    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE scan_engine_jobs
            SET lease_expires_at = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND worker_id = ? AND attempt_count = ? AND status = 'running'
            """,
            (lease_expires_at, job_id, worker_id, attempt_generation),
        )
        return int(cursor.rowcount) > 0


def list_engine_results(scan_job_id: int) -> list[EngineResultRecord]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                scan_job_id,
                engine_name,
                engine_version,
                signature_version,
                status,
                detected,
                signature,
                severity,
                confidence,
                raw_output,
                error_message,
                duration_ms,
                details_json,
                findings_json,
                created_at
            FROM engine_results
            WHERE scan_job_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (scan_job_id,),
        ).fetchall()
    return [row_to_engine_result_record(row) for row in rows]


def list_engine_results_by_scan_ids(scan_job_ids: list[int]) -> dict[int, list[EngineResultRecord]]:
    if not scan_job_ids:
        return {}

    placeholders = ", ".join("?" for _ in scan_job_ids)
    with connect() as connection:
        rows = connection.execute(
            f"""
            SELECT
                id,
                scan_job_id,
                engine_name,
                engine_version,
                signature_version,
                status,
                detected,
                signature,
                severity,
                confidence,
                raw_output,
                error_message,
                duration_ms,
                details_json,
                findings_json,
                created_at
            FROM engine_results
            WHERE scan_job_id IN ({placeholders})
            ORDER BY scan_job_id ASC, created_at ASC, id ASC
            """,
            tuple(scan_job_ids),
        ).fetchall()

    results_by_scan: dict[int, list[EngineResultRecord]] = {scan_id: [] for scan_id in scan_job_ids}
    for row in rows:
        record = row_to_engine_result_record(row)
        results_by_scan.setdefault(record.scan_job_id, []).append(record)
    return results_by_scan


def create_scan_worker_event(
    *,
    scan_job_id: int,
    event_name: str,
    worker_id: str,
    worker_engine_keys: str,
    engine_name: str | None = None,
    duration_ms: int | None = None,
    details_json: str = "{}",
) -> int:
    with connect() as connection:
        cursor = connection.execute(
            f"""
            INSERT INTO scan_worker_events (
                scan_job_id,
                event_name,
                worker_id,
                worker_engine_keys,
                engine_name,
                duration_ms,
                details_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            {returning_id_clause()}
            """,
            (
                scan_job_id,
                event_name,
                worker_id,
                worker_engine_keys,
                engine_name,
                duration_ms,
                details_json,
            ),
        )
        return require_lastrowid(cursor)


def list_scan_worker_events(scan_job_id: int) -> list[ScanWorkerEventRecord]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                scan_job_id,
                event_name,
                worker_id,
                worker_engine_keys,
                engine_name,
                duration_ms,
                details_json,
                created_at
            FROM scan_worker_events
            WHERE scan_job_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (scan_job_id,),
        ).fetchall()
    return [row_to_scan_worker_event_record(row) for row in rows]


def _insert_engine_jobs(
    connection: Any,
    scan_job_id: int,
    engines: list[EngineInstanceRecord],
) -> int:
    created = 0
    for engine in engines:
        if using_postgres():
            cursor = connection.execute(
                """
                INSERT INTO scan_engine_jobs (
                    scan_job_id,
                    engine_instance_id,
                    engine_key,
                    engine_name
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT (scan_job_id, engine_instance_id) DO NOTHING
                RETURNING id
                """,
                (scan_job_id, engine.id, engine.adapter_key, engine.display_name),
            )
            if cursor.fetchone() is not None:
                created += 1
            continue

        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO scan_engine_jobs (
                scan_job_id,
                engine_instance_id,
                engine_key,
                engine_name
            )
            VALUES (?, ?, ?, ?)
            """,
            (scan_job_id, engine.id, engine.adapter_key, engine.display_name),
        )
        created += int(cursor.rowcount > 0)
    return created


def create_scan_intake(
    *,
    sample: StoredSample,
    engines: list[EngineInstanceRecord],
    case_name: str,
    priority: str,
    note: str,
    source: str,
    archive_mode: str,
    archive_format: str | None,
) -> int:
    """Atomically create the sample, optional archive batch, scan job, and its
    engine jobs in ONE transaction. Either the whole scan is persisted or nothing
    is — no orphaned sample rows or engine-jobless scans stuck queued forever.

    The caller must pass a non-empty ``engines`` list; every engine yields an
    engine job in the same transaction. The stored sample FILE is created before
    this call, so the caller compensates (deletes it) if this raises.
    """
    if not engines:
        raise ValueError("create_scan_intake requires at least one enabled engine")
    with connect() as connection:
        sample_id = _insert_sample(connection, sample)
        batch_id: int | None = None
        relative_path: str | None = None
        scan_role = "standalone"
        if archive_format is not None:
            batch_id = _insert_scan_batch(
                connection,
                source=source,
                original_filename=sample.original_filename,
                archive_mode=archive_mode,
                total_items=1,
                metadata_json=json.dumps(
                    {
                        "container_sha256": sample.sha256,
                        "container_size_bytes": sample.size_bytes,
                        "container_archive_format": archive_format,
                    }
                ),
            )
            relative_path = sample.original_filename
            scan_role = "container"

        scan_id = _insert_scan_job(
            connection,
            sample_id=sample_id,
            case_name=case_name,
            priority=priority,
            note=note,
            source=source,
            batch_id=batch_id,
            relative_path=relative_path,
            scan_role=scan_role,
        )
        _insert_engine_jobs(connection, scan_id, engines)
    return scan_id


def create_scan_engine_jobs(
    scan_job_id: int,
    engines: list[EngineInstanceRecord],
) -> int:
    with connect() as connection:
        return _insert_engine_jobs(connection, scan_job_id, engines)


# Test-only seam: when set, invoked while the parent row lock is held inside
# create_archive_child (after the ownership check, before the child insert), so a
# test can prove the FOR UPDATE / BEGIN IMMEDIATE lock actually serializes a
# concurrent lease steal. Always None in production; one branch, no other cost.
_ARCHIVE_CHILD_LOCK_TEST_HOOK: Callable[[], None] | None = None


def create_archive_child(
    *,
    parent_scan_id: int,
    parent_finalize_worker_id: str,
    parent_finalize_generation: int,
    batch_id: int,
    sample: StoredSample,
    engines: list[EngineInstanceRecord],
    case_name: str,
    priority: str,
    note: str,
    source: str,
    relative_path: str,
    member_ordinal: int,
) -> int | None:
    """Atomically register one archive member as a child scan, idempotent by its
    ordinal within the parent, and fenced to the parent's finalizer.

    The child sample, scan job, and engine jobs are created in ONE transaction,
    keyed by ``(parent_scan_id, member_ordinal)`` — NOT the relative path, which
    can repeat within an archive — and only if the parent is still ``finalizing``
    under the same ``worker_id``/``generation``, so a stale (superseded) finalizer
    cannot mutate the DB. Returns the new child scan id, None if this ordinal was
    already registered, and raises :class:`StaleFinalizerError` if the caller is
    no longer the parent's finalizer.
    """
    try:
        with connect() as connection:
            if not using_postgres():
                connection.execute("BEGIN IMMEDIATE")
            # Lock the parent row (FOR UPDATE on PostgreSQL; SQLite already
            # serializes writers via BEGIN IMMEDIATE) so a concurrent
            # claim_scan_finalization cannot steal the lease between this
            # ownership check and the child insert — the check + insert are one
            # atomic unit.
            parent = connection.execute(
                f"""
                SELECT id FROM scan_jobs
                WHERE id = ? AND status = 'finalizing'
                  AND finalize_worker_id = ? AND finalize_generation = ?
                {"FOR UPDATE" if using_postgres() else ""}
                """,
                (parent_scan_id, parent_finalize_worker_id, parent_finalize_generation),
            ).fetchone()
            if parent is None:
                raise StaleFinalizerError(
                    f"scan {parent_scan_id} is not finalizing under "
                    f"{parent_finalize_worker_id}#{parent_finalize_generation}"
                )
            if _ARCHIVE_CHILD_LOCK_TEST_HOOK is not None:
                # Parent row is locked here; a test uses this to run a concurrent
                # lease steal and prove it blocks until this transaction commits.
                _ARCHIVE_CHILD_LOCK_TEST_HOOK()
            existing = connection.execute(
                """
                SELECT id FROM scan_jobs
                WHERE parent_scan_id = ? AND archive_member_ordinal = ?
                """,
                (parent_scan_id, member_ordinal),
            ).fetchone()
            if existing is not None:
                return None  # idempotent: this member is already registered
            sample_id = _insert_sample(connection, sample)
            child_id = _insert_scan_job(
                connection,
                sample_id=sample_id,
                case_name=case_name,
                priority=priority,
                note=note,
                source=source,
                batch_id=batch_id,
                parent_scan_id=parent_scan_id,
                relative_path=relative_path,
                scan_role="child",
                archive_member_ordinal=member_ordinal,
            )
            _insert_engine_jobs(connection, child_id, engines)
            return child_id
    except IntegrityViolation:
        # The exception propagated OUT of the transaction, so the whole
        # sample+child+jobs insert rolled back (no orphan sample). ONLY a
        # duplicate (parent_scan_id, member_ordinal) is idempotent — any other
        # integrity error (FK, NOT NULL, ...) is a real bug and must surface, so
        # re-check whether this ordinal is now present and re-raise otherwise.
        if _archive_child_exists(parent_scan_id, member_ordinal):
            return None
        raise


# Bound-parameter budget per IN (...) list. SQLite builds historically cap bound
# variables at 999, so chunk well under that; larger inputs are split across
# queries on one connection and the results merged.
SQL_IN_CHUNK_SIZE = 500


def _in_chunks(items: list) -> Iterable[list]:
    for start in range(0, len(items), SQL_IN_CHUNK_SIZE):
        yield items[start:start + SQL_IN_CHUNK_SIZE]


def get_scan_statuses(scan_ids: list[int]) -> dict[int, str]:
    """Bulk map of scan id -> status for the given ids (missing ids omitted).

    Chunked IN queries on one connection instead of one query per id, so
    orphan-sample cleanup can classify thousands of ``child-*`` files by their
    parent's lifecycle without N+1 connections.
    """
    if not scan_ids:
        return {}
    unique_ids = list({int(i) for i in scan_ids})
    statuses: dict[int, str] = {}
    with connect() as connection:
        for chunk in _in_chunks(unique_ids):
            placeholders = ", ".join("?" for _ in chunk)
            rows = connection.execute(
                f"SELECT id, status FROM scan_jobs WHERE id IN ({placeholders})",
                tuple(chunk),
            ).fetchall()
            for row in rows:
                statuses[int(row_value(row, "id"))] = str(row_value(row, "status"))
    return statuses


def filter_referenced_storage_paths(paths: list[str]) -> set[str]:
    """Return the subset of ``paths`` that at least one sample row references.

    Bulk companion to per-file existence checks: cleanup passes every candidate
    file at once and keeps only the unreferenced ones for deletion. Chunked like
    :func:`get_scan_statuses`.
    """
    if not paths:
        return set()
    unique_paths = list({str(p) for p in paths})
    referenced: set[str] = set()
    with connect() as connection:
        for chunk in _in_chunks(unique_paths):
            placeholders = ", ".join("?" for _ in chunk)
            rows = connection.execute(
                f"SELECT storage_path FROM samples WHERE storage_path IN ({placeholders})",
                tuple(chunk),
            ).fetchall()
            referenced.update(str(row_value(row, "storage_path")) for row in rows)
    return referenced


def remove_orphan_child_sample(
    parent_scan_id: int, storage_path: str, remove: Callable[[], None]
) -> bool:
    """Run ``remove()`` (delete the file) only if it is provably orphaned,
    holding the parent scan's row lock while doing so. Returns whether removed.

    A bulk pre-scan alone cannot be trusted: :func:`retry_scan_job` moves a
    terminal parent back to queued, after which a new finalizer re-promotes the
    SAME deterministic path before committing the child row — a stale
    check-then-unlink would delete the new child's file. Every promote happens
    only after a finalization claim committed ``status='finalizing'``, and both
    that claim and the retry must UPDATE this parent row. So with the row locked
    (FOR UPDATE on PostgreSQL; SQLite serializes writers via BEGIN IMMEDIATE):

    * parent missing or terminal => no finalizer is mid-promote, and neither a
      retry nor a new claim can commit until this transaction does;
    * no ``samples`` row references the path => no committed child owns it.

    Only then is the file removed, before the lock is released.
    """
    with connect() as connection:
        if not using_postgres():
            connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            f"""
            SELECT status FROM scan_jobs WHERE id = ?
            {"FOR UPDATE" if using_postgres() else ""}
            """,
            (parent_scan_id,),
        ).fetchone()
        if row is not None and str(row_value(row, "status")) not in TERMINAL_SCAN_STATUSES:
            return False
        referenced = connection.execute(
            "SELECT 1 FROM samples WHERE storage_path = ? LIMIT 1",
            (storage_path,),
        ).fetchone()
        if referenced is not None:
            return False
        remove()
        return True


def _archive_child_exists(parent_scan_id: int, member_ordinal: int) -> bool:
    with connect() as connection:
        row = connection.execute(
            """
            SELECT 1 FROM scan_jobs
            WHERE parent_scan_id = ? AND archive_member_ordinal = ?
            """,
            (parent_scan_id, member_ordinal),
        ).fetchone()
    return row is not None


def list_scan_engine_jobs(scan_job_id: int) -> list[ScanEngineJobRecord]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                scan_job_id,
                engine_instance_id,
                engine_key,
                engine_name,
                status,
                worker_id,
                claimed_at,
                started_at,
                finished_at,
                lease_expires_at,
                attempt_count,
                last_error,
                created_at,
                updated_at
            FROM scan_engine_jobs
            WHERE scan_job_id = ?
            ORDER BY id ASC
            """,
            (scan_job_id,),
        ).fetchall()
    return [row_to_scan_engine_job_record(row) for row in rows]


def get_scan_engine_job(job_id: int) -> ScanEngineJobRecord | None:
    with connect() as connection:
        return get_scan_engine_job_with_connection(connection, job_id)


def claim_next_scan_engine_job(
    engine_keys: set[str],
    worker_id: str,
    *,
    worker_node_id: str | None = None,
    eligible_engine_instance_ids: set[int] | None = None,
    lease_seconds: int = 120,
    now: int | None = None,
    max_attempts: int = 5,
) -> ScanEngineJobRecord | None:
    if not engine_keys:
        return None
    if eligible_engine_instance_ids is not None and not eligible_engine_instance_ids:
        return None

    current_time = int(time.time()) if now is None else now
    lease_expires_at = current_time + max(1, lease_seconds)
    sorted_engine_keys = sorted(engine_keys)
    placeholders = ", ".join("?" for _ in sorted_engine_keys)
    sorted_instance_ids = sorted(eligible_engine_instance_ids or set())
    instance_clause = ""
    if eligible_engine_instance_ids is not None:
        instance_placeholders = ", ".join("?" for _ in sorted_instance_ids)
        instance_clause = (
            f"AND scan_engine_jobs.engine_instance_id IN ({instance_placeholders})"
        )

    with connect() as connection:
        if not using_postgres():
            connection.execute("BEGIN IMMEDIATE")

        if worker_node_id:
            node = connection.execute(
                f"""
                SELECT lifecycle_state, capacity
                FROM worker_nodes
                WHERE node_id = ?
                {"FOR UPDATE" if using_postgres() else ""}
                """,
                (worker_node_id,),
            ).fetchone()
            if node is not None:
                if str(row_value(node, "lifecycle_state")) != "active":
                    return None
                capacity = max(1, int(row_value(node, "capacity")))
                active_row = connection.execute(
                    """
                    SELECT COUNT(*) AS active_count
                    FROM scan_engine_jobs
                    WHERE worker_node_id = ?
                      AND status IN ('claimed', 'running')
                    """,
                    (worker_node_id,),
                ).fetchone()
                active_count = (
                    0 if active_row is None else int(row_value(active_row, "active_count"))
                )
                if active_count >= capacity:
                    return None

        # Only ``pending`` jobs are claimed. An expired ``claimed``/``running``
        # job is NOT reclaimed here — reviving a possibly-still-live owner inside
        # the claim would defeat fencing. recover_running_scan_jobs is the sole
        # path that returns an expired job to ``pending`` (or fails it at the
        # attempt cap), after which it becomes claimable again. The attempt-count
        # guard is belt-and-suspenders against a capped job slipping through.
        row = connection.execute(
            f"""
            SELECT scan_engine_jobs.id
            FROM scan_engine_jobs
            JOIN scan_jobs ON scan_jobs.id = scan_engine_jobs.scan_job_id
            WHERE scan_jobs.status IN ('queued', 'running')
              AND scan_engine_jobs.engine_key IN ({placeholders})
              {instance_clause}
              AND scan_engine_jobs.status = 'pending'
              AND scan_engine_jobs.attempt_count < ?
            ORDER BY scan_jobs.created_at ASC, scan_jobs.id ASC, scan_engine_jobs.id ASC
            LIMIT 1
            {"FOR UPDATE SKIP LOCKED" if using_postgres() else ""}
            """,
            (*sorted_engine_keys, *sorted_instance_ids, max(1, max_attempts)),
        ).fetchone()
        if row is None:
            return None

        job_id = int(row_value(row, "id"))
        connection.execute(
            """
            UPDATE scan_engine_jobs
            SET
                status = 'claimed',
                worker_id = ?,
                worker_node_id = ?,
                claimed_at = CURRENT_TIMESTAMP,
                started_at = NULL,
                finished_at = NULL,
                lease_expires_at = ?,
                attempt_count = attempt_count + 1,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (worker_id, worker_node_id, lease_expires_at, job_id),
        )
        return get_scan_engine_job_with_connection(connection, job_id)


def mark_scan_engine_job_running(
    job_id: int,
    worker_id: str,
    *,
    lease_seconds: int = 120,
    now: int | None = None,
    attempt_generation: int | None = None,
) -> bool:
    """Mark a claimed job running and (re)set its lease.

    When ``attempt_generation`` is given, the update is fenced to the owning
    worker at that ``attempt_count`` generation, so a worker that already lost the
    job to a re-claim cannot resurrect its ownership. Returns whether it applied.
    """
    current_time = int(time.time()) if now is None else now
    lease_expires_at = current_time + max(1, lease_seconds)
    fence_sql = ""
    fence_params: tuple[object, ...] = ()
    if attempt_generation is not None:
        fence_sql = " AND worker_id = ? AND attempt_count = ?"
        fence_params = (worker_id, attempt_generation)
    with connect() as connection:
        cursor = connection.execute(
            f"""
            UPDATE scan_engine_jobs
            SET
                status = 'running',
                worker_id = ?,
                started_at = COALESCE(started_at, CURRENT_TIMESTAMP),
                lease_expires_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('claimed', 'running'){fence_sql}
            """,
            (worker_id, lease_expires_at, job_id, *fence_params),
        )
        return int(cursor.rowcount) > 0


def mark_scan_engine_job_terminal(
    job_id: int,
    status: str,
    *,
    last_error: str | None = None,
) -> bool:
    if status not in {"completed", "failed", "skipped"}:
        raise ValueError("scan engine job terminal status must be completed, failed, or skipped")

    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE scan_engine_jobs
            SET
                status = ?,
                finished_at = CURRENT_TIMESTAMP,
                lease_expires_at = NULL,
                last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, last_error, job_id),
        )
        return int(cursor.rowcount) > 0


def skip_pending_scan_engine_job(
    job_id: int,
    *,
    last_error: str | None = None,
) -> bool:
    """Mark a still-unclaimed engine job as skipped.

    Returns False if the job was already claimed, running, or finished, so a
    reaper cannot clobber a worker that just picked the job up. Only jobs still
    in ``pending`` are affected.
    """
    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE scan_engine_jobs
            SET
                status = 'skipped',
                finished_at = CURRENT_TIMESTAMP,
                lease_expires_at = NULL,
                last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'pending'
            """,
            (last_error, job_id),
        )
        return int(cursor.rowcount) > 0


def get_scan_engine_job_with_connection(
    connection: Any,
    job_id: int,
) -> ScanEngineJobRecord | None:
    row = connection.execute(
        """
        SELECT
            id,
            scan_job_id,
            engine_instance_id,
            engine_key,
            engine_name,
            status,
            worker_id,
            claimed_at,
            started_at,
            finished_at,
            lease_expires_at,
            attempt_count,
            last_error,
            created_at,
            updated_at
        FROM scan_engine_jobs
        WHERE id = ?
        """,
        (job_id,),
    ).fetchone()
    if row is None:
        return None
    return row_to_scan_engine_job_record(row)


def build_scan_history_where_clause(
    *,
    source: str | tuple[str, ...] | list[str] | None = None,
    query: str = "",
    status_filter: str = "all",
    verdict_filter: str = "all",
    include_child_scans: bool = True,
) -> tuple[str, list[object]]:
    conditions: list[str] = []
    params: list[object] = []

    if source:
        if isinstance(source, str):
            conditions.append("scan_jobs.source = ?")
            params.append(source)
        else:
            placeholders = ", ".join("?" for _ in source)
            conditions.append(f"scan_jobs.source IN ({placeholders})")
            params.extend(source)

    if not include_child_scans:
        conditions.append("scan_jobs.scan_role != 'child'")

    normalized_query = query.strip().lower()
    if normalized_query:
        like_value = f"%{normalized_query}%"
        conditions.append(
            """
            (
                LOWER(samples.original_filename) LIKE ?
                OR LOWER(scan_jobs.case_name) LIKE ?
                OR LOWER(scan_jobs.note) LIKE ?
                OR LOWER(samples.sha256) LIKE ?
                OR LOWER(samples.sha1) LIKE ?
                OR LOWER(samples.md5) LIKE ?
            )
            """
        )
        params.extend([like_value] * 6)

    if status_filter and status_filter != "all":
        if status_filter == "active":
            conditions.append("scan_jobs.status IN ('queued', 'running', 'finalizing')")
        else:
            conditions.append("scan_jobs.status = ?")
            params.append(status_filter)

    if verdict_filter and verdict_filter != "all":
        conditions.append("scan_jobs.verdict = ?")
        params.append(verdict_filter)

    if not conditions:
        return "", params
    return "WHERE " + " AND ".join(conditions), params


def list_recent_scans(
    limit: int | None = 20,
    offset: int = 0,
    *,
    source: str | tuple[str, ...] | list[str] | None = None,
    include_child_scans: bool = True,
) -> list[ScanRecord]:
    with connect() as connection:
        query = """
            SELECT
                scan_jobs.id,
                scan_jobs.sample_id,
                scan_jobs.case_name,
                scan_jobs.priority,
                scan_jobs.note,
                scan_jobs.source,
                scan_jobs.batch_id,
                scan_jobs.parent_scan_id,
                scan_jobs.relative_path,
                scan_jobs.scan_role,
                scan_jobs.status,
                scan_jobs.verdict,
                scan_jobs.risk_score,
                scan_jobs.created_at,
                scan_jobs.started_at,
                scan_jobs.completed_at,
                scan_jobs.failed_at,
                scan_jobs.attempt_count,
                scan_jobs.last_error,
                samples.original_filename,
                samples.stored_filename,
                samples.storage_path,
                samples.content_type,
                samples.size_bytes,
                samples.md5,
                samples.sha1,
                samples.sha256
            FROM scan_jobs
            JOIN samples ON samples.id = scan_jobs.sample_id
            """
        params: list[object] = []
        where_clause, where_params = build_scan_history_where_clause(
            source=source,
            include_child_scans=include_child_scans,
        )
        if where_clause:
            query += "\n" + where_clause
            params.extend(where_params)
        query += "\nORDER BY scan_jobs.created_at DESC, scan_jobs.id DESC"
        if limit is not None:
            query += "\nLIMIT ?\nOFFSET ?"
            params.extend([limit, max(0, offset)])
        rows = connection.execute(query, tuple(params)).fetchall()
    return [row_to_scan_record(row) for row in rows]


def count_scan_history(
    *,
    source: str | tuple[str, ...] | list[str] | None = None,
    query: str = "",
    status_filter: str = "all",
    verdict_filter: str = "all",
    include_child_scans: bool = True,
) -> int:
    with connect() as connection:
        where_clause, params = build_scan_history_where_clause(
            source=source,
            query=query,
            status_filter=status_filter,
            verdict_filter=verdict_filter,
            include_child_scans=include_child_scans,
        )
        row = connection.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM scan_jobs
            JOIN samples ON samples.id = scan_jobs.sample_id
            {where_clause}
            """,
            tuple(params),
        ).fetchone()
    if row is None:
        return 0
    if isinstance(row, dict):
        return int(row["total"])
    return int(row[0])


def list_scan_history(
    *,
    source: str | tuple[str, ...] | list[str] | None = None,
    query: str = "",
    status_filter: str = "all",
    verdict_filter: str = "all",
    limit: int = 20,
    offset: int = 0,
    include_child_scans: bool = True,
) -> list[ScanRecord]:
    return list_recent_scans(
        limit=max(1, limit),
        offset=max(0, offset),
        source=source,
        include_child_scans=include_child_scans,
    ) if not query.strip() and status_filter == "all" and verdict_filter == "all" else _list_scan_history_filtered(
        source=source,
        query=query,
        status_filter=status_filter,
        verdict_filter=verdict_filter,
        limit=limit,
        offset=offset,
        include_child_scans=include_child_scans,
    )


def _list_scan_history_filtered(
    *,
    source: str | tuple[str, ...] | list[str] | None = None,
    query: str = "",
    status_filter: str = "all",
    verdict_filter: str = "all",
    limit: int = 20,
    offset: int = 0,
    include_child_scans: bool = True,
) -> list[ScanRecord]:
    with connect() as connection:
        where_clause, params = build_scan_history_where_clause(
            source=source,
            query=query,
            status_filter=status_filter,
            verdict_filter=verdict_filter,
            include_child_scans=include_child_scans,
        )
        rows = connection.execute(
            f"""
            SELECT
                scan_jobs.id,
                scan_jobs.sample_id,
                scan_jobs.case_name,
                scan_jobs.priority,
                scan_jobs.note,
                scan_jobs.source,
                scan_jobs.batch_id,
                scan_jobs.parent_scan_id,
                scan_jobs.relative_path,
                scan_jobs.scan_role,
                scan_jobs.status,
                scan_jobs.verdict,
                scan_jobs.risk_score,
                scan_jobs.created_at,
                scan_jobs.started_at,
                scan_jobs.completed_at,
                scan_jobs.failed_at,
                scan_jobs.attempt_count,
                scan_jobs.last_error,
                samples.original_filename,
                samples.stored_filename,
                samples.storage_path,
                samples.content_type,
                samples.size_bytes,
                samples.md5,
                samples.sha1,
                samples.sha256
            FROM scan_jobs
            JOIN samples ON samples.id = scan_jobs.sample_id
            {where_clause}
            ORDER BY scan_jobs.created_at DESC, scan_jobs.id DESC
            LIMIT ?
            OFFSET ?
            """,
            tuple(params + [max(1, limit), max(0, offset)]),
        ).fetchall()
    return [row_to_scan_record(row) for row in rows]


def count_scans_older_than(created_before: str) -> int:
    with connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM scan_jobs WHERE created_at < ?",
            (created_before,),
        ).fetchone()
    if row is None:
        return 0
    if isinstance(row, dict):
        return int(row["total"])
    return int(row[0])


def list_scans_older_than(created_before: str, limit: int = 100) -> list[ScanRecord]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                scan_jobs.id,
                scan_jobs.sample_id,
                scan_jobs.case_name,
                scan_jobs.priority,
                scan_jobs.note,
                scan_jobs.source,
                scan_jobs.batch_id,
                scan_jobs.parent_scan_id,
                scan_jobs.relative_path,
                scan_jobs.scan_role,
                scan_jobs.status,
                scan_jobs.verdict,
                scan_jobs.risk_score,
                scan_jobs.created_at,
                scan_jobs.started_at,
                scan_jobs.completed_at,
                scan_jobs.failed_at,
                scan_jobs.attempt_count,
                scan_jobs.last_error,
                samples.original_filename,
                samples.stored_filename,
                samples.storage_path,
                samples.content_type,
                samples.size_bytes,
                samples.md5,
                samples.sha1,
                samples.sha256
            FROM scan_jobs
            JOIN samples ON samples.id = scan_jobs.sample_id
            WHERE scan_jobs.created_at < ?
            ORDER BY scan_jobs.created_at ASC, scan_jobs.id ASC
            LIMIT ?
            """,
            (created_before, max(1, limit)),
        ).fetchall()
    return [row_to_scan_record(row) for row in rows]


def list_active_scans(limit: int = 20) -> list[ScanRecord]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                scan_jobs.id,
                scan_jobs.sample_id,
                scan_jobs.case_name,
                scan_jobs.priority,
                scan_jobs.note,
                scan_jobs.source,
                scan_jobs.batch_id,
                scan_jobs.parent_scan_id,
                scan_jobs.relative_path,
                scan_jobs.scan_role,
                scan_jobs.status,
                scan_jobs.verdict,
                scan_jobs.risk_score,
                scan_jobs.created_at,
                scan_jobs.started_at,
                scan_jobs.completed_at,
                scan_jobs.failed_at,
                scan_jobs.attempt_count,
                scan_jobs.last_error,
                samples.original_filename,
                samples.stored_filename,
                samples.storage_path,
                samples.content_type,
                samples.size_bytes,
                samples.md5,
                samples.sha1,
                samples.sha256
            FROM scan_jobs
            JOIN samples ON samples.id = scan_jobs.sample_id
            WHERE scan_jobs.status IN ('queued', 'running', 'finalizing')
            ORDER BY scan_jobs.created_at ASC, scan_jobs.id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [row_to_scan_record(row) for row in rows]


def get_scan(scan_id: int) -> ScanRecord | None:
    with connect() as connection:
        row = connection.execute(
            """
            SELECT
                scan_jobs.id,
                scan_jobs.sample_id,
                scan_jobs.case_name,
                scan_jobs.priority,
                scan_jobs.note,
                scan_jobs.source,
                scan_jobs.batch_id,
                scan_jobs.parent_scan_id,
                scan_jobs.relative_path,
                scan_jobs.scan_role,
                scan_jobs.status,
                scan_jobs.verdict,
                scan_jobs.risk_score,
                scan_jobs.created_at,
                scan_jobs.started_at,
                scan_jobs.completed_at,
                scan_jobs.failed_at,
                scan_jobs.attempt_count,
                scan_jobs.last_error,
                samples.original_filename,
                samples.stored_filename,
                samples.storage_path,
                samples.content_type,
                samples.size_bytes,
                samples.md5,
                samples.sha1,
                samples.sha256
            FROM scan_jobs
            JOIN samples ON samples.id = scan_jobs.sample_id
            WHERE scan_jobs.id = ?
            """,
            (scan_id,),
        ).fetchone()

    if row is None:
        return None
    return row_to_scan_record(row)


def mark_scan_running(scan_id: int) -> None:
    with connect() as connection:
        connection.execute(
            """
            UPDATE scan_jobs
            SET
                status = 'running',
                started_at = COALESCE(started_at, CURRENT_TIMESTAMP),
                completed_at = NULL,
                failed_at = NULL,
                last_error = NULL,
                attempt_count = CASE
                    WHEN status = 'queued' THEN attempt_count + 1
                    ELSE attempt_count
                END
            WHERE id = ? AND status IN ('queued', 'running')
            """,
            (scan_id,),
        )


def delete_scan(scan_id: int) -> ScanRecord | None:
    scan = get_scan(scan_id)
    if scan is None:
        return None

    with connect() as connection:
        connection.execute("DELETE FROM samples WHERE id = ?", (scan.sample_id,))

    return scan


def update_scan_assessment(scan_id: int, verdict: str, risk_score: int) -> None:
    with connect() as connection:
        connection.execute(
            """
            UPDATE scan_jobs
            SET verdict = ?, risk_score = ?
            WHERE id = ?
            """,
            (verdict, risk_score, scan_id),
        )


def update_scan_status(scan_id: int, status: str, last_error: str | None = None) -> None:
    with connect() as connection:
        connection.execute(
            """
            UPDATE scan_jobs
            SET
                status = ?,
                last_error = CASE
                    WHEN CAST(? AS TEXT) IS NOT NULL THEN CAST(? AS TEXT)
                    WHEN CAST(? AS TEXT) = 'completed' THEN NULL
                    ELSE last_error
                END,
                started_at = CASE
                    WHEN CAST(? AS TEXT) = 'queued' THEN NULL
                    ELSE started_at
                END,
                completed_at = CASE
                    WHEN CAST(? AS TEXT) IN ('completed', 'failed') THEN CURRENT_TIMESTAMP
                    ELSE NULL
                END,
                failed_at = CASE
                    WHEN CAST(? AS TEXT) = 'failed' THEN CURRENT_TIMESTAMP
                    ELSE NULL
                END
            WHERE id = ?
            """,
            (
                status,
                last_error,
                last_error,
                status,
                status,
                status,
                status,
                scan_id,
            ),
        )


def transition_scan_to_completed(
    scan_id: int, verdict: str, risk_score: int | None
) -> bool:
    """Atomically mark a scan completed, exactly once.

    Only a scan currently in ``queued`` or ``running`` may complete — a scan
    already ``failed`` (or ``completed``) is never silently turned into
    ``completed``. Returns True for the single caller that wins the transition, so
    concurrent finalizers (worker + recovery sweep) do not both run completion
    side effects such as enqueuing archive children.
    """
    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE scan_jobs
            SET
                status = 'completed',
                verdict = ?,
                risk_score = ?,
                last_error = NULL,
                failed_at = NULL,
                completed_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('queued', 'running')
            """,
            (verdict, risk_score, scan_id),
        )
        return int(cursor.rowcount) > 0


def claim_scan_finalization(
    scan_id: int,
    worker_id: str,
    *,
    lease_seconds: int = 120,
    now: int | None = None,
) -> int | None:
    """Claim the right to finalize a scan: queued/running -> finalizing.

    Exactly one worker wins. An expired ``finalizing`` claim (a crashed
    finalizer) may be stolen, which bumps the generation and fences the crashed
    owner out of ``complete_finalizing_scan``. Returns the new finalize
    generation on success, else None.
    """
    current_time = int(time.time()) if now is None else now
    lease_expires_at = current_time + max(1, lease_seconds)
    with connect() as connection:
        if not using_postgres():
            connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """
            UPDATE scan_jobs
            SET
                status = 'finalizing',
                finalize_worker_id = ?,
                finalize_generation = finalize_generation + 1,
                finalize_lease_expires_at = ?
            WHERE id = ?
              AND (
                status IN ('queued', 'running')
                OR (
                    status = 'finalizing'
                    AND (finalize_lease_expires_at IS NULL OR finalize_lease_expires_at <= ?)
                )
              )
            """,
            (worker_id, lease_expires_at, scan_id, current_time),
        )
        if int(cursor.rowcount) <= 0:
            return None
        row = connection.execute(
            "SELECT finalize_generation FROM scan_jobs WHERE id = ?",
            (scan_id,),
        ).fetchone()
        return None if row is None else int(row_value(row, "finalize_generation"))


def renew_scan_finalization(
    scan_id: int,
    worker_id: str,
    generation: int,
    lease_seconds: int,
    *,
    now: int | None = None,
) -> bool:
    """Extend a finalization lease, fenced to the owner + generation."""
    current_time = int(time.time()) if now is None else now
    lease_expires_at = current_time + max(1, lease_seconds)
    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE scan_jobs
            SET finalize_lease_expires_at = ?
            WHERE id = ? AND status = 'finalizing'
              AND finalize_worker_id = ? AND finalize_generation = ?
            """,
            (lease_expires_at, scan_id, worker_id, generation),
        )
        return int(cursor.rowcount) > 0


def complete_finalizing_scan(
    scan_id: int, worker_id: str, generation: int, verdict: str, risk_score: int | None
) -> bool:
    """Complete a scan, fenced to the finalization owner + generation.

    Only the current finalizer (matching worker + generation) completes the
    scan, so a crashed finalizer that was superseded cannot complete it later.
    """
    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE scan_jobs
            SET
                status = 'completed',
                verdict = ?,
                risk_score = ?,
                last_error = NULL,
                failed_at = NULL,
                completed_at = CURRENT_TIMESTAMP,
                finalize_lease_expires_at = NULL
            WHERE id = ? AND status = 'finalizing'
              AND finalize_worker_id = ? AND finalize_generation = ?
            """,
            (verdict, risk_score, scan_id, worker_id, generation),
        )
        return int(cursor.rowcount) > 0


def claim_next_scan_job() -> ScanRecord | None:
    with connect() as connection:
        if not using_postgres():
            connection.execute("BEGIN IMMEDIATE")
        queued_row = connection.execute(
            f"""
            SELECT id
            FROM scan_jobs
            WHERE status = 'queued'
            ORDER BY created_at ASC, id ASC
            LIMIT 1
            {"FOR UPDATE SKIP LOCKED" if using_postgres() else ""}
            """
        ).fetchone()

        if queued_row is None:
            return None

        scan_id = int(row_value(queued_row, "id"))
        connection.execute(
            """
            UPDATE scan_jobs
            SET
                status = 'running',
                started_at = CURRENT_TIMESTAMP,
                completed_at = NULL,
                failed_at = NULL,
                last_error = NULL,
                attempt_count = attempt_count + 1
            WHERE id = ?
            """,
            (scan_id,),
        )
        row = connection.execute(
            """
            SELECT
                scan_jobs.id,
                scan_jobs.sample_id,
                scan_jobs.case_name,
                scan_jobs.priority,
                scan_jobs.note,
                scan_jobs.source,
                scan_jobs.batch_id,
                scan_jobs.parent_scan_id,
                scan_jobs.relative_path,
                scan_jobs.scan_role,
                scan_jobs.status,
                scan_jobs.verdict,
                scan_jobs.risk_score,
                scan_jobs.created_at,
                scan_jobs.started_at,
                scan_jobs.completed_at,
                scan_jobs.failed_at,
                scan_jobs.attempt_count,
                scan_jobs.last_error,
                samples.original_filename,
                samples.stored_filename,
                samples.storage_path,
                samples.content_type,
                samples.size_bytes,
                samples.md5,
                samples.sha1,
                samples.sha256
            FROM scan_jobs
            JOIN samples ON samples.id = scan_jobs.sample_id
            WHERE scan_jobs.id = ?
            """,
            (scan_id,),
        ).fetchone()

        if row is None:
            return None
        return row_to_scan_record(row)


def get_scan_counts(
    source: str | tuple[str, ...] | list[str] | None = None,
    *,
    include_child_scans: bool = True,
) -> dict[str, int]:
    with connect() as connection:
        params: list[object] = []
        conditions: list[str] = []
        if source:
            if isinstance(source, str):
                conditions.append("source = ?")
                params.append(source)
            else:
                placeholders = ", ".join("?" for _ in source)
                conditions.append(f"source IN ({placeholders})")
                params.extend(source)
        if not include_child_scans:
            conditions.append("scan_role != 'child'")
        source_where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query_params = tuple(params)

        total_row = connection.execute(
            f"SELECT COUNT(*) AS total FROM scan_jobs {source_where}",
            query_params,
        ).fetchone()
        active_row = connection.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM scan_jobs
            {source_where}
            {'AND' if source_where else 'WHERE'} status IN ('queued', 'running', 'finalizing')
            """,
            query_params,
        ).fetchone()
        high_risk_row = connection.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM scan_jobs
            {source_where}
            {'AND' if source_where else 'WHERE'} verdict IN ('high', 'critical')
            """,
            query_params,
        ).fetchone()
        queued_row = connection.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM scan_jobs
            {source_where}
            {'AND' if source_where else 'WHERE'} status = 'queued'
            """,
            query_params,
        ).fetchone()
        completed_row = connection.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM scan_jobs
            {source_where}
            {'AND' if source_where else 'WHERE'} status = 'completed'
            """,
            query_params,
        ).fetchone()
        failed_row = connection.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM scan_jobs
            {source_where}
            {'AND' if source_where else 'WHERE'} status = 'failed'
            """,
            query_params,
        ).fetchone()

    return {
        "total": int(total_row["total"] if isinstance(total_row, dict) else total_row[0]),
        "running": int(active_row["total"] if isinstance(active_row, dict) else active_row[0]),
        "high_risk": int(high_risk_row["total"] if isinstance(high_risk_row, dict) else high_risk_row[0]),
        "queued": int(queued_row["total"] if isinstance(queued_row, dict) else queued_row[0]),
        "completed": int(completed_row["total"] if isinstance(completed_row, dict) else completed_row[0]),
        "failed": int(failed_row["total"] if isinstance(failed_row, dict) else failed_row[0]),
    }


def get_queue_metrics() -> dict[str, int]:
    with connect() as connection:
        queued = fetch_count(
            connection,
            "SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued'",
        )
        running = fetch_count(
            connection,
            "SELECT COUNT(*) FROM scan_jobs WHERE status IN ('running', 'finalizing')",
        )
        completed = fetch_count(
            connection,
            "SELECT COUNT(*) FROM scan_jobs WHERE status = 'completed'",
        )
        failed = fetch_count(
            connection,
            "SELECT COUNT(*) FROM scan_jobs WHERE status = 'failed'",
        )
        total = fetch_count(connection, "SELECT COUNT(*) FROM scan_jobs")

    return {
        "queued": queued,
        "running": running,
        "active": queued + running,
        "completed": completed,
        "failed": failed,
        "total": total,
    }


def get_oldest_active_scan_timestamps() -> dict[str, str | None]:
    """``created_at`` of the oldest scan still queued and still running.

    Counts alone cannot distinguish a healthy busy queue from a stalled one: a
    steady depth of 20 is fine, 20 scans that have not moved in an hour is an
    outage. Exposing the oldest entry's age makes that difference alertable.
    """
    with connect() as connection:
        queued = connection.execute(
            "SELECT MIN(created_at) AS oldest FROM scan_jobs WHERE status = 'queued'"
        ).fetchone()
        running = connection.execute(
            """
            SELECT MIN(created_at) AS oldest FROM scan_jobs
            WHERE status IN ('running', 'finalizing')
            """
        ).fetchone()
    oldest_queued = None if queued is None else row_value(queued, "oldest")
    oldest_running = None if running is None else row_value(running, "oldest")
    return {
        "oldest_queued_at": None if oldest_queued is None else str(oldest_queued),
        "oldest_running_at": None if oldest_running is None else str(oldest_running),
    }


def get_scan_queue_position(scan_id: int) -> int | None:
    with connect() as connection:
        row = connection.execute(
            """
            SELECT id, status, created_at
            FROM scan_jobs
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
        if row is None:
            return None

        status = str(row_value(row, "status"))
        if status == "running":
            return 0
        if status != "queued":
            return None

        created_at = row_value(row, "created_at")
        queued_before_row = connection.execute(
            """
            SELECT COUNT(*)
            FROM scan_jobs
            WHERE status = 'queued'
              AND (
                created_at < ?
                OR (created_at = ? AND id < ?)
              )
            """,
            (created_at, created_at, scan_id),
        ).fetchone()
    if queued_before_row is None:
        return 1
    if isinstance(queued_before_row, dict):
        return int(next(iter(queued_before_row.values()))) + 1
    return int(queued_before_row[0]) + 1


def list_engine_result_metrics() -> list[dict[str, object]]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                engine_name,
                COUNT(*) AS total_results,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_results,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_results,
                SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END) AS skipped_results,
                SUM(CASE WHEN detected THEN 1 ELSE 0 END) AS detections,
                AVG(duration_ms) AS avg_duration_ms,
                MAX(duration_ms) AS max_duration_ms,
                MAX(created_at) AS last_result_at
            FROM engine_results
            GROUP BY engine_name
            ORDER BY engine_name ASC
            """
        ).fetchall()

    return [
        {
            "engine_name": str(row_value(row, "engine_name")),
            "total_results": int(row_value(row, "total_results") or 0),
            "completed_results": int(row_value(row, "completed_results") or 0),
            "failed_results": int(row_value(row, "failed_results") or 0),
            "skipped_results": int(row_value(row, "skipped_results") or 0),
            "detections": int(row_value(row, "detections") or 0),
            "avg_duration_ms": int(float(row_value(row, "avg_duration_ms") or 0)),
            "max_duration_ms": int(row_value(row, "max_duration_ms") or 0),
            "last_result_at": None
            if row_value(row, "last_result_at") is None
            else str(row_value(row, "last_result_at")),
        }
        for row in rows
    ]


def retry_scan_job(scan_id: int) -> bool:
    with connect() as connection:
        row = connection.execute(
            "SELECT status FROM scan_jobs WHERE id = ?",
            (scan_id,),
        ).fetchone()
        if row is None:
            return False

        status = str(row_value(row, "status"))
        # Do not retry an active scan (queued/running/finalizing): a finalizing
        # scan is owned by a live finalizer, and deleting its engine results/jobs
        # under it would corrupt the run.
        if status in ACTIVE_SCAN_STATUSES:
            return False

        connection.execute(
            "DELETE FROM engine_results WHERE scan_job_id = ?",
            (scan_id,),
        )
        connection.execute(
            "DELETE FROM scan_engine_jobs WHERE scan_job_id = ?",
            (scan_id,),
        )
        connection.execute(
            "DELETE FROM scan_worker_events WHERE scan_job_id = ?",
            (scan_id,),
        )
        connection.execute(
            """
            UPDATE scan_jobs
            SET
                status = 'queued',
                verdict = 'pending',
                risk_score = NULL,
                started_at = NULL,
                completed_at = NULL,
                failed_at = NULL,
                last_error = NULL
            WHERE id = ?
            """,
            (scan_id,),
        )
    return True


def recover_running_scan_jobs(
    *,
    now: int | None = None,
    max_attempts: int = 5,
) -> int:
    """Recover engine jobs orphaned by a dead/restarted worker.

    A job left ``claimed``/``running`` with an EXPIRED lease has no live owner
    (a live worker renews its lease). ``claim_next_scan_engine_job`` only reclaims
    such a job for engine keys a worker advertises, so an expired job whose
    engine no worker covers would otherwise sit forever and its scan would never
    finalize. This resets those jobs so progress can resume:

    - ``attempt_count >= max_attempts`` -> ``failed`` (poison-job cap, so a job
      that keeps killing its worker cannot retry forever);
    - otherwise -> ``pending`` (re-claimable, or reap-able if uncovered).

    Jobs with a still-valid lease (live work) are never touched. Returns the
    number of jobs recovered.
    """
    current_time = int(time.time()) if now is None else now
    with connect() as connection:
        if not using_postgres():
            connection.execute("BEGIN IMMEDIATE")

        poisoned = connection.execute(
            """
            UPDATE scan_engine_jobs
            SET
                status = 'failed',
                finished_at = CURRENT_TIMESTAMP,
                lease_expires_at = NULL,
                last_error = 'Recovered as failed: exceeded max attempts after lease expiry.',
                updated_at = CURRENT_TIMESTAMP
            WHERE status IN ('claimed', 'running')
              AND lease_expires_at IS NOT NULL
              AND lease_expires_at <= ?
              AND attempt_count >= ?
            """,
            (current_time, max(1, max_attempts)),
        )
        reset = connection.execute(
            """
            UPDATE scan_engine_jobs
            SET
                status = 'pending',
                worker_id = NULL,
                worker_node_id = NULL,
                claimed_at = NULL,
                started_at = NULL,
                lease_expires_at = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE status IN ('claimed', 'running')
              AND lease_expires_at IS NOT NULL
              AND lease_expires_at <= ?
              AND attempt_count < ?
            """,
            (current_time, max(1, max_attempts)),
        )
        return max(0, int(poisoned.rowcount)) + max(0, int(reset.rowcount))


def row_to_scan_record(row: sqlite3.Row) -> ScanRecord:
    return ScanRecord(
        id=int(row_value(row, "id")),
        sample_id=int(row_value(row, "sample_id")),
        case_name=str(row_value(row, "case_name")),
        priority=str(row_value(row, "priority")),
        note=str(row_value(row, "note")),
        source=str(row_value(row, "source")),
        batch_id=None
        if row_value(row, "batch_id") is None
        else int(row_value(row, "batch_id")),
        parent_scan_id=None
        if row_value(row, "parent_scan_id") is None
        else int(row_value(row, "parent_scan_id")),
        relative_path=None
        if row_value(row, "relative_path") is None
        else str(row_value(row, "relative_path")),
        scan_role=str(row_value(row, "scan_role") or "standalone"),
        status=str(row_value(row, "status")),
        verdict=str(row_value(row, "verdict")),
        risk_score=None
        if row_value(row, "risk_score") is None
        else int(row_value(row, "risk_score")),
        created_at=str(row_value(row, "created_at")),
        started_at=None
        if row_value(row, "started_at") is None
        else str(row_value(row, "started_at")),
        completed_at=None
        if row_value(row, "completed_at") is None
        else str(row_value(row, "completed_at")),
        failed_at=None
        if row_value(row, "failed_at") is None
        else str(row_value(row, "failed_at")),
        attempt_count=int(row_value(row, "attempt_count")),
        last_error=None
        if row_value(row, "last_error") is None
        else str(row_value(row, "last_error")),
        original_filename=str(row_value(row, "original_filename")),
        stored_filename=str(row_value(row, "stored_filename")),
        storage_path=str(row_value(row, "storage_path")),
        content_type=str(row_value(row, "content_type")),
        size_bytes=int(row_value(row, "size_bytes")),
        md5=str(row_value(row, "md5")),
        sha1=str(row_value(row, "sha1")),
        sha256=str(row_value(row, "sha256")),
    )


def row_to_scan_batch_record(row: sqlite3.Row) -> ScanBatchRecord:
    return ScanBatchRecord(
        id=int(row_value(row, "id")),
        source=str(row_value(row, "source")),
        original_filename=str(row_value(row, "original_filename")),
        archive_mode=str(row_value(row, "archive_mode")),
        status=str(row_value(row, "status")),
        total_items=int(row_value(row, "total_items")),
        queued_items=int(row_value(row, "queued_items")),
        running_items=int(row_value(row, "running_items")),
        completed_items=int(row_value(row, "completed_items")),
        failed_items=int(row_value(row, "failed_items")),
        malicious_items=int(row_value(row, "malicious_items")),
        skipped_items=int(row_value(row, "skipped_items")),
        metadata_json=str(row_value(row, "metadata_json")),
        created_at=str(row_value(row, "created_at")),
        updated_at=str(row_value(row, "updated_at")),
        completed_at=None
        if row_value(row, "completed_at") is None
        else str(row_value(row, "completed_at")),
        last_error=None
        if row_value(row, "last_error") is None
        else str(row_value(row, "last_error")),
    )


def row_to_engine_result_record(row: sqlite3.Row) -> EngineResultRecord:
    return EngineResultRecord(
        id=int(row_value(row, "id")),
        scan_job_id=int(row_value(row, "scan_job_id")),
        engine_name=str(row_value(row, "engine_name")),
        engine_version=None
        if row_value(row, "engine_version") is None
        else str(row_value(row, "engine_version")),
        signature_version=None
        if row_value(row, "signature_version") is None
        else str(row_value(row, "signature_version")),
        status=str(row_value(row, "status")),
        detected=bool(row_value(row, "detected")),
        signature=None
        if row_value(row, "signature") is None
        else str(row_value(row, "signature")),
        severity=str(row_value(row, "severity")),
        confidence=int(row_value(row, "confidence")),
        raw_output=str(row_value(row, "raw_output")),
        error_message=None
        if row_value(row, "error_message") is None
        else str(row_value(row, "error_message")),
        duration_ms=int(row_value(row, "duration_ms")),
        created_at=str(row_value(row, "created_at")),
        details_json=str(row_value(row, "details_json")),
        findings_json=str(row_value(row, "findings_json")),
    )


def row_to_scan_worker_event_record(row: sqlite3.Row) -> ScanWorkerEventRecord:
    return ScanWorkerEventRecord(
        id=int(row_value(row, "id")),
        scan_job_id=int(row_value(row, "scan_job_id")),
        event_name=str(row_value(row, "event_name")),
        worker_id=str(row_value(row, "worker_id")),
        worker_engine_keys=str(row_value(row, "worker_engine_keys")),
        engine_name=None
        if row_value(row, "engine_name") is None
        else str(row_value(row, "engine_name")),
        duration_ms=None
        if row_value(row, "duration_ms") is None
        else int(row_value(row, "duration_ms")),
        details_json=str(row_value(row, "details_json")),
        created_at=str(row_value(row, "created_at")),
    )


def row_to_scan_engine_job_record(row: sqlite3.Row) -> ScanEngineJobRecord:
    return ScanEngineJobRecord(
        id=int(row_value(row, "id")),
        scan_job_id=int(row_value(row, "scan_job_id")),
        engine_instance_id=None
        if row_value(row, "engine_instance_id") is None
        else int(row_value(row, "engine_instance_id")),
        engine_key=str(row_value(row, "engine_key")),
        engine_name=str(row_value(row, "engine_name")),
        status=str(row_value(row, "status")),
        worker_id=None
        if row_value(row, "worker_id") is None
        else str(row_value(row, "worker_id")),
        claimed_at=None
        if row_value(row, "claimed_at") is None
        else str(row_value(row, "claimed_at")),
        started_at=None
        if row_value(row, "started_at") is None
        else str(row_value(row, "started_at")),
        finished_at=None
        if row_value(row, "finished_at") is None
        else str(row_value(row, "finished_at")),
        lease_expires_at=None
        if row_value(row, "lease_expires_at") is None
        else int(row_value(row, "lease_expires_at")),
        attempt_count=int(row_value(row, "attempt_count")),
        last_error=None
        if row_value(row, "last_error") is None
        else str(row_value(row, "last_error")),
        created_at=str(row_value(row, "created_at")),
        updated_at=str(row_value(row, "updated_at")),
    )


def row_to_engine_instance_record(row: sqlite3.Row) -> EngineInstanceRecord:
    return EngineInstanceRecord(
        id=int(row_value(row, "id")),
        adapter_key=str(row_value(row, "adapter_key")),
        display_name=str(row_value(row, "display_name")),
        enabled=bool(int(row_value(row, "enabled"))),
        config_json=str(row_value(row, "config_json")),
        created_at=str(row_value(row, "created_at")),
        updated_at=str(row_value(row, "updated_at")),
    )


def row_to_worker_node_record(row: Any) -> WorkerNodeRecord:
    return WorkerNodeRecord(
        node_id=str(row_value(row, "node_id")),
        display_name=str(row_value(row, "display_name")),
        hostname=str(row_value(row, "hostname")),
        platform=str(row_value(row, "platform")),
        agent_version=str(row_value(row, "agent_version")),
        labels_json=str(row_value(row, "labels_json")),
        capacity=int(row_value(row, "capacity")),
        advertised_engine_keys_json=str(
            row_value(row, "advertised_engine_keys_json")
        ),
        lifecycle_state=str(row_value(row, "lifecycle_state")),
        runtime_state=str(row_value(row, "runtime_state")),
        active_scan_id=(
            None
            if row_value(row, "active_scan_id") is None
            else int(row_value(row, "active_scan_id"))
        ),
        process_id=(
            None
            if row_value(row, "process_id") is None
            else int(row_value(row, "process_id"))
        ),
        last_heartbeat_at=int(row_value(row, "last_heartbeat_at")),
        created_at=str(row_value(row, "created_at")),
        updated_at=str(row_value(row, "updated_at")),
    )


def row_to_worker_agent_credential_record(row: Any) -> WorkerAgentCredentialRecord:
    return WorkerAgentCredentialRecord(
        id=int(row_value(row, "id")),
        node_id=str(row_value(row, "node_id")),
        token_hash=str(row_value(row, "token_hash")),
        token_prefix=str(row_value(row, "token_prefix")),
        created_at=str(row_value(row, "created_at")),
        last_used_at=(
            None
            if row_value(row, "last_used_at") is None
            else int(row_value(row, "last_used_at"))
        ),
        expires_at=(
            None
            if row_value(row, "expires_at") is None
            else int(row_value(row, "expires_at"))
        ),
        revoked_at=(
            None
            if row_value(row, "revoked_at") is None
            else int(row_value(row, "revoked_at"))
        ),
    )


def row_to_worker_pool_record(row: Any) -> WorkerPoolRecord:
    return WorkerPoolRecord(
        id=int(row_value(row, "id")),
        name=str(row_value(row, "name")),
        selector_json=str(row_value(row, "selector_json")),
        enabled=bool(int(row_value(row, "enabled"))),
        created_at=str(row_value(row, "created_at")),
        updated_at=str(row_value(row, "updated_at")),
    )


def row_to_engine_node_health_record(row: Any) -> EngineNodeHealthRecord:
    return EngineNodeHealthRecord(
        node_id=str(row_value(row, "node_id")),
        engine_instance_id=int(row_value(row, "engine_instance_id")),
        status=str(row_value(row, "status")),
        ok=bool(int(row_value(row, "ok"))),
        health_status=str(row_value(row, "health_status")),
        detail=str(row_value(row, "detail")),
        product_version=None
        if row_value(row, "product_version") is None
        else str(row_value(row, "product_version")),
        engine_version=None
        if row_value(row, "engine_version") is None
        else str(row_value(row, "engine_version")),
        signature_version=None
        if row_value(row, "signature_version") is None
        else str(row_value(row, "signature_version")),
        service_state=None
        if row_value(row, "service_state") is None
        else str(row_value(row, "service_state")),
        storage_readable=None
        if row_value(row, "storage_readable") is None
        else bool(int(row_value(row, "storage_readable"))),
        storage_writable=None
        if row_value(row, "storage_writable") is None
        else bool(int(row_value(row, "storage_writable"))),
        consecutive_failures=int(row_value(row, "consecutive_failures")),
        last_checked_at=None
        if row_value(row, "last_checked_at") is None
        else int(row_value(row, "last_checked_at")),
        last_success_at=None
        if row_value(row, "last_success_at") is None
        else int(row_value(row, "last_success_at")),
        last_scan_success_at=None
        if row_value(row, "last_scan_success_at") is None
        else int(row_value(row, "last_scan_success_at")),
        details_json=str(row_value(row, "details_json")),
        check_worker_id=None
        if row_value(row, "check_worker_id") is None
        else str(row_value(row, "check_worker_id")),
        check_generation=int(row_value(row, "check_generation")),
        check_lease_expires_at=None
        if row_value(row, "check_lease_expires_at") is None
        else int(row_value(row, "check_lease_expires_at")),
        created_at=str(row_value(row, "created_at")),
        updated_at=str(row_value(row, "updated_at")),
    )


def row_to_user_record(row: sqlite3.Row) -> UserRecord:
    return UserRecord(
        id=int(row_value(row, "id")),
        username=str(row_value(row, "username")),
        password_hash=str(row_value(row, "password_hash")),
        role=str(row_value(row, "role")),
        created_at=str(row_value(row, "created_at")),
        updated_at=str(row_value(row, "updated_at")),
        auth_source=str(row_value(row, "auth_source") or "local"),
        external_id=(
            None
            if row_value(row, "external_id") is None
            else str(row_value(row, "external_id"))
        ),
        display_name=(
            None
            if row_value(row, "display_name") is None
            else str(row_value(row, "display_name"))
        ),
        last_login_at=(
            None
            if row_value(row, "last_login_at") is None
            else str(row_value(row, "last_login_at"))
        ),
    )


def row_to_audit_event_record(row: sqlite3.Row) -> AuditEventRecord:
    return AuditEventRecord(
        id=int(row_value(row, "id")),
        created_at=str(row_value(row, "created_at")),
        actor_type=str(row_value(row, "actor_type")),
        actor_id=None if row_value(row, "actor_id") is None else str(row_value(row, "actor_id")),
        actor_name=None
        if row_value(row, "actor_name") is None
        else str(row_value(row, "actor_name")),
        action=str(row_value(row, "action")),
        target_type=str(row_value(row, "target_type")),
        target_id=None
        if row_value(row, "target_id") is None
        else str(row_value(row, "target_id")),
        outcome=str(row_value(row, "outcome")),
        source_ip=None
        if row_value(row, "source_ip") is None
        else str(row_value(row, "source_ip")),
        request_id=str(row_value(row, "request_id")),
        details_json=str(row_value(row, "details_json")),
    )
