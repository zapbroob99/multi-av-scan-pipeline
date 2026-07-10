from pathlib import Path
import os
import sqlite3
import time
from typing import Any, Iterable

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - exercised only when Postgres is configured.
    psycopg = None  # type: ignore[assignment]
    dict_row = None  # type: ignore[assignment]

from app.models import (
    EngineInstanceRecord,
    EngineResultInput,
    EngineResultRecord,
    ScanBatchRecord,
    ScanEngineJobRecord,
    ScanRecord,
    ScanWorkerEventRecord,
    StoredSample,
    UserRecord,
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


if psycopg is None:
    DatabaseOperationalError = (sqlite3.Error,)
else:
    DatabaseOperationalError = (sqlite3.Error, psycopg.Error)


class PostgresConnection:
    def __init__(self, connection: Any):
        self.connection = connection

    def __enter__(self) -> "PostgresConnection":
        self.connection.__enter__()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> object:
        return self.connection.__exit__(exc_type, exc, traceback)

    def execute(self, query: str, params: Iterable[object] | None = None) -> Any:
        return self.connection.execute(postgres_query(query), tuple(params or ()))

    def executescript(self, script: str) -> None:
        for statement in split_sql_script(script):
            self.execute(statement)


def using_postgres() -> bool:
    return bool(DATABASE_URL)


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
                adapter_key TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                config_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
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
        ensure_column(connection, "engine_results", "details_json", "TEXT NOT NULL DEFAULT '{}'")
        ensure_column(connection, "engine_results", "findings_json", "TEXT NOT NULL DEFAULT '[]'")
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
            CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_engine_jobs_scan_engine
            ON scan_engine_jobs (scan_job_id, engine_key)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_engine_jobs_claim
            ON scan_engine_jobs (status, engine_key, lease_expires_at, id)
            """
        )


def init_postgres_db() -> None:
    with connect() as connection:
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

            CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_engine_jobs_scan_engine
            ON scan_engine_jobs (scan_job_id, engine_key);

            CREATE INDEX IF NOT EXISTS idx_scan_engine_jobs_claim
            ON scan_engine_jobs (status, engine_key, lease_expires_at, id);

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS engine_instances (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                adapter_key TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                config_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
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
        ensure_column(connection, "engine_results", "details_json", "TEXT NOT NULL DEFAULT '{}'")
        ensure_column(connection, "engine_results", "findings_json", "TEXT NOT NULL DEFAULT '[]'")
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
            CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_engine_jobs_scan_engine
            ON scan_engine_jobs (scan_job_id, engine_key)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_engine_jobs_claim
            ON scan_engine_jobs (status, engine_key, lease_expires_at, id)
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


def create_user(username: str, password_hash: str, role: str) -> int:
    try:
        with connect() as connection:
            cursor = connection.execute(
                f"""
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                {returning_id_clause()}
                """,
                (username, password_hash, role),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()
        return create_user(username, password_hash, role)
    return require_lastrowid(cursor)


def list_users() -> list[UserRecord]:
    try:
        with connect() as connection:
            rows = connection.execute(
                """
                SELECT id, username, password_hash, role, created_at, updated_at
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
                SELECT id, username, password_hash, role, created_at, updated_at
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
                SELECT id, username, password_hash, role, created_at, updated_at
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


def delete_user(user_id: int) -> None:
    try:
        with connect() as connection:
            connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()


def count_users_by_role(role: str) -> int:
    try:
        with connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM users WHERE role = ?",
                (role,),
            ).fetchone()
    except sqlite3.OperationalError as exc:
        if not is_missing_users_table(exc):
            raise
        init_db()
        return 0
    if row is None:
        return 0
    return int(row[0])


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
                """,
                (adapter_key,),
            ).fetchone()
    if row is None:
        return None
    return row_to_engine_instance_record(row)


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
                WHERE adapter_key = ?
                """,
                (
                    display_name if display_name is not None else instance.display_name,
                    db_bool(enabled if enabled is not None else instance.enabled),
                    config_json if config_json is not None else instance.config_json,
                    adapter_key,
                ),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_engine_instances_table(exc):
            raise
        init_db()
        update_engine_instance(adapter_key, display_name, enabled, config_json)


def delete_engine_instance(adapter_key: str) -> None:
    try:
        with connect() as connection:
            connection.execute(
                "DELETE FROM engine_instances WHERE adapter_key = ?",
                (adapter_key,),
            )
    except sqlite3.OperationalError as exc:
        if not is_missing_engine_instances_table(exc):
            raise
        init_db()
        with connect() as connection:
            connection.execute(
                "DELETE FROM engine_instances WHERE adapter_key = ?",
                (adapter_key,),
            )


def create_sample(sample: StoredSample) -> int:
    with connect() as connection:
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
        running_items = sum(1 for status in statuses if status == "running")
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
                started_at,
                completed_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL,
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
                status,
            ),
        )
        return require_lastrowid(cursor)


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


def create_engine_result_if_missing(scan_job_id: int, result: EngineResultInput) -> int | None:
    with connect() as connection:
        if using_postgres():
            cursor = connection.execute(
                """
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
            if row is None:
                return None
            return int(row_value(row, "id"))

        connection.execute("BEGIN IMMEDIATE")
        existing_row = connection.execute(
            """
            SELECT id
            FROM engine_results
            WHERE scan_job_id = ? AND engine_name = ?
            LIMIT 1
            """,
            (scan_job_id, result.engine_name),
        ).fetchone()
        if existing_row is not None:
            return None

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


def create_scan_engine_jobs(
    scan_job_id: int,
    engines: list[EngineInstanceRecord],
) -> int:
    created = 0
    with connect() as connection:
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
                    ON CONFLICT (scan_job_id, engine_key) DO NOTHING
                    RETURNING id
                    """,
                    (
                        scan_job_id,
                        engine.id,
                        engine.adapter_key,
                        engine.display_name,
                    ),
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
                (
                    scan_job_id,
                    engine.id,
                    engine.adapter_key,
                    engine.display_name,
                ),
            )
            created += int(cursor.rowcount > 0)
    return created


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
    lease_seconds: int = 120,
    now: int | None = None,
) -> ScanEngineJobRecord | None:
    if not engine_keys:
        return None

    current_time = int(time.time()) if now is None else now
    lease_expires_at = current_time + max(1, lease_seconds)
    sorted_engine_keys = sorted(engine_keys)
    placeholders = ", ".join("?" for _ in sorted_engine_keys)
    claimable_statuses = ("pending", "claimed", "running")

    with connect() as connection:
        if not using_postgres():
            connection.execute("BEGIN IMMEDIATE")

        row = connection.execute(
            f"""
            SELECT scan_engine_jobs.id
            FROM scan_engine_jobs
            JOIN scan_jobs ON scan_jobs.id = scan_engine_jobs.scan_job_id
            WHERE scan_jobs.status IN ('queued', 'running')
              AND scan_engine_jobs.engine_key IN ({placeholders})
              AND (
                scan_engine_jobs.status = ?
                OR (
                  scan_engine_jobs.status IN (?, ?)
                  AND scan_engine_jobs.lease_expires_at IS NOT NULL
                  AND scan_engine_jobs.lease_expires_at <= ?
                )
              )
            ORDER BY scan_jobs.created_at ASC, scan_jobs.id ASC, scan_engine_jobs.id ASC
            LIMIT 1
            {"FOR UPDATE SKIP LOCKED" if using_postgres() else ""}
            """,
            (
                *sorted_engine_keys,
                claimable_statuses[0],
                claimable_statuses[1],
                claimable_statuses[2],
                current_time,
            ),
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
                claimed_at = CURRENT_TIMESTAMP,
                started_at = NULL,
                finished_at = NULL,
                lease_expires_at = ?,
                attempt_count = attempt_count + 1,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (worker_id, lease_expires_at, job_id),
        )
        return get_scan_engine_job_with_connection(connection, job_id)


def mark_scan_engine_job_running(
    job_id: int,
    worker_id: str,
    *,
    lease_seconds: int = 120,
    now: int | None = None,
) -> bool:
    current_time = int(time.time()) if now is None else now
    lease_expires_at = current_time + max(1, lease_seconds)
    with connect() as connection:
        cursor = connection.execute(
            """
            UPDATE scan_engine_jobs
            SET
                status = 'running',
                worker_id = ?,
                started_at = COALESCE(started_at, CURRENT_TIMESTAMP),
                lease_expires_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('claimed', 'running')
            """,
            (worker_id, lease_expires_at, job_id),
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
            conditions.append("scan_jobs.status IN ('queued', 'running')")
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
            WHERE scan_jobs.status IN ('queued', 'running')
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
            {'AND' if source_where else 'WHERE'} status IN ('queued', 'running')
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
            "SELECT COUNT(*) FROM scan_jobs WHERE status = 'running'",
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
        if status in {"queued", "running"}:
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


def recover_running_scan_jobs() -> int:
    return 0


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


def row_to_user_record(row: sqlite3.Row) -> UserRecord:
    return UserRecord(
        id=int(row_value(row, "id")),
        username=str(row_value(row, "username")),
        password_hash=str(row_value(row, "password_hash")),
        role=str(row_value(row, "role")),
        created_at=str(row_value(row, "created_at")),
        updated_at=str(row_value(row, "updated_at")),
    )
