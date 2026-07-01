from pathlib import Path
import sqlite3
from typing import Any

from app.models import ScanRecord, StoredSample


ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DB_PATH = DATA_DIR / "app.db"


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(DB_PATH))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def require_lastrowid(cursor: sqlite3.Cursor) -> int:
    if cursor.lastrowid is None:
        raise RuntimeError("Database insert did not return a row id.")
    return cursor.lastrowid


def fetch_count(connection: sqlite3.Connection, query: str) -> int:
    row = connection.execute(query).fetchone()
    if row is None:
        return 0
    return int(row[0])


def row_value(row: sqlite3.Row, key: str) -> Any:
    return row[key]


def init_db() -> None:
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

            CREATE TABLE IF NOT EXISTS scan_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id INTEGER NOT NULL,
                case_name TEXT NOT NULL,
                priority TEXT NOT NULL,
                note TEXT NOT NULL,
                status TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                FOREIGN KEY (sample_id) REFERENCES samples (id) ON DELETE CASCADE
            );
            """
        )


def create_sample(sample: StoredSample) -> int:
    with connect() as connection:
        cursor = connection.execute(
            """
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


def create_scan_job(
    sample_id: int,
    case_name: str,
    priority: str,
    note: str,
    status: str = "completed",
    verdict: str = "metadata_only",
    risk_score: int | None = None,
) -> int:
    with connect() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scan_jobs (
                sample_id,
                case_name,
                priority,
                note,
                status,
                verdict,
                risk_score,
                completed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                sample_id,
                case_name,
                priority,
                note,
                status,
                verdict,
                risk_score,
            ),
        )
        return require_lastrowid(cursor)


def list_recent_scans(limit: int = 20) -> list[ScanRecord]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                scan_jobs.id,
                scan_jobs.sample_id,
                scan_jobs.case_name,
                scan_jobs.priority,
                scan_jobs.note,
                scan_jobs.status,
                scan_jobs.verdict,
                scan_jobs.risk_score,
                scan_jobs.created_at,
                scan_jobs.completed_at,
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
            ORDER BY scan_jobs.created_at DESC, scan_jobs.id DESC
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
                scan_jobs.status,
                scan_jobs.verdict,
                scan_jobs.risk_score,
                scan_jobs.created_at,
                scan_jobs.completed_at,
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


def get_scan_counts() -> dict[str, int]:
    with connect() as connection:
        total = fetch_count(connection, "SELECT COUNT(*) FROM scan_jobs")
        running = fetch_count(
            connection,
            "SELECT COUNT(*) FROM scan_jobs WHERE status = 'running'",
        )
        high_risk = fetch_count(
            connection,
            """
            SELECT COUNT(*)
            FROM scan_jobs
            WHERE verdict IN ('high', 'critical')
            """,
        )

    return {
        "total": total,
        "running": running,
        "high_risk": high_risk,
    }


def row_to_scan_record(row: sqlite3.Row) -> ScanRecord:
    return ScanRecord(
        id=int(row_value(row, "id")),
        sample_id=int(row_value(row, "sample_id")),
        case_name=str(row_value(row, "case_name")),
        priority=str(row_value(row, "priority")),
        note=str(row_value(row, "note")),
        status=str(row_value(row, "status")),
        verdict=str(row_value(row, "verdict")),
        risk_score=None
        if row_value(row, "risk_score") is None
        else int(row_value(row, "risk_score")),
        created_at=str(row_value(row, "created_at")),
        completed_at=None
        if row_value(row, "completed_at") is None
        else str(row_value(row, "completed_at")),
        original_filename=str(row_value(row, "original_filename")),
        stored_filename=str(row_value(row, "stored_filename")),
        storage_path=str(row_value(row, "storage_path")),
        content_type=str(row_value(row, "content_type")),
        size_bytes=int(row_value(row, "size_bytes")),
        md5=str(row_value(row, "md5")),
        sha1=str(row_value(row, "sha1")),
        sha256=str(row_value(row, "sha256")),
    )
