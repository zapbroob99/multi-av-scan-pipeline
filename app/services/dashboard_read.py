"""Read-only manual-scan dashboard. Never hydrate engine output or run adapters."""
from datetime import datetime, timezone
from threading import Lock
import time

from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget


class ScanPreview(BaseModel):
    id: int
    filename: str
    sha256: str
    size_bytes: int
    case_name: str
    status: str
    risk_level: str
    risk_score: int | None
    attempt_count: int
    job_revision: int
    created_at: str
    # Engines that failed or were skipped, recorded when the scan finished.
    # Null for active scans and scans finished before this was recorded.
    unavailable_engines: int | None


class ScanPage(BaseModel):
    items: list[ScanPreview]
    next_before: int | None


class DashboardSummary(BaseModel):
    total: int
    active: int
    high_risk: int
    enabled_engines: int
    generated_at: str
    refresh_after_seconds: int = 30


_summary_lock = Lock()
_summary_cache = None


def summary() -> DashboardSummary:
    # One entry per API process, single-flight. Authentication happens before this
    # shared manual-only aggregate; no user/client-specific data is cached here.
    global _summary_cache
    key = (str(db.DB_PATH), db.DATABASE_URL)
    with _summary_lock:
        if _summary_cache and _summary_cache[0] == key and time.monotonic() < _summary_cache[1]:
            return _summary_cache[2]
        with db.connect() as connection:
            apply_read_budget(connection)
            row = connection.execute("""
                SELECT COUNT(*) AS total,
                    COALESCE(SUM(CASE WHEN status IN ('queued', 'running', 'finalizing') THEN 1 ELSE 0 END), 0) AS active,
                    COALESCE(SUM(CASE WHEN verdict IN ('high', 'critical') THEN 1 ELSE 0 END), 0) AS high_risk
                FROM scan_jobs WHERE source = 'manual' AND scan_role != 'child'
            """).fetchone()
            engines = connection.execute(
                "SELECT COUNT(*) AS total FROM engine_instances WHERE enabled"
            ).fetchone()
        result = DashboardSummary(total=row['total'], active=row['active'], high_risk=row['high_risk'],
            enabled_engines=engines['total'], generated_at=datetime.now(timezone.utc).isoformat())
        _summary_cache = (key, time.monotonic() + 30, result)
        return result


def scan_page(*, limit: int, before: int | None, query: str, status: str, risk: str,
              detection: str = 'all') -> ScanPage:
    conditions = ["j.source = 'manual'", "j.scan_role != 'child'"]
    params: list[object] = []
    if before is not None:
        conditions.append('j.id < ?')
        params.append(before)
    if status == 'active':
        conditions.append("j.status IN ('queued', 'running', 'finalizing')")
    elif status != 'all':
        conditions.append('j.status = ?')
        params.append(status)
    if risk != 'all':
        conditions.append('j.verdict = ?')
        params.append(risk)
    # Legacy dashboard parity ("malicious"/"undetected"), bounded: one indexed
    # probe per candidate row instead of loading every scan and its results.
    # Recorded engine results only; "undetected" is not coverage or a clean verdict.
    detected = ("EXISTS (SELECT 1 FROM engine_results r WHERE r.scan_job_id = j.id "
                "AND r.status = 'completed' AND r.detected)")
    if detection == 'detected':
        conditions.append(detected)
    elif detection == 'undetected':
        conditions.append(f"j.status NOT IN ('queued', 'running', 'finalizing') AND NOT {detected}")
    if query.strip():
        # Literal substring matching: user '%'/'_' must not become wildcards.
        pattern = '%' + query.strip().lower().replace('!', '!!').replace('%', '!%').replace('_', '!_') + '%'
        columns = ('s.original_filename', 's.sha256', 's.sha1', 's.md5', 'j.case_name', 'j.note', 'j.priority')
        conditions.append('(' + ' OR '.join(f"LOWER({column}) LIKE ? ESCAPE '!'" for column in columns) + ')')
        params.extend([pattern] * len(columns))
    params.append(limit + 1)
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute(f"""
            SELECT j.id, SUBSTR(s.original_filename, 1, 512) AS filename,
                s.sha256, s.size_bytes, SUBSTR(j.case_name, 1, 128) AS case_name,
                j.status, j.verdict AS risk_level, j.risk_score, j.attempt_count,
                COALESCE((SELECT MAX(ej.id) FROM scan_engine_jobs ej
                    WHERE ej.scan_job_id = j.id), 0) AS job_revision,
                j.unavailable_engines,
                j.created_at
            FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
            WHERE {' AND '.join(conditions)} ORDER BY j.id DESC LIMIT ?
        """, tuple(params)).fetchall()
    items = [ScanPreview(**{**dict(row), 'created_at': str(row['created_at'])}) for row in rows[:limit]]
    return ScanPage(items=items, next_before=items[-1].id if len(rows) > limit else None)
