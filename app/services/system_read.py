"""Admin aggregates: bounded responses, no engine output or filesystem reads."""
from datetime import datetime, timezone
from threading import Lock
import time
from pydantic import BaseModel
from app import database as db
from app.services.browser_db_budget import apply_read_budget
from app.services.retention import retention_policy_from_env
from app.services.worker_runtime import worker_stale_seconds


class SystemSummary(BaseModel):
    total: int
    queued: int
    running: int
    finalizing: int
    completed: int
    failed: int
    registered_nodes: int
    online_nodes: int
    active_online_nodes: int
    generated_at: str
    retention_days: int
    retention_batch_size: int


class EngineMetric(BaseModel):
    first_result_id: int
    engine_name: str
    name_truncated: bool
    total: int
    completed: int
    failed: int
    skipped: int
    detections: int
    avg_duration_ms: float | None
    max_duration_ms: int | None


class EngineMetricPage(BaseModel):
    items: list[EngineMetric]
    next_after: int | None
    generated_at: str


_summary_lock = Lock()
_summary_cache = None
_metrics_lock = Lock()
_metrics_cache = None


def summary() -> SystemSummary:
    global _summary_cache
    policy = retention_policy_from_env()
    stale = worker_stale_seconds()
    key = (str(db.DB_PATH), db.DATABASE_URL, policy.days, policy.batch_size, stale)
    with _summary_lock:
        if _summary_cache and _summary_cache[0] == key and time.monotonic() < _summary_cache[1]:
            return _summary_cache[2]
        now = int(time.time())
        with db.connect() as connection:
            connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
            apply_read_budget(connection)
            scans = connection.execute('''SELECT COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END), 0) AS queued,
                COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0) AS running,
                COALESCE(SUM(CASE WHEN status = 'finalizing' THEN 1 ELSE 0 END), 0) AS finalizing,
                COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) AS completed,
                COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) AS failed
                FROM scan_jobs''').fetchone()
            nodes = connection.execute('''SELECT COUNT(*) AS registered_nodes,
                COALESCE(SUM(CASE WHEN last_heartbeat_at > 0 AND last_heartbeat_at >= ? THEN 1 ELSE 0 END), 0) AS online_nodes,
                COALESCE(SUM(CASE WHEN last_heartbeat_at > 0 AND last_heartbeat_at >= ? AND lifecycle_state = 'active' THEN 1 ELSE 0 END), 0) AS active_online_nodes
                FROM worker_nodes''', (now - stale, now - stale)).fetchone()
        result = SystemSummary(**dict(scans), **dict(nodes), generated_at=datetime.now(timezone.utc).isoformat(),
            retention_days=policy.days, retention_batch_size=policy.batch_size)
        _summary_cache = (key, time.monotonic() + 30, result)
        return result


def metrics(*, limit: int, after: int | None) -> EngineMetricPage:
    global _metrics_cache
    key = (str(db.DB_PATH), db.DATABASE_URL, limit, after)
    # A single cached page per process bounds memory even for arbitrary cursors.
    with _metrics_lock:
        if _metrics_cache and _metrics_cache[0] == key and time.monotonic() < _metrics_cache[1]:
            return _metrics_cache[2]
        with db.connect() as connection:
            apply_read_budget(connection)
            rows = connection.execute('''SELECT MIN(id) AS first_result_id,
                SUBSTR(engine_name, 1, 512) AS engine_name, LENGTH(engine_name) > 512 AS name_truncated,
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
                SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END) AS skipped,
                SUM(CASE WHEN detected THEN 1 ELSE 0 END) AS detections,
                AVG(duration_ms) AS avg_duration_ms, MAX(duration_ms) AS max_duration_ms
                FROM engine_results GROUP BY engine_name ''' +
                ('HAVING MIN(id) > ? ' if after is not None else '') + 'ORDER BY MIN(id) LIMIT ?',
                (*((after,) if after is not None else ()), limit + 1)).fetchall()
        result = EngineMetricPage(items=[EngineMetric(**dict(row)) for row in rows[:limit]],
            next_after=rows[limit - 1]['first_result_id'] if len(rows) > limit else None,
            generated_at=datetime.now(timezone.utc).isoformat())
        _metrics_cache = (key, time.monotonic() + 30, result)
        return result
