"""PostgreSQL budgets for browser read work and management row locks."""
import os

from app import database as db


DEFAULT_READ_TIMEOUT_MS = 5000
DEFAULT_WRITE_LOCK_TIMEOUT_MS = 5000
MIN_TIMEOUT_MS = 100
MAX_TIMEOUT_MS = 60000


def _timeout_ms(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(MIN_TIMEOUT_MS, min(value, MAX_TIMEOUT_MS))


def read_timeout_ms() -> int:
    return _timeout_ms('MASP_UI_READ_TIMEOUT_MS', DEFAULT_READ_TIMEOUT_MS)


def write_lock_timeout_ms() -> int:
    return _timeout_ms('MASP_UI_WRITE_LOCK_TIMEOUT_MS', DEFAULT_WRITE_LOCK_TIMEOUT_MS)


def apply_read_budget(connection) -> None:
    if db.using_postgres():
        connection.execute("SELECT set_config('statement_timeout', ?, true)",
                           (f'{read_timeout_ms()}ms',))
        # Archive child-presence probes are strongly parameter-sensitive. Once
        # psycopg auto-prepares the statement, PostgreSQL's generic plan can
        # misestimate a dominant parent and run one full scan per visible row.
        connection.execute("SELECT set_config('plan_cache_mode', 'force_custom_plan', true)")
