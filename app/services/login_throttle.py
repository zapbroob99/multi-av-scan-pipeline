"""Sign-in throttling: slow password guessing against local and directory accounts.

Failures are counted per username and per source address in the database, so
every app process shares the count. Five failures for one username within 15
minutes lock that username for 15 minutes; twenty from one address lock the
address. The check runs before any password or directory check, so a guessing
run cannot also lock the directory account, and the answer is the same whether
or not the username exists. A successful sign-in clears its username's count but
never the address's, so one valid account cannot reset a guessing address.

Usernames are stored only as a SHA-256 (people type passwords into the username
field), and rows older than a day are removed as failures arrive.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any

from app import database as db

WINDOW_SECONDS = 15 * 60
LOCK_SECONDS = 15 * 60
USER_FAILURES = 5
ADDRESS_FAILURES = 20
KEEP_SECONDS = 24 * 3600


def ensure_schema(connection: Any) -> None:
    connection.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
        scope TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        failures INTEGER NOT NULL,
        window_started BIGINT NOT NULL,
        locked_until BIGINT NOT NULL,
        PRIMARY KEY (scope, key_hash)
    )''')


def _key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _keys(username: str, address: str | None) -> list[tuple[str, str, int]]:
    keys = [("user", _key(username.strip().lower()), USER_FAILURES)]
    if address:
        keys.append(("address", _key(address), ADDRESS_FAILURES))
    return keys


def locked_for(username: str, address: str | None, now: int | None = None) -> int:
    """Seconds until this username or address may try again; 0 when it may now."""
    current = int(time.time()) if now is None else now
    keys = _keys(username, address)
    with db.connect() as connection:
        rows = connection.execute(
            f'''SELECT locked_until FROM login_attempts WHERE locked_until > ? AND ({" OR ".join(
                "(scope = ? AND key_hash = ?)" for _ in keys)})''',
            (current, *[part for scope, key, _ in keys for part in (scope, key)])).fetchall()
    return max((int(row["locked_until"]) - current for row in rows), default=0)


def record_failure(username: str, address: str | None, now: int | None = None) -> None:
    current = int(time.time()) if now is None else now
    expired = current - WINDOW_SECONDS
    with db.connect() as connection:
        for scope, key, limit in _keys(username, address):
            connection.execute('''INSERT INTO login_attempts (scope, key_hash, failures, window_started, locked_until)
                VALUES (?, ?, 1, ?, 0)
                ON CONFLICT (scope, key_hash) DO UPDATE SET
                    failures = CASE WHEN login_attempts.window_started <= ? THEN 1 ELSE login_attempts.failures + 1 END,
                    window_started = CASE WHEN login_attempts.window_started <= ? THEN excluded.window_started
                                          ELSE login_attempts.window_started END''',
                               (scope, key, current, expired, expired))
            # The count starts again once a lock is set, so the next lock needs a full new run.
            connection.execute('''UPDATE login_attempts SET locked_until = ?, failures = 0, window_started = ?
                WHERE scope = ? AND key_hash = ? AND failures >= ?''',
                               (current + LOCK_SECONDS, current, scope, key, limit))
        connection.execute('DELETE FROM login_attempts WHERE window_started < ? AND locked_until < ?',
                           (current - KEEP_SECONDS, current))


def record_success(username: str) -> None:
    with db.connect() as connection:
        connection.execute("DELETE FROM login_attempts WHERE scope = 'user' AND key_hash = ?",
                           (_key(username.strip().lower()),))


def message(seconds: int) -> str:
    minutes = max(1, -(-seconds // 60))
    return (f"Too many failed sign-in attempts. Try again in {minutes} minute{'s' if minutes != 1 else ''}. "
            "An administrator can see the attempts in the audit trail.")
