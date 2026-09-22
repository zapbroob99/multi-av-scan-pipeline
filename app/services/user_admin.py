"""Admin-only bounded user metadata and explicit local account creation."""
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app import database as db
from app.services.auth import hash_password
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms


class UserSummary(BaseModel):
    id: int
    management_revision: int
    username: str
    username_truncated: bool
    role: str
    auth_source: str
    display_name: str | None
    last_login_at: str | None
    created_at: str


class UserPage(BaseModel):
    items: list[UserSummary]
    next_after: int | None


class CreateUserBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    username: str = Field(min_length=1, max_length=128)
    role: Literal['admin', 'analyst']
    password: SecretStr = Field(min_length=8, max_length=4096)


class UserCreated(BaseModel):
    user_id: int


class UserFence(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    expected_revision: int = Field(ge=0, le=9007199254740991)


class UpdateUserBody(UserFence):
    role: Literal['admin', 'analyst']
    password: SecretStr | None = Field(default=None, min_length=8, max_length=4096)


# Serialize cross-row last-admin decisions across all browser/legacy writers.
# Separate from the schema initialization advisory lock.
USER_ADMIN_LOCK = 0x4D41535055534552


def manage(actor_id: int, user_id: int, *, expected_revision: int | None = None,
           role: str | None = None, password: str | None = None, delete: bool = False) -> None:
    if actor_id == user_id:
        raise HTTPException(403, 'Use Account to manage your own credentials; self-deletion is not allowed.')
    if not delete and role not in {'admin', 'analyst'}:
        raise HTTPException(422, 'Choose an administrator or analyst role.')
    if password is not None and not 8 <= len(password) <= 4096:
        raise HTTPException(422, 'Passwords must have 8 to 4096 characters.')
    replacement = hash_password(password) if password is not None else None
    with db.connect() as connection:
        if db.using_postgres():
            connection.execute("SELECT set_config('lock_timeout', ?, true)", (f'{write_lock_timeout_ms()}ms',))
            connection.execute('SELECT pg_advisory_xact_lock(?)', (USER_ADMIN_LOCK,))
        else:
            connection.execute('BEGIN IMMEDIATE')
        rows = connection.execute('''SELECT id, role, auth_source, management_revision
            FROM users WHERE id IN (?, ?) ORDER BY id''' + (' FOR UPDATE' if db.using_postgres() else ''),
            (actor_id, user_id)).fetchall()
        users = {row['id']: row for row in rows}
        actor, target = users.get(actor_id), users.get(user_id)
        if actor is None or actor['role'] != 'admin':
            raise HTTPException(403, 'Administrator access changed. Sign in again.')
        if target is None:
            raise HTTPException(404, 'User not found.')
        if expected_revision is not None and target['management_revision'] != expected_revision:
            raise HTTPException(409, 'Account changed. Refresh the user list before another action.')
        if not delete and target['auth_source'] != 'local':
            raise HTTPException(403, 'Directory users are managed by the directory.')
        if target['role'] == 'admin' and (delete or role != 'admin'):
            scope = " AND auth_source = 'local'" if target['auth_source'] == 'local' else ''
            remaining = connection.execute("SELECT id FROM users WHERE role = 'admin' AND id != ?" + scope + ' LIMIT 1', (user_id,)).fetchone()
            if remaining is None:
                raise HTTPException(409, 'At least one local administrator must remain active.' if scope else 'At least one administrator must remain active.')
        if delete:
            # Existing FK cascade removes sessions; directory identities may return
            # on a later LDAP sign-in. This does not disable the directory account.
            connection.execute('DELETE FROM users WHERE id = ?', (user_id,))
        else:
            if replacement is None:
                connection.execute('''UPDATE users SET role = ?, management_revision = management_revision + 1,
                    updated_at = CURRENT_TIMESTAMP WHERE id = ?''', (role, user_id))
            else:
                connection.execute('''UPDATE users SET role = ?, password_hash = ?, management_revision = management_revision + 1,
                    updated_at = CURRENT_TIMESTAMP WHERE id = ?''', (role, replacement, user_id))
                connection.execute('DELETE FROM auth_sessions WHERE user_id = ?', (user_id,))


def page(after: int | None) -> UserPage:
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute('''SELECT id, management_revision, SUBSTR(username, 1, 128) AS username,
            CASE WHEN LENGTH(username) > 128 THEN 1 ELSE 0 END AS username_truncated,
            role, auth_source, SUBSTR(display_name, 1, 128) AS display_name,
            last_login_at, created_at FROM users WHERE id > ? ORDER BY id LIMIT 21''',
            (after or 0,)).fetchall()
    items = [UserSummary(**{**dict(row), 'created_at': str(row['created_at']),
                           'last_login_at': str(row['last_login_at']) if row['last_login_at'] is not None else None}) for row in rows[:20]]
    return UserPage(items=items, next_after=items[-1].id if len(rows) > 20 else None)


def create(body: CreateUserBody) -> UserCreated:
    username = body.username.strip()
    if not username:
        raise HTTPException(422, 'Username is required.')
    # Same hash implementation and database uniqueness constraint as legacy.
    # Do not load existing users' password hashes to check for a duplicate.
    try:
        user_id = db.create_user(username, hash_password(body.password.get_secret_value()), body.role)
    except db.IntegrityViolation:
        raise HTTPException(409, 'Username already exists.') from None
    return UserCreated(user_id=user_id)
