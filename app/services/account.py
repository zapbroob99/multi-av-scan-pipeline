"""Own-account password changes shared by legacy and independent browsers."""
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app import database as db
from app.models import UserRecord
from app.services import auth
from app.services.browser_db_budget import write_lock_timeout_ms


class AccountPayload(BaseModel):
    user_id: int
    username: str
    role: str
    auth_source: str


class PasswordChangeBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    current_password: SecretStr = Field(min_length=1, max_length=4096)
    new_password: SecretStr = Field(min_length=8, max_length=4096)
    confirm_password: SecretStr = Field(min_length=8, max_length=4096)


def change_password(user: UserRecord, current_password: str,
                    new_password: str, confirm_password: str) -> None:
    if user.auth_source != 'local':
        raise HTTPException(403, 'Directory passwords are managed by the directory.')
    if not 1 <= len(current_password) <= 4096 or not 8 <= len(new_password) <= 4096 or not 8 <= len(confirm_password) <= 4096:
        raise HTTPException(422, 'New passwords must have 8 to 4096 characters; current password is required and limited to 4096 characters.')
    if not auth.verify_password(current_password, user.password_hash):
        raise HTTPException(403, 'Current password is incorrect.')
    if new_password != confirm_password:
        raise HTTPException(422, 'New password and confirmation must match.')
    if auth.verify_password(new_password, user.password_hash):
        raise HTTPException(422, 'Choose a different password than your current one.')
    if not db.change_local_user_password(user.id, user.password_hash, auth.hash_password(new_password),
                                         lock_timeout_ms=write_lock_timeout_ms()):
        raise HTTPException(409, 'Account credentials changed. Sign in again before making another change.')
