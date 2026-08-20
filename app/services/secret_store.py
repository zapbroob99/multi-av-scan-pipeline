"""Authenticated encryption for administrator-managed integration secrets.

The encryption key is deliberately kept outside the database.  Operators set
``MASP_SECRET_ENCRYPTION_KEY`` to a Fernet key; engine configuration stores only
versioned ciphertext.  This keeps database dumps from containing usable API
credentials while still allowing an administrator to configure integrations in
the MASP UI.
"""

from __future__ import annotations

import os
from typing import Mapping

from cryptography.fernet import Fernet, InvalidToken


SECRET_KEY_ENV = "MASP_SECRET_ENCRYPTION_KEY"
TOKEN_PREFIX = "fernet:v1:"


class SecretStoreError(RuntimeError):
    """Base error for secret encryption and decryption failures."""


class SecretStoreNotConfiguredError(SecretStoreError):
    """Raised when no valid server-side encryption key is available."""


class SecretDecryptionError(SecretStoreError):
    """Raised when stored ciphertext cannot be authenticated or decrypted."""


def _fernet(environ: Mapping[str, str] | None = None) -> Fernet:
    values = os.environ if environ is None else environ
    raw_key = values.get(SECRET_KEY_ENV, "").strip()
    if not raw_key:
        raise SecretStoreNotConfiguredError(
            f"{SECRET_KEY_ENV} must be configured before secrets can be saved in the UI."
        )
    try:
        return Fernet(raw_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise SecretStoreNotConfiguredError(
            f"{SECRET_KEY_ENV} must be a valid Fernet key."
        ) from exc


def encrypt_secret(value: str, environ: Mapping[str, str] | None = None) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("Secret value cannot be empty.")
    token = _fernet(environ).encrypt(normalized.encode("utf-8")).decode("ascii")
    return f"{TOKEN_PREFIX}{token}"


def decrypt_secret(value: str, environ: Mapping[str, str] | None = None) -> str:
    if not value.startswith(TOKEN_PREFIX):
        raise SecretDecryptionError("Stored secret has an unsupported format.")
    token = value[len(TOKEN_PREFIX) :]
    try:
        return _fernet(environ).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise SecretDecryptionError(
            "Stored secret could not be decrypted with the configured server key."
        ) from exc


def secret_encryption_available(environ: Mapping[str, str] | None = None) -> bool:
    try:
        _fernet(environ)
    except SecretStoreNotConfiguredError:
        return False
    return True
