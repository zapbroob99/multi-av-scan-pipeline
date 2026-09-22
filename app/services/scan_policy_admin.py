"""Explicit three-field browser policy projection; no deployment secret reads."""
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app import database as db
from app.services import scan_policy
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms


class ScanPolicyBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    api_max_wait_seconds: str = Field(max_length=128)
    api_retry_after_seconds: str = Field(max_length=128)
    upload_max_bytes: str = Field(max_length=128)


class ScanPolicyField(BaseModel):
    key: str
    label: str
    help: str
    unit: str
    minimum: int
    maximum: int
    default: int
    value: int
    override_raw: str
    source: str


class ScanPolicySnapshot(BaseModel):
    fields: list[ScanPolicyField]


def read() -> ScanPolicySnapshot:
    keys = [scan_policy.SETTING_PREFIX + spec.key for spec in scan_policy.SPECS]
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute('''SELECT key, SUBSTR(value, 1, 129) AS value
            FROM app_settings WHERE key IN (?, ?, ?)''', tuple(keys)).fetchall()
    overrides = {row['key']: row['value'] for row in rows}
    fields = []
    for spec in scan_policy.SPECS:
        raw = overrides.get(scan_policy.SETTING_PREFIX + spec.key, '') or ''
        if len(raw) > 128:
            raise HTTPException(409, 'Stored scan policy exceeds the browser field limit. Correct the server setting before editing.')
        source = ('database override' if raw.strip() else
                  f'environment ({spec.env_var})' if scan_policy.env_value(spec.key) else 'default')
        fields.append(ScanPolicyField(key=spec.key, label=spec.label, help=spec.help, unit=spec.unit,
            minimum=spec.minimum, maximum=spec.maximum, default=spec.default,
            value=scan_policy.resolve_raw(spec.key, raw), override_raw=raw.strip(), source=source))
    return ScanPolicySnapshot(fields=fields)


def save(body: ScanPolicyBody) -> dict[str, int | None]:
    resolved = {}
    for key, raw in body.model_dump().items():
        value, error = scan_policy.validate(key, raw)
        if error:
            raise HTTPException(422, error)
        resolved[key] = value
    # Validate all fields first, then commit all three overrides together.
    with db.connect() as connection:
        apply_read_budget(connection)
        if db.using_postgres():
            connection.execute("SELECT set_config('lock_timeout', ?, true)", (f'{write_lock_timeout_ms()}ms',))
        for key, value in resolved.items():
            full_key = scan_policy.SETTING_PREFIX + key
            if value is None:
                connection.execute('DELETE FROM app_settings WHERE key = ?', (full_key,))
            else:
                connection.execute('''INSERT INTO app_settings (key, value, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value, updated_at = CURRENT_TIMESTAMP''', (full_key, str(value)))
    return resolved
