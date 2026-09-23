"""Whether a service client is configured well enough to accept traffic.

Everything here already existed, spread across the client list, the profile
routing editor and the credential page. An operator connecting a new system had
to visit three screens and still could not see the endpoint to point it at. This
answers one question in one place: is this client ready, and what does the other
side need to be told?

It reads configuration only. It cannot prove the integration can reach MASP, that
a credential value is correct, or that an assigned engine is healthy.
"""
from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget
from app.services.engine_registry import adapter_capabilities, engine_allowed_for_source


AUTOMATION_SOURCE = 'api'


class ReadinessCheck(BaseModel):
    key: str
    label: str
    passed: bool
    detail: str


class AssignedEngine(BaseModel):
    id: int
    display_name: str
    adapter_key: str
    enabled: bool
    eligible: bool
    excluded_reason: str | None


class ClientReadiness(BaseModel):
    client_id: int
    client_key: str
    display_name: str
    enabled: bool
    managed: bool
    ready: bool
    checks: list[ReadinessCheck]
    profile_id: int | None
    profile_name: str | None
    engines: list[AssignedEngine]
    eligible_engine_count: int
    active_credential_count: int
    scan_endpoint: str
    status_endpoint: str
    deferred_endpoint: str
    authorization_header: str
    icap_client_key_setting: str
    generated_at: str


def _engine_eligibility(adapter_key: str, enabled: bool) -> tuple[bool, str | None]:
    try:
        capabilities = adapter_capabilities(adapter_key)
    except KeyError:
        return False, 'Adapter is not registered in this deployment.'
    if not enabled:
        return False, 'Engine instance is disabled.'
    if capabilities.consumes_external_quota:
        # Automation never spends a metered external service. This is an
        # adapter-level rule, so the engine can stay assigned for manual use.
        return False, 'Metered reputation adapter; API and ICAP exclude it before job creation.'
    if not (capabilities.supports_file_upload or capabilities.supports_file_hash_scan):
        return False, 'Adapter cannot accept a submitted file.'
    return True, None


def readiness(client_id: int, base_url: str) -> ClientReadiness:
    root = base_url.rstrip('/')
    with db.connect() as connection:
        # One snapshot: a profile edit between these reads would otherwise report
        # a readiness state that never existed.
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        client = connection.execute('''SELECT id, SUBSTR(client_key, 1, 128) AS client_key,
            SUBSTR(display_name, 1, 100) AS display_name, enabled,
            client_key = 'legacy-default' AS managed
            FROM service_clients WHERE id = ?''', (client_id,)).fetchone()
        if client is None:
            raise HTTPException(404, 'Service client not found.')
        profile = connection.execute('''SELECT id, SUBSTR(name, 1, 100) AS name FROM scan_profiles
            WHERE service_client_id = ? AND is_default = ? AND enabled = ? AND deleted_at IS NULL
            ORDER BY id LIMIT 1''', (client_id, db.db_bool(True), db.db_bool(True))).fetchone()
        rows = []
        if profile is not None:
            rows = connection.execute('''SELECT e.id, SUBSTR(e.display_name, 1, 128) AS display_name,
                e.adapter_key, e.enabled FROM scan_profile_engines pe
                JOIN engine_instances e ON e.id = pe.engine_instance_id
                WHERE pe.scan_profile_id = ? ORDER BY e.id LIMIT 101''', (profile['id'],)).fetchall()
        credentials = connection.execute('''SELECT COUNT(*) AS active FROM api_client_credentials
            WHERE service_client_id = ? AND revoked_at IS NULL''', (client_id,)).fetchone()

    engines: list[AssignedEngine] = []
    for row in rows[:100]:
        eligible, reason = _engine_eligibility(str(row['adapter_key']), bool(row['enabled']))
        engines.append(AssignedEngine(id=int(row['id']), display_name=str(row['display_name']),
                                      adapter_key=str(row['adapter_key']), enabled=bool(row['enabled']),
                                      eligible=eligible, excluded_reason=reason))
    eligible_count = sum(1 for engine in engines if engine.eligible)
    active_credentials = int(credentials['active'])
    enabled_client = bool(client['enabled'])

    checks = [
        ReadinessCheck(key='client_enabled', label='Client is enabled', passed=enabled_client,
                       detail='Accepting submissions.' if enabled_client
                       else 'Disabled clients are refused at intake.'),
        ReadinessCheck(key='default_profile', label='Enabled default profile', passed=profile is not None,
                       detail=f"Routing through {profile['name']}." if profile is not None
                       else 'No enabled default profile; intake cannot resolve routing.'),
        ReadinessCheck(key='assigned_engines', label='Profile has assigned engines', passed=bool(engines),
                       detail=f'{len(engines)} engine instance(s) assigned.' if engines
                       else 'Assign at least one engine to the default profile.'),
        ReadinessCheck(key='eligible_engines', label='An assigned engine can run automation work',
                       passed=eligible_count > 0,
                       detail=f'{eligible_count} of {len(engines)} assigned engine(s) are eligible for API and ICAP.'
                       if engines else 'No assigned engine to evaluate.'),
        ReadinessCheck(key='active_credential', label='Active API credential', passed=active_credentials > 0,
                       detail=f'{active_credentials} active credential(s).' if active_credentials
                       else 'Add a credential, or bind an ICAP gateway to this client key instead.'),
    ]
    return ClientReadiness(
        client_id=int(client['id']), client_key=str(client['client_key']),
        display_name=str(client['display_name']), enabled=enabled_client,
        managed=bool(client['managed']),
        ready=all(check.passed for check in checks),
        checks=checks,
        profile_id=None if profile is None else int(profile['id']),
        profile_name=None if profile is None else str(profile['name']),
        engines=engines, eligible_engine_count=eligible_count,
        active_credential_count=active_credentials,
        scan_endpoint=f'{root}/api/v1/scans',
        status_endpoint=f'{root}/api/v1/scans/{{scan_id}}',
        deferred_endpoint=f'{root}/api/v1/deferred-scans',
        # The value only, never a stored token: credentials are write-only.
        authorization_header='Authorization: Bearer <api token>',
        icap_client_key_setting=f'MASP_ICAP_SERVICE_CLIENT_KEY={client["client_key"]}',
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
