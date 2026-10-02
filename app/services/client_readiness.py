"""Whether a service client is configured well enough to accept traffic.

Everything here already existed, spread across the client list, the profile
routing editor and the credential page. An operator connecting a new system had
to visit three screens and still could not see the endpoint to point it at. This
answers one question in one place: is this client ready, and what does the other
side need to be told?

A client connects in one or more ways -- the REST API with a bearer token, an
ICAP gateway bound to its key, or a manifest worker reading a share on its
behalf -- and each needs different things. Readiness is therefore the shared
routing checks plus at least one connection method that is set up; a client that
only receives manifests needs no API credential.

It reads configuration and recorded activity only. It cannot prove the
integration can reach MASP, that a credential value is correct, or that an
assigned engine is healthy.
"""
from datetime import datetime, timezone
import json
import time
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget
from app.services.engine_registry import adapter_capabilities, engine_allowed_for_source
from app.icap.activity import SETTING_PREFIX as ICAP_SETTING_PREFIX
from app.services.deferred_storage import backend_allowed_for_client
from app.services.health_read import ICAP_FORGOTTEN_SECONDS, ICAP_STALE_SECONDS, age_text, icap_gateways
from app.services.intake_read import MIN_STALE_SECONDS, STALE_POLL_INTERVALS
from app.services.manifest_intake import LAST_CYCLE_SETTING


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


class ConnectionMethod(BaseModel):
    key: Literal['api', 'icap', 'manifest']
    label: str
    in_use: bool
    ready: bool
    summary: str
    checks: list[ReadinessCheck]


class ClientReadiness(BaseModel):
    client_id: int
    client_key: str
    display_name: str
    enabled: bool
    managed: bool
    ready: bool
    checks: list[ReadinessCheck]
    methods: list[ConnectionMethod]
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
        # Newest automation scan per source, on the ledger's (client, id) index.
        last_scans = {source: connection.execute('''SELECT id, created_at FROM scan_jobs
            WHERE service_client_id = ? AND source = ? AND scan_role != 'child' ORDER BY id DESC LIMIT 1''',
            (client_id, source)).fetchone() for source in ('api', 'icap')}
        settings = {str(row['key']): str(row['value']) for row in connection.execute(
            "SELECT key, value FROM app_settings WHERE key = ? OR key LIKE ?",
            (LAST_CYCLE_SETTING, ICAP_SETTING_PREFIX + '%')).fetchall()}

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
    ]
    client_key = str(client['client_key'])
    methods = [
        _api_method(active_credentials, last_scans['api']),
        _icap_method(client_key, settings, last_scans['icap']),
        _manifest_method(client_key, settings.get(LAST_CYCLE_SETTING)),
    ]
    return ClientReadiness(
        client_id=int(client['id']), client_key=str(client['client_key']),
        display_name=str(client['display_name']), enabled=enabled_client,
        managed=bool(client['managed']),
        ready=all(check.passed for check in checks) and any(method.ready for method in methods),
        checks=checks,
        methods=methods,
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


def _last(row) -> str:
    return f" Last scan #{row['id']} at {str(row['created_at'])[:19]}." if row is not None else ''


def _api_method(active_credentials: int, last_scan) -> ConnectionMethod:
    check = ReadinessCheck(key='active_credential', label='Active API credential', passed=active_credentials > 0,
                           detail=f'{active_credentials} active credential(s).' if active_credentials
                           else 'Create a credential on the Credentials tab.')
    in_use = active_credentials > 0 or last_scan is not None
    return ConnectionMethod(key='api', label='REST API', in_use=in_use, ready=check.passed, checks=[check],
                            summary=('Ready for bearer-token submissions.' if check.passed
                                     else 'Not set up: no active credential.') + _last(last_scan))


def _icap_method(client_key: str, settings: dict[str, str], last_scan, now: float | None = None) -> ConnectionMethod:
    current = time.time() if now is None else now
    reporting_gateways = [g for g in icap_gateways({k: v for k, v in settings.items() if k.startswith(ICAP_SETTING_PREFIX)})
                          if current - int(g['at']) < ICAP_FORGOTTEN_SECONDS]
    gateways = [g for g in reporting_gateways if str(g.get('client_key', '')).lower() == client_key.lower()]
    # A gateway reporting under another key is the usual mistake: the setting
    # never reached the icap container, so its scans go to legacy-default.
    others = sorted({f"port {g.get('port')} files scans under {g.get('client_key')}" for g in reporting_gateways
                     if g not in gateways})
    bound = ReadinessCheck(key='icap_gateway', label='An ICAP gateway is bound to this client', passed=bool(gateways),
                           detail=', '.join(f"port {g.get('port')}" for g in gateways) if gateways
                           else f'Set MASP_ICAP_SERVICE_CLIENT_KEY={client_key} on the gateway'
                           + (f" and restart it; the gateway on {'; '.join(others)}." if others else '.'))
    reporting = [g for g in gateways if current - int(g['at']) < ICAP_STALE_SECONDS]
    if reporting:
        alive_detail = 'Reported within the last minute.'
    elif gateways:
        alive_detail = f"Last report {age_text(current - max(int(g['at']) for g in gateways))} ago."
    else:
        alive_detail = 'No gateway report for this client.'
    alive = ReadinessCheck(key='icap_reporting', label='The gateway is running', passed=bool(reporting),
                           detail=alive_detail)
    ready = bound.passed and alive.passed
    if ready:
        summary = 'A gateway answers for this client.'
    elif gateways:
        summary = 'Gateway stopped.'
    else:
        summary = 'Not set up: no gateway uses this client key.'
    return ConnectionMethod(key='icap', label='ICAP gateway', in_use=bool(gateways) or last_scan is not None,
                            ready=ready, checks=[bound, alive], summary=summary + _last(last_scan))


def _manifest_method(client_key: str, raw: str | None, now: float | None = None) -> ConnectionMethod:
    current = time.time() if now is None else now
    try:
        record = json.loads(raw) if raw else None
    except (TypeError, ValueError):
        record = None
    runs_for = str(record.get('client_key') or '') if isinstance(record, dict) else ''
    mine = bool(runs_for) and runs_for.lower() == client_key.lower()
    if mine:
        worker_detail = 'It reports this client.'
    elif runs_for:
        worker_detail = f'It runs for {runs_for}; set MASP_MANIFEST_CLIENT_KEY={client_key} to use this client.'
    else:
        worker_detail = 'No manifest worker has run. Enable the manifest profile.'
    checks = [ReadinessCheck(key='manifest_worker', label='The manifest worker runs for this client', passed=mine,
                             detail=worker_detail)]
    ready = False
    if mine:
        age = max(0, current - int(record.get('at') or 0))
        poll = float(record.get('poll_seconds') or 0)
        running = age <= max(MIN_STALE_SECONDS, STALE_POLL_INTERVALS * poll)
        checks.append(ReadinessCheck(key='manifest_running', label='The worker is reading manifests', passed=running,
                                     detail=f'Last cycle {age_text(age)} ago.' + ('' if running else ' It has stopped or is stuck.')))
        backend = str(record.get('backend_key') or '')
        prefix = str(record.get('root_prefix') or '').strip('/')
        probe = f'{prefix}/manifest.json' if prefix else 'manifest.json'
        allowed = bool(backend) and backend_allowed_for_client(backend, client_key, probe)
        checks.append(ReadinessCheck(key='manifest_grant', label='The client may read the watched share', passed=allowed,
                                     detail=f'Backend {backend or "unset"}, prefix {prefix or "(root)"}.' + (
                                         '' if allowed else ' Grant it on the Storage tab, or every manifest is rejected.')))
        ready = running and allowed
    if ready:
        summary = 'Manifests dropped on the share are accepted.'
    elif mine:
        summary = 'Set up but not working.'
    else:
        summary = 'Not set up.'
    return ConnectionMethod(key='manifest', label='Manifest intake', in_use=mine, ready=ready, checks=checks,
                            summary=summary)
