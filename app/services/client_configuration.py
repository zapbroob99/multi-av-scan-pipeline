"""Bounded, read-only explanation of one client's current default/selected profile.

No engine configuration, secrets, probes, scheduler decisions or scan history.
Worker observations are recorded evidence, never a guarantee of current routing.
"""
import time
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel

from app import database as db
from app.icap.activity import SETTING_PREFIX
from app.services import scan_policy
from app.services.browser_db_budget import apply_read_budget
from app.services.health_read import icap_gateways, ICAP_STALE_SECONDS
from app.services.profile_admin import POLICY_READ_LIMIT, ProfileSummary
from app.services.profile_rules import engine_eligibility, is_rules_policy, parse_rules_policy
from app.services.upload_admission import validated_deployment_http_ceiling_bytes
from app.services.worker_runtime import worker_stale_seconds
from app.services.worker_health import health_interval_seconds
from app.services.configuration_context import ConfigurationContext, policy_context, http_context, PROFILE_CONTEXT, PLACEMENT_CONTEXT
from app.services.content_types import TYPE_FAMILIES


class WorkerObservation(BaseModel):
    node_id: str
    lifecycle: str
    online: bool
    checked_at: int | None
    check: Literal['unknown', 'stale', 'passed', 'failed']


class ConfigurationEngine(BaseModel):
    id: int
    name: str
    eligible: bool
    excluded_reason: str | None
    pool_id: int | None
    pool_name: str | None
    pool_enabled: bool | None
    observations: list[WorkerObservation]
    observations_incomplete: bool


class ConfigurationGateway(BaseModel):
    port: int
    reported_at: int
    stale: bool
    max_bytes: int | None
    wait_seconds: int | None
    fail_closed: bool | None


class HeaderTypeOption(BaseModel):
    key: str
    family: str


class ClientConfiguration(BaseModel):
    client_id: int
    client_name: str
    enabled: bool
    managed: bool
    profile: ProfileSummary | None
    upload_policy_bytes: int
    upload_policy_source: str
    http_body_ceiling_bytes: int | None
    http_configuration_valid: bool
    gateways: list[ConfigurationGateway]
    gateways_incomplete: bool
    engines: list[ConfigurationEngine]
    observed_at: int
    upload_policy_context: ConfigurationContext
    http_context: ConfigurationContext
    profile_context: ConfigurationContext
    placement_context: ConfigurationContext
    header_types: list[HeaderTypeOption]


def read(client_id: int, profile_id: int | None = None) -> ClientConfiguration:
    now = int(time.time())
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        client = connection.execute('''SELECT id, SUBSTR(display_name, 1, 100) AS name,
            SUBSTR(client_key, 1, 128) AS client_key, enabled FROM service_clients WHERE id = ?''', (client_id,)).fetchone()
        if client is None:
            raise HTTPException(404, 'Service client not found.')
        row = connection.execute(f'''SELECT id, SUBSTR(name, 1, 100) AS name, enabled, is_default,
            management_revision, LENGTH(name) > 100 AS incomplete,
            SUBSTR(policy_json, 1, {POLICY_READ_LIMIT}) AS policy_json,
            LENGTH(policy_json) > {POLICY_READ_LIMIT} AS oversized
            FROM scan_profiles WHERE service_client_id = ? AND deleted_at IS NULL AND ''' +
            ('id = ?' if profile_id is not None else 'is_default = ?') + ' ORDER BY id LIMIT 1',
            (client_id, profile_id if profile_id is not None else db.db_bool(True))).fetchone()
        if profile_id is not None and row is None:
            raise HTTPException(404, 'Scan profile not found.')
        profile, engines = None, []
        if row is not None:
            rows = connection.execute('''SELECT e.id, SUBSTR(e.display_name, 1, 128) AS name, e.adapter_key, e.enabled,
                b.worker_pool_id AS pool_id, SUBSTR(p.name, 1, 100) AS pool_name, p.enabled AS pool_enabled
                FROM scan_profile_engines pe JOIN engine_instances e ON e.id = pe.engine_instance_id
                LEFT JOIN engine_instance_worker_pools b ON b.engine_instance_id = e.id
                LEFT JOIN worker_pools p ON p.id = b.worker_pool_id
                WHERE pe.scan_profile_id = ? ORDER BY e.id LIMIT 101''', (row['id'],)).fetchall()
            rules = None
            if not row['oversized']:
                try:
                    if is_rules_policy(row['policy_json']):
                        rules = parse_rules_policy(row['policy_json'])
                except (ValueError, TypeError, RecursionError):
                    pass
            profile = ProfileSummary(id=row['id'], name=row['name'], enabled=row['enabled'], is_default=row['is_default'],
                management_revision=row['management_revision'], engine_ids=[r['id'] for r in rows[:100]],
                incomplete=bool(row['incomplete']) or len(rows) > 100 or (rules is not None and set(rules.engine_ids()) != {r['id'] for r in rows}), rules=rules, rules_invalid=rules is None)
            ids = [engine['id'] for engine in rows[:100]]
            reports = []
            if ids:
                placeholders = ', '.join('?' for _ in ids)
                reports = connection.execute(f'''SELECT h.engine_instance_id,
                    SUBSTR(n.node_id, 1, 128) AS node_id, n.lifecycle_state,
                    n.last_heartbeat_at, h.last_checked_at, h.ok FROM engine_node_health h
                    JOIN worker_nodes n ON n.node_id = h.node_id
                    WHERE h.engine_instance_id IN ({placeholders})
                    ORDER BY h.engine_instance_id, h.node_id LIMIT 201''', tuple(ids)).fetchall()
            for engine in rows[:100]:
                eligible, reason = engine_eligibility(engine['adapter_key'], bool(engine['enabled']))
                engine_reports = [report for report in reports[:200] if report['engine_instance_id'] == engine['id']]
                observations = []
                for report in engine_reports[:20]:
                    checked = report['last_checked_at']
                    state = ('unknown' if checked is None else 'stale' if now - checked > max(300, 2 * health_interval_seconds())
                             else 'passed' if report['ok'] else 'failed')
                    observations.append(WorkerObservation(node_id=report['node_id'], lifecycle=report['lifecycle_state'],
                        online=now - (report['last_heartbeat_at'] or 0) <= worker_stale_seconds(), checked_at=checked, check=state))
                engines.append(ConfigurationEngine(id=engine['id'], name=engine['name'], eligible=eligible,
                    excluded_reason=reason, pool_id=engine['pool_id'], pool_name=engine['pool_name'],
                    pool_enabled=engine['pool_enabled'], observations=observations, observations_incomplete=len(reports) > 200 or len(engine_reports) > 20))
        raw = connection.execute('SELECT SUBSTR(value, 1, 129) AS value FROM app_settings WHERE key = ?',
            (scan_policy.SETTING_PREFIX + 'upload_max_bytes',)).fetchone()
        override = raw['value'] if raw else None
        if override and len(override) > 128:
            raise HTTPException(409, 'Stored upload policy exceeds the display limit.')
        cap = scan_policy.resolve_raw('upload_max_bytes', override)
        source = 'Set in console' if override and override.strip() else 'API process environment' if scan_policy.env_value('upload_max_bytes') else 'Built-in default'
        settings = connection.execute('''SELECT key, SUBSTR(value, 1, 65537) AS value FROM app_settings
            WHERE key LIKE ? ORDER BY key LIMIT 65''', (SETTING_PREFIX + '%',)).fetchall()
        gateways = [ConfigurationGateway(port=int(g.get('port') or 0), reported_at=int(g['at']),
            stale=now - int(g['at']) >= ICAP_STALE_SECONDS, max_bytes=g.get('max_bytes'),
            wait_seconds=g.get('wait_seconds'), fail_closed=g.get('fail_closed') if isinstance(g.get('fail_closed'), bool) else None)
            for g in icap_gateways({r['key']: r['value'] for r in settings[:64]}, now)
            if str(g.get('client_key', '')).lower() == client['client_key'].lower()]
    try:
        ceiling = validated_deployment_http_ceiling_bytes()
        valid = True
    except HTTPException:
        ceiling, valid = None, False
    return ClientConfiguration(client_id=client_id, client_name=client['name'], enabled=client['enabled'],
        managed=client['client_key'] == 'legacy-default', profile=profile,
        upload_policy_bytes=cap, upload_policy_source=source, http_body_ceiling_bytes=ceiling if valid else None,
        http_configuration_valid=valid, gateways=gateways, gateways_incomplete=len(settings) > 64,
        engines=engines, observed_at=now, upload_policy_context=policy_context('upload_max_bytes', override),
        http_context=http_context(valid), profile_context=PROFILE_CONTEXT, placement_context=PLACEMENT_CONTEXT,
        header_types=[HeaderTypeOption(key=key, family=family) for key, family in TYPE_FAMILIES.items()])
