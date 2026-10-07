"""Client-scoped profiles: an ordered rule list each, without engine configuration."""
from typing import Annotated, Literal
import time
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app import database as db
from app.icap.activity import SETTING_PREFIX as ICAP_SETTING_PREFIX
from app.services import scan_policy
from app.services.browser_db_budget import apply_read_budget, write_lock_timeout_ms
from app.services.engine_registry import adapter_definition
from app.services.health_read import ICAP_FORGOTTEN_SECONDS, icap_gateways
from app.services.profile_rules import (
    Rule, RulesPolicy, engine_eligibility, is_rules_policy, parse_rules_policy, rules_policy_json,
)

# A valid rule list serializes to a few KiB at most; anything this large is not one.
POLICY_READ_LIMIT = 65536

SafeId = Annotated[int, Field(ge=1, le=9007199254740991)]
Inconclusive = Literal['block', 'allow']


class ProfileRoutingBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    engine_ids: list[SafeId] = Field(min_length=1, max_length=100)
    expected_engine_ids: list[SafeId] = Field(max_length=100)
    expected_revision: int | None = Field(default=None, ge=0, le=9007199254740991)


class ProfileCreateBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    name: str = Field(min_length=1, max_length=100)
    # The engines of the starting "every file" rule, and what an inconclusive
    # result becomes. Both are explicit: a new profile has no hidden default.
    engine_ids: list[SafeId] = Field(min_length=1, max_length=100)
    inconclusive: Inconclusive


class ProfileCreated(BaseModel):
    profile_id: int


class ProfileFence(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    expected_revision: int = Field(ge=0, le=9007199254740991)


class ProfileUpdateBody(ProfileFence):
    name: str = Field(min_length=1, max_length=100)
    enabled: bool


class ProfileDefaultBody(ProfileFence):
    expected_default_profile_id: SafeId | None


class ProfileRulesBody(ProfileFence):
    rules: RulesPolicy


class ProfileEngineChoice(BaseModel):
    id: int
    display_name: str
    adapter_key: str
    enabled: bool
    # An antivirus or other detection engine; the rest are light checks.
    detection: bool
    # Why API and ICAP files never reach this engine, shown where it is chosen.
    excluded_reason: str | None = None


class ProfileSummary(BaseModel):
    id: int
    name: str
    enabled: bool
    is_default: bool
    engine_ids: list[int]
    incomplete: bool
    management_revision: int
    # None with rules_invalid when the stored rules cannot be read, or the profile
    # predates rules and could not be converted; the editor then starts empty
    # instead of guessing.
    rules: RulesPolicy | None
    rules_invalid: bool


class GatewayLimits(BaseModel):
    """What an ICAP gateway bound to this client decides before any rule runs."""
    port: int
    fail_closed: bool
    # None from a gateway older than these fields; 0 bytes means no limit.
    max_bytes: int | None = None
    wait_seconds: int | None = None


class ClientProfiles(BaseModel):
    client_id: int
    managed: bool
    items: list[ProfileSummary]
    engines: list[ProfileEngineChoice]
    engines_incomplete: bool
    next_after: int | None
    default_profile_id: int | None
    # The server's upload limit (0: none) and the client's gateways: the only
    # settings outside the profile, shown read-only beside the rules.
    upload_cap_bytes: int = 0
    gateways: list[GatewayLimits] = Field(default_factory=list)


def _detection(adapter_key: str) -> bool:
    try:
        return adapter_definition(adapter_key).detection
    except KeyError:
        return False


def engine_choice(row) -> ProfileEngineChoice:
    adapter_key, enabled = str(row['adapter_key']), bool(row['enabled'])
    return ProfileEngineChoice(id=int(row['id']), display_name=str(row['display_name']), adapter_key=adapter_key,
                               enabled=enabled, detection=_detection(adapter_key),
                               excluded_reason=engine_eligibility(adapter_key, enabled)[1])


def check_rule_engines(connection, rules: RulesPolicy) -> None:
    """Every engine a rule names must exist and run for API and ICAP files, and fit its action."""
    ids = rules.engine_ids()
    placeholders = ', '.join('?' for _ in ids)
    rows = {int(row['id']): row for row in connection.execute(
        f'SELECT id, display_name, adapter_key, enabled FROM engine_instances WHERE id IN ({placeholders})',
        tuple(ids)).fetchall()}
    missing = [str(engine) for engine in ids if engine not in rows]
    if missing:
        raise HTTPException(422, f"Engine #{', #'.join(missing)} no longer exists. Refresh and choose again.")
    for engine_id, row in rows.items():
        eligible, reason = engine_eligibility(str(row['adapter_key']), bool(row['enabled']))
        if not eligible:
            raise HTTPException(422, f"{row['display_name']}: {reason}")
    for number, rule in enumerate(rules.rules, start=1):
        detection = [engine for engine in rule.engines if _detection(str(rows[engine]['adapter_key']))]
        if rule.action == 'scan' and not detection:
            raise HTTPException(422, f'Rule {number}: Scan needs at least one antivirus or other detection engine; '
                                     'use Light check for File Type, Hash List or Static Metadata alone.')
        if rule.action == 'light' and detection:
            raise HTTPException(422, f'Rule {number}: a Light check runs only File Type, Hash List or Static Metadata.')


def starting_rules(connection, engine_ids: list[int], inconclusive: str) -> RulesPolicy:
    """A new profile's one rule: every file goes to the chosen engines."""
    ids = sorted(set(engine_ids))
    placeholders = ', '.join('?' for _ in ids)
    keys = [str(row['adapter_key']) for row in connection.execute(
        f'SELECT adapter_key FROM engine_instances WHERE id IN ({placeholders})', tuple(ids)).fetchall()]
    rule = (Rule(action='scan', engines=ids, archive='whole') if any(_detection(key) for key in keys)
            else Rule(action='light', engines=ids))
    rules = RulesPolicy(version=2, rules=[rule], inconclusive=inconclusive)
    check_rule_engines(connection, rules)
    return rules


def page(client_id: int, after: int | None) -> ClientProfiles:
    with db.connect() as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ' if db.using_postgres() else 'BEGIN')
        apply_read_budget(connection)
        client = connection.execute("""SELECT client_key = 'legacy-default' AS managed, SUBSTR(client_key, 1, 128) AS client_key
            FROM service_clients WHERE id = ?""", (client_id,)).fetchone()
        if client is None:
            raise HTTPException(404, 'Service client not found.')
        default = connection.execute('SELECT id FROM scan_profiles WHERE service_client_id = ? AND is_default = ? AND deleted_at IS NULL LIMIT 1',
            (client_id, db.db_bool(True))).fetchone()
        choices = connection.execute('''SELECT id, SUBSTR(display_name, 1, 128) AS display_name,
            SUBSTR(adapter_key, 1, 64) AS adapter_key, enabled FROM engine_instances ORDER BY id LIMIT 101''').fetchall()
        rows = connection.execute(f'''SELECT id, SUBSTR(name, 1, 100) AS name, LENGTH(name) > 100 AS incomplete,
            enabled, is_default, management_revision, SUBSTR(policy_json, 1, {POLICY_READ_LIMIT}) AS policy_json,
            LENGTH(policy_json) > {POLICY_READ_LIMIT} AS policy_oversized
            FROM scan_profiles WHERE service_client_id = ? AND deleted_at IS NULL ''' +
            ('AND id > ? ' if after is not None else '') + 'ORDER BY id LIMIT 21',
            (client_id, *((after,) if after is not None else ()))).fetchall()
        settings = {str(row['key']): str(row['value']) for row in connection.execute(
            'SELECT key, value FROM app_settings WHERE key LIKE ? OR key = ? ORDER BY key LIMIT 65',
            (ICAP_SETTING_PREFIX + '%', scan_policy.SETTING_PREFIX + 'upload_max_bytes')).fetchall()}
        upload_cap = scan_policy.resolve_raw('upload_max_bytes', settings.pop(scan_policy.SETTING_PREFIX + 'upload_max_bytes', None))
        now = time.time()
        gateways = [GatewayLimits(port=int(gateway.get('port') or 0), fail_closed=bool(gateway.get('fail_closed', True)),
                                  max_bytes=gateway.get('max_bytes'), wait_seconds=gateway.get('wait_seconds'))
                    for gateway in icap_gateways(settings, now)
                    if now - int(gateway['at']) < ICAP_FORGOTTEN_SECONDS
                    and str(gateway.get('client_key', '')).lower() == str(client['client_key']).lower()]
        items = []
        for row in rows[:20]:
            assigned = connection.execute('SELECT engine_instance_id FROM scan_profile_engines WHERE scan_profile_id = ? ORDER BY engine_instance_id LIMIT 101', (row['id'],)).fetchall()
            values = dict(row)
            values['incomplete'] = bool(values['incomplete']) or len(assigned) > 100
            raw_policy, oversized = values.pop('policy_json'), bool(values.pop('policy_oversized'))
            try:
                values['rules'] = None if oversized or not is_rules_policy(raw_policy) else parse_rules_policy(raw_policy)
            except (ValueError, TypeError):
                values['rules'] = None
            values['rules_invalid'] = values['rules'] is None and not client['managed']
            items.append(ProfileSummary(**values, engine_ids=[item['engine_instance_id'] for item in assigned[:100]]))
    return ClientProfiles(client_id=client_id, managed=client['managed'], items=items,
        engines=[engine_choice(row) for row in choices[:100]], engines_incomplete=len(choices) > 100,
        next_after=rows[19]['id'] if len(rows) > 20 else None,
        default_profile_id=None if default is None else default['id'],
        upload_cap_bytes=upload_cap, gateways=gateways)


def save(client_id: int, profile_id: int, body: ProfileRoutingBody):
    if len(set(body.engine_ids)) != len(body.engine_ids) or len(set(body.expected_engine_ids)) != len(body.expected_engine_ids):
        raise HTTPException(422, 'Engine IDs must be unique.')
    with db.connect() as connection:
        stored = connection.execute('SELECT policy_json FROM scan_profiles WHERE id = ? AND service_client_id = ?',
                                    (profile_id, client_id)).fetchone()
    if stored is not None and is_rules_policy(stored['policy_json']):
        # A rule profile's engines are the union of its rules' engines.
        raise HTTPException(409, "This profile chooses engines per rule; edit its rules instead.")
    try:
        db.set_scan_profile_engines(profile_id, body.engine_ids, client_id=client_id,
            expected_engine_ids=body.expected_engine_ids, expected_revision=body.expected_revision,
            lock_timeout_ms=write_lock_timeout_ms())
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


def create(client_id: int, body: ProfileCreateBody) -> ProfileCreated:
    name = body.name.strip()
    if not name or len(set(body.engine_ids)) != len(body.engine_ids):
        raise HTTPException(422, 'Supply a nonblank profile name and unique engine IDs.')
    with db.connect() as connection:
        rules = starting_rules(connection, body.engine_ids, body.inconclusive)
    try:
        profile_id = db.create_scan_profile(client_id, name, engine_instance_ids=rules.engine_ids(),
            policy_json=rules_policy_json(rules), managed_guard=True, lock_timeout_ms=write_lock_timeout_ms())
    except db.IntegrityViolation as exc:
        raise HTTPException(409, 'That profile name is already reserved for this client, including deleted profiles.') from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return ProfileCreated(profile_id=profile_id)


def manage(client_id: int, profile_id: int, body: ProfileFence, operation: str) -> None:
    try:
        with db.profile_write_transaction(client_id, write_lock_timeout_ms()) as (connection, client):
            if client['client_key'] == 'legacy-default':
                raise ValueError('Profiles for the compatibility client are deployment-managed.')
            profile = connection.execute('''SELECT id, enabled, is_default, management_revision FROM scan_profiles
                WHERE id = ? AND service_client_id = ? AND deleted_at IS NULL''' +
                (' FOR UPDATE' if db.using_postgres() else ''), (profile_id, client_id)).fetchone()
            if profile is None or profile['management_revision'] != body.expected_revision:
                raise ValueError('Profile is missing or changed. Refresh before continuing.')
            if operation == 'update' and isinstance(body, ProfileUpdateBody):
                name = body.name.strip()
                if not name:
                    raise HTTPException(422, 'Profile name must not be blank.')
                if profile['is_default'] and not body.enabled:
                    raise ValueError('Select another default profile before disabling this one.')
                connection.execute('''UPDATE scan_profiles SET name = ?, enabled = ?,
                    management_revision = management_revision + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?''',
                    (name, db.db_bool(body.enabled), profile_id))
            elif operation == 'default' and isinstance(body, ProfileDefaultBody):
                current = connection.execute('''SELECT id FROM scan_profiles WHERE service_client_id = ?
                    AND is_default = ? AND deleted_at IS NULL''', (client_id, db.db_bool(True))).fetchone()
                if (None if current is None else current['id']) != body.expected_default_profile_id:
                    raise ValueError('Default profile changed. Refresh before continuing.')
                assigned = connection.execute('SELECT 1 FROM scan_profile_engines WHERE scan_profile_id = ? LIMIT 1', (profile_id,)).fetchone()
                if not profile['enabled'] or assigned is None:
                    raise ValueError('The default profile must be enabled and have assigned engines.')
                connection.execute('''UPDATE scan_profiles SET is_default = ?, management_revision = management_revision + 1,
                    updated_at = CURRENT_TIMESTAMP WHERE service_client_id = ? AND is_default = ?''',
                    (db.db_bool(False), client_id, db.db_bool(True)))
                connection.execute('''UPDATE scan_profiles SET is_default = ?, management_revision = management_revision + 1,
                    updated_at = CURRENT_TIMESTAMP WHERE id = ?''', (db.db_bool(True), profile_id))
            elif operation == 'delete':
                if profile['is_default']:
                    raise ValueError('Select another default profile before deleting this one.')
                # Retain the identity and engine rows: deferred submissions have a
                # cascading FK and old reports may still refer to the profile.
                connection.execute('''UPDATE scan_profiles SET deleted_at = ?, enabled = ?,
                    management_revision = management_revision + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?''',
                    (int(time.time()), db.db_bool(False), profile_id))
            else:
                raise ValueError('Unsupported profile operation.')
    except db.IntegrityViolation as exc:
        raise HTTPException(409, 'That profile name is already reserved for this client, including deleted profiles.') from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


def save_rules(client_id: int, profile_id: int, body: ProfileRulesBody) -> None:
    """Replace one profile's rules and its engine set. Accepted scans keep what they were routed with."""
    try:
        with db.profile_write_transaction(client_id, write_lock_timeout_ms()) as (connection, client):
            if client['client_key'] == 'legacy-default':
                raise ValueError('Profiles for the compatibility client are deployment-managed.')
            profile = connection.execute('''SELECT id, management_revision FROM scan_profiles
                WHERE id = ? AND service_client_id = ? AND deleted_at IS NULL''' +
                (' FOR UPDATE' if db.using_postgres() else ''), (profile_id, client_id)).fetchone()
            if profile is None or profile['management_revision'] != body.expected_revision:
                raise ValueError('Profile is missing or changed. Refresh before continuing.')
            check_rule_engines(connection, body.rules)
            connection.execute('''UPDATE scan_profiles SET policy_json = ?,
                management_revision = management_revision + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?''',
                (rules_policy_json(body.rules), profile_id))
            # The profile's engine set is every engine a rule names: routing, readiness
            # and hash lookups read it, and intake narrows it to the matched rule.
            connection.execute('DELETE FROM scan_profile_engines WHERE scan_profile_id = ?', (profile_id,))
            for engine_id in body.rules.engine_ids():
                connection.execute('''INSERT INTO scan_profile_engines (scan_profile_id, engine_instance_id, required)
                    VALUES (?, ?, ?)''', (profile_id, engine_id, db.db_bool(True)))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
