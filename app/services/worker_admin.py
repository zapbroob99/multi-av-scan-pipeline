"""Bounded browser projection of durable workers; no probes or credentials."""
import json
import time

from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget
from app.services.worker_runtime import worker_stale_seconds
from app.services.worker_scheduling import parse_worker_pool_selector

METADATA_LIMIT = 4096


def normalized_pool_form(name: str, selector: str) -> tuple[str, str]:
    clean_name = name.strip()
    if not clean_name or len(clean_name) > 100:
        raise ValueError('Worker pool name must be between 1 and 100 characters.')
    return clean_name, json.dumps(parse_worker_pool_selector(selector), sort_keys=True)


class PoolSummary(BaseModel):
    id: int
    name: str
    selector: str
    enabled: bool
    has_assignments: bool
    metadata_incomplete: bool


class PoolPage(BaseModel):
    items: list[PoolSummary]
    next_after: int | None


def pool_page(*, limit: int, after: int | None) -> PoolPage:
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute('''SELECT p.id, SUBSTR(p.name, 1, 101) AS name,
            SUBSTR(p.selector_json, 1, 4097) AS selector, p.enabled,
            EXISTS (SELECT 1 FROM engine_instance_worker_pools b WHERE b.worker_pool_id = p.id) AS has_assignments
            FROM worker_pools p ''' + ('WHERE p.id > ? ' if after is not None else '') +
            'ORDER BY p.id LIMIT ?', (*((after,) if after is not None else ()), limit + 1)).fetchall()
    items = []
    for row in rows[:limit]:
        incomplete = len(row['name']) > 100 or len(row['selector']) > METADATA_LIMIT
        selector = row['selector']
        try:
            value = json.loads(selector) if not incomplete else None
            if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
                raise ValueError('Invalid selector')
        except (ValueError, TypeError, RecursionError):
            incomplete = True
        items.append(PoolSummary(id=row['id'], name=row['name'], selector='' if incomplete else selector,
            enabled=bool(row['enabled']), has_assignments=bool(row['has_assignments']), metadata_incomplete=incomplete))
    return PoolPage(items=items, next_after=items[-1].id if len(rows) > limit else None)


class WorkerSummary(BaseModel):
    node_id: str
    display_name: str
    hostname: str
    platform: str
    agent_version: str
    capacity: int
    lifecycle_state: str
    runtime_state: str
    active_scan_id: int | None
    last_heartbeat_at: int
    age_seconds: int
    online: bool
    labels: dict[str, str]
    engine_keys: list[str]
    metadata_incomplete: bool


class WorkerPage(BaseModel):
    items: list[WorkerSummary]
    next_after: str | None
    stale_after_seconds: int


def page(*, limit: int, after: str | None) -> WorkerPage:
    now, stale = int(time.time()), worker_stale_seconds()
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute('''SELECT node_id, SUBSTR(display_name, 1, 256) AS display_name,
            SUBSTR(hostname, 1, 256) AS hostname, SUBSTR(platform, 1, 64) AS platform,
            SUBSTR(agent_version, 1, 64) AS agent_version, capacity, lifecycle_state,
            SUBSTR(runtime_state, 1, 128) AS runtime_state, active_scan_id, last_heartbeat_at,
            SUBSTR(labels_json, 1, ?) AS labels_json,
            SUBSTR(advertised_engine_keys_json, 1, ?) AS engines_json
            FROM worker_nodes ''' + ('WHERE node_id > ? ' if after is not None else '') +
            'ORDER BY node_id ASC LIMIT ?',
            (METADATA_LIMIT + 1, METADATA_LIMIT + 1, *((after,) if after is not None else ()), limit + 1)).fetchall()
    items = []
    for row in rows[:limit]:
        labels, engines, incomplete = {}, [], False
        try:
            if len(row['labels_json']) > METADATA_LIMIT or len(row['engines_json']) > METADATA_LIMIT:
                raise ValueError('Oversized metadata')
            labels, engines = json.loads(row['labels_json']), json.loads(row['engines_json'])
            if (not isinstance(labels, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items())
                    or not isinstance(engines, list) or not all(isinstance(k, str) for k in engines)):
                raise ValueError('Invalid metadata')
        except (ValueError, TypeError, RecursionError):
            labels, engines, incomplete = {}, [], True
        age = max(0, now - row['last_heartbeat_at'])
        items.append(WorkerSummary(**{key: row[key] for key in (
            'node_id', 'display_name', 'hostname', 'platform', 'agent_version', 'capacity',
            'lifecycle_state', 'runtime_state', 'active_scan_id', 'last_heartbeat_at')},
            age_seconds=age, online=row['last_heartbeat_at'] > 0 and age <= stale,
            labels=labels, engine_keys=engines, metadata_incomplete=incomplete))
    return WorkerPage(items=items, next_after=items[-1].node_id if len(rows) > limit else None,
                      stale_after_seconds=stale)
