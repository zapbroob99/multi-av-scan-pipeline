from __future__ import annotations

import json

from app.database import (
    get_worker_node,
    list_engine_instance_worker_pool_bindings,
    list_engine_instances,
    list_worker_pools,
)
from app.models import EngineInstanceRecord


def parse_worker_pool_selector(raw: str) -> dict[str, str]:
    """Parse a JSON object or comma-separated ``key=value`` selector."""
    normalized = raw.strip()
    if not normalized:
        return {}
    if normalized.startswith("{"):
        try:
            value = json.loads(normalized)
        except json.JSONDecodeError as exc:
            raise ValueError("Worker pool selector must be valid JSON or key=value pairs.") from exc
        if not isinstance(value, dict):
            raise ValueError("Worker pool selector JSON must be an object.")
        selector = {
            str(key).strip(): str(item).strip()
            for key, item in value.items()
            if str(key).strip()
        }
    else:
        selector: dict[str, str] = {}
        for part in normalized.split(","):
            key, separator, value = part.partition("=")
            if not separator or not key.strip() or not value.strip():
                raise ValueError("Worker pool selectors use comma-separated key=value pairs.")
            selector[key.strip()] = value.strip()
    if not selector:
        raise ValueError("Worker pool selector cannot be empty.")
    return selector


def selector_matches(labels: dict[str, str], selector: dict[str, str]) -> bool:
    return all(labels.get(key) == value for key, value in selector.items())


def eligible_engine_instance_ids_for_node(
    node_id: str,
    engine_keys: set[str],
) -> set[int] | None:
    """Return routable instance ids, or ``None`` for a legacy unregistered node.

    Unbound instances retain adapter-key scheduling. Bound instances require an
    enabled pool whose exact-match selector is satisfied by the node labels.
    """
    node = get_worker_node(node_id)
    if node is None:
        return None
    try:
        labels_value = json.loads(node.labels_json)
    except json.JSONDecodeError:
        labels_value = {}
    labels = (
        {str(key): str(value) for key, value in labels_value.items()}
        if isinstance(labels_value, dict)
        else {}
    )
    pools = {pool.id: pool for pool in list_worker_pools()}
    bindings = list_engine_instance_worker_pool_bindings()
    eligible: set[int] = set()
    for instance in list_engine_instances():
        if not instance.enabled or instance.adapter_key not in engine_keys:
            continue
        pool_id = bindings.get(instance.id)
        if pool_id is None:
            eligible.add(instance.id)
            continue
        pool = pools.get(pool_id)
        if pool is None or not pool.enabled:
            continue
        try:
            selector_value = json.loads(pool.selector_json)
        except json.JSONDecodeError:
            continue
        selector = (
            {str(key): str(value) for key, value in selector_value.items()}
            if isinstance(selector_value, dict)
            else {}
        )
        if selector and selector_matches(labels, selector):
            eligible.add(instance.id)
    return eligible


def schedulable_engine_instance_ids(
    worker_status: dict[str, object],
    engines: list[EngineInstanceRecord],
) -> set[int]:
    """Resolve current node coverage for timeout/reaper decisions."""
    pools = {pool.id: pool for pool in list_worker_pools()}
    bindings = list_engine_instance_worker_pool_bindings()
    unbound_engine_keys = {
        str(value) for value in worker_status.get("engine_keys", [])
    }
    raw_nodes = worker_status.get("nodes")
    nodes = raw_nodes if isinstance(raw_nodes, list) else []
    covered: set[int] = set()
    for instance in engines:
        pool_id = bindings.get(instance.id)
        if pool_id is None:
            if instance.adapter_key in unbound_engine_keys:
                covered.add(instance.id)
            continue
        pool = pools.get(pool_id)
        if pool is None or not pool.enabled:
            continue
        try:
            selector_value = json.loads(pool.selector_json)
        except json.JSONDecodeError:
            continue
        if not isinstance(selector_value, dict) or not selector_value:
            continue
        selector = {str(key): str(value) for key, value in selector_value.items()}
        for raw_node in nodes:
            if not isinstance(raw_node, dict) or not bool(raw_node.get("schedulable")):
                continue
            if instance.adapter_key not in {
                str(value) for value in raw_node.get("engine_keys", [])
            }:
                continue
            raw_labels = raw_node.get("labels")
            labels = (
                {str(key): str(value) for key, value in raw_labels.items()}
                if isinstance(raw_labels, dict)
                else {}
            )
            if selector_matches(labels, selector):
                covered.add(instance.id)
                break
    return covered


def eligible_worker_node_ids_for_engine_instance(
    worker_status: dict[str, object],
    instance: EngineInstanceRecord,
) -> set[str]:
    """Return currently schedulable durable nodes for one exact instance."""
    bindings = list_engine_instance_worker_pool_bindings()
    pool_id = bindings.get(instance.id)
    pool = None
    selector: dict[str, str] | None = None
    if pool_id is not None:
        pool = next((item for item in list_worker_pools() if item.id == pool_id), None)
        if pool is None or not pool.enabled:
            return set()
        try:
            raw_selector = json.loads(pool.selector_json)
        except json.JSONDecodeError:
            return set()
        if not isinstance(raw_selector, dict) or not raw_selector:
            return set()
        selector = {str(key): str(value) for key, value in raw_selector.items()}

    raw_nodes = worker_status.get("nodes")
    nodes = raw_nodes if isinstance(raw_nodes, list) else []
    eligible: set[str] = set()
    for raw_node in nodes:
        if not isinstance(raw_node, dict) or not bool(raw_node.get("schedulable")):
            continue
        if instance.adapter_key not in {
            str(value) for value in raw_node.get("engine_keys", [])
        }:
            continue
        if selector is not None:
            raw_labels = raw_node.get("labels")
            labels = (
                {str(key): str(value) for key, value in raw_labels.items()}
                if isinstance(raw_labels, dict)
                else {}
            )
            if not selector_matches(labels, selector):
                continue
        node_id = str(raw_node.get("node_id") or "")
        if node_id:
            eligible.add(node_id)
    return eligible
