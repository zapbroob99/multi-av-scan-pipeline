from __future__ import annotations

import json
import os
import time

from app.database import (
    claim_due_engine_node_health,
    commit_engine_node_health_if_owned,
    ensure_engine_node_health_rows,
    get_engine_instance_by_id,
)
from app.services.engine_registry import adapter_capabilities, engine_health
from app.services.sample_paths import SAMPLES_DIR
from app.services.worker_capabilities import worker_engine_keys
from app.services.worker_runtime import current_worker_node_id, current_worker_process_id
from app.services.worker_scheduling import eligible_engine_instance_ids_for_node


def health_interval_seconds() -> int:
    try:
        return max(15, int(os.getenv("MASP_WORKER_HEALTH_INTERVAL_SECONDS", "60")))
    except ValueError:
        return 60


def health_lease_seconds() -> int:
    try:
        return max(30, int(os.getenv("MASP_WORKER_HEALTH_LEASE_SECONDS", "1200")))
    except ValueError:
        return 1200


def health_checks_per_tick() -> int:
    try:
        return max(1, int(os.getenv("MASP_WORKER_HEALTH_CHECKS_PER_TICK", "2")))
    except ValueError:
        return 2


def storage_access() -> tuple[bool, bool, str]:
    readable = SAMPLES_DIR.is_dir() and os.access(SAMPLES_DIR, os.R_OK)
    writable = SAMPLES_DIR.is_dir() and os.access(SAMPLES_DIR, os.W_OK)
    if readable and writable:
        detail = f"Sample storage {SAMPLES_DIR} is readable and writable."
    elif readable:
        detail = f"Sample storage {SAMPLES_DIR} is readable but not writable."
    else:
        detail = f"Sample storage {SAMPLES_DIR} is not readable on this worker."
    return readable, writable, detail


def run_due_worker_health_checks(*, now: int | None = None) -> int:
    current_time = int(time.time()) if now is None else now
    node_id = current_worker_node_id()
    worker_id = current_worker_process_id()
    engine_keys = worker_engine_keys()
    eligible_ids = eligible_engine_instance_ids_for_node(node_id, engine_keys)
    if eligible_ids is None or not eligible_ids:
        return 0
    ensure_engine_node_health_rows(node_id, eligible_ids)
    completed = 0
    for _ in range(health_checks_per_tick()):
        claim = claim_due_engine_node_health(
            node_id,
            worker_id,
            eligible_ids,
            interval_seconds=health_interval_seconds(),
            lease_seconds=health_lease_seconds(),
            now=current_time,
        )
        if claim is None:
            break
        instance = get_engine_instance_by_id(claim.engine_instance_id)
        if instance is None or not instance.enabled:
            continue
        try:
            probe = engine_health(instance)
        except Exception as exc:  # adapter failures become health data, not worker failures
            probe = {
                "ok": False,
                "status": "unexpected",
                "detail": f"Health check raised {type(exc).__name__}: {exc}",
            }

        storage_readable: bool | None = None
        storage_writable: bool | None = None
        storage_detail = "Storage access is not required by this adapter."
        if adapter_capabilities(instance.adapter_key).supports_file_upload:
            storage_readable, storage_writable, storage_detail = storage_access()

        ok = bool(probe.get("ok")) and storage_readable is not False
        health_status = str(probe.get("status") or "unknown")
        detail = str(probe.get("detail") or "No health detail was returned.")
        if storage_readable is False:
            health_status = "storage unavailable"
            detail = f"{detail} {storage_detail}"
        details = {
            "adapter_key": instance.adapter_key,
            "engine_name": instance.display_name,
            "probe": probe,
            "storage": {
                "required": adapter_capabilities(instance.adapter_key).supports_file_upload,
                "readable": storage_readable,
                "writable": storage_writable,
                "detail": storage_detail,
            },
        }
        committed = commit_engine_node_health_if_owned(
            node_id=node_id,
            engine_instance_id=instance.id,
            worker_id=worker_id,
            check_generation=claim.check_generation,
            ok=ok,
            health_status=health_status,
            detail=detail,
            product_version=_optional_probe_value(probe, "product_version"),
            engine_version=_optional_probe_value(probe, "engine_version"),
            signature_version=_optional_probe_value(probe, "signature_version"),
            service_state=_optional_probe_value(probe, "service_state"),
            storage_readable=storage_readable,
            storage_writable=storage_writable,
            details_json=json.dumps(details, sort_keys=True, default=str),
            now=current_time,
        )
        if committed:
            completed += 1
    return completed


def _optional_probe_value(probe: dict[str, object], key: str) -> str | None:
    value = probe.get(key)
    return None if value is None or str(value).strip() == "" else str(value)
