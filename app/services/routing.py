from __future__ import annotations

import json
from dataclasses import dataclass

from app.models import EngineInstanceRecord, EngineResultInput, ScanRecord
from app.services.engine_registry import adapter_capabilities, runtime_config
from app.services.worker_capabilities import adapter_supported_on_platform, worker_platform


ROUTE_ACTION_RUN = "run"
ROUTE_ACTION_WAIT = "wait"
ROUTE_ACTION_SKIP = "skip"

ROUTE_REASON_ENGINE_DISABLED = "engine_disabled"
ROUTE_REASON_WORKER_NOT_ASSIGNED = "worker_not_assigned"
ROUTE_REASON_UNSUPPORTED_PLATFORM = "unsupported_platform"
ROUTE_REASON_FILE_TOO_LARGE = "file_too_large"
ROUTE_REASON_WORKER_TIMEOUT = "worker_timeout"


@dataclass(frozen=True)
class EngineRouteDecision:
    engine: EngineInstanceRecord
    action: str
    reason_code: str
    reason: str
    details: dict[str, object]


def route_engine_for_worker(
    engine: EngineInstanceRecord,
    scan: ScanRecord,
    engine_keys: set[str],
    platform_name: str | None = None,
) -> EngineRouteDecision:
    current_platform = worker_platform() if platform_name is None else platform_name
    capability = adapter_capabilities(engine.adapter_key)

    if not engine.enabled:
        return EngineRouteDecision(
            engine=engine,
            action=ROUTE_ACTION_SKIP,
            reason_code=ROUTE_REASON_ENGINE_DISABLED,
            reason="Engine instance is disabled.",
            details=route_details(
                engine=engine,
                scan=scan,
                reason_code=ROUTE_REASON_ENGINE_DISABLED,
                reason="Engine instance is disabled.",
                current_platform=current_platform,
            ),
        )

    if not adapter_supported_on_platform(engine.adapter_key, current_platform):
        return EngineRouteDecision(
            engine=engine,
            action=ROUTE_ACTION_WAIT,
            reason_code=ROUTE_REASON_UNSUPPORTED_PLATFORM,
            reason="This worker platform cannot execute the adapter.",
            details=route_details(
                engine=engine,
                scan=scan,
                reason_code=ROUTE_REASON_UNSUPPORTED_PLATFORM,
                reason="This worker platform cannot execute the adapter.",
                current_platform=current_platform,
                extra_details={"supported_platforms": list(capability.supported_platforms)},
            ),
        )

    if engine.adapter_key not in engine_keys:
        return EngineRouteDecision(
            engine=engine,
            action=ROUTE_ACTION_WAIT,
            reason_code=ROUTE_REASON_WORKER_NOT_ASSIGNED,
            reason="This worker is not assigned to run the adapter.",
            details=route_details(
                engine=engine,
                scan=scan,
                reason_code=ROUTE_REASON_WORKER_NOT_ASSIGNED,
                reason="This worker is not assigned to run the adapter.",
                current_platform=current_platform,
                extra_details={"worker_engine_keys": sorted(engine_keys)},
            ),
        )

    max_file_size_bytes, size_limit_source = engine_size_limit(engine)
    if max_file_size_bytes is not None and scan.size_bytes > max_file_size_bytes:
        # Name the layer that actually binds, so "I raised the limit and nothing
        # changed" is answerable from the result alone.
        reason = f"Sample exceeds the effective max file size ({size_limit_source})."
        return EngineRouteDecision(
            engine=engine,
            action=ROUTE_ACTION_SKIP,
            reason_code=ROUTE_REASON_FILE_TOO_LARGE,
            reason=reason,
            details=route_details(
                engine=engine,
                scan=scan,
                reason_code=ROUTE_REASON_FILE_TOO_LARGE,
                reason=reason,
                current_platform=current_platform,
                extra_details={
                    "sample_size_bytes": scan.size_bytes,
                    "max_file_size_bytes": max_file_size_bytes,
                    "max_file_size_source": size_limit_source,
                },
            ),
        )

    return EngineRouteDecision(
        engine=engine,
        action=ROUTE_ACTION_RUN,
        reason_code="eligible",
        reason="Worker can execute this adapter for the sample.",
        details=route_details(
            engine=engine,
            scan=scan,
            reason_code="eligible",
            reason="Worker can execute this adapter for the sample.",
            current_platform=current_platform,
        ),
    )


def engine_max_file_size_bytes(engine: EngineInstanceRecord) -> int | None:
    return engine_size_limit(engine)[0]


def engine_size_limit(engine: EngineInstanceRecord) -> tuple[int | None, str]:
    """The size cap routing enforces, plus which layer produced it.

    Prefers ``effective_max_file_size_bytes`` when the adapter reports one. An
    adapter's own cap is not the whole story: the underlying scanner may enforce
    a smaller one (clamd's StreamMaxLength/MaxFileSize), and skipping only on the
    adapter cap lets a file reach the scanner just to be rejected there, which
    surfaces as an opaque engine failure. Adapters that report no effective limit
    fall back to their plain cap, so this stays engine-agnostic.
    """
    config = runtime_config(engine)
    value = config.get("effective_max_file_size_bytes")
    source = str(config.get("effective_max_file_size_source") or "adapter max_file_size_bytes")
    if value is None:
        value = config.get("max_file_size_bytes")
        source = "adapter max_file_size_bytes"
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None, source
    return (parsed if parsed > 0 else None), source


def build_skipped_engine_result(
    decision: EngineRouteDecision,
    duration_ms: int,
    error_message: str | None = None,
    raw_output: str | None = None,
) -> EngineResultInput:
    payload = dict(decision.details)
    existing_routing = payload.get("routing")
    routing = existing_routing if isinstance(existing_routing, dict) else {}
    payload["routing"] = {
        **routing,
        "action": ROUTE_ACTION_SKIP,
        "reason_code": decision.reason_code,
        "reason": decision.reason,
        **(
            {"deferred_reason_code": deferred_code, "deferred_reason": deferred_reason}
            if (deferred_code := payload.get("deferred_reason_code")) and (deferred_reason := payload.get("deferred_reason"))
            else {}
        ),
    }
    message = raw_output or decision.reason
    return EngineResultInput(
        engine_name=decision.engine.display_name,
        status="skipped",
        detected=False,
        severity="info",
        confidence=0,
        signature=None,
        raw_output=message,
        error_message=error_message or decision.reason,
        duration_ms=max(1, duration_ms),
        details_json=json.dumps(payload, sort_keys=True),
    )


def route_details(
    *,
    engine: EngineInstanceRecord,
    scan: ScanRecord,
    reason_code: str,
    reason: str,
    current_platform: str,
    extra_details: dict[str, object] | None = None,
) -> dict[str, object]:
    capability = adapter_capabilities(engine.adapter_key)
    details = {
        "adapter": engine.adapter_key,
        "sample": {
            "filename": scan.original_filename,
            "sha256": scan.sha256,
            "size_bytes": scan.size_bytes,
        },
        "routing": {
            "action": None,
            "reason_code": reason_code,
            "reason": reason,
            "worker_platform": current_platform,
            "deployment": capability.deployment,
            "supported_platforms": list(capability.supported_platforms),
            "input_modes": list(capability.input_modes),
        },
    }
    if extra_details:
        details["routing"].update(extra_details)
    return details
