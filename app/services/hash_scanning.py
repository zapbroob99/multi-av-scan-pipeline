"""Engine-neutral contracts and aggregation for SHA-256 reputation scans."""

from __future__ import annotations

from dataclasses import dataclass

from app.models import EngineInstanceRecord, EngineResultInput


class HashEngineError(RuntimeError):
    status_code = 502
    retry_after: int | None = None


class HashEngineNotConfiguredError(HashEngineError):
    status_code = 503


class HashEngineQuotaError(HashEngineError):
    status_code = 503


@dataclass(frozen=True)
class HashEngineExecution:
    result: EngineResultInput
    payload: dict[str, object]


@dataclass(frozen=True)
class HashEngineRun:
    engine: EngineInstanceRecord
    support_state: str
    execution: HashEngineExecution


def build_hash_scan_payload(
    sha256: str,
    runs: list[HashEngineRun],
) -> dict[str, object]:
    actions: list[str] = []
    results: list[dict[str, object]] = []
    for run in runs:
        payload = run.execution.payload
        raw_decision = payload.get("decision")
        decision = raw_decision if isinstance(raw_decision, dict) else {}
        action = str(decision.get("action", "review"))
        if action not in {"allow", "review", "block"}:
            action = "review"
        reason = str(decision.get("reason", payload.get("detail", "Review required.")))
        actions.append(action)
        results.append(
            {
                "engine": {
                    "key": run.engine.adapter_key,
                    "name": run.engine.display_name,
                    "support_state": run.support_state,
                },
                "status": str(payload.get("status", run.execution.result.status)),
                "found": bool(payload.get("found", False)),
                "decision": {"action": action, "reason": reason},
                "duration_ms": run.execution.result.duration_ms,
                "data": payload,
            }
        )

    overall_action = (
        "block" if "block" in actions else "review" if "review" in actions else "allow"
    )
    if overall_action == "block":
        reason = "At least one enabled hash engine returned a block decision."
    elif overall_action == "review":
        reason = "At least one enabled hash engine requires review."
    else:
        reason = "All enabled hash engines returned an allow decision."
    return {
        "hash": sha256,
        "algorithm": "sha256",
        "decision": {"action": overall_action, "reason": reason},
        "engines": {
            "expected": len(runs),
            "completed": len(runs),
            "failed": 0,
        },
        "results": results,
    }
