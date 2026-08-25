"""VirusTotal SHA-256 reputation engine adapter.

This is a hash-reputation engine. It can run from the dedicated hash endpoint
or participate in an ordinary file scan by using the SHA-256 MASP already
computed during intake. It never uploads content or requests re-analysis.
"""

from __future__ import annotations

import json
from dataclasses import replace
from time import perf_counter

from app.models import EngineResultInput, ScanRecord
from app.services.hash_scanning import HashEngineError, HashEngineExecution
from app.services.virustotal import (
    VirusTotalNotConfiguredError,
    load_virustotal_config,
    lookup_virustotal_hash,
    probe_virustotal_connection,
)


ENGINE_NAME = "VirusTotal"


def get_virustotal_config(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | int | bool]:
    """Return public-safe runtime configuration; never expose the API key."""
    try:
        config = load_virustotal_config(config_override=config_override)
    except VirusTotalNotConfiguredError as exc:
        return {
            "mode": "hash_reputation",
            "configured": False,
            "detail": str(exc),
            "timeout_seconds": 10,
            "cache_seconds": 3600,
            "unknown_cache_seconds": 300,
            "cache_max_entries": 10000,
            "malicious_threshold": 1,
            "allow_undetected": False,
            "max_age_days": 30,
        }
    return {
        "mode": "hash_reputation",
        "configured": True,
        "detail": "Licensed VirusTotal API credentials are configured.",
        "timeout_seconds": config.timeout_seconds,
        "cache_seconds": config.cache_seconds,
        "unknown_cache_seconds": config.unknown_cache_seconds,
        "cache_max_entries": config.cache_max_entries,
        "malicious_threshold": config.malicious_threshold,
        "allow_undetected": config.allow_undetected,
        "max_age_days": config.max_age_days,
    }


def check_virustotal_health(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | bool]:
    runtime = get_virustotal_config(config_override)
    if not bool(runtime["configured"]):
        return {
            "ok": False,
            "status": "not configured",
            "detail": str(runtime["detail"]),
        }
    return {
        "ok": True,
        "status": "configured",
        "detail": (
            "Licensed credentials are configured. Use Test connection or interactive "
            "Scan Hash to validate live connectivity without uploading a file."
        ),
        "product_version": "API v3",
        "engine_version": "api-v3",
        "service_state": "configured",
    }


def test_virustotal_connection(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | bool]:
    return probe_virustotal_connection(config_override)


def run_virustotal_hash_engine(
    sha256: str,
    config_override: dict[str, str] | None = None,
) -> HashEngineExecution:
    started_at = perf_counter()
    payload = lookup_virustotal_hash(sha256, config_override)
    duration_ms = max(1, int((perf_counter() - started_at) * 1000))
    decision = payload.get("decision")
    public_decision = decision if isinstance(decision, dict) else {}
    action = str(public_decision.get("action", "review"))
    status = str(payload["status"])
    stats = payload.get("stats")
    public_stats = stats if isinstance(stats, dict) else {}
    malicious = int(public_stats.get("malicious", 0))
    suspicious = int(public_stats.get("suspicious", 0))
    total = int(public_stats.get("total", 0))
    detected = action == "block"
    severity = "critical" if detected else "medium" if status == "suspicious" else "info"
    confidence = 95 if detected else 60 if status == "suspicious" else 75 if status == "undetected" else 0
    signature = (
        f"VirusTotal {malicious}/{total} malicious"
        if detected
        else f"VirusTotal {suspicious}/{total} suspicious"
        if status == "suspicious"
        else None
    )
    findings: list[dict[str, object]] = []
    if detected or status == "suspicious":
        findings.append(
            {
                "source": ENGINE_NAME,
                "title": "VirusTotal reputation signal",
                "type": "hash_reputation",
                "severity": severity,
                "confidence": confidence,
                "action": action,
                "classification": ["reputation", "virustotal"],
                "matched_evidence": {
                    "sha256": payload["hash"],
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total": total,
                },
            }
        )

    serialized = json.dumps(payload, sort_keys=True)
    last_analysis_date = payload.get("last_analysis_date")
    return HashEngineExecution(
        result=EngineResultInput(
            engine_name=ENGINE_NAME,
            engine_version="api-v3",
            signature_version=(
                str(last_analysis_date) if last_analysis_date is not None else None
            ),
            # A 404/no-report response is a successful reputation lookup with
            # an Unknown policy outcome. It is not an execution skip; keeping
            # it completed preserves truthful engine coverage while the
            # decision remains fail-closed through action=review.
            status="completed",
            detected=detected,
            signature=signature,
            severity=severity,
            confidence=confidence,
            raw_output=serialized,
            error_message=None,
            duration_ms=duration_ms,
            details_json=serialized,
            findings_json=json.dumps(findings, sort_keys=True),
        ),
        payload=payload,
    )


def run_virustotal_file_hash_engine(
    scan: ScanRecord,
    config_override: dict[str, str] | None = None,
) -> EngineResultInput:
    """Run VirusTotal in a file scan without sending the file itself.

    ``scan.sha256`` is computed locally during intake. Hash-engine failures are
    normalized into a regular failed engine result so an upstream outage lowers
    coverage and yields Review instead of crashing the whole scan worker. A
    successful lookup is enrichment: no-report, undetected, and stale
    zero-signal responses do not override otherwise-clean local scan engines.
    The dedicated Scan Hash workflow keeps its stricter fail-closed policy.
    """
    started_at = perf_counter()
    try:
        execution = run_virustotal_hash_engine(scan.sha256, config_override)
        payload = dict(execution.payload)
        payload["mode"] = "file_hash_lookup"
        payload["file_uploaded"] = False
        reputation_decision = payload.get("decision")
        status = str(payload.get("status", "unknown"))
        if status in {"unknown", "undetected", "stale"}:
            payload["reputation_decision"] = reputation_decision
            if status == "unknown":
                reason = (
                    "No VirusTotal report was found for this hash. "
                    "This does not change the file scan decision."
                )
            elif status == "stale":
                reason = (
                    "VirusTotal has no malicious or suspicious detections in the "
                    "available report. Its age does not change the file scan decision."
                )
            else:
                reason = (
                    "VirusTotal has no malicious or suspicious detections. "
                    "This does not change the file scan decision."
                )
            payload["decision"] = {"action": "allow", "reason": reason}
            payload["detail"] = reason

        serialized = json.dumps(payload, sort_keys=True)
        return replace(
            execution.result,
            raw_output=serialized,
            details_json=serialized,
        )
    except HashEngineError as exc:
        duration_ms = max(1, int((perf_counter() - started_at) * 1000))
        details = json.dumps(
            {
                "hash": scan.sha256,
                "source": "virustotal",
                "mode": "file_hash_lookup",
                "file_uploaded": False,
                "error": str(exc),
            },
            sort_keys=True,
        )
        return EngineResultInput(
            engine_name=ENGINE_NAME,
            engine_version="api-v3",
            status="failed",
            detected=False,
            severity="info",
            confidence=0,
            signature=None,
            raw_output=details,
            error_message=str(exc),
            duration_ms=duration_ms,
            details_json=details,
        )
