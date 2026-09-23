"""Institution-controlled SHA-256 blocklist and allowlist.

The digest compared is the one MASP computed itself while ingesting or copying
the sample, never a value a client asserted, so a client cannot choose the hash
that clears its own file. No sample bytes are read: the cost is one indexed
lookup regardless of sample size.

A blocklist match is reported as a detection. An allowlist match is
informational only: it never suppresses another engine's detection and never
produces an allow decision, because one wrongly listed hash would otherwise
clear a malicious file. No match proves nothing about the file either way.
"""
import json
import re
from time import perf_counter

from app.database import get_hash_list_entry, hash_list_counts
from app.models import EngineResultInput, ScanRecord
from app.services.findings import evidence_object, normalized_finding


ENGINE_NAME = "Hash List"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def get_hash_list_config(config_override: dict[str, str] | None = None) -> dict[str, object]:
    return {"mode": "builtin", "enabled": True, "timeout_seconds": 5}


def check_hash_list_health(config_override: dict[str, str] | None = None) -> dict[str, str | bool]:
    try:
        counts = hash_list_counts()
    except Exception as exc:
        return {
            "ok": False,
            "status": "unavailable",
            "detail": f"Hash list could not be read ({type(exc).__name__}).",
            "product_version": "builtin",
            "engine_version": "builtin",
            "service_state": "unavailable",
        }
    return {
        "ok": True,
        "status": "available",
        "detail": f"Hash list holds {counts['block']} blocked and {counts['allow']} allowed SHA-256 values.",
        "product_version": "builtin",
        "engine_version": "builtin",
        "service_state": "available",
    }


def run_hash_list_engine(scan: ScanRecord, config_override: dict[str, str] | None = None) -> EngineResultInput:
    started_at = perf_counter()
    sha256 = (scan.sha256 or "").strip().lower()
    if not SHA256_PATTERN.fullmatch(sha256):
        return _result(status="failed", raw_output="The sample has no valid MASP-computed SHA-256.",
                       error_message="Missing or malformed sample SHA-256.", started_at=started_at)
    try:
        entry = get_hash_list_entry(sha256)
    except Exception as exc:
        # A lookup that did not happen must never read as "not listed".
        return _result(status="failed", raw_output=f"Hash list could not be read ({type(exc).__name__}).",
                       error_message="Hash list lookup failed.", started_at=started_at)

    details: dict[str, object] = {"adapter": "hash_list", "sha256": sha256}
    if entry is None:
        details["outcome"] = "no_match"
        return _result(status="completed", details=details, started_at=started_at,
                       raw_output="SHA-256 is not on the institution hash list. This is not evidence that the file is clean.")

    list_kind = str(entry["list_kind"])
    note = str(entry.get("note") or "")[:256]
    details.update(outcome=f"{list_kind}_match", entry_id=int(entry["id"]), note=note or None,
                   listed_at=int(entry["created_at"]))
    evidence = {"sha256": evidence_object(kind="sha256", value=sha256, location="sample",
                                          metadata={"entry_id": int(entry["id"])})}
    suffix = f" Note: {note}" if note else ""
    if list_kind == "block":
        summary = f"SHA-256 is on the institution blocklist.{suffix}"
        finding = normalized_finding(
            title="Sample SHA-256 is on the institution blocklist",
            finding_type="hash_blocklist_match", source=ENGINE_NAME, severity="high",
            confidence=100, target=sha256, category="known_bad",
            tags=["hash-list", "blocklist"], evidence=evidence,
            vendor_details={"summary": summary},
        )
        return _result(status="completed", detected=True, severity="high", signature="HashList.Blocked",
                       raw_output=summary, details=details, findings=[finding], started_at=started_at)

    summary = (f"SHA-256 is on the institution allowlist.{suffix} This is informational: "
               "it does not suppress other engines' results or produce an allow decision.")
    finding = normalized_finding(
        title="Sample SHA-256 is on the institution allowlist",
        finding_type="hash_allowlist_match", source=ENGINE_NAME, severity="info",
        confidence=100, target=sha256, category="known_good",
        tags=["hash-list", "allowlist", "informational"], evidence=evidence,
        vendor_details={"summary": summary},
    )
    return _result(status="completed", raw_output=summary, details=details, findings=[finding],
                   started_at=started_at)


def _result(*, status: str, raw_output: str, started_at: float, severity: str = "info",
            detected: bool = False, signature: str | None = None, error_message: str | None = None,
            details: dict[str, object] | None = None,
            findings: list[dict[str, object]] | None = None) -> EngineResultInput:
    return EngineResultInput(
        engine_name=ENGINE_NAME,
        engine_version="builtin",
        signature_version=None,
        status=status,
        detected=detected,
        signature=signature,
        severity=severity,
        confidence=100 if status == "completed" else 0,
        raw_output=raw_output,
        error_message=error_message,
        duration_ms=max(1, int((perf_counter() - started_at) * 1000)),
        details_json=json.dumps(details or {"adapter": "hash_list"}, sort_keys=True),
        findings_json=json.dumps(findings or [], sort_keys=True),
    )
