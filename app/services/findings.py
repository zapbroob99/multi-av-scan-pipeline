from __future__ import annotations

from typing import Any


def normalized_finding(
    *,
    title: str,
    finding_type: str,
    source: str,
    severity: str,
    confidence: int,
    target: str | None = None,
    action: str | None = None,
    category: str | None = None,
    tags: list[str] | None = None,
    evidence: dict[str, Any] | None = None,
    vendor_details: dict[str, Any] | None = None,
    enrichment: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "title": title,
        "type": finding_type,
        "source": source,
        "severity": severity,
        "confidence": confidence,
        "target": target,
        "action": action,
        "category": category,
        "tags": tags or [],
        "evidence": evidence or {},
        "vendor_details": vendor_details or {},
        "enrichment": enrichment or [],
    }


def evidence_object(
    *,
    kind: str,
    value: str,
    location: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "value": value,
        "location": location,
        "metadata": metadata or {},
    }


def enrichment_result(
    *,
    source: str,
    status: str,
    summary: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "source": source,
        "status": status,
        "summary": summary,
        "details": details or {},
    }
