from __future__ import annotations

import csv
from dataclasses import asdict
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Callable

from app.models import EngineResultRecord, ScanRecord
from app.services.scan_assessment import (
    detection_engine_results,
    detection_summary,
    required_engine_coverage,
    scan_decision,
)
from app.services.scoring import calculate_risk
from app.services.service_clients import required_detection_engine_names
from app.services.timing import build_scan_timing_payload


def parse_json_value(value: str, fallback: object) -> object:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return fallback
    return parsed


def report_filename_base(scan: ScanRecord) -> str:
    stem = Path(scan.original_filename).stem or f"scan-{scan.id}"
    clean = "".join(char if char.isalnum() else "-" for char in stem).strip("-")
    return clean or f"scan-{scan.id}"


def result_findings(result: EngineResultRecord) -> list[dict[str, object]]:
    parsed = parse_json_value(result.findings_json, [])
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def build_report_finding_rows(
    results: list[EngineResultRecord],
    *,
    matched_evidence_for_finding: Callable[[dict[str, object], EngineResultRecord], object],
    finding_classification_values: Callable[[dict[str, object]], list[str]],
    fallback_finding_detail_payload: Callable[[dict[str, object], EngineResultRecord], dict[str, object]],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for result in results:
        for finding in result_findings(result):
            source = str(finding.get("source") or result.engine_name)
            title = str(finding.get("title") or result.signature or "Detection")
            finding_type = str(finding.get("type") or "finding").replace("_", " ").title()
            severity = str(finding.get("severity") or result.severity)
            confidence = int(finding.get("confidence") or result.confidence or 0)
            action = str(finding.get("action") or "detected").replace("_", " ").title()
            matched = matched_evidence_for_finding(finding, result)
            rows.append(
                {
                    "engine": source,
                    "status": result.status,
                    "title": title,
                    "finding": finding_type,
                    "severity": severity,
                    "confidence": confidence,
                    "action": action,
                    "matched_evidence": matched if isinstance(matched, list) else [str(matched)],
                    "classification": finding_classification_values(finding),
                    "evidence": fallback_finding_detail_payload(finding, result),
                }
            )
    return rows


def create_scan_report_payload(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
    *,
    verdict: str,
    risk_score: int,
    findings: list[dict[str, object]],
    coverage_ran: int,
    coverage_total: int,
    coverage_unavailable: list[str],
    decision_payload: dict[str, object] | None,
    assessment_reasons: list[str],
    detection_label: str,
    detection_detail: str,
    detected_engines: list[str],
    coverage_label: str,
    coverage_detail: str,
) -> dict[str, object]:
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan": {
            "id": scan.id,
            "filename": scan.original_filename,
            "case_name": scan.case_name,
            "priority": scan.priority,
            "source": scan.source,
            "status": scan.status,
            "verdict": verdict,
            "risk_score": risk_score,
            "created_at": scan.created_at,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "failed_at": scan.failed_at,
            "attempt_count": scan.attempt_count,
            "last_error": scan.last_error,
            "note": scan.note,
            "content_type": scan.content_type,
            "size_bytes": scan.size_bytes,
            "batch": {
                "id": scan.batch_id,
                "parent_scan_id": scan.parent_scan_id,
                "relative_path": scan.relative_path,
                "role": scan.scan_role,
            },
            "timing": build_scan_timing_payload(scan),
            "hashes": {
                "md5": scan.md5,
                "sha1": scan.sha1,
                "sha256": scan.sha256,
            },
        },
        "summary": {
            "detection": {
                "label": detection_label,
                "detail": detection_detail,
                "detected_engines": detected_engines,
            },
            "coverage": {
                "label": coverage_label,
                "detail": coverage_detail,
                "ran": coverage_ran,
                "total": coverage_total,
                "unavailable": coverage_unavailable,
            },
            "assessment": {
                "score": risk_score,
                "verdict": verdict,
                "reasons": assessment_reasons,
            },
            "decision": decision_payload,
        },
        "findings": findings,
        "engine_results": [
            {
                "engine_name": result.engine_name,
                "engine_version": result.engine_version,
                "signature_version": result.signature_version,
                "status": result.status,
                "detected": result.detected,
                "signature": result.signature,
                "severity": result.severity,
                "confidence": result.confidence,
                "duration_ms": result.duration_ms,
                "error_message": result.error_message,
                "raw_output": result.raw_output,
                "details": parse_json_value(result.details_json, {}),
                "findings": result_findings(result),
                "created_at": result.created_at,
            }
            for result in engine_results
        ],
    }


def csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    force_text = isinstance(value, (str, list, tuple, set, dict))
    if isinstance(value, (list, tuple, set)):
        value = "; ".join(" ".join(str(item).split()) for item in value)
    if isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = " ".join(str(value).split())
    if not text:
        return ""
    # Every untrusted textual cell is spreadsheet text, even when leading
    # whitespace/control characters would otherwise hide a formula marker.
    return "'" + text if force_text else text


def create_scan_report_csv(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
    payload: dict[str, object],
) -> str:
    summary = payload["summary"]
    findings = payload["findings"]
    assessment = summary["assessment"]
    detection = summary["detection"]
    coverage = summary["coverage"]
    decision = summary["decision"] or {}
    output = io.StringIO(newline="")
    fieldnames = [
        "section",
        "scan_id",
        "filename",
        "sha256",
        "status",
        "verdict",
        "risk_score",
        "decision",
        "decision_policy",
        "engine",
        "detected",
        "severity",
        "confidence",
        "finding",
        "signature",
        "matched_evidence",
        "duration_ms",
        "error_message",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    def write_row(**values: object) -> None:
        base = {
            "scan_id": scan.id,
            "filename": scan.original_filename,
            "sha256": scan.sha256,
            "status": scan.status,
            "verdict": assessment["verdict"],
            "risk_score": assessment["score"],
            "decision": decision.get("action"),
            "decision_policy": decision.get("policy"),
        }
        base.update(values)
        writer.writerow({key: csv_cell(base.get(key)) for key in fieldnames})

    write_row(
        section="summary",
        finding=detection["label"],
        matched_evidence=", ".join(detection["detected_engines"]),
        error_message="" if not coverage["unavailable"] else coverage["detail"],
    )

    for finding in findings:
        write_row(
            section="finding",
            engine=finding["engine"],
            detected=finding["status"] == "completed",
            severity=finding["severity"],
            confidence=finding["confidence"],
            finding=finding["finding"],
            signature=finding["title"],
            matched_evidence=finding["matched_evidence"],
        )

    for result in engine_results:
        write_row(
            section="engine_result",
            engine=result.engine_name,
            detected=result.detected,
            severity=result.severity,
            confidence=result.confidence,
            signature=result.signature,
            duration_ms=result.duration_ms,
            error_message=result.error_message,
        )

    return output.getvalue()


def _clean_evidence_value(value: object) -> object:
    if isinstance(value, dict):
        return {key: _clean_evidence_value(item) for key, item in value.items()
                if key not in {"raw_output", "raw_response"} and item not in ({}, [], None, "")}
    if isinstance(value, list):
        return [_clean_evidence_value(item) for item in value if item not in ({}, [], None, "")]
    return value


def _finding_detail_payload(finding: dict[str, object]) -> dict[str, object]:
    evidence = finding.get("evidence")
    clean_evidence = ({key: _clean_evidence_value(value) for key, value in evidence.items()
                       if key not in {"raw_output", "raw_response"} and value not in ({}, [], None, "")}
                      if isinstance(evidence, dict) else {})
    payload = {
        "finding": {key: finding.get(key) for key in
                    ("source", "title", "type", "category", "severity", "confidence", "action", "tags", "target")},
        "evidence": clean_evidence,
        "enrichment": finding.get("enrichment") or [],
    }
    return {key: value for key, value in payload.items() if value not in ({}, [], None, "")}


def _fallback_finding_detail_payload(finding: dict[str, object], result: EngineResultRecord) -> dict[str, object]:
    payload = _finding_detail_payload(finding)
    if payload:
        return payload
    return ({"evidence": {"signature": result.signature, "source_engine": result.engine_name}}
            if result.signature else {})


def _matched_evidence_for_finding(finding: dict[str, object], result: EngineResultRecord) -> object:
    evidence = finding.get("evidence")
    values = [str(item["value"]) for item in evidence.get("objects", [])
              if isinstance(item, dict) and item.get("value")] if isinstance(evidence, dict) else []
    return values or str(finding.get("title") or result.signature or "-")


def _unique_values(values: list[str], limit: int = 6) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        normalized = value.strip()
        folded = normalized.casefold()
        if not normalized or folded in seen:
            continue
        seen.add(folded)
        unique.append(normalized)
        if len(unique) == limit:
            break
    return unique


def _finding_classification_values(finding: dict[str, object]) -> list[str]:
    category = str(finding.get("category") or finding.get("type") or "")
    tags = finding.get("tags")
    clean_tags = [str(tag) for tag in tags if str(tag)] if isinstance(tags, list) else []
    values = [category.replace("_", " ").title()] if category else []
    values.extend(tag for tag in clean_tags if tag.casefold() != category.casefold())
    return _unique_values(values)


def build_scan_report_payload(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
    *,
    required_names: list[str] | None = None,
    decision_available: bool = True,
) -> dict[str, object]:
    """Build the shared complete operator export without importing app.main."""
    required = required_detection_engine_names(scan) if required_names is None else required_names
    assessment = calculate_risk(engine_results)
    verdict = scan.verdict if scan.risk_score is not None else assessment.verdict
    risk_score = scan.risk_score if scan.risk_score is not None else assessment.score
    findings = build_report_finding_rows(
        engine_results,
        matched_evidence_for_finding=_matched_evidence_for_finding,
        finding_classification_values=_finding_classification_values,
        fallback_finding_detail_payload=_fallback_finding_detail_payload,
    )
    ran, total, unavailable = required_engine_coverage(
        engine_results, scan=scan, required_names=required
    )
    detected, detection_total = detection_summary(
        engine_results, scan=scan, required_names=required
    )
    detected_names = [result.engine_name for result in detection_engine_results(
        engine_results, required_names=required
    ) if result.status == "completed" and result.detected]
    if scan.status in {"queued", "running", "finalizing"}:
        detection_label = "Pending engine results"
        detection_detail = "Detection engines have not completed yet."
    else:
        detection_label = ("No detection engines configured" if detection_total == 0
                           else f"{detected} of {detection_total} engines detected")
        detection_detail = (", ".join(detected_names) if detected_names else
                            "No detection adapters are assigned to this scan profile." if detection_total == 0 else
                            "No detection engine flagged this sample.")
    if total == 0:
        coverage_label = "No required detection engines configured"
        coverage_detail = "Only metadata analyzers are assigned to this scan profile."
    elif scan.status == "queued":
        coverage_label = f"{ran} of {total} required engines queued"
        coverage_detail = (f"Waiting for required engines: {'; '.join(unavailable)}."
                           if unavailable else "Required engine jobs are queued.")
    elif scan.status in {"running", "finalizing"}:
        coverage_label = f"{ran} of {total} required engines completed"
        coverage_detail = (f"Waiting for required engines: {'; '.join(unavailable)}."
                           if unavailable else "Required engine coverage is complete; finalizing scan.")
    else:
        coverage_label = f"{ran} of {total} required engines ran"
        coverage_detail = "; ".join(unavailable) if unavailable else "All required detection engines completed."
    decision = scan_decision(
        scan, engine_results, risk_score=risk_score, verdict=verdict, required_names=required
    ) if decision_available else None
    return create_scan_report_payload(
        scan,
        engine_results,
        verdict=verdict,
        risk_score=risk_score,
        findings=findings,
        coverage_ran=ran,
        coverage_total=total,
        coverage_unavailable=unavailable,
        decision_payload=asdict(decision) if decision else None,
        assessment_reasons=assessment.reasons,
        detection_label=detection_label,
        detection_detail=detection_detail,
        detected_engines=detected_names,
        coverage_label=coverage_label,
        coverage_detail=coverage_detail,
    )


def build_scan_report_csv(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
    *,
    required_names: list[str] | None = None,
    decision_available: bool = True,
) -> str:
    payload = build_scan_report_payload(
        scan, engine_results, required_names=required_names, decision_available=decision_available
    )
    return create_scan_report_csv(scan, engine_results, payload)
