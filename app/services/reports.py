from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Callable

from app.models import EngineResultRecord, ScanRecord
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
    decision_payload: dict[str, object],
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
    if isinstance(value, (list, tuple, set)):
        return "; ".join(csv_cell(item) for item in value)
    if isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return " ".join(str(value).split())


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
    decision = summary["decision"]
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
            "decision": decision["action"],
            "decision_policy": decision["policy"],
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
