from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanDecision:
    action: str
    label: str
    tone: str
    confidence: str
    policy: str
    reason: str
    reasons: list[str]


def decide_scan_action(
    *,
    scan_status: str,
    verdict: str,
    risk_score: int,
    detected_engines: int,
    detection_engines: int,
    unavailable_engines: list[str],
) -> ScanDecision:
    if scan_status in {"queued", "running"}:
        return ScanDecision(
            action="wait",
            label="Wait",
            tone="neutral",
            confidence="low",
            policy="scan_in_progress",
            reason="Scan is still running.",
            reasons=["Scan is still running.", "Final action is deferred until engine results are ready."],
        )

    if scan_status == "failed":
        return ScanDecision(
            action="review",
            label="Review",
            tone="warning",
            confidence="low",
            policy="scan_failed",
            reason="Scan failed before a reliable automation decision could be made.",
            reasons=["Scan failed.", "Manual review is required before taking action."],
        )

    if detected_engines > 0 or verdict in {"high", "critical"} or risk_score >= 60:
        detection_label = "engine" if detected_engines == 1 else "engines"
        return ScanDecision(
            action="block",
            label="Block",
            tone="danger",
            confidence="high",
            policy="malware_detected",
            reason=f"{detected_engines} detection {detection_label} reported malicious content.",
            reasons=[
                f"{detected_engines} detection {detection_label} reported malicious content.",
                f"Risk score is {risk_score}/100 with verdict {verdict}.",
            ],
        )

    if detection_engines == 0:
        return ScanDecision(
            action="review",
            label="Review",
            tone="warning",
            confidence="low",
            policy="metadata_only",
            reason="No detection engines were available for this scan.",
            reasons=[
                "No detection engines were available for this scan.",
                "Metadata-only scans should not be automatically allowed.",
            ],
        )

    if unavailable_engines:
        return ScanDecision(
            action="review",
            label="Review",
            tone="warning",
            confidence="medium",
            policy="partial_coverage",
            reason="One or more required engines did not complete.",
            reasons=[
                "One or more required engines did not complete.",
                "; ".join(unavailable_engines),
            ],
        )

    if risk_score >= 30 or verdict == "medium":
        return ScanDecision(
            action="review",
            label="Review",
            tone="warning",
            confidence="medium",
            policy="elevated_risk",
            reason=f"Risk score is {risk_score}/100 with verdict {verdict}.",
            reasons=[
                f"Risk score is {risk_score}/100 with verdict {verdict}.",
                "Manual review is recommended before allowing the file.",
            ],
        )

    return ScanDecision(
        action="allow",
        label="Allow",
        tone="success",
        confidence="high",
        policy="clean_full_coverage",
        reason="No detection engines reported malicious content and required coverage completed.",
        reasons=[
            "No detection engines reported malicious content.",
            "Required engine coverage completed.",
        ],
    )
