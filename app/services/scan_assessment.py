"""Verdict, detection-coverage, and decision resolution for a scan.

Extracted from ``app.main`` so both the FastAPI app and the standalone ICAP
server share the exact same decision logic without importing the web app.
"""

from __future__ import annotations

from app.database import list_engine_results
from app.models import EngineResultRecord, ScanRecord
from app.services.decisions import ScanDecision, decide_scan_action
from app.services.engine_registry import detection_engine_names
from app.services.scoring import calculate_risk


def detection_engine_results(
    results: list[EngineResultRecord],
) -> list[EngineResultRecord]:
    return [
        result
        for result in results
        if result.engine_name.lower() != "static metadata"
    ]


def engine_result_map(
    results: list[EngineResultRecord],
) -> dict[str, EngineResultRecord]:
    return {result.engine_name.lower(): result for result in results}


def detection_summary(results: list[EngineResultRecord]) -> tuple[int, int]:
    detection_results = detection_engine_results(results)
    detected = sum(
        1
        for result in detection_results
        if result.status == "completed" and result.detected
    )
    return detected, max(len(detection_results), len(detection_engine_names()))


def required_engine_coverage(
    results: list[EngineResultRecord],
) -> tuple[int, int, list[str]]:
    result_map = engine_result_map(results)
    unavailable = []
    ran = 0
    required_engines = detection_engine_names()

    for engine_name in required_engines:
        result = result_map.get(engine_name.lower())
        if result is None:
            unavailable.append(f"{engine_name} missing")
            continue

        if result.status == "completed":
            ran += 1
            continue

        unavailable.append(f"{engine_name} {result.status}")

    return ran, len(required_engines), unavailable


def scan_decision(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
    *,
    risk_score: int | None = None,
    verdict: str | None = None,
) -> ScanDecision:
    assessment = calculate_risk(engine_results)
    effective_score = risk_score if risk_score is not None else scan.risk_score
    effective_verdict = verdict if verdict is not None else scan.verdict
    if effective_score is None:
        effective_score = assessment.score
    if effective_verdict == "pending":
        effective_verdict = assessment.verdict
    detected_count, detection_total = detection_summary(engine_results)
    _, _, coverage_unavailable = required_engine_coverage(engine_results)
    return decide_scan_action(
        scan_status=scan.status,
        verdict=effective_verdict,
        risk_score=effective_score,
        detected_engines=detected_count,
        detection_engines=detection_total,
        unavailable_engines=coverage_unavailable,
    )


def resolve_scan_decision(scan: ScanRecord) -> ScanDecision:
    """Load a scan's engine results and compute its final decision."""
    return scan_decision(scan, list_engine_results(scan.id))
