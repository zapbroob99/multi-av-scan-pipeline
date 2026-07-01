from dataclasses import dataclass

from app.models import EngineResultRecord


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    verdict: str
    reasons: list[str]


def calculate_risk(engine_results: list[EngineResultRecord]) -> RiskAssessment:
    reasons: list[str] = []
    score = 0

    detections = [
        result
        for result in engine_results
        if result.status == "completed" and result.detected
    ]
    completed_clean = [
        result
        for result in engine_results
        if result.status == "completed" and not result.detected
    ]
    unavailable = [
        result
        for result in engine_results
        if result.status in {"skipped", "failed"}
    ]

    if detections:
        score += 70
        first_detection = detections[0]
        signature = first_detection.signature or "unknown signature"
        reasons.append(f"{first_detection.engine_name} detected {signature}.")

    if len(detections) > 1:
        score += 20
        reasons.append("Multiple engines reported detections.")

    if completed_clean and not detections:
        score += 10
        reasons.append("No completed engine reported a detection.")

    if not engine_results:
        reasons.append("No engine results are available.")

    for result in unavailable:
        reasons.append(f"{result.engine_name} was {result.status}.")

    score = min(score, 100)
    return RiskAssessment(
        score=score,
        verdict=verdict_for_score(score, detections=bool(detections)),
        reasons=reasons or ["Static metadata collected."],
    )


def verdict_for_score(score: int, detections: bool) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if detections:
        return "medium"
    if score > 0:
        return "low"
    return "info"
