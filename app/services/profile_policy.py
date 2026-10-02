"""Per-profile scan policy: what one client accepts and when it blocks.

A profile's policy is stored on the profile, frozen into every accepted scan's
routing snapshot, judged once at intake against the stored sample, and applied
by the shared decision, so ICAP, the REST API and the console always agree.

Every field defaults to "inherit": an empty policy changes nothing, so a
deployment upgraded to this release behaves exactly as before until an
administrator sets a rule. A policy can only make a decision stricter. It never
turns a review or a detection into an allow.

Content is judged from the sample's header, never from its name alone, with
the same classifier and family names as the file_type engine and storage
protection's light tier.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.services.content_types import FAMILIES, classify
from app.services.decisions import ScanDecision

HEADER_BYTES = 4096
MAX_SAFE_INTEGER = 9007199254740991
_CODE_FAMILIES = frozenset({"executable", "script"})


class TypeRule(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # allowlist: only these families are accepted. denylist: these are not.
    mode: Literal["allowlist", "denylist"]
    families: list[str] = Field(min_length=1, max_length=len(FAMILIES))

    @field_validator("families")
    @classmethod
    def _known_families(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(FAMILIES))
        if unknown:
            raise ValueError(f"Unknown content families: {', '.join(unknown)}.")
        return sorted(set(value), key=FAMILIES.index)


class ProfilePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # None: the deployment's upload and ICAP limits alone apply.
    max_file_bytes: int | None = Field(default=None, ge=1, le=MAX_SAFE_INTEGER)
    # None: no content rule.
    type_rule: TypeRule | None = None
    # A declared extension contradicted by the header, such as an executable
    # named report.pdf.
    block_masquerade: bool = False
    # What a type or masquerade violation does: scan the file and block it
    # whatever the engines say, or reject it at intake without scanning.
    violation_action: Literal["scan_and_block", "reject"] = "scan_and_block"
    # "inherit" keeps review as review (an ICAP gateway then follows its own
    # MASP_ICAP_BLOCK_ON_REVIEW); "block" blocks what could not be assessed.
    review_action: Literal["inherit", "block"] = "inherit"


def parse_profile_policy(raw: object) -> ProfilePolicy:
    """Parse a stored or submitted policy; raises ValueError on anything invalid."""
    if raw is None or raw == "":
        return ProfilePolicy()
    payload = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(payload, dict):
        raise ValueError("A profile policy must be an object.")
    return ProfilePolicy.model_validate(payload)


def profile_policy_json(policy: ProfilePolicy) -> str:
    return json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def is_inherit_only(policy: ProfilePolicy) -> bool:
    return policy == ProfilePolicy()


class PolicyRejectedError(ValueError):
    """The profile policy refuses this sample at intake; no scan is created."""

    def __init__(self, kind: str, reason: str) -> None:
        super().__init__(reason)
        self.kind = kind
        self.reason = reason


@dataclass(frozen=True)
class IntakeEvaluation:
    violations: tuple[dict, ...]
    reject_kind: str | None = None

    @property
    def reason(self) -> str:
        return "; ".join(str(item["detail"]) for item in self.violations)


def _size_text(value: int) -> str:
    for unit, size in (("GiB", 1024 ** 3), ("MiB", 1024 ** 2), ("KiB", 1024)):
        if value >= size:
            return f"{value / size:.1f} {unit}"
    return f"{value} bytes"


def evaluate_intake(policy: ProfilePolicy, *, filename: str, size: int, header: bytes) -> IntakeEvaluation:
    """Judge one sample against the policy before any engine runs."""
    if policy.max_file_bytes is not None and size > policy.max_file_bytes:
        detail = (f"File is {_size_text(size)}; this client's profile accepts at most "
                  f"{_size_text(policy.max_file_bytes)}.")
        return IntakeEvaluation(({"kind": "size", "detail": detail, "size_bytes": size,
                                  "max_file_bytes": policy.max_file_bytes},), reject_kind="size")
    classification = classify(header, filename)
    families = sorted(classification.families, key=FAMILIES.index)
    base = {"detected_type": classification.detected_type, "extension": classification.extension or None,
            "families": families}
    violations: list[dict] = []
    rule = policy.type_rule
    if rule is not None:
        allowed = set(rule.families)
        violating = [family for family in families
                     if (family in allowed) == (rule.mode == "denylist")]
        if violating:
            violations.append({**base, "kind": "type", "mode": rule.mode, "violating": violating,
                               "detail": f"Content family not accepted by this client's profile: {', '.join(violating)}."})
    if policy.block_masquerade and classification.mismatch:
        violations.append({**base, "kind": "masquerade",
                           "expected_types": sorted(classification.expected_types or ()),
                           "detail": (f"Declared .{classification.extension} content is actually "
                                      f"{classification.detected_type}.")})
    reject = "type" if violations and policy.violation_action == "reject" else None
    return IntakeEvaluation(tuple(violations), reject_kind=reject)


def _read_header(path: str) -> bytes:
    with Path(path).open("rb") as handle:
        return handle.read(HEADER_BYTES)


def snapshot_policy(snapshot: dict) -> object:
    profile = snapshot.get("scan_profile")
    return profile.get("policy") if isinstance(profile, dict) else None


def apply_intake_policy(snapshot_json: str, *, filename: str, size: int, storage_path: str) -> str:
    """Return the snapshot to store with this sample, or raise PolicyRejectedError.

    The evaluation is recorded in the scan's own snapshot so the decision can
    apply it later without reading the sample again. A snapshot whose policy
    cannot be parsed is stored unchanged; the decision then withholds an allow.
    """
    try:
        snapshot = json.loads(snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return snapshot_json
    if not isinstance(snapshot, dict):
        return snapshot_json
    try:
        policy = parse_profile_policy(snapshot_policy(snapshot))
    except ValueError:
        return snapshot_json
    if is_inherit_only(policy):
        return snapshot_json
    header = _read_header(storage_path) if (policy.type_rule or policy.block_masquerade) else b""
    evaluation = evaluate_intake(policy, filename=filename, size=size, header=header)
    if evaluation.reject_kind is not None:
        raise PolicyRejectedError(evaluation.reject_kind, evaluation.reason)
    if not evaluation.violations:
        return snapshot_json
    snapshot["intake_policy"] = {"violations": list(evaluation.violations)}
    return json.dumps(snapshot, separators=(",", ":"), sort_keys=True)


def _block(decision: ScanDecision, policy: str, reason: str, extra: list[str]) -> ScanDecision:
    return ScanDecision(action="block", label="Block", tone="danger", confidence="high", policy=policy,
                        reason=reason, reasons=[reason, *extra])


def apply_profile_policy(decision: ScanDecision, snapshot: dict, *, scan_role: str) -> ScanDecision:
    """Make a computed decision as strict as the scan's frozen profile policy."""
    raw = snapshot_policy(snapshot)
    if raw in (None, {}) and "intake_policy" not in snapshot:
        return decision
    if decision.action == "wait":
        return decision
    try:
        policy = parse_profile_policy(raw)
    except (ValueError, TypeError):
        if decision.action == "block":
            return decision
        return ScanDecision(action="review", label="Review", tone="warning", confidence="low",
                            policy="profile_policy_invalid",
                            reason="The client's recorded profile policy could not be read.",
                            reasons=["The client's recorded profile policy could not be read.",
                                     "An allow decision is withheld until the policy is fixed."])
    # Archive members inherit the container's snapshot, not its intake verdict.
    intake = snapshot.get("intake_policy") if scan_role != "child" else None
    violations = intake.get("violations") if isinstance(intake, dict) else None
    details = [str(item.get("detail")) for item in violations or [] if isinstance(item, dict)]
    if details:
        if decision.action == "block":
            return replace(decision, reasons=[*decision.reasons, *details])
        return _block(decision, "profile_content_policy", "The client's profile does not accept this content.", details)
    if decision.action == "review" and policy.review_action == "block":
        return _block(decision, "profile_review_block",
                      "The client's profile blocks files that could not be fully assessed.",
                      [decision.reason])
    return decision
