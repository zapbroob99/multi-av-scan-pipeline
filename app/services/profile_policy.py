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

Archive handling is the one rule that also lifts something: an ICAP gateway
refuses every archive unless the profile says how archives are judged. Both
modes only make the scan's own decision stricter, so the exchange is a blanket
refusal for a decision that still blocks what MASP could not check.

Everything a file can be refused for at admission is a violation recorded here,
including that gateway refusal, and every violation kind maps to one entry of
NOT_ALLOWED: a short code stored on the scan, the operator's label and the
message an ICAP end user sees. A file that is not allowed is not malware: it is
blocked, but its recorded risk, detections and malware notifications are left
to the engines.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.services.archive_extractor import detect_archive_format
from app.services.archive_inspection import inspect_archive
from app.services.content_types import FAMILIES, classify
from app.services.decisions import ScanDecision
from app.services import profile_rules

HEADER_BYTES = 4096
MAX_SAFE_INTEGER = 9007199254740991


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
    # "inherit": an ICAP gateway follows MASP_ICAP_BLOCK_ARCHIVES and the API
    # scans the archive as one file. "inspect": engines scan it as one file and
    # MASP opens it to block what they could not see. "scan_members": also scan
    # every member with the profile's engines and decide on all of them.
    archive_handling: Literal["inherit", "inspect", "scan_members"] = "inherit"


@dataclass(frozen=True)
class NotAllowed:
    code: str
    label: str
    # What an ICAP end user is told; it names the kind of reason, never details.
    message: str


_CONTENT = "Blocked by MASP: this type of file is not accepted."
_ARCHIVE_UNCHECKED = "Blocked by MASP: the archive could not be fully checked."
_ARCHIVE_MEMBER = "Blocked by MASP: a file inside the archive is not accepted."
NOT_ALLOWED: dict[str, NotAllowed] = {
    "size": NotAllowed("too_large", "Too large", "Blocked by MASP: the file is larger than this service accepts."),
    "type": NotAllowed("content_type", "File type", _CONTENT),
    "masquerade": NotAllowed("masquerade", "Extension mismatch", _CONTENT),
    "archive_refused": NotAllowed("archive_refused", "Archive", "Blocked by MASP: archive files are not accepted."),
    "archive_encrypted": NotAllowed("archive_encrypted", "Encrypted archive", _ARCHIVE_UNCHECKED),
    "archive_unreadable": NotAllowed("archive_unreadable", "Damaged archive", _ARCHIVE_UNCHECKED),
    "archive_unsupported": NotAllowed("archive_unsupported", "Unsupported archive", _ARCHIVE_UNCHECKED),
    "archive_limit": NotAllowed("archive_limit", "Archive over limit", _ARCHIVE_UNCHECKED),
    "archive_nesting": NotAllowed("archive_nesting", "Nested too deep", _ARCHIVE_UNCHECKED),
    "member_type": NotAllowed("archive_content", "File type in archive", _ARCHIVE_MEMBER),
    "member_masquerade": NotAllowed("archive_content", "File type in archive", _ARCHIVE_MEMBER),
    "member_blocklisted": NotAllowed("blocklisted", "Hash blocklist", _ARCHIVE_MEMBER),
    # A profile rule whose action is Block, and an archive member such a rule blocks.
    "rule_block": NotAllowed("rule_block", "Blocked by rule", "Blocked by MASP: files like this are not accepted."),
    "member_rule": NotAllowed("archive_content", "File type in archive", _ARCHIVE_MEMBER),
}
# A kind this release does not know (written by a newer one) still reads as refused.
_UNKNOWN = NotAllowed("policy", "Policy", _CONTENT)
_BY_CODE = {entry.code: entry for entry in [*NOT_ALLOWED.values(), _UNKNOWN]}


def not_allowed_for_kind(kind: str) -> NotAllowed:
    return NOT_ALLOWED.get(kind, _UNKNOWN)


def not_allowed_by_code(code: str | None) -> NotAllowed | None:
    """The table entry for a stored code; None when the scan was not refused."""
    if not code:
        return None
    return _BY_CODE.get(code, _UNKNOWN)


def not_allowed(snapshot: dict) -> NotAllowed | None:
    """Why the scan's own intake refused it, from its frozen snapshot (first violation)."""
    intake = snapshot.get("intake_policy")
    violations = intake.get("violations") if isinstance(intake, dict) else None
    for item in violations or []:
        if isinstance(item, dict):
            return not_allowed_for_kind(str(item.get("kind", "")))
    return None


def not_allowed_code(snapshot_json: str) -> str | None:
    try:
        snapshot = json.loads(snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return None
    entry = not_allowed(snapshot) if isinstance(snapshot, dict) else None
    return entry.code if entry else None


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

    def __init__(self, kind: str, reason: str, violation_kind: str | None = None) -> None:
        super().__init__(reason)
        self.kind = kind
        self.reason = reason
        # The first violation's kind, for the NOT_ALLOWED entry an end user is shown.
        self.not_allowed = not_allowed_for_kind(violation_kind or kind)


@dataclass(frozen=True)
class IntakeEvaluation:
    violations: tuple[dict, ...]
    reject_kind: str | None = None

    @property
    def reason(self) -> str:
        return " ".join(str(item["detail"]) for item in self.violations)


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
    violations = content_violations(policy, filename=filename, header=header)
    reject = "type" if violations and policy.violation_action == "reject" else None
    return IntakeEvaluation(tuple(violations), reject_kind=reject)


def content_violations(policy: ProfilePolicy, *, filename: str, header: bytes) -> list[dict]:
    """The content and masquerade rules one file breaks, judged from its header."""
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
    return violations


def _read_header(path: str) -> bytes:
    with Path(path).open("rb") as handle:
        return handle.read(HEADER_BYTES)


def snapshot_policy(snapshot: dict) -> object:
    profile = snapshot.get("scan_profile")
    return profile.get("policy") if isinstance(profile, dict) else None


ARCHIVE_REFUSED_DETAIL = ("Archive files are not accepted through this ICAP gateway "
                          "(MASP_ICAP_BLOCK_ARCHIVES) unless the client's profile sets archive handling.")


def apply_intake_policy(snapshot_json: str, *, filename: str, size: int, storage_path: str,
                        refuse_archives: bool = False) -> str:
    """Return the snapshot to store with this sample, or raise PolicyRejectedError.

    The evaluation is recorded in the scan's own snapshot so the decision can
    apply it later without reading the sample again. A snapshot whose policy
    cannot be parsed is stored unchanged; the decision then withholds an allow.
    An archive inspection is recorded as ``archive_inspection`` whatever it
    found, so scan_members can later prove every member was registered.

    ``refuse_archives`` is an ICAP gateway's MASP_ICAP_BLOCK_ARCHIVES: an archive
    whose profile does not set archive handling is recorded as not allowed, so
    the gateway, the report and the API all give the same answer.
    """
    try:
        snapshot = json.loads(snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return snapshot_json
    if not isinstance(snapshot, dict):
        return snapshot_json
    if profile_rules.is_rules_policy(snapshot_policy(snapshot)):
        # A rule profile decides archives itself: the gateway's refusal does not apply.
        return _apply_rules_intake(snapshot, snapshot_json, filename=filename, size=size, storage_path=storage_path)
    try:
        policy = parse_profile_policy(snapshot_policy(snapshot))
    except ValueError:
        policy = None
    # An unreadable policy has no archive handling of its own, so the gateway refuses.
    refusing = refuse_archives and (policy is None or policy.archive_handling == "inherit")
    refused = ({"kind": "archive_refused", "detail": ARCHIVE_REFUSED_DETAIL}
               if refusing and detect_archive_format(storage_path) is not None else None)
    if policy is None or is_inherit_only(policy):
        if refused is None:
            return snapshot_json
        if policy is not None and policy.violation_action == "reject":
            raise PolicyRejectedError("archive", ARCHIVE_REFUSED_DETAIL, "archive_refused")
        snapshot["intake_policy"] = {"violations": [refused]}
        return json.dumps(snapshot, separators=(",", ":"), sort_keys=True)
    inspecting = policy.archive_handling != "inherit"
    needs_header = policy.type_rule or policy.block_masquerade or inspecting
    header = _read_header(storage_path) if needs_header else b""
    evaluation = evaluate_intake(policy, filename=filename, size=size, header=header)
    if evaluation.reject_kind is not None:
        raise PolicyRejectedError(evaluation.reject_kind, evaluation.reason, evaluation.violations[0]["kind"])
    violations = list(evaluation.violations)
    if refused is not None:
        violations.append(refused)
        if policy.violation_action == "reject":
            raise PolicyRejectedError("archive", ARCHIVE_REFUSED_DETAIL, "archive_refused")
    inspection = inspect_archive(
        storage_path, header=header, check_blocklist=_routes_hash_list(snapshot),
        member_check=lambda member_header, member_name: content_violations(
            policy, filename=member_name, header=member_header),
    ) if inspecting else None
    if inspection is not None:
        snapshot["archive_inspection"] = inspection.summary(policy.archive_handling)
        violations.extend(inspection.violations)
        # A blocklisted member is a detection, not content this client refuses:
        # it is always scanned and blocked so the scan records why.
        refused = [item for item in inspection.violations if item["kind"] != "member_blocklisted"]
        if refused and policy.violation_action == "reject":
            raise PolicyRejectedError("archive", " ".join(str(item["detail"]) for item in refused), refused[0]["kind"])
    elif not violations:
        return snapshot_json
    if violations:
        snapshot["intake_policy"] = {"violations": violations}
    return json.dumps(snapshot, separators=(",", ":"), sort_keys=True)


def _apply_rules_intake(snapshot: dict, snapshot_json: str, *, filename: str, size: int, storage_path: str) -> str:
    """Freeze the first matching rule into the snapshot; inspect an archive it asks to open."""
    try:
        policy = profile_rules.parse_rules_policy(snapshot_policy(snapshot))
    except (ValueError, TypeError):
        # Stored unchanged: the decision then withholds an allow (profile_policy_invalid).
        return snapshot_json
    header = _read_header(storage_path)
    number, rule = profile_rules.match(policy, size=size, classification=classify(header, filename))
    routed = profile_rules.routed_snapshot(snapshot, number, rule)
    if rule.action == "scan" and rule.archive in ("inspect", "members"):
        inspection = inspect_archive(
            storage_path, header=header, check_blocklist=_routes_hash_list(routed),
            member_check=lambda member_header, member_name: member_rule_violations(
                policy, filename=member_name, header=member_header),
        )
        if inspection is not None:
            routed["archive_inspection"] = inspection.summary("inspect" if rule.archive == "inspect" else "scan_members")
            if inspection.violations:
                routed["intake_policy"] = {"violations": list(inspection.violations)}
    return json.dumps(routed, separators=(",", ":"), sort_keys=True)


def route_member(parent_snapshot_json: str, *, filename: str, size: int, storage_path: str) -> str | None:
    """A rule-routed archive member's own snapshot; None when the parent is not rule-routed.

    A member is a file of its own: it takes the first rule it matches by its own
    size and type, from every engine the profile routes, never the container's
    narrowed engines or intake verdict.
    """
    try:
        parent = json.loads(parent_snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(parent, dict) or profile_rules.snapshot_rule(parent) is None:
        return None
    base = {key: value for key, value in parent.items() if key not in ("rule", "intake_policy", "archive_inspection")}
    base["engines"] = parent.get("profile_engines") if isinstance(parent.get("profile_engines"), list) else []
    return _apply_rules_intake(base, json.dumps(base), filename=filename, size=size, storage_path=storage_path)


def member_rule_violations(policy: profile_rules.RulesPolicy, *, filename: str, header: bytes) -> list[dict]:
    """Whether a rule blocks an archive member, judged when the archive is inspected.

    Inspection sees a member's header and name, not its size, so it applies the
    first rule without a size condition that the member matches. Size rules apply
    when members are scanned on their own (``members``), where the size is known.
    """
    classification = classify(header, filename)
    for number, rule in enumerate(policy.rules, start=1):
        if rule.when.larger_than_bytes is not None or rule.when.up_to_bytes is not None:
            continue
        if profile_rules.rule_matches(rule, size=0, classification=classification):
            if rule.action != "block":
                return []
            return [{"kind": "rule", "families": sorted(classification.families, key=FAMILIES.index),
                     "detail": profile_rules.block_detail(number, rule)}]
    return []


def _routes_hash_list(snapshot: dict) -> bool:
    engines = snapshot.get("engines")
    return isinstance(engines, list) and any(
        isinstance(engine, dict) and engine.get("adapter_key") == "hash_list" for engine in engines)


def archive_handling(snapshot: dict) -> str:
    """The recorded archive handling; "inherit" when the policy cannot be read."""
    treatment = profile_rules.archive_treatment(snapshot)
    if treatment is not None:
        return treatment
    try:
        return parse_profile_policy(snapshot_policy(snapshot)).archive_handling
    except (ValueError, TypeError):
        return "inherit"


def scans_every_member(snapshot_json: str) -> bool:
    """Whether intake registers every archive member for scanning.

    Only an archive that passed inspection is opened for member scanning: one
    the policy already blocks needs no further engine work.
    """
    try:
        snapshot = json.loads(snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(snapshot, dict) or archive_handling(snapshot) != "scan_members":
        return False
    inspection = snapshot.get("archive_inspection")
    return (isinstance(inspection, dict) and inspection.get("violation_total") == 0
            and inspection.get("members", 0) > 0 and "intake_policy" not in snapshot)


def _block(decision: ScanDecision, policy: str, reason: str, extra: list[str]) -> ScanDecision:
    return ScanDecision(action="block", label="Block", tone="danger", confidence="high", policy=policy,
                        reason=reason, reasons=[reason, *extra])


def apply_profile_policy(decision: ScanDecision, snapshot: dict, *, scan_role: str,
                         unfinished: list[str] | None = None) -> ScanDecision:
    """Make a computed decision as strict as the scan's frozen profile policy."""
    raw = snapshot_policy(snapshot)
    if raw in (None, {}) and "intake_policy" not in snapshot:
        return decision
    if decision.action == "wait":
        return decision
    if profile_rules.is_rules_policy(raw):
        try:
            rules = profile_rules.parse_rules_policy(raw)
        except (ValueError, TypeError):
            rules = None
        if rules is not None and profile_rules.snapshot_rule(snapshot) is not None:
            # Each rule scan, archive members included, carries its own evaluation.
            return profile_rules.apply_rules_decision(decision, snapshot, rules, unfinished)
        if decision.action == "block":
            return decision
        return ScanDecision(action="review", label="Review", tone="warning", confidence="low",
                            policy="profile_policy_invalid",
                            reason="The client's recorded profile rules could not be read.",
                            reasons=["The client's recorded profile rules could not be read.",
                                     "An allow decision is withheld until the rules are fixed."])
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
        kinds = [str(item.get("kind", "")) for item in violations or [] if isinstance(item, dict)]
        policy_name = ("profile_archive_policy" if kinds and all(kind.startswith(("archive_", "member_")) for kind in kinds)
                       else "profile_content_policy")
        # The first violation is the reason; the rest follow it.
        return _block(decision, policy_name, f"Not allowed: {details[0]}", details[1:])
    if decision.action == "review" and policy.review_action == "block":
        return _block(decision, "profile_review_block",
                      "The client's profile blocks files that could not be fully assessed.",
                      [decision.reason])
    return decision
