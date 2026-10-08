"""Profile rules: an ordered list, the first rule a file matches decides.

See docs/architecture/PROFILE_RULES.md. A rule names conditions (size range,
content families, a disguised extension) and one action: scan with chosen
engines, a light check with non-detection engines, allow without scanning, or
block. Nothing is implicit: the last rule matches every file and the result of
an inconclusive scan is chosen explicitly, so no server or gateway setting
decides a rule profile's archives or reviews.

Intake evaluates the rules once and freezes the outcome in the scan's routing
snapshot (``rule``, the narrowed ``engines`` and every ``profile_engines``);
decisions read only that snapshot. A snapshot written under the previous policy
format keeps the previous logic.
"""
from __future__ import annotations

from dataclasses import replace
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.services.content_types import FAMILIES, Classification
from app.services.decisions import ScanDecision
from app.services.engine_registry import adapter_capabilities

RULES_VERSION = 2
MAX_RULES = 50
MAX_SAFE_INTEGER = 9007199254740991
MIB = 1024 * 1024

Action = Literal["scan", "light", "allow", "block"]
ArchiveTreatment = Literal["whole", "inspect", "members"]

FAMILY_WORDS = {
    "executable": "programs", "script": "scripts", "archive": "archives", "office": "Office documents",
    "pdf": "PDF files", "image": "images", "markup": "XML files", "unrecognized": "unrecognized files",
}
ACTION_WORDS = {"scan": "Scan", "light": "Light check", "allow": "Allow without scanning", "block": "Block"}


class RuleWhen(BaseModel):
    """All given conditions must match; no condition matches every file."""
    model_config = ConfigDict(extra="forbid", strict=True)

    # Matches files strictly larger than this many bytes.
    larger_than_bytes: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)
    # Matches files of at most this many bytes.
    up_to_bytes: int | None = Field(default=None, ge=1, le=MAX_SAFE_INTEGER)
    # Matches a file belonging to any of these content families.
    families: list[str] = Field(default_factory=list, max_length=len(FAMILIES))
    # Matches a file whose declared extension contradicts its content.
    masquerade: bool = False

    @field_validator("families")
    @classmethod
    def _known_families(cls, value: list[str]) -> list[str]:
        unknown = [family for family in value if family not in FAMILIES]
        if unknown:
            raise ValueError(f"Unknown content family: {', '.join(unknown)}.")
        if len(set(value)) != len(value):
            raise ValueError("Content families must be unique.")
        return [family for family in FAMILIES if family in value]

    @model_validator(mode="after")
    def _ordered_range(self) -> "RuleWhen":
        if (self.larger_than_bytes is not None and self.up_to_bytes is not None
                and self.up_to_bytes <= self.larger_than_bytes):
            raise ValueError("The upper size must be larger than the lower size.")
        return self

    @property
    def empty(self) -> bool:
        return self == RuleWhen()

    def can_match_archives(self) -> bool:
        return not self.families or "archive" in self.families


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    when: RuleWhen = Field(default_factory=RuleWhen)
    action: Action
    engines: list[int] = Field(default_factory=list, max_length=100)
    # How a Scan rule that can match archives treats one: as one file, opened and
    # checked, or opened with every file inside scanned on its own.
    archive: ArchiveTreatment | None = None

    @field_validator("engines")
    @classmethod
    def _unique_engines(cls, value: list[int]) -> list[int]:
        if any(engine < 1 or engine > MAX_SAFE_INTEGER for engine in value) or len(set(value)) != len(value):
            raise ValueError("Engine IDs must be unique positive integers.")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> "Rule":
        if self.action in ("scan", "light") and not self.engines:
            raise ValueError(f"A {ACTION_WORDS[self.action]} rule needs at least one engine.")
        if self.action in ("allow", "block") and self.engines:
            raise ValueError(f"A {ACTION_WORDS[self.action]} rule runs no engine.")
        if self.action == "scan" and self.when.can_match_archives():
            if self.archive is None:
                raise ValueError("Choose how this rule treats archives.")
        elif self.archive is not None:
            raise ValueError("Only a Scan rule that can match archives treats archives.")
        return self


class RulesPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[2]
    rules: list[Rule] = Field(min_length=1, max_length=MAX_RULES)
    # What an inconclusive scan becomes: an engine failed or did not finish, an
    # engine asked for review, or the risk is elevated without a detection.
    inconclusive: Literal["block", "allow"]

    @model_validator(mode="after")
    def _ends_with_every_file(self) -> "RulesPolicy":
        if not self.rules[-1].when.empty:
            raise ValueError("The last rule must match every file.")
        if any(rule.when.empty for rule in self.rules[:-1]):
            raise ValueError("Only the last rule may match every file; give the others a condition.")
        if not self.engine_ids():
            raise ValueError("A profile needs at least one rule that runs an engine.")
        return self

    def engine_ids(self) -> list[int]:
        return sorted({engine for rule in self.rules for engine in rule.engines})


def engine_eligibility(adapter_key: str, enabled: bool) -> tuple[bool, str | None]:
    """Whether an engine can run for API and ICAP files, and why not."""
    try:
        capabilities = adapter_capabilities(adapter_key)
    except KeyError:
        return False, "Adapter is not registered in this deployment."
    if not enabled:
        return False, "Engine instance is disabled."
    if capabilities.consumes_external_quota:
        # Automation never spends a metered external service. This is an
        # adapter-level rule, so the engine can stay in use for manual lookups.
        return False, "Paid reputation service: used for manual lookups only, never for API or ICAP files."
    if not (capabilities.supports_file_upload or capabilities.supports_file_hash_scan):
        return False, "Adapter cannot accept a submitted file."
    return True, None


def is_rules_policy(raw: object) -> bool:
    payload = raw
    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return False
    return isinstance(payload, dict) and payload.get("version") == RULES_VERSION


def parse_rules_policy(raw: object) -> RulesPolicy:
    payload = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(payload, dict):
        raise ValueError("A rules policy must be an object.")
    return RulesPolicy.model_validate(payload)


def rules_policy_json(policy: RulesPolicy) -> str:
    return json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def size_text(value: int) -> str:
    if value >= MIB:
        number = value / MIB
        return f"{number:g} MB" if number == int(number) or number >= 10 else f"{number:.1f} MB"
    return f"{value} bytes"


def condition_text(when: RuleWhen) -> str:
    """The rule's condition in operator words, for reasons and summaries."""
    if when.empty:
        return "every other file"
    parts = []
    if when.larger_than_bytes is not None and when.up_to_bytes is not None:
        parts.append(f"size {size_text(when.larger_than_bytes)} to {size_text(when.up_to_bytes)}")
    elif when.larger_than_bytes is not None:
        parts.append(f"larger than {size_text(when.larger_than_bytes)}")
    elif when.up_to_bytes is not None:
        parts.append(f"up to {size_text(when.up_to_bytes)}")
    if when.families:
        parts.append(", ".join(FAMILY_WORDS.get(family, family) for family in when.families))
    if when.masquerade:
        parts.append("extension contradicts content")
    return "; ".join(parts)


def rule_matches(rule: Rule, *, size: int, classification: Classification) -> bool:
    when = rule.when
    if when.larger_than_bytes is not None and size <= when.larger_than_bytes:
        return False
    if when.up_to_bytes is not None and size > when.up_to_bytes:
        return False
    if when.families and not classification.families.intersection(when.families):
        return False
    if when.masquerade and not classification.mismatch:
        return False
    return True


def match(policy: RulesPolicy, *, size: int, classification: Classification) -> tuple[int, Rule]:
    """The first matching rule and its 1-based number; the last rule always matches."""
    for index, rule in enumerate(policy.rules, start=1):
        if rule_matches(rule, size=size, classification=classification):
            return index, rule
    return len(policy.rules), policy.rules[-1]


def block_detail(number: int, rule: Rule) -> str:
    return f"Blocked by rule {number} ({condition_text(rule.when)})."


def routed_snapshot(snapshot: dict, number: int, rule: Rule) -> dict:
    """Freeze one rule's routing into a scan snapshot.

    ``profile_engines`` keeps every engine the profile routes, so archive members
    can be evaluated later; ``engines`` narrows to this rule's engines, which is
    what engine jobs, coverage and retries read.
    """
    routed = {key: value for key, value in snapshot.items()
              if key not in ("rule", "intake_policy", "archive_inspection")}
    profile_engines = snapshot.get("profile_engines")
    if not isinstance(profile_engines, list):
        profile_engines = snapshot.get("engines") if isinstance(snapshot.get("engines"), list) else []
    chosen = set(rule.engines)
    routed["profile_engines"] = profile_engines
    routed["engines"] = [engine for engine in profile_engines
                         if isinstance(engine, dict) and engine.get("id") in chosen]
    routed["rule"] = {"number": number, "action": rule.action, "condition": condition_text(rule.when),
                      **({"archive": rule.archive} if rule.archive else {})}
    if rule.action == "block":
        routed["intake_policy"] = {"violations": [{"kind": "rule_block", "detail": block_detail(number, rule)}]}
    return routed


def routing(snapshot_json: str) -> tuple[str, set[int]] | None:
    """The matched rule's action and engine IDs, once intake has routed a snapshot."""
    try:
        snapshot = json.loads(snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return None
    rule = snapshot_rule(snapshot) if isinstance(snapshot, dict) else None
    if rule is None:
        return None
    engines = snapshot.get("engines")
    ids = {int(entry["id"]) for entry in engines or [] if isinstance(entry, dict) and isinstance(entry.get("id"), int)}
    return str(rule["action"]), ids


def narrow(engines: list, snapshot_json: str) -> tuple[list, str | None]:
    """The engines a routed file runs, and the rule action to record with it.

    A scan or light rule whose engines are all unavailable now yields no engine;
    the caller refuses intake as it does for a profile with no eligible engine.
    """
    routed = routing(snapshot_json)
    if routed is None:
        return engines, None
    action, ids = routed
    if action in ("allow", "block"):
        return [], action
    return [engine for engine in engines if engine.id in ids], action


def without_engines(snapshot_json: str) -> str:
    """A routed snapshot whose rule's engines are all unavailable, recorded as blocked."""
    snapshot = json.loads(snapshot_json)
    rule = snapshot_rule(snapshot) or {}
    snapshot["engines"] = []
    snapshot["intake_policy"] = {"violations": [{"kind": "rule_block", "detail":
        f"No engine of rule {rule.get('number')} ({rule.get('condition')}) is available."}]}
    return json.dumps(snapshot, separators=(",", ":"), sort_keys=True)


def snapshot_rule(snapshot: dict) -> dict | None:
    rule = snapshot.get("rule")
    return rule if isinstance(rule, dict) and rule.get("action") in ACTION_WORDS else None


def archive_treatment(snapshot: dict) -> str | None:
    """The recorded archive treatment of a rule scan, in the previous names."""
    rule = snapshot_rule(snapshot)
    if rule is None:
        return None
    return {"inspect": "inspect", "members": "scan_members"}.get(str(rule.get("archive")), "inherit")


# Decisions that mean "not conclusive": nothing detected, but the scan cannot
# vouch for the file. A rule profile turns each into its chosen block or allow.
INCONCLUSIVE = {"scan_failed", "partial_coverage", "engine_policy_review", "elevated_risk", "metadata_only"}


def _block(decision: ScanDecision, policy: str, reason: str, extra: list[str]) -> ScanDecision:
    return ScanDecision(action="block", label="Block", tone="danger", confidence="high", policy=policy,
                        reason=reason, reasons=[reason, *extra])


def _allow(policy: str, label: str, reason: str, extra: list[str]) -> ScanDecision:
    return ScanDecision(action="allow", label=label, tone="warning", confidence="medium", policy=policy,
                        reason=reason, reasons=[reason, *extra])


def unfinished_checks(snapshot: dict, results: list) -> list[str]:
    """The checks the matched rule chose that did not complete, as "<name> <status>".

    Antivirus coverage counts only detection engines; this covers every engine
    the rule names, File Type and Hash List included. A check that did not run
    is not a check that found nothing.
    """
    rule = snapshot_rule(snapshot)
    if rule is None or rule.get("action") not in ("scan", "light"):
        return []
    by_name = {str(result.engine_name).lower(): result for result in results}
    unfinished = []
    for entry in snapshot.get("engines") or []:
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        name = str(entry["name"])
        result = by_name.get(name.lower())
        if result is None:
            unfinished.append(f"{name} missing")
        elif result.status != "completed":
            unfinished.append(f"{name} {result.status}")
    return unfinished


def _inconclusive(policy: RulesPolicy, decision: ScanDecision, why: str) -> ScanDecision:
    if policy.inconclusive == "block":
        return _block(decision, "profile_inconclusive_block",
                      "The result is not conclusive, and this client's profile blocks such files.", [why])
    return _allow("profile_inconclusive_allow", "Allow (not fully scanned)",
                  "The result is not conclusive; this client's profile allows such files.", [why])


def apply_rules_decision(decision: ScanDecision, snapshot: dict, policy: RulesPolicy,
                         unfinished: list[str] | None = None) -> ScanDecision:
    """Turn a computed decision into a rule profile's explicit block or allow.

    ``unfinished`` lists the rule's checks that did not complete
    (``unfinished_checks``): any one makes the result inconclusive, so a failed
    Hash List lookup can never become "Allow (light check only)".
    """
    rule = snapshot_rule(snapshot)
    if decision.action == "wait":
        return decision
    intake = snapshot.get("intake_policy")
    violations = intake.get("violations") if isinstance(intake, dict) else None
    details = [str(item.get("detail")) for item in violations or [] if isinstance(item, dict)]
    if details:
        if decision.action == "block" and decision.policy == "malware_detected":
            return replace(decision, reasons=[*decision.reasons, *details])
        kinds = [str(item.get("kind", "")) for item in violations or [] if isinstance(item, dict)]
        name = ("profile_rule_block" if kinds == ["rule_block"]
                else "profile_archive_policy" if all(kind.startswith(("archive_", "member_")) for kind in kinds)
                else "profile_content_policy")
        return _block(decision, name, f"Not allowed: {details[0]}", details[1:])
    if decision.action == "block":
        return decision
    action = rule.get("action") if rule else None
    number = rule.get("number") if rule else None
    if action == "allow":
        return _allow("profile_rule_not_scanned", "Allow (not scanned)",
                      f"Allowed without scanning by rule {number} ({rule.get('condition')}).", [])
    if unfinished:
        return _inconclusive(policy, decision, f"Not every check of rule {number} completed: {', '.join(unfinished)}.")
    if action == "light" and decision.policy == "metadata_only":
        return _allow("profile_rule_light_check", "Allow (light check only)",
                      f"Light check only (rule {number}): no antivirus engine ran, and the checks found nothing.", [])
    if decision.action == "review" or decision.policy in INCONCLUSIVE:
        return _inconclusive(policy, decision, decision.reason)
    return decision


def from_previous_policy(policy, engine_ids: list[int], *, detection_engine_ids: set[int],
                         receives_icap: bool, gateway_blocks_review: bool) -> RulesPolicy:
    """The rule list that behaves like a profile written in the previous format.

    ``policy`` is a ``profile_policy.ProfilePolicy``. Behaviour that depended on
    an ICAP gateway setting is fixed at the value the gateway used: a client that
    receives ICAP traffic and inherited archive handling had every archive
    refused (the gateway default), and an inherited review followed
    MASP_ICAP_BLOCK_ON_REVIEW. Without ICAP traffic, archives were scanned as one
    file and an inherited review becomes a block, since review is no answer now.
    A profile whose engines include no detection engine never scanned for
    malware, so its scan rules become light checks.
    """
    if not engine_ids:
        raise ValueError("A profile without engines cannot be converted.")
    engines = sorted(set(engine_ids))
    scan: Action = "scan" if detection_engine_ids.intersection(engines) else "light"

    def scanning(when: RuleWhen, archive: ArchiveTreatment) -> Rule:
        if scan == "light":
            return Rule(when=when, action="light", engines=engines)
        return Rule(when=when, action="scan", engines=engines, archive=archive if when.can_match_archives() else None)
    rules: list[Rule] = []
    if policy.max_file_bytes is not None:
        rules.append(Rule(when=RuleWhen(larger_than_bytes=policy.max_file_bytes), action="block"))
    if policy.block_masquerade:
        rules.append(Rule(when=RuleWhen(masquerade=True), action="block"))
    type_rule = policy.type_rule
    if type_rule is not None and type_rule.mode == "denylist":
        rules.append(Rule(when=RuleWhen(families=list(type_rule.families)), action="block"))
    handling = policy.archive_handling
    if handling in ("inspect", "scan_members"):
        rules.append(scanning(RuleWhen(families=["archive"]), "inspect" if handling == "inspect" else "members"))
    elif receives_icap:
        rules.append(Rule(when=RuleWhen(families=["archive"]), action="block"))
    if type_rule is not None and type_rule.mode == "allowlist":
        rules.append(scanning(RuleWhen(families=list(type_rule.families)), "whole"))
        rules.append(Rule(action="block"))
    else:
        rules.append(scanning(RuleWhen(), "whole"))
    if policy.review_action == "block":
        inconclusive = "block"
    elif receives_icap:
        inconclusive = "block" if gateway_blocks_review else "allow"
    else:
        inconclusive = "block"
    return RulesPolicy(version=2, rules=rules, inconclusive=inconclusive)
