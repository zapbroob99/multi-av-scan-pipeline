"""Per-location storage protection policy: which tier a file gets, and what the
light tier treats as a finding.

The policy is validated in full before it is stored, and stored with a
revision so every inspected object records which policy judged it.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.services.content_types import FAMILIES, Classification

TIERS = ("full", "light")
MAX_TIER_RULES = 50
MAX_IGNORE_PATTERNS = 50
MAX_PATTERN_LENGTH = 256
DEFAULT_IGNORE_PATTERNS = ("*.tmp", "~$*", "*.partial", "*.crdownload", ".~lock.*")
DEFAULT_HASH_MAX_BYTES = 10 * 1024 ** 3


def _pattern(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned or len(cleaned) > MAX_PATTERN_LENGTH or "\x00" in cleaned:
        raise ValueError(f"Patterns must be 1 to {MAX_PATTERN_LENGTH} characters.")
    return cleaned


class TierRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Matched against the path relative to the location prefix, so a rule
    # keeps meaning the same thing if the location is moved.
    pattern: str = "*"
    min_bytes: int | None = Field(default=None, ge=0)
    max_bytes: int | None = Field(default=None, ge=0)
    tier: Literal["full", "light"]

    @field_validator("pattern")
    @classmethod
    def _check_pattern(cls, value: str) -> str:
        return _pattern(value)

    @model_validator(mode="after")
    def _ordered_range(self) -> "TierRule":
        if self.min_bytes is not None and self.max_bytes is not None and self.min_bytes > self.max_bytes:
            raise ValueError("min_bytes must not exceed max_bytes.")
        return self

    def matches(self, relative_path: str, size: int) -> bool:
        if self.min_bytes is not None and size < self.min_bytes:
            return False
        if self.max_bytes is not None and size > self.max_bytes:
            return False
        name = relative_path.rsplit("/", 1)[-1]
        return fnmatchcase(relative_path, self.pattern) or ("/" not in self.pattern and fnmatchcase(name, self.pattern))


class TypePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # allowlist: only these families may appear. denylist: these must not.
    mode: Literal["allowlist", "denylist"] = "denylist"
    families: list[str] = Field(default_factory=lambda: ["executable", "script"], max_length=len(FAMILIES))

    @field_validator("families")
    @classmethod
    def _known_families(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(FAMILIES))
        if unknown:
            raise ValueError(f"Unknown content families: {', '.join(unknown)}.")
        return sorted(set(value), key=FAMILIES.index)


class HashCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    # Hashing reads the whole file. Above this size the light tier inspects the
    # header only and records that no hash was computed.
    max_bytes: int = Field(default=DEFAULT_HASH_MAX_BYTES, ge=0)


class StoragePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_tier: Literal["full", "light"] = "full"
    tier_rules: list[TierRule] = Field(default_factory=list, max_length=MAX_TIER_RULES)
    type_policy: TypePolicy = Field(default_factory=TypePolicy)
    # A header cannot show what an archive holds, so by default an archive in
    # a light location is escalated to the full tier.
    archive_action: Literal["full", "allow", "detect"] = "full"
    hash_check: HashCheck = Field(default_factory=HashCheck)
    ignore_patterns: list[str] = Field(default_factory=lambda: list(DEFAULT_IGNORE_PATTERNS),
                                       max_length=MAX_IGNORE_PATTERNS)
    stability_seconds: int = Field(default=60, ge=5, le=86400)
    crawl_interval_seconds: int = Field(default=300, ge=10, le=86400)
    crawl_entries_per_cycle: int = Field(default=5000, ge=100, le=100000)
    inspections_per_cycle: int = Field(default=500, ge=10, le=10000)

    @field_validator("ignore_patterns")
    @classmethod
    def _patterns(cls, value: list[str]) -> list[str]:
        return [_pattern(item) for item in value]


def parse_policy(raw: str | dict | None) -> StoragePolicy:
    """Parse stored or submitted policy; raises ValueError on anything invalid."""
    if raw is None or raw == "":
        return StoragePolicy()
    payload = json.loads(raw) if isinstance(raw, str) else raw
    return StoragePolicy.model_validate(payload)


def policy_json(policy: StoragePolicy) -> str:
    return json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def ignored(policy: StoragePolicy, name: str) -> bool:
    return any(fnmatchcase(name, pattern) for pattern in policy.ignore_patterns)


def choose_tier(policy: StoragePolicy, relative_path: str, size: int) -> str:
    for rule in policy.tier_rules:
        if rule.matches(relative_path, size):
            return rule.tier
    return policy.default_tier


@dataclass(frozen=True)
class LightFinding:
    kind: str
    severity: str
    detected: bool
    title: str
    detail: dict


@dataclass(frozen=True)
class LightOutcome:
    findings: tuple[LightFinding, ...]
    # True when the archive action sends this object to the full tier instead.
    escalate_to_full: bool = False

    @property
    def detected(self) -> bool:
        return any(item.detected for item in self.findings)


_CODE_FAMILIES = frozenset({"executable", "script"})


def evaluate_light(policy: StoragePolicy, classification: Classification,
                   hash_list_kind: str | None) -> LightOutcome:
    """Judge one classified object. Never returns a clean verdict: an empty
    outcome means "nothing the light tier checks for", not "no malware"."""
    findings: list[LightFinding] = []
    families = set(classification.families)
    base = {"detected_type": classification.detected_type, "extension": classification.extension or None,
            "families": sorted(families)}

    if "archive" in families:
        if policy.archive_action == "full":
            return LightOutcome(findings=(), escalate_to_full=True)
        if policy.archive_action == "detect":
            findings.append(LightFinding(
                "archive_policy", "medium", True,
                "Archive found in a location that does not accept archives", base))
        # "allow" and "detect" both settle the archive here; its family is not
        # judged again by the type policy.
        families.discard("archive")

    rules = set(policy.type_policy.families)
    if policy.type_policy.mode == "denylist":
        violating = sorted(families & rules)
    else:
        violating = sorted(families - rules)
    if violating:
        code = bool(set(violating) & _CODE_FAMILIES)
        findings.append(LightFinding(
            "type_policy", "high" if code else "medium", True,
            f"Content family not permitted here: {', '.join(violating)}",
            {**base, "mode": policy.type_policy.mode, "violating": violating}))

    if classification.mismatch:
        # A disguised executable is the case this check exists for; any other
        # disguise is worth recording but is not by itself a detection.
        code = classification.content_family in _CODE_FAMILIES
        findings.append(LightFinding(
            "type_mismatch", "high" if code else "medium", code,
            f"Declared .{classification.extension} content is actually {classification.detected_type}",
            {**base, "expected_types": sorted(classification.expected_types or ())}))

    if hash_list_kind == "block":
        findings.append(LightFinding("hash_block", "high", True, "SHA-256 is on the institution blocklist", base))
    return LightOutcome(findings=tuple(findings))
