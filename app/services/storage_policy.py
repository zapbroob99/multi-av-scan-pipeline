"""A protected location's own settings, and how a profile rule judges one stored object.

What happens to a file is decided by the location's profile rules
(app/services/profile_rules.py), the same rules API and ICAP files follow. A
location keeps only what is about discovery itself: which names to ignore, how
long a file must stop changing, and how much work one cycle does. The settings
are validated in full before they are stored, and stored with a revision so
every inspected object records which settings judged it.

Settings written before profile rules also held tier rules, a type policy, an
archive action and a hash check. Those fields are dropped when read: the
profile's rules replaced them.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
import json

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.services.content_types import Classification
from app.services.profile_rules import Rule, condition_text

MAX_IGNORE_PATTERNS = 50
MAX_PATTERN_LENGTH = 256
DEFAULT_IGNORE_PATTERNS = ("*.tmp", "~$*", "*.partial", "*.crdownload", ".~lock.*")
# Fields of the settings format before profile rules; ignored when read.
PREVIOUS_FIELDS = ("default_tier", "tier_rules", "type_policy", "archive_action", "hash_check")


def _pattern(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned or len(cleaned) > MAX_PATTERN_LENGTH or "\x00" in cleaned:
        raise ValueError(f"Patterns must be 1 to {MAX_PATTERN_LENGTH} characters.")
    return cleaned


class StoragePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    """Parse stored or submitted settings; raises ValueError on anything invalid."""
    if raw is None or raw == "":
        return StoragePolicy()
    payload = json.loads(raw) if isinstance(raw, str) else raw
    if isinstance(payload, dict):
        payload = {key: value for key, value in payload.items() if key not in PREVIOUS_FIELDS}
    return StoragePolicy.model_validate(payload)


def policy_json(policy: StoragePolicy) -> str:
    return json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def ignored(policy: StoragePolicy, name: str) -> bool:
    return any(fnmatchcase(name, pattern) for pattern in policy.ignore_patterns)


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

    @property
    def detected(self) -> bool:
        return any(item.detected for item in self.findings)


_CODE_FAMILIES = frozenset({"executable", "script"})


def judge(number: int, rule: Rule, classification: Classification, *, checks: set[str],
          hash_list_kind: str | None) -> LightOutcome:
    """Judge one object a Block or Light check rule matched. Never returns a clean
    verdict: an empty outcome means "nothing these checks look for", not "no malware".

    ``checks`` are the adapter keys of the rule's engines that are available
    now; a light check runs only the checks its rule names.
    """
    families = set(classification.families)
    base = {"detected_type": classification.detected_type, "extension": classification.extension or None,
            "families": sorted(families), "rule": number}
    if rule.action == "block":
        return LightOutcome(findings=(LightFinding(
            "rule_block", "high" if families & _CODE_FAMILIES else "medium", True,
            f"Blocked by rule {number} ({condition_text(rule.when)})", base),))
    findings: list[LightFinding] = []
    if "file_type" in checks and classification.mismatch:
        # A disguised executable is the case this check exists for; any other
        # disguise is worth recording but is not by itself a detection.
        code = classification.content_family in _CODE_FAMILIES
        findings.append(LightFinding(
            "type_mismatch", "high" if code else "medium", code,
            f"Declared .{classification.extension} content is actually {classification.detected_type}",
            {**base, "expected_types": sorted(classification.expected_types or ())}))
    if "hash_list" in checks and hash_list_kind == "block":
        findings.append(LightFinding("hash_block", "high", True, "SHA-256 is on the institution blocklist", base))
    return LightOutcome(findings=tuple(findings))
