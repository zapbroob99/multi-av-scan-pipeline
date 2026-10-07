"""What happens to a client's files under one scan profile, in operator words.

Every input already exists: the profile's file rules, its engines, the server's
upload limit and each ICAP gateway's own settings (reported in its activity
record). An operator used to have to combine them in their head -- a clean zip
blocked over ICAP while the profile said nothing about archives was the pilot's
first support call. This module combines them in one place and changes nothing:
it reads no data itself and decides nothing a scan uses.

A setting that no gateway has reported is unknown, never assumed: a gateway
record from an older release lacks the newer fields, and a client without a
reporting gateway has no ICAP answer at all. Only the default profile serves
ICAP, so a named profile's ICAP column says so instead of guessing.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Literal

from pydantic import BaseModel

from app.services.engine_registry import adapter_capabilities
from app.services.profile_policy import ProfilePolicy

FAMILY_WORDS = {
    "executable": "programs", "script": "scripts", "archive": "archives", "office": "Office documents",
    "pdf": "PDF files", "image": "images", "markup": "XML files", "unrecognized": "unrecognized files",
}


class EngineOutcome(BaseModel):
    id: int
    display_name: str
    runs: bool
    reason: str | None


class Outcome(BaseModel):
    topic: Literal["size", "content", "archives", "unassessed", "unfinished"]
    label: str
    api: str
    icap: str
    # False when the ICAP answer depends on a setting no gateway has reported.
    icap_known: bool


class ProfileOutcome(BaseModel):
    engines: list[EngineOutcome]
    # Which gateways the ICAP column describes: none when the profile is not the
    # default, or when no gateway reports for this client.
    icap: Literal["gateway", "no_gateway", "not_default"]
    icap_ports: list[int]
    lines: list[Outcome]


def engine_eligibility(adapter_key: str, enabled: bool) -> tuple[bool, str | None]:
    """Whether an assigned engine runs for API and ICAP files, and why not."""
    try:
        capabilities = adapter_capabilities(adapter_key)
    except KeyError:
        return False, "Adapter is not registered in this deployment."
    if not enabled:
        return False, "Engine instance is disabled."
    if capabilities.consumes_external_quota:
        # Automation never spends a metered external service. This is an
        # adapter-level rule, so the engine can stay assigned for manual use.
        return False, "Paid reputation service: used for manual lookups only, never for API or ICAP files."
    if not (capabilities.supports_file_upload or capabilities.supports_file_hash_scan):
        return False, "Adapter cannot accept a submitted file."
    return True, None


def size_text(value: int) -> str:
    for unit, scale in (("GiB", 1024 ** 3), ("MiB", 1024 ** 2), ("KiB", 1024)):
        if value >= scale:
            number = value / scale
            return f"{number:.0f} {unit}" if number >= 10 or number == int(number) else f"{number:.1f} {unit}"
    return f"{value} B"


def _per_gateway(gateways: list[Mapping], describe) -> tuple[str, bool]:
    """One ICAP answer, or each gateway's when they disagree."""
    answers = [describe(gateway) for gateway in gateways]
    known = all(known for _, known in answers)
    texts = [text for text, _ in answers]
    if len(set(texts)) == 1:
        return texts[0], known
    return " ".join(f"Port {gateway.get('port')}: {text}" for gateway, text in zip(gateways, texts)), known


def _sentence(parts: list[str]) -> str:
    text = "; ".join(parts)
    return text[:1].upper() + text[1:]


def _words(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _content_rules(policy: ProfilePolicy) -> list[str]:
    rules = []
    if policy.type_rule:
        words = _words([FAMILY_WORDS.get(family, family) for family in policy.type_rule.families])
        rules.append(f"only {words} are accepted" if policy.type_rule.mode == "allowlist" else f"{words} are not accepted")
    if policy.block_masquerade:
        rules.append("files whose extension contradicts their content are not accepted")
    return rules


def describe(policy: ProfilePolicy, engines: Iterable[Mapping], *, is_default: bool,
             gateways: list[Mapping], upload_cap: int) -> ProfileOutcome:
    """Combine one profile's rules with the server and gateway settings.

    ``gateways`` are the activity records of gateways bound to this client that
    are still reporting; ``upload_cap`` is the resolved server upload limit (0:
    none). Wording mirrors what intake, ``scan_decision`` and the ICAP gateway do.
    """
    engine_rows = []
    for row in engines:
        runs, reason = engine_eligibility(str(row["adapter_key"]), bool(row["enabled"]))
        engine_rows.append(EngineOutcome(id=int(row["id"]), display_name=str(row["display_name"]), runs=runs, reason=reason))

    if not is_default:
        icap_mode = "not_default"
    elif gateways:
        icap_mode = "gateway"
    else:
        icap_mode = "no_gateway"

    def icap(describe_gateway, *, needs_gateway: bool = True, fixed: str | None = None) -> tuple[str, bool]:
        if icap_mode == "not_default":
            return "Not used: an ICAP gateway always uses the default profile.", True
        if fixed is not None and not needs_gateway:
            return fixed, True
        if icap_mode == "no_gateway":
            return "Unknown: no ICAP gateway reports for this client.", False
        return _per_gateway(gateways, describe_gateway)

    lines: list[Outcome] = []

    # Size. A profile limit refuses at intake whatever the fail mode; the
    # gateway's own limit is checked before storing and follows the fail mode.
    profile_cap = policy.max_file_bytes
    caps = [cap for cap in (profile_cap, upload_cap or None) if cap]
    if not caps:
        api_size = "No limit in MASP; the server's request size limit still applies."
    elif profile_cap and profile_cap == min(caps):
        api_size = f"Files over {size_text(profile_cap)} are refused without scanning (HTTP 413)."
    else:
        api_size = f"Files over {size_text(upload_cap)} are refused without scanning (HTTP 413, server setting)."

    def gateway_size(gateway: Mapping) -> tuple[str, bool]:
        limit = gateway.get("max_bytes")
        parts: list[tuple[int, str]] = []
        if limit:
            fallback = ("blocked (gateway limit)." if gateway.get("fail_closed", True)
                        else "allowed without scanning (gateway limit, fail-open).")
            parts.append((int(limit), f"Files over {size_text(int(limit))}: {fallback}"))
        if profile_cap and not (limit and int(limit) <= profile_cap):
            parts.append((profile_cap, f"Files over {size_text(profile_cap)}: blocked as Not allowed."))
        if limit is None:
            text = " ".join(text for _, text in sorted(parts)) + (" " if parts else "")
            return text + "The gateway's own limit is unknown (it does not report it).", False
        if not parts:
            return "No size limit.", True
        return " ".join(text for _, text in sorted(parts)), True

    text, known = icap(gateway_size)
    lines.append(Outcome(topic="size", label="Large files", api=api_size, icap=text, icap_known=known))

    # Content rules: the profile alone decides, the same way for both paths.
    rules = _content_rules(policy)
    if not rules:
        content = "No content rule: every file type is scanned."
        api_content = icap_content = content
    elif policy.violation_action == "reject":
        sentence = _sentence(rules)
        api_content = f"{sentence}. A file that breaks a rule is refused without scanning (HTTP 415); no scan record is kept."
        icap_content = f"{sentence}. A file that breaks a rule is blocked without scanning; no scan record is kept."
    else:
        sentence = _sentence(rules)
        api_content = icap_content = f"{sentence}. A file that breaks a rule is still scanned, then blocked and listed as Not allowed."
    text, known = icap(None, needs_gateway=False, fixed=icap_content)
    lines.append(Outcome(topic="content", label="File types", api=api_content, icap=text, icap_known=known))

    # Archives.
    handling = policy.archive_handling
    if handling == "inspect":
        api_archive = ("Scanned as one file and opened by MASP: encrypted, damaged, oversized or unsupported archives "
                       "(RAR, CAB) and refused files inside are blocked as Not allowed.")
        text, known = icap(None, needs_gateway=False, fixed=api_archive)
    elif handling == "scan_members":
        api_archive = ("Opened by MASP and every file inside is also scanned; the archive is allowed only when all "
                       "of them are.")

        def gateway_members(gateway: Mapping) -> tuple[str, bool]:
            wait = gateway.get("wait_seconds")
            if wait is None:
                return api_archive + " The gateway's wait time is unknown.", False
            return api_archive + f" The gateway waits up to {int(wait)} s for all of them.", True
        text, known = icap(gateway_members)
    else:
        api_archive = "Scanned as one file; MASP does not look inside."

        def gateway_archives(gateway: Mapping) -> tuple[str, bool]:
            refuse = gateway.get("block_archives")
            if refuse is None:
                return "Unknown: the gateway does not report whether it refuses archives.", False
            if refuse:
                return ("Every zip, 7z and tar is blocked as Not allowed (gateway setting). "
                        "Choose Check archives to scan them instead."), True
            return api_archive, True
        text, known = icap(gateway_archives)
    lines.append(Outcome(topic="archives", label="Archives", api=api_archive, icap=text, icap_known=known))

    # An engine failed or timed out and nothing was detected: the decision is review.
    if policy.review_action == "block":
        text, known = icap(None, needs_gateway=False, fixed="Blocked (this profile's rule).")
        lines.append(Outcome(topic="unassessed", label="An engine fails", api="Blocked (this profile's rule).",
                             icap=text, icap_known=known))
    else:
        def gateway_review(gateway: Mapping) -> tuple[str, bool]:
            return ("Blocked (gateway setting)." if gateway.get("block_on_review")
                    else "Allowed (gateway setting), although not every engine checked it."), True
        text, known = icap(gateway_review)
        lines.append(Outcome(topic="unassessed", label="An engine fails",
                             api="Answered as review: the integration decides.", icap=text, icap_known=known))

    # No verdict in time, or MASP unreachable: the gateway's fail mode decides.
    def gateway_unfinished(gateway: Mapping) -> tuple[str, bool]:
        wait = gateway.get("wait_seconds")
        within = f"within {int(wait)} s" if wait is not None else "within the gateway's wait time"
        action = "blocked" if gateway.get("fail_closed", True) else "allowed without a verdict"
        return f"Not finished {within}, or MASP unavailable: {action} (gateway fail mode).", wait is not None
    text, known = icap(gateway_unfinished)
    lines.append(Outcome(topic="unfinished", label="No verdict in time",
                         api="The integration is told to ask again later and keeps polling.", icap=text, icap_known=known))

    return ProfileOutcome(engines=engine_rows, icap=icap_mode,
                          icap_ports=sorted({int(g.get("port") or 0) for g in gateways}) if icap_mode == "gateway" else [],
                          lines=lines)
