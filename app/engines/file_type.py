"""Header inspection: compare the declared file type against the actual bytes.

This reads a bounded header, never the whole file, so its cost does not grow
with sample size. It is not an antivirus engine and reports no malware verdict;
a mismatch between a declared extension and the real content is a masquerade
indicator an analyst still has to judge.
"""
import json
import os
from time import perf_counter

from app.models import EngineResultInput, ScanRecord
from app.services.content_types import (  # noqa: F401 - re-exported for callers
    EXECUTABLE_TYPES,
    EXTENSION_TYPES,
    SIGNATURES,
    declared_extension,
    detect_type,
)
from app.services.findings import evidence_object, normalized_finding
from app.services.sample_paths import resolve_sample_path, sample_path_error


ENGINE_NAME = "File Type"
DEFAULT_HEADER_BYTES = 4096
MIN_HEADER_BYTES = 512
MAX_HEADER_BYTES = 1024 * 1024


def _bounded_int(value: object, default: int, low: int, high: int) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(low, min(parsed, high))


def get_file_type_config(config_override: dict[str, str] | None = None) -> dict[str, object]:
    override = config_override or {}

    def setting(key: str, env_key: str, fallback: str) -> str:
        # A present-but-empty override means unset, matching the ClamAV and
        # Defender resolution fixed in the pilot follow-ups.
        value = override.get(key)
        if value is None or not str(value).strip():
            value = os.getenv(env_key, "").strip() or fallback
        return str(value).strip()

    action = setting("mismatch_action", "MASP_FILE_TYPE_MISMATCH_ACTION", "report").lower()
    return {
        "header_bytes": _bounded_int(
            setting("header_bytes", "MASP_FILE_TYPE_HEADER_BYTES", str(DEFAULT_HEADER_BYTES)),
            DEFAULT_HEADER_BYTES, MIN_HEADER_BYTES, MAX_HEADER_BYTES,
        ),
        # "report" records the mismatch as a finding only. "detect" also marks
        # the result detected, which the shared scoring layer treats like any
        # other engine detection. Default stays "report": a masquerading
        # extension is a strong signal but it is not a malware identification.
        "mismatch_action": action if action in {"report", "detect"} else "report",
    }


def check_file_type_health(config_override: dict[str, str] | None = None) -> dict[str, str | bool]:
    config = get_file_type_config(config_override)
    return {
        "ok": True,
        "status": "available",
        "detail": f"Header inspection ready; reads at most {config['header_bytes']} bytes per sample.",
        "product_version": "builtin",
        "engine_version": "builtin",
        "service_state": "available",
    }


def run_file_type_engine(scan: ScanRecord, config_override: dict[str, str] | None = None) -> EngineResultInput:
    started_at = perf_counter()
    config = get_file_type_config(config_override)
    sample_path = resolve_sample_path(scan)
    if not sample_path.is_file():
        return _result(scan, config, status="skipped", severity="info",
                       raw_output=sample_path_error(scan, sample_path),
                       error_message="Sample file is not available to this worker.",
                       started_at=started_at)
    try:
        with sample_path.open("rb") as handle:
            header = handle.read(int(config["header_bytes"]))
    except OSError as error:
        return _result(scan, config, status="failed", severity="info",
                       raw_output=f"Unable to read sample header: {error}",
                       error_message=str(error), started_at=started_at)

    detected_type = detect_type(header)
    extension = declared_extension(scan.original_filename)
    expected = EXTENSION_TYPES.get(extension)
    details: dict[str, object] = {
        "adapter": "file_type",
        "declared_extension": extension or None,
        "declared_content_type": scan.content_type or None,
        "detected_type": detected_type,
        "expected_types": sorted(expected) if expected else None,
        "header_bytes_read": len(header),
        "header_bytes_limit": config["header_bytes"],
        "mismatch_action": config["mismatch_action"],
    }

    if detected_type is None:
        details["outcome"] = "undetermined"
        summary = "No known signature matched the header; the content type could not be determined."
    elif expected is None:
        details["outcome"] = "undeclared"
        summary = f"Header matched {detected_type}; the filename declares no known extension to compare."
    elif detected_type in expected:
        details["outcome"] = "match"
        summary = f"Header matched {detected_type}, consistent with the declared .{extension} extension."
    else:
        details["outcome"] = "mismatch"
        summary = (f"Header matched {detected_type} but the filename declares .{extension}, "
                   f"which expects {', '.join(sorted(expected))}.")

    if details["outcome"] != "mismatch":
        return _result(scan, config, status="completed", severity="info",
                       raw_output=summary, details=details, started_at=started_at)

    executable = detected_type in EXECUTABLE_TYPES
    severity = "high" if executable else "medium"
    finding = normalized_finding(
        title=f"Declared .{extension} content is actually {detected_type}",
        finding_type="file_type_mismatch",
        source=ENGINE_NAME,
        severity=severity,
        confidence=90 if executable else 70,
        target=scan.original_filename[:512],
        category="masquerade",
        tags=["file-type", "masquerade"] + (["executable"] if executable else []),
        evidence={"header": evidence_object(
            kind="magic_bytes", value=detected_type,
            location=f"offset 0..{len(header)}",
            metadata={"declared_extension": extension, "expected_types": sorted(expected)},
        )},
        vendor_details={"summary": summary},
    )
    return _result(scan, config, status="completed", severity=severity,
                   detected=config["mismatch_action"] == "detect",
                   signature=f"TypeMismatch.{extension}-is-{detected_type}",
                   raw_output=summary, details=details, findings=[finding],
                   confidence=90 if executable else 70, started_at=started_at)


def _result(scan: ScanRecord, config: dict[str, object], *, status: str, severity: str,
            raw_output: str, started_at: float, details: dict[str, object] | None = None,
            findings: list[dict[str, object]] | None = None, detected: bool = False,
            signature: str | None = None, error_message: str | None = None,
            confidence: int = 100) -> EngineResultInput:
    return EngineResultInput(
        engine_name=ENGINE_NAME,
        engine_version="builtin",
        signature_version=None,
        status=status,
        detected=detected,
        signature=signature,
        severity=severity,
        confidence=confidence,
        raw_output=raw_output,
        error_message=error_message,
        duration_ms=max(1, int((perf_counter() - started_at) * 1000)),
        details_json=json.dumps(details or {"adapter": "file_type"}, sort_keys=True),
        findings_json=json.dumps(findings or [], sort_keys=True),
    )
