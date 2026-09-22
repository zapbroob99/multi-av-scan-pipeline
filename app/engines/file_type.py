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
from app.services.findings import evidence_object, normalized_finding
from app.services.sample_paths import resolve_sample_path, sample_path_error


ENGINE_NAME = "File Type"
DEFAULT_HEADER_BYTES = 4096
MIN_HEADER_BYTES = 512
MAX_HEADER_BYTES = 1024 * 1024

# (offset, magic, type key). Ordered most specific first: a prefix that is also
# the prefix of another format must come after the longer one.
SIGNATURES: tuple[tuple[int, bytes, str], ...] = (
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"GIF87a", "gif"),
    (0, b"GIF89a", "gif"),
    (0, b"%PDF-", "pdf"),
    (0, b"{\\rtf", "rtf"),
    (0, b"\x7fELF", "elf"),
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip"),
    (0, b"PK\x07\x08", "zip"),
    (0, b"\xca\xfe\xba\xbe", "java_class"),
    (0, b"\xff\xd8\xff", "jpeg"),
    (0, b"MSCF", "cab"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"<?xml", "xml"),
    (0, b"#!", "script"),
    (0, b"MZ", "pe"),
    (0, b"BM", "bmp"),
    (257, b"ustar", "tar"),
)

# Extensions an operator is likely to see, mapped to the content families that
# are legitimate for them. OOXML and JAR/APK are ZIP containers; legacy Office
# is OLE2. An extension absent here is treated as undeclared, never a mismatch.
EXTENSION_TYPES: dict[str, frozenset[str]] = {
    "pdf": frozenset({"pdf"}),
    "png": frozenset({"png"}),
    "jpg": frozenset({"jpeg"}),
    "jpeg": frozenset({"jpeg"}),
    "gif": frozenset({"gif"}),
    "bmp": frozenset({"bmp"}),
    "zip": frozenset({"zip"}),
    "docx": frozenset({"zip"}),
    "xlsx": frozenset({"zip"}),
    "pptx": frozenset({"zip"}),
    "jar": frozenset({"zip"}),
    "apk": frozenset({"zip"}),
    "odt": frozenset({"zip"}),
    "ods": frozenset({"zip"}),
    "doc": frozenset({"ole2"}),
    "xls": frozenset({"ole2"}),
    "ppt": frozenset({"ole2"}),
    "msi": frozenset({"ole2"}),
    "rtf": frozenset({"rtf"}),
    "exe": frozenset({"pe"}),
    "dll": frozenset({"pe"}),
    "sys": frozenset({"pe"}),
    "so": frozenset({"elf"}),
    "class": frozenset({"java_class"}),
    "gz": frozenset({"gzip"}),
    "tgz": frozenset({"gzip"}),
    "bz2": frozenset({"bzip2"}),
    "xz": frozenset({"xz"}),
    "7z": frozenset({"7z"}),
    "rar": frozenset({"rar"}),
    "cab": frozenset({"cab"}),
    "tar": frozenset({"tar"}),
    "xml": frozenset({"xml"}),
}

# Families that are executable or can carry code. A mismatch that lands here is
# reported at a higher severity than one that does not.
EXECUTABLE_TYPES = frozenset({"pe", "elf", "java_class", "script", "ole2"})


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


def declared_extension(filename: str) -> str:
    _, _, suffix = (filename or "").rpartition(".")
    return suffix.strip().lower() if suffix and suffix != filename else ""


def detect_type(header: bytes) -> str | None:
    for offset, magic, type_key in SIGNATURES:
        if header[offset:offset + len(magic)] == magic:
            return type_key
    return None


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
