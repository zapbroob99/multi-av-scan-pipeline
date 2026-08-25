import json
import os
from pathlib import Path
import shutil
import subprocess
from time import monotonic, perf_counter

from app.models import EngineResultInput, ScanRecord
from app.services.findings import evidence_object, normalized_finding
from app.services.sample_paths import resolve_sample_path, sample_path_error


ENGINE_NAME = "YARA"
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_RULES_DIR = ROOT_DIR / "rules"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_RULES_CACHE_SECONDS = 30

# Per-worker-process cache for rule-file discovery, keyed by rules dir. Each
# entry holds (expiry, signature, files). The signature is (path, mtime) over
# the rule files, so a rule add/remove/edit invalidates immediately; the TTL is
# only a backstop bound. Discovery (the sorted rglob + Path build) is skipped
# on a hit when the signature still matches.
_rule_files_cache: dict[str, tuple[float, tuple, list[Path]]] = {}


def rules_cache_seconds() -> int:
    raw = os.getenv("MASP_YARA_RULES_CACHE_SECONDS", str(DEFAULT_RULES_CACHE_SECONDS)).strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_RULES_CACHE_SECONDS


def rule_dir_signature(rules_dir: Path) -> tuple:
    """Cheap change-signature over rule files: (path, mtime_ns) sorted.

    Catches count changes (add/remove) and content edits (mtime), including
    nested dirs. On Windows ``os.scandir`` returns stat info without an extra
    syscall, so this stays cheap.
    """
    entries: list[tuple[str, int]] = []
    for root, _dirs, files in os.walk(rules_dir):
        for name in files:
            if (name.endswith(".yar") or name.endswith(".yara")) and not name.endswith(".disabled"):
                full = os.path.join(root, name)
                try:
                    entries.append((full, os.stat(full).st_mtime_ns))
                except OSError:
                    continue
    return tuple(sorted(entries))


def cached_rule_files(rules_dir: Path) -> list[Path]:
    """Discover rule files, reusing a cached list while nothing changed.

    Invalidates immediately when a rule file is added, removed, or edited
    (signature change), and re-discovers at the latest after
    ``MASP_YARA_RULES_CACHE_SECONDS`` (default 30; set 0 to always re-scan).
    """
    ttl = rules_cache_seconds()
    if ttl <= 0:
        return list_rule_files(rules_dir)

    key = str(rules_dir)
    now = monotonic()
    signature = rule_dir_signature(rules_dir)
    entry = _rule_files_cache.get(key)
    if entry is not None and entry[0] > now and entry[1] == signature:
        return entry[2]

    files = list_rule_files(rules_dir)
    _rule_files_cache[key] = (now + ttl, signature, files)
    return files


def clear_rule_files_cache() -> None:
    _rule_files_cache.clear()


def get_yara_config(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | int | bool]:
    override = config_override or {}
    command = setting_value(
        override,
        "command",
        env_or_setting("MASP_YARA_COMMAND", "yara.command", "yara"),
    )
    configured_rules_dir = Path(
        setting_value(
            override,
            "rules_dir",
            env_or_setting("MASP_YARA_RULES_DIR", "yara.rules_dir", str(DEFAULT_RULES_DIR)),
        )
    )
    rules_dir = resolve_rules_dir(configured_rules_dir)
    rule_files = cached_rule_files(rules_dir)

    return {
        "command": command,
        "rules_dir": str(rules_dir),
        "rule_count": len(rule_files),
        "timeout_seconds": setting_int(
            override,
            "timeout_seconds",
            engine_setting(
                "yara.timeout_seconds",
                os.getenv("MASP_YARA_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)),
            ),
            DEFAULT_TIMEOUT_SECONDS,
        ),
        "enabled": shutil.which(command) is not None and bool(rule_files),
    }


def check_yara_health(
    config_override: dict[str, str] | None = None,
) -> dict[str, str | bool]:
    config = get_yara_config(config_override)
    command = str(config["command"])
    path = shutil.which(command)
    if path is None:
        return {
            "ok": False,
            "status": "not configured",
            "detail": f"{command} was not found on PATH.",
        }

    if int(config["rule_count"]) == 0:
        return {
            "ok": False,
            "status": "no rules",
            "detail": f"No .yar or .yara files found in {config['rules_dir']}.",
        }

    try:
        completed = subprocess.run(
            [command, "--version"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "status": "unavailable",
            "detail": f"Could not execute {command}: {exc}",
        }

    version = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0:
        return {
            "ok": False,
            "status": "unavailable",
            "detail": f"{command} exited with code {completed.returncode}: {version}",
        }

    return {
        "ok": True,
        "status": "available",
        "detail": f"{command} {version} found at {path}; {config['rule_count']} rules loaded.",
        "product_version": version,
        "engine_version": version,
        "signature_version": f"{config['rule_count']} rules",
        "service_state": "available",
    }


def run_yara_engine(
    scan: ScanRecord,
    config_override: dict[str, str] | None = None,
) -> EngineResultInput:
    config = get_yara_config(config_override)
    started_at = perf_counter()
    command = str(config["command"])
    timeout = int(config["timeout_seconds"])
    rules_dir = Path(str(config["rules_dir"]))
    rule_files = cached_rule_files(rules_dir)

    if shutil.which(command) is None:
        return build_result(
            status="skipped",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=f"{command} was not found on PATH.",
            error_message="YARA is not installed or not configured.",
            duration_ms=elapsed_ms(started_at),
            signature_version=None,
            details=yara_details(command, rules_dir, rule_files, scan),
        )

    if not rule_files:
        return build_result(
            status="skipped",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=f"No .yar or .yara files found in {rules_dir}.",
            error_message="YARA rules directory is empty.",
            duration_ms=elapsed_ms(started_at),
            signature_version=str(rules_dir),
            details=yara_details(command, rules_dir, rule_files, scan),
        )

    sample_path = resolve_sample_path(scan)
    if not sample_path.is_file():
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=sample_path_error(scan, sample_path),
            error_message="Stored sample file is missing.",
            duration_ms=elapsed_ms(started_at),
            signature_version=str(rules_dir),
            details=yara_details(command, rules_dir, rule_files, scan),
        )

    try:
        single = scan_single_invocation(command, rule_files, sample_path, timeout)
    except YaraBatchTimeout as exc:
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=str(exc),
            error_message=str(exc),
            duration_ms=elapsed_ms(started_at),
            signature_version=str(rules_dir),
            details=yara_details(
                command,
                rules_dir,
                rule_files,
                scan,
                errors=[str(exc)],
            ),
        )
    if single is not None:
        outputs, errors, matches = single
    else:
        # Batch invocation errored (bad rule file, duplicate rule id, timeout);
        # fall back to per-file so one broken rule cannot hide the rest.
        outputs = []
        errors = []
        matches = []
        for rule_file in rule_files:
            try:
                completed = subprocess.run(
                    [command, "-w", str(rule_file), str(sample_path)],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as exc:
                errors.append(f"{rule_file.name}: timed out after {timeout} seconds")
                outputs.append((exc.stdout or "") + (exc.stderr or ""))
                continue
            except OSError as exc:
                return build_result(
                    status="failed",
                    detected=False,
                    signature=None,
                    severity="info",
                    confidence=0,
                    raw_output=str(exc),
                    error_message="YARA could not be executed.",
                    duration_ms=elapsed_ms(started_at),
                    signature_version=str(rules_dir),
                    details=yara_details(
                        command,
                        rules_dir,
                        rule_files,
                        scan,
                        errors=[str(exc)],
                    ),
                )

            raw_output = "\n".join(
                part for part in [completed.stdout.strip(), completed.stderr.strip()] if part
            )
            if raw_output:
                outputs.append(raw_output)

            file_matches = parse_matches(completed.stdout)
            matches.extend(file_matches)

            stderr = completed.stderr.strip()
            if completed.returncode != 0 and not file_matches and stderr:
                errors.append(
                    f"{rule_file.name}: yara exited with code {completed.returncode}"
                )
                continue

    unique_matches = sorted(set(matches))
    raw_output = json.dumps(
        {
            "rules_dir": str(rules_dir),
            "rule_files": [str(rule_file) for rule_file in rule_files],
            "matches": unique_matches,
            "output": outputs,
            "errors": errors,
        },
        indent=2,
        sort_keys=True,
    )

    if unique_matches:
        return build_result(
            status="completed",
            detected=True,
            signature=", ".join(unique_matches),
            severity="high",
            confidence=85,
            raw_output=raw_output,
            error_message="; ".join(errors) if errors else None,
            duration_ms=elapsed_ms(started_at),
            signature_version=str(rules_dir),
            details=yara_details(
                command,
                rules_dir,
                rule_files,
                scan,
                matches=unique_matches,
                output=outputs,
                errors=errors,
            ),
            findings=yara_findings(unique_matches, rule_files),
        )

    if errors:
        return build_result(
            status="failed",
            detected=False,
            signature=None,
            severity="info",
            confidence=0,
            raw_output=raw_output,
            error_message="; ".join(errors),
            duration_ms=elapsed_ms(started_at),
            signature_version=str(rules_dir),
            details=yara_details(
                command,
                rules_dir,
                rule_files,
                scan,
                matches=unique_matches,
                output=outputs,
                errors=errors,
            ),
        )

    return build_result(
        status="completed",
        detected=False,
        signature=None,
        severity="info",
        confidence=100,
        raw_output=raw_output,
        error_message=None,
        duration_ms=elapsed_ms(started_at),
        signature_version=str(rules_dir),
        details=yara_details(
            command,
            rules_dir,
            rule_files,
            scan,
            matches=unique_matches,
            output=outputs,
            errors=errors,
        ),
    )


def list_rule_files(rules_dir: Path) -> list[Path]:
    if not rules_dir.is_dir():
        return []
    return sorted(
        path
        for pattern in ("*.yar", "*.yara")
        for path in rules_dir.rglob(pattern)
        if path.is_file() and not path.name.endswith(".disabled")
    )


def resolve_rules_dir(configured_rules_dir: Path) -> Path:
    if configured_rules_dir.is_dir():
        return configured_rules_dir
    if DEFAULT_RULES_DIR.is_dir():
        return DEFAULT_RULES_DIR
    return configured_rules_dir


class YaraBatchTimeout(Exception):
    """Raised when the single batch YARA invocation times out.

    A timeout must NOT trigger the per-file fallback: re-running every rule file
    individually could each time out again (N x timeout worst case). The caller
    turns this into a single failed result instead.
    """


def scan_single_invocation(
    command: str,
    rule_files: list[Path],
    sample_path: Path,
    timeout: int,
) -> tuple[list[str], list[str], list[str]] | None:
    """Scan every rule file in one YARA invocation (the fast path).

    Returns ``(outputs, errors, matches)`` on a clean run, or ``None`` to signal
    the caller to fall back to per-file scanning for isolation. Fallback covers
    a non-zero exit (bad rule file / duplicate rule identifier) or an OS error,
    so one broken rule file cannot suppress every other rule's matches. A
    timeout raises :class:`YaraBatchTimeout` instead — see that class.
    """
    args = [command, "-w", *[str(rule_file) for rule_file in rule_files], str(sample_path)]
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise YaraBatchTimeout(
            f"YARA batch scan timed out after {timeout} seconds"
        ) from exc
    except OSError:
        return None

    if completed.returncode != 0:
        return None

    raw_output = "\n".join(
        part for part in [completed.stdout.strip(), completed.stderr.strip()] if part
    )
    outputs = [raw_output] if raw_output else []
    matches = parse_matches(completed.stdout)
    return outputs, [], matches


def parse_matches(stdout: str) -> list[str]:
    matches = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        rule_name = stripped.split(maxsplit=1)[0]
        if rule_name:
            matches.append(rule_name)
    return matches


def build_result(
    status: str,
    detected: bool,
    signature: str | None,
    severity: str,
    confidence: int,
    raw_output: str,
    error_message: str | None,
    duration_ms: int,
    signature_version: str | None,
    details: dict[str, object] | None = None,
    findings: list[dict[str, object]] | None = None,
) -> EngineResultInput:
    return EngineResultInput(
        engine_name=ENGINE_NAME,
        engine_version="yara-cli",
        signature_version=signature_version,
        status=status,
        detected=detected,
        signature=signature,
        severity=severity,
        confidence=confidence,
        raw_output=raw_output,
        error_message=error_message,
        duration_ms=duration_ms,
        details_json=json.dumps(details or {}, sort_keys=True),
        findings_json=json.dumps(findings or [], sort_keys=True),
    )


def yara_details(
    command: str,
    rules_dir: Path,
    rule_files: list[Path],
    scan: ScanRecord,
    matches: list[str] | None = None,
    output: list[str] | None = None,
    errors: list[str] | None = None,
) -> dict[str, object]:
    return {
        "adapter": "yara",
        "command": command,
        "rules_dir": str(rules_dir),
        "rule_files": [str(rule_file) for rule_file in rule_files],
        "matches": matches or [],
        "output": output or [],
        "errors": errors or [],
        "sample": {
            "filename": scan.original_filename,
            "sha256": scan.sha256,
            "size_bytes": scan.size_bytes,
        },
    }


def yara_findings(
    matches: list[str],
    rule_files: list[Path],
) -> list[dict[str, object]]:
    rule_file_names = [rule_file.name for rule_file in rule_files]
    return [
        normalized_finding(
            title=match,
            finding_type="yara_rule_match",
            source=ENGINE_NAME,
            severity="high",
            confidence=85,
            action="matched",
            category="rule_match",
            tags=["yara", "rule"],
            evidence={
                "objects": [
                    evidence_object(
                        kind="yara_rule",
                        value=match,
                        metadata={"rule_files": rule_file_names},
                    )
                ],
                "rule": match,
                "rule_files": rule_file_names,
            },
            vendor_details={
                "rule": match,
                "rule_files": rule_file_names,
            },
        )
        for match in matches
    ]


def elapsed_ms(started_at: float) -> int:
    return max(1, int((perf_counter() - started_at) * 1000))


def engine_setting(key: str, fallback: str) -> str:
    from app.database import get_setting

    value = get_setting(key, fallback)
    return fallback if value is None else value


def env_or_setting(env_key: str, setting_key: str, fallback: str) -> str:
    value = os.getenv(env_key)
    if value is not None:
        return value
    return engine_setting(setting_key, fallback)


def engine_setting_int(key: str, fallback: str, default: int) -> int:
    try:
        return int(engine_setting(key, fallback))
    except ValueError:
        return default


def setting_value(config_override: dict[str, str], key: str, fallback: str) -> str:
    value = config_override.get(key)
    if value is None:
        return fallback
    return value


def setting_int(
    config_override: dict[str, str],
    key: str,
    fallback: str,
    default: int,
) -> int:
    try:
        return int(setting_value(config_override, key, fallback))
    except ValueError:
        return default
