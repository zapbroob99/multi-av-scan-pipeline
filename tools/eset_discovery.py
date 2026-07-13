#!/usr/bin/env python3
"""Read-only ESET Server Security for Linux (odscan) discovery tool.

Purpose: collect the facts MASP needs to finalize the ESET adapter WITHOUT
guessing — real executable path, version/help output, and (only on explicit
request) the exact exit code + output of scanning a known sample.

Stage A note: this runs standalone with the Python standard library only, so it
can be carried into the corporate test environment without installing MASP or
its dependencies.

Safety model:
- Default mode is inventory ONLY (no scanning): locate odscan, probe safe
  version/help candidates, report what was found.
- Sample scanning requires BOTH `--scan-sample PATH` and `--yes`, because in a
  real environment ESET real-time protection may quarantine a malicious sample.
  Only scan files in a security-approved, exclusion-applied staging directory.
- The tool verifies the sample's SHA-256 before and after the scan so a silent
  clean/quarantine by real-time protection is detected deterministically.
- Output JSON is redacted (hostname, username, IPs, home paths) on a best
  effort basis. It is NOT a substitute for a human security review of the file
  before it leaves the corporate network. Standard ESET install paths
  (/opt/eset/...) are intentionally kept for the adapter's benefit.
"""

import argparse
import getpass
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone


STANDARD_ODSCAN_PATHS = ("/opt/eset/efs/bin/odscan",)
VERSION_PROBE_CANDIDATES = (["--version"], ["--help"], ["-h"])
IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def build_redactor(extra_redactions: "list[tuple[str, str]] | None" = None) -> "callable":
    username = getpass.getuser() or ""
    hostname = socket.gethostname() or ""
    short_host = hostname.split(".")[0] if hostname else ""
    home = os.path.expanduser("~")
    # (label, literal) pairs applied first, longest literal first, so specific
    # corporate paths (sample staging, a custom odscan path) are masked before
    # the generic PII passes run.
    extra = sorted(
        [(label, value) for label, value in (extra_redactions or []) if value],
        key=lambda pair: len(pair[1]),
        reverse=True,
    )

    def redact(text: str) -> str:
        if not text:
            return text
        result = text
        for label, literal in extra:
            result = result.replace(literal, label)
        if home and home not in ("/", ""):
            result = result.replace(home, "[HOME]")
        for user_home_root in ("/home/", "/Users/"):
            result = re.sub(
                re.escape(user_home_root) + r"[^/\s:]+",
                user_home_root + "[USER]",
                result,
            )
        if username:
            result = re.sub(rf"\b{re.escape(username)}\b", "[USER]", result)
        if hostname:
            result = result.replace(hostname, "[HOST]")
        if short_host and short_host != hostname:
            result = re.sub(rf"\b{re.escape(short_host)}\b", "[HOST]", result)
        result = IPV4_RE.sub("[IP]", result)
        return result

    return redact


def sha256_of(path: str) -> "str | None":
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def find_odscan(configured: str) -> "str | None":
    if configured and configured.lower() != "auto":
        return configured if os.path.isfile(configured) else None
    for candidate in STANDARD_ODSCAN_PATHS:
        if os.path.isfile(candidate):
            return candidate
    return shutil.which("odscan")


def probe(executable: str, args: "list[str]", timeout: int, redact) -> dict:
    argv = [executable, *args]
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "argv": [redact(part) for part in argv],
            "timed_out": True,
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
    except OSError as exc:
        return {
            "argv": [redact(part) for part in argv],
            "error": redact(str(exc)),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
    return {
        "argv": [redact(part) for part in argv],
        "exit_code": completed.returncode,
        "stdout": redact((completed.stdout or "").strip()),
        "stderr": redact((completed.stderr or "").strip()),
        "duration_ms": int((time.perf_counter() - started) * 1000),
    }


def run_inventory(executable: "str | None", timeout: int, redact) -> dict:
    result = {
        "odscan_found": executable is not None,
        "odscan_path": redact(executable) if executable is not None else None,
        "standard_paths_checked": [
            {"path": path, "exists": os.path.isfile(path)}
            for path in STANDARD_ODSCAN_PATHS
        ],
        "version_probes": [],
    }
    if executable is None:
        return result
    # FIXTURE-PENDING: which of these is the real version command is unknown, so
    # every candidate is tried and recorded for the adapter's health contract.
    for args in VERSION_PROBE_CANDIDATES:
        result["version_probes"].append(probe(executable, args, timeout, redact))
    return result


def run_sample_scan(
    executable: str, sample_path: str, timeout: int, redact
) -> dict:
    sha_before = sha256_of(sample_path)
    # Match the adapter's command exactly so the fixture measures the same
    # contract, including --ignore-exclusions.
    argv = [executable, "--scan", "--readonly", "--ignore-exclusions", sample_path]
    started = time.perf_counter()
    outcome: dict = {
        "argv": [redact(part) for part in argv],
        "sha256_before": sha_before,
    }
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        outcome["exit_code"] = completed.returncode
        outcome["stdout"] = redact((completed.stdout or "").strip())
        outcome["stderr"] = redact((completed.stderr or "").strip())
    except subprocess.TimeoutExpired:
        outcome["timed_out"] = True
    except OSError as exc:
        outcome["error"] = redact(str(exc))
    outcome["duration_ms"] = int((time.perf_counter() - started) * 1000)

    sha_after = sha256_of(sample_path)
    file_missing_after = not os.path.exists(sample_path)
    outcome["sha256_after"] = sha_after
    outcome["file_missing_after_scan"] = file_missing_after
    outcome["file_changed"] = (
        None
        if sha_before is None or sha_after is None
        else sha_before != sha_after
    )
    return outcome


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only ESET odscan discovery (Stage A). Inventory by "
        "default; sample scanning requires --scan-sample and --yes."
    )
    parser.add_argument(
        "--odscan",
        default="auto",
        help="Path to odscan, or 'auto' to probe standard EFS locations and PATH.",
    )
    parser.add_argument(
        "--scan-sample",
        metavar="PATH",
        default=None,
        help="Scan a specific sample file (requires --yes). Use only on an "
        "approved, exclusion-applied staging file.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Explicit confirmation required to actually scan a sample.",
    )
    parser.add_argument("--timeout", type=int, default=120, help="Per-command timeout (s).")
    parser.add_argument("--output", default=None, help="Write JSON here instead of stdout.")
    args = parser.parse_args(argv)

    executable = find_odscan(args.odscan)
    # Redact the sample path and any NON-standard odscan path (standard ESET
    # install paths are intentionally preserved for the adapter's benefit).
    extra_redactions: "list[tuple[str, str]]" = []
    if executable is not None and executable not in STANDARD_ODSCAN_PATHS:
        extra_redactions.append(("[EXECUTABLE]", executable))
    if args.scan_sample:
        extra_redactions.append(("[SAMPLE_PATH]", args.scan_sample))
    redact = build_redactor(extra_redactions)
    report = {
        "tool": "eset_discovery",
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": sys.platform,
        "mode": "inventory",
        "redacted": True,
    }

    if sys.platform.startswith("win"):
        report["warning"] = (
            "This tool targets ESET Server Security for Linux (odscan). Windows "
            "ecls discovery is a separate future phase."
        )

    report["inventory"] = run_inventory(executable, args.timeout, redact)

    if args.scan_sample is not None:
        if not args.yes:
            print(
                "Refusing to scan a sample without --yes. Sample scanning may "
                "trigger real-time quarantine; only run on an approved, "
                "exclusion-applied staging file.",
                file=sys.stderr,
            )
            return 2
        if executable is None:
            print("odscan was not found; cannot scan sample.", file=sys.stderr)
            return 3
        if not os.path.isfile(args.scan_sample):
            print(f"Sample file not found: {args.scan_sample}", file=sys.stderr)
            return 4
        report["mode"] = "sample_scan"
        report["sample_scan"] = run_sample_scan(
            executable, args.scan_sample, args.timeout, redact
        )

    serialized = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        # Create 0600 so redacted-but-still-sensitive output is not world
        # readable (best effort on Windows, enforced on POSIX).
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
        fd = os.open(args.output, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            if os.name == "posix":
                # The mode passed to os.open only applies when creating a file.
                # Tighten an existing report too before writing sensitive data.
                os.fchmod(handle.fileno(), 0o600)
            handle.write(serialized + "\n")
        print(f"Discovery report written to {args.output}")
    else:
        print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
