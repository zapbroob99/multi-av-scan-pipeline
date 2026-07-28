"""Build a secret-free, checksummed MASP single-host pilot release ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DIST_DIR = ROOT_DIR / "dist"

ROOT_FILES = (
    ".dockerignore",
    ".env.pilot.example",
    "Dockerfile",
    "docker-compose.pilot.yml",
    "requirements.txt",
)
TREE_DIRS = ("app", "rules", "deploy/pilot")
EXTRA_FILES = (
    "docs/deployment/PILOT.md",
    "tools/icap_probe.py",
    "tools/verify_scan_api.py",
)
ALLOWED_SUFFIXES = {
    "",
    ".css",
    ".example",
    ".html",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".svg",
    ".txt",
    ".yar",
    ".yara",
    ".yml",
}
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
FORBIDDEN_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "real API token",
        re.compile(r"(?m)^MASP_API_TOKEN=(?!CHANGE_ME)[^\s$<{]{16,}$"),
    ),
    (
        "real database password",
        re.compile(r"(?m)^MASP_POSTGRES_PASSWORD=(?!CHANGE_ME)[^\s$<{]{16,}$"),
    ),
)


def git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def collect_files() -> list[Path]:
    files = [ROOT_DIR / name for name in (*ROOT_FILES, *EXTRA_FILES)]
    for directory_name in TREE_DIRS:
        directory = ROOT_DIR / directory_name
        if not directory.is_dir():
            raise RuntimeError(f"required directory missing: {directory_name}")
        files.extend(path for path in directory.rglob("*") if path.is_file())

    selected: list[Path] = []
    for path in sorted(set(files)):
        relative = path.relative_to(ROOT_DIR)
        if not path.is_file():
            raise RuntimeError(f"required file missing: {relative}")
        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        if path.suffix.lower() not in ALLOWED_SUFFIXES:
            raise RuntimeError(f"unexpected release file type: {relative}")
        if path.is_symlink():
            raise RuntimeError(f"release cannot contain symlink: {relative}")
        selected.append(path)
    return selected


def ensure_clean_release_inputs(paths: list[Path]) -> None:
    relative_paths = [str(path.relative_to(ROOT_DIR)) for path in paths]
    result = subprocess.run(
        ["git", "status", "--porcelain", "--", *relative_paths],
        cwd=ROOT_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        raise RuntimeError("release inputs are modified or untracked; commit them before packaging")


def checked_payloads(paths: list[Path]) -> list[tuple[str, bytes]]:
    payloads: list[tuple[str, bytes]] = []
    violations: list[str] = []
    for path in paths:
        relative = str(path.relative_to(ROOT_DIR)).replace("\\", "/")
        data = path.read_bytes()
        text = data.decode("utf-8", errors="replace")
        for label, pattern in FORBIDDEN_PATTERNS:
            if pattern.search(text):
                violations.append(f"{relative}: {label}")
        payloads.append((relative, data))
    if violations:
        raise RuntimeError("secret-like release content found:\n  " + "\n  ".join(violations))
    return payloads


def write_entry(archive: zipfile.ZipFile, name: str, data: bytes, *, executable: bool = False) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = ((0o755 if executable else 0o644) & 0xFFFF) << 16
    archive.writestr(info, data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Example: 0.1.0-pilot.1")
    parser.add_argument("--output-dir", default=str(DIST_DIR))
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Development only: package uncommitted release inputs.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not VERSION_PATTERN.fullmatch(args.version):
        print("Invalid release version.", file=sys.stderr)
        return 2

    try:
        paths = collect_files()
        if not args.allow_dirty:
            ensure_clean_release_inputs(paths)
        payloads = checked_payloads(paths)
        commit = git_output("rev-parse", "HEAD")
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Refusing to package: {exc}", file=sys.stderr)
        return 1

    release_metadata = json.dumps(
        {"version": args.version, "commit": commit},
        indent=2,
        sort_keys=True,
    ).encode() + b"\n"
    payloads.append(("RELEASE.json", release_metadata))
    manifest = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in payloads
    ).encode()

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    zip_path = output_dir / f"masp-pilot-{args.version}.zip"
    prefix = f"masp-pilot-{args.version}"
    with zipfile.ZipFile(zip_path, "w") as archive:
        for name, data in payloads:
            write_entry(
                archive,
                f"{prefix}/{name}",
                data,
                executable=name.startswith("deploy/pilot/") and name.endswith(".sh"),
            )
        write_entry(archive, f"{prefix}/SHA256SUMS", manifest)

    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    sidecar = zip_path.with_suffix(".zip.sha256")
    sidecar.write_text(f"{digest}  {zip_path.name}\n", encoding="ascii")
    print(f"Packaged {len(payloads)} files -> {zip_path}")
    print(f"SHA-256({zip_path.name}) = {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
