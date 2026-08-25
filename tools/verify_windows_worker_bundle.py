"""Verify the integrity and shape of an extracted MASP Windows worker bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


MANIFEST_NAME = "windows-worker-manifest.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_bundle(root: Path) -> dict[str, object]:
    root = root.resolve()
    manifest_path = root / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to read {MANIFEST_NAME}: {exc}") from exc

    if manifest.get("package") != "masp-windows-worker":
        raise RuntimeError("Manifest package identity is not masp-windows-worker.")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise RuntimeError("Manifest files map is missing or empty.")

    verified: list[str] = []
    for relative, expected_digest in sorted(files.items()):
        if not isinstance(relative, str) or not isinstance(expected_digest, str):
            raise RuntimeError("Manifest file entries must map paths to SHA-256 strings.")
        posix_path = PurePosixPath(relative)
        if posix_path.is_absolute() or ".." in posix_path.parts:
            raise RuntimeError(f"Unsafe path in manifest: {relative!r}")
        target = root.joinpath(*posix_path.parts).resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise RuntimeError(f"Manifest path escapes bundle root: {relative!r}") from exc
        if not target.is_file():
            raise RuntimeError(f"Manifest file is missing: {relative}")
        actual_digest = sha256_file(target)
        if actual_digest.lower() != expected_digest.lower():
            raise RuntimeError(
                f"SHA-256 mismatch for {relative}: expected {expected_digest}, got {actual_digest}"
            )
        verified.append(relative)

    tracked = set(verified)
    unexpected_code = sorted(
        path.relative_to(root).as_posix()
        for base in (root / "app", root / "tools")
        if base.is_dir()
        for path in base.rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".py", ".ps1"}
        and path.relative_to(root).as_posix() not in tracked
    )
    if unexpected_code:
        raise RuntimeError(
            "Untracked executable source exists in the bundle: "
            + ", ".join(unexpected_code)
        )

    return {
        "ok": True,
        "package": manifest["package"],
        "version": manifest.get("version"),
        "verified_files": len(verified),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Extracted bundle root containing windows-worker-manifest.json.",
    )
    parser.add_argument("--report", type=Path, help="Optional JSON report path.")
    args = parser.parse_args()
    try:
        result = verify_bundle(args.root)
    except RuntimeError as exc:
        result = {"ok": False, "detail": str(exc)}
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    print(output, end="")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(output, encoding="utf-8")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
