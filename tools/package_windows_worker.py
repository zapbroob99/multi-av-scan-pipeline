from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parent.parent
PACKAGE_VERSION = "0.1.0"
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def package_sources(root: Path = ROOT) -> list[Path]:
    files = [
        path
        for path in (root / "app").rglob("*.py")
        if "__pycache__" not in path.parts
    ]
    files.extend((root / "tools" / "windows_worker").glob("*.ps1"))
    for relative in (
        "requirements.txt",
        "tools/verify_scan_api.py",
        "tools/verify_windows_worker_bundle.py",
        "README.md",
        "LICENSE",
        "NOTICE",
        "docs/deployment/WINDOWS_WORKER_AGENT.md",
        "docs/integrations/SUPPORT_MATRIX.md",
    ):
        path = root / relative
        if path.is_file():
            files.append(path)
    return sorted(set(files), key=lambda path: path.relative_to(root).as_posix())


def _write_bytes(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def build_package(output: Path, *, root: Path = ROOT) -> dict[str, object]:
    sources = package_sources(root)
    if not sources:
        raise RuntimeError("No Windows worker package sources were found.")
    manifest_files: dict[str, str] = {}
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        for source in sources:
            relative = source.relative_to(root).as_posix()
            data = source.read_bytes()
            manifest_files[relative] = hashlib.sha256(data).hexdigest()
            _write_bytes(archive, relative, data)
        manifest: dict[str, object] = {
            "package": "masp-windows-worker",
            "version": PACKAGE_VERSION,
            "files": manifest_files,
        }
        _write_bytes(
            archive,
            "windows-worker-manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the MASP Windows worker bundle")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / f"masp-windows-worker-{PACKAGE_VERSION}.zip",
    )
    args = parser.parse_args()
    manifest = build_package(args.output.resolve())
    print(
        f"Built {args.output.resolve()} with {len(manifest['files'])} files.",
        flush=True,
    )


if __name__ == "__main__":
    main()
