"""Software bill of materials for a MASP release, as CycloneDX 1.5 JSON.

Built from the files the release ships, so it lists exactly what the image
installs: the hash-pinned Python packages (requirements-lock.txt), the console's
runtime npm packages (frontend/package-lock.json, development tools excluded)
and the container images by digest (the Dockerfile's base images and the
PostgreSQL and ClamAV images in .env.pilot.example). The image's operating
system packages are listed inside it at /app/os-packages.txt.

The document has no timestamp and a serial number derived from the version, so
packaging the same commit twice gives the same bytes.

    python tools/generate_sbom.py --version 0.1.0-pilot.18 > sbom.cdx.json
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

ROOT_DIR = Path(__file__).resolve().parent.parent
SOURCES = ("requirements-lock.txt", "frontend/package-lock.json", "Dockerfile", ".env.pilot.example")
_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)")
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")
_IMAGE = re.compile(r"^([a-z0-9./_-]+):([A-Za-z0-9._-]+)@sha256:([0-9a-f]{64})$")


def python_components(lock: str) -> list[dict]:
    components: list[dict] = []
    current: dict | None = None
    for line in lock.splitlines():
        match = _REQUIREMENT.match(line)
        if match:
            name, version = match.group(1).lower().replace("_", "-"), match.group(2)
            current = {"type": "library", "bom-ref": f"pkg:pypi/{name}@{version}", "name": name,
                       "version": version, "purl": f"pkg:pypi/{name}@{version}", "hashes": []}
            components.append(current)
        if current is not None:
            current["hashes"].extend({"alg": "SHA-256", "content": digest} for digest in _HASH.findall(line))
    return components


def npm_components(package_lock: str) -> list[dict]:
    packages = json.loads(package_lock).get("packages", {})
    seen: dict[str, dict] = {}
    for path, entry in packages.items():
        if not path or not isinstance(entry, dict) or entry.get("dev") or entry.get("devOptional"):
            continue
        name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
        version = entry.get("version")
        if not version or entry.get("link"):
            continue
        purl = f"pkg:npm/{quote(name, safe='/')}@{version}"
        component = {"type": "library", "bom-ref": purl, "name": name, "version": version, "purl": purl}
        integrity = str(entry.get("integrity") or "")
        if integrity.startswith("sha512-"):
            component["hashes"] = [{"alg": "SHA-512", "content": base64.b64decode(integrity[7:]).hex()}]
        seen.setdefault(purl, component)
    return [seen[key] for key in sorted(seen)]


def image_components(dockerfile: str, env_example: str) -> list[dict]:
    references = [line.split()[1] for line in dockerfile.splitlines() if line.startswith("FROM ")]
    references += [line.split("=", 1)[1].strip() for line in env_example.splitlines()
                   if re.match(r"^MASP_(POSTGRES|CLAMAV)_IMAGE=", line)]
    components = []
    for reference in references:
        match = _IMAGE.match(reference)
        if not match:
            raise ValueError(f"image is not pinned by digest: {reference}")
        name, tag, digest = match.groups()
        repository = name if "/" in name else f"library/{name}"
        purl = f"pkg:oci/{name.rsplit('/', 1)[-1]}@sha256%3A{digest}?repository_url=docker.io/{repository}&tag={tag}"
        components.append({"type": "container", "bom-ref": purl, "name": name, "version": tag, "purl": purl,
                           "hashes": [{"alg": "SHA-256", "content": digest}]})
    return components


def build_sbom(version: str, files: dict[str, bytes]) -> dict:
    text = {name: files[name].decode("utf-8") for name in SOURCES}
    components = (image_components(text["Dockerfile"], text[".env.pilot.example"])
                  + python_components(text["requirements-lock.txt"])
                  + npm_components(text["frontend/package-lock.json"]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'masp-pilot/{version}')}",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "bom-ref": "masp-pilot", "name": "masp-pilot", "version": version},
            "properties": [{"name": "masp:os-packages",
                            "value": "Listed inside the application image at /app/os-packages.txt."}],
        },
        "components": components,
    }


def render(version: str, files: dict[str, bytes]) -> bytes:
    return (json.dumps(build_sbom(version, files), indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    files = {name: (ROOT_DIR / name).read_bytes().replace(b"\r\n", b"\n") for name in SOURCES}
    sys.stdout.buffer.write(render(args.version, files))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
