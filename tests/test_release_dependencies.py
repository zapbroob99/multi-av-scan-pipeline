"""The image installs exactly the locked dependencies, and the release lists them."""
import json
import re
import unittest
from pathlib import Path

from tools import generate_sbom
from tools.package_pilot_release import checked_payloads, collect_files

ROOT_DIR = Path(__file__).resolve().parent.parent


def _name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


class LockedDependencyTests(unittest.TestCase):
    def lock(self) -> dict[str, list[str]]:
        locked: dict[str, list[str]] = {}
        current = None
        for line in (ROOT_DIR / "requirements-lock.txt").read_text(encoding="utf-8").splitlines():
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)", line)
            if match:
                current = _name(match.group(1))
                locked[current] = []
            if current and "--hash=sha256:" in line:
                locked[current].append(line)
        return locked

    def test_every_direct_dependency_is_locked_with_hashes(self):
        locked = self.lock()
        for line in (ROOT_DIR / "requirements.txt").read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or "sys_platform == \"win32\"" in line:
                continue
            name = _name(re.split(r"[\[<>=!~; ]", line, maxsplit=1)[0])
            with self.subTest(dependency=name):
                self.assertIn(name, locked, "requirements.txt changed: regenerate requirements-lock.txt (see its header)")
        self.assertTrue(all(locked.values()), "every locked package needs at least one hash")

    def test_the_image_installs_only_the_lock_with_hashes_and_pins_every_base_image(self):
        dockerfile = (ROOT_DIR / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("pip install --no-cache-dir --require-hashes -r requirements-lock.txt", dockerfile)
        self.assertNotIn("-r requirements.txt", dockerfile)
        for line in dockerfile.splitlines():
            if line.startswith("FROM "):
                self.assertRegex(line.split()[1], r"@sha256:[0-9a-f]{64}$")
        self.assertIn("/app/os-packages.txt", dockerfile)


class SbomTests(unittest.TestCase):
    def release_files(self) -> dict[str, bytes]:
        return dict(checked_payloads(collect_files()))

    def test_the_release_ships_the_lock_and_an_sbom_of_it(self):
        files = self.release_files()
        self.assertIn("requirements-lock.txt", files)
        document = json.loads(generate_sbom.render("0.1.0-test", files))
        self.assertEqual((document["bomFormat"], document["specVersion"]), ("CycloneDX", "1.5"))
        purls = {component["purl"] for component in document["components"]}
        for name in LockedDependencyTests.lock(self):
            with self.subTest(package=name):
                self.assertTrue(any(purl.startswith(f"pkg:pypi/{name}@") for purl in purls))
        self.assertTrue(any(purl.startswith("pkg:npm/react@") for purl in purls))
        # Build and test tools never reach the console bundle, so they are not listed.
        self.assertFalse(any(purl.startswith(("pkg:npm/vite@", "pkg:npm/vitest@", "pkg:npm/typescript@"))
                             for purl in purls))
        images = {component["name"] for component in document["components"] if component["type"] == "container"}
        self.assertEqual(images, {"node", "python", "postgres", "clamav/clamav"})
        self.assertTrue(all(component.get("hashes") for component in document["components"]))

    def test_the_sbom_is_reproducible_and_versioned(self):
        files = self.release_files()
        self.assertEqual(generate_sbom.render("0.1.0-a", files), generate_sbom.render("0.1.0-a", files))
        self.assertNotEqual(json.loads(generate_sbom.render("0.1.0-a", files))["serialNumber"],
                            json.loads(generate_sbom.render("0.1.0-b", files))["serialNumber"])
        self.assertNotIn(b"timestamp", generate_sbom.render("0.1.0-a", files))

    def test_an_unpinned_image_is_refused(self):
        with self.assertRaisesRegex(ValueError, "not pinned by digest"):
            generate_sbom.image_components("FROM node:24-alpine AS console\n", "")


if __name__ == "__main__":
    unittest.main()
