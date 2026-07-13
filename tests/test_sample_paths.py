import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.services import sample_paths
from app.services.sample_paths import (
    SAMPLES_DIR,
    STORAGE_DIR,
    SamplePathConfigError,
    acceptable_direct_path,
    all_path_mappings,
    configured_path_mappings,
    has_parent_traversal,
    map_path_prefix,
    path_within_root,
    safe_map_path_prefix,
)


class SamplePathTests(unittest.TestCase):
    def test_maps_docker_sample_path_to_local_storage(self) -> None:
        mapped_path = map_path_prefix(
            "/app/storage/samples/example.bin",
            "/app/storage/samples",
            SAMPLES_DIR,
        )
        self.assertEqual(mapped_path, SAMPLES_DIR / "example.bin")

    def test_maps_nested_docker_storage_path_to_local_storage(self) -> None:
        mapped_path = map_path_prefix(
            "/app/storage/samples/nested/example.bin",
            "/app/storage",
            SAMPLES_DIR.parent,
        )
        self.assertEqual(mapped_path, SAMPLES_DIR / "nested" / "example.bin")

    def test_prefix_boundary_does_not_match_sibling(self) -> None:
        # /app/storage2 must NOT match the /app/storage prefix.
        self.assertIsNone(
            map_path_prefix("/app/storage2/example.bin", "/app/storage", SAMPLES_DIR)
        )


class ConfiguredPathMappingsTests(unittest.TestCase):
    def set_env(self, value: str | None):
        if value is None:
            return mock.patch.dict("os.environ", {}, clear=False)
        return mock.patch.dict(
            "os.environ", {sample_paths.SAMPLE_PATH_MAPPINGS_ENV: value}
        )

    def test_empty_env_returns_no_mappings(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop(sample_paths.SAMPLE_PATH_MAPPINGS_ENV, None)
            self.assertEqual(configured_path_mappings(), ())

    def test_valid_mapping_parsed(self) -> None:
        # Use a runtime-native absolute target so the check is platform-correct.
        with tempfile.TemporaryDirectory() as tmp:
            target = str(Path(tmp) / "samples")
            with self.set_env(json.dumps({"/app/storage/samples": target})):
                mappings = configured_path_mappings()
            self.assertEqual(mappings, (("/app/storage/samples", Path(target)),))

    def test_malformed_json_raises(self) -> None:
        with self.set_env("{not json"):
            with self.assertRaises(SamplePathConfigError):
                configured_path_mappings()

    def test_non_object_raises(self) -> None:
        with self.set_env('["/a", "/b"]'):
            with self.assertRaises(SamplePathConfigError):
                configured_path_mappings()

    def test_relative_target_raises(self) -> None:
        with self.set_env('{"/app/storage": "relative/path"}'):
            with self.assertRaises(SamplePathConfigError):
                configured_path_mappings()

    def test_empty_value_raises(self) -> None:
        with self.set_env('{"/app/storage": ""}'):
            with self.assertRaises(SamplePathConfigError):
                configured_path_mappings()

    def test_longest_prefix_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = str(Path(tmp))
            payload = json.dumps(
                {"/app/storage": base, "/app/storage/samples": str(Path(tmp) / "samples")}
            )
            with self.set_env(payload):
                ordered = [prefix for prefix, _ in all_path_mappings()]
        self.assertLess(
            ordered.index("/app/storage/samples"), ordered.index("/app/storage")
        )


class DirectPathGuardTests(unittest.TestCase):
    def test_traversal_detected(self) -> None:
        self.assertTrue(has_parent_traversal("/app/storage/../etc/passwd"))
        self.assertFalse(has_parent_traversal("/app/storage/samples/x.bin"))

    def test_direct_path_with_traversal_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "x.bin"
            f.write_bytes(b"x")
            # Even though the file exists, a ".." in the stored path is rejected.
            self.assertFalse(
                acceptable_direct_path(f"{tmp}/../x.bin", f, configured=())
            )

    def test_direct_path_accepted_without_mappings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "x.bin"
            f.write_bytes(b"x")
            self.assertTrue(acceptable_direct_path(str(f), f, configured=()))

    def test_direct_path_requires_known_root_with_mappings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            known = Path(tmp) / "known"
            known.mkdir()
            other = Path(tmp) / "other"
            other.mkdir()
            inside = known / "x.bin"
            inside.write_bytes(b"x")
            outside = other / "y.bin"
            outside.write_bytes(b"y")
            configured = (("/app/storage", known),)
            # inside a known root -> accepted
            self.assertTrue(acceptable_direct_path(str(inside), inside, configured))
            # existing file but outside all known roots -> rejected in VM mode
            self.assertFalse(acceptable_direct_path(str(outside), outside, configured))


class PathBoundaryTests(unittest.TestCase):
    def test_within_root_true_for_child(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertTrue(path_within_root(root / "a" / "b", root))

    def test_within_root_false_for_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "inside"
            root.mkdir()
            escaped = root / ".." / "outside.bin"
            self.assertFalse(path_within_root(escaped, root))

    def test_symlink_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            outside = Path(tmp) / "outside"
            outside.mkdir()
            link = root / "link"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported in this environment")
            # link/escape resolves outside root -> rejected
            self.assertFalse(path_within_root(link / "escape.bin", root))

    def test_safe_map_rejects_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            outside = Path(tmp) / "outside"
            outside.mkdir()
            link = root / "link"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported in this environment")
            mapped = safe_map_path_prefix(
                "/app/storage/link/escape.bin", "/app/storage", root
            )
            self.assertIsNone(mapped)


if __name__ == "__main__":
    unittest.main()
