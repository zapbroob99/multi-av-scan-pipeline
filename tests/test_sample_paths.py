import unittest

from app.services.sample_paths import SAMPLES_DIR, map_path_prefix


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

if __name__ == "__main__":
    unittest.main()
