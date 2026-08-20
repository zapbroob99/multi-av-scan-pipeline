import unittest
from unittest.mock import patch

from app.main import health_tone_for, render_engine_card, worker_backed_engine_health
from app.models import EngineInstanceRecord


def make_engine(adapter_key: str, display_name: str) -> EngineInstanceRecord:
    return EngineInstanceRecord(
        id=10,
        adapter_key=adapter_key,
        display_name=display_name,
        enabled=True,
        config_json="{}",
        created_at="",
        updated_at="",
    )


class WorkerBackedEngineHealthTests(unittest.TestCase):
    UNSUPPORTED = {
        "ok": False,
        "status": "unsupported",
        "detail": "Only supported on Windows workers.",
    }

    def test_unsupported_defender_with_online_worker_reads_healthy(self) -> None:
        engine = make_engine("microsoft_defender", "Microsoft Defender")
        with patch(
            "app.main.get_worker_status",
            return_value={"engine_keys": ["clamav", "microsoft_defender"]},
        ):
            health = worker_backed_engine_health(engine, dict(self.UNSUPPORTED))

        self.assertTrue(health["ok"])
        self.assertEqual(health["status"], "worker online")
        self.assertEqual(health_tone_for(engine.adapter_key, health), "success")

    def test_unsupported_defender_without_worker_reads_no_online_worker(self) -> None:
        engine = make_engine("microsoft_defender", "Microsoft Defender")
        with patch(
            "app.main.get_worker_status",
            return_value={"engine_keys": ["clamav", "yara"]},
        ):
            health = worker_backed_engine_health(engine, dict(self.UNSUPPORTED))

        self.assertFalse(health["ok"])
        self.assertEqual(health["status"], "no online worker")
        self.assertEqual(health_tone_for(engine.adapter_key, health), "warning")

    def test_non_unsupported_status_passes_through_untouched(self) -> None:
        engine = make_engine("microsoft_defender", "Microsoft Defender")
        original = {"ok": True, "status": "ready", "detail": "ok"}
        with patch("app.main.get_worker_status") as worker_status:
            health = worker_backed_engine_health(engine, dict(original))

        self.assertEqual(health, original)
        worker_status.assert_not_called()

    def test_local_engine_unsupported_status_is_left_alone(self) -> None:
        # static_metadata is deployment='local', not worker-backed.
        engine = make_engine("static_metadata", "Static Metadata")
        with patch("app.main.get_worker_status") as worker_status:
            health = worker_backed_engine_health(engine, dict(self.UNSUPPORTED))

        self.assertEqual(health["status"], "unsupported")
        worker_status.assert_not_called()


class VirusTotalEngineCardTests(unittest.TestCase):
    def test_hash_only_engine_card_exposes_lifecycle_without_rendering_secret(self) -> None:
        engine = make_engine("virustotal", "VirusTotal")
        with patch.dict(
            "os.environ",
            {
                "MASP_VIRUSTOTAL_ENABLED": "1",
                "MASP_VIRUSTOTAL_API_KEY": "ui-secret-must-not-render",
            },
            clear=False,
        ):
            rendered = render_engine_card(engine, {})

        self.assertIn("SHA-256 hash-only reputation", rendered)
        self.assertIn("GET /api/v1/hashes/{sha256}", rendered)
        self.assertIn('class="engine-logo engine-logo-virustotal"', rendered)
        self.assertIn('viewBox="0 0 24 24"', rendered)
        self.assertIn("Disable", rendered)
        self.assertIn("Remove", rendered)
        self.assertIn("Test connection", rendered)
        self.assertIn('action="/engines/virustotal/config"', rendered)
        self.assertIn('type="password" name="virustotal_api_key"', rendered)
        self.assertNotIn("ui-secret-must-not-render", rendered)


if __name__ == "__main__":
    unittest.main()
