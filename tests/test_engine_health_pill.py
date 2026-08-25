import unittest
from unittest.mock import patch

from app.main import health_tone_for, render_engine_card, worker_backed_engine_health
from app.models import EngineInstanceRecord, EngineNodeHealthRecord


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

    def test_api_host_status_does_not_override_worker_placement(self) -> None:
        engine = make_engine("microsoft_defender", "Microsoft Defender")
        original = {"ok": True, "status": "ready", "detail": "ok"}
        with patch(
            "app.main.get_worker_status",
            return_value={"engine_keys": [], "nodes": []},
        ):
            health = worker_backed_engine_health(engine, dict(original))

        self.assertFalse(health["ok"])
        self.assertEqual(health["status"], "no online worker")

    def test_local_engine_unsupported_status_is_left_alone(self) -> None:
        # static_metadata is deployment='local', not worker-backed.
        engine = make_engine("static_metadata", "Static Metadata")
        with patch("app.main.get_worker_status") as worker_status:
            health = worker_backed_engine_health(engine, dict(self.UNSUPPORTED))

        self.assertEqual(health["status"], "unsupported")
        worker_status.assert_not_called()

    def test_worker_report_supplies_real_instance_health_and_versions(self) -> None:
        engine = make_engine("microsoft_defender", "Microsoft Defender")
        record = EngineNodeHealthRecord(
            node_id="windows-01",
            engine_instance_id=engine.id,
            status="healthy",
            ok=True,
            health_status="available",
            detail="Defender is ready.",
            product_version="4.18",
            engine_version="1.1",
            signature_version="1.2.3",
            service_state="enabled",
            storage_readable=True,
            storage_writable=True,
            consecutive_failures=0,
            last_checked_at=1000,
            last_success_at=1000,
            last_scan_success_at=900,
            details_json="{}",
            check_worker_id=None,
            check_generation=1,
            check_lease_expires_at=None,
            created_at="",
            updated_at="",
        )
        worker_status = {
            "engine_keys": ["microsoft_defender"],
            "nodes": [
                {
                    "node_id": "windows-01",
                    "schedulable": True,
                    "engine_keys": ["microsoft_defender"],
                    "labels": {"os": "windows"},
                }
            ],
        }
        with patch("app.main.get_worker_status", return_value=worker_status), patch(
            "app.main.list_engine_node_health", return_value=[record]
        ), patch(
            "app.main.eligible_worker_node_ids_for_engine_instance",
            return_value={"windows-01"},
        ):
            health = worker_backed_engine_health(engine, dict(self.UNSUPPORTED))

        self.assertTrue(health["ok"])
        self.assertEqual(health["status"], "available")
        self.assertIn("windows-01", health["detail"])
        self.assertIn("1.2.3", health["detail"])


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
        self.assertIn("Manual hash-only execution", rendered)
        self.assertIn("REST and ICAP automation exclude this metered engine", rendered)
        self.assertIn("allow fresh zero-detection reports in Scan Hash", rendered)
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
