import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
import zipfile

from app.workers import control_api_worker, windows_agent, windows_service
from app.engines.microsoft_defender import get_microsoft_defender_config
from tools.package_windows_worker import build_package
from tools.verify_windows_worker_bundle import verify_bundle


class WindowsServiceConfigTests(unittest.TestCase):
    def test_config_parser_accepts_masp_values_and_rejects_database_url(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "worker.env"
            config.write_text(
                "# managed config\n"
                "MASP_WORKER_CONTROL_URL=https://masp/api/v1/worker-control\n"
                "MASP_WORKER_LABELS=site=istanbul,os=windows\n",
                encoding="utf-8",
            )
            parsed = windows_service.parse_config_file(config)
            self.assertEqual(parsed["MASP_WORKER_LABELS"], "site=istanbul,os=windows")

            config.write_text("MASP_DATABASE_URL=postgresql://forbidden\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                windows_service.parse_config_file(config)

    def test_service_environment_forces_control_transport_and_clears_database(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token = root / "agent.token"
            token.write_text("masp_wa_test", encoding="utf-8")
            config = root / "worker.env"
            config.write_text(
                "MASP_WORKER_CONTROL_URL=https://masp/api/v1/worker-control\n"
                f"MASP_WORKER_AGENT_TOKEN_FILE={token}\n"
                "MASP_WORKER_NODE_ID=defender-01\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"MASP_DATABASE_URL": "postgresql://no"}, clear=False):
                values = windows_service.load_service_environment(config)
                self.assertEqual(values["MASP_WORKER_TRANSPORT"], "control_api")
                self.assertNotIn("MASP_DATABASE_URL", os.environ)


class WindowsAgentPreflightTests(unittest.TestCase):
    def test_non_windows_preflight_fails_without_running_commands(self) -> None:
        result = windows_agent.defender_preflight(platform_name="posix")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "unsupported")

    def test_windows_preflight_uses_explicit_config_without_database_fallback(self) -> None:
        with patch(
            "app.workers.windows_agent.check_microsoft_defender_health",
            return_value={"ok": True, "status": "available", "detail": "ready"},
        ) as health:
            result = windows_agent.defender_preflight(platform_name="nt")
        self.assertTrue(result["ok"])
        config = health.call_args.kwargs["config"]
        self.assertEqual(config["mpcmdrun_path"], "auto")
        self.assertEqual(config["timeout_seconds"], 900)

    def test_complete_remote_defender_config_never_reads_local_database(self) -> None:
        remote_config = {
            "execution_mode": "powershell",
            "powershell_path": "powershell.exe",
            "mpcmdrun_path": "auto",
            "default_scan_type": "custom",
            "timeout_seconds": "900",
            "update_before_scan": "false",
            "require_real_time_enabled": "true",
        }
        with patch(
            "app.engines.microsoft_defender.engine_setting",
            side_effect=AssertionError("remote config must not use local DB"),
        ):
            resolved = get_microsoft_defender_config(remote_config)
        self.assertEqual(resolved["timeout_seconds"], 900)
        self.assertTrue(resolved["require_real_time_enabled"])

    def test_installed_preflight_loads_service_config_before_control_check(self) -> None:
        config_path = Path("C:/ProgramData/MASP/Worker/worker.env")
        with patch(
            "app.workers.windows_service.load_service_environment",
            return_value={
                "MASP_WORKER_NODE_ID": "defender-01",
                "MASP_WORKER_CONTROL_URL": "https://masp/api/v1/worker-control",
            },
        ) as load, patch(
            "app.workers.windows_agent.control_preflight",
            return_value={"ok": True, "defender": {"ok": True}, "control_api": {"ok": True}},
        ):
            result = windows_agent.installed_service_preflight(config_path=config_path)

        self.assertTrue(result["ok"])
        self.assertEqual(result["service_config"]["node_id"], "defender-01")
        load.assert_called_once_with(config_path)

    def test_installed_preflight_normalizes_config_failure(self) -> None:
        with patch(
            "app.workers.windows_service.load_service_environment",
            side_effect=RuntimeError("config denied"),
        ):
            result = windows_agent.installed_service_preflight()

        self.assertFalse(result["ok"])
        self.assertIn("config denied", result["service_config"]["detail"])


class StoppableControlWorkerTests(unittest.TestCase):
    def test_pre_set_stop_event_avoids_polling_and_sends_stopping_heartbeat(self) -> None:
        stop = threading.Event()
        stop.set()
        fake_client = unittest.mock.Mock()
        with patch(
            "app.workers.control_api_worker.WorkerControlClient",
            return_value=fake_client,
        ), patch("app.workers.control_api_worker.control_url", return_value="https://masp"), patch(
            "app.workers.control_api_worker.agent_token", return_value="token"
        ), patch(
            "app.workers.control_api_worker.current_worker_node_id", return_value="node-1"
        ), patch(
            "app.workers.control_api_worker.worker_engine_keys",
            return_value={"microsoft_defender"},
        ):
            control_api_worker.run_forever(stop_event=stop)

        fake_client.post_json.assert_called_once()
        self.assertEqual(fake_client.post_json.call_args.args[0], "heartbeat")
        self.assertEqual(
            fake_client.post_json.call_args.args[1]["runtime_state"], "stopping"
        )


class WindowsWorkerPackageTests(unittest.TestCase):
    def test_package_contains_service_scripts_manifest_and_no_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "worker.zip"
            manifest = build_package(output)
            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
        self.assertIn("app/workers/windows_service.py", names)
        self.assertIn("tools/windows_worker/Install-MaspWorker.ps1", names)
        self.assertIn("tools/windows_worker/Invoke-MaspWorkerAcceptance.ps1", names)
        self.assertIn("tools/verify_scan_api.py", names)
        self.assertIn("tools/verify_windows_worker_bundle.py", names)
        self.assertIn("windows-worker-manifest.json", names)
        self.assertFalse(any(name.endswith((".pyc", ".pyo")) for name in names))
        self.assertGreater(len(manifest["files"]), 10)

    def test_extracted_bundle_verifier_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "worker.zip"
            extracted = root / "extracted"
            build_package(output)
            with zipfile.ZipFile(output) as archive:
                archive.extractall(extracted)

            result = verify_bundle(extracted)
            self.assertTrue(result["ok"])
            target = extracted / "app" / "workers" / "windows_agent.py"
            target.write_bytes(target.read_bytes() + b"\n# tampered\n")
            with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                verify_bundle(extracted)

    def test_bundle_verifier_rejects_manifest_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "windows-worker-manifest.json").write_text(
                '{"package":"masp-windows-worker","version":"0.1.0",'
                '"files":{"../outside":"00"}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "Unsafe path"):
                verify_bundle(root)

    def test_bundle_verifier_rejects_untracked_executable_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "worker.zip"
            extracted = root / "extracted"
            build_package(output)
            with zipfile.ZipFile(output) as archive:
                archive.extractall(extracted)
            unexpected = extracted / "app" / "workers" / "unexpected.py"
            unexpected.write_text("raise RuntimeError('untracked')\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "Untracked executable source"):
                verify_bundle(extracted)


if __name__ == "__main__":
    unittest.main()
