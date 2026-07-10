import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from app.engines import yara_engine
from app.engines.yara_engine import (
    YaraBatchTimeout,
    cached_rule_files,
    clear_rule_files_cache,
    run_yara_engine,
    scan_single_invocation,
)
from app.models import ScanRecord


@dataclass
class FakeCompleted:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def make_scan() -> ScanRecord:
    return ScanRecord(
        id=1,
        sample_id=1,
        case_name="Case",
        priority="Normal",
        note="",
        source="api",
        status="running",
        verdict="pending",
        risk_score=None,
        created_at="2026-07-10 00:00:00+00:00",
        started_at=None,
        completed_at=None,
        failed_at=None,
        attempt_count=0,
        last_error=None,
        original_filename="sample.bin",
        stored_filename="sample.bin",
        storage_path="storage/samples/sample.bin",
        content_type="application/octet-stream",
        size_bytes=16,
        md5="md5",
        sha1="sha1",
        sha256="sha256",
    )


class RuleFilesCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_rule_files_cache()

    def tearDown(self) -> None:
        clear_rule_files_cache()

    def test_discovery_cached_within_ttl(self) -> None:
        rules = [Path("r1.yar")]
        with patch.object(yara_engine, "rules_cache_seconds", return_value=30), patch.object(
            yara_engine, "monotonic", return_value=1000.0
        ), patch.object(yara_engine, "list_rule_files", return_value=rules) as discover:
            cached_rule_files(Path("rules"))
            cached_rule_files(Path("rules"))

        self.assertEqual(discover.call_count, 1)

    def test_discovery_rewalks_after_ttl(self) -> None:
        with patch.object(yara_engine, "rules_cache_seconds", return_value=30), patch.object(
            yara_engine, "monotonic", side_effect=[1000.0, 1031.0]
        ), patch.object(yara_engine, "list_rule_files", return_value=[]) as discover:
            cached_rule_files(Path("rules"))
            cached_rule_files(Path("rules"))

        self.assertEqual(discover.call_count, 2)

    def test_discovery_rewalks_for_different_dir(self) -> None:
        with patch.object(yara_engine, "rules_cache_seconds", return_value=30), patch.object(
            yara_engine, "monotonic", return_value=1000.0
        ), patch.object(yara_engine, "list_rule_files", return_value=[]) as discover:
            cached_rule_files(Path("rules-a"))
            cached_rule_files(Path("rules-b"))

        self.assertEqual(discover.call_count, 2)

    def test_discovery_disabled_when_ttl_zero(self) -> None:
        with patch.object(yara_engine, "rules_cache_seconds", return_value=0), patch.object(
            yara_engine, "list_rule_files", return_value=[]
        ) as discover:
            cached_rule_files(Path("rules"))
            cached_rule_files(Path("rules"))

        self.assertEqual(discover.call_count, 2)

    def test_rediscovers_when_rule_file_added(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp)
            (rules_dir / "a.yar").write_text("rule A { condition: true }")
            with patch.object(
                yara_engine, "rules_cache_seconds", return_value=30
            ), patch.object(yara_engine, "monotonic", return_value=1000.0), patch.object(
                yara_engine, "list_rule_files", return_value=[rules_dir / "a.yar"]
            ) as discover:
                cached_rule_files(rules_dir)
                cached_rule_files(rules_dir)  # unchanged -> cached
                self.assertEqual(discover.call_count, 1)

                # Add a second rule file: count changes -> immediate re-discovery.
                (rules_dir / "b.yar").write_text("rule B { condition: true }")
                cached_rule_files(rules_dir)
                self.assertEqual(discover.call_count, 2)

    def test_rediscovers_when_rule_file_mtime_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp)
            rule = rules_dir / "a.yar"
            rule.write_text("rule A { condition: true }")
            with patch.object(
                yara_engine, "rules_cache_seconds", return_value=30
            ), patch.object(yara_engine, "monotonic", return_value=1000.0), patch.object(
                yara_engine, "list_rule_files", return_value=[rule]
            ) as discover:
                cached_rule_files(rules_dir)
                self.assertEqual(discover.call_count, 1)

                # Bump mtime well into the future: edit detected within TTL.
                future = os.stat(rule).st_mtime_ns + 5_000_000_000
                os.utime(rule, ns=(future, future))
                cached_rule_files(rules_dir)
                self.assertEqual(discover.call_count, 2)


class SingleInvocationTests(unittest.TestCase):
    def test_clean_run_returns_matches(self) -> None:
        rule_files = [Path("a.yar"), Path("b.yar")]
        with patch.object(
            yara_engine.subprocess,
            "run",
            return_value=FakeCompleted(returncode=0, stdout="EvilRule /tmp/sample\n"),
        ) as run:
            result = scan_single_invocation("yara", rule_files, Path("/tmp/sample"), 30)

        self.assertIsNotNone(result)
        assert result is not None
        _outputs, errors, matches = result
        self.assertEqual(matches, ["EvilRule"])
        self.assertEqual(errors, [])
        # One invocation for all rule files, not one per file.
        self.assertEqual(run.call_count, 1)
        args = run.call_args.args[0]
        self.assertIn("a.yar", args)
        self.assertIn("b.yar", args)

    def test_nonzero_exit_signals_fallback(self) -> None:
        with patch.object(
            yara_engine.subprocess,
            "run",
            return_value=FakeCompleted(returncode=1, stderr="duplicated identifier"),
        ):
            result = scan_single_invocation("yara", [Path("a.yar")], Path("/tmp/s"), 30)
        self.assertIsNone(result)

    def test_timeout_raises_instead_of_fallback(self) -> None:
        with patch.object(
            yara_engine.subprocess,
            "run",
            side_effect=yara_engine.subprocess.TimeoutExpired("yara", 30),
        ):
            with self.assertRaises(YaraBatchTimeout):
                scan_single_invocation("yara", [Path("a.yar")], Path("/tmp/s"), 30)


class RunYaraEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_rule_files_cache()
        self.existing_file = Path(__file__).resolve()

    def tearDown(self) -> None:
        clear_rule_files_cache()

    def _patches(self):
        return [
            patch.object(
                yara_engine,
                "get_yara_config",
                return_value={
                    "command": "yara",
                    "rules_dir": "rules",
                    "rule_count": 2,
                    "timeout_seconds": 30,
                    "enabled": True,
                },
            ),
            patch.object(
                yara_engine,
                "cached_rule_files",
                return_value=[Path("a.yar"), Path("b.yar")],
            ),
            patch.object(yara_engine.shutil, "which", return_value="yara"),
            patch.object(yara_engine, "resolve_sample_path", return_value=self.existing_file),
        ]

    def test_single_invocation_detection(self) -> None:
        patches = self._patches()
        for p in patches:
            p.start()
        try:
            with patch.object(
                yara_engine.subprocess,
                "run",
                return_value=FakeCompleted(returncode=0, stdout="EvilRule /path\n"),
            ) as run:
                result = run_yara_engine(make_scan())
        finally:
            for p in patches:
                p.stop()

        self.assertEqual(result.status, "completed")
        self.assertTrue(result.detected)
        self.assertEqual(result.signature, "EvilRule")
        self.assertEqual(run.call_count, 1)  # single invocation, not per-file

    def test_falls_back_to_per_file_on_batch_error(self) -> None:
        patches = self._patches()
        for p in patches:
            p.start()
        try:
            # First call = batch invocation errors; next calls = per-file loop.
            with patch.object(
                yara_engine.subprocess,
                "run",
                side_effect=[
                    FakeCompleted(returncode=1, stderr="duplicated identifier"),
                    FakeCompleted(returncode=0, stdout="EvilRule /path\n"),
                    FakeCompleted(returncode=0, stdout=""),
                ],
            ) as run:
                result = run_yara_engine(make_scan())
        finally:
            for p in patches:
                p.stop()

        self.assertEqual(result.status, "completed")
        self.assertTrue(result.detected)
        self.assertEqual(result.signature, "EvilRule")
        # 1 batch attempt + 2 per-file calls.
        self.assertEqual(run.call_count, 3)

    def test_batch_timeout_fails_without_per_file_fallback(self) -> None:
        patches = self._patches()
        for p in patches:
            p.start()
        try:
            with patch.object(
                yara_engine.subprocess,
                "run",
                side_effect=yara_engine.subprocess.TimeoutExpired("yara", 30),
            ) as run:
                result = run_yara_engine(make_scan())
        finally:
            for p in patches:
                p.stop()

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.detected)
        self.assertIn("timed out", str(result.error_message))
        # Exactly one attempt: no per-file retry storm after a batch timeout.
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
