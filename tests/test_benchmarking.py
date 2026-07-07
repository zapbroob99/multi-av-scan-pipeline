import unittest

from app.services.benchmarking import BenchmarkRun, percentile, summarize_benchmark
from tools.benchmark_scans import extract_engine_durations


class BenchmarkingTests(unittest.TestCase):
    def test_percentile_returns_expected_rank(self) -> None:
        self.assertEqual(percentile([100, 200, 300, 400, 500], 0.50), 300)
        self.assertEqual(percentile([100, 200, 300, 400, 500], 0.95), 500)

    def test_summarize_benchmark_reports_partial_runs_and_counts(self) -> None:
        runs = [
            BenchmarkRun(
                request_index=1,
                scan_id=101,
                accepted=True,
                completed=True,
                submit_duration_ms=120,
                queue_wait_ms=400,
                processing_duration_ms=1400,
                total_duration_ms=1800,
                polls=2,
                queue_position=0,
                final_status="completed",
                final_verdict="critical",
                decision_action="block",
                expected_engines=4,
                reported_engines=4,
                completed_engines=4,
                failed_engines=0,
                skipped_engines=0,
                detections=3,
                engine_durations_ms={"ClamAV": 1200, "YARA": 300},
                worker_event_durations_ms={
                    "load_context": 20,
                    "engine_run:ClamAV": 1250,
                    "finalize": 30,
                },
                error=None,
            ),
            BenchmarkRun(
                request_index=2,
                scan_id=102,
                accepted=True,
                completed=True,
                submit_duration_ms=140,
                queue_wait_ms=600,
                processing_duration_ms=1600,
                total_duration_ms=2200,
                polls=3,
                queue_position=1,
                final_status="completed",
                final_verdict="review",
                decision_action="review",
                expected_engines=4,
                reported_engines=3,
                completed_engines=3,
                failed_engines=0,
                skipped_engines=1,
                detections=0,
                engine_durations_ms={"ClamAV": 1800, "Microsoft Defender": 4200},
                worker_event_durations_ms={
                    "load_context": 30,
                    "engine_run:Microsoft Defender": 4300,
                    "finalize": 40,
                },
                error=None,
            ),
            BenchmarkRun(
                request_index=3,
                scan_id=None,
                accepted=False,
                completed=False,
                submit_duration_ms=90,
                queue_wait_ms=None,
                processing_duration_ms=None,
                total_duration_ms=None,
                polls=0,
                queue_position=None,
                final_status="submit_failed",
                final_verdict=None,
                decision_action=None,
                expected_engines=None,
                reported_engines=None,
                completed_engines=None,
                failed_engines=None,
                skipped_engines=None,
                detections=None,
                error="401 unauthorized",
            ),
        ]

        summary = summarize_benchmark(
            runs,
            base_url="http://localhost:8000",
            sample_name="eicar.com",
            sample_size_bytes=68,
            requested_runs=3,
            concurrency=2,
            poll_interval_seconds=1.0,
            wait_seconds=0,
            benchmark_duration_ms=2500,
        )

        self.assertEqual(summary["summary"]["submitted"], 3)
        self.assertEqual(summary["summary"]["completed"], 2)
        self.assertEqual(summary["summary"]["errored"], 1)
        self.assertEqual(summary["summary"]["terminal_statuses"]["completed"], 2)
        self.assertEqual(summary["summary"]["terminal_statuses"]["submit_failed"], 1)
        self.assertEqual(summary["summary"]["decision_actions"]["block"], 1)
        self.assertEqual(summary["summary"]["decision_actions"]["review"], 1)
        self.assertEqual(summary["engines"]["partial_runs"], 1)
        self.assertEqual(summary["latency_ms"]["submit_p50"], 120)
        self.assertEqual(summary["latency_ms"]["queue_wait_p50"], 400)
        self.assertEqual(summary["latency_ms"]["processing_p50"], 1400)
        self.assertEqual(summary["engine_timings_ms"]["ClamAV"]["samples"], 2)
        self.assertEqual(summary["engine_timings_ms"]["ClamAV"]["avg"], 1500)
        self.assertEqual(summary["engine_timings_ms"]["YARA"]["p95"], 300)
        self.assertEqual(summary["worker_timing_ms"]["load_context"]["avg"], 25)
        self.assertEqual(summary["worker_timing_ms"]["finalize"]["p95"], 40)

    def test_extract_engine_durations_ignores_skipped_results(self) -> None:
        durations = extract_engine_durations(
            [
                {
                    "engine_name": "Microsoft Defender",
                    "status": "skipped",
                    "duration_ms": 21000,
                },
                {
                    "engine_name": "ClamAV",
                    "status": "completed",
                    "duration_ms": 42,
                },
            ]
        )

        self.assertEqual(durations, {"ClamAV": 42})


if __name__ == "__main__":
    unittest.main()
