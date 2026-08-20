import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError

from app.engines.virustotal import (
    run_virustotal_file_hash_engine,
    run_virustotal_hash_engine,
)
from app.services.virustotal import (
    InvalidSha256Error,
    VirusTotalConfig,
    VirusTotalNotConfiguredError,
    VirusTotalQuotaError,
    VirusTotalReport,
    VirusTotalUnavailableError,
    _NoRedirectHandler,
    build_reputation_payload,
    clear_virustotal_cache,
    load_virustotal_config,
    lookup_virustotal_hash,
    normalize_sha256,
)


SHA256 = "a" * 64


def config(**overrides: object) -> VirusTotalConfig:
    values = {
        "api_key": "test-api-key",
        "timeout_seconds": 10,
        "cache_seconds": 3600,
        "unknown_cache_seconds": 300,
        "cache_max_entries": 10000,
        "malicious_threshold": 1,
        "allow_undetected": False,
        "max_age_days": 30,
    }
    values.update(overrides)
    return VirusTotalConfig(**values)


def report(**stats: int) -> VirusTotalReport:
    complete_stats = {
        "malicious": 0,
        "suspicious": 0,
        "undetected": 0,
        "harmless": 0,
        "timeout": 0,
        "failure": 0,
        "type-unsupported": 0,
        "confirmed-timeout": 0,
    }
    complete_stats.update(stats)
    return VirusTotalReport(
        sha256=SHA256,
        stats=complete_stats,
        last_analysis_date=datetime.now(timezone.utc),
    )


def vt_body(*, sha256: str = SHA256, **stats: int) -> bytes:
    return json.dumps(
        {
            "data": {
                "type": "file",
                "id": sha256,
                "attributes": {
                    "last_analysis_date": 1786924800,
                    "last_analysis_stats": stats,
                },
            }
        }
    ).encode("utf-8")


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]


class VirusTotalValidationTests(unittest.TestCase):
    def test_normalizes_sha256_case_and_whitespace(self) -> None:
        self.assertEqual(normalize_sha256(f"  {'A' * 64}  "), SHA256)

    def test_rejects_non_sha256_and_non_hex_values(self) -> None:
        for value in ("a" * 32, "a" * 63, "g" * 64, ""):
            with self.subTest(value=value), self.assertRaises(InvalidSha256Error):
                normalize_sha256(value)

    def test_configuration_is_disabled_by_default_and_requires_a_real_key(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "not enabled"):
            load_virustotal_config({})
        with self.assertRaisesRegex(RuntimeError, "API key"):
            load_virustotal_config(
                {
                    "MASP_VIRUSTOTAL_ENABLED": "1",
                    "MASP_VIRUSTOTAL_API_KEY": "CHANGE_ME_LICENSED_API_KEY",
                }
            )

    def test_configuration_bounds_operator_values(self) -> None:
        loaded = load_virustotal_config(
            {
                "MASP_VIRUSTOTAL_ENABLED": "1",
                "MASP_VIRUSTOTAL_API_KEY": "secret",
                "MASP_VIRUSTOTAL_TIMEOUT_SECONDS": "999",
                "MASP_VIRUSTOTAL_CACHE_SECONDS": "-1",
                "MASP_VIRUSTOTAL_UNKNOWN_CACHE_SECONDS": "99999",
                "MASP_VIRUSTOTAL_CACHE_MAX_ENTRIES": "999999",
                "MASP_VIRUSTOTAL_MALICIOUS_THRESHOLD": "0",
                "MASP_VIRUSTOTAL_ALLOW_UNDETECTED": "true",
                "MASP_VIRUSTOTAL_MAX_AGE_DAYS": "99999",
            }
        )

        self.assertEqual(loaded.timeout_seconds, 60)
        self.assertEqual(loaded.cache_seconds, 0)
        self.assertEqual(loaded.unknown_cache_seconds, 3600)
        self.assertEqual(loaded.cache_max_entries, 100000)
        self.assertEqual(loaded.malicious_threshold, 1)
        self.assertTrue(loaded.allow_undetected)
        self.assertEqual(loaded.max_age_days, 3650)


class VirusTotalPolicyTests(unittest.TestCase):
    def test_unknown_is_review_not_clean(self) -> None:
        payload = build_reputation_payload(SHA256, None, config(), cached=False)

        self.assertEqual(payload["status"], "unknown")
        self.assertEqual(payload["decision"]["action"], "review")
        self.assertFalse(payload["found"])

    def test_malicious_threshold_blocks(self) -> None:
        payload = build_reputation_payload(
            SHA256,
            report(malicious=3, undetected=60),
            config(malicious_threshold=3),
            cached=False,
        )

        self.assertEqual(payload["status"], "malicious")
        self.assertEqual(payload["decision"]["action"], "block")
        self.assertEqual(payload["stats"]["total"], 63)

    def test_below_threshold_or_suspicious_requires_review(self) -> None:
        below_threshold = build_reputation_payload(
            SHA256,
            report(malicious=1, undetected=60),
            config(malicious_threshold=2),
            cached=False,
        )
        suspicious = build_reputation_payload(
            SHA256,
            report(suspicious=1, undetected=60),
            config(),
            cached=False,
        )

        self.assertEqual(below_threshold["status"], "suspicious")
        self.assertEqual(below_threshold["decision"]["action"], "review")
        self.assertEqual(suspicious["decision"]["action"], "review")

    def test_undetected_requires_explicit_allow_policy(self) -> None:
        conservative = build_reputation_payload(
            SHA256, report(undetected=60), config(), cached=False
        )
        permissive = build_reputation_payload(
            SHA256,
            report(undetected=60),
            config(allow_undetected=True),
            cached=False,
        )

        self.assertEqual(conservative["status"], "undetected")
        self.assertEqual(conservative["decision"]["action"], "review")
        self.assertEqual(permissive["decision"]["action"], "allow")

    def test_stale_or_undated_undetected_report_cannot_allow(self) -> None:
        now = datetime(2026, 8, 17, tzinfo=timezone.utc)
        stale_report = report(undetected=60)
        stale_report = VirusTotalReport(
            sha256=stale_report.sha256,
            stats=stale_report.stats,
            last_analysis_date=now - timedelta(days=31),
        )
        no_date_report = VirusTotalReport(
            sha256=SHA256,
            stats=stale_report.stats,
            last_analysis_date=None,
        )
        enabled = config(allow_undetected=True, max_age_days=30)

        stale = build_reputation_payload(SHA256, stale_report, enabled, cached=False, now=now)
        undated = build_reputation_payload(SHA256, no_date_report, enabled, cached=False, now=now)

        self.assertEqual(stale["status"], "stale")
        self.assertEqual(stale["decision"]["action"], "review")
        self.assertEqual(undated["status"], "stale")
        self.assertEqual(undated["decision"]["action"], "review")


class VirusTotalEngineAdapterTests(unittest.TestCase):
    def test_malicious_reputation_is_normalized_as_an_engine_detection(self) -> None:
        payload = build_reputation_payload(
            SHA256,
            report(malicious=2, undetected=58),
            config(),
            cached=False,
        )
        with patch(
            "app.engines.virustotal.lookup_virustotal_hash", return_value=payload
        ):
            execution = run_virustotal_hash_engine(SHA256)

        self.assertTrue(execution.result.detected)
        self.assertEqual(execution.result.status, "completed")
        self.assertEqual(execution.result.severity, "critical")
        self.assertEqual(execution.result.signature, "VirusTotal 2/60 malicious")
        findings = json.loads(execution.result.findings_json)
        self.assertEqual(findings[0]["type"], "hash_reputation")
        self.assertEqual(findings[0]["matched_evidence"]["sha256"], SHA256)

    def test_unknown_hash_is_a_skipped_review_result_not_a_clean_detection(self) -> None:
        payload = build_reputation_payload(SHA256, None, config(), cached=False)
        with patch(
            "app.engines.virustotal.lookup_virustotal_hash", return_value=payload
        ):
            execution = run_virustotal_hash_engine(SHA256)

        self.assertFalse(execution.result.detected)
        self.assertEqual(execution.result.status, "skipped")
        self.assertIn("no report", execution.result.error_message or "")
        self.assertEqual(json.loads(execution.result.findings_json), [])

    def test_file_scan_uses_the_precomputed_sha256(self) -> None:
        payload = build_reputation_payload(
            SHA256,
            report(malicious=2, undetected=58),
            config(),
            cached=False,
        )
        scan = SimpleNamespace(sha256=SHA256)
        with patch(
            "app.engines.virustotal.lookup_virustotal_hash", return_value=payload
        ) as lookup:
            result = run_virustotal_file_hash_engine(scan)  # type: ignore[arg-type]

        lookup.assert_called_once_with(SHA256, None)
        self.assertEqual(result.engine_name, "VirusTotal")
        self.assertTrue(result.detected)

    def test_file_scan_normalizes_upstream_failure_as_an_engine_failure(self) -> None:
        scan = SimpleNamespace(sha256=SHA256)
        with patch(
            "app.engines.virustotal.lookup_virustotal_hash",
            side_effect=VirusTotalUnavailableError("VirusTotal could not be reached."),
        ):
            result = run_virustotal_file_hash_engine(scan)  # type: ignore[arg-type]

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.detected)
        self.assertIn("could not be reached", result.error_message or "")
        self.assertFalse(json.loads(result.details_json)["file_uploaded"])


class VirusTotalClientTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_virustotal_cache()
        self.env = {
            "MASP_VIRUSTOTAL_ENABLED": "1",
            "MASP_VIRUSTOTAL_API_KEY": "licensed-test-key",
            "MASP_VIRUSTOTAL_CACHE_SECONDS": "3600",
            "MASP_VIRUSTOTAL_UNKNOWN_CACHE_SECONDS": "300",
        }

    def tearDown(self) -> None:
        clear_virustotal_cache()

    def test_lookup_sends_only_hash_and_api_key_header(self) -> None:
        response = FakeResponse(vt_body(malicious=2, undetected=58))
        with patch.dict(os.environ, self.env, clear=False), patch(
            "app.services.virustotal._URL_OPENER.open", return_value=response
        ) as mocked_open:
            payload = lookup_virustotal_hash(SHA256.upper())

        request = mocked_open.call_args.args[0]
        self.assertEqual(request.full_url, f"https://www.virustotal.com/api/v3/files/{SHA256}")
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.get_header("X-apikey"), "licensed-test-key")
        self.assertIsNone(request.data)
        self.assertEqual(payload["decision"]["action"], "block")

    def test_redirects_are_refused_before_the_api_key_can_be_forwarded(self) -> None:
        handler = _NoRedirectHandler()

        self.assertIsNone(
            handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example", None)
        )

    def test_positive_and_unknown_results_are_cached(self) -> None:
        with patch.dict(os.environ, self.env, clear=False), patch(
            "app.services.virustotal._URL_OPENER.open",
            return_value=FakeResponse(vt_body(undetected=60)),
        ) as positive_open:
            first = lookup_virustotal_hash(SHA256)
            second = lookup_virustotal_hash(SHA256)

        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        positive_open.assert_called_once()

        clear_virustotal_cache()
        not_found = HTTPError(
            url=f"https://www.virustotal.com/api/v3/files/{SHA256}",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=BytesIO(b"{}"),
        )
        with patch.dict(os.environ, self.env, clear=False), patch(
            "app.services.virustotal._URL_OPENER.open", side_effect=not_found
        ) as unknown_open:
            first_unknown = lookup_virustotal_hash(SHA256)
            second_unknown = lookup_virustotal_hash(SHA256)

        self.assertEqual(first_unknown["status"], "unknown")
        self.assertTrue(second_unknown["cached"])
        unknown_open.assert_called_once()
        not_found.close()

    def test_cache_has_a_bounded_lru_size(self) -> None:
        second_hash = "b" * 64
        bounded_env = {**self.env, "MASP_VIRUSTOTAL_CACHE_MAX_ENTRIES": "1"}

        def open_for_hash(request: object, **_: object) -> FakeResponse:
            requested_hash = str(request.full_url).rsplit("/", 1)[-1]
            return FakeResponse(vt_body(sha256=requested_hash, undetected=60))

        with patch.dict(os.environ, bounded_env, clear=False), patch(
            "app.services.virustotal._URL_OPENER.open", side_effect=open_for_hash
        ) as mocked_open:
            lookup_virustotal_hash(SHA256)
            lookup_virustotal_hash(second_hash)
            lookup_virustotal_hash(SHA256)

        self.assertEqual(mocked_open.call_count, 3)

    def test_quota_response_preserves_numeric_retry_after(self) -> None:
        quota_error = HTTPError(
            url=f"https://www.virustotal.com/api/v3/files/{SHA256}",
            code=429,
            msg="Too Many Requests",
            hdrs={"Retry-After": "45"},
            fp=BytesIO(b"{}"),
        )
        with patch.dict(os.environ, self.env, clear=False), patch(
            "app.services.virustotal._URL_OPENER.open", side_effect=quota_error
        ):
            with self.assertRaises(VirusTotalQuotaError) as context:
                lookup_virustotal_hash(SHA256)

        self.assertEqual(context.exception.retry_after, 45)
        quota_error.close()

    def test_upstream_rejected_credentials_are_configuration_failure(self) -> None:
        auth_error = HTTPError(
            url=f"https://www.virustotal.com/api/v3/files/{SHA256}",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=BytesIO(b"{}"),
        )
        with patch.dict(os.environ, self.env, clear=False), patch(
            "app.services.virustotal._URL_OPENER.open", side_effect=auth_error
        ):
            with self.assertRaises(VirusTotalNotConfiguredError):
                lookup_virustotal_hash(SHA256)
        auth_error.close()

    def test_rejects_malformed_or_mismatched_reports(self) -> None:
        mismatched = json.dumps(
            {"data": {"id": "b" * 64, "attributes": {"last_analysis_stats": {}}}}
        ).encode("utf-8")
        for body in (b"not-json", mismatched):
            clear_virustotal_cache()
            with self.subTest(body=body), patch.dict(os.environ, self.env, clear=False), patch(
                "app.services.virustotal._URL_OPENER.open", return_value=FakeResponse(body)
            ):
                with self.assertRaises(VirusTotalUnavailableError):
                    lookup_virustotal_hash(SHA256)


if __name__ == "__main__":
    unittest.main()
