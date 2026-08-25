import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.engines.virustotal import HashEngineExecution
from app.main import (
    engine_result_verdict_pill,
    hash_scan_page,
    hash_scan_submit,
    render_engine_result_rows,
    render_hash_scan_page,
)
from app.models import EngineInstanceRecord, EngineResultInput, UserRecord


SHA256 = "a" * 64


class FileScanVirusTotalUiTests(unittest.TestCase):
    def test_review_policy_is_not_rendered_as_clean(self) -> None:
        result = SimpleNamespace(
            status="completed",
            detected=False,
            details_json='{"decision":{"action":"review"}}',
        )

        self.assertIn("Review", engine_result_verdict_pill(result))  # type: ignore[arg-type]

    def test_file_result_shows_a_compact_reputation_summary(self) -> None:
        payload = dict(execution(action="allow").payload)
        payload["mode"] = "file_hash_lookup"
        payload["file_uploaded"] = False
        payload["decision"] = {
            "action": "allow",
            "reason": "No malicious or suspicious detections.",
        }
        result = SimpleNamespace(
            engine_name="VirusTotal",
            engine_version="api-v3",
            status="completed",
            detected=False,
            severity="info",
            confidence=75,
            signature=None,
            duration_ms=12,
            error_message=None,
            raw_output=json.dumps(payload),
            details_json=json.dumps(payload),
        )

        rendered = render_engine_result_rows([result])  # type: ignore[list-item]

        self.assertIn("VirusTotal", rendered)
        self.assertIn("No detections", rendered)
        self.assertIn("Last analysis", rendered)
        self.assertIn("Live lookup", rendered)
        self.assertIn(">60</strong>", rendered)
        self.assertIn(f"https://www.virustotal.com/gui/file/{SHA256}", rendered)
        self.assertIn("Only the hash was queried", rendered)
        self.assertIn("Technical details", rendered)
        self.assertNotIn("Undetected policy", rendered)
        self.assertNotIn("Freshness limit", rendered)
        self.assertNotIn("Why this verdict?", rendered)

    def test_file_result_treats_no_report_as_neutral_enrichment(self) -> None:
        payload = dict(execution(action="allow", status="unknown").payload)
        payload.update(
            {
                "found": False,
                "stats": None,
                "mode": "file_hash_lookup",
                "file_uploaded": False,
                # Legacy file results persisted the strict hash-policy review.
                # The manual result UI must still present this as neutral.
                "decision": {
                    "action": "review",
                    "reason": "No report; hash policy requires review.",
                },
                "last_analysis_date": None,
                "permalink": None,
            }
        )
        result = SimpleNamespace(
            engine_name="VirusTotal",
            engine_version="api-v3",
            status="completed",
            detected=False,
            severity="info",
            confidence=0,
            signature=None,
            duration_ms=12,
            error_message=None,
            raw_output=json.dumps(payload),
            details_json=json.dumps(payload),
        )

        rendered = render_engine_result_rows([result])  # type: ignore[list-item]

        self.assertIn("No report", rendered)
        self.assertIn("No VirusTotal report found", rendered)
        self.assertIn("does not change the file scan decision", rendered)
        self.assertNotIn("· Review", rendered)
        self.assertNotIn("Why this verdict?", rendered)


def user() -> UserRecord:
    return UserRecord(
        id=1,
        username="analyst",
        password_hash="test",
        role="analyst",
        created_at="2026-08-17T00:00:00+00:00",
        updated_at="2026-08-17T00:00:00+00:00",
    )


def engine() -> EngineInstanceRecord:
    return EngineInstanceRecord(
        id=10,
        adapter_key="virustotal",
        display_name="VirusTotal",
        enabled=True,
        config_json="{}",
        created_at="2026-08-17T00:00:00+00:00",
        updated_at="2026-08-17T00:00:00+00:00",
    )


def execution(*, action: str = "review", status: str = "undetected") -> HashEngineExecution:
    payload: dict[str, object] = {
        "hash": SHA256,
        "algorithm": "sha256",
        "source": "virustotal",
        "found": True,
        "status": status,
        "detail": "VirusTotal policy requires review.",
        "decision": {
            "action": action,
            "reason": "VirusTotal policy requires review.",
        },
        "stats": {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 60,
            "harmless": 0,
            "timeout": 0,
            "failure": 0,
            "type_unsupported": 0,
            "confirmed_timeout": 0,
            "total": 60,
        },
        "last_analysis_date": "2026-08-17T00:00:00+00:00",
        "permalink": f"https://www.virustotal.com/gui/file/{SHA256}",
        "cached": False,
        "policy": {
            "malicious_threshold": 1,
            "allow_undetected": False,
            "max_age_days": 30,
        },
    }
    return HashEngineExecution(
        result=EngineResultInput(
            engine_name="VirusTotal",
            engine_version="api-v3",
            signature_version="2026-08-17T00:00:00+00:00",
            status="completed",
            detected=action == "block",
            signature=None,
            severity="info",
            confidence=75,
            raw_output=json.dumps(payload),
            duration_ms=12,
        ),
        payload=payload,
    )


PUBLIC_CONFIG = {
    "configured": True,
    "detail": "Licensed VirusTotal API credentials are configured.",
}


class HashScanPageTests(unittest.TestCase):
    def test_tab_and_form_render_for_an_enabled_engine_without_secret(self) -> None:
        with patch("app.main.runtime_config", return_value=PUBLIC_CONFIG):
            rendered = render_hash_scan_page(
                user(),
                engines=[engine()],
            )

        self.assertIn('class="nav-link is-active" href="/hash-scan"', rendered)
        self.assertIn('action="/hash-scan" method="post"', rendered)
        self.assertIn('name="sha256"', rendered)
        self.assertIn('engine-logo-virustotal', rendered)
        self.assertNotIn("MASP_VIRUSTOTAL_API_KEY", rendered)

    def test_submit_executes_the_registry_engine_and_renders_review_not_clean(self) -> None:
        vt_engine = engine()
        vt_execution = execution()
        with patch("app.main.require_user", return_value=user()), patch(
            "app.main.enabled_hash_engines", return_value=[vt_engine]
        ), patch("app.main.run_hash_engine", return_value=vt_execution) as run_hash, patch(
            "app.main.runtime_config", return_value=PUBLIC_CONFIG
        ):
            rendered = hash_scan_submit(object(), sha256=SHA256.upper())

        run_hash.assert_called_once_with(vt_engine, SHA256)
        self.assertIn("Aggregate decision", rendered)
        self.assertIn('class="hash-scan-result hash-result-review"', rendered)
        self.assertIn("Why this decision?", rendered)
        self.assertIn("Manual review required", rendered)
        self.assertIn("Engine results", rendered)
        self.assertIn("Technical details", rendered)
        self.assertIn("Review", rendered)
        self.assertIn("Undetected", rendered)
        self.assertNotIn(">Clean<", rendered)
        self.assertIn("Only the SHA-256 digest was sent", rendered)
        self.assertIn(f"https://www.virustotal.com/gui/file/{SHA256}", rendered)

    def test_invalid_hash_is_escaped_and_does_not_execute_an_engine(self) -> None:
        with patch("app.main.require_user", return_value=user()), patch(
            "app.main.enabled_hash_engines", return_value=[engine()]
        ), patch("app.main.run_hash_engine") as run_hash, patch(
            "app.main.runtime_config", return_value=PUBLIC_CONFIG
        ):
            rendered = hash_scan_submit(object(), sha256="<script>alert(1)</script>")

        run_hash.assert_not_called()
        self.assertIn("Hash must be a 64-character SHA-256", rendered)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)

    def test_disabled_or_missing_engine_is_fail_closed(self) -> None:
        with patch("app.main.require_user", return_value=user()), patch(
            "app.main.enabled_hash_engines", return_value=[]
        ), patch("app.main.run_hash_engine") as run_hash:
            rendered = hash_scan_submit(object(), sha256=SHA256)

        run_hash.assert_not_called()
        self.assertIn("No hash-capable engine is added and enabled", rendered)
        self.assertIn("No hash engine enabled", rendered)

    def test_get_requires_session_and_resolves_current_engine_state(self) -> None:
        vt_engine = engine()
        with patch("app.main.require_user", return_value=user()) as require, patch(
            "app.main.enabled_hash_engines", return_value=[vt_engine]
        ), patch("app.main.runtime_config", return_value=PUBLIC_CONFIG):
            rendered = hash_scan_page(object())

        require.assert_called_once()
        self.assertIn("Submit SHA-256", rendered)
        self.assertIn("Ready engines", rendered)
        self.assertIn("1/1", rendered)


if __name__ == "__main__":
    unittest.main()
