import os
import unittest
from unittest.mock import patch

from app.services import scan_policy
from app.services.configuration_context import policy_context, http_context


class ConfigurationContextTests(unittest.TestCase):
    def test_override_environment_and_default_are_distinct(self):
        with patch.dict(os.environ, {'MASP_UPLOAD_MAX_BYTES': '123'}, clear=True):
            self.assertEqual(policy_context('upload_max_bytes', '456').source, 'Console override')
            self.assertIn('API process environment', policy_context('upload_max_bytes', '').source)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(policy_context('upload_max_bytes', None).source, 'Built-in default')

    def test_invalid_and_clamped_sources_explain_actual_resolution_without_echo(self):
        with patch.dict(os.environ, {'MASP_API_MAX_WAIT_SECONDS': 'private-bad-value'}, clear=True):
            context = policy_context('api_max_wait_seconds', '')
            self.assertEqual(context.state, 'defaulted')
            self.assertNotIn('private-bad-value', context.model_dump_json())
            self.assertEqual(scan_policy.resolve_raw('api_max_wait_seconds', ''), 15)
        self.assertEqual(policy_context('api_retry_after_seconds', '0').state, 'clamped')
        self.assertEqual(scan_policy.resolve_raw('api_retry_after_seconds', '0'), 1)

    def test_event_switch_matches_event_producer_literal_one_semantics(self):
        for value in ('1', ' 1 ', '0', '2', '-1', '+1', '01', 'invalid'):
            self.assertEqual(scan_policy.resolve_raw('siem_not_allowed_events', value), int(value.strip() == '1'))
        self.assertEqual(policy_context('siem_not_allowed_events', '2').state, 'defaulted')
        self.assertIn('Workers may have different', policy_context('siem_not_allowed_events', '').note)

    def test_http_failure_is_not_an_editable_console_setting(self):
        context = http_context(False)
        self.assertEqual(context.state, 'invalid')
        self.assertIn('deployment', context.edit_at)
        self.assertIn('restart', context.restart)
