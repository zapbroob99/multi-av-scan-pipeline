import json
import os
import time
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from app import database as db
from app.services import client_configuration, profile_rules, rule_preview
from app.services.content_types import SIGNATURES, classify, classify_detected_type
from tests import test_client_configuration as fixtures


class RulePreviewTests(unittest.TestCase):
    setUp = fixtures.ClientConfigurationTests.setUp
    tearDown = fixtures.ClientConfigurationTests.tearDown

    def policy(self, *rules):
        policy = profile_rules.RulesPolicy.model_validate(dict(version=2, inconclusive='block', rules=[*rules,
            dict(action='scan', engines=[self.engine], archive='whole')]))
        with db.connect() as connection:
            connection.execute('UPDATE scan_profiles SET policy_json = ? WHERE id = ?', (profile_rules.rules_policy_json(policy), self.profile))
        return policy

    def body(self, **values):
        return rule_preview.RulePreviewBody(profile_id=self.profile, expected_revision=0, source='api', size_bytes=values.pop('size_bytes', 10), **values)

    def test_shared_header_classification_preserves_real_inspection(self):
        for offset, magic, type_key in SIGNATURES:
            for ext in ('pdf', 'exe', 'js', 'docx', 'txt', ''):
                filename = 'sample.' + ext
                self.assertEqual(classify(bytes(offset) + magic, filename), classify_detected_type(type_key, filename))
        self.assertEqual(classify(b'PK\x03\x04[Content_Types].xml', 'document.docx'), classify_detected_type('ooxml', 'document.docx'))

    def test_first_match_size_boundaries_and_shared_resolver(self):
        policy = self.policy(dict(when=dict(larger_than_bytes=10), action='block'),
            dict(when=dict(families=['pdf']), action='allow'))
        for size in (0, 10, 11, 9007199254740991):
            for header in ('pdf', 'pe', 'unrecognized'):
                body = self.body(size_bytes=size, header_type=header)
                result = rule_preview.preview(self.client, body)
                expected, rule = profile_rules.match(policy, size=size, classification=classify_detected_type(None if header == 'unrecognized' else header, 'preview'))
                self.assertEqual(result.status, 'matched')
                self.assertEqual((result.matches[0].number, result.matches[0].action), (expected, rule.action))

    def test_extension_never_invents_header_and_unknown_is_not_unrecognized(self):
        self.policy(dict(when=dict(masquerade=True), action='block'), dict(when=dict(families=['pdf']), action='allow'))
        unknown = rule_preview.preview(self.client, self.body(extension='pdf'))
        self.assertEqual(unknown.status, 'ambiguous')
        self.assertEqual([r.number for r in unknown.matches], [1, 2, 3])
        unrecognized = rule_preview.preview(self.client, self.body(extension='pdf', header_type='unrecognized'))
        self.assertEqual(unrecognized.status, 'matched')
        self.assertEqual(unrecognized.matches[0].number, 3)
        disguised = rule_preview.preview(self.client, self.body(extension='pdf', header_type='pe'))
        self.assertEqual(disguised.matches[0].number, 1)

    def test_extension_families_and_header_independent_matches(self):
        self.policy(dict(when=dict(families=['script']), action='block'))
        result = rule_preview.preview(self.client, self.body(extension='js'))
        self.assertEqual(result.status, 'matched')
        self.assertEqual(result.matches[0].number, 1)
        self.policy(dict(when=dict(larger_than_bytes=9), action='block'))
        self.assertEqual(rule_preview.preview(self.client, self.body()).status, 'matched')

    def test_stale_revision_and_foreign_profile_and_icap_default_are_refused(self):
        self.policy()
        for body, code in [(self.body().model_copy(update={'expected_revision': 1}), 409),
                           (self.body().model_copy(update={'profile_id': self.other_profile}), 404)]:
            with self.assertRaises(HTTPException) as caught:
                rule_preview.preview(self.client, body)
            self.assertEqual(caught.exception.status_code, code)
        with db.connect() as connection:
            connection.execute('UPDATE scan_profiles SET is_default = ? WHERE id = ?', (db.db_bool(False), self.profile))
        with self.assertRaises(HTTPException) as caught:
            rule_preview.preview(self.client, self.body().model_copy(update={'source': 'icap'}))
        self.assertEqual(caught.exception.status_code, 409)

    def test_invalid_or_incomplete_profile_is_never_simulated(self):
        for raw in ('{}', 'x' * 65537, json.dumps(dict(version=2, inconclusive='block', rules=[dict(action='scan', engines=[999999], archive='whole')]))):
            with db.connect() as connection:
                connection.execute('UPDATE scan_profiles SET policy_json = ? WHERE id = ?', (raw, self.profile))
            with self.assertRaises(HTTPException) as caught:
                rule_preview.preview(self.client, self.body())
            self.assertEqual(caught.exception.status_code, 409)

    def test_http_and_file_bounds_never_promise_admission(self):
        self.policy()
        with patch.dict(os.environ, {'MASP_HTTP_UPLOAD_MAX_BYTES': '100', 'MASP_UPLOAD_MAX_BYTES': '10'}):
            at_limit = rule_preview.preview(self.client, self.body())
            self.assertEqual([limit.state for limit in at_limit.limits], ['within_limit', 'unknown'])
            above = rule_preview.preview(self.client, self.body(size_bytes=100))
            self.assertEqual([limit.state for limit in above.limits], ['exceeds_limit', 'exceeds_limit'])
        with patch.dict(os.environ, {'MASP_HTTP_UPLOAD_MAX_BYTES': 'bad'}):
            invalid = rule_preview.preview(self.client, self.body())
            self.assertEqual(invalid.limits[-1].state, 'blocked')

    def test_gateway_staleness_and_fail_open_are_explicit(self):
        self.policy()
        body = self.body().model_copy(update={'source': 'icap'})
        self.assertEqual(rule_preview.preview(self.client, body).limits[0].state, 'unknown')
        for age, expected in [(0, 'exceeds_limit'), (600, 'unknown')]:
            db.set_setting(client_configuration.SETTING_PREFIX + 'preview', json.dumps(dict(client_key='configuration-test', port=1344,
                at=int(time.time()) - age, max_bytes=5, fail_closed=False)))
            result = rule_preview.preview(self.client, body)
            self.assertEqual(result.limits[0].state, expected)
            self.assertIn('allow without scanning', result.limits[0].explanation)

    def test_read_only_preview_fingerprints_current_config_and_warns_on_disabled_engine(self):
        self.policy()
        with db.connect() as connection:
            before = {table: connection.execute(f'SELECT COUNT(*) AS n FROM {table}').fetchone()['n'] for table in ('scan_jobs', 'scan_engine_jobs', 'audit_events', 'notification_outbox')}
        first = rule_preview.preview(self.client, self.body())
        self.assertEqual(first.configuration_fingerprint, rule_preview.preview(self.client, self.body()).configuration_fingerprint)
        with db.connect() as connection:
            connection.execute('UPDATE engine_instances SET enabled = ? WHERE id = ?', (db.db_bool(False), self.engine))
        second = rule_preview.preview(self.client, self.body())
        self.assertNotEqual(first.configuration_fingerprint, second.configuration_fingerprint)
        self.assertTrue(any('disabled' in warning for warning in second.warnings))
        self.assertNotIn('synthetic-hash', second.model_dump_json())
        with db.connect() as connection:
            after = {table: connection.execute(f'SELECT COUNT(*) AS n FROM {table}').fetchone()['n'] for table in before}
        self.assertEqual(before, after)

    def test_strict_metadata_bounds(self):
        valid = self.body().model_dump()
        for changes in ({'size_bytes': True}, {'size_bytes': -1}, {'size_bytes': 9007199254740992}, {'header_type': 'made-up'},
                        {'header_type': 'x' * 33}, {'extension': '../path'}, {'source': 'manual'}, {'sample': 'no files'}):
            with self.assertRaises(ValidationError):
                rule_preview.RulePreviewBody.model_validate({**valid, **changes})
