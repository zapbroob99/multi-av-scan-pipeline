import json
from pathlib import Path
import tempfile
import time
import unittest

from app import database as db
from app.services import profile_admin
from app.services.profile_outcome import describe
from app.services.profile_policy import ProfilePolicy
from app.services.service_clients import hash_api_token

MIB = 1024 * 1024
CLAMAV = {'id': 1, 'display_name': 'ClamAV', 'adapter_key': 'clamav', 'enabled': True}


def gateway(**values):
    record = {'port': 1344, 'fail_closed': True, 'block_on_review': False, 'block_archives': True,
              'max_bytes': 0, 'wait_seconds': 30}
    record.update(values)
    return record


def lines(outcome):
    return {line.topic: line for line in outcome.lines}


class ProfileOutcomeTests(unittest.TestCase):
    """The summary states what intake, the decision and the gateway already do."""

    def test_inherited_archives_follow_the_gateway_setting(self):
        refused = lines(describe(ProfilePolicy(), [CLAMAV], is_default=True, gateways=[gateway()], upload_cap=0))
        self.assertIn('blocked as Not allowed (gateway setting)', refused['archives'].icap)
        self.assertEqual(refused['archives'].api, 'Scanned as one file; MASP does not look inside.')
        scanned = lines(describe(ProfilePolicy(), [CLAMAV], is_default=True, gateways=[gateway(block_archives=False)], upload_cap=0))
        self.assertEqual(scanned['archives'].icap, 'Scanned as one file; MASP does not look inside.')

    def test_profile_archive_handling_does_not_depend_on_the_gateway(self):
        outcome = lines(describe(ProfilePolicy(archive_handling='inspect'), [CLAMAV], is_default=True, gateways=[], upload_cap=0))
        self.assertTrue(outcome['archives'].icap_known)
        self.assertIn('opened by MASP', outcome['archives'].icap)
        members = lines(describe(ProfilePolicy(archive_handling='scan_members'), [CLAMAV], is_default=True,
                                 gateways=[gateway(wait_seconds=45)], upload_cap=0))
        self.assertIn('waits up to 45 s', members['archives'].icap)

    def test_a_missing_gateway_or_setting_is_unknown_never_assumed(self):
        outcome = describe(ProfilePolicy(), [CLAMAV], is_default=True, gateways=[], upload_cap=0)
        self.assertEqual(outcome.icap, 'no_gateway')
        for topic in ('archives', 'unassessed', 'unfinished', 'size'):
            self.assertFalse(lines(outcome)[topic].icap_known, topic)
            self.assertTrue(lines(outcome)[topic].icap.startswith('Unknown'), topic)
        # A gateway from an older release reports fail mode and review only.
        old = {'port': 1344, 'fail_closed': True, 'block_on_review': True}
        older = lines(describe(ProfilePolicy(), [CLAMAV], is_default=True, gateways=[old], upload_cap=0))
        self.assertFalse(older['archives'].icap_known)
        self.assertFalse(older['size'].icap_known)
        self.assertEqual(older['unassessed'].icap, 'Blocked (gateway setting).')

    def test_a_named_profile_is_never_described_as_serving_icap(self):
        outcome = describe(ProfilePolicy(), [CLAMAV], is_default=False, gateways=[gateway()], upload_cap=0)
        self.assertEqual(outcome.icap, 'not_default')
        self.assertTrue(all(line.icap.startswith('Not used') for line in outcome.lines))

    def test_size_limits_say_which_one_applies_first_and_what_fail_open_means(self):
        policy = ProfilePolicy(max_file_bytes=50 * MIB)
        outcome = lines(describe(policy, [CLAMAV], is_default=True,
                                 gateways=[gateway(max_bytes=100 * MIB, fail_closed=False)], upload_cap=200 * MIB))
        self.assertEqual(outcome['size'].api, 'Files over 50 MiB are refused without scanning (HTTP 413).')
        self.assertEqual(outcome['size'].icap, 'Files over 50 MiB: blocked as Not allowed. '
                         'Files over 100 MiB: allowed without scanning (gateway limit, fail-open).')
        # A gateway limit below the profile's makes the profile limit unreachable over ICAP.
        lower = lines(describe(policy, [CLAMAV], is_default=True, gateways=[gateway(max_bytes=10 * MIB)], upload_cap=0))
        self.assertEqual(lower['size'].icap, 'Files over 10 MiB: blocked (gateway limit).')
        server = lines(describe(ProfilePolicy(), [CLAMAV], is_default=True, gateways=[gateway()], upload_cap=20 * MIB))
        self.assertIn('20 MiB', server['size'].api)
        self.assertIn('server setting', server['size'].api)
        self.assertEqual(server['size'].icap, 'No size limit.')

    def test_content_rules_and_violation_action(self):
        rule = {'mode': 'denylist', 'families': ['executable', 'script']}
        scanned = lines(describe(ProfilePolicy(type_rule=rule), [CLAMAV], is_default=True, gateways=[], upload_cap=0))
        self.assertEqual(scanned['content'].api, 'Programs and scripts are not accepted. '
                         'A file that breaks a rule is still scanned, then blocked and listed as Not allowed.')
        self.assertTrue(scanned['content'].icap_known)
        refused = lines(describe(ProfilePolicy(type_rule=rule, violation_action='reject'), [CLAMAV], is_default=True,
                                 gateways=[], upload_cap=0))
        self.assertIn('HTTP 415', refused['content'].api)
        self.assertIn('no scan record', refused['content'].icap)

    def test_review_and_unfinished_follow_profile_then_gateway(self):
        blocked = lines(describe(ProfilePolicy(review_action='block'), [CLAMAV], is_default=True, gateways=[], upload_cap=0))
        self.assertEqual(blocked['unassessed'].icap, "Blocked (this profile's rule).")
        open_gateway = lines(describe(ProfilePolicy(), [CLAMAV], is_default=True,
                                      gateways=[gateway(fail_closed=False, wait_seconds=12)], upload_cap=0))
        self.assertIn('Allowed (gateway setting)', open_gateway['unassessed'].icap)
        self.assertEqual(open_gateway['unfinished'].icap,
                         'Not finished within 12 s, or MASP unavailable: allowed without a verdict (gateway fail mode).')

    def test_gateways_that_disagree_are_listed_per_port(self):
        outcome = lines(describe(ProfilePolicy(), [CLAMAV], is_default=True,
                                 gateways=[gateway(port=1344), gateway(port=1345, block_archives=False)], upload_cap=0))
        self.assertTrue(outcome['archives'].icap.startswith('Port 1344: Every zip'))
        self.assertIn('Port 1345: Scanned as one file', outcome['archives'].icap)

    def test_engines_left_out_carry_the_reason(self):
        engines = [CLAMAV, {'id': 2, 'display_name': 'VT', 'adapter_key': 'virustotal', 'enabled': True},
                   {'id': 3, 'display_name': 'Off', 'adapter_key': 'clamav', 'enabled': False}]
        outcome = describe(ProfilePolicy(), engines, is_default=True, gateways=[], upload_cap=0)
        self.assertEqual([(engine.display_name, engine.runs) for engine in outcome.engines],
                         [('ClamAV', True), ('VT', False), ('Off', False)])
        self.assertIn('Paid reputation service', outcome.engines[1].reason)
        self.assertEqual(outcome.engines[2].reason, 'Engine instance is disabled.')


class ProfilePageOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original = db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED
        db.close_pool()
        db.DB_PATH = Path(self.temp.name) / 'outcome.db'
        db.DATABASE_URL = ''
        db.DB_POOL_ENABLED = False
        db.init_db()
        self.clamav = db.create_engine_instance('clamav', 'ClamAV')
        self.client, self.default, _ = db.create_service_client_bundle(client_key='fil', display_name='Files',
            profile_name='Standard', engine_instance_ids=[self.clamav], credential_label='Test',
            token_hash=hash_api_token('synthetic-outcome-token-xxxxxxxxxxxxxxxxxx'), token_prefix='synthetic')

    def tearDown(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original
        self.temp.cleanup()

    def record(self, client_key, port, **values):
        db.set_setting(f'icap_gateway_status:{client_key}:{port}', json.dumps(
            gateway(port=port, client_key=client_key, at=int(time.time()), started_at=int(time.time()) - 60, **values)))

    def test_page_reads_only_this_clients_gateways_and_the_server_limit(self):
        self.record('FIL', 1344, block_archives=True)             # the key matches case-insensitively
        self.record('other', 1345, block_archives=False)
        db.set_setting('scan_policy.upload_max_bytes', str(20 * MIB))
        page = profile_admin.page(self.client, None)
        outcome = page.items[0].outcome
        self.assertEqual((outcome.icap, outcome.icap_ports), ('gateway', [1344]))
        self.assertIn('gateway setting', lines(outcome)['archives'].icap)
        self.assertIn('20 MiB', lines(outcome)['size'].api)

    def test_a_long_silent_gateway_is_forgotten_and_an_unreadable_policy_has_no_outcome(self):
        db.set_setting('icap_gateway_status:fil:1344', json.dumps(gateway(client_key='fil', at=1, started_at=0)))
        self.assertEqual(profile_admin.page(self.client, None).items[0].outcome.icap, 'no_gateway')
        with db.connect() as connection:
            connection.execute("UPDATE scan_profiles SET policy_json = '{not json' WHERE id = ?", (self.default,))
        item = profile_admin.page(self.client, None).items[0]
        self.assertTrue(item.policy_invalid)
        self.assertIsNone(item.outcome)


if __name__ == '__main__':
    unittest.main()
