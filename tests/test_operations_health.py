"""Operations visibility: health checks, delivery status and intake actions."""
import asyncio
from collections import namedtuple
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app import database as db
from app.engines.clamav import parse_clamav_version
from app.icap import activity, server
from app.icap.config import IcapConfig
from app.services import delivery_read, health_read, intake_admin, intake_read


NOW = 1_790_000_000
Usage = namedtuple('Usage', 'total used free')


def engine(name, state, adapter='clamav'):
    return health_read.EngineState(name=name, adapter_key=adapter, state=state, detail=f'{name} detail')


class HealthRuleTests(unittest.TestCase):
    """Thresholds and wording, without a database."""

    def test_workers_distinguish_missing_offline_and_draining(self):
        self.assertEqual(health_read.workers_check({'nodes': [], 'online_count': 0}).state, 'critical')
        offline = {'nodes': [{'node_id': 'n1', 'lifecycle_state': 'active', 'online': False}],
                   'online_count': 0, 'schedulable_count': 0}
        self.assertIn('Every worker is offline', health_read.workers_check(offline).detail)
        draining = {'nodes': [{'node_id': 'n1', 'lifecycle_state': 'draining', 'online': True}],
                    'online_count': 1, 'schedulable_count': 0}
        self.assertIn('draining or disabled', health_read.workers_check(draining).detail)
        partial = {'nodes': [{'node_id': 'n1', 'display_name': 'Linux', 'lifecycle_state': 'active', 'online': True},
                             {'node_id': 'n2', 'display_name': 'Windows', 'lifecycle_state': 'active', 'online': False},
                             {'node_id': 'n3', 'display_name': 'Retired', 'lifecycle_state': 'disabled', 'online': False}],
                   'online_count': 1, 'schedulable_count': 1}
        check = health_read.workers_check(partial)
        # A disabled worker being offline is expected; an active one is not.
        self.assertEqual((check.state, check.detail.split('.')[0]), ('warning', 'Offline: Windows'))

    def test_queue_age_thresholds_follow_the_documented_alert(self):
        self.assertEqual(health_read.queue_check(0, None, None).state, 'ok')
        self.assertEqual(health_read.queue_check(3, 30, None).state, 'ok')
        self.assertEqual(health_read.queue_check(3, 120, 'why').state, 'warning')
        critical = health_read.queue_check(3, 301, 'No worker is online.')
        self.assertEqual((critical.state, critical.detail), ('critical', 'No worker is online.'))
        self.assertIn('the oldest for 5 min', critical.summary)

    def test_waiting_reason_checks_workers_then_placement_then_capacity(self):
        none_online = {'schedulable_count': 0, 'workers': []}
        self.assertIn('No worker is online', health_read.waiting_reason(none_online, [], 2))
        online = {'schedulable_count': 1, 'workers': [{'online': True, 'state': 'running'}]}
        unplaced = health_read.waiting_reason(online, [engine('Defender', 'unavailable')], 2)
        self.assertIn('No active worker can run Defender', unplaced)
        self.assertIn('All 1 accepting worker(s) are busy', health_read.waiting_reason(online, [engine('ClamAV', 'healthy')], 2))
        idle = {'schedulable_count': 1, 'workers': [{'online': True, 'state': 'idle'}]}
        self.assertIn('check the worker log', health_read.waiting_reason(idle, [], 2))
        self.assertIsNone(health_read.waiting_reason(none_online, [], 0))

    def test_engines_report_failures_before_unconfirmed_checks(self):
        self.assertEqual(health_read.engines_check([engine('ClamAV', 'disabled')]).state, 'critical')
        failing = health_read.engines_check([engine('ClamAV', 'failed'), engine('YARA', 'pending', 'yara')])
        self.assertEqual(failing.state, 'critical')
        self.assertEqual(failing.detail, 'ClamAV: ClamAV detail')
        self.assertEqual(health_read.engines_check([engine('YARA', 'pending', 'yara')]).state, 'warning')
        self.assertEqual(health_read.engines_check([engine('ClamAV', 'healthy')]).state, 'ok')

    def test_signature_age_judges_every_clamav_report_and_shows_the_oldest(self):
        day = 86400

        def stamp(age):
            return time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(NOW - age))

        def record(adapter, date, version='27771', node='linux-1', instance=1, checked=NOW):
            probe = {'signature_date': date, 'signature_version': version} if date else {}
            return SimpleNamespace(details_json=json.dumps({'adapter_key': adapter, 'probe': probe}),
                                   node_id=node, engine_instance_id=instance, last_checked_at=checked)
        clamav = [engine('ClamAV', 'healthy')]
        self.assertEqual(health_read.signatures_check([], [], NOW).state, 'inactive')
        self.assertEqual(health_read.signatures_check(clamav, [record('clamav', None)], NOW).state, 'unknown')
        fresh = health_read.signatures_check(clamav, [
            record('clamav', stamp(day), '27771'),
            record('yara', stamp(0), '9', instance=2)], NOW)
        self.assertEqual((fresh.state, fresh.summary), ('ok', 'Database 27771, published 24 h ago.'))
        self.assertEqual(health_read.signatures_check(clamav, [record('clamav', stamp(8 * day))], NOW).state, 'critical')
        # A current database on one node never hides an old one on another.
        mixed = health_read.signatures_check(clamav, [
            record('clamav', stamp(30 * day), '27000', node='linux-2'),
            record('clamav', stamp(day), '27771', node='linux-1')], NOW, enabled_ids={1})
        self.assertEqual(mixed.state, 'critical')
        self.assertEqual(mixed.summary, '1 of 2 reports out of date; the oldest is database 27000 on linux-2, published 30 d ago.')
        both = health_read.signatures_check(clamav, [
            record('clamav', stamp(day), node='linux-2'), record('clamav', stamp(2 * 3600), node='linux-1')], NOW)
        self.assertEqual((both.state, both.summary), ('ok', '2 reports current; the oldest is database 27771, published 24 h ago.'))
        # A disabled instance or a node that stopped checking a week ago is not judged here.
        retired = [record('clamav', stamp(30 * day), node='old', checked=NOW - 8 * day),
                   record('clamav', stamp(30 * day), instance=9), record('clamav', stamp(day))]
        self.assertEqual(health_read.signatures_check(clamav, retired, NOW, enabled_ids={1}).state, 'ok')

    def test_storage_thresholds(self):
        gib = 1024 ** 3
        with patch('app.services.health_read.shutil.disk_usage', return_value=Usage(100 * gib, 50 * gib, 50 * gib)):
            self.assertEqual(health_read.storage_check().state, 'ok')
        with patch('app.services.health_read.shutil.disk_usage', return_value=Usage(100 * gib, 85 * gib, 15 * gib)):
            self.assertEqual(health_read.storage_check().state, 'warning')
        with patch('app.services.health_read.shutil.disk_usage', return_value=Usage(100 * gib, 95 * gib, 5 * gib)):
            check = health_read.storage_check()
        self.assertEqual((check.state, check.summary), ('critical', '95% used; 5.0 GiB free.'))
        with patch('app.services.health_read.shutil.disk_usage', side_effect=OSError('gone')):
            self.assertEqual(health_read.storage_check().state, 'unknown')

    def test_icap_gateway_states(self):
        def gateway(age, events=()):
            return {'at': NOW - age, 'client_key': 'storage', 'port': 1344, 'counters': {'requests': 4},
                    'events': list(events)}
        self.assertEqual(health_read.icap_check([], NOW).state, 'inactive')
        self.assertEqual(health_read.icap_check([gateway(10)], NOW).state, 'ok')
        self.assertEqual(health_read.icap_check([gateway(200)], NOW).state, 'critical')
        # A listener silent for a week was removed, not stopped.
        self.assertEqual(health_read.icap_check([gateway(8 * 86400)], NOW).state, 'inactive')
        refused = gateway(5, [{'at': NOW - 60, 'kind': 'rejected', 'detail': 'Connection refused', 'peer': '10.0.0.9'},
                              {'at': NOW - 7200, 'kind': 'error', 'detail': 'old'}])
        check = health_read.icap_check([refused], NOW)
        self.assertEqual((check.state, check.summary), ('warning', '1 refused connection(s) in the last hour.'))
        self.assertIn('10.0.0.9', check.detail)

    def test_an_unresolved_client_binding_fails_every_icap_request(self):
        def gateway(binding, fail_closed=True):
            return {'at': NOW - 5, 'client_key': 'typo', 'port': 1344, 'fail_closed': fail_closed, 'counters': {},
                    'events': [], 'binding': binding, 'binding_detail': 'No service client has the key typo.'}
        check = health_read.icap_check([gateway('unresolved')], NOW)
        self.assertEqual(check.state, 'critical')
        self.assertIn('No service client has the key typo.', check.summary)
        self.assertIn('blocks every upload', check.detail)
        open_check = health_read.icap_check([gateway('unresolved', fail_closed=False)], NOW)
        self.assertEqual(open_check.state, 'warning')
        self.assertIn('unscanned', open_check.detail)
        # The compatibility client is a working, if unintended, binding: not an outage.
        self.assertEqual(health_read.icap_check([gateway('legacy_default')], NOW).state, 'ok')

    def test_a_gateway_rebound_to_another_client_is_not_a_stopped_gateway(self):
        def record(key, at, started_at, port=1344):
            return {f'{activity.SETTING_PREFIX}{key}:{port}': json.dumps({
                'at': NOW - at, 'started_at': NOW - started_at, 'client_key': key, 'port': port,
                'fail_closed': True, 'counters': {}, 'events': []})}
        # Seen in an upgrade rehearsal: the legacy-default record stops when the
        # gateway restarts under its own client, and was reported as critical.
        rebound = {**record('legacy-default', 600, 3600), **record('fil', 5, 590)}
        self.assertEqual([g['client_key'] for g in health_read.icap_gateways(rebound, NOW)], ['fil'])
        self.assertEqual(health_read.icap_check(health_read.icap_gateways(rebound, NOW), NOW).state, 'ok')
        # Nothing started after it on that port: the gateway really stopped.
        alone = health_read.icap_gateways(record('legacy-default', 600, 3600), NOW)
        self.assertEqual(health_read.icap_check(alone, NOW).state, 'critical')
        # A gateway on the same port number elsewhere that was already running does not hide it,
        others = {**record('legacy-default', 600, 3600), **record('other', 5, 7200)}
        self.assertEqual(health_read.icap_check(health_read.icap_gateways(others, NOW), NOW).state, 'critical')
        # nor does one on another port, and a live record is never replaced.
        elsewhere = {**record('legacy-default', 600, 3600), **record('fil', 5, 590, port=1345)}
        self.assertEqual(len(health_read.icap_gateways(elsewhere, NOW)), 2)
        both_live = {**record('a', 5, 3600), **record('b', 5, 10)}
        self.assertEqual(len(health_read.icap_gateways(both_live, NOW)), 2)


class DatabaseCase(unittest.TestCase):
    postgres = False

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.original = (db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED)
        db.close_pool()
        url = os.environ['MASP_TEST_POSTGRES_URL'] if self.postgres else ''
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = Path(self.temp.name) / 'ops.db', url, False
        self.addCleanup(self._restore)
        if self.postgres:
            import psycopg
            with psycopg.connect(url, autocommit=True) as connection:
                connection.execute('DROP SCHEMA IF EXISTS public CASCADE')
                connection.execute('CREATE SCHEMA public')
        db.init_db()
        self.client_id = db.create_service_client('drive', 'Drive')
        metadata = db.create_engine_instance('static_metadata', 'Metadata')
        self.profile_id = db.create_scan_profile(self.client_id, 'Default', engine_instance_ids=[metadata], is_default=True)

    def _restore(self):
        db.close_pool()
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = self.original

    def submission(self, request_id, status):
        record, _ = db.create_deferred_scan_submission(
            service_client_id=self.client_id, scan_profile_id=self.profile_id, client_request_id=request_id,
            backend_key='drive', object_id=f'uploads/{request_id}.pdf', original_filename=f'{request_id}.pdf',
            content_type='application/pdf', expected_size_bytes=None, expected_sha256=None,
            archive_mode='lazy_extract_on_detection', case_name='Upload', priority='Normal', note='',
            profile_snapshot_json='{}')
        with db.connect() as connection:
            connection.execute('''UPDATE deferred_scan_submissions SET status = ?, attempt_count = 2,
                last_error = 'Source SHA-256 does not match', available_at = ? WHERE id = ?''',
                               (status, NOW + 3600, record.id))
        return record.id

    def outbox(self, key, status, attempts, available_at=0, error=None):
        from app.models import StoredSample
        sample = db.create_sample(StoredSample(f'{key}.bin', key, str(Path(self.temp.name) / key), 'text/plain', 1,
                                               key.ljust(64, '0')[:64], 'b' * 40, 'c' * 32))
        scan_id = db.create_scan_job(sample, 'Case', 'Normal', '', source='api', service_client_id=self.client_id)
        with db.connect() as connection:
            connection.execute('''INSERT INTO notification_outbox (scan_job_id, service_client_id, event_type,
                idempotency_key, payload_json, status, attempt_count, available_at, last_error)
                VALUES (?, ?, 'malware.detected', ?, '{}', ?, ?, ?, ?)''',
                               (scan_id, self.client_id, key, status, attempts, available_at, error))


class IntakeActionTests(DatabaseCase):
    def test_retry_returns_a_failed_copy_to_the_queue_now(self):
        failed = self.submission('failed-1', 'failed')
        intake_admin.retry_failed_submission(failed, now=NOW)
        with db.connect() as connection:
            row = connection.execute('SELECT status, available_at, attempt_count FROM deferred_scan_submissions WHERE id = ?',
                                     (failed,)).fetchone()
        # Attempt count is the worker's fencing generation; it must not reset.
        self.assertEqual((row['status'], int(row['available_at']), int(row['attempt_count'])), ('pending', NOW, 2))
        self.assertEqual(intake_read.overview().failures, [])

    def test_retry_refuses_anything_but_a_failed_submission(self):
        pending = self.submission('pending-1', 'pending')
        with self.assertRaises(HTTPException) as caught:
            intake_admin.retry_failed_submission(pending, now=NOW)
        self.assertEqual(caught.exception.status_code, 409)
        with self.assertRaises(HTTPException):
            intake_admin.retry_failed_submission(999999, now=NOW)

    def test_dismissing_a_rejection_removes_only_that_record(self):
        with db.connect() as connection:
            for name in ('a.json', 'b.json'):
                connection.execute('''INSERT INTO manifest_rejections (backend_key, manifest_object_id, reason,
                    first_seen_at, last_seen_at, occurrences) VALUES ('drive', ?, 'bad', 1, 1, 1)''', (name,))
        intake_admin.dismiss_rejection(intake_admin.RejectionDismissal(backend_key='drive', manifest_object_id='a.json'))
        self.assertEqual([r.manifest_object_id for r in intake_read.overview().rejections], ['b.json'])
        with self.assertRaises(HTTPException):
            intake_admin.dismiss_rejection(intake_admin.RejectionDismissal(backend_key='drive', manifest_object_id='a.json'))


class DeliveryTests(DatabaseCase):
    def test_notification_summary_and_retry_now(self):
        self.outbox('delivered', 'delivered', 1)
        self.outbox('waiting', 'pending', 0)
        self.outbox('failing', 'pending', 3, available_at=NOW + 600, error="Webhook refused '/etc/masp/secret'")
        view = delivery_read.overview(now=NOW)
        self.assertEqual((view.notifications.pending, view.notifications.delivered, view.notifications.retrying), (2, 1, 1))
        failure = view.notifications.failures[0]
        self.assertEqual((failure.attempt_count, failure.client_name), (3, 'Drive'))
        self.assertIn('<path>', failure.last_error)
        self.assertEqual(delivery_read.retry_notifications_now(now=NOW).rescheduled, 1)
        with self.assertRaises(HTTPException):
            delivery_read.retry_notifications_now(now=NOW)

    def test_notifications_nobody_tried_to_send_are_not_an_outage(self):
        # Detections queue notifications even where SIEM delivery is not deployed.
        self.outbox('never-sent', 'pending', 0)
        with db.connect() as connection:
            connection.execute("UPDATE notification_outbox SET created_at = '2020-01-01 00:00:00'")
            check = health_read.notifications_check(connection, NOW)
        self.assertEqual(check.state, 'inactive')
        self.assertIn('no delivery has been attempted', check.summary)
        self.outbox('failed-once', 'pending', 1, error='refused')
        with db.connect() as connection:
            self.assertEqual(health_read.notifications_check(connection, NOW).state, 'critical')

    def test_gateway_records_are_listed_and_marked_stale(self):
        db.set_setting(activity.SETTING_PREFIX + 'storage:1344', json.dumps({
            'at': NOW - 200, 'client_key': 'storage', 'service_name': 'masp', 'port': 1344, 'fail_closed': True,
            'block_on_review': True, 'allowlist_entries': 2, 'started_at': NOW - 999,
            'counters': {'requests': 3}, 'last_request_at': NOW - 300,
            'events': [{'at': NOW - 250, 'kind': 'rejected', 'detail': 'refused', 'peer': '10.0.0.9', 'scan_id': None}]}))
        db.set_setting(activity.SETTING_PREFIX + 'broken:1', 'not json')
        gateway, = delivery_read.overview(now=NOW).gateways
        self.assertEqual((gateway.client_key, gateway.stale, gateway.events[0].peer), ('storage', True, '10.0.0.9'))

    def test_gateway_binding_resolves_the_client_key_as_the_gateway_does(self):
        from app.services.service_clients import identity_for_service_client_key
        disabled = db.create_service_client('disabled', 'Disabled')
        db.create_service_client('no-profile', 'No Profile')
        with db.connect() as connection:
            connection.execute('UPDATE service_clients SET enabled = ? WHERE id = ?', (db.db_bool(False), disabled))
        for key in ('drive', 'legacy-default', 'disabled', 'no-profile', 'missing'):
            db.set_setting(f'{activity.SETTING_PREFIX}{key}:1344', json.dumps({
                'at': NOW - 5, 'client_key': key, 'service_name': 'masp', 'port': 1344, 'fail_closed': True,
                'block_on_review': False, 'allowlist_entries': 0, 'started_at': NOW - 99, 'counters': {},
                'last_request_at': None, 'events': []}))
        gateways = {g.client_key: g for g in delivery_read.overview(now=NOW).gateways}
        self.assertEqual({key: g.binding for key, g in gateways.items()}, {
            'drive': 'client', 'legacy-default': 'legacy_default', 'disabled': 'unresolved',
            'no-profile': 'unresolved', 'missing': 'unresolved'})
        self.assertEqual((gateways['drive'].client_id, gateways['drive'].client_name), (self.client_id, 'Drive'))
        self.assertIn('disabled', gateways['disabled'].binding_detail)
        self.assertIn('no enabled scan profile', gateways['no-profile'].binding_detail)
        self.assertEqual(gateways['missing'].binding_detail, 'No service client has the key missing.')
        # The console must agree with what the gateway itself would do with each key.
        for key, gateway in gateways.items():
            if gateway.binding == 'unresolved':
                with self.assertRaises(ValueError):
                    identity_for_service_client_key(key)
            else:
                identity_for_service_client_key(key)
        with patch('app.services.health_read.shutil.disk_usage', return_value=Usage(100, 10, 90)):
            report = health_read.report([engine('Metadata', 'healthy', 'static_metadata')], now=NOW)
        icap = next(check for check in report.checks if check.key == 'icap')
        self.assertEqual(icap.state, 'critical')

    def test_health_report_combines_every_part(self):
        self.outbox('failing', 'pending', 2, error='refused')
        with patch('app.services.health_read.shutil.disk_usage', return_value=Usage(100, 10, 90)):
            report = health_read.report([engine('Metadata', 'healthy', 'static_metadata')])
        states = {check.key: check.state for check in report.checks}
        self.assertEqual(states['workers'], 'critical')           # no worker registered
        self.assertEqual(states['signatures'], 'inactive')        # no ClamAV engine
        self.assertEqual(states['manifest'], 'inactive')
        self.assertEqual(states['icap'], 'inactive')
        self.assertEqual(states['notifications'], 'warning')
        self.assertEqual(report.overall, 'critical')


class ReadModelTests(DatabaseCase):
    """The new list, readiness and bundle queries, run on both database backends."""

    def test_search_readiness_ledger_choices_and_bundle(self):
        from app.services import client_admin, client_readiness, ledger_read, support_bundle, worker_admin
        db.create_service_client('mail_gw', 'Mail 100% gateway')
        self.assertEqual([c.client_key for c in client_admin.page(20, None, 'DRIVE').items], ['drive'])
        self.assertEqual([c.client_key for c in client_admin.page(20, None, '100%').items], ['mail_gw'])
        db.upsert_worker_node_heartbeat(node_id='linux-01', display_name='Linux scanner', hostname='scan-a', platform='linux',
            agent_version='1', labels_json='{}', capacity=1, advertised_engine_keys_json='[]', runtime_state='idle',
            active_scan_id=None, process_id=0, last_heartbeat_at=NOW)
        self.assertEqual([w.node_id for w in worker_admin.page(limit=20, after=None, query='SCAN-A').items], ['linux-01'])
        db.create_worker_pool('Windows pool', '{}')
        self.assertEqual([p.name for p in worker_admin.pool_page(limit=20, after=None, query='windows').items], ['Windows pool'])
        self.assertEqual([c.display_name for c in ledger_read.clients().items], ['Drive', 'Mail 100% gateway'])
        db.set_setting(activity.SETTING_PREFIX + 'drive:1344', json.dumps({'at': int(time.time()), 'client_key': 'drive',
            'port': 1344, 'counters': {}, 'events': []}))
        view = client_readiness.readiness(self.client_id, 'https://masp.example')
        self.assertEqual({m.key: m.ready for m in view.methods}, {'api': False, 'icap': True, 'manifest': False})
        self.assertTrue(view.ready)
        # A client whose gateway reports under another key is told which one.
        db.set_setting(activity.SETTING_PREFIX + 'drive:1344', json.dumps({'at': int(time.time()),
            'client_key': 'legacy-default', 'port': 1344, 'counters': {}, 'events': []}))
        icap = next(m for m in client_readiness.readiness(self.client_id, 'https://masp.example').methods if m.key == 'icap')
        self.assertFalse(icap.ready)
        self.assertIn('MASP_ICAP_SERVICE_CLIENT_KEY=drive', icap.checks[0].detail)
        self.assertIn('port 1344 files scans under legacy-default', icap.checks[0].detail)
        db.set_setting(activity.SETTING_PREFIX + 'drive:1344', json.dumps({'at': int(time.time()), 'client_key': 'drive',
            'port': 1344, 'counters': {}, 'events': []}))
        with patch('app.services.health_read.shutil.disk_usage', return_value=Usage(100, 10, 90)):
            report = health_read.report([engine('Metadata', 'healthy', 'static_metadata')])
            bundle = json.loads(support_bundle.build(report, []).content)
        self.assertEqual(bundle['workers'][0]['node_id'], 'linux-01')
        self.assertEqual(bundle['recent_engine_failures'], [])


class PostgresDatabaseTests(IntakeActionTests, DeliveryTests, ReadModelTests):
    postgres = True

    def setUp(self):
        if not os.environ.get('MASP_TEST_POSTGRES_URL'):
            self.skipTest('MASP_TEST_POSTGRES_URL is not set')
        super().setUp()


class IcapActivityTests(unittest.TestCase):
    def setUp(self):
        self.config = IcapConfig(service_client_key='storage', port=1344, allowed_ips=frozenset({'10.0.0.1'}))
        activity.ACTIVITY = activity.IcapActivity(self.config, now=NOW)
        self.addCleanup(setattr, activity, 'ACTIVITY', None)

    def test_snapshot_is_one_bounded_redacted_record(self):
        recorder = activity.ACTIVITY
        for index in range(activity.EVENT_LIMIT + 5):
            recorder.event('error', f"failed reading '/srv/masp/storage/{index}'", now=NOW + index)
        snapshot = json.loads(recorder.snapshot(now=NOW + 60))
        self.assertEqual(recorder.key, 'icap_gateway_status:storage:1344')
        self.assertEqual((snapshot['at'], snapshot['allowlist_entries'], snapshot['fail_closed']), (NOW + 60, 1, True))
        # The gateway's own decisions, so a profile summary can state them; 0 is "no size limit".
        self.assertEqual((snapshot['block_archives'], snapshot['max_bytes'], snapshot['wait_seconds']), (True, 0, 30))
        self.assertEqual(len(snapshot['events']), activity.EVENT_LIMIT)
        self.assertEqual(snapshot['events'][0]['at'], NOW + activity.EVENT_LIMIT + 4)   # newest first
        self.assertNotIn('/srv/masp', json.dumps(snapshot))

    def test_a_refused_source_is_recorded_with_its_address(self):
        class Writer:
            def get_extra_info(self, name):
                return ('10.9.9.9', 5000)

            def close(self):
                pass
        asyncio.run(server.handle_connection(None, Writer(), self.config))
        snapshot = json.loads(activity.ACTIVITY.snapshot())
        self.assertEqual(snapshot['counters']['connections_rejected'], 1)
        self.assertEqual(snapshot['events'][0]['kind'], 'rejected')
        # The observed address, flagged when it may be a NAT or bridge gateway.
        self.assertTrue(snapshot['events'][0]['peer'].startswith('10.9.9.9 (private address'))

    def test_handlers_do_not_need_a_recorder(self):
        activity.ACTIVITY = None
        activity.count('requests')
        activity.event('error', 'ignored')


class ClamavVersionTests(unittest.TestCase):
    def test_clamd_version_reply_is_parsed(self):
        self.assertEqual(parse_clamav_version('ClamAV 1.5.2/28134/Fri Sep 25 06:25:58 2026'), {
            'product_version': 'ClamAV 1.5.2', 'engine_version': '1.5.2', 'signature_version': '28134',
            'signature_date': '2026-09-25T06:25:58+00:00'})
        # Without a signature database clamd reports only the program version.
        self.assertEqual(parse_clamav_version('ClamAV 1.5.2'), {'product_version': 'ClamAV 1.5.2', 'engine_version': '1.5.2'})
        self.assertEqual(parse_clamav_version('ClamAV 1.0.7/27500/Thu Jan  2 09:00:00 2025')['signature_date'],
                         '2025-01-02T09:00:00+00:00')
        self.assertEqual(parse_clamav_version('UNKNOWN COMMAND'), {})


if __name__ == '__main__':
    unittest.main()
