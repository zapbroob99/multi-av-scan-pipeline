import datetime
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database as db
from app.services import manifest_intake
from app.services.deferred_storage import DeferredSourcePermanentError


class ManifestIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.share = self.root / 'share'
        self.today = datetime.date(2026, 9, 23)
        self.partition = self.share / 'uploads' / self.today.strftime('%Y/%m/%d')
        self.partition.mkdir(parents=True)

        self.original = (db.DB_PATH, db.DATABASE_URL)
        db.DB_PATH, db.DATABASE_URL = self.root / 'manifest.db', ''
        self.addCleanup(self._restore)
        db.init_db()
        self.client_id = db.create_service_client('drive-storage', 'Drive storage')
        engine = db.create_engine_instance('static_metadata', 'Metadata')
        db.create_scan_profile(self.client_id, 'Full scan', engine_instance_ids=[engine], is_default=True)

        self.env = patch.dict(os.environ, {
            'MASP_DEFERRED_STORAGE_BACKENDS_JSON': json.dumps({'drive': str(self.share)}),
            'MASP_DEFERRED_BACKEND_CLIENTS_JSON': json.dumps({'drive': ['drive-storage']}),
            'MASP_MANIFEST_BACKEND_KEY': 'drive',
            'MASP_MANIFEST_CLIENT_KEY': 'drive-storage',
            'MASP_MANIFEST_ROOT_PREFIX': 'uploads',
        }, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)

    def _restore(self) -> None:
        db.DB_PATH, db.DATABASE_URL = self.original

    def drop(self, upload_id: str, *, body: bytes = b'%PDF-1.7 body',
             extension: str = '.pdf', manifest: dict | None = None,
             write_object: bool = True, directory: Path | None = None) -> None:
        target = directory or self.partition
        if write_object:
            (target / f'{upload_id}{extension}').write_bytes(body)
        payload = {'upload_id': upload_id, 'original_filename': 'contract.pdf',
                   'user_id': '12345', 'tenant_id': 'tenant-x', 'size_bytes': len(body)}
        payload.update(manifest or {})
        (target / f'{upload_id}.json').write_text(json.dumps(payload), encoding='utf-8')

    def cycle(self):
        return manifest_intake.process_cycle(self.today)

    def submissions(self) -> list[dict]:
        with db.connect() as connection:
            return [dict(row) for row in connection.execute(
                'SELECT * FROM deferred_scan_submissions ORDER BY id').fetchall()]

    def test_manifest_creates_one_submission_and_rereading_is_free(self) -> None:
        self.drop('UP-1')
        self.drop('UP-2')
        self.assertEqual(self.cycle(), (2, 0, 0))
        # The share is read-only, so the same manifests are seen again forever.
        # The unique client request id, not a deletion, keeps this idempotent.
        self.assertEqual(self.cycle(), (0, 2, 0))
        rows = self.submissions()
        self.assertEqual([row['client_request_id'] for row in rows], ['UP-1', 'UP-2'])
        self.assertTrue(rows[0]['object_id'].endswith('UP-1.pdf'))
        self.assertEqual(rows[0]['backend_key'], 'drive')

    def test_manifest_metadata_reaches_the_submission(self) -> None:
        self.drop('UP-1', manifest={'sha256': 'a' * 64, 'content_type': 'application/pdf',
                                    'user_display': 'Test User', 'uploaded_at': '2026-09-23T10:15:00Z'})
        self.cycle()
        row = self.submissions()[0]
        self.assertEqual(row['expected_sha256'], 'a' * 64)
        self.assertEqual(row['content_type'], 'application/pdf')
        self.assertEqual(row['expected_size_bytes'], len(b'%PDF-1.7 body'))
        for expected in ('upload_id=UP-1', 'user_id=12345', 'tenant_id=tenant-x'):
            self.assertIn(expected, row['note'])

    def test_object_id_cannot_leave_the_manifest_directory(self) -> None:
        # Defence in depth behind the prefix grant.
        self.drop('UP-1', write_object=False, manifest={'object_id': 'uploads/elsewhere/secret.pdf'})
        self.assertEqual(self.cycle(), (0, 0, 1))
        rejection = db.list_manifest_rejections()[0]
        self.assertIn('same directory', rejection['reason'])
        self.assertEqual(self.submissions(), [])

    def test_traversal_and_absolute_paths_are_refused(self) -> None:
        for object_id in ('../../../etc/passwd', '/etc/passwd', 'a/../../b.pdf'):
            with self.subTest(object_id=object_id):
                with db.connect() as connection:
                    connection.execute('DELETE FROM manifest_rejections')
                for existing in self.partition.glob('*'):
                    existing.unlink()
                self.drop('UP-1', write_object=False, manifest={'object_id': object_id})
                self.assertEqual(self.cycle(), (0, 0, 1))
                self.assertEqual(self.submissions(), [])

    def test_manifest_outside_the_client_storage_grant_is_refused(self) -> None:
        self.drop('UP-1')
        with patch.dict(os.environ, {'MASP_DEFERRED_BACKEND_CLIENTS_JSON':
                                     json.dumps({'drive': {'drive-storage': ['uploads/other']}})}):
            self.assertEqual(self.cycle(), (0, 0, 1))
        self.assertIn('approved storage scope', db.list_manifest_rejections()[0]['reason'])
        self.assertEqual(self.submissions(), [])

    def test_malformed_manifests_are_rejected_without_stopping_the_batch(self) -> None:
        self.drop('GOOD-1')
        (self.partition / 'broken.json').write_text('{ not json', encoding='utf-8')
        (self.partition / 'wrongtype.json').write_text('[1, 2, 3]', encoding='utf-8')
        (self.partition / 'missingfields.json').write_text(json.dumps({'upload_id': 'x'}), encoding='utf-8')
        accepted, _duplicates, rejected = self.cycle()
        self.assertEqual(accepted, 1)
        self.assertEqual(rejected, 3)
        self.assertEqual([row['client_request_id'] for row in self.submissions()], ['GOOD-1'])

    def test_manifest_without_a_matching_object_is_rejected(self) -> None:
        self.drop('UP-1', write_object=False)
        self.assertEqual(self.cycle(), (0, 0, 1))
        self.assertIn('exactly one matching object', db.list_manifest_rejections()[0]['reason'])

    def test_ambiguous_siblings_require_an_explicit_object_id(self) -> None:
        self.drop('UP-1')
        (self.partition / 'UP-1.docx').write_bytes(b'PK\x03\x04')
        self.assertEqual(self.cycle(), (0, 0, 1))
        # Naming one of them explicitly resolves the ambiguity.
        self.drop('UP-1', manifest={'object_id': f'uploads/{self.today.strftime("%Y/%m/%d")}/UP-1.docx'})
        self.assertEqual(self.cycle(), (1, 0, 0))
        self.assertTrue(self.submissions()[0]['object_id'].endswith('UP-1.docx'))

    def test_rejections_are_counted_and_cleared_once_the_manifest_is_fixed(self) -> None:
        self.drop('UP-1', write_object=False)
        self.cycle()
        self.cycle()
        self.assertEqual(db.list_manifest_rejections()[0]['occurrences'], 2)
        (self.partition / 'UP-1.pdf').write_bytes(b'%PDF-1.7 body')
        self.assertEqual(self.cycle(), (1, 0, 0))
        self.assertEqual(db.list_manifest_rejections(), [])

    def test_only_recent_partitions_are_scanned(self) -> None:
        old = self.share / 'uploads' / (self.today - datetime.timedelta(days=30)).strftime('%Y/%m/%d')
        old.mkdir(parents=True)
        self.drop('OLD-1', directory=old)
        self.drop('NEW-1')
        self.assertEqual(self.cycle(), (1, 0, 0))
        self.assertEqual([row['client_request_id'] for row in self.submissions()], ['NEW-1'])
        # Widening the lookback picks the older partition up without any rewrite.
        with patch.dict(os.environ, {'MASP_MANIFEST_LOOKBACK_DAYS': '40'}):
            self.assertEqual(self.cycle(), (1, 1, 0))
        self.assertEqual({row['client_request_id'] for row in self.submissions()}, {'NEW-1', 'OLD-1'})

    def test_batch_limit_bounds_one_cycle(self) -> None:
        for index in range(5):
            self.drop(f'UP-{index}')
        with patch.dict(os.environ, {'MASP_MANIFEST_BATCH': '2'}):
            self.assertEqual(self.cycle(), (2, 0, 0))
        self.assertEqual(len(self.submissions()), 2)

    def test_intake_never_writes_to_the_source_share(self) -> None:
        self.drop('UP-1')
        before = {path.name: path.read_bytes() for path in self.partition.iterdir()}
        self.cycle()
        after = {path.name: path.read_bytes() for path in self.partition.iterdir()}
        self.assertEqual(before, after)

    def test_disabled_client_or_missing_profile_defers_rather_than_accepting(self) -> None:
        self.drop('UP-1')
        with db.connect() as connection:
            connection.execute('UPDATE scan_profiles SET enabled = ? WHERE service_client_id = ?',
                               (db.db_bool(False), self.client_id))
        self.assertEqual(self.cycle(), (0, 0, 1))
        self.assertEqual(self.submissions(), [])


class ManifestConfigurationTests(unittest.TestCase):
    def test_missing_configuration_is_an_operator_error(self) -> None:
        with patch.dict(os.environ, {'MASP_MANIFEST_BACKEND_KEY': '', 'MASP_MANIFEST_CLIENT_KEY': ''}):
            with self.assertRaises(manifest_intake.ManifestConfigError):
                manifest_intake.require_configuration()

    def test_unknown_backend_is_refused(self) -> None:
        # The root must be absolute on this platform for the backend to parse,
        # so the only thing under test is the unknown key.
        configured = str(Path(tempfile.gettempdir()).resolve() / 'share')
        with patch.dict(os.environ, {
            'MASP_DEFERRED_STORAGE_BACKENDS_JSON': json.dumps({'drive': configured}),
            'MASP_MANIFEST_BACKEND_KEY': 'absent', 'MASP_MANIFEST_CLIENT_KEY': 'drive-storage',
        }):
            with self.assertRaises(manifest_intake.ManifestConfigError):
                manifest_intake.require_configuration()

    def test_lookback_and_batch_are_clamped(self) -> None:
        with patch.dict(os.environ, {'MASP_MANIFEST_LOOKBACK_DAYS': '0', 'MASP_MANIFEST_BATCH': '99999'}):
            self.assertEqual(manifest_intake.lookback_days(), 1)
            self.assertEqual(manifest_intake.batch_limit(), manifest_intake.MAX_BATCH)
        with patch.dict(os.environ, {'MASP_MANIFEST_LOOKBACK_DAYS': 'abc'}):
            self.assertEqual(manifest_intake.lookback_days(), manifest_intake.DEFAULT_LOOKBACK_DAYS)

    def test_empty_date_layout_scans_the_prefix_itself(self) -> None:
        with patch.dict(os.environ, {'MASP_MANIFEST_ROOT_PREFIX': 'uploads',
                                     'MASP_MANIFEST_DATE_LAYOUT': ''}):
            self.assertEqual(manifest_intake.candidate_directories(datetime.date(2026, 9, 23)), ['uploads'])

    def test_dated_layout_lists_newest_partition_first(self) -> None:
        with patch.dict(os.environ, {'MASP_MANIFEST_ROOT_PREFIX': 'uploads',
                                     'MASP_MANIFEST_LOOKBACK_DAYS': '3'}):
            self.assertEqual(manifest_intake.candidate_directories(datetime.date(2026, 9, 23)),
                             ['uploads/2026/09/23', 'uploads/2026/09/22', 'uploads/2026/09/21'])


class ManifestRejectionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.original = (db.DB_PATH, db.DATABASE_URL)
        db.DB_PATH, db.DATABASE_URL = Path(self.temp.name) / 'rejections.db', ''
        self.addCleanup(self._restore)
        db.init_db()

    def _restore(self) -> None:
        db.DB_PATH, db.DATABASE_URL = self.original

    def test_store_is_capped_so_a_broken_producer_cannot_grow_it(self) -> None:
        with patch.object(db, 'MAX_MANIFEST_REJECTIONS', 5):
            for index in range(20):
                db.record_manifest_rejection('drive', f'uploads/{index:03}.json', 'invalid')
            self.assertLessEqual(len(db.list_manifest_rejections(limit=200)), 5)

    def test_reason_updates_and_clearing_removes_the_row(self) -> None:
        db.record_manifest_rejection('drive', 'uploads/a.json', 'first reason')
        db.record_manifest_rejection('drive', 'uploads/a.json', 'second reason')
        row = db.list_manifest_rejections()[0]
        self.assertEqual(row['reason'], 'second reason')
        self.assertEqual(row['occurrences'], 2)
        self.assertLessEqual(row['first_seen_at'], row['last_seen_at'])
        db.clear_manifest_rejection('drive', 'uploads/a.json')
        self.assertEqual(db.list_manifest_rejections(), [])


if __name__ == '__main__':
    unittest.main()
