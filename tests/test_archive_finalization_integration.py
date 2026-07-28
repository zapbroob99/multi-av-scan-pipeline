"""Mock-free integration tests for archive finalization (real DB + filesystem).

Exercises the real extraction -> staging -> atomic promote -> fenced child
intake path end to end, proving the crash-safety contracts that the mock-based
tests cannot: a child is never visible before its file is in place, the file
path is deterministic across retries, re-running is idempotent, and a stale
finalizer leaves no orphan sample.

SQLite runs by default; a PostgreSQL-gated subclass runs the same on real PG.
"""

import os
import tempfile
import time as _time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from app import database
from app.models import EngineResultRecord
from app.services import archive_extractor
from app.services.ingest import store_bytes
from app.services.scoring import RiskAssessment
from app.workers import scan_worker

TEST_POSTGRES_URL = os.getenv("MASP_TEST_POSTGRES_URL", "").strip()


def _detected_result(scan_id: int, engine_name: str) -> EngineResultRecord:
    return EngineResultRecord(
        id=1,
        scan_job_id=scan_id,
        engine_name=engine_name,
        engine_version=None,
        signature_version=None,
        status="completed",
        detected=True,
        signature="Test.Detection",
        severity="high",
        confidence=90,
        raw_output="",
        error_message=None,
        duration_ms=1,
        details_json="{}",
        findings_json="[]",
        created_at="",
    )


class _ArchiveFinalizationContract:
    def _build_zip(self) -> bytes:
        import io

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("dup.txt", b"first member")
            zf.writestr("dup.txt", b"second member with the same name")  # duplicate name
            zf.writestr("nested/other.bin", b"third")
        return buffer.getvalue()

    def _container(self):
        stored = store_bytes("bundle.zip", "application/zip", self._build_zip())
        sample_id = database.create_sample(stored)
        database.create_engine_instance("static_metadata", "Static Metadata")
        batch_id = database.create_scan_batch(
            source="api",
            original_filename="bundle.zip",
            archive_mode="lazy_extract_on_detection",
            total_items=1,
        )
        scan_id = database.create_scan_job(
            sample_id,
            case_name="C",
            priority="Normal",
            note="",
            source="api",
            batch_id=batch_id,
            relative_path="bundle.zip",
            scan_role="container",
            status="running",
        )
        return database.get_scan(scan_id), batch_id

    def _run_finalization(self, scan, generation):
        engines = database.list_engine_instances()
        return scan_worker.maybe_enqueue_lazy_archive_children(
            scan,
            RiskAssessment(score=90, verdict="high", reasons=[]),
            [_detected_result(scan.id, "Static Metadata")],
            engines,
            set(),
            finalize_generation=generation,
        )

    def test_children_have_existing_files_and_reruns_are_idempotent(self) -> None:
        scan, _batch = self._container()
        generation = database.claim_scan_finalization(
            scan.id, scan_worker.WORKER_ID, lease_seconds=120, now=1000
        )

        created = self._run_finalization(scan, generation)
        self.assertEqual(created, 3)  # duplicate names are distinct children

        children = _children(scan)
        self.assertEqual(len(children), 3)
        # Every child's sample file exists at exactly the path the DB references
        # (promotion happened before the child became visible).
        first_paths = sorted(child.storage_path for child in children)
        for child in children:
            self.assertTrue(Path(child.storage_path).is_file(), child.storage_path)

        # Re-running (as a crash retry would) creates nothing new, keeps the same
        # deterministic paths, and the files still exist.
        self.assertEqual(self._run_finalization(scan, generation), 0)
        children_again = _children(scan)
        self.assertEqual(len(children_again), 3)
        self.assertEqual(sorted(c.storage_path for c in children_again), first_paths)
        for child in children_again:
            self.assertTrue(Path(child.storage_path).is_file())

    def test_stale_finalizer_creates_no_children_or_orphan_samples(self) -> None:
        scan, _batch = self._container()
        generation = database.claim_scan_finalization(
            scan.id, scan_worker.WORKER_ID, lease_seconds=120, now=1000
        )
        samples_before = _sample_count()
        # A superseded generation: the fenced child intake must raise and write
        # no DB rows (no child, no orphan sample).
        with self.assertRaises(database.StaleFinalizerError):
            self._run_finalization(scan, generation + 1)
        self.assertEqual(_children(scan), [])
        self.assertEqual(_sample_count(), samples_before)

        # It DID promote the first member's file before the fence rejected it,
        # leaving a child-* file no scan references.
        orphans = list(self.samples.glob("child-*"))
        self.assertTrue(orphans, "stale finalizer should have left a promoted file")
        for orphan in orphans:
            old = _time.time() - 10_000
            os.utime(orphan, (old, old))

        # While the parent is STILL finalizing, cleanup must NOT touch the file:
        # the (real) finalizer could still commit a child for that exact path.
        # This is the race the old mtime-only cleanup was exposed to.
        self.assertEqual(scan_worker.cleanup_orphan_child_samples(max_age_seconds=3600), 0)
        self.assertEqual(list(self.samples.glob("child-*")), orphans)

        # Once the parent settles (its real finalizer completed), no new child
        # will ever reference the path, so cleanup removes the orphan.
        database.complete_finalizing_scan(
            scan.id, scan_worker.WORKER_ID, generation, "high", 90
        )
        removed = scan_worker.cleanup_orphan_child_samples(max_age_seconds=3600)
        self.assertGreaterEqual(removed, 1)
        self.assertEqual(list(self.samples.glob("child-*")), [])

    def test_cleanup_preserves_committed_child_of_settled_parent(self) -> None:
        # The committed-child-vs-cleanup race, made deterministic: a real child is
        # committed (file promoted, row present) and its parent completed. Even
        # with an aged mtime, cleanup must keep the file because a sample row
        # references it — the parent-lifecycle gate alone must never delete a
        # live child's file.
        scan, _batch = self._container()
        generation = database.claim_scan_finalization(
            scan.id, scan_worker.WORKER_ID, lease_seconds=120, now=1000
        )
        self.assertEqual(self._run_finalization(scan, generation), 3)
        database.complete_finalizing_scan(
            scan.id, scan_worker.WORKER_ID, generation, "high", 90
        )
        children = _children(scan)
        self.assertEqual(len(children), 3)
        for child in children:
            old = _time.time() - 10_000
            os.utime(child.storage_path, (old, old))

        removed = scan_worker.cleanup_orphan_child_samples(max_age_seconds=3600)
        self.assertEqual(removed, 0)
        for child in children:
            self.assertTrue(Path(child.storage_path).is_file(), child.storage_path)

    def test_cleanup_does_not_race_a_retry_refinalization(self) -> None:
        # The retry race, made deterministic: cleanup takes its bulk snapshot
        # (parent completed, orphan path unreferenced) and — before it deletes —
        # the scan is retried, re-finalized, and children are committed at the
        # SAME deterministic paths. The locked per-file confirm must observe the
        # new state and keep every file; trusting the stale snapshot would
        # delete a file the DB now references.
        scan, _batch = self._container()
        generation = database.claim_scan_finalization(
            scan.id, scan_worker.WORKER_ID, lease_seconds=120, now=1000
        )
        # A fenced-out stale finalizer leaves an orphan file, then the real
        # finalizer completes the container WITHOUT children.
        with self.assertRaises(database.StaleFinalizerError):
            self._run_finalization(scan, generation + 1)
        database.complete_finalizing_scan(
            scan.id, scan_worker.WORKER_ID, generation, "clean", 0
        )
        orphans = list(self.samples.glob("child-*"))
        self.assertTrue(orphans, "stale finalizer should have left a promoted file")
        for orphan in orphans:
            old = _time.time() - 10_000
            os.utime(orphan, (old, old))

        real_filter = scan_worker.filter_referenced_storage_paths

        def filter_then_retry(paths):
            stale = real_filter(paths)  # cleanup's snapshot, taken pre-retry
            # Interleave the full user flow between the snapshot and the delete:
            # retry -> new finalization claim -> re-promote + commit children.
            self.assertTrue(database.retry_scan_job(scan.id))
            new_generation = database.claim_scan_finalization(
                scan.id, scan_worker.WORKER_ID, lease_seconds=120, now=2000
            )
            self.assertIsNotNone(new_generation)
            created = self._run_finalization(database.get_scan(scan.id), new_generation)
            self.assertEqual(created, 3)
            database.complete_finalizing_scan(
                scan.id, scan_worker.WORKER_ID, new_generation, "high", 90
            )
            return stale

        with patch.object(scan_worker, "filter_referenced_storage_paths", filter_then_retry):
            removed = scan_worker.cleanup_orphan_child_samples(max_age_seconds=3600)

        self.assertEqual(removed, 0, "cleanup must not delete a re-promoted child file")
        children = _children(database.get_scan(scan.id))
        self.assertEqual(len(children), 3)
        for child in children:
            self.assertTrue(Path(child.storage_path).is_file(), child.storage_path)

    def test_bulk_lookup_helpers_chunk_large_parameter_lists(self) -> None:
        scan, _batch = self._container()
        # Force multiple chunks with a tiny chunk size; results must merge into
        # the same answer a single query would give.
        probe_ids = [scan.id, 999_991, 999_992, 999_993, 999_994]
        sample_paths = [database.get_scan(scan.id).storage_path]
        probe_paths = sample_paths + [f"/nope/{i}" for i in range(4)]
        with patch.object(database, "SQL_IN_CHUNK_SIZE", 2):
            statuses = database.get_scan_statuses(probe_ids)
            referenced = database.filter_referenced_storage_paths(probe_paths)
        self.assertEqual(statuses, {scan.id: scan.status})
        self.assertEqual(referenced, set(sample_paths))



def _children(scan):
    return [
        child
        for child in database.list_scan_batch_scans(scan.batch_id, limit=100)
        if child.scan_role == "child"
    ]


def _sample_count() -> int:
    with database.connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()
    return int(row["n"] if isinstance(row, dict) else row[0])



class SqliteArchiveFinalizationTests(_ArchiveFinalizationContract, unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.temp_dir.name)
        self.samples = root / "samples"
        self.samples.mkdir()
        self.staging = root / "staging"
        self._patches = [
            patch.object(archive_extractor, "SAMPLES_DIR", self.samples),
            patch.object(archive_extractor, "STAGING_DIR", self.staging),
            patch.object(scan_worker, "SAMPLES_DIR", self.samples),
            patch("app.services.ingest.SAMPLES_DIR", self.samples),
        ]
        for p in self._patches:
            p.start()
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = root / "test.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        for p in self._patches:
            p.stop()
        self.temp_dir.cleanup()


@unittest.skipUnless(TEST_POSTGRES_URL, "set MASP_TEST_POSTGRES_URL to a throwaway PostgreSQL")
class PostgresArchiveFinalizationTests(_ArchiveFinalizationContract, unittest.TestCase):
    def setUp(self) -> None:
        import psycopg

        with psycopg.connect(TEST_POSTGRES_URL, autocommit=True) as connection:
            connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
            connection.execute("CREATE SCHEMA public")
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.temp_dir.name)
        self.samples = root / "samples"
        self.samples.mkdir()
        self.staging = root / "staging"
        self._patches = [
            patch.object(archive_extractor, "SAMPLES_DIR", self.samples),
            patch.object(archive_extractor, "STAGING_DIR", self.staging),
            patch.object(scan_worker, "SAMPLES_DIR", self.samples),
            patch("app.services.ingest.SAMPLES_DIR", self.samples),
        ]
        for p in self._patches:
            p.start()
        self.original_database_url = database.DATABASE_URL
        self.original_pool_enabled = database.DB_POOL_ENABLED
        database.close_pool()
        database.DATABASE_URL = TEST_POSTGRES_URL
        database.DB_POOL_ENABLED = False
        database.init_db()

    def tearDown(self) -> None:
        database.close_pool()
        database.DATABASE_URL = self.original_database_url
        database.DB_POOL_ENABLED = self.original_pool_enabled
        for p in self._patches:
            p.stop()
        self.temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
