import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import database
from app.main import (
    redirect_url,
    render_engine_placement_rows,
    render_system_page,
    render_worker_pool_rows,
)
from app.models import StoredSample, UserRecord
from app.services.worker_scheduling import (
    eligible_engine_instance_ids_for_node,
    parse_worker_pool_selector,
)


class WorkerPoolSchedulingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "worker-pools.db"
        database.DATABASE_URL = ""
        database.init_db()
        self.primary_engine_id = database.create_engine_instance(
            "clamav", "ClamAV Primary"
        )
        self.unbound_engine_id = database.create_engine_instance(
            "clamav", "ClamAV Unbound"
        )
        database.upsert_worker_node_heartbeat(
            node_id="linux-ist-01",
            display_name="Linux Istanbul 01",
            hostname="linux-ist-01",
            platform="linux",
            agent_version="0.2.0",
            labels_json='{"site": "istanbul", "tier": "primary"}',
            capacity=1,
            advertised_engine_keys_json='["clamav"]',
            runtime_state="idle",
            active_scan_id=None,
            process_id=101,
            last_heartbeat_at=1000,
        )

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_selector_binding_routes_only_matching_instances(self) -> None:
        selector = parse_worker_pool_selector("site=istanbul,tier=primary")
        pool_id = database.create_worker_pool(
            "Istanbul Primary", json.dumps(selector, sort_keys=True)
        )
        database.set_engine_instance_worker_pool(self.primary_engine_id, pool_id)

        eligible = eligible_engine_instance_ids_for_node(
            "linux-ist-01", {"clamav"}
        )

        self.assertEqual(
            eligible,
            {self.primary_engine_id, self.unbound_engine_id},
        )
        database.update_worker_pool(
            pool_id,
            name="Istanbul Primary",
            selector_json='{"site": "ankara"}',
            enabled=True,
        )
        self.assertEqual(
            eligible_engine_instance_ids_for_node("linux-ist-01", {"clamav"}),
            {self.unbound_engine_id},
        )

    def test_disabled_pool_is_fail_closed_but_unbound_instance_remains_compatible(self) -> None:
        pool_id = database.create_worker_pool(
            "Disabled Pool", '{"site": "istanbul"}'
        )
        database.set_engine_instance_worker_pool(self.primary_engine_id, pool_id)
        database.update_worker_pool(
            pool_id,
            name="Disabled Pool",
            selector_json='{"site": "istanbul"}',
            enabled=False,
        )

        self.assertEqual(
            eligible_engine_instance_ids_for_node("linux-ist-01", {"clamav"}),
            {self.unbound_engine_id},
        )
        with self.assertRaises(ValueError):
            database.delete_worker_pool(pool_id)

    def test_node_capacity_prevents_a_second_concurrent_claim(self) -> None:
        first_scan = self.create_scan()
        second_scan = self.create_scan()
        engine = database.get_engine_instance_by_id(self.primary_engine_id)
        assert engine is not None
        database.create_scan_engine_jobs(first_scan, [engine])
        database.create_scan_engine_jobs(second_scan, [engine])

        first = database.claim_next_scan_engine_job(
            {"clamav"},
            "linux-ist-01:101",
            worker_node_id="linux-ist-01",
            eligible_engine_instance_ids={self.primary_engine_id},
            now=1000,
        )
        second = database.claim_next_scan_engine_job(
            {"clamav"},
            "linux-ist-01:202",
            worker_node_id="linux-ist-01",
            eligible_engine_instance_ids={self.primary_engine_id},
            now=1000,
        )

        self.assertIsNotNone(first)
        self.assertIsNone(second)
        assert first is not None
        self.assertTrue(
            database.mark_scan_engine_job_terminal_if_owned(
                first.id,
                "linux-ist-01:101",
                first.attempt_count,
                "completed",
            )
        )
        self.assertIsNotNone(
            database.claim_next_scan_engine_job(
                {"clamav"},
                "linux-ist-01:202",
                worker_node_id="linux-ist-01",
                eligible_engine_instance_ids={self.primary_engine_id},
                now=1001,
            )
        )

    def test_admin_rows_expose_pool_controls_and_engine_assignment(self) -> None:
        pool_id = database.create_worker_pool(
            "Istanbul Primary", '{"site": "istanbul"}'
        )
        database.set_engine_instance_worker_pool(self.primary_engine_id, pool_id)
        pools = database.list_worker_pools()
        bindings = database.list_engine_instance_worker_pool_bindings()
        engines = database.list_engine_instances()

        pool_html = render_worker_pool_rows(pools, bindings, engines)
        placement_html = render_engine_placement_rows(engines, pools, bindings)

        self.assertIn("site=istanbul", pool_html)
        self.assertIn(f'action="/worker-pools/{pool_id}/update"', pool_html)
        self.assertIn("ClamAV Primary", pool_html)
        self.assertIn('action="/engines/pool"', placement_html)
        self.assertIn(f'value="{pool_id}" selected', placement_html)

    def test_system_create_pool_form_preserves_rejected_input(self) -> None:
        admin = UserRecord(
            id=1,
            username="admin",
            password_hash="hash",
            role="admin",
            created_at="now",
            updated_at="now",
        )

        html = render_system_page(
            admin,
            error="Worker pool selectors use comma-separated key=value pairs.",
            pool_name="Windows <Pool>",
            pool_selector="os:windows",
        )

        self.assertIn('value="Windows &lt;Pool&gt;"', html)
        self.assertIn('value="os:windows"', html)
        self.assertIn("Selector format", html)
        self.assertIn("key=value", html)

    def test_redirect_url_can_carry_rejected_form_values(self) -> None:
        url = redirect_url(
            "/system",
            error="invalid selector",
            params={
                "pool_name": "Windows Pool",
                "pool_selector": "os:windows",
            },
        )

        self.assertIn("pool_name=Windows+Pool", url)
        self.assertIn("pool_selector=os%3Awindows", url)
        self.assertIn("error=invalid+selector", url)

    def test_disabled_node_cannot_claim_and_matching_failover_node_can(self) -> None:
        database.upsert_worker_node_heartbeat(
            node_id="linux-ist-02",
            display_name="Linux Istanbul 02",
            hostname="linux-ist-02",
            platform="linux",
            agent_version="0.2.0",
            labels_json='{"site": "istanbul", "tier": "primary"}',
            capacity=1,
            advertised_engine_keys_json='["clamav"]',
            runtime_state="idle",
            active_scan_id=None,
            process_id=202,
            last_heartbeat_at=1000,
        )
        pool_id = database.create_worker_pool(
            "Istanbul Primary", '{"site": "istanbul", "tier": "primary"}'
        )
        database.set_engine_instance_worker_pool(self.primary_engine_id, pool_id)
        scan_id = self.create_scan()
        engine = database.get_engine_instance_by_id(self.primary_engine_id)
        assert engine is not None
        database.create_scan_engine_jobs(scan_id, [engine])
        database.update_worker_node_lifecycle("linux-ist-01", "disabled")

        self.assertIsNone(
            database.claim_next_scan_engine_job(
                {"clamav"},
                "linux-ist-01:101",
                worker_node_id="linux-ist-01",
                eligible_engine_instance_ids={self.primary_engine_id},
            )
        )
        claimed = database.claim_next_scan_engine_job(
            {"clamav"},
            "linux-ist-02:202",
            worker_node_id="linux-ist-02",
            eligible_engine_instance_ids={self.primary_engine_id},
        )
        self.assertIsNotNone(claimed)
        assert claimed is not None
        self.assertEqual(claimed.engine_instance_id, self.primary_engine_id)

    def test_legacy_database_is_upgraded_with_pool_schema(self) -> None:
        legacy_path = Path(self.temp_dir.name) / "legacy-pools.db"
        with sqlite3.connect(legacy_path) as connection:
            connection.execute(
                "CREATE TABLE app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO app_settings (key, value) VALUES ('legacy', 'kept')"
            )
        database.DB_PATH = legacy_path

        database.init_db()

        with database.connect() as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            job_columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(scan_engine_jobs)"
                ).fetchall()
            }
        self.assertIn("worker_pools", tables)
        self.assertIn("engine_instance_worker_pools", tables)
        self.assertIn("engine_node_health", tables)
        self.assertIn("worker_node_id", job_columns)
        self.assertEqual(database.get_setting("legacy"), "kept")

    def create_scan(self) -> int:
        sample_id = database.create_sample(
            StoredSample(
                original_filename="sample.bin",
                stored_filename="sample.bin",
                storage_path="storage/samples/sample.bin",
                content_type="application/octet-stream",
                size_bytes=1,
                md5="md5",
                sha1="sha1",
                sha256="sha256",
            )
        )
        return database.create_scan_job(
            sample_id,
            case_name="Pool test",
            priority="Normal",
            note="",
        )


if __name__ == "__main__":
    unittest.main()
