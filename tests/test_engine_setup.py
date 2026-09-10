import tempfile
import unittest
from pathlib import Path

from app import database
from app.main import engine_setup_from_form, page_shell, render_add_engine_panel
from app.models import UserRecord


class EngineInitialSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db_path = database.DB_PATH
        self.original_database_url = database.DATABASE_URL
        database.DB_PATH = Path(self.temp_dir.name) / "engine-setup.db"
        database.DATABASE_URL = ""
        database.init_db()

    def tearDown(self) -> None:
        database.DB_PATH = self.original_db_path
        database.DATABASE_URL = self.original_database_url
        self.temp_dir.cleanup()

    def test_catalog_does_not_preselect_an_adapter_or_runtime_values(self) -> None:
        markup = render_add_engine_panel()

        self.assertNotRegex(markup, r"data-engine-adapter-choice[^>]*\schecked")
        self.assertIn('data-modal-open="add-engine-modal"', markup)
        self.assertIn(
            '<dialog id="add-engine-modal" class="modal-dialog add-engine-modal" data-modal ',
            markup,
        )
        self.assertNotIn("data-modal data-auto-open", markup)
        self.assertIn("data-engine-adapter-list", markup)
        self.assertIn("data-engine-selected-adapter hidden", markup)
        self.assertEqual(markup.count("data-engine-config-section"), 2)
        self.assertIn('name="engine_display_name" maxlength="128" required', markup)
        self.assertIn('<option value="">Select mode</option>', markup)
        self.assertIn('placeholder="3310"', markup)
        self.assertNotIn('name="clamav_port" value="3310"', markup)

    def test_selected_adapter_reopens_modal_without_persisting_defaults(self) -> None:
        markup = render_add_engine_panel(selected_adapter="clamav")

        self.assertIn("data-modal data-auto-open", markup)
        self.assertRegex(
            markup,
            r'name="adapter_key" value="clamav"[^>]*\schecked',
        )
        self.assertIn("data-engine-change-adapter", markup)
        self.assertIn('data-engine-setup="clamav"', markup)
        self.assertNotIn('name="clamav_port" value="3310"', markup)

    def test_page_shell_contains_engine_modal_state_contract(self) -> None:
        admin = UserRecord(
            id=1,
            username="admin",
            password_hash="hash",
            role="admin",
            created_at="now",
            updated_at="now",
        )

        markup = page_shell("Engines", "engines", render_add_engine_panel(), admin)

        self.assertIn("let engineAdapterListExpanded = false;", markup)
        self.assertIn(
            "engineAdapterList.hidden = Boolean(selected && !engineAdapterListExpanded);",
            markup,
        )
        self.assertIn("engineDisplayName.disabled = !showEngineConfig;", markup)
        self.assertIn('dialog[data-modal][data-auto-open]', markup)
        self.assertIn("modal.showModal();", markup)

    def test_clamav_setup_requires_explicit_runtime_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "timeout seconds is required"):
            engine_setup_from_form(
                "clamav",
                {
                    "engine_display_name": "ClamAV Istanbul",
                    "clamav_mode": "clamd",
                    "clamav_host": "clamav.internal",
                    "clamav_port": "3310",
                },
            )

    def test_clamav_setup_returns_only_submitted_configuration(self) -> None:
        display_name, config = engine_setup_from_form(
            "clamav",
            {
                "engine_display_name": "ClamAV Istanbul",
                "clamav_mode": "clamd",
                "clamav_host": "clamav.internal",
                "clamav_port": "3311",
                "clamav_timeout_seconds": "75",
                "clamav_max_file_size_bytes": "104857600",
            },
        )

        self.assertEqual(display_name, "ClamAV Istanbul")
        self.assertEqual(
            config,
            {
                "mode": "clamd",
                "host": "clamav.internal",
                "port": "3311",
                "timeout_seconds": "75",
                "max_file_size_bytes": "104857600",
            },
        )

    def test_navigation_groups_related_admin_pages(self) -> None:
        admin = UserRecord(
            id=1,
            username="admin",
            password_hash="hash",
            role="admin",
            created_at="now",
            updated_at="now",
        )

        markup = page_shell("Engines", "engines", "", admin)

        self.assertIn('class="nav-section-label">Scanning</span>', markup)
        self.assertIn('class="nav-section-label">Configuration</span>', markup)
        self.assertIn('class="nav-section-label">Access &amp; audit</span>', markup)
        self.assertLess(markup.index('href="/engines"'), markup.index('href="/scan-policy"'))
        self.assertLess(markup.index('href="/scan-policy"'), markup.index('href="/system"'))
        self.assertLess(markup.index('href="/users"'), markup.index('href="/audit"'))


if __name__ == "__main__":
    unittest.main()
