import html
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.database import (
    create_sample,
    create_scan_job,
    create_user,
    delete_scan,
    delete_user,
    get_scan,
    get_scan_counts,
    get_user_by_username,
    init_db,
    list_engine_results,
    list_recent_scans,
    list_users,
    update_scan_assessment,
    update_user,
)
from app.models import EngineInstanceRecord, EngineResultRecord, ScanRecord, UserRecord
from app.services.cleanup import delete_sample_file
from app.services.auth import (
    ROLE_ADMIN,
    SESSION_COOKIE,
    current_user,
    hash_password,
    login,
    logout,
    require_admin,
    require_user,
    seed_default_users,
)
from app.services.engine_registry import (
    ADAPTERS,
    ROADMAP_ADAPTERS,
    adapter_definition,
    add_engine,
    available_adapter_definitions,
    clamav_form_values,
    configured_engines,
    detection_engine_names,
    enabled_engines,
    engine_health,
    runtime_config,
    seed_default_engines,
    toggle_engine,
    update_engine_config,
    yara_form_values,
    remove_engine,
)
from app.services.ingest import store_upload
from app.services.scoring import calculate_risk
from app.services.yara_rules import (
    delete_yara_rule,
    list_yara_rules,
    save_yara_rule,
    toggle_yara_rule,
)


app = FastAPI(
    title="MASP",
    description=(
        "Multi AV Scan Pipeline: self-hosted orchestration layer for file scanning engines, "
        "normalization, risk scoring, and analyst reports."
    ),
    version="0.1.0",
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
CSS_PATH = STATIC_DIR / "css" / "app.css"

init_db()
seed_default_users()
seed_default_engines()

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def page_shell(
    title: str,
    active: str,
    body: str,
    user: UserRecord,
    refresh_seconds: int | None = None,
) -> str:
    css_version = int(CSS_PATH.stat().st_mtime) if CSS_PATH.exists() else 1
    refresh_html = (
        f'<meta http-equiv="refresh" content="{refresh_seconds}">'
        if refresh_seconds is not None
        else ""
    )
    nav_items = [
        ("dashboard", "/", "Dashboard"),
        ("new_scan", "/scans/new", "New Scan"),
    ]
    if user.role == ROLE_ADMIN:
        nav_items.append(("engines", "/engines", "Engines"))
        nav_items.append(("users", "/users", "Users"))
    nav_html = "\n".join(
        f'<a class="nav-link {"is-active" if key == active else ""}" href="{href}">'
        f'<span class="nav-mark"></span>{label}</a>'
        for key, href, label in nav_items
    )
    username = html.escape(getattr(user, "username", ""))
    role = html.escape(str(getattr(user, "role", "")).title())

    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        {refresh_html}
        <title>{title} | MASP</title>
        <link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
        <script>
          (() => {{
            try {{
              const savedTheme = localStorage.getItem("masp-theme");
              const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
              const theme = savedTheme || (prefersDark ? "dark" : "light");
              document.documentElement.setAttribute("data-theme", theme);
            }} catch (error) {{
              document.documentElement.setAttribute("data-theme", "light");
            }}
          }})();
        </script>
        <link rel="stylesheet" href="/static/css/app.css?v={css_version}">
      </head>
      <body>
        <div class="app-shell">
          <aside class="sidebar">
            <a class="brand" href="/">
              <span class="brand-mark" aria-hidden="true">
                <span class="brand-glyph"></span>
              </span>
              <span>
                <strong>MASP</strong>
                <small>Multi AV Scan Pipeline</small>
              </span>
            </a>
            <nav class="nav-list" aria-label="Main navigation">
              {nav_html}
            </nav>
            <div class="side-status">
              <span class="status-dot"></span>
              <span>Local node online</span>
            </div>
          </aside>
          <div class="workspace">
            <header class="topbar">
              <div>
                <p class="eyebrow">Multi AV orchestration</p>
                <h1>{title}</h1>
              </div>
              <div class="topbar-actions">
                <div class="user-menu">
                  <span class="user-avatar" aria-hidden="true">{username[:1].upper()}</span>
                  <span>
                    <strong>{username}</strong>
                    <small>{role}</small>
                  </span>
                  <form action="/logout" method="post">
                    <button class="secondary-action compact-action" type="submit">Logout</button>
                  </form>
                </div>
                <button class="theme-toggle" type="button" data-theme-toggle aria-label="Toggle dark theme" title="Toggle dark theme">
                  <span class="theme-toggle-icon" aria-hidden="true"></span>
                  <span data-theme-label>Dark</span>
                </button>
              </div>
            </header>
            <main class="content">
              {body}
            </main>
          </div>
        </div>
        <script>
          const uploadForm = document.querySelector("[data-upload-form]");
          const fileInput = document.querySelector("[data-file-input]");
          const selectedFile = document.querySelector("[data-selected-file]");
          const submitButton = document.querySelector("[data-submit-button]");
          const bulkDeleteForm = document.querySelector("[data-bulk-delete-form]");
          const bulkDeleteButton = document.querySelector("[data-bulk-delete]");
          const scanRows = document.querySelectorAll("[data-scan-row]");
          const rowCheckboxes = document.querySelectorAll("[data-row-checkbox]");
          const selectAllCheckbox = document.querySelector("[data-select-all]");
          const copyTargets = document.querySelectorAll("[data-copy-value]");
          const themeToggle = document.querySelector("[data-theme-toggle]");
          const themeLabel = document.querySelector("[data-theme-label]");
          const selectedScanIds = new Set();
          const clickTimers = new Map();

          const applyTheme = (theme) => {{
            document.documentElement.setAttribute("data-theme", theme);
            try {{
              localStorage.setItem("masp-theme", theme);
            }} catch (error) {{
              console.warn("Theme preference could not be saved", error);
            }}
            if (themeLabel) {{
              themeLabel.textContent = theme === "dark" ? "Light" : "Dark";
            }}
          }};

          applyTheme(document.documentElement.getAttribute("data-theme") || "light");

          if (themeToggle) {{
            themeToggle.addEventListener("click", () => {{
              const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
              applyTheme(currentTheme === "dark" ? "light" : "dark");
            }});
          }}

          const updateBulkDeleteVisibility = () => {{
            if (!bulkDeleteButton) {{
              return;
            }}

            bulkDeleteButton.hidden = selectedScanIds.size === 0;
          }};

          const syncSelectionControls = () => {{
            rowCheckboxes.forEach((checkbox) => {{
              const row = checkbox.closest("[data-scan-row]");
              const scanId = row && row.getAttribute("data-scan-id");
              checkbox.checked = Boolean(scanId && selectedScanIds.has(scanId));
            }});

            if (selectAllCheckbox) {{
              const totalRows = scanRows.length;
              selectAllCheckbox.checked = totalRows > 0 && selectedScanIds.size === totalRows;
              selectAllCheckbox.indeterminate = selectedScanIds.size > 0 && selectedScanIds.size < totalRows;
            }}
          }};

          const syncBulkDeleteInputs = () => {{
            if (!bulkDeleteForm) {{
              return;
            }}

            bulkDeleteForm.querySelectorAll("input[name='scan_ids']").forEach((input) => input.remove());
            selectedScanIds.forEach((scanId) => {{
              const input = document.createElement("input");
              input.type = "hidden";
              input.name = "scan_ids";
              input.value = scanId;
              bulkDeleteForm.appendChild(input);
            }});
          }};

          const setRowSelection = (row, selected) => {{
            const scanId = row.getAttribute("data-scan-id");
            if (!scanId) {{
              return;
            }}

            if (selected) {{
              selectedScanIds.add(scanId);
            }} else {{
              selectedScanIds.delete(scanId);
            }}

            row.classList.toggle("is-selected", selected);
            row.setAttribute("aria-selected", selected ? "true" : "false");
            syncBulkDeleteInputs();
            syncSelectionControls();
            updateBulkDeleteVisibility();
          }};

          const toggleRowSelection = (row) => {{
            setRowSelection(row, !row.classList.contains("is-selected"));
          }};

          const setAllRowSelection = (selected) => {{
            scanRows.forEach((row) => setRowSelection(row, selected));
          }};

          const shouldIgnoreRowClick = (event) => {{
            return Boolean(event.target.closest("[data-copy-value], a, button, input, select, textarea, summary, details"));
          }};

          if (fileInput && selectedFile) {{
            fileInput.addEventListener("change", () => {{
              const file = fileInput.files && fileInput.files[0];
              selectedFile.textContent = file ? file.name : "No file selected";
              selectedFile.classList.toggle("has-file", Boolean(file));
            }});
          }}

          if (uploadForm && submitButton) {{
            uploadForm.addEventListener("submit", () => {{
              submitButton.textContent = "Uploading...";
              submitButton.disabled = true;
            }});
          }}

          if (scanRows.length) {{
            if (selectAllCheckbox) {{
              selectAllCheckbox.addEventListener("change", () => {{
                setAllRowSelection(selectAllCheckbox.checked);
              }});
            }}

            rowCheckboxes.forEach((checkbox) => {{
              checkbox.addEventListener("change", () => {{
                const row = checkbox.closest("[data-scan-row]");
                if (row) {{
                  setRowSelection(row, checkbox.checked);
                }}
              }});
            }});

            scanRows.forEach((row) => {{
              row.addEventListener("click", (event) => {{
                if (shouldIgnoreRowClick(event)) {{
                  return;
                }}

                if (selectedScanIds.size === 0) {{
                  return;
                }}

                const scanId = row.getAttribute("data-scan-id");
                window.clearTimeout(clickTimers.get(scanId));
                clickTimers.set(scanId, window.setTimeout(() => {{
                  toggleRowSelection(row);
                  clickTimers.delete(scanId);
                }}, 180));
              }});

              row.addEventListener("dblclick", (event) => {{
                if (shouldIgnoreRowClick(event)) {{
                  return;
                }}

                const scanId = row.getAttribute("data-scan-id");
                window.clearTimeout(clickTimers.get(scanId));
                const scanUrl = row.getAttribute("data-scan-url");
                if (scanUrl) {{
                  window.location.href = scanUrl;
                }}
              }});

              row.addEventListener("keydown", (event) => {{
                if (event.key === "Enter") {{
                  const scanUrl = row.getAttribute("data-scan-url");
                  if (scanUrl) {{
                    window.location.href = scanUrl;
                  }}
                }}

                if (event.key === " ") {{
                  event.preventDefault();
                  toggleRowSelection(row);
                }}
              }});
            }});
            syncSelectionControls();
            updateBulkDeleteVisibility();
          }}

          if (copyTargets.length) {{
            copyTargets.forEach((target) => {{
              target.addEventListener("click", async (event) => {{
                event.stopPropagation();
                const value = target.getAttribute("data-copy-value");
                if (!value) {{
                  return;
                }}

                try {{
                  await navigator.clipboard.writeText(value);
                  target.classList.add("is-copied");
                  const previousLabel = target.getAttribute("aria-label") || "Copy value";
                  target.setAttribute("aria-label", "Copied");
                  window.setTimeout(() => {{
                    target.classList.remove("is-copied");
                    target.setAttribute("aria-label", previousLabel);
                  }}, 1200);
                }} catch (error) {{
                  console.error("Clipboard copy failed", error);
                }}
              }});
            }});
          }}
        </script>
      </body>
    </html>
    """


def auth_shell(title: str, body: str) -> str:
    css_version = int(CSS_PATH.stat().st_mtime) if CSS_PATH.exists() else 1
    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{title} | MASP</title>
        <link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
        <script>
          (() => {{
            try {{
              const savedTheme = localStorage.getItem("masp-theme");
              const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
              const theme = savedTheme || (prefersDark ? "dark" : "light");
              document.documentElement.setAttribute("data-theme", theme);
            }} catch (error) {{
              document.documentElement.setAttribute("data-theme", "light");
            }}
          }})();
        </script>
        <link rel="stylesheet" href="/static/css/app.css?v={css_version}">
      </head>
      <body class="auth-body">
        {body}
      </body>
    </html>
    """


def render_login_page(next_url: str = "/", error: str = "") -> str:
    error_html = (
        f'<div class="auth-error">{html.escape(error)}</div>'
        if error
        else ""
    )
    body = f"""
    <main class="auth-layout">
      <section class="auth-card">
        <a class="brand auth-brand" href="/login">
          <span class="brand-mark" aria-hidden="true">
            <span class="brand-glyph"></span>
          </span>
          <span>
            <strong>MASP</strong>
            <small>Multi AV Scan Pipeline</small>
          </span>
        </a>
        <div class="auth-heading">
          <p class="eyebrow">Secure workspace</p>
          <h1>Sign in</h1>
          <span>Use an admin or analyst account to access local scan operations.</span>
        </div>
        {error_html}
        <form class="auth-form" action="/login" method="post">
          <input type="hidden" name="next_url" value="{html.escape(safe_next_url(next_url))}">
          <label>
            Username
            <input type="text" name="username" autocomplete="username" required autofocus>
          </label>
          <label>
            Password
            <input type="password" name="password" autocomplete="current-password" required>
          </label>
          <button class="primary-action" type="submit">Sign in</button>
        </form>
        <div class="auth-hint">
          <strong>Default dev users</strong>
          <span>admin / admin123! · analyst / analyst123!</span>
        </div>
      </section>
    </main>
    """
    return auth_shell("Sign in", body)


def safe_next_url(next_url: str) -> str:
    if not next_url.startswith("/"):
        return "/"
    if next_url.startswith("//"):
        return "/"
    return next_url


def normalize_role(role: str) -> str:
    normalized_role = role.strip().lower()
    if normalized_role not in {ROLE_ADMIN, "analyst"}:
        raise HTTPException(status_code=400, detail="Unsupported user role.")
    return normalized_role


def metric_card(label: str, value: str, meta: str, tone: str = "") -> str:
    return f"""
    <article class="metric-card {tone}">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{meta}</small>
    </article>
    """


def format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} {unit}"
        value /= 1024
    return f"{size} B"


def format_unix_timestamp(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def render_yara_rule_rows() -> str:
    rules = list_yara_rules()
    if not rules:
        return """
        <div class="rule-empty">
          <strong>No YARA rules yet</strong>
          <span>Upload a .yar or .yara file to enable local rule-based analysis.</span>
        </div>
        """

    rows = []
    for rule in rules:
        name = str(rule["name"])
        encoded_name = quote(name, safe="")
        enabled = bool(rule["enabled"])
        status_tone = "success" if enabled else "neutral"
        status_label = "Enabled" if enabled else "Disabled"
        toggle_label = "Disable" if enabled else "Enable"
        row_class = "" if enabled else "muted"
        rows.append(
            f"""
            <div class="rule-row {row_class}">
              <div>
                <strong>{html.escape(str(rule["base_name"]))}</strong>
                <small>{html.escape(name)}</small>
              </div>
              <span class="pill {status_tone}">{status_label}</span>
              <span>{format_bytes(int(rule["size_bytes"]))}</span>
              <span>{html.escape(format_unix_timestamp(int(rule["modified_at"])))}</span>
              <div class="rule-actions">
                <form action="/engines/yara/rules/{encoded_name}/toggle" method="post">
                  <button class="secondary-action compact-action" type="submit">{toggle_label}</button>
                </form>
                <form action="/engines/yara/rules/{encoded_name}/delete" method="post">
                  <button class="danger-action compact-action" type="submit">Delete</button>
                </form>
              </div>
            </div>
            """
        )

    return "\n".join(rows)


def render_engine_logo(label: str, key: str) -> str:
    safe_label = html.escape(label)

    if key == "clamav":
        return f"""
        <span class="engine-logo engine-logo-clamav" aria-hidden="true">
          <svg viewBox="0 0 44 44" role="img" focusable="false">
            <path d="M11.2 14.4 16.7 7l3.8 5.5h3.1L27.3 7l5.5 7.4A14.7 14.7 0 0 1 36.5 24c0 8.1-6.5 14.5-14.5 14.5S7.5 32.1 7.5 24a14.7 14.7 0 0 1 3.7-9.6Z" fill="currentColor"></path>
            <path d="M13.4 22.2c1.6-2.2 5.8-2.6 9-.5-1.7 3.7-5 5.8-8.5 5.6-.8-1.7-.9-3.5-.5-5.1Z" fill="#ffffff"></path>
            <path d="M30.6 22.2c-1.6-2.2-5.8-2.6-9-.5 1.7 3.7 5 5.8 8.5 5.6.8-1.7.9-3.5.5-5.1Z" fill="#ffffff"></path>
            <path d="M17.5 23.7c.8 1.2 2.3 2.6 4.2 3.4-2 .7-3.9.5-5.3-.4.1-1 .5-2 .9-3Z" fill="#202124"></path>
            <path d="M26.5 23.7c-.8 1.2-2.3 2.6-4.2 3.4 2 .7 3.9.5 5.3-.4-.1-1-.5-2-.9-3Z" fill="#202124"></path>
          </svg>
        </span>
        """

    if key == "yara":
        return '<span class="engine-logo engine-logo-yara engine-logo-glyph" aria-hidden="true">&#123;</span>'

    return f'<span class="engine-logo engine-logo-text" aria-hidden="true">{safe_label}</span>'


def render_add_engine_panel() -> str:
    available_adapters = available_adapter_definitions()
    if available_adapters:
        adapter_rows_html = "\n".join(
            f"""
            <label class="adapter-option">
              <input type="radio" name="adapter_key" value="{html.escape(definition.key)}" {"checked" if index == 0 else ""}>
              {render_engine_logo(definition.short_label, definition.key)}
              <span>
                <strong>{html.escape(definition.label)}</strong>
                <small>{html.escape(definition.description)}</small>
              </span>
            </label>
            """
            for index, definition in enumerate(available_adapters)
        )
        description = "Add adapters from the supported engine catalog, then configure them per node."
        button_disabled = ""
        pill = '<span class="pill success">Catalog ready</span>'
    else:
        adapter_rows_html = """
        <div class="adapter-empty">
          <strong>All implemented adapters are configured</strong>
          <span>Remove an adapter to add it again, or implement a new adapter to expose it here.</span>
        </div>
        """
        description = "All implemented adapters are already configured on this node."
        button_disabled = " disabled"
        pill = '<span class="pill neutral">No adapters left</span>'

    return f"""
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Engine registry</h2>
          <p>{description}</p>
        </div>
        {pill}
      </div>
      <details class="add-engine-drawer">
        <summary>
          <span class="add-engine-trigger">Add new engine</span>
          <span class="engine-expand-indicator" aria-hidden="true"></span>
        </summary>
        <form class="add-engine-form" action="/engines/add" method="post">
          <div class="adapter-scroll-list">
            {adapter_rows_html}
          </div>
          <button class="primary-action" type="submit"{button_disabled}>Add selected engine</button>
        </form>
      </details>
    </section>
    """


def health_tone_for(adapter_key: str, health: dict[str, str | bool]) -> str:
    if str(health["status"]) == "disabled":
        return "neutral"
    if bool(health["ok"]):
        return "success"
    if adapter_key == "clamav" and health["status"] in {"unreachable", "unexpected"}:
        return "danger"
    if adapter_key == "yara" and health["status"] in {"not configured", "no rules", "unavailable"}:
        return "danger"
    return "neutral"


def render_engine_actions(instance: EngineInstanceRecord, show_test: bool) -> str:
    buttons = []
    if show_test:
        buttons.append(
            f"""
            <form action="/engines/{html.escape(instance.adapter_key)}/test" method="post">
              <button class="secondary-action" type="submit">Test connection</button>
            </form>
            """
        )
    buttons.append(
        f"""
        <form action="/engines/{html.escape(instance.adapter_key)}/toggle" method="post">
          <button class="secondary-action" type="submit">{"Disable" if instance.enabled else "Enable"}</button>
        </form>
        """
    )
    buttons.append(
        f"""
        <form action="/engines/{html.escape(instance.adapter_key)}/delete" method="post">
          <button class="danger-action" type="submit">Remove</button>
        </form>
        """
    )
    return f'<div class="engine-toolbar">{"".join(buttons)}</div>'


def render_engine_summary(
    instance: EngineInstanceRecord,
    status_html: str,
    meta: str,
) -> str:
    definition = adapter_definition(instance.adapter_key)
    disabled_note = (
        '<small class="engine-disabled-note">Disabled engines are skipped by the worker.</small>'
        if not instance.enabled
        else ""
    )
    return f"""
    <summary class="engine-card-summary">
      {render_engine_logo(definition.short_label, instance.adapter_key)}
      <span class="engine-summary-copy">
        <strong>{html.escape(instance.display_name)}</strong>
        <small>{html.escape(definition.description)}</small>
        {disabled_note}
      </span>
      <span class="engine-summary-meta">{html.escape(meta)}</span>
      {status_html}
      <span class="engine-expand-indicator" aria-hidden="true"></span>
    </summary>
    """


def render_engine_details_shell(
    instance: EngineInstanceRecord,
    status_html: str,
    meta: str,
    body: str,
    health_overrides: dict[str, dict[str, str | bool]],
) -> str:
    disabled_class = " is-disabled" if not instance.enabled else ""
    open_attr = " open" if instance.adapter_key in health_overrides else ""
    return f"""
    <details class="panel engine-secondary engine-card{disabled_class}"{open_attr}>
      {render_engine_summary(instance, status_html, meta)}
      <div class="engine-config">
        {body}
      </div>
    </details>
    """


def render_engine_card(
    instance: EngineInstanceRecord,
    health_overrides: dict[str, dict[str, str | bool]],
) -> str:
    definition = adapter_definition(instance.adapter_key)
    runtime = runtime_config(instance)

    health = (
        {"ok": False, "status": "disabled", "detail": "Engine instance is disabled."}
        if not instance.enabled
        else health_overrides.get(instance.adapter_key) or engine_health(instance)
    )
    tone = health_tone_for(instance.adapter_key, health)
    status_html = f'<span class="pill {tone}">{html.escape(str(health["status"]).title())}</span>'
    meta = "Disabled" if not instance.enabled else "Detection" if definition.detection else "Metadata"

    if instance.adapter_key == "clamav":
        form_values = clamav_form_values(instance)
        if str(runtime["mode"]) == "clamd":
            fields = [
                ("Adapter", "clamd TCP"),
                ("Host", str(runtime["host"])),
                ("Port", str(runtime["port"])),
                ("Timeout", f'{runtime["timeout_seconds"]}s'),
                ("Configured via", "engine registry"),
            ]
        else:
            fields = [
                ("Adapter", "local CLI"),
                ("Command", str(runtime["command"])),
                ("Timeout", f'{runtime["timeout_seconds"]}s'),
                ("Configured via", "engine registry"),
            ]

        field_html = "\n".join(
            f"""
            <div>
              <span>{html.escape(label)}</span>
              <strong>{html.escape(value)}</strong>
            </div>
            """
            for label, value in fields
        )
        body = f"""
            <div class="config-grid">{field_html}</div>
            <div class="engine-health">
              <div>
                <span>Last check</span>
                <strong>{html.escape(str(health["detail"]))}</strong>
              </div>
              {render_engine_actions(instance, show_test=instance.enabled)}
            </div>
            <details class="engine-settings-drawer">
              <summary>
                <span>Settings</span>
                <span class="engine-expand-indicator" aria-hidden="true"></span>
              </summary>
              <form class="settings-form embedded" action="/engines/clamav/config" method="post">
                <div class="settings-section">
                  <div>
                    <h3>Connection settings</h3>
                    <p>Use clamd TCP when host is set; leave host empty for local CLI mode.</p>
                  </div>
                  <div class="settings-grid">
                    <label>
                      clamd host
                      <input type="text" name="clamav_host" value="{html.escape(form_values["host"])}" placeholder="clamav">
                    </label>
                    <label>
                      clamd port
                      <input type="number" name="clamav_port" value="{html.escape(form_values["port"])}" min="1" max="65535">
                    </label>
                    <label>
                      CLI command
                      <input type="text" name="clamav_command" value="{html.escape(form_values["command"])}" placeholder="clamscan">
                    </label>
                    <label>
                      timeout seconds
                      <input type="number" name="clamav_timeout_seconds" value="{html.escape(form_values["timeout_seconds"])}" min="1" max="600">
                    </label>
                  </div>
                </div>
                <div class="settings-actions">
                  <button class="primary-action" type="submit">Save ClamAV settings</button>
                </div>
              </form>
            </details>
        """
        return render_engine_details_shell(
            instance,
            status_html=status_html,
            meta=meta,
            body=body,
            health_overrides=health_overrides,
        )

    if instance.adapter_key == "yara":
        form_values = yara_form_values(instance)
        fields = [
            ("Adapter", "local CLI"),
            ("Command", str(runtime["command"])),
            ("Rules", str(runtime["rules_dir"])),
            ("Rule count", str(runtime["rule_count"])),
            ("Timeout", f'{runtime["timeout_seconds"]}s'),
        ]
        field_html = "\n".join(
            f"""
            <div>
              <span>{html.escape(label)}</span>
              <strong>{html.escape(value)}</strong>
            </div>
            """
            for label, value in fields
        )
        body = f"""
            <div class="config-grid">{field_html}</div>
            <div class="engine-health">
              <div>
                <span>Last check</span>
                <strong>{html.escape(str(health["detail"]))}</strong>
              </div>
              {render_engine_actions(instance, show_test=instance.enabled)}
            </div>
            <details class="engine-settings-drawer">
              <summary>
                <span>Settings</span>
                <span class="engine-expand-indicator" aria-hidden="true"></span>
              </summary>
              <form class="settings-form embedded" action="/engines/yara/config" method="post">
                <div class="settings-section">
                  <div>
                    <h3>Runtime settings</h3>
                    <p>Configure the local YARA executable and rule directory used by the worker.</p>
                  </div>
                  <div class="settings-grid three">
                    <label>
                      CLI command
                      <input type="text" name="yara_command" value="{html.escape(form_values["command"])}" placeholder="yara">
                    </label>
                    <label>
                      rules directory
                      <input type="text" name="yara_rules_dir" value="{html.escape(form_values["rules_dir"])}" placeholder="rules">
                    </label>
                    <label>
                      timeout seconds
                      <input type="number" name="yara_timeout_seconds" value="{html.escape(form_values["timeout_seconds"])}" min="1" max="600">
                    </label>
                  </div>
                </div>
                <div class="settings-actions">
                  <button class="primary-action" type="submit">Save YARA settings</button>
                </div>
              </form>
            </details>
            <div class="engine-subsection">
              <div class="engine-subsection-header">
                <div>
                  <h3>Rule library</h3>
                  <p>Upload, disable, or remove local YARA rules.</p>
                </div>
                <span class="pill neutral">{html.escape(str(runtime["rule_count"]))} enabled</span>
              </div>
              <form class="rule-upload" action="/engines/yara/rules" method="post" enctype="multipart/form-data">
                <label>
                  Upload rule file
                  <input type="file" name="rule_file" accept=".yar,.yara">
                </label>
                <div class="rule-or">or</div>
                <label>
                  Rule filename
                  <input type="text" name="rule_name" placeholder="custom_rule.yar">
                </label>
                <label class="rule-body">
                  Paste rule
                  <textarea name="rule_body" rows="7" placeholder="rule sample_rule {{ condition: true }}"></textarea>
                </label>
                <div class="settings-actions">
                  <button class="primary-action" type="submit">Add rule</button>
                </div>
              </form>
              <div class="rule-table">
                <div class="rule-row rule-header">
                  <span>Rule</span>
                  <span>Status</span>
                  <span>Size</span>
                  <span>Modified</span>
                  <span>Actions</span>
                </div>
                {render_yara_rule_rows()}
              </div>
            </div>
        """
        return render_engine_details_shell(
            instance,
            status_html=status_html,
            meta=meta,
            body=body,
            health_overrides=health_overrides,
        )

    fields = [
        ("Adapter", "built-in"),
        ("Category", "metadata"),
        ("Detection", "No"),
        ("Configured via", "engine registry"),
    ]
    field_html = "\n".join(
        f"""
        <div>
          <span>{html.escape(label)}</span>
          <strong>{html.escape(value)}</strong>
        </div>
        """
        for label, value in fields
    )
    body = f"""
        <div class="config-grid">{field_html}</div>
        <div class="engine-health">
          <div>
            <span>Last check</span>
            <strong>{html.escape(str(health["detail"]))}</strong>
          </div>
          {render_engine_actions(instance, show_test=False)}
        </div>
    """
    return render_engine_details_shell(
        instance,
        status_html=status_html,
        meta=meta,
        body=body,
        health_overrides=health_overrides,
    )


def render_configured_engine_rows() -> str:
    rows = []
    for instance in configured_engines():
        definition = adapter_definition(instance.adapter_key)
        rows.append(
            f"""
            <div class="engine-row {'muted' if not instance.enabled else ''}">
              {render_engine_logo(definition.short_label, instance.adapter_key)}
              <div><strong>{html.escape(instance.display_name)}</strong><small>{html.escape(definition.description)}</small></div>
              <span class="pill {'success' if instance.enabled else 'neutral'}">{'Enabled' if instance.enabled else 'Disabled'}</span>
            </div>
            """
        )
    return "\n".join(rows)


def role_options(selected_role: str) -> str:
    return "\n".join(
        f'<option value="{role}" {"selected" if role == selected_role else ""}>{label}</option>'
        for role, label in [
            (ROLE_ADMIN, "Admin"),
            ("analyst", "Analyst"),
        ]
    )


def render_user_rows(current_admin: UserRecord) -> str:
    rows = []
    for user in list_users():
        delete_action = (
            '<span class="pill neutral">Current session</span>'
            if user.id == current_admin.id
            else f"""
            <form action="/users/{user.id}/delete" method="post">
              <button class="danger-action compact-action" type="submit">Delete</button>
            </form>
            """
        )
        rows.append(
            f"""
            <div class="user-row">
              <div>
                <strong>{html.escape(user.username)}</strong>
                <small>Created {html.escape(user.created_at)}</small>
              </div>
              <form class="user-inline-form" action="/users/{user.id}" method="post">
                <label>
                  Role
                  <select name="role">
                    {role_options(user.role)}
                  </select>
                </label>
                <label>
                  New password
                  <input type="password" name="password" placeholder="Leave unchanged" autocomplete="new-password">
                </label>
                <button class="secondary-action compact-action" type="submit">Save</button>
              </form>
              <div class="user-actions">
                {delete_action}
              </div>
            </div>
            """
        )
    return "\n".join(rows)


def render_users_page(user: UserRecord, message: str = "") -> str:
    message_html = (
        f'<section class="notice success-notice"><div><strong>Users updated</strong><span>{html.escape(message)}</span></div></section>'
        if message
        else ""
    )
    body = f"""
    {message_html}
    <section class="users-layout">
      <form class="panel user-create-panel" action="/users" method="post">
        <div class="panel-header">
          <div>
            <h2>Create user</h2>
            <p>Add a local account for this MASP node.</p>
          </div>
          <span class="pill neutral">Admin only</span>
        </div>
        <div class="settings-form embedded">
          <div class="settings-grid three">
            <label>
              Username
              <input type="text" name="username" autocomplete="username" required>
            </label>
            <label>
              Role
              <select name="role">
                {role_options("analyst")}
              </select>
            </label>
            <label>
              Password
              <input type="password" name="password" autocomplete="new-password" required>
            </label>
          </div>
          <div class="settings-actions">
            <button class="primary-action" type="submit">Create user</button>
          </div>
        </div>
      </form>

      <section class="panel">
        <div class="panel-header compact">
          <h2>Local users</h2>
          <span class="pill neutral">{len(list_users())} accounts</span>
        </div>
        <div class="user-table">
          {render_user_rows(user)}
        </div>
      </section>
    </section>
    """
    return page_shell("Users", "users", body, user)


def short_hash(value: str) -> str:
    return f"{value[:12]}...{value[-8:]}"


def display_verdict(verdict: str) -> str:
    return verdict.replace("_", " ").title()


def status_pill(status: str) -> str:
    tone_by_status = {
        "queued": "neutral",
        "completed": "success",
        "skipped": "neutral",
        "failed": "danger",
        "running": "warning",
        "partial": "warning",
    }
    tone = tone_by_status.get(status, "warning")
    return f'<span class="pill {tone}">{html.escape(display_verdict(status))}</span>'


def verdict_pill(verdict: str) -> str:
    tone_by_verdict = {
        "pending": "neutral",
        "info": "neutral",
        "metadata_only": "neutral",
        "low": "success",
        "medium": "warning",
        "high": "danger",
        "critical": "danger",
    }
    tone = tone_by_verdict.get(verdict, "warning")
    return f'<span class="pill {tone}">{html.escape(display_verdict(verdict))}</span>'


def dashboard_verdict_pill(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status in {"queued", "running"}:
        return '<span class="pill neutral">Pending</span>'

    detected, total = detection_summary(results)
    if total == 0:
        return '<span class="pill neutral">Metadata Only</span>'
    if detected > 0:
        return '<span class="pill danger">Malicious</span>'
    return '<span class="pill success">Undetected</span>'


def severity_pill(severity: str) -> str:
    tone_by_severity = {
        "info": "neutral",
        "low": "success",
        "medium": "warning",
        "high": "warning",
        "critical": "danger",
    }
    tone = tone_by_severity.get(severity, "neutral")
    return f'<span class="pill {tone}">{html.escape(severity.title())}</span>'


def detected_pill(status: str, detected: bool) -> str:
    if status == "skipped":
        return '<span class="pill neutral">Not run</span>'
    if status == "failed":
        return '<span class="pill danger">Error</span>'
    if detected:
        return '<span class="pill danger">Detected</span>'
    return '<span class="pill success">Clean</span>'


def detection_engine_results(results: list[EngineResultRecord]) -> list[EngineResultRecord]:
    return [
        result
        for result in results
        if result.engine_name.lower() != "static metadata"
    ]


def detection_summary(results: list[EngineResultRecord]) -> tuple[int, int]:
    detection_results = detection_engine_results(results)
    detected = sum(
        1
        for result in detection_results
        if result.status == "completed" and result.detected
    )
    return detected, max(len(detection_results), len(detection_engine_names()))


def detected_engine_names(results: list[EngineResultRecord]) -> list[str]:
    return [
        result.engine_name
        for result in detection_engine_results(results)
        if result.status == "completed" and result.detected
    ]


def detection_summary_text(results: list[EngineResultRecord]) -> str:
    detected, total = detection_summary(results)
    if total == 0:
        return "No detection engines configured"
    if detected == 0:
        return f"0 of {total} engines detected"
    return f"{detected} of {total} engines detected"


def detection_summary_label(results: list[EngineResultRecord]) -> str:
    return detection_summary_text(results)


def detection_summary_pill(results: list[EngineResultRecord]) -> str:
    detected, total = detection_summary(results)
    if total == 0:
        tone = "neutral"
    elif detected > 0:
        tone = "danger"
    else:
        tone = "success"
    return f'<span class="pill {tone}">{html.escape(detection_summary_text(results))}</span>'


def detection_meter(results: list[EngineResultRecord]) -> str:
    detected, total = detection_summary(results)
    meter_angle = 0 if total == 0 else round((detected / total) * 360)
    if total == 0:
        tone = "neutral"
        label = "No detection engines configured"
    elif detected > 0:
        tone = "danger"
        label = f"{detected} of {total} engines detected"
    else:
        tone = "success"
        label = f"0 of {total} engines detected"

    return f"""
    <div class="detection-meter {tone}" style="--meter-angle: {meter_angle}deg" aria-label="{html.escape(label)}" title="{html.escape(label)}">
      <div class="detection-meter-core">
        <strong>{detected}</strong>
        <span>/ {total}</span>
      </div>
    </div>
    """


def detection_summary_text_for_scan(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status in {"queued", "running"}:
        return "Pending engine results"
    return detection_summary_text(results)


def detection_summary_tone_for_scan(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status in {"queued", "running"}:
        return "neutral"
    return detection_summary_tone(results)


def detection_detail_text_for_scan(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status in {"queued", "running"}:
        return "Detection engines have not completed yet."
    return detection_detail_text(results)


def detection_meter_for_scan(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status not in {"queued", "running"}:
        return detection_meter(results)

    total = len(detection_engine_names())
    label = "Pending engine results"
    return f"""
    <div class="detection-meter neutral" style="--meter-angle: 0deg" aria-label="{html.escape(label)}" title="{html.escape(label)}">
      <div class="detection-meter-core">
        <strong>0</strong>
        <span>/ {total}</span>
      </div>
    </div>
    """


def detection_summary_tone(results: list[EngineResultRecord]) -> str:
    detected, total = detection_summary(results)
    if total == 0:
        return "neutral"
    if detected > 0:
        return "danger"
    return "success"


def engine_result_map(results: list[EngineResultRecord]) -> dict[str, EngineResultRecord]:
    return {result.engine_name.lower(): result for result in results}


def required_engine_coverage(
    results: list[EngineResultRecord],
) -> tuple[int, int, list[str]]:
    result_map = engine_result_map(results)
    unavailable = []
    ran = 0
    required_engines = detection_engine_names()

    for engine_name in required_engines:
        result = result_map.get(engine_name.lower())
        if result is None:
            unavailable.append(f"{engine_name} missing")
            continue

        if result.status == "completed":
            ran += 1
            continue

        unavailable.append(f"{engine_name} {result.status}")

    return ran, len(required_engines), unavailable


def coverage_summary_text(results: list[EngineResultRecord]) -> str:
    ran, total, _ = required_engine_coverage(results)
    if total == 0:
        return "No required detection engines configured"
    return f"{ran} of {total} required engines ran"


def coverage_detail_text(results: list[EngineResultRecord]) -> str:
    _, total, unavailable = required_engine_coverage(results)
    if total == 0:
        return "Only metadata analyzers are enabled for this scan."
    if not unavailable:
        return "All required detection engines completed."
    return "; ".join(unavailable)


def coverage_tone(results: list[EngineResultRecord]) -> str:
    ran, total, unavailable = required_engine_coverage(results)
    if total == 0:
        return "neutral"
    if not unavailable:
        return "success"
    if ran == 0 and total > 0:
        return "danger"
    return "warning"


def coverage_summary_text_for_scan(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status == "queued":
        return "Waiting for worker"
    if scan.status == "running":
        return "Engines are running"
    return coverage_summary_text(results)


def coverage_detail_text_for_scan(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status == "queued":
        return "Required engines have not started yet."
    if scan.status == "running":
        return "Required engines are being executed by the worker."
    return coverage_detail_text(results)


def coverage_tone_for_scan(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status in {"queued", "running"}:
        return "warning"
    if scan.status == "failed":
        return "danger"
    return coverage_tone(results)


def coverage_status_pill(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status != "completed":
        return status_pill(scan.status)

    tone = coverage_tone_for_scan(scan, results)
    if tone == "success":
        return status_pill(scan.status)
    if tone == "neutral":
        return '<span class="pill neutral">Metadata Only</span>'
    if tone == "danger":
        return '<span class="pill danger">Engine Failure</span>'
    return '<span class="pill warning">Partial</span>'


def coverage_status_detail_for_scan(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status != "completed":
        return ""

    tone = coverage_tone_for_scan(scan, results)
    if tone in {"success", "neutral"}:
        return ""
    return coverage_detail_text(results)


def coverage_summary_card_class(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    return f"summary-wide coverage-summary-card {coverage_tone_for_scan(scan, results)}"


def detection_detail_text(results: list[EngineResultRecord]) -> str:
    names = detected_engine_names(results)
    if names:
        return ", ".join(names)

    _, total = detection_summary(results)
    if total == 0:
        return "Add a detection adapter from Engines to populate this."
    return "No detection engine flagged this sample."


def detection_summary_card_class(results: list[EngineResultRecord]) -> str:
    detected, total = detection_summary(results)
    if total == 0:
        return "summary-wide detection-summary-card neutral"
    if detected > 0:
        return "summary-wide detection-summary-card danger"
    return "summary-wide detection-summary-card success"


def render_recent_scan_rows(scans: list[ScanRecord], can_select: bool) -> str:
    if not scans:
        colspan = 7 if can_select else 6
        return f'<tr><td class="empty-cell" colspan="{colspan}">No scans submitted yet.</td></tr>'

    rows = []
    for scan in scans:
        engine_results = list_engine_results(scan.id)
        select_cell = (
            f"""
              <td class="select-cell">
                <input class="row-checkbox" type="checkbox" data-row-checkbox aria-label="Select scan {scan.id}">
              </td>
            """
            if can_select
            else ""
        )
        rows.append(
            f"""
            <tr class="dashboard-scan-row" data-scan-row data-scan-id="{scan.id}" data-scan-url="/scans/{scan.id}" tabindex="0" aria-selected="false">
              {select_cell}
              <td>
                <div class="table-link">
                  <strong>{html.escape(scan.original_filename)}</strong>
                  <small>{html.escape(scan.case_name)}</small>
                </div>
              </td>
              <td><code class="copyable" data-copy-value="{html.escape(scan.sha256)}" aria-label="Copy SHA256" title="Copy SHA256">{short_hash(scan.sha256)}</code></td>
              <td>
                {coverage_status_pill(scan, engine_results)}
                <small class="status-detail">{html.escape(coverage_status_detail_for_scan(scan, engine_results))}</small>
              </td>
              <td>{dashboard_verdict_pill(scan, engine_results)}</td>
              <td>
                <span class="detection-count {detection_summary_tone_for_scan(scan, engine_results)}">{html.escape(detection_summary_text_for_scan(scan, engine_results))}</span>
              </td>
              <td>{html.escape(scan.created_at)}</td>
            </tr>
            """
        )
    return "\n".join(rows)


def render_engine_result_rows(results: list[EngineResultRecord]) -> str:
    if not results:
        return """
        <tr>
          <td class="empty-cell" colspan="7">
            No engine results yet. The next step is wiring the Static Metadata engine.
          </td>
        </tr>
        """

    rows = []
    for result in results:
        signature = result.signature or "-"
        error = result.error_message or "-"
        row_class = (
            ' class="engine-detected-row"'
            if result.status == "completed" and result.detected
            else ""
        )
        raw_row_class = (
            "raw-output-row engine-detected-raw"
            if result.status == "completed" and result.detected
            else "raw-output-row"
        )
        rows.append(
            f"""
            <tr{row_class}>
              <td>
                <strong>{html.escape(result.engine_name)}</strong>
                <small>{html.escape(result.engine_version or "version unknown")}</small>
              </td>
              <td>{status_pill(result.status)}</td>
              <td>{detected_pill(result.status, result.detected)}</td>
              <td>{severity_pill(result.severity)}</td>
              <td>{result.confidence}%</td>
              <td>{html.escape(signature)}</td>
              <td>{html.escape(str(result.duration_ms))} ms</td>
            </tr>
            <tr class="{raw_row_class}">
              <td colspan="7">
                <details>
                  <summary>Raw output</summary>
                  <pre>{html.escape(result.raw_output)}</pre>
                  <small>{html.escape(error)}</small>
                </details>
              </td>
            </tr>
            """
        )
    return "\n".join(rows)


def render_risk_reasons(reasons: list[str]) -> str:
    return "\n".join(
        f"<li>{html.escape(reason)}</li>"
        for reason in reasons
    )


def render_coverage_notice(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status in {"queued", "running"}:
        return f"""
        <section class="notice processing-notice">
          <div>
            <strong>{html.escape(display_verdict(scan.status))}</strong>
            <span>{html.escape(coverage_detail_text_for_scan(scan, results))} This page refreshes automatically.</span>
          </div>
        </section>
        """

    tone = coverage_tone_for_scan(scan, results)
    if tone in {"success", "neutral"}:
        return ""

    title = "Required engine did not complete"
    if tone == "danger":
        title = "Required engines did not complete"

    return f"""
        <section class="notice warning-notice">
          <div>
            <strong>{html.escape(title)}</strong>
            <span>{html.escape(coverage_summary_text_for_scan(scan, results))}: {html.escape(coverage_detail_text_for_scan(scan, results))}</span>
          </div>
        </section>
        """


def render_scan_result(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
    user: UserRecord,
) -> str:
    assessment = calculate_risk(engine_results)
    score = scan.risk_score if scan.risk_score is not None else assessment.score
    verdict = scan.verdict if scan.risk_score is not None else assessment.verdict
    body = f"""
    <section class="notice success-notice">
      <div>
        <strong>Sample accepted</strong>
        <span>{html.escape(scan.original_filename)} was uploaded and stored successfully.</span>
      </div>
      <a class="row-action" href="/">Back to dashboard</a>
    </section>
    {render_coverage_notice(scan, engine_results)}

    <section class="result-layout">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h2>Scan summary</h2>
            <p>The sample was stored, analyzed by configured engines, and scored.</p>
          </div>
          <div class="scan-verdict-group">
            {verdict_pill(verdict)}
            {detection_meter_for_scan(scan, engine_results)}
          </div>
        </div>
        <div class="summary-grid">
          <div><span>Filename</span><strong>{html.escape(scan.original_filename)}</strong></div>
          <div><span>Case</span><strong>{html.escape(scan.case_name)}</strong></div>
          <div><span>Priority</span><strong>{html.escape(scan.priority)}</strong></div>
          <div><span>Size</span><strong>{format_bytes(scan.size_bytes)}</strong></div>
          <div><span>Content type</span><strong>{html.escape(scan.content_type)}</strong></div>
          <div><span>Risk score</span><strong>{score} / 100</strong></div>
          <div class="{detection_summary_card_class(engine_results)}">
            <span>Engine detections</span>
            <strong>{html.escape(detection_summary_text_for_scan(scan, engine_results))}</strong>
            <small>{html.escape(detection_detail_text_for_scan(scan, engine_results))}</small>
          </div>
          <div class="{coverage_summary_card_class(scan, engine_results)}">
            <span>Engine coverage</span>
            <strong>{html.escape(coverage_summary_text_for_scan(scan, engine_results))}</strong>
            <small>{html.escape(coverage_detail_text_for_scan(scan, engine_results))}</small>
          </div>
        </div>
        <div class="reason-block">
          <span>Reasons</span>
          <ul>
            {render_risk_reasons(assessment.reasons)}
          </ul>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header compact">
          <h2>Hashes</h2>
          <span class="pill neutral">Static metadata</span>
        </div>
        <dl class="hash-list">
          <div><dt>MD5</dt><dd><code class="copyable" data-copy-value="{html.escape(scan.md5)}" aria-label="Copy MD5" title="Copy MD5">{html.escape(scan.md5)}</code></dd></div>
          <div><dt>SHA1</dt><dd><code class="copyable" data-copy-value="{html.escape(scan.sha1)}" aria-label="Copy SHA1" title="Copy SHA1">{html.escape(scan.sha1)}</code></dd></div>
          <div><dt>SHA256</dt><dd><code class="copyable" data-copy-value="{html.escape(scan.sha256)}" aria-label="Copy SHA256" title="Copy SHA256">{html.escape(scan.sha256)}</code></dd></div>
        </dl>
      </div>

      <div class="panel wide">
        <div class="panel-header compact">
          <h2>Engine results</h2>
          <span class="pill neutral">{len(engine_results)} results</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Engine</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Signature</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {render_engine_result_rows(engine_results)}
            </tbody>
          </table>
        </div>
      </div>
    </section>
    """
    refresh_seconds = 5 if scan.status in {"queued", "running"} else None
    return page_shell("Scan Result", "dashboard", body, user, refresh_seconds=refresh_seconds)


def backfill_missing_assessments(limit: int = 250) -> None:
    for scan in list_recent_scans(limit=limit):
        if scan.risk_score is not None:
            continue
        if scan.status in {"queued", "running"}:
            continue

        engine_results = list_engine_results(scan.id)
        assessment = calculate_risk(engine_results)
        update_scan_assessment(scan.id, assessment.verdict, assessment.score)


backfill_missing_assessments()


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/"):
    if current_user(request) is not None:
        return RedirectResponse(url=safe_next_url(next), status_code=303)
    return HTMLResponse(render_login_page(next_url=next))


@app.post("/login", response_class=HTMLResponse)
def login_route(
    username: str = Form(...),
    password: str = Form(...),
    next_url: str = Form("/"),
):
    result = login(username, password)
    if result is None:
        return HTMLResponse(
            render_login_page(
                next_url=next_url,
                error="Invalid username or password.",
            ),
            status_code=401,
        )

    response = RedirectResponse(url=safe_next_url(next_url), status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        result.session_token,
        max_age=result.expires_at - int(datetime.now().timestamp()),
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/logout")
def logout_route(request: Request) -> RedirectResponse:
    logout(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> str:
    user = require_user(request)
    can_manage_scans = user.role == ROLE_ADMIN
    scans = list_recent_scans()
    counts = get_scan_counts()
    configured_engine_count = len(configured_engines())
    delete_actions = (
        """
            <form id="bulk-delete-form" action="/scans/delete" method="post" data-bulk-delete-form></form>
            <button class="toolbar-delete" type="submit" form="bulk-delete-form" data-bulk-delete hidden>Delete selected</button>
        """
        if can_manage_scans
        else '<span class="pill neutral">Read-only history</span>'
    )
    select_header = (
        """
                <th class="select-cell">
                  <input class="row-checkbox" type="checkbox" data-select-all aria-label="Select all scans" title="Select all scans">
                </th>
        """
        if can_manage_scans
        else ""
    )
    body = f"""
    <section class="metric-grid">
      {metric_card("Samples", str(counts["total"]), "Persisted scan jobs")}
      {metric_card("Active", str(counts["running"]), "Queued or running jobs", "tone-blue")}
      {metric_card("High risk", str(counts["high_risk"]), "All persisted jobs", "tone-red")}
      {metric_card("Engines", str(configured_engine_count), "Configured locally", "tone-green")}
    </section>

    <section class="dashboard-grid">
      <div class="panel wide">
        <div class="panel-header">
          <div>
            <h2>Recent scans</h2>
            <p>Latest submitted samples will appear here.</p>
          </div>
          <div class="panel-actions">
            {delete_actions}
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                {select_header}
                <th>File</th>
                <th>SHA256</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>Engines</th>
                <th>Submitted</th>
              </tr>
            </thead>
            <tbody>
              {render_recent_scan_rows(scans, can_select=can_manage_scans)}
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header compact">
          <h2>Pipeline</h2>
          <span class="pill success">Ready</span>
        </div>
        <ol class="step-list">
          <li><span>1</span><strong>Ingest</strong><small>Store sample and metadata</small></li>
          <li><span>2</span><strong>Analyze</strong><small>Run configured engines</small></li>
          <li><span>3</span><strong>Normalize</strong><small>Unify engine outputs</small></li>
          <li><span>4</span><strong>Report</strong><small>Score and summarize findings</small></li>
        </ol>
      </div>
    </section>
    """
    return page_shell("Scan Dashboard", "dashboard", body, user)


@app.get("/users", response_class=HTMLResponse)
def users(request: Request) -> str:
    user = require_admin(request)
    return render_users_page(user)


@app.post("/users")
def create_user_route(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("analyst"),
) -> RedirectResponse:
    require_admin(request)
    clean_username = username.strip()
    if not clean_username:
        raise HTTPException(status_code=400, detail="Username is required.")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    if get_user_by_username(clean_username) is not None:
        raise HTTPException(status_code=400, detail="Username already exists.")

    create_user(
        username=clean_username,
        password_hash=hash_password(password),
        role=normalize_role(role),
    )
    return RedirectResponse(url="/users", status_code=303)


@app.post("/users/{user_id}")
def update_user_route(
    request: Request,
    user_id: int,
    role: str = Form("analyst"),
    password: str = Form(""),
) -> RedirectResponse:
    require_admin(request)
    new_password_hash = hash_password(password) if password else None
    if password and len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    update_user(user_id, normalize_role(role), new_password_hash)
    return RedirectResponse(url="/users", status_code=303)


@app.post("/users/{user_id}/delete")
def delete_user_route(request: Request, user_id: int) -> RedirectResponse:
    user = require_admin(request)
    if user.id == user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your current user.")
    delete_user(user_id)
    return RedirectResponse(url="/users", status_code=303)


@app.get("/scans/new", response_class=HTMLResponse)
def new_scan(request: Request) -> str:
    user = require_user(request)
    body = f"""
    <section class="scan-layout">
      <form class="panel upload-panel" action="/scans" method="post" enctype="multipart/form-data" data-upload-form>
        <div class="panel-header">
          <div>
            <h2>Submit sample</h2>
            <p>Create a scan job for the local engine pipeline.</p>
          </div>
          <span class="pill warning">Draft</span>
        </div>

        <label class="dropzone" for="sample-file">
          <span class="dropzone-icon">+</span>
          <strong>Select file</strong>
          <small>Maximum size policy will be enforced by the ingest service.</small>
          <span class="selected-file" data-selected-file>No file selected</span>
          <input id="sample-file" name="sample" type="file" data-file-input required>
        </label>

        <div class="field-grid">
          <label>
            Case name
            <input type="text" name="case_name" placeholder="IR-2026-001">
          </label>
          <label>
            Priority
            <select name="priority">
              <option>Normal</option>
              <option>High</option>
              <option>Low</option>
            </select>
          </label>
        </div>

        <label>
          Analyst note
          <textarea name="note" rows="4" placeholder="Initial context, source, ticket, or handling notes"></textarea>
        </label>

        <div class="form-actions">
          <a class="secondary-action" href="/">Cancel</a>
          <button class="primary-action" type="submit" data-submit-button>Create Scan</button>
        </div>
      </form>

      <aside class="panel">
        <div class="panel-header compact">
          <h2>Selected engines</h2>
          <span class="pill success">{len(enabled_engines())} active</span>
        </div>
        <div class="engine-list">
          {render_configured_engine_rows()}
        </div>
      </aside>
    </section>
    """
    return page_shell("New Scan", "new_scan", body, user)


@app.post("/scans", response_class=HTMLResponse)
async def create_scan(
    request: Request,
    sample: UploadFile = File(...),
    case_name: str = Form("Unassigned"),
    priority: str = Form("Normal"),
    note: str = Form(""),
) -> RedirectResponse:
    require_user(request)
    if not sample.filename:
        raise HTTPException(status_code=400, detail="A file must be selected.")

    stored_sample = await store_upload(sample)
    sample_id = create_sample(stored_sample)
    scan_id = create_scan_job(
        sample_id=sample_id,
        case_name=case_name.strip() or "Unassigned",
        priority=priority,
        note=note.strip(),
    )
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=500, detail="Scan could not be loaded.")

    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


def delete_scan_record(scan_id: int) -> None:
    deleted_scan = delete_scan(scan_id)
    if deleted_scan is not None:
        delete_sample_file(deleted_scan)


@app.post("/scans/delete")
async def delete_selected_scans(
    request: Request,
    scan_ids: list[int] = Form(default=[]),
) -> RedirectResponse:
    require_admin(request)
    for scan_id in scan_ids:
        delete_scan_record(scan_id)
    return RedirectResponse(url="/", status_code=303)


@app.post("/scans/{scan_id}/delete")
async def delete_single_scan(request: Request, scan_id: int) -> RedirectResponse:
    require_admin(request)
    delete_scan_record(scan_id)
    return RedirectResponse(url="/", status_code=303)


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int) -> str:
    user = require_user(request)
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    engine_results = list_engine_results(scan.id)
    return render_scan_result(scan, engine_results, user)


@app.get("/engines", response_class=HTMLResponse)
def engines(request: Request) -> str:
    user = require_admin(request)
    return render_engines_page(user)


@app.post("/engines/add")
def add_engine_route(request: Request, adapter_key: str = Form(...)) -> RedirectResponse:
    require_admin(request)
    try:
        add_engine(adapter_key)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="Unknown engine adapter.") from exc
    return RedirectResponse(url="/engines", status_code=303)


@app.post("/engines/{adapter_key}/toggle")
def toggle_engine_route(request: Request, adapter_key: str) -> RedirectResponse:
    require_admin(request)
    toggle_engine(adapter_key)
    return RedirectResponse(url="/engines", status_code=303)


@app.post("/engines/{adapter_key}/delete")
def delete_engine_route(request: Request, adapter_key: str) -> RedirectResponse:
    require_admin(request)
    remove_engine(adapter_key)
    return RedirectResponse(url="/engines", status_code=303)


@app.post("/engines/{adapter_key}/test", response_class=HTMLResponse)
def test_engine_route(request: Request, adapter_key: str) -> str:
    user = require_admin(request)
    matches = [engine for engine in configured_engines() if engine.adapter_key == adapter_key]
    if not matches:
        raise HTTPException(status_code=404, detail="Engine not found.")
    return render_engines_page(
        user,
        health_overrides={adapter_key: engine_health(matches[0])}
    )


@app.post("/engines/clamav/config")
def save_clamav_config(
    request: Request,
    clamav_host: str = Form(""),
    clamav_port: str = Form("3310"),
    clamav_command: str = Form("clamscan"),
    clamav_timeout_seconds: str = Form("60"),
) -> RedirectResponse:
    require_admin(request)
    update_engine_config(
        "clamav",
        {
            "host": clamav_host.strip(),
            "port": clamav_port.strip() or "3310",
            "command": clamav_command.strip() or "clamscan",
            "timeout_seconds": clamav_timeout_seconds.strip() or "60",
        },
    )
    return RedirectResponse(url="/engines", status_code=303)


@app.post("/engines/yara/config")
def save_yara_config(
    request: Request,
    yara_command: str = Form("yara"),
    yara_rules_dir: str = Form("rules"),
    yara_timeout_seconds: str = Form("30"),
) -> RedirectResponse:
    require_admin(request)
    update_engine_config(
        "yara",
        {
            "command": yara_command.strip() or "yara",
            "rules_dir": yara_rules_dir.strip() or "rules",
            "timeout_seconds": yara_timeout_seconds.strip() or "30",
        },
    )
    return RedirectResponse(url="/engines", status_code=303)


@app.post("/engines/yara/rules")
async def upload_yara_rule(
    request: Request,
    rule_file: UploadFile | None = File(default=None),
    rule_name: str = Form(""),
    rule_body: str = Form(""),
) -> RedirectResponse:
    require_admin(request)
    try:
        if rule_file is not None and rule_file.filename:
            content = await rule_file.read()
            save_yara_rule(rule_file.filename, content)
        else:
            save_yara_rule(rule_name, rule_body.encode("utf-8"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return RedirectResponse(url="/engines", status_code=303)


@app.post("/engines/yara/rules/{rule_name}/toggle")
def toggle_yara_rule_route(request: Request, rule_name: str) -> RedirectResponse:
    require_admin(request)
    try:
        toggle_yara_rule(rule_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="YARA rule not found.") from exc
    return RedirectResponse(url="/engines", status_code=303)


@app.post("/engines/yara/rules/{rule_name}/delete")
def delete_yara_rule_route(request: Request, rule_name: str) -> RedirectResponse:
    require_admin(request)
    try:
        delete_yara_rule(rule_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="YARA rule not found.") from exc
    return RedirectResponse(url="/engines", status_code=303)


def render_engines_page(
    user: UserRecord,
    health_overrides: dict[str, dict[str, str | bool]] | None = None,
) -> str:
    overrides = health_overrides or {}
    engine_cards_html = "\n".join(
        render_engine_card(instance, overrides) for instance in configured_engines()
    )
    roadmap_rows_html = "\n".join(
        f"""
        <div class="engine-row muted">
          {render_engine_logo(str(item["short_label"]), str(item["label"]).lower().replace(" ", "_"))}
          <div><strong>{html.escape(item["label"])}</strong><small>{html.escape(item["description"])}</small></div>
          <span class="pill neutral">{html.escape(item["status"])}</span>
        </div>
        """
        for item in ROADMAP_ADAPTERS
    )

    body = f"""
    {render_add_engine_panel()}
    {engine_cards_html}
    <section class="panel engine-secondary">
      <div class="panel-header compact">
        <h2>Roadmap adapters</h2>
        <span class="pill neutral">{len(ROADMAP_ADAPTERS)} planned</span>
      </div>
      <div class="engine-table">
        {roadmap_rows_html}
      </div>
    </section>
    """
    return page_shell("Engines", "engines", body, user)
