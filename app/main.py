import html
import csv
import io
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.database import (
    count_users_by_role,
    create_sample,
    create_scan_job,
    create_user,
    delete_scan,
    delete_user,
    get_scan,
    get_queue_metrics,
    get_scan_counts,
    get_user_by_id,
    get_user_by_username,
    init_db,
    list_active_scans,
    list_engine_result_metrics,
    list_engine_results,
    list_recent_scans,
    list_users,
    retry_scan_job as retry_scan_job_record,
    update_scan_assessment,
    update_user,
)
from app.models import EngineInstanceRecord, EngineResultRecord, ScanRecord, UserRecord
from app.services.cleanup import delete_sample_file
from app.services.auth import (
    ROLE_ADMIN,
    SESSION_TTL_SECONDS,
    SESSION_COOKIE,
    current_user,
    dev_login_hint,
    hash_password,
    login,
    logout,
    require_admin,
    require_user,
    revoke_user_sessions,
    session_cookie_secure,
    seed_default_users,
    verify_password,
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
    microsoft_defender_form_values,
    runtime_config,
    seed_default_engines,
    toggle_engine,
    update_engine_config,
    yara_form_values,
    remove_engine,
)
from app.services.ingest import store_upload
from app.services.scoring import calculate_risk
from app.services.worker_runtime import get_worker_status
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


def nav_icon(icon_key: str) -> str:
    icons = {
        "dashboard": """
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="3" y="3" width="6" height="6" rx="1.4"></rect>
          <rect x="11" y="3" width="6" height="9" rx="1.4"></rect>
          <rect x="3" y="11" width="6" height="6" rx="1.4"></rect>
          <rect x="11" y="14" width="6" height="3" rx="1.4"></rect>
        </svg>
        """,
        "new_scan": """
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="8.5" cy="8.5" r="4.5"></circle>
          <path d="M12 12l4.5 4.5"></path>
        </svg>
        """,
        "account": """
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="10" cy="6.5" r="3"></circle>
          <path d="M4 16c1.2-2.7 3.2-4 6-4s4.8 1.3 6 4"></path>
        </svg>
        """,
        "logout": """
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M8 4H5.5A1.5 1.5 0 0 0 4 5.5v9A1.5 1.5 0 0 0 5.5 16H8"></path>
          <path d="M12 6l4 4-4 4"></path>
          <path d="M7 10h9"></path>
        </svg>
        """,
        "engines": """
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="6" cy="10" r="2.2"></circle>
          <circle cx="14" cy="6" r="2.2"></circle>
          <circle cx="14" cy="14" r="2.2"></circle>
          <path d="M7.9 8.9 12.1 7.1"></path>
          <path d="M7.9 11.1 12.1 12.9"></path>
        </svg>
        """,
        "system": """
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M3 13.5h3l2-7 4 9 2-6h3"></path>
          <path d="M3 4.5h14"></path>
          <path d="M3 17h14"></path>
        </svg>
        """,
        "users": """
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="7" cy="7" r="2.5"></circle>
          <path d="M2.8 15c.9-2.1 2.4-3.2 4.2-3.2S10.3 12.9 11.2 15"></path>
          <circle cx="14.5" cy="8" r="1.9"></circle>
          <path d="M12.7 14.2c.5-1.4 1.5-2.2 3-2.2 1 0 1.8.4 2.5 1.2"></path>
        </svg>
        """,
    }
    return icons.get(icon_key, "")


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
        ("account", "/account", "Account"),
    ]
    if user.role == ROLE_ADMIN:
        nav_items.append(("engines", "/engines", "Engines"))
        nav_items.append(("system", "/system", "System"))
        nav_items.append(("users", "/users", "Users"))
    nav_html = "\n".join(
        f'<a class="nav-link {"is-active" if key == active else ""}" href="{href}">'
        f'<span class="nav-icon">{nav_icon(key)}</span>'
        f'<span class="nav-label">{label}</span></a>'
        for key, href, label in nav_items
    )
    logout_nav_html = f"""
    <form class="nav-form" action="/logout" method="post">
      <button class="nav-link nav-button" type="submit">
        <span class="nav-icon">{nav_icon("logout")}</span>
        <span class="nav-label">Logout</span>
      </button>
    </form>
    """
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
            <div class="nav-utility">
              {logout_nav_html}
            </div>
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
          const evidenceButtons = document.querySelectorAll("[data-evidence-button]");
          const evidenceDrawer = document.querySelector("[data-evidence-drawer]");
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

          if (evidenceButtons.length && evidenceDrawer) {{
            const drawerTitle = evidenceDrawer.querySelector("[data-evidence-drawer-title]");
            const drawerBody = evidenceDrawer.querySelector("[data-evidence-drawer-body]");
            const drawerClose = evidenceDrawer.querySelector("[data-evidence-drawer-close]");

            evidenceButtons.forEach((button) => {{
              button.addEventListener("click", () => {{
                const templateId = button.getAttribute("data-evidence-template");
                const template = templateId ? document.getElementById(templateId) : null;
                if (!template || !drawerBody || !drawerTitle) {{
                  return;
                }}

                evidenceButtons.forEach((otherButton) => {{
                  otherButton.classList.toggle("is-active", otherButton === button);
                }});

                drawerTitle.textContent = button.getAttribute("data-evidence-title") || "Details";
                const templateText = template.content
                  ? template.content.textContent
                  : template.textContent;
                const detailsText = templateText && templateText.trim() ? templateText.trim() : "";
                drawerBody.textContent = detailsText && detailsText !== "{{}}"
                  ? detailsText
                  : "No structured details are available for this item.";
                evidenceDrawer.hidden = false;
              }});
            }});

            if (drawerClose) {{
              drawerClose.addEventListener("click", () => {{
                evidenceButtons.forEach((button) => button.classList.remove("is-active"));
                evidenceDrawer.hidden = true;
              }});
            }}
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


def legacy_render_login_page(next_url: str = "/", error: str = "") -> str:
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


def page_notice(title: str, message: str, tone: str = "success") -> str:
    if not message:
        return ""
    tone_class = {
        "success": "success-notice",
        "warning": "warning-notice",
        "danger": "danger-notice",
    }.get(tone, "success-notice")
    return (
        f'<section class="notice {tone_class}"><div>'
        f"<strong>{html.escape(title)}</strong>"
        f"<span>{html.escape(message)}</span>"
        f"</div></section>"
    )


def render_login_page(next_url: str = "/", error: str = "", message: str = "") -> str:
    error_html = (
        f'<div class="auth-error">{html.escape(error)}</div>'
        if error
        else ""
    )
    message_html = (
        f'<div class="auth-message">{html.escape(message)}</div>'
        if message
        else ""
    )
    login_hint = dev_login_hint()
    login_hint_html = (
        f"""
        <div class="auth-hint">
          <strong>Default dev users</strong>
          <span>{html.escape(login_hint)}</span>
        </div>
        """
        if login_hint
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
        {message_html}
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
        {login_hint_html}
      </section>
    </main>
    """
    return auth_shell("Sign in", body)


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


def worker_status_pill(worker_status: dict[str, object]) -> str:
    state = str(worker_status.get("state") or "offline")
    if not bool(worker_status.get("online")):
        return '<span class="pill danger">Worker offline</span>'
    if state == "running":
        return '<span class="pill warning">Worker busy</span>'
    if state == "starting":
        return '<span class="pill warning">Worker starting</span>'
    if state == "error":
        return '<span class="pill danger">Worker error</span>'
    return '<span class="pill success">Worker online</span>'


def worker_status_detail(worker_status: dict[str, object]) -> str:
    if not bool(worker_status.get("online")):
        last_seen_at = worker_status.get("last_seen_at")
        if last_seen_at:
            return f"Last heartbeat {last_seen_at}"
        return "No worker heartbeat recorded yet."

    active_scan_id = worker_status.get("active_scan_id")
    if active_scan_id:
        return f"Processing scan #{active_scan_id}"
    last_seen_at = worker_status.get("last_seen_at")
    if last_seen_at:
        return f"Heartbeat refreshed at {last_seen_at}"
    return "Heartbeat is healthy."


def render_worker_status_panel(worker_status: dict[str, object]) -> str:
    active_scan_id = worker_status.get("active_scan_id")
    worker_count = f'{int(worker_status.get("online_count", 0) or 0)} online'
    queue_state = f"Processing scan #{active_scan_id}" if active_scan_id else "Idle"
    last_seen_at = str(worker_status.get("last_seen_at") or "-")
    hostname = str(worker_status.get("hostname") or "-")
    return f"""
      <div class="panel status-panel">
        <div class="panel-header compact">
          <div>
            <h2>System status</h2>
            <p>Worker readiness and queue state.</p>
          </div>
          {worker_status_pill(worker_status)}
        </div>
        <div class="status-summary-grid">
          <div>
            <span>Workers</span>
            <strong>{html.escape(worker_count)}</strong>
          </div>
          <div>
            <span>Queue</span>
            <strong>{html.escape(queue_state)}</strong>
          </div>
          <div>
            <span>Last heartbeat</span>
            <strong>{html.escape(last_seen_at)}</strong>
          </div>
          <div>
            <span>Node</span>
            <strong>{html.escape(hostname)}</strong>
          </div>
        </div>
      </div>
    """


def format_duration_ms(duration_ms: int | float | None) -> str:
    if duration_ms is None:
        return "-"
    value = int(duration_ms)
    if value < 1000:
        return f"{value} ms"
    seconds = value / 1000
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    remaining_seconds = int(seconds % 60)
    return f"{minutes}m {remaining_seconds}s"


def engine_metric_tone(engine: EngineInstanceRecord, supported_engine_keys: set[str]) -> str:
    if not engine.enabled:
        return "neutral"
    if engine.adapter_key not in supported_engine_keys:
        return "danger"
    return "success"


def engine_metric_status(engine: EngineInstanceRecord, supported_engine_keys: set[str]) -> str:
    if not engine.enabled:
        return "Disabled"
    if engine.adapter_key not in supported_engine_keys:
        return "No online worker"
    return "Worker covered"


def render_system_worker_rows(worker_status: dict[str, object]) -> str:
    workers = worker_status.get("workers")
    if not isinstance(workers, list) or not workers:
        return """
        <tr>
          <td class="empty-cell" colspan="6">No worker heartbeat has been recorded yet.</td>
        </tr>
        """

    rows = []
    for worker in workers:
        if not isinstance(worker, dict):
            continue
        online = bool(worker.get("online"))
        state = str(worker.get("state") or "offline")
        engine_keys = ", ".join(str(item) for item in worker.get("engine_keys", [])) or "-"
        active_scan_id = worker.get("active_scan_id")
        active_scan = f"#{active_scan_id}" if active_scan_id else "-"
        rows.append(
            f"""
            <tr>
              <td>{status_pill(state if online else "offline")}</td>
              <td>
                <strong>{html.escape(str(worker.get("hostname") or "-"))}</strong>
                <small>PID {html.escape(str(worker.get("pid") or "-"))}</small>
              </td>
              <td>{html.escape(engine_keys)}</td>
              <td>{html.escape(active_scan)}</td>
              <td>{html.escape(str(worker.get("last_seen_at") or "-"))}</td>
              <td>{html.escape(str(worker.get("age_seconds") if worker.get("age_seconds") is not None else "-"))}s</td>
            </tr>
            """
        )
    return "\n".join(rows)


def render_system_engine_rows(
    engines: list[EngineInstanceRecord],
    metrics: list[dict[str, object]],
    worker_status: dict[str, object],
) -> str:
    metrics_by_engine = {str(metric["engine_name"]): metric for metric in metrics}
    supported_engine_keys = set(str(item) for item in worker_status.get("engine_keys", []))
    if not engines:
        return '<tr><td class="empty-cell" colspan="9">No engines are configured.</td></tr>'

    rows = []
    for engine in engines:
        metric = metrics_by_engine.get(engine.display_name, {})
        tone = engine_metric_tone(engine, supported_engine_keys)
        runtime = runtime_config(engine)
        timeout = runtime.get("timeout_seconds")
        rows.append(
            f"""
            <tr>
              <td>
                <div class="engine-mini">
                  {render_engine_logo(adapter_definition(engine.adapter_key).short_label, engine.adapter_key)}
                  <div>
                    <strong>{html.escape(engine.display_name)}</strong>
                    <small>{html.escape(adapter_definition(engine.adapter_key).integration_method)}</small>
                  </div>
                </div>
              </td>
              <td><span class="pill {tone}">{html.escape(engine_metric_status(engine, supported_engine_keys))}</span></td>
              <td>{html.escape(str(metric.get("total_results", 0)))}</td>
              <td>{html.escape(str(metric.get("completed_results", 0)))}</td>
              <td>{html.escape(str(metric.get("failed_results", 0)))}</td>
              <td>{html.escape(str(metric.get("skipped_results", 0)))}</td>
              <td>{format_duration_ms(int(metric.get("avg_duration_ms", 0) or 0))}</td>
              <td>{format_duration_ms(int(metric.get("max_duration_ms", 0) or 0))}</td>
              <td>
                {html.escape(str(metric.get("last_result_at") or "-"))}
                <small>Timeout {html.escape(str(timeout if timeout is not None else "-"))}s</small>
              </td>
            </tr>
            """
        )
    return "\n".join(rows)


def render_system_queue_rows(active_scans: list[ScanRecord]) -> str:
    if not active_scans:
        return '<tr><td class="empty-cell" colspan="6">No queued or running scans.</td></tr>'

    rows = []
    for scan in active_scans:
        marker_label, marker_value = scan_runtime_marker(scan)
        rows.append(
            f"""
            <tr>
              <td><a class="table-link" href="/scans/{scan.id}"><strong>#{scan.id}</strong><small>{html.escape(scan.original_filename)}</small></a></td>
              <td>{status_pill(scan.status)}</td>
              <td>{html.escape(scan.case_name)}</td>
              <td>{html.escape(format_bytes(scan.size_bytes))}</td>
              <td>{html.escape(marker_label)}</td>
              <td>{html.escape(marker_value)}</td>
            </tr>
            """
        )
    return "\n".join(rows)


def render_system_page(user: UserRecord) -> str:
    worker_status = get_worker_status()
    queue_metrics = get_queue_metrics()
    engine_metrics = list_engine_result_metrics()
    engines = configured_engines()
    active_scans = list_active_scans(limit=50)
    supported_engine_count = len(set(str(item) for item in worker_status.get("engine_keys", [])))

    body = f"""
    <section class="metric-grid">
      {metric_card("Workers", str(worker_status.get("online_count", 0)), "Online worker processes")}
      {metric_card("Queue", str(queue_metrics["queued"]), "Waiting scan jobs", "tone-blue")}
      {metric_card("Running", str(queue_metrics["running"]), "Currently active jobs", "tone-green")}
      {metric_card("Failures", str(queue_metrics["failed"]), "Failed scan jobs", "tone-red")}
    </section>

    <section class="system-layout">
      <div class="panel">
        <div class="panel-header compact">
          <div>
            <h2>Worker runtime</h2>
            <p>Heartbeat, node identity, supported engines, and active work.</p>
          </div>
          {worker_status_pill(worker_status)}
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Node</th>
                <th>Engines</th>
                <th>Active scan</th>
                <th>Last heartbeat</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {render_system_worker_rows(worker_status)}
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header compact">
          <div>
            <h2>Queue health</h2>
            <p>{queue_metrics["active"]} active of {queue_metrics["total"]} total scan jobs.</p>
          </div>
          <span class="pill neutral">{supported_engine_count} worker engine keys</span>
        </div>
        <div class="status-summary-grid">
          <div><span>Completed</span><strong>{queue_metrics["completed"]}</strong></div>
          <div><span>Failed</span><strong>{queue_metrics["failed"]}</strong></div>
          <div><span>Queued</span><strong>{queue_metrics["queued"]}</strong></div>
          <div><span>Running</span><strong>{queue_metrics["running"]}</strong></div>
        </div>
      </div>

      <div class="panel system-wide">
        <div class="panel-header compact">
          <div>
            <h2>Engine metrics</h2>
            <p>Coverage, throughput, failures, skips, and latency from recorded results.</p>
          </div>
          <span class="pill neutral">{len(engines)} configured</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Engine</th>
                <th>Worker coverage</th>
                <th>Total</th>
                <th>Completed</th>
                <th>Failed</th>
                <th>Skipped</th>
                <th>Avg latency</th>
                <th>Max latency</th>
                <th>Last result</th>
              </tr>
            </thead>
            <tbody>
              {render_system_engine_rows(engines, engine_metrics, worker_status)}
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel system-wide">
        <div class="panel-header compact">
          <div>
            <h2>Active queue</h2>
            <p>Queued and running scans in processing order.</p>
          </div>
          <span class="pill neutral">{len(active_scans)} shown</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Scan</th>
                <th>Status</th>
                <th>Case</th>
                <th>Size</th>
                <th>Marker</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {render_system_queue_rows(active_scans)}
            </tbody>
          </table>
        </div>
      </div>
    </section>
    """
    return page_shell("System", "system", body, user, refresh_seconds=10)


def scan_runtime_marker(scan: ScanRecord) -> tuple[str, str]:
    if scan.status == "failed" and scan.failed_at:
        return "Failed at", scan.failed_at
    if scan.completed_at:
        return "Completed", scan.completed_at
    if scan.started_at:
        return "Started", scan.started_at
    return "Created", scan.created_at


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

    if key == "microsoft_defender":
        return """
        <span class="engine-logo engine-logo-defender" aria-hidden="true">
          <svg viewBox="0 0 44 44" role="img" focusable="false">
            <path d="M22 5.8c4.5 2.9 8.9 4.5 13.3 4.8v10.1c0 8.5-4.7 14.7-13.3 17.5-8.6-2.8-13.3-9-13.3-17.5V10.6c4.4-.3 8.8-1.9 13.3-4.8Z" fill="#2563eb"></path>
            <path d="M22 10.1v23.3c-6-2.4-9.3-6.8-9.3-12.5v-6.3c3.2-.7 6.2-1.8 9.3-4.5Z" fill="#eaf3ff"></path>
            <path d="M22 10.1c3.1 2.7 6.1 3.8 9.3 4.5v6.3c0 5.7-3.3 10.1-9.3 12.5V10.1Z" fill="#7dc4ff"></path>
            <path d="M22 12.3v18.8" stroke="#1d4ed8" stroke-width="1.2" stroke-linecap="round"></path>
            <path d="M14.5 20.7h15" stroke="#1d4ed8" stroke-width="1.2" stroke-linecap="round"></path>
          </svg>
        </span>
        """

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
                <small>{html.escape(definition.integration_method)} · {html.escape(definition.description)}</small>
                <small>{html.escape(definition.vendor)} · {html.escape(definition.support_state.title())}</small>
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
    if str(health["status"]) == "degraded":
        return "warning"
    if bool(health["ok"]):
        return "success"
    if adapter_key == "clamav" and health["status"] in {"unreachable", "unexpected"}:
        return "danger"
    if adapter_key == "yara" and health["status"] in {"not configured", "no rules", "unavailable"}:
        return "danger"
    if adapter_key == "microsoft_defender" and health["status"] in {
        "permission denied",
        "unexpected",
        "unavailable",
    }:
        return "danger"
    return "neutral"


def render_engine_actions(instance: EngineInstanceRecord, show_test: bool) -> str:
    test_button = ""
    if show_test:
        test_button = f"""
        <form action="/engines/{html.escape(instance.adapter_key)}/test" method="post">
          <button class="secondary-action engine-action-primary" type="submit">Test connection</button>
        </form>
        """
    toggle_button = f"""
    <form action="/engines/{html.escape(instance.adapter_key)}/toggle" method="post">
      <button class="secondary-action engine-action-compact" type="submit">{"Disable" if instance.enabled else "Enable"}</button>
    </form>
    """
    remove_button = f"""
    <form action="/engines/{html.escape(instance.adapter_key)}/delete" method="post">
      <button class="danger-action engine-action-compact" type="submit">Remove</button>
    </form>
    """
    return f"""
    <div class="engine-toolbar">
      {test_button}
      <div class="engine-toolbar-secondary">
        {toggle_button}
        {remove_button}
      </div>
    </div>
    """


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
        <small class="engine-definition-meta">{html.escape(definition.vendor)} · {html.escape(definition.integration_method)} · {html.escape(definition.support_state.title())}</small>
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

    if instance.adapter_key == "microsoft_defender":
        form_values = microsoft_defender_form_values(instance)
        fields = [
            ("Adapter", "local PowerShell / CLI"),
            ("Execution mode", str(runtime["execution_mode"])),
            ("Default scan", str(runtime["default_scan_type"])),
            ("Timeout", f'{runtime["timeout_seconds"]}s'),
            ("Support state", definition.support_state.title()),
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
        update_checked = " checked" if str(form_values["update_before_scan"]).lower() in {"1", "true", "yes", "on"} else ""
        realtime_checked = " checked" if str(form_values["require_real_time_enabled"]).lower() in {"1", "true", "yes", "on"} else ""
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
              <form class="settings-form embedded" action="/engines/microsoft_defender/config" method="post">
                <div class="settings-section">
                  <div>
                    <h3>Runtime settings</h3>
                    <p>Research-phase local Windows integration. Health checks are supported; scan semantics still need lab validation.</p>
                  </div>
                  <div class="settings-grid">
                    <label>
                      execution mode
                      <select name="microsoft_defender_execution_mode">
                        <option value="powershell" {"selected" if form_values["execution_mode"] == "powershell" else ""}>powershell</option>
                        <option value="mpcmdrun" {"selected" if form_values["execution_mode"] == "mpcmdrun" else ""}>mpcmdrun</option>
                      </select>
                    </label>
                    <label>
                      PowerShell path
                      <input type="text" name="microsoft_defender_powershell_path" value="{html.escape(form_values["powershell_path"])}" placeholder="powershell.exe">
                    </label>
                    <label>
                      MpCmdRun path
                      <input type="text" name="microsoft_defender_mpcmdrun_path" value="{html.escape(form_values["mpcmdrun_path"])}" placeholder="auto">
                    </label>
                    <label>
                      default scan type
                      <select name="microsoft_defender_default_scan_type">
                        <option value="custom" {"selected" if form_values["default_scan_type"] == "custom" else ""}>custom</option>
                        <option value="quick" {"selected" if form_values["default_scan_type"] == "quick" else ""}>quick</option>
                        <option value="full" {"selected" if form_values["default_scan_type"] == "full" else ""}>full</option>
                      </select>
                    </label>
                    <label>
                      timeout seconds
                      <input type="number" name="microsoft_defender_timeout_seconds" value="{html.escape(form_values["timeout_seconds"])}" min="30" max="86400">
                    </label>
                    <label class="checkbox-field">
                      <input type="checkbox" name="microsoft_defender_update_before_scan" value="true"{update_checked}>
                      update signatures before scan
                    </label>
                    <label class="checkbox-field">
                      <input type="checkbox" name="microsoft_defender_require_real_time_enabled" value="true"{realtime_checked}>
                      require real-time protection
                    </label>
                  </div>
                </div>
                <div class="settings-actions">
                  <button class="primary-action" type="submit">Save Defender settings</button>
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
        is_current_user = user.id == current_admin.id
        admin_badge = '<span class="pill neutral">Current session</span>' if is_current_user else ""
        management_html = (
            f"""
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
            """
            if not is_current_user
            else """
            <div class="user-inline-readonly">
              <span class="pill neutral">Managed on account page</span>
              <small>Use Account to change your own password or review your session.</small>
            </div>
            """
        )
        delete_action = (
            ""
            if is_current_user
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
                {admin_badge}
              </div>
              {management_html}
              <div class="user-actions">
                {delete_action}
              </div>
            </div>
            """
        )
    return "\n".join(rows)


def render_users_page(user: UserRecord, message: str = "", error: str = "") -> str:
    notice_html = (
        page_notice("Users updated", message, "success")
        + page_notice("Action blocked", error, "danger")
    )
    users = list_users()
    body = f"""
    {notice_html}
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
          <span class="pill neutral">{len(users)} accounts</span>
        </div>
        <div class="user-table">
          {render_user_rows(user)}
        </div>
      </section>
    </section>
    """
    return page_shell("Users", "users", body, user)


def render_account_page(user: UserRecord, message: str = "", error: str = "") -> str:
    ttl_hours = max(1, SESSION_TTL_SECONDS // 3600)
    notice_html = (
        page_notice("Account updated", message, "success")
        + page_notice("Action blocked", error, "danger")
    )
    body = f"""
    {notice_html}
    <section class="users-layout">
      <section class="panel">
        <div class="panel-header compact">
          <h2>Account</h2>
          <span class="pill neutral">{html.escape(user.role.title())}</span>
        </div>
        <div class="config-grid">
          <div><span>Username</span><strong>{html.escape(user.username)}</strong></div>
          <div><span>Role</span><strong>{html.escape(user.role.title())}</strong></div>
          <div><span>Created</span><strong>{html.escape(user.created_at)}</strong></div>
          <div><span>Updated</span><strong>{html.escape(user.updated_at)}</strong></div>
          <div><span>Session policy</span><strong>{ttl_hours}h login window</strong></div>
        </div>
      </section>

      <form class="panel user-create-panel" action="/account/password" method="post">
        <div class="panel-header">
          <div>
            <h2>Change password</h2>
            <p>Updating your password signs out active sessions for this user.</p>
          </div>
          <span class="pill neutral">Self service</span>
        </div>
        <div class="settings-form embedded">
          <div class="settings-grid three">
            <label>
              Current password
              <input type="password" name="current_password" autocomplete="current-password" required>
            </label>
            <label>
              New password
              <input type="password" name="new_password" autocomplete="new-password" required>
            </label>
            <label>
              Confirm password
              <input type="password" name="confirm_password" autocomplete="new-password" required>
            </label>
          </div>
          <div class="settings-actions">
            <button class="primary-action" type="submit">Update password</button>
          </div>
        </div>
      </form>
    </section>
    """
    return page_shell("Account", "account", body, user)


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
        "offline": "danger",
        "error": "danger",
        "idle": "success",
        "starting": "warning",
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
        return "Required engines are being executed by the worker. Missing engines may be marked skipped after the orchestration wait window."
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


def dashboard_verdict_key(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    if scan.status in {"queued", "running"}:
        return "pending"

    detected, total = detection_summary(results)
    if total == 0:
        return "metadata_only"
    if detected > 0:
        return "malicious"
    return "undetected"


def scan_matches_recent_filters(
    scan: ScanRecord,
    results: list[EngineResultRecord],
    query: str,
    status_filter: str,
    verdict_filter: str,
) -> bool:
    normalized_query = query.strip().lower()
    if normalized_query:
        search_blob = " ".join(
            [
                scan.original_filename,
                scan.case_name,
                scan.sha256,
                scan.sha1,
                scan.md5,
                scan.priority,
                scan.note,
            ]
        ).lower()
        if normalized_query not in search_blob:
            return False

    if status_filter and status_filter != "all":
        if status_filter == "active":
            if scan.status not in {"queued", "running"}:
                return False
        elif scan.status != status_filter:
            return False

    if verdict_filter and verdict_filter != "all":
        if dashboard_verdict_key(scan, results) != verdict_filter:
            return False

    return True


def filter_recent_scans(
    scans: list[ScanRecord],
    query: str,
    status_filter: str,
    verdict_filter: str,
) -> tuple[list[ScanRecord], dict[int, list[EngineResultRecord]]]:
    results_by_scan: dict[int, list[EngineResultRecord]] = {}
    filtered_scans = []
    for scan in scans:
        engine_results = list_engine_results(scan.id)
        results_by_scan[scan.id] = engine_results
        if scan_matches_recent_filters(scan, engine_results, query, status_filter, verdict_filter):
            filtered_scans.append(scan)
    return filtered_scans, results_by_scan


def select_option(value: str, label: str, selected_value: str) -> str:
    selected = " selected" if value == selected_value else ""
    return f'<option value="{html.escape(value)}"{selected}>{html.escape(label)}</option>'


def render_recent_scan_filters(query: str, status_filter: str, verdict_filter: str) -> str:
    return f"""
    <form class="scan-filter-bar" action="/" method="get">
      <label class="scan-search-field">
        <span>Search</span>
        <input type="search" name="q" value="{html.escape(query)}" placeholder="File, case, hash">
      </label>
      <label>
        <span>Status</span>
        <select name="status">
          {select_option("all", "All statuses", status_filter)}
          {select_option("active", "Active", status_filter)}
          {select_option("queued", "Queued", status_filter)}
          {select_option("running", "Running", status_filter)}
          {select_option("completed", "Completed", status_filter)}
          {select_option("partial", "Partial", status_filter)}
          {select_option("failed", "Failed", status_filter)}
        </select>
      </label>
      <label>
        <span>Verdict</span>
        <select name="verdict">
          {select_option("all", "All verdicts", verdict_filter)}
          {select_option("pending", "Pending", verdict_filter)}
          {select_option("malicious", "Malicious", verdict_filter)}
          {select_option("undetected", "Undetected", verdict_filter)}
          {select_option("metadata_only", "Metadata only", verdict_filter)}
        </select>
      </label>
      <div class="scan-filter-actions">
        <button class="secondary-action compact-action" type="submit">Apply</button>
        <a class="secondary-action compact-action" href="/">Reset</a>
      </div>
    </form>
    """


def render_recent_scan_rows(
    scans: list[ScanRecord],
    can_select: bool,
    results_by_scan: dict[int, list[EngineResultRecord]] | None = None,
    empty_message: str = "No scans submitted yet.",
) -> str:
    if not scans:
        colspan = 7 if can_select else 6
        return f'<tr><td class="empty-cell" colspan="{colspan}">{html.escape(empty_message)}</td></tr>'

    rows = []
    cached_results = results_by_scan or {}
    for scan in scans:
        engine_results = cached_results.get(scan.id)
        if engine_results is None:
            engine_results = list_engine_results(scan.id)
        detection_tone = detection_summary_tone_for_scan(scan, engine_results)
        file_tone_class = "danger" if detection_tone == "danger" else ""
        pending_icon = (
            '<span class="scan-alert-icon" aria-hidden="true" title="Scan not completed">!</span>'
            if scan.status != "completed"
            else ""
        )
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
                <div class="table-link {file_tone_class}">
                  <strong><span class="scan-file-label">{pending_icon}<span>{html.escape(scan.original_filename)}</span></span></strong>
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
                <span class="detection-count {detection_tone}">{html.escape(detection_summary_text_for_scan(scan, engine_results))}</span>
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


def parse_json_value(value: str, fallback: object) -> object:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return fallback
    return parsed


def report_filename_base(scan: ScanRecord) -> str:
    stem = Path(scan.original_filename).stem or f"scan-{scan.id}"
    clean = "".join(char if char.isalnum() else "-" for char in stem).strip("-")
    return clean or f"scan-{scan.id}"


def result_findings(result: EngineResultRecord) -> list[dict[str, object]]:
    parsed = parse_json_value(result.findings_json, [])
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def render_value_list(values: object, empty_label: str = "-") -> str:
    if isinstance(values, list):
        clean_values = [str(value) for value in values if str(value)]
    elif values:
        clean_values = [str(values)]
    else:
        clean_values = []

    if not clean_values:
        return html.escape(empty_label)

    return ", ".join(html.escape(value) for value in clean_values[:6])


def clean_evidence_value(value: object) -> object:
    raw_keys = {"raw_output", "raw_response"}
    if isinstance(value, dict):
        return {
            key: clean_evidence_value(item)
            for key, item in value.items()
            if key not in raw_keys and item not in ({}, [], None, "")
        }
    if isinstance(value, list):
        return [
            clean_evidence_value(item)
            for item in value
            if item not in ({}, [], None, "")
        ]
    return value


def finding_detail_payload(finding: dict[str, object]) -> dict[str, object]:
    evidence = finding.get("evidence")
    clean_evidence = {}
    if isinstance(evidence, dict):
        clean_evidence = {
            key: clean_evidence_value(value)
            for key, value in evidence.items()
            if key not in {"raw_output", "raw_response"} and value not in ({}, [], None, "")
        }

    payload = {
        "finding": {
            "source": finding.get("source"),
            "title": finding.get("title"),
            "type": finding.get("type"),
            "category": finding.get("category"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "action": finding.get("action"),
            "tags": finding.get("tags") or [],
            "target": finding.get("target"),
        },
        "evidence": clean_evidence,
        "enrichment": finding.get("enrichment") or [],
    }
    return {
        key: value
        for key, value in payload.items()
        if value not in ({}, [], None, "")
    }


def fallback_finding_detail_payload(
    finding: dict[str, object],
    result: EngineResultRecord,
) -> dict[str, object]:
    payload = finding_detail_payload(finding)
    if payload:
        return payload

    fallback: dict[str, object] = {}
    if result.signature:
        fallback["evidence"] = {
            "signature": result.signature,
            "source_engine": result.engine_name,
        }
    return fallback


def render_evidence_button(
    label: str,
    title: str,
    template_id: str,
) -> str:
    return f"""
    <button class="evidence-button" type="button" data-evidence-button data-evidence-template="{html.escape(template_id)}" data-evidence-title="{html.escape(title)}">
      <span aria-hidden="true">&gt;</span>
      {html.escape(label)}
    </button>
    """


def matched_evidence_for_finding(
    finding: dict[str, object],
    result: EngineResultRecord,
) -> object:
    values = []
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        objects = evidence.get("objects")
        if isinstance(objects, list):
            for item in objects:
                if isinstance(item, dict) and item.get("value"):
                    values.append(str(item["value"]))

    if values:
        return values
    if finding.get("title"):
        return str(finding["title"])
    if result.signature:
        return result.signature
    return "-"


def finding_classification_html(finding: dict[str, object]) -> str:
    category = str(finding.get("category") or finding.get("type") or "")
    tags = finding.get("tags")
    clean_tags = [str(tag) for tag in tags if str(tag)] if isinstance(tags, list) else []

    chips = []
    if category:
        chips.append(category.replace("_", " ").title())
    chips.extend(tag for tag in clean_tags if tag.lower() != category.lower())

    if not chips:
        return "-"

    return '<div class="finding-tags">' + "".join(
        f'<span class="finding-tag">{html.escape(chip)}</span>'
        for chip in chips[:6]
    ) + "</div>"


def finding_classification_values(finding: dict[str, object]) -> list[str]:
    category = str(finding.get("category") or finding.get("type") or "")
    tags = finding.get("tags")
    clean_tags = [str(tag) for tag in tags if str(tag)] if isinstance(tags, list) else []
    values = []
    if category:
        values.append(category.replace("_", " ").title())
    values.extend(tag for tag in clean_tags if tag.lower() != category.lower())
    return unique_values(values, limit=6)


def unique_values(values: list[str], limit: int = 4) -> list[str]:
    seen = set()
    unique = []
    for value in values:
        normalized = value.strip()
        if not normalized or normalized.lower() in seen:
            continue
        seen.add(normalized.lower())
        unique.append(normalized)
        if len(unique) == limit:
            break
    return unique


def render_detection_summary_bar(
    finding_count: int,
    engine_names: list[str],
    severities: list[str],
    finding_titles: list[str],
) -> str:
    severity_rank = {
        "info": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }
    top_severity = max(
        severities or ["info"],
        key=lambda value: severity_rank.get(value.lower(), 0),
    )
    summary_tone = "danger" if finding_count else "neutral"
    finding_label = "finding" if finding_count == 1 else "findings"
    engine_label = ", ".join(unique_values(engine_names)) if engine_names else "No engines"
    title_label = ", ".join(unique_values(finding_titles)) if finding_titles else "No matched evidence"

    return f"""
    <div class="evidence-summary {summary_tone}">
      <div>
        <span>Findings</span>
        <strong>{finding_count} {finding_label}</strong>
      </div>
      <div>
        <span>Max severity</span>
        <strong>{html.escape(top_severity.title())}</strong>
      </div>
      <div>
        <span>Detected by</span>
        <strong>{html.escape(engine_label)}</strong>
      </div>
      <div>
        <span>Top evidence</span>
        <strong>{html.escape(title_label)}</strong>
      </div>
    </div>
    """


def render_detection_evidence(results: list[EngineResultRecord]) -> str:
    evidence_rows = []
    detail_templates = []
    detail_index = 0
    engine_names = []
    severities = []
    finding_titles = []

    for result in results:
        for finding in result_findings(result):
            detail_index += 1
            template_id = f"evidence-detail-{detail_index}"
            title = str(finding.get("title") or result.signature or "Detection")
            finding_type = str(finding.get("type") or "finding").replace("_", " ").title()
            severity = str(finding.get("severity") or result.severity)
            confidence = str(finding.get("confidence") or result.confidence)
            source = str(finding.get("source") or result.engine_name)
            action = str(finding.get("action") or "detected")
            category = str(finding.get("category") or finding_type)
            target = finding.get("target")
            detail_payload = fallback_finding_detail_payload(finding, result)
            evidence_text = json.dumps(
                detail_payload,
                indent=2,
                sort_keys=True,
            )
            evidence_button = ""
            if detail_payload:
                detail_templates.append(
                    f'<template id="{template_id}">{html.escape(evidence_text)}</template>'
                )
                evidence_button = render_evidence_button(
                    "Evidence",
                    f"{source} evidence",
                    template_id,
                )
            else:
                detail_index -= 1
                template_id = ""
            engine_names.append(source)
            severities.append(severity)
            finding_titles.append(title)
            finding_context = " / ".join(
                value
                for value in [
                    category.replace("_", " ").title(),
                    f"{confidence}% confidence",
                    action.replace("_", " ").title(),
                    str(target) if target else "",
                ]
                if value
            )
            evidence_rows.append(
                f"""
                <div class="evidence-row">
                  <div>
                    <strong>{html.escape(source)}</strong>
                    <small>{html.escape(result.status.title())}</small>
                  </div>
                  <span>{severity_pill(severity)}</span>
                  <span>{html.escape(finding_type)}</span>
                  <div>
                    <strong>{html.escape(title)}</strong>
                    <small>{html.escape(finding_context)}</small>
                  </div>
                  <span>{render_value_list(matched_evidence_for_finding(finding, result))}</span>
                  <div class="evidence-classification">{finding_classification_html(finding)}</div>
                  {evidence_button or "<span>-</span>"}
                </div>
                """
            )

    summary_html = render_detection_summary_bar(
        len(evidence_rows),
        engine_names,
        severities,
        finding_titles,
    )
    evidence_html = "\n".join(evidence_rows) or """
      <div class="evidence-empty">
        <strong>No normalized evidence rows yet</strong>
        <span>Detected engine findings will populate this comparison table.</span>
      </div>
    """

    return f"""
    <section class="panel wide">
      <div class="panel-header compact">
        <h2>Detection evidence</h2>
        <span class="pill neutral">Offline-first</span>
      </div>
      <div class="evidence-layout">
        {summary_html}
        <div class="evidence-table">
          <div class="evidence-row evidence-header">
            <span>Engine</span>
            <span>Severity</span>
            <span>Finding</span>
            <span>Summary</span>
            <span>Matched evidence</span>
            <span>Classification</span>
            <span>Evidence</span>
          </div>
          {evidence_html}
        </div>
        <div class="evidence-drawer" data-evidence-drawer hidden>
          <div class="evidence-drawer-header">
            <strong data-evidence-drawer-title>Details</strong>
            <div class="evidence-drawer-actions">
              <span class="pill neutral">Structured JSON</span>
              <button class="evidence-drawer-close" type="button" data-evidence-drawer-close aria-label="Close evidence details">x</button>
            </div>
          </div>
          <pre data-evidence-drawer-body>No evidence selected.</pre>
        </div>
        {"".join(detail_templates)}
      </div>
    </section>
    """


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


def report_finding_rows(results: list[EngineResultRecord]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for result in results:
        for finding in result_findings(result):
            source = str(finding.get("source") or result.engine_name)
            title = str(finding.get("title") or result.signature or "Detection")
            finding_type = str(finding.get("type") or "finding").replace("_", " ").title()
            severity = str(finding.get("severity") or result.severity)
            confidence = int(finding.get("confidence") or result.confidence or 0)
            action = str(finding.get("action") or "detected").replace("_", " ").title()
            matched = matched_evidence_for_finding(finding, result)
            rows.append(
                {
                    "engine": source,
                    "status": result.status,
                    "title": title,
                    "finding": finding_type,
                    "severity": severity,
                    "confidence": confidence,
                    "action": action,
                    "matched_evidence": matched if isinstance(matched, list) else [str(matched)],
                    "classification": finding_classification_values(finding),
                    "evidence": fallback_finding_detail_payload(finding, result),
                }
            )
    return rows


def build_scan_report_payload(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
) -> dict[str, object]:
    assessment = calculate_risk(engine_results)
    verdict = scan.verdict if scan.risk_score is not None else assessment.verdict
    risk_score = scan.risk_score if scan.risk_score is not None else assessment.score
    findings = report_finding_rows(engine_results)
    coverage_ran, coverage_total, coverage_unavailable = required_engine_coverage(engine_results)

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan": {
            "id": scan.id,
            "filename": scan.original_filename,
            "case_name": scan.case_name,
            "priority": scan.priority,
            "status": scan.status,
            "verdict": verdict,
            "risk_score": risk_score,
            "created_at": scan.created_at,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "failed_at": scan.failed_at,
            "attempt_count": scan.attempt_count,
            "last_error": scan.last_error,
            "note": scan.note,
            "content_type": scan.content_type,
            "size_bytes": scan.size_bytes,
            "hashes": {
                "md5": scan.md5,
                "sha1": scan.sha1,
                "sha256": scan.sha256,
            },
        },
        "summary": {
            "detection": {
                "label": detection_summary_text_for_scan(scan, engine_results),
                "detail": detection_detail_text_for_scan(scan, engine_results),
                "detected_engines": detected_engine_names(engine_results),
            },
            "coverage": {
                "label": coverage_summary_text_for_scan(scan, engine_results),
                "detail": coverage_detail_text_for_scan(scan, engine_results),
                "ran": coverage_ran,
                "total": coverage_total,
                "unavailable": coverage_unavailable,
            },
            "assessment": {
                "score": risk_score,
                "verdict": verdict,
                "reasons": assessment.reasons,
            },
        },
        "findings": findings,
        "engine_results": [
            {
                "engine_name": result.engine_name,
                "engine_version": result.engine_version,
                "signature_version": result.signature_version,
                "status": result.status,
                "detected": result.detected,
                "signature": result.signature,
                "severity": result.severity,
                "confidence": result.confidence,
                "duration_ms": result.duration_ms,
                "error_message": result.error_message,
                "raw_output": result.raw_output,
                "details": parse_json_value(result.details_json, {}),
                "findings": result_findings(result),
                "created_at": result.created_at,
            }
            for result in engine_results
        ],
    }


def csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple, set)):
        return "; ".join(csv_cell(item) for item in value)
    if isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return " ".join(str(value).split())


def build_scan_report_csv(scan: ScanRecord, engine_results: list[EngineResultRecord]) -> str:
    payload = build_scan_report_payload(scan, engine_results)
    summary = payload["summary"]
    findings = payload["findings"]
    assessment = summary["assessment"]
    detection = summary["detection"]
    coverage = summary["coverage"]
    output = io.StringIO(newline="")
    fieldnames = [
        "section",
        "scan_id",
        "filename",
        "sha256",
        "status",
        "verdict",
        "risk_score",
        "engine",
        "detected",
        "severity",
        "confidence",
        "finding",
        "signature",
        "matched_evidence",
        "duration_ms",
        "error_message",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    def write_row(**values: object) -> None:
        base = {
            "scan_id": scan.id,
            "filename": scan.original_filename,
            "sha256": scan.sha256,
            "status": scan.status,
            "verdict": assessment["verdict"],
            "risk_score": assessment["score"],
        }
        base.update(values)
        writer.writerow({key: csv_cell(base.get(key)) for key in fieldnames})

    write_row(
        section="summary",
        finding=detection["label"],
        matched_evidence=", ".join(detection["detected_engines"]),
        error_message="" if not coverage["unavailable"] else coverage["detail"],
    )

    for finding in findings:
        write_row(
            section="finding",
            engine=finding["engine"],
            detected=finding["status"] == "completed",
            severity=finding["severity"],
            confidence=finding["confidence"],
            finding=finding["finding"],
            signature=finding["title"],
            matched_evidence=finding["matched_evidence"],
        )

    for result in engine_results:
        write_row(
            section="engine_result",
            engine=result.engine_name,
            detected=result.detected,
            severity=result.severity,
            confidence=result.confidence,
            signature=result.signature,
            duration_ms=result.duration_ms,
            error_message=result.error_message,
        )

    return output.getvalue()


def report_shell(title: str, body: str) -> str:
    css_version = int(CSS_PATH.stat().st_mtime) if CSS_PATH.exists() else 1
    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{title} | MASP Report</title>
        <link rel="stylesheet" href="/static/css/app.css?v={css_version}">
      </head>
      <body class="report-body">
        {body}
        <script>
          function printReport() {{
            window.print();
          }}
        </script>
      </body>
    </html>
    """


def render_report_page(scan: ScanRecord, engine_results: list[EngineResultRecord]) -> str:
    payload = build_scan_report_payload(scan, engine_results)
    summary = payload["summary"]
    findings = payload["findings"]
    assessment = summary["assessment"]
    detection = summary["detection"]
    coverage = summary["coverage"]
    report_title = f"Scan report #{scan.id}"
    finding_rows = "\n".join(
        f"""
        <tr>
          <td><strong>{html.escape(str(item['engine']))}</strong></td>
          <td>{severity_pill(str(item['severity']))}</td>
          <td>{html.escape(str(item['finding']))}</td>
          <td>{html.escape(str(item['title']))}</td>
          <td>{html.escape(', '.join(str(value) for value in item['matched_evidence']))}</td>
          <td>{html.escape(', '.join(str(value) for value in item['classification'])) or '-'}</td>
        </tr>
        """
        for item in findings
    ) or """
        <tr><td class="empty-cell" colspan="6">No normalized findings were produced for this scan.</td></tr>
    """
    engine_rows = "\n".join(
        f"""
        <tr{' class="engine-detected-row"' if result.detected and result.status == 'completed' else ''}>
          <td><strong>{html.escape(result.engine_name)}</strong></td>
          <td>{status_pill(result.status)}</td>
          <td>{detected_pill(result.status, result.detected)}</td>
          <td>{severity_pill(result.severity)}</td>
          <td>{result.confidence}%</td>
          <td>{html.escape(result.signature or '-')}</td>
          <td>{html.escape(str(result.duration_ms))} ms</td>
        </tr>
        """
        for result in engine_results
    ) or """
        <tr><td class="empty-cell" colspan="7">No engine results are available yet.</td></tr>
    """
    raw_output_blocks = "\n".join(
        f"""
        <section class="panel">
          <div class="panel-header compact">
            <h2>{html.escape(result.engine_name)}</h2>
            {status_pill(result.status)}
          </div>
          <pre>{html.escape(result.raw_output)}</pre>
        </section>
        """
        for result in engine_results
    ) or """
        <section class="panel">
          <div class="panel-header compact">
            <h2>Raw outputs</h2>
            <span class="pill neutral">Empty</span>
          </div>
          <pre>No raw engine output is available for this scan yet.</pre>
        </section>
    """

    body = f"""
    <main class="report-shell">
      <section class="report-header">
        <div>
          <p class="eyebrow">MASP analyst report</p>
          <h1>{html.escape(scan.original_filename)}</h1>
          <span>Generated {html.escape(str(payload['generated_at']))}</span>
        </div>
        <div class="row-actions">
          <a class="secondary-action" href="/scans/{scan.id}/export.json">Export JSON</a>
          <a class="secondary-action" href="/scans/{scan.id}/export.csv">Export CSV</a>
          <button class="secondary-action" type="button" onclick="printReport()">Print</button>
          <a class="row-action" href="/scans/{scan.id}">Open scan</a>
        </div>
      </section>

      <section class="report-grid">
        <div class="panel">
          <div class="panel-header">
            <div>
              <h2>Assessment</h2>
              <p>Analyst-facing summary of the completed scan.</p>
            </div>
            <div class="scan-verdict-group">
              {verdict_pill(str(assessment['verdict']))}
              {detection_meter_for_scan(scan, engine_results)}
            </div>
          </div>
          <div class="summary-grid">
            <div><span>Case</span><strong>{html.escape(scan.case_name)}</strong></div>
            <div><span>Priority</span><strong>{html.escape(scan.priority)}</strong></div>
            <div><span>Status</span><strong>{html.escape(display_verdict(scan.status))}</strong></div>
            <div><span>Risk score</span><strong>{assessment['score']} / 100</strong></div>
            <div><span>Detection</span><strong>{html.escape(str(detection['label']))}</strong></div>
            <div><span>Coverage</span><strong>{html.escape(str(coverage['label']))}</strong></div>
            <div><span>Attempts</span><strong>{scan.attempt_count}</strong></div>
            <div><span>Completed</span><strong>{html.escape(scan.completed_at or scan.created_at)}</strong></div>
          </div>
          <div class="reason-block">
            <span>Reasons</span>
            <ul>{render_risk_reasons(list(assessment['reasons']))}</ul>
          </div>
        </div>

        <div class="panel">
          <div class="panel-header compact">
            <h2>Sample</h2>
            <span class="pill neutral">{format_bytes(scan.size_bytes)}</span>
          </div>
          <dl class="hash-list">
            <div><dt>Filename</dt><dd>{html.escape(scan.original_filename)}</dd></div>
            <div><dt>Content type</dt><dd>{html.escape(scan.content_type)}</dd></div>
            <div><dt>MD5</dt><dd><code>{html.escape(scan.md5)}</code></dd></div>
            <div><dt>SHA1</dt><dd><code>{html.escape(scan.sha1)}</code></dd></div>
            <div><dt>SHA256</dt><dd><code>{html.escape(scan.sha256)}</code></dd></div>
          </dl>
        </div>

        <div class="panel wide">
          <div class="panel-header compact">
            <h2>Normalized findings</h2>
            <span class="pill neutral">{len(findings)} rows</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Engine</th>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Summary</th>
                  <th>Matched evidence</th>
                  <th>Classification</th>
                </tr>
              </thead>
              <tbody>{finding_rows}</tbody>
            </table>
          </div>
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
              <tbody>{engine_rows}</tbody>
            </table>
          </div>
        </div>

        <div class="panel wide report-raw-grid">
          <div class="panel-header compact">
            <h2>Raw outputs</h2>
            <span class="pill neutral">Engine debug trail</span>
          </div>
          <div class="report-raw-list">
            {raw_output_blocks}
          </div>
        </div>
      </section>
    </main>
    """
    return report_shell(report_title, body)


def render_scan_result(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
    user: UserRecord,
) -> str:
    assessment = calculate_risk(engine_results)
    score = scan.risk_score if scan.risk_score is not None else assessment.score
    verdict = scan.verdict if scan.risk_score is not None else assessment.verdict
    worker_status = get_worker_status()
    runtime_label, runtime_value = scan_runtime_marker(scan)
    retry_action = (
        f"""
        <form action="/scans/{scan.id}/retry" method="post">
          <button class="secondary-action compact-action" type="submit">Retry scan</button>
        </form>
        """
        if scan.status not in {"queued", "running"}
        else ""
    )
    report_actions = (
        f"""
        <a class="secondary-action compact-action" href="/scans/{scan.id}/report">View report</a>
        <a class="secondary-action compact-action" href="/scans/{scan.id}/export.json">Export JSON</a>
        <a class="secondary-action compact-action" href="/scans/{scan.id}/export.csv">Export CSV</a>
        """
        if scan.status not in {"queued", "running"}
        else ""
    )
    runtime_notice = ""
    if scan.last_error:
        runtime_notice = page_notice("Last worker error", scan.last_error, "danger")
    elif scan.status in {"queued", "running"} and not bool(worker_status.get("online")):
        runtime_notice = page_notice(
            "Worker heartbeat missing",
            worker_status_detail(worker_status),
            "warning",
        )
    body = f"""
    <section class="notice success-notice">
      <div class="notice-copy">
        <strong>Sample accepted</strong>
        <span>{html.escape(scan.original_filename)} was uploaded and stored successfully.</span>
      </div>
      <div class="row-actions notice-actions">
        {report_actions}
        {retry_action}
        <a class="secondary-action compact-action" href="/">Back to dashboard</a>
      </div>
    </section>
    {render_coverage_notice(scan, engine_results)}
    {runtime_notice}

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
          <div><span>Attempts</span><strong>{scan.attempt_count}</strong></div>
          <div><span>{html.escape(runtime_label)}</span><strong>{html.escape(runtime_value)}</strong></div>
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

      {render_detection_evidence(engine_results)}

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
def login_page(request: Request, next: str = "/", message: str = ""):
    if current_user(request) is not None:
        return RedirectResponse(url=safe_next_url(next), status_code=303)
    return HTMLResponse(render_login_page(next_url=next, message=message))


@app.post("/login", response_class=HTMLResponse)
def login_route(
    request: Request,
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
        expires=result.expires_at,
        max_age=result.expires_at - int(datetime.now().timestamp()),
        httponly=True,
        path="/",
        secure=session_cookie_secure(request),
        samesite="lax",
    )
    return response


@app.post("/logout")
def logout_route(request: Request) -> RedirectResponse:
    logout(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    q: str = "",
    status: str = "all",
    verdict: str = "all",
) -> str:
    user = require_user(request)
    can_manage_scans = user.role == ROLE_ADMIN
    scans = list_recent_scans()
    status_filter = status if status in {"all", "active", "queued", "running", "completed", "partial", "failed"} else "all"
    verdict_filter = verdict if verdict in {"all", "pending", "malicious", "undetected", "metadata_only"} else "all"
    filtered_scans, results_by_scan = filter_recent_scans(scans, q, status_filter, verdict_filter)
    filters_active = bool(q.strip()) or status_filter != "all" or verdict_filter != "all"
    empty_message = "No scans match the current filters." if filters_active else "No scans submitted yet."
    counts = get_scan_counts()
    worker_status = get_worker_status()
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
            <p>{len(filtered_scans)} of {len(scans)} latest samples shown.</p>
          </div>
          <div class="panel-actions">
            {delete_actions}
          </div>
        </div>
        {render_recent_scan_filters(q, status_filter, verdict_filter)}
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
              {render_recent_scan_rows(filtered_scans, can_select=can_manage_scans, results_by_scan=results_by_scan, empty_message=empty_message)}
            </tbody>
          </table>
        </div>
      </div>

      {render_worker_status_panel(worker_status)}
    </section>
    """
    return page_shell("Scan Dashboard", "dashboard", body, user)


@app.get("/system", response_class=HTMLResponse)
def system_page(request: Request) -> str:
    user = require_admin(request)
    return render_system_page(user)


@app.get("/users", response_class=HTMLResponse)
def users(request: Request, message: str = "", error: str = "") -> str:
    user = require_admin(request)
    return render_users_page(user, message=message, error=error)


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
        return RedirectResponse(url="/users?error=Username%20is%20required.", status_code=303)
    if len(password) < 8:
        return RedirectResponse(url="/users?error=Password%20must%20be%20at%20least%208%20characters.", status_code=303)
    if get_user_by_username(clean_username) is not None:
        return RedirectResponse(url="/users?error=Username%20already%20exists.", status_code=303)

    create_user(
        username=clean_username,
        password_hash=hash_password(password),
        role=normalize_role(role),
    )
    return RedirectResponse(url=f"/users?message={quote(f'Created user {clean_username}.')}", status_code=303)


@app.post("/users/{user_id}")
def update_user_route(
    request: Request,
    user_id: int,
    role: str = Form("analyst"),
    password: str = Form(""),
) -> RedirectResponse:
    admin_user = require_admin(request)
    target_user = get_user_by_id(user_id)
    if target_user is None:
        return RedirectResponse(url="/users?error=User%20not%20found.", status_code=303)
    if admin_user.id == user_id:
        return RedirectResponse(url="/users?error=Use%20Account%20to%20manage%20your%20own%20credentials.", status_code=303)

    normalized_role = normalize_role(role)
    if password and len(password) < 8:
        return RedirectResponse(url="/users?error=Password%20must%20be%20at%20least%208%20characters.", status_code=303)
    if target_user.role == ROLE_ADMIN and normalized_role != ROLE_ADMIN and count_users_by_role(ROLE_ADMIN) <= 1:
        return RedirectResponse(url="/users?error=At%20least%20one%20admin%20must%20remain%20active.", status_code=303)

    new_password_hash = hash_password(password) if password else None
    update_user(user_id, normalized_role, new_password_hash)
    if new_password_hash is not None:
        revoke_user_sessions(user_id)
    return RedirectResponse(
        url=f"/users?message={quote(f'Updated user {target_user.username}.')}",
        status_code=303,
    )


@app.post("/users/{user_id}/delete")
def delete_user_route(request: Request, user_id: int) -> RedirectResponse:
    user = require_admin(request)
    if user.id == user_id:
        return RedirectResponse(url="/users?error=You%20cannot%20delete%20your%20current%20user.", status_code=303)
    target_user = get_user_by_id(user_id)
    if target_user is None:
        return RedirectResponse(url="/users?error=User%20not%20found.", status_code=303)
    if target_user.role == ROLE_ADMIN and count_users_by_role(ROLE_ADMIN) <= 1:
        return RedirectResponse(url="/users?error=At%20least%20one%20admin%20must%20remain%20active.", status_code=303)
    delete_user(user_id)
    return RedirectResponse(
        url=f"/users?message={quote(f'Deleted user {target_user.username}.')}",
        status_code=303,
    )


@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request, message: str = "", error: str = "") -> str:
    user = require_user(request)
    return render_account_page(user, message=message, error=error)


@app.post("/account/password")
def update_account_password_route(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
) -> RedirectResponse:
    user = require_user(request)
    if not verify_password(current_password, user.password_hash):
        return RedirectResponse(url="/account?error=Current%20password%20is%20incorrect.", status_code=303)
    if len(new_password) < 8:
        return RedirectResponse(url="/account?error=Password%20must%20be%20at%20least%208%20characters.", status_code=303)
    if new_password != confirm_password:
        return RedirectResponse(url="/account?error=New%20password%20and%20confirmation%20must%20match.", status_code=303)
    if verify_password(new_password, user.password_hash):
        return RedirectResponse(url="/account?error=Choose%20a%20different%20password%20than%20your%20current%20one.", status_code=303)

    update_user(user.id, user.role, hash_password(new_password))
    revoke_user_sessions(user.id)
    response = RedirectResponse(
        url="/login?message=Password%20updated.%20Please%20sign%20in%20again.",
        status_code=303,
    )
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


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


@app.post("/scans/{scan_id}/retry")
async def retry_single_scan(request: Request, scan_id: int) -> RedirectResponse:
    require_user(request)
    if not retry_scan_job_record(scan_id):
        raise HTTPException(status_code=400, detail="Only completed or failed scans can be retried.")
    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


@app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
def scan_report(request: Request, scan_id: int) -> str:
    require_user(request)
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    engine_results = list_engine_results(scan.id)
    return render_report_page(scan, engine_results)


@app.get("/scans/{scan_id}/export.json")
def scan_export_json(request: Request, scan_id: int) -> JSONResponse:
    require_user(request)
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    engine_results = list_engine_results(scan.id)
    payload = build_scan_report_payload(scan, engine_results)
    filename = f"{report_filename_base(scan)}-scan-{scan.id}.json"
    return JSONResponse(
        payload,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/scans/{scan_id}/export.csv")
def scan_export_csv(request: Request, scan_id: int) -> Response:
    require_user(request)
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    engine_results = list_engine_results(scan.id)
    csv_body = build_scan_report_csv(scan, engine_results)
    filename = f"{report_filename_base(scan)}-scan-{scan.id}.csv"
    return Response(
        csv_body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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


@app.post("/engines/microsoft_defender/config")
def save_microsoft_defender_config(
    request: Request,
    microsoft_defender_execution_mode: str = Form("powershell"),
    microsoft_defender_powershell_path: str = Form("powershell.exe"),
    microsoft_defender_mpcmdrun_path: str = Form("auto"),
    microsoft_defender_default_scan_type: str = Form("custom"),
    microsoft_defender_timeout_seconds: str = Form("900"),
    microsoft_defender_update_before_scan: str = Form("false"),
    microsoft_defender_require_real_time_enabled: str = Form("false"),
) -> RedirectResponse:
    require_admin(request)
    update_engine_config(
        "microsoft_defender",
        {
            "execution_mode": microsoft_defender_execution_mode.strip() or "powershell",
            "powershell_path": microsoft_defender_powershell_path.strip() or "powershell.exe",
            "mpcmdrun_path": microsoft_defender_mpcmdrun_path.strip() or "auto",
            "default_scan_type": microsoft_defender_default_scan_type.strip() or "custom",
            "timeout_seconds": microsoft_defender_timeout_seconds.strip() or "900",
            "update_before_scan": "true" if microsoft_defender_update_before_scan.strip().lower() in {"1", "true", "yes", "on"} else "false",
            "require_real_time_enabled": "true" if microsoft_defender_require_real_time_enabled.strip().lower() in {"1", "true", "yes", "on"} else "false",
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
          {render_engine_logo(item.short_label, item.label.lower().replace(" ", "_"))}
          <div>
            <strong>{html.escape(item.label)}</strong>
            <small>{html.escape(item.vendor)} · {html.escape(item.product)} · {html.escape(item.integration_method)}</small>
            <small>{html.escape(item.blocker)}</small>
          </div>
          <span class="pill neutral">{html.escape(item.status.title())}</span>
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
