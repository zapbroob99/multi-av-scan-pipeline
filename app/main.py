import asyncio
import html
import json
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlencode

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.database import (
    count_scan_history,
    count_scans_older_than,
    count_users_by_role,
    create_sample,
    create_scan_batch,
    create_scan_engine_jobs,
    create_scan_job,
    create_user,
    delete_scan,
    delete_user,
    get_scan,
    get_scan_batch,
    get_scan_queue_position,
    get_queue_metrics,
    get_scan_counts,
    get_user_by_id,
    get_user_by_username,
    init_db,
    list_active_scans,
    list_engine_result_metrics,
    list_engine_results,
    list_engine_results_by_scan_ids,
    list_recent_scans,
    list_scan_batch_scans,
    list_scan_history,
    list_scan_worker_events,
    list_scans_older_than,
    list_users,
    retry_scan_job as retry_scan_job_record,
    refresh_scan_batch_counts,
    update_scan_assessment,
    update_user,
)
from app.models import (
    EngineInstanceRecord,
    EngineResultRecord,
    ScanBatchRecord,
    ScanRecord,
    ScanWorkerEventRecord,
    UserRecord,
)
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
    require_api_token,
    require_admin,
    require_user,
    revoke_user_sessions,
    session_cookie_secure,
    seed_default_users,
    verify_password,
)
from app.services.decisions import ScanDecision, decide_scan_action
from app.services.engine_registry import (
    ADAPTERS,
    ROADMAP_ADAPTERS,
    adapter_capabilities,
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
from app.services.ingest import UploadTooLargeError, store_upload
from app.services.archive_extractor import is_supported_archive
from app.services.api_payloads import (
    create_api_scan_result_payload,
    create_api_scan_status_payload,
)
from app.services.retention import RetentionPolicy, retention_cutoff_value, retention_policy_from_env
from app.services.reports import (
    build_report_finding_rows,
    create_scan_report_csv,
    create_scan_report_payload,
    parse_json_value,
    report_filename_base,
    result_findings,
)
from app.services.scoring import calculate_risk
from app.services.timing import build_scan_timing_payload
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
LEGACY_CSS_PATH = STATIC_DIR / "css" / "legacy.css"
API_TERMINAL_SCAN_STATUSES = {"completed", "failed"}
SUPPORTED_ARCHIVE_MODES = {"container", "lazy_extract_on_detection"}
DEFAULT_ARCHIVE_MODE = "lazy_extract_on_detection"

init_db()
seed_default_users()
seed_default_engines()

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def nav_icon(icon_key: str) -> str:
    icons = {
        "dashboard": """
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="3" y="3" width="7" height="9" rx="1.5"></rect>
          <rect x="14" y="3" width="7" height="5" rx="1.5"></rect>
          <rect x="14" y="12" width="7" height="9" rx="1.5"></rect>
          <rect x="3" y="16" width="7" height="5" rx="1.5"></rect>
        </svg>
        """,
        "new_scan": """
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="11" cy="11" r="7"></circle>
          <path d="m21 21-4.35-4.35"></path>
        </svg>
        """,
        "api_ledger": """
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M4 5h16"></path>
          <path d="M4 12h16"></path>
          <path d="M4 19h16"></path>
          <path d="M8 8v8"></path>
          <path d="M16 8v8"></path>
        </svg>
        """,
        "account": """
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="12" cy="8" r="4"></circle>
          <path d="M6 20c1.7-3.1 4-4.7 6-4.7s4.3 1.6 6 4.7"></path>
        </svg>
        """,
        "logout": """
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M9 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4"></path>
          <path d="m16 17 5-5-5-5"></path>
          <path d="M21 12H9"></path>
        </svg>
        """,
        "engines": """
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M12 6V2"></path>
          <path d="M15 11a3 3 0 1 0-6 0v3a3 3 0 1 0 6 0z"></path>
          <path d="M12 18v4"></path>
          <path d="M8 20h8"></path>
        </svg>
        """,
        "system": """
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
        </svg>
        """,
        "users": """
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
          <circle cx="8.5" cy="7" r="4"></circle>
          <path d="M20 8v6"></path>
          <path d="M23 11h-6"></path>
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
    legacy_css_version = int(LEGACY_CSS_PATH.stat().st_mtime) if LEGACY_CSS_PATH.exists() else 1
    refresh_html = (
        f'<meta http-equiv="refresh" content="{refresh_seconds}">'
        if refresh_seconds is not None
        else ""
    )
    nav_items = [
        ("dashboard", "/", "Dashboard"),
        ("api_ledger", "/api-ledger", "API Ledger"),
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
              document.documentElement.classList.toggle("dark", theme === "dark");
            }} catch (error) {{
              document.documentElement.setAttribute("data-theme", "light");
              document.documentElement.classList.remove("dark");
            }}
          }})();
        </script>
        <link rel="stylesheet" href="/static/css/legacy.css?v={legacy_css_version}">
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
                <div class="user-menu topbar-user-card">
                  <span class="user-avatar topbar-user-avatar" aria-hidden="true">{username[:1].upper()}</span>
                  <span class="topbar-user-copy">
                    <small class="topbar-user-label">Signed in as</small>
                    <strong>{username}</strong>
                  </span>
                  <span class="topbar-user-role-badge">
                    <small class="topbar-user-role">{role}</small>
                  </span>
                </div>
                <button class="theme-toggle topbar-theme-toggle" type="button" data-theme-toggle aria-label="Toggle dark theme" title="Toggle dark theme">
                  <span class="theme-toggle-track" aria-hidden="true">
                    <span class="theme-toggle-sun">L</span>
                    <span class="theme-toggle-thumb">
                      <span class="theme-toggle-icon" aria-hidden="true"></span>
                    </span>
                    <span class="theme-toggle-moon">D</span>
                  </span>
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
          const actionForms = document.querySelectorAll("form[data-action-form]");
          const selectedScanIds = new Set();
          const clickTimers = new Map();
          const scrollRestoreKey = "masp-scroll-restore";

          const applyTheme = (theme) => {{
            document.documentElement.setAttribute("data-theme", theme);
            document.documentElement.classList.toggle("dark", theme === "dark");
            try {{
              localStorage.setItem("masp-theme", theme);
            }} catch (error) {{
              console.warn("Theme preference could not be saved", error);
            }}
            if (themeToggle) {{
              const nextTheme = theme === "dark" ? "light" : "dark";
              themeToggle.setAttribute("aria-label", `Switch to ${{nextTheme}} theme`);
              themeToggle.setAttribute("title", `Switch to ${{nextTheme}} theme`);
            }}
          }};

          applyTheme(document.documentElement.getAttribute("data-theme") || "light");

          try {{
            const rawScrollState = window.sessionStorage.getItem(scrollRestoreKey);
            if (rawScrollState && !window.location.hash) {{
              const scrollState = JSON.parse(rawScrollState);
              const isFresh = typeof scrollState.ts === "number" && (Date.now() - scrollState.ts) < 15000;
              if (isFresh && scrollState.path === window.location.pathname && typeof scrollState.scrollY === "number") {{
                window.scrollTo({{ top: scrollState.scrollY }});
              }}
            }}
            window.sessionStorage.removeItem(scrollRestoreKey);
          }} catch (error) {{
            console.warn("Scroll state could not be restored", error);
          }}

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

          if (actionForms.length) {{
            actionForms.forEach((form) => {{
              form.addEventListener("submit", (event) => {{
                const submitter = event.submitter instanceof HTMLElement
                  ? event.submitter
                  : form.querySelector("button[type='submit'], input[type='submit']");
                const busyLabel = submitter && submitter.getAttribute("data-busy-label");

                if (form.hasAttribute("data-preserve-scroll")) {{
                  try {{
                    window.sessionStorage.setItem(scrollRestoreKey, JSON.stringify({{
                      path: window.location.pathname,
                      scrollY: window.scrollY,
                      ts: Date.now(),
                    }}));
                  }} catch (error) {{
                    console.warn("Scroll state could not be saved", error);
                  }}
                }}

                form.querySelectorAll("button[type='submit'], input[type='submit']").forEach((button) => {{
                  button.disabled = true;
                }});

                if (submitter) {{
                  if (busyLabel) {{
                    submitter.textContent = busyLabel;
                  }}
                  submitter.disabled = true;
                }}
              }});
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
    legacy_css_version = int(LEGACY_CSS_PATH.stat().st_mtime) if LEGACY_CSS_PATH.exists() else 1
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
              document.documentElement.classList.toggle("dark", theme === "dark");
            }} catch (error) {{
              document.documentElement.setAttribute("data-theme", "light");
              document.documentElement.classList.remove("dark");
            }}
          }})();
        </script>
        <link rel="stylesheet" href="/static/css/legacy.css?v={legacy_css_version}">
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


ARCHIVE_CHILD_REFRESH_GRACE_SECONDS = 30


def scan_completed_seconds_ago(scan: ScanRecord) -> int | None:
    if not scan.completed_at:
        return None
    normalized = scan.completed_at.replace("Z", "+00:00")
    try:
        completed_at = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    now = datetime.now(completed_at.tzinfo) if completed_at.tzinfo else datetime.now()
    return max(0, int((now - completed_at).total_seconds()))


def should_refresh_archive_children(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
    child_scans: list[ScanRecord],
) -> bool:
    if scan.scan_role != "container" or scan.batch_id is None:
        return False
    if scan.status in {"queued", "running"} or child_scans:
        return False
    detected = any(
        result.status == "completed" and result.detected
        for result in engine_results
    )
    if not detected and scan.verdict not in {"medium", "high", "critical"}:
        return False
    completed_seconds_ago = scan_completed_seconds_ago(scan)
    if completed_seconds_ago is None:
        return True
    return completed_seconds_ago <= ARCHIVE_CHILD_REFRESH_GRACE_SECONDS


def redirect_url(
    path: str,
    *,
    message: str = "",
    error: str = "",
    target: str = "",
) -> str:
    query_params: dict[str, str] = {}
    if message:
        query_params["message"] = message
    if error:
        query_params["error"] = error
    if target:
        query_params["target"] = target

    query = urlencode(query_params)
    url = f"{path}?{query}" if query else path
    if target:
        url = f"{url}#engine-{quote(target, safe='')}"
    return url


def scan_is_terminal(scan: ScanRecord) -> bool:
    return scan.status in API_TERMINAL_SCAN_STATUSES


def configured_api_max_wait_seconds() -> int:
    raw_value = os.getenv("MASP_API_MAX_WAIT_SECONDS", "15").strip()
    try:
        wait_seconds = int(raw_value or "15")
    except ValueError:
        return 15
    return max(0, min(wait_seconds, 300))


def configured_api_retry_after_seconds() -> int:
    raw_value = os.getenv("MASP_API_RETRY_AFTER_SECONDS", "2").strip()
    try:
        retry_seconds = int(raw_value or "2")
    except ValueError:
        return 2
    return max(1, min(retry_seconds, 30))


def normalized_api_wait_seconds(requested_wait_seconds: int) -> int:
    return max(0, min(requested_wait_seconds, configured_api_max_wait_seconds()))


def normalized_archive_mode(requested_archive_mode: str) -> str:
    archive_mode = requested_archive_mode.strip().lower() or DEFAULT_ARCHIVE_MODE
    aliases = {
        "lazy": "lazy_extract_on_detection",
        "lazy_extract": "lazy_extract_on_detection",
    }
    archive_mode = aliases.get(archive_mode, archive_mode)
    if archive_mode not in SUPPORTED_ARCHIVE_MODES:
        supported = ", ".join(sorted(SUPPORTED_ARCHIVE_MODES))
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported archive_mode '{requested_archive_mode}'. Supported values: {supported}.",
        )
    return archive_mode


def api_scan_links(request: Request, scan_id: int) -> dict[str, str]:
    return {
        "status": str(request.url_for("api_scan_status", scan_id=scan_id)),
        "result": str(request.url_for("api_scan_result", scan_id=scan_id)),
        "ui": str(request.base_url).rstrip("/") + f"/scans/{scan_id}",
    }


def api_batch_links(request: Request, batch_id: int) -> dict[str, str]:
    return {
        "status": str(request.url_for("api_batch_status", batch_id=batch_id)),
        "result": str(request.url_for("api_batch_result", batch_id=batch_id)),
        "ui": str(request.base_url).rstrip("/") + f"/api-ledger/batches/{batch_id}",
    }


def build_scan_summary_payload(scan: ScanRecord) -> dict[str, object]:
    return {
        "id": scan.id,
        "sample_id": scan.sample_id,
        "filename": scan.original_filename,
        "case_name": scan.case_name,
        "priority": scan.priority,
        "source": scan.source,
        "status": scan.status,
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "failed_at": scan.failed_at,
        "attempt_count": scan.attempt_count,
        "last_error": scan.last_error,
        "note": scan.note,
        "content_type": scan.content_type,
        "size_bytes": scan.size_bytes,
        "batch": {
            "id": scan.batch_id,
            "parent_scan_id": scan.parent_scan_id,
            "relative_path": scan.relative_path,
            "role": scan.scan_role,
        },
        "timing": build_scan_timing_payload(scan),
        "hashes": {
            "md5": scan.md5,
            "sha1": scan.sha1,
            "sha256": scan.sha256,
        },
    }


def scan_batch_is_terminal(batch: ScanBatchRecord) -> bool:
    return batch.status == "completed"


def build_scan_batch_summary_payload(
    request: Request,
    batch: ScanBatchRecord,
    scans: list[ScanRecord],
) -> dict[str, object]:
    container_scan = next((scan for scan in scans if scan.scan_role == "container"), None)
    child_count = sum(1 for scan in scans if scan.scan_role == "child")
    return {
        "id": batch.id,
        "source": batch.source,
        "original_filename": batch.original_filename,
        "archive_mode": batch.archive_mode,
        "status": batch.status,
        "counts": {
            "total_items": batch.total_items,
            "queued_items": batch.queued_items,
            "running_items": batch.running_items,
            "completed_items": batch.completed_items,
            "failed_items": batch.failed_items,
            "malicious_items": batch.malicious_items,
            "skipped_items": batch.skipped_items,
            "child_items": child_count,
        },
        "container_scan_id": None if container_scan is None else container_scan.id,
        "metadata": json.loads(batch.metadata_json) if batch.metadata_json.strip() else {},
        "created_at": batch.created_at,
        "updated_at": batch.updated_at,
        "completed_at": batch.completed_at,
        "last_error": batch.last_error,
        "completed": scan_batch_is_terminal(batch),
        "links": api_batch_links(request, batch.id),
    }


def build_scan_batch_status_payload(
    request: Request,
    batch: ScanBatchRecord,
    scans: list[ScanRecord],
) -> dict[str, object]:
    return {
        "completed": scan_batch_is_terminal(batch),
        "result_ready": scan_batch_is_terminal(batch),
        "batch": build_scan_batch_summary_payload(request, batch, scans),
        "scans": [
            {
                **build_scan_summary_payload(scan),
                "result_ready": scan_is_terminal(scan),
                "links": api_scan_links(request, scan.id),
            }
            for scan in scans
        ],
        "links": api_batch_links(request, batch.id),
    }


def build_scan_batch_result_payload(
    request: Request,
    batch: ScanBatchRecord,
    scans: list[ScanRecord],
) -> dict[str, object]:
    return {
        "completed": scan_batch_is_terminal(batch),
        "result_ready": scan_batch_is_terminal(batch),
        "batch": build_scan_batch_summary_payload(request, batch, scans),
        "scans": [
            {
                "id": scan.id,
                "role": scan.scan_role,
                "parent_scan_id": scan.parent_scan_id,
                "relative_path": scan.relative_path,
                "result": build_scan_report_payload(scan, list_engine_results(scan.id)),
                "links": api_scan_links(request, scan.id),
            }
            for scan in scans
        ],
        "links": api_batch_links(request, batch.id),
    }


def scan_decision(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
    *,
    risk_score: int | None = None,
    verdict: str | None = None,
) -> ScanDecision:
    assessment = calculate_risk(engine_results)
    effective_score = risk_score if risk_score is not None else scan.risk_score
    effective_verdict = verdict if verdict is not None else scan.verdict
    if effective_score is None:
        effective_score = assessment.score
    if effective_verdict == "pending":
        effective_verdict = assessment.verdict
    detected_count, detection_total = detection_summary(engine_results)
    _, _, coverage_unavailable = required_engine_coverage(engine_results)
    return decide_scan_action(
        scan_status=scan.status,
        verdict=effective_verdict,
        risk_score=effective_score,
        detected_engines=detected_count,
        detection_engines=detection_total,
        unavailable_engines=coverage_unavailable,
    )


def scan_decision_payload(decision: ScanDecision) -> dict[str, object]:
    return {
        "action": decision.action,
        "label": decision.label,
        "tone": decision.tone,
        "confidence": decision.confidence,
        "policy": decision.policy,
        "reason": decision.reason,
        "reasons": decision.reasons,
    }


def decision_pill(decision: ScanDecision) -> str:
    return f'<span class="pill {html.escape(decision.tone)}">{html.escape(decision.label)}</span>'


def build_api_scan_status_payload(
    request: Request,
    scan: ScanRecord,
    engine_results: list[EngineResultRecord] | None = None,
    worker_events: list[ScanWorkerEventRecord] | None = None,
) -> dict[str, object]:
    results = engine_results if engine_results is not None else list_engine_results(scan.id)
    events = worker_events if worker_events is not None else list_scan_worker_events(scan.id)
    queue_metrics = get_queue_metrics()
    queue_position = get_scan_queue_position(scan.id)
    result_ready = scan_is_terminal(scan)
    decision = scan_decision(scan, results)
    payload = create_api_scan_status_payload(
        scan=scan,
        result_ready=result_ready,
        recommended_poll_seconds=None if result_ready else configured_api_retry_after_seconds(),
        decision_payload=scan_decision_payload(decision),
        scan_payload=build_scan_summary_payload(scan),
        queue_metrics=queue_metrics,
        queue_position=queue_position,
        expected_engines=len(enabled_engines()),
        results=results,
        worker_events=events,
        links=api_scan_links(request, scan.id),
    )
    if scan.batch_id is not None:
        payload["batch_links"] = api_batch_links(request, scan.batch_id)
    return payload


def build_api_scan_result_payload(
    request: Request,
    scan: ScanRecord,
    engine_results: list[EngineResultRecord] | None = None,
) -> dict[str, object]:
    results = engine_results if engine_results is not None else list_engine_results(scan.id)
    report_payload = build_scan_report_payload(scan, results)
    result_ready = scan_is_terminal(scan)
    payload = create_api_scan_result_payload(
        report_payload=report_payload,
        completed=result_ready,
        result_ready=result_ready,
        decision_payload=report_payload["summary"]["decision"],
        links=api_scan_links(request, scan.id),
    )
    if scan.batch_id is not None:
        payload["batch_links"] = api_batch_links(request, scan.batch_id)
    return payload


async def wait_for_terminal_scan(scan_id: int, wait_seconds: int) -> ScanRecord | None:
    scan = get_scan(scan_id)
    if scan is None or wait_seconds <= 0 or scan_is_terminal(scan):
        return scan

    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_seconds
    while loop.time() < deadline:
        await asyncio.sleep(min(0.5, max(0.1, deadline - loop.time())))
        scan = get_scan(scan_id)
        if scan is None or scan_is_terminal(scan):
            return scan
    return get_scan(scan_id)


async def enqueue_scan_from_upload(
    sample: UploadFile,
    *,
    case_name: str,
    priority: str,
    note: str,
    source: str,
    archive_mode: str = DEFAULT_ARCHIVE_MODE,
) -> ScanRecord:
    if not sample.filename:
        raise HTTPException(status_code=400, detail="A file must be selected.")

    effective_archive_mode = normalized_archive_mode(archive_mode)
    try:
        stored_sample = await store_upload(sample)
    except UploadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc

    sample_id = create_sample(stored_sample)
    batch_id: int | None = None
    relative_path: str | None = None
    scan_role = "standalone"
    if is_supported_archive(stored_sample.storage_path):
        batch_id = create_scan_batch(
            source=source,
            original_filename=stored_sample.original_filename,
            archive_mode=effective_archive_mode,
            total_items=1,
            metadata_json=json.dumps(
                {
                    "container_sha256": stored_sample.sha256,
                    "container_size_bytes": stored_sample.size_bytes,
                }
            ),
        )
        relative_path = stored_sample.original_filename
        scan_role = "container"

    scan_id = create_scan_job(
        sample_id=sample_id,
        case_name=case_name.strip() or "Unassigned",
        priority=priority,
        note=note.strip(),
        source=source,
        batch_id=batch_id,
        relative_path=relative_path,
        scan_role=scan_role,
    )
    create_scan_engine_jobs(scan_id, enabled_engines())
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=500, detail="Scan could not be loaded.")
    return scan


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


def retention_policy_badge(policy: RetentionPolicy) -> str:
    if policy.enabled:
        return '<span class="pill success">Retention enabled</span>'
    return '<span class="pill neutral">Retention disabled</span>'


def render_retention_panel(policy: RetentionPolicy) -> str:
    cutoff_value = retention_cutoff_value(policy)
    eligible_count = count_scans_older_than(cutoff_value) if cutoff_value else 0
    action_disabled = "disabled" if not policy.enabled or eligible_count == 0 else ""
    cutoff_label = cutoff_value or "Not configured"
    helper_text = (
        f"{eligible_count} scans are older than the retention window."
        if policy.enabled
        else "Set MASP_RETENTION_DAYS above 0 to enable manual cleanup."
    )

    return f"""
      <div class="panel system-wide">
        <div class="panel-header compact">
          <div>
            <h2>Retention cleanup</h2>
            <p>Manual housekeeping for old scan records and stored sample files.</p>
          </div>
          {retention_policy_badge(policy)}
        </div>
        <div class="retention-grid">
          <div>
            <span>Policy window</span>
            <strong>{html.escape(str(policy.days))} days</strong>
          </div>
          <div>
            <span>Batch size</span>
            <strong>{html.escape(str(policy.batch_size))} scans</strong>
          </div>
          <div>
            <span>Cutoff</span>
            <strong>{html.escape(cutoff_label)}</strong>
          </div>
          <div>
            <span>Eligible</span>
            <strong>{eligible_count}</strong>
          </div>
        </div>
        <div class="retention-actions">
          <p>{html.escape(helper_text)}</p>
          <form action="/system/retention/run" method="post" data-action-form data-preserve-scroll>
            <button class="danger-action" type="submit" data-busy-label="Cleaning old scans..." {action_disabled}>
              Run cleanup
            </button>
          </form>
        </div>
      </div>
    """


def render_system_page(user: UserRecord, message: str = "", error: str = "") -> str:
    worker_status = get_worker_status()
    queue_metrics = get_queue_metrics()
    engine_metrics = list_engine_result_metrics()
    engines = configured_engines()
    active_scans = list_active_scans(limit=50)
    supported_engine_count = len(set(str(item) for item in worker_status.get("engine_keys", [])))
    retention_policy = retention_policy_from_env()
    notice_html = (
        page_notice("System updated", message, "success")
        + page_notice("Action blocked", error, "danger")
    )

    body = f"""
    {notice_html}
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

      {render_retention_panel(retention_policy)}
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
                <form action="/engines/yara/rules/{encoded_name}/toggle" method="post" data-action-form data-preserve-scroll>
                  <button class="secondary-action compact-action" type="submit" data-busy-label="{html.escape('Disabling...' if enabled else 'Enabling...')}">{toggle_label}</button>
                </form>
                <form action="/engines/yara/rules/{encoded_name}/delete" method="post" data-action-form data-preserve-scroll>
                  <button class="danger-action compact-action" type="submit" data-busy-label="Deleting...">Delete</button>
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
            <defs>
              <linearGradient id="clamavBadge" x1="9" y1="8" x2="33" y2="36" gradientUnits="userSpaceOnUse">
                <stop stop-color="#ff6b6b"></stop>
                <stop offset="1" stop-color="#dc2626"></stop>
              </linearGradient>
            </defs>
            <path d="M11.2 14.4 16.7 7l3.8 5.5h3.1L27.3 7l5.5 7.4A14.7 14.7 0 0 1 36.5 24c0 8.1-6.5 14.5-14.5 14.5S7.5 32.1 7.5 24a14.7 14.7 0 0 1 3.7-9.6Z" fill="url(#clamavBadge)"></path>
            <path d="M13.6 21.9c1.7-2.1 5.7-2.4 8.8-.5-1.6 3.6-4.8 5.7-8.1 5.5-.9-1.5-1.2-3.2-.7-5Z" fill="#fff7f7"></path>
            <path d="M30.4 21.9c-1.7-2.1-5.7-2.4-8.8-.5 1.6 3.6 4.8 5.7 8.1 5.5.9-1.5 1.2-3.2.7-5Z" fill="#fff7f7"></path>
            <path d="M17.7 23.5c.8 1.1 2.1 2.4 4 3.2-1.8.8-3.7.6-5.1-.2.1-1 .5-2 .9-3Z" fill="#1f2937"></path>
            <path d="M26.3 23.5c-.8 1.1-2.1 2.4-4 3.2 1.8.8 3.7.6 5.1-.2-.1-1-.5-2-.9-3Z" fill="#1f2937"></path>
          </svg>
        </span>
        """

    if key == "yara":
        return '<span class="engine-logo engine-logo-yara engine-logo-glyph" aria-hidden="true">&#123;</span>'

    if key == "microsoft_defender":
        return """
        <span class="engine-logo engine-logo-defender" aria-hidden="true">
          <svg viewBox="0 0 44 44" role="img" focusable="false">
            <defs>
              <linearGradient id="defenderShield" x1="10" y1="7" x2="34" y2="37" gradientUnits="userSpaceOnUse">
                <stop stop-color="#60a5fa"></stop>
                <stop offset="1" stop-color="#2563eb"></stop>
              </linearGradient>
            </defs>
            <path d="M22 5.6c4.5 2.7 8.9 4.2 13.1 4.6v10.2c0 8.2-4.6 14.8-13.1 18-8.5-3.2-13.1-9.8-13.1-18V10.2c4.2-.4 8.6-1.9 13.1-4.6Z" fill="url(#defenderShield)"></path>
            <path d="M22 9.4v24.8c-6.2-2.7-9.8-7.3-9.8-13V15c3.2-.8 6.5-2.1 9.8-5.6Z" fill="#eff6ff"></path>
            <path d="M22 9.4c3.3 3.5 6.6 4.8 9.8 5.6v6.2c0 5.7-3.6 10.3-9.8 13V9.4Z" fill="#93c5fd"></path>
            <path d="M22 12.8v17" stroke="#1d4ed8" stroke-width="1.45" stroke-linecap="round"></path>
            <path d="M15.7 18.9c2.6 1 4.7 1.2 6.3 1.2s3.7-.2 6.3-1.2" stroke="#1d4ed8" stroke-width="1.45" stroke-linecap="round"></path>
            <path d="M17.7 24.6c1.5 1 2.9 1.4 4.3 1.4s2.8-.4 4.3-1.4" stroke="#1d4ed8" stroke-width="1.3" stroke-linecap="round"></path>
          </svg>
        </span>
        """

    return f'<span class="engine-logo engine-logo-text" aria-hidden="true">{safe_label}</span>'


def format_engine_capability_modes(modes: tuple[str, ...]) -> str:
    labels = {
        "metadata": "metadata",
        "file": "file",
        "path": "path",
        "hash": "hash",
    }
    return ", ".join(labels.get(mode, mode) for mode in modes)


def format_engine_platforms(platforms: tuple[str, ...]) -> str:
    labels = {
        "linux": "Linux",
        "windows": "Windows",
    }
    return ", ".join(labels.get(platform, platform.title()) for platform in platforms)


def format_max_file_size(max_file_size_bytes: int | None) -> str:
    if max_file_size_bytes is None:
        return "Inherited"
    if max_file_size_bytes <= 0:
        return "Unlimited"
    return format_bytes(max_file_size_bytes)


def append_capability_fields(
    fields: list[tuple[str, str]],
    adapter_key: str,
) -> list[tuple[str, str]]:
    capability = adapter_capabilities(adapter_key)
    fields.extend(
        [
            ("Deployment", capability.deployment.title()),
            ("Inputs", format_engine_capability_modes(capability.input_modes)),
            ("Platforms", format_engine_platforms(capability.supported_platforms)),
            ("Execution", capability.execution_model.title()),
            ("Network", "Required" if capability.requires_network else "Local only"),
        ]
    )
    return fields


def render_add_engine_panel() -> str:
    available_adapters = available_adapter_definitions()
    if available_adapters:
        available_count = len(available_adapters)
        available_label = (
            f"{available_count} adapter available"
            if available_count == 1
            else f"{available_count} adapters available"
        )
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
        pill = '<span class="pill success">Catalog ready</span>'
        registry_body = f"""
      <details class="add-engine-drawer">
        <summary class="add-engine-summary">
          <div class="add-engine-summary-copy">
            <span class="add-engine-summary-eyebrow">Adapter catalog</span>
            <strong>Add engine adapter</strong>
            <small>{available_label}. Register it here, then configure health checks and runtime settings below.</small>
          </div>
          <div class="add-engine-summary-actions">
            <span class="add-engine-trigger">
              <span class="add-engine-trigger-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M12 5v14"></path>
                  <path d="M5 12h14"></path>
                </svg>
              </span>
              <span>Browse catalog</span>
            </span>
            <span class="engine-expand-indicator" aria-hidden="true"></span>
          </div>
        </summary>
        <form class="add-engine-form" action="/engines/add" method="post" data-action-form data-preserve-scroll>
          <div class="adapter-scroll-list">
            {adapter_rows_html}
          </div>
          <div class="add-engine-form-footer">
            <div class="add-engine-form-note">
              <strong>Register selected adapter</strong>
              <span>The engine is added to this node first. Connection tests and runtime overrides stay editable afterward.</span>
            </div>
            <button class="primary-action add-engine-submit" type="submit" data-busy-label="Adding...">Add selected engine</button>
          </div>
        </form>
      </details>
        """
    else:
        empty_state_html = """
        <div class="adapter-empty">
          <strong>All implemented adapters are configured</strong>
          <span>Remove an adapter to add it again, or implement a new adapter to expose it here.</span>
        </div>
        """
        description = "All implemented adapters are already configured on this node."
        pill = '<span class="pill neutral">No adapters left</span>'
        registry_body = f"""
      <div class="add-engine-empty-state">
        {empty_state_html}
      </div>
        """

    return f"""
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Engine registry</h2>
          <p>{description}</p>
        </div>
        {pill}
      </div>
      {registry_body}
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
    toggle_busy_label = "Disabling..." if instance.enabled else "Enabling..."
    if show_test:
        test_button = f"""
        <form action="/engines/{html.escape(instance.adapter_key)}/test" method="post" data-action-form data-preserve-scroll>
          <button class="secondary-action engine-action-primary" type="submit" data-busy-label="Testing...">Test connection</button>
        </form>
        """
    toggle_button = f"""
    <form action="/engines/{html.escape(instance.adapter_key)}/toggle" method="post" data-action-form data-preserve-scroll>
      <button class="secondary-action engine-action-compact" type="submit" data-busy-label="{toggle_busy_label}">{"Disable" if instance.enabled else "Enable"}</button>
    </form>
    """
    remove_button = f"""
    <form action="/engines/{html.escape(instance.adapter_key)}/delete" method="post" data-action-form data-preserve-scroll>
      <button class="danger-action engine-action-compact" type="submit" data-busy-label="Removing...">Remove</button>
    </form>
    """
    return f"""
    <div class="engine-toolbar">
      {test_button}
      {toggle_button}
      {remove_button}
    </div>
    """


def render_engine_summary(
    instance: EngineInstanceRecord,
    status_html: str,
    meta: str,
) -> str:
    definition = adapter_definition(instance.adapter_key)
    capability = adapter_capabilities(instance.adapter_key)
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
        <small class="engine-definition-meta">Deployment: {html.escape(capability.deployment.title())} | Inputs: {html.escape(format_engine_capability_modes(capability.input_modes))}</small>
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
    focus_adapter_key: str = "",
) -> str:
    disabled_class = " is-disabled" if not instance.enabled else ""
    open_attr = " open" if instance.adapter_key in health_overrides or instance.adapter_key == focus_adapter_key else ""
    return f"""
    <details id="engine-{html.escape(instance.adapter_key)}" class="panel engine-secondary engine-card{disabled_class}"{open_attr}>
      {render_engine_summary(instance, status_html, meta)}
      <div class="engine-config">
        {body}
      </div>
    </details>
    """


def render_engine_card(
    instance: EngineInstanceRecord,
    health_overrides: dict[str, dict[str, str | bool]],
    focus_adapter_key: str = "",
) -> str:
    definition = adapter_definition(instance.adapter_key)
    capability = adapter_capabilities(instance.adapter_key)
    runtime = runtime_config(instance)

    health = (
        {"ok": False, "status": "disabled", "detail": "Engine instance is disabled."}
        if not instance.enabled
        else health_overrides.get(instance.adapter_key) or engine_health(instance)
    )
    tone = health_tone_for(instance.adapter_key, health)
    status_html = f'<span class="pill {tone}">{html.escape(str(health["status"]).title())}</span>'
    meta = (
        "Disabled"
        if not instance.enabled
        else f'{definition.category.title()} | {capability.deployment.title()}'
    )

    if instance.adapter_key == "clamav":
        form_values = clamav_form_values(instance)
        if str(runtime["mode"]) == "clamd":
            fields = [
                ("Adapter", "clamd TCP"),
                ("Host", str(runtime["host"])),
                ("Port", str(runtime["port"])),
                ("Timeout", f'{runtime["timeout_seconds"]}s'),
                ("Max size", format_max_file_size(int(runtime.get("max_file_size_bytes", 0) or 0))),
                ("Configured via", "engine registry"),
            ]
        else:
            fields = [
                ("Adapter", "local CLI"),
                ("Command", str(runtime["command"])),
                ("Timeout", f'{runtime["timeout_seconds"]}s'),
                ("Max size", format_max_file_size(int(runtime.get("max_file_size_bytes", 0) or 0))),
                ("Configured via", "engine registry"),
            ]
        fields = append_capability_fields(fields, instance.adapter_key)

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
              <form class="settings-form embedded" action="/engines/clamav/config" method="post" data-action-form data-preserve-scroll>
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
                    <label>
                      max file size bytes
                      <input type="number" name="clamav_max_file_size_bytes" value="{html.escape(form_values["max_file_size_bytes"])}" min="0" step="1">
                    </label>
                  </div>
                </div>
                <div class="settings-actions">
                  <button class="primary-action" type="submit" data-busy-label="Saving...">Save ClamAV settings</button>
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
            focus_adapter_key=focus_adapter_key,
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
        fields = append_capability_fields(fields, instance.adapter_key)
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
              <form class="settings-form embedded" action="/engines/yara/config" method="post" data-action-form data-preserve-scroll>
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
                  <button class="primary-action" type="submit" data-busy-label="Saving...">Save YARA settings</button>
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
              <form class="rule-upload" action="/engines/yara/rules" method="post" enctype="multipart/form-data" data-action-form data-preserve-scroll>
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
                  <button class="primary-action" type="submit" data-busy-label="Saving...">Add rule</button>
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
            focus_adapter_key=focus_adapter_key,
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
        fields = append_capability_fields(fields, instance.adapter_key)
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
              <form class="settings-form embedded" action="/engines/microsoft_defender/config" method="post" data-action-form data-preserve-scroll>
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
                  <button class="primary-action" type="submit" data-busy-label="Saving...">Save Defender settings</button>
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
            focus_adapter_key=focus_adapter_key,
        )

    fields = [
        ("Adapter", "built-in"),
        ("Category", "metadata"),
        ("Detection", "No"),
        ("Configured via", "engine registry"),
    ]
    fields = append_capability_fields(fields, instance.adapter_key)
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
        focus_adapter_key=focus_adapter_key,
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


def scan_role_pill(scan_role: str) -> str:
    tone_by_role = {
        "standalone": "neutral",
        "container": "warning",
        "child": "neutral",
    }
    tone = tone_by_role.get(scan_role, "neutral")
    return f'<span class="pill {tone}">{html.escape(display_verdict(scan_role))}</span>'


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
    results_by_scan = list_engine_results_by_scan_ids([scan.id for scan in scans])
    filtered_scans = []
    for scan in scans:
        engine_results = results_by_scan.get(scan.id, [])
        if scan_matches_recent_filters(scan, engine_results, query, status_filter, verdict_filter):
            filtered_scans.append(scan)
    return filtered_scans, results_by_scan


def normalize_dashboard_page(page: int) -> int:
    return max(1, page)


def paginate_scans(
    scans: list[ScanRecord],
    page: int,
    page_size: int,
) -> tuple[list[ScanRecord], int, int, int]:
    total_items = len(scans)
    if total_items == 0:
        return [], 1, 0, 0

    total_pages = max(1, (total_items + page_size - 1) // page_size)
    current_page = min(normalize_dashboard_page(page), total_pages)
    start_index = (current_page - 1) * page_size
    end_index = start_index + page_size
    return scans[start_index:end_index], current_page, total_pages, total_items


def scan_query_url(
    base_path: str,
    *,
    page: int,
    query: str,
    status_filter: str,
    verdict_filter: str,
) -> str:
    params: dict[str, str] = {"page": str(page)}
    if query.strip():
        params["q"] = query.strip()
    if status_filter != "all":
        params["status"] = status_filter
    if verdict_filter != "all":
        params["verdict"] = verdict_filter
    query_string = urlencode(params)
    return f"{base_path}?{query_string}" if query_string else base_path


def dashboard_query_url(
    *,
    page: int,
    query: str,
    status_filter: str,
    verdict_filter: str,
) -> str:
    return scan_query_url(
        "/",
        page=page,
        query=query,
        status_filter=status_filter,
        verdict_filter=verdict_filter,
    )


def api_ledger_query_url(
    *,
    page: int,
    query: str,
    status_filter: str,
    verdict_filter: str,
) -> str:
    return scan_query_url(
        "/api-ledger",
        page=page,
        query=query,
        status_filter=status_filter,
        verdict_filter=verdict_filter,
    )


def batch_query_url(
    batch_id: int,
    *,
    page: int,
) -> str:
    return scan_query_url(
        f"/batches/{batch_id}",
        page=page,
        query="",
        status_filter="all",
        verdict_filter="all",
    )


def select_option(value: str, label: str, selected_value: str) -> str:
    selected = " selected" if value == selected_value else ""
    return f'<option value="{html.escape(value)}"{selected}>{html.escape(label)}</option>'


def render_scan_filters(
    *,
    action_path: str,
    reset_path: str,
    query: str,
    status_filter: str,
    verdict_filter: str,
    verdict_options: list[tuple[str, str]],
) -> str:
    verdict_option_html = "\n".join(
        select_option(value, label, verdict_filter)
        for value, label in verdict_options
    )
    return f"""
    <form class="scan-filter-bar" action="{html.escape(action_path)}" method="get">
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
          {verdict_option_html}
        </select>
      </label>
      <div class="scan-filter-actions">
        <button class="primary-action compact-action" type="submit">Apply</button>
        <a class="secondary-action compact-action" href="{html.escape(reset_path)}">Reset</a>
      </div>
    </form>
    """


def render_recent_scan_filters(query: str, status_filter: str, verdict_filter: str) -> str:
    return render_scan_filters(
        action_path="/",
        reset_path="/",
        query=query,
        status_filter=status_filter,
        verdict_filter=verdict_filter,
        verdict_options=[
            ("all", "All verdicts"),
            ("pending", "Pending"),
            ("malicious", "Malicious"),
            ("undetected", "Undetected"),
            ("metadata_only", "Metadata only"),
        ],
    )


def render_scan_pagination(
    *,
    base_path: str,
    page: int,
    total_pages: int,
    total_items: int,
    page_size: int,
    query: str,
    status_filter: str,
    verdict_filter: str,
) -> str:
    if total_items == 0:
        return ""

    start_item = ((page - 1) * page_size) + 1
    end_item = min(page * page_size, total_items)
    previous_link = (
        f'<a class="secondary-action compact-action" href="{html.escape(scan_query_url(base_path, page=page - 1, query=query, status_filter=status_filter, verdict_filter=verdict_filter))}">Previous</a>'
        if page > 1
        else '<span class="secondary-action compact-action is-disabled" aria-disabled="true">Previous</span>'
    )
    next_link = (
        f'<a class="secondary-action compact-action" href="{html.escape(scan_query_url(base_path, page=page + 1, query=query, status_filter=status_filter, verdict_filter=verdict_filter))}">Next</a>'
        if page < total_pages
        else '<span class="secondary-action compact-action is-disabled" aria-disabled="true">Next</span>'
    )

    return f"""
    <div class="scan-pagination">
      <div class="scan-pagination-copy">
        <strong>{start_item}-{end_item}</strong>
        <span>of {total_items} scans</span>
      </div>
      <div class="scan-pagination-actions">
        {previous_link}
        <span class="scan-pagination-page">Page {page} of {total_pages}</span>
        {next_link}
      </div>
    </div>
    """


def render_recent_scan_pagination(
    *,
    page: int,
    total_pages: int,
    total_items: int,
    page_size: int,
    query: str,
    status_filter: str,
    verdict_filter: str,
) -> str:
    return render_scan_pagination(
        base_path="/",
        page=page,
        total_pages=total_pages,
        total_items=total_items,
        page_size=page_size,
        query=query,
        status_filter=status_filter,
        verdict_filter=verdict_filter,
    )


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
        batch_badge = (
            '<span class="pill warning batch-badge" title="Archive upload scanned as a batch">Batch</span>'
            if scan.scan_role == "container"
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
                  <strong><span class="scan-file-label">{pending_icon}{batch_badge}<span>{html.escape(scan.original_filename)}</span></span></strong>
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


def scan_type_label(scan: ScanRecord) -> str:
    if scan.scan_role == "container":
        return "Archive container"
    if scan.scan_role == "child":
        return "Archive member"
    return "Standalone sample"


def render_archive_member_rows(
    scans: list[ScanRecord],
    results_by_scan: dict[int, list[EngineResultRecord]],
) -> str:
    if not scans:
        return '<tr><td class="empty-cell" colspan="5">No extracted child scans are attached to this archive.</td></tr>'

    rows = []
    for child_scan in scans:
        child_results = results_by_scan.get(child_scan.id, [])
        relative_path = child_scan.relative_path or child_scan.original_filename
        detection_tone = detection_summary_tone_for_scan(child_scan, child_results)
        rows.append(
            f"""
            <tr>
              <td>
                <div class="table-link {'danger' if detection_tone == 'danger' else ''}">
                  <strong>{html.escape(relative_path)}</strong>
                  <small>{html.escape(child_scan.original_filename)}</small>
                </div>
              </td>
              <td>{status_pill(child_scan.status)}</td>
              <td>{dashboard_verdict_pill(child_scan, child_results)}</td>
              <td><span class="detection-count {detection_tone}">{html.escape(detection_summary_text_for_scan(child_scan, child_results))}</span></td>
              <td>
                <div class="table-actions">
                  <a class="secondary-action compact-action" href="/scans/{child_scan.id}">Open</a>
                </div>
              </td>
            </tr>
            """
        )
    return "\n".join(rows)


def render_archive_members_panel(
    scan: ScanRecord,
    child_scans: list[ScanRecord],
    results_by_scan: dict[int, list[EngineResultRecord]],
) -> str:
    if scan.scan_role != "container":
        return ""
    if not child_scans:
        return ""

    malicious_child_count = sum(
        1
        for child_scan in child_scans
        if detection_summary_tone_for_scan(child_scan, results_by_scan.get(child_scan.id, [])) == "danger"
    )
    subtitle = (
        f"{len(child_scans)} extracted files | {malicious_child_count} detected"
        if malicious_child_count
        else f"{len(child_scans)} extracted files"
    )
    return f"""
      <div class="panel archive-members-panel">
        <div class="panel-header compact">
          <div>
            <h2>Archive contents</h2>
            <p>{html.escape(subtitle)}</p>
          </div>
          <span class="pill {'danger' if malicious_child_count else 'neutral'}">{html.escape(display_verdict(scan.status))}</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>Detections</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {render_archive_member_rows(child_scans, results_by_scan)}
            </tbody>
          </table>
        </div>
      </div>
    """


def api_scan_source_pill(scan: ScanRecord) -> str:
    tone = "warning" if scan.status in {"queued", "running"} else "neutral"
    return f'<span class="pill {tone}">{html.escape(scan.source.title())}</span>'


def render_api_ledger_rows(
    scans: list[ScanRecord],
    results_by_scan: dict[int, list[EngineResultRecord]],
    empty_message: str,
    can_delete: bool = False,
) -> str:
    if not scans:
        colspan = 9 if can_delete else 8
        return f'<tr><td class="empty-cell" colspan="{colspan}">{html.escape(empty_message)}</td></tr>'

    rows = []
    for scan in scans:
        engine_results = results_by_scan.get(scan.id, [])
        timing = build_scan_timing_payload(scan)
        queue_wait = format_duration_ms(timing["queue_wait_ms"])
        processing_duration = format_duration_ms(timing["processing_duration_ms"])
        total_duration = format_duration_ms(timing["total_duration_ms"])
        detection_summary = detection_summary_text_for_scan(scan, engine_results)
        detail_summary = coverage_detail_text_for_scan(scan, engine_results) or detection_detail_text_for_scan(scan, engine_results)
        batch_detail = (
            f"Batch #{scan.batch_id} | {display_verdict(scan.scan_role)}"
            if scan.batch_id is not None
            else f"{scan.priority} priority | attempt {scan.attempt_count}"
        )
        batch_action = (
            f'<a class="secondary-action compact-action" href="/api-ledger/batches/{scan.batch_id}">Batch</a>'
            if scan.batch_id is not None
            else ""
        )
        delete_action = (
            f"""
                  <form action="/api-ledger/scans/{scan.id}/delete" method="post" data-action-form data-preserve-scroll>
                    <button class="danger-action compact-action" type="submit" data-busy-label="Deleting...">Delete</button>
                  </form>
            """
            if can_delete
            else ""
        )
        select_cell = (
            f"""
              <td class="select-cell">
                <input class="row-checkbox" type="checkbox" data-row-checkbox aria-label="Select scan {scan.id}">
              </td>
            """
            if can_delete
            else ""
        )
        rows.append(
            f"""
            <tr class="dashboard-scan-row" data-scan-row data-scan-id="{scan.id}" data-scan-url="/scans/{scan.id}" tabindex="0" aria-selected="false">
              {select_cell}
              <td>
                <div class="table-link">
                  <strong>{html.escape(scan.original_filename)}</strong>
                  <small>{html.escape(scan.case_name or "Unassigned")}</small>
                </div>
              </td>
              <td><code class="copyable" data-copy-value="{html.escape(scan.sha256)}" aria-label="Copy SHA256" title="Copy SHA256">{short_hash(scan.sha256)}</code></td>
              <td>
                {status_pill(scan.status)}
                <small class="status-detail">{html.escape(scan.last_error or detail_summary)}</small>
              </td>
              <td>
                {verdict_pill(scan.verdict)}
                <small class="status-detail">{html.escape(detection_summary)}</small>
              </td>
              <td>
                <strong>Q {html.escape(queue_wait)}</strong>
                <small>P {html.escape(processing_duration)} | T {html.escape(total_duration)}</small>
              </td>
              <td>
                {api_scan_source_pill(scan)}
                <small class="status-detail">{html.escape(batch_detail)}</small>
              </td>
              <td>{html.escape(scan.created_at)}</td>
              <td>
                <div class="table-actions">
                  <a class="secondary-action compact-action" href="/scans/{scan.id}">Open</a>
                  {batch_action}
                  <a class="secondary-action compact-action" href="/api-ledger/scans/{scan.id}/status">Status JSON</a>
                  <a class="secondary-action compact-action" href="/api-ledger/scans/{scan.id}/result">Result JSON</a>
                  {delete_action}
                </div>
              </td>
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
        skip_reason = engine_result_skip_reason_label(result)
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
                <details class="engine-raw-output">
                  <summary class="engine-raw-output-toggle">Raw output</summary>
                  <pre>{html.escape(result.raw_output)}</pre>
                  {f'<small>Skip reason: {html.escape(skip_reason)}</small>' if skip_reason else ''}
                  <small>{html.escape(error)}</small>
                </details>
              </td>
            </tr>
            """
        )
    return "\n".join(rows)


def engine_result_skip_reason_label(result: EngineResultRecord) -> str:
    if result.status != "skipped":
        return ""
    details = parse_json_value(result.details_json, {})
    if not isinstance(details, dict):
        return ""
    routing = details.get("routing")
    if not isinstance(routing, dict):
        return ""
    reason = routing.get("reason")
    return str(reason) if reason else ""


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
    return build_report_finding_rows(
        results,
        matched_evidence_for_finding=matched_evidence_for_finding,
        finding_classification_values=finding_classification_values,
        fallback_finding_detail_payload=fallback_finding_detail_payload,
    )


def build_scan_report_payload(
    scan: ScanRecord,
    engine_results: list[EngineResultRecord],
) -> dict[str, object]:
    assessment = calculate_risk(engine_results)
    verdict = scan.verdict if scan.risk_score is not None else assessment.verdict
    risk_score = scan.risk_score if scan.risk_score is not None else assessment.score
    findings = report_finding_rows(engine_results)
    coverage_ran, coverage_total, coverage_unavailable = required_engine_coverage(engine_results)
    decision = scan_decision(
        scan,
        engine_results,
        risk_score=risk_score,
        verdict=verdict,
    )
    return create_scan_report_payload(
        scan,
        engine_results,
        verdict=verdict,
        risk_score=risk_score,
        findings=findings,
        coverage_ran=coverage_ran,
        coverage_total=coverage_total,
        coverage_unavailable=coverage_unavailable,
        decision_payload=scan_decision_payload(decision),
        assessment_reasons=assessment.reasons,
        detection_label=detection_summary_text_for_scan(scan, engine_results),
        detection_detail=detection_detail_text_for_scan(scan, engine_results),
        detected_engines=detected_engine_names(engine_results),
        coverage_label=coverage_summary_text_for_scan(scan, engine_results),
        coverage_detail=coverage_detail_text_for_scan(scan, engine_results),
    )


def build_scan_report_csv(scan: ScanRecord, engine_results: list[EngineResultRecord]) -> str:
    payload = build_scan_report_payload(scan, engine_results)
    return create_scan_report_csv(scan, engine_results, payload)


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
    decision = summary["decision"]
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
              <span class="pill {html.escape(str(decision['tone']))}">{html.escape(str(decision['label']))}</span>
              {verdict_pill(str(assessment['verdict']))}
              {detection_meter_for_scan(scan, engine_results)}
            </div>
          </div>
          <div class="summary-grid">
            <div><span>Case</span><strong>{html.escape(scan.case_name)}</strong></div>
            <div><span>Priority</span><strong>{html.escape(scan.priority)}</strong></div>
            <div><span>Status</span><strong>{html.escape(display_verdict(scan.status))}</strong></div>
            <div><span>Risk score</span><strong>{assessment['score']} / 100</strong></div>
            <div><span>Decision</span><strong>{html.escape(str(decision['label']))}</strong></div>
            <div><span>Policy</span><strong>{html.escape(display_verdict(str(decision['policy'])))}</strong></div>
            <div><span>Detection</span><strong>{html.escape(str(detection['label']))}</strong></div>
            <div><span>Coverage</span><strong>{html.escape(str(coverage['label']))}</strong></div>
            <div><span>Attempts</span><strong>{scan.attempt_count}</strong></div>
            <div><span>Completed</span><strong>{html.escape(scan.completed_at or scan.created_at)}</strong></div>
          </div>
          <div class="reason-block">
            <span>Decision reasons</span>
            <ul>{render_risk_reasons(list(decision['reasons']))}</ul>
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
    message: str = "",
    error: str = "",
) -> str:
    assessment = calculate_risk(engine_results)
    score = scan.risk_score if scan.risk_score is not None else assessment.score
    verdict = scan.verdict if scan.risk_score is not None else assessment.verdict
    decision = scan_decision(
        scan,
        engine_results,
        risk_score=score,
        verdict=verdict,
    )
    worker_status = get_worker_status()
    runtime_label, runtime_value = scan_runtime_marker(scan)
    child_scans: list[ScanRecord] = []
    child_results_by_scan: dict[int, list[EngineResultRecord]] = {}
    if scan.scan_role == "container" and scan.batch_id is not None:
        child_scans = [
            batch_scan
            for batch_scan in list_scan_batch_scans(scan.batch_id, limit=5000)
            if batch_scan.parent_scan_id == scan.id
        ]
        if child_scans:
            child_results_by_scan = list_engine_results_by_scan_ids([child_scan.id for child_scan in child_scans])
    archive_children_refresh_pending = should_refresh_archive_children(
        scan,
        engine_results,
        child_scans,
    )
    retry_action = (
        f"""
        <form action="/scans/{scan.id}/retry" method="post" data-action-form data-preserve-scroll>
          <button class="secondary-action compact-action" type="submit" data-busy-label="Retrying...">Retry scan</button>
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
    elif archive_children_refresh_pending:
        runtime_notice = page_notice(
            "Archive contents pending",
            "Detected archive members are still being indexed. This page will refresh automatically.",
            "warning",
        )
    action_notice = (
        page_notice("Scan updated", message, "success")
        + page_notice("Action blocked", error, "danger")
    )
    body = f"""
    {action_notice}
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
            {decision_pill(decision)}
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
          <div><span>Decision</span><strong>{html.escape(decision.label)}</strong></div>
          <div><span>Policy</span><strong>{html.escape(display_verdict(decision.policy))}</strong></div>
          <div><span>Attempts</span><strong>{scan.attempt_count}</strong></div>
          <div><span>Scan type</span><strong>{html.escape(scan_type_label(scan))}</strong></div>
          <div><span>Path</span><strong>{html.escape(scan.relative_path or scan.original_filename)}</strong></div>
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
          <span>Decision reasons</span>
          <ul>
            {render_risk_reasons(decision.reasons)}
          </ul>
        </div>
      </div>

      <div class="result-side-column">
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

        {render_archive_members_panel(scan, child_scans, child_results_by_scan)}
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
    archive_refresh_active = archive_children_refresh_pending or any(
        child_scan.status in {"queued", "running"}
        for child_scan in child_scans
    )
    refresh_seconds = 5 if scan.status in {"queued", "running"} or archive_refresh_active else None
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
    page: int = 1,
    message: str = "",
    error: str = "",
) -> str:
    user = require_user(request)
    can_manage_scans = user.role == ROLE_ADMIN
    scans = list_recent_scans(limit=None, source="manual", include_child_scans=False)
    page_size = 20
    status_filter = status if status in {"all", "active", "queued", "running", "completed", "partial", "failed"} else "all"
    verdict_filter = verdict if verdict in {"all", "pending", "malicious", "undetected", "metadata_only"} else "all"
    filtered_scans, results_by_scan = filter_recent_scans(scans, q, status_filter, verdict_filter)
    paginated_scans, current_page, total_pages, total_filtered_scans = paginate_scans(
        filtered_scans,
        page,
        page_size,
    )
    filters_active = bool(q.strip()) or status_filter != "all" or verdict_filter != "all"
    empty_message = "No scans match the current filters." if filters_active else "No scans submitted yet."
    counts = get_scan_counts(source="manual", include_child_scans=False)
    worker_status = get_worker_status()
    configured_engine_count = len(configured_engines())
    delete_actions = (
        """
            <form id="bulk-delete-form" action="/scans/delete" method="post" data-bulk-delete-form data-action-form data-preserve-scroll></form>
            <button class="toolbar-delete" type="submit" form="bulk-delete-form" data-bulk-delete data-busy-label="Deleting..." hidden>Delete selected</button>
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
    notice_html = (
        page_notice("Scan queue updated", message, "success")
        + page_notice("Action blocked", error, "danger")
    )
    body = f"""
    {notice_html}
    <section class="metric-grid">
      {metric_card("Samples", str(counts["total"]), "Persisted manual scan jobs")}
      {metric_card("Active", str(counts["running"]), "Queued or running manual jobs", "tone-blue")}
      {metric_card("High risk", str(counts["high_risk"]), "Manual scans with high verdicts", "tone-red")}
      {metric_card("Engines", str(configured_engine_count), "Configured locally", "tone-green")}
    </section>

    <section class="dashboard-grid">
      <div class="panel wide">
        <div class="panel-header">
          <div>
            <h2>Recent scans</h2>
            <p>{total_filtered_scans} matching scans across {len(scans)} manual submissions.</p>
          </div>
          <div class="panel-actions">
            {delete_actions}
          </div>
        </div>
        {render_recent_scan_filters(q, status_filter, verdict_filter)}
        {render_recent_scan_pagination(page=current_page, total_pages=total_pages, total_items=total_filtered_scans, page_size=page_size, query=q, status_filter=status_filter, verdict_filter=verdict_filter)}
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
              {render_recent_scan_rows(paginated_scans, can_select=can_manage_scans, results_by_scan=results_by_scan, empty_message=empty_message)}
            </tbody>
          </table>
        </div>
        {render_recent_scan_pagination(page=current_page, total_pages=total_pages, total_items=total_filtered_scans, page_size=page_size, query=q, status_filter=status_filter, verdict_filter=verdict_filter)}
      </div>

      {render_worker_status_panel(worker_status)}
    </section>
    """
    return page_shell("Scan Dashboard", "dashboard", body, user)


@app.get("/batches/{batch_id}", response_class=HTMLResponse)
def batch_detail_page(request: Request, batch_id: int) -> str:
    user = require_user(request)
    batch = get_scan_batch(batch_id)
    if batch is None:
        raise HTTPException(status_code=404, detail="Batch not found.")
    back_href = "/" if batch.source == "manual" else "/api-ledger"
    active_nav = "dashboard" if batch.source == "manual" else "api_ledger"
    return render_batch_detail_page(
        request,
        user,
        batch,
        active_nav=active_nav,
        back_href=back_href,
    )


def render_api_payload_page(
    *,
    title: str,
    active_nav: str,
    scan: ScanRecord,
    payload: dict[str, object],
    user: UserRecord,
) -> str:
    pretty_payload = html.escape(json.dumps(payload, indent=2, ensure_ascii=True))
    body = f"""
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>{html.escape(title)}</h2>
          <p>Session-authenticated view of the normalized API payload for scan #{scan.id}.</p>
        </div>
        <div class="panel-actions">
          <a class="secondary-action compact-action" href="/api-ledger">Back to ledger</a>
          <a class="secondary-action compact-action" href="/scans/{scan.id}">Open scan</a>
        </div>
      </div>
      <div class="report-raw-grid">
        <section class="panel wide">
          <div class="panel-header compact">
            <div>
              <h2>Payload</h2>
              <p>{html.escape(scan.original_filename)} | {html.escape(scan.sha256)}</p>
            </div>
            {verdict_pill(scan.verdict)}
          </div>
          <div class="table-wrap">
            <pre>{pretty_payload}</pre>
          </div>
        </section>
      </div>
    </section>
    """
    return page_shell(title, active_nav, body, user)


def render_api_batch_payload_page(
    *,
    title: str,
    active_nav: str,
    batch: ScanBatchRecord,
    payload: dict[str, object],
    user: UserRecord,
) -> str:
    pretty_payload = html.escape(json.dumps(payload, indent=2, ensure_ascii=True))
    body = f"""
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>{html.escape(title)}</h2>
          <p>Session-authenticated view of the normalized API payload for batch #{batch.id}.</p>
        </div>
        <div class="panel-actions">
          <a class="secondary-action compact-action" href="/api-ledger">Back to ledger</a>
          <a class="secondary-action compact-action" href="/api-ledger/batches/{batch.id}">Open batch</a>
        </div>
      </div>
      <div class="report-raw-grid">
        <section class="panel wide">
          <div class="panel-header compact">
            <div>
              <h2>Payload</h2>
              <p>{html.escape(batch.original_filename)} | mode {html.escape(batch.archive_mode)}</p>
            </div>
            {status_pill(batch.status)}
          </div>
          <div class="table-wrap">
            <pre>{pretty_payload}</pre>
          </div>
        </section>
      </div>
    </section>
    """
    return page_shell(title, active_nav, body, user)


def render_api_batch_rows(
    scans: list[ScanRecord],
    results_by_scan: dict[int, list[EngineResultRecord]],
) -> str:
    if not scans:
        return '<tr><td class="empty-cell" colspan="7">No scans are attached to this batch yet.</td></tr>'

    rows = []
    for scan in scans:
        engine_results = results_by_scan.get(scan.id, [])
        timing = build_scan_timing_payload(scan)
        queue_wait = format_duration_ms(timing["queue_wait_ms"])
        processing_duration = format_duration_ms(timing["processing_duration_ms"])
        total_duration = format_duration_ms(timing["total_duration_ms"])
        relative_path = scan.relative_path or scan.original_filename
        rows.append(
            f"""
            <tr>
              <td>
                <div class="table-link">
                  <strong>{html.escape(relative_path)}</strong>
                  <small>{html.escape(scan.original_filename)}</small>
                </div>
              </td>
              <td>{scan_role_pill(scan.scan_role)}</td>
              <td>{status_pill(scan.status)}</td>
              <td>
                {verdict_pill(scan.verdict)}
                <small class="status-detail">{html.escape(detection_summary_text_for_scan(scan, engine_results))}</small>
              </td>
              <td>
                <strong>Q {html.escape(queue_wait)}</strong>
                <small>P {html.escape(processing_duration)} | T {html.escape(total_duration)}</small>
              </td>
              <td>{html.escape(scan.created_at)}</td>
              <td>
                <div class="table-actions">
                  <a class="secondary-action compact-action" href="/scans/{scan.id}">Open</a>
                  <a class="secondary-action compact-action" href="/api-ledger/scans/{scan.id}/status">Status JSON</a>
                  <a class="secondary-action compact-action" href="/api-ledger/scans/{scan.id}/result">Result JSON</a>
                </div>
              </td>
            </tr>
            """
        )
    return "\n".join(rows)


def render_batch_detail_page(
    request: Request,
    user: UserRecord,
    batch: ScanBatchRecord,
    *,
    active_nav: str,
    back_href: str,
) -> str:
    refresh_scan_batch_counts(batch.id)
    batch = get_scan_batch(batch.id)
    if batch is None:
        raise HTTPException(status_code=404, detail="Batch not found.")

    all_scans = list_scan_batch_scans(batch.id, limit=5000)
    page_items, current_page, total_pages, total_items = paginate_scans(all_scans, page=int(request.query_params.get("page", "1") or "1"), page_size=25)
    results_by_scan = list_engine_results_by_scan_ids([scan.id for scan in page_items])
    batch_summary = build_scan_batch_summary_payload(request, batch, all_scans)
    pagination_base = f"/batches/{batch.id}" if active_nav == "dashboard" else f"/api-ledger/batches/{batch.id}"

    body = f"""
    <section class="metric-grid">
      {metric_card("Batch items", str(batch.total_items), "Container plus extracted child scans")}
      {metric_card("Running", str(batch.running_items), "Currently queued or running members", "tone-blue")}
      {metric_card("Completed", str(batch.completed_items), "Terminal successful members", "tone-green")}
      {metric_card("Malicious", str(batch.malicious_items), "Members with high or critical verdict", "tone-red")}
    </section>

    <section class="dashboard-grid">
      <div class="panel wide">
        <div class="panel-header">
          <div>
            <h2>Batch #{batch.id}</h2>
            <p>{html.escape(batch.original_filename)} | mode {html.escape(batch.archive_mode)} | {total_items} scans attached</p>
          </div>
          <div class="panel-actions">
            <a class="secondary-action compact-action" href="{html.escape(back_href)}">Back</a>
            <a class="secondary-action compact-action" href="/api-ledger/batches/{batch.id}/status">Status JSON</a>
            <a class="secondary-action compact-action" href="/api-ledger/batches/{batch.id}/result">Result JSON</a>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <tbody>
              <tr><th>Source</th><td>{html.escape(batch.source)}</td><th>Status</th><td>{status_pill(batch.status)}</td></tr>
              <tr><th>Container scan</th><td>{html.escape(str(batch_summary["container_scan_id"] or "-"))}</td><th>Last update</th><td>{html.escape(batch.updated_at)}</td></tr>
            </tbody>
          </table>
        </div>
        {render_scan_pagination(base_path=pagination_base, page=current_page, total_pages=total_pages, total_items=total_items, page_size=25, query="", status_filter="all", verdict_filter="all")}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>Role</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>Timing</th>
                <th>Submitted</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {render_api_batch_rows(page_items, results_by_scan)}
            </tbody>
          </table>
        </div>
        {render_scan_pagination(base_path=pagination_base, page=current_page, total_pages=total_pages, total_items=total_items, page_size=25, query="", status_filter="all", verdict_filter="all")}
      </div>
      {render_worker_status_panel(get_worker_status())}
    </section>
    """
    return page_shell(f"Batch #{batch.id}", active_nav, body, user)


@app.get("/api-ledger", response_class=HTMLResponse)
def api_ledger(
    request: Request,
    q: str = "",
    status: str = "all",
    verdict: str = "all",
    page: int = 1,
    message: str = "",
    error: str = "",
) -> str:
    user = require_user(request)
    can_delete_scans = user.role == ROLE_ADMIN
    page_size = 25
    status_filter = status if status in {"all", "active", "queued", "running", "completed", "partial", "failed"} else "all"
    verdict_filter = verdict if verdict in {"all", "pending", "info", "metadata_only", "low", "medium", "high", "critical"} else "all"
    total_items = count_scan_history(
        source="api",
        query=q,
        status_filter=status_filter,
        verdict_filter=verdict_filter,
        include_child_scans=False,
    )
    total_pages = max(1, (total_items + page_size - 1) // page_size) if total_items else 1
    current_page = min(normalize_dashboard_page(page), total_pages)
    scans = list_scan_history(
        source="api",
        query=q,
        status_filter=status_filter,
        verdict_filter=verdict_filter,
        limit=page_size,
        offset=(current_page - 1) * page_size,
        include_child_scans=False,
    )
    results_by_scan = list_engine_results_by_scan_ids([scan.id for scan in scans])
    counts = get_scan_counts(source="api", include_child_scans=False)
    queue_metrics = get_queue_metrics()
    empty_message = "No API scans match the current filters." if total_items else "No API scans have been submitted yet."
    notice_html = (
        page_notice("API ledger updated", message, "success")
        + page_notice("Action blocked", error, "danger")
    )
    delete_actions = (
        """
            <form id="bulk-delete-form" action="/api-ledger/scans/delete" method="post" data-bulk-delete-form data-action-form data-preserve-scroll></form>
            <button class="toolbar-delete" type="submit" form="bulk-delete-form" data-bulk-delete data-busy-label="Deleting..." hidden>Delete selected</button>
        """
        if can_delete_scans
        else '<span class="pill neutral">Read-only history</span>'
    )
    select_header = (
        """
                <th class="select-cell">
                  <input class="row-checkbox" type="checkbox" data-select-all aria-label="Select all scans" title="Select all scans">
                </th>
        """
        if can_delete_scans
        else ""
    )
    body = f"""
    {notice_html}
    <section class="metric-grid">
      {metric_card("API scans", str(counts["total"]), "Persisted API submissions")}
      {metric_card("Active", str(counts["running"]), "Queued or running API jobs", "tone-blue")}
      {metric_card("Failed", str(counts["failed"]), "API jobs with terminal failure", "tone-red")}
      {metric_card("Global queue", str(queue_metrics["active"]), "All queued or running jobs", "tone-green")}
    </section>

    <section class="dashboard-grid">
      <div class="panel wide">
        <div class="panel-header">
          <div>
            <h2>API ledger</h2>
            <p>{total_items} matching API scans. This view is optimized for lookups, exclusions, and raw payload review.</p>
          </div>
          <div class="panel-actions">
            {delete_actions}
          </div>
        </div>
        {render_scan_filters(
            action_path="/api-ledger",
            reset_path="/api-ledger",
            query=q,
            status_filter=status_filter,
            verdict_filter=verdict_filter,
            verdict_options=[
                ("all", "All verdicts"),
                ("pending", "Pending"),
                ("info", "Info"),
                ("metadata_only", "Metadata only"),
                ("low", "Low"),
                ("medium", "Medium"),
                ("high", "High"),
                ("critical", "Critical"),
            ],
        )}
        {render_scan_pagination(base_path="/api-ledger", page=current_page, total_pages=total_pages, total_items=total_items, page_size=page_size, query=q, status_filter=status_filter, verdict_filter=verdict_filter)}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                {select_header}
                <th>File</th>
                <th>SHA256</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>Timing</th>
                <th>Meta</th>
                <th>Submitted</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {render_api_ledger_rows(scans, results_by_scan, empty_message, can_delete=can_delete_scans)}
            </tbody>
          </table>
        </div>
        {render_scan_pagination(base_path="/api-ledger", page=current_page, total_pages=total_pages, total_items=total_items, page_size=page_size, query=q, status_filter=status_filter, verdict_filter=verdict_filter)}
      </div>

      {render_worker_status_panel(get_worker_status())}
    </section>
    """
    return page_shell("API Ledger", "api_ledger", body, user)


@app.get("/api-ledger/batches/{batch_id}", response_class=HTMLResponse)
def api_ledger_batch_detail(
    request: Request,
    batch_id: int,
    page: int = 1,
) -> str:
    user = require_user(request)
    batch = get_scan_batch(batch_id)
    if batch is None or batch.source != "api":
        raise HTTPException(status_code=404, detail="API batch not found.")
    return render_batch_detail_page(
        request,
        user,
        batch,
        active_nav="api_ledger",
        back_href="/api-ledger",
    )


@app.get("/api-ledger/batches/{batch_id}/status", response_class=HTMLResponse)
def api_ledger_batch_status_payload(request: Request, batch_id: int) -> str:
    user = require_user(request)
    batch = get_scan_batch(batch_id)
    if batch is None or batch.source != "api":
        raise HTTPException(status_code=404, detail="API batch not found.")
    refresh_scan_batch_counts(batch_id)
    batch = get_scan_batch(batch_id)
    if batch is None:
        raise HTTPException(status_code=404, detail="API batch not found.")
    scans = list_scan_batch_scans(batch_id, limit=5000)
    payload = build_scan_batch_status_payload(request, batch, scans)
    return render_api_batch_payload_page(
        title=f"API Batch Status Payload #{batch.id}",
        active_nav="api_ledger",
        batch=batch,
        payload=payload,
        user=user,
    )


@app.get("/api-ledger/batches/{batch_id}/result", response_class=HTMLResponse)
def api_ledger_batch_result_payload(request: Request, batch_id: int) -> str:
    user = require_user(request)
    batch = get_scan_batch(batch_id)
    if batch is None or batch.source != "api":
        raise HTTPException(status_code=404, detail="API batch not found.")
    refresh_scan_batch_counts(batch_id)
    batch = get_scan_batch(batch_id)
    if batch is None:
        raise HTTPException(status_code=404, detail="API batch not found.")
    scans = list_scan_batch_scans(batch_id, limit=5000)
    payload = build_scan_batch_result_payload(request, batch, scans)
    return render_api_batch_payload_page(
        title=f"API Batch Result Payload #{batch.id}",
        active_nav="api_ledger",
        batch=batch,
        payload=payload,
        user=user,
    )


@app.get("/api-ledger/scans/{scan_id}/status", response_class=HTMLResponse)
def api_ledger_status_payload(request: Request, scan_id: int) -> str:
    user = require_user(request)
    scan = get_scan(scan_id)
    if scan is None or scan.source != "api":
        raise HTTPException(status_code=404, detail="API scan not found.")
    payload = build_api_scan_status_payload(request, scan)
    return render_api_payload_page(
        title=f"API Status Payload #{scan.id}",
        active_nav="api_ledger",
        scan=scan,
        payload=payload,
        user=user,
    )


@app.get("/api-ledger/scans/{scan_id}/result", response_class=HTMLResponse)
def api_ledger_result_payload(request: Request, scan_id: int) -> str:
    user = require_user(request)
    scan = get_scan(scan_id)
    if scan is None or scan.source != "api":
        raise HTTPException(status_code=404, detail="API scan not found.")
    payload = build_api_scan_result_payload(request, scan)
    return render_api_payload_page(
        title=f"API Result Payload #{scan.id}",
        active_nav="api_ledger",
        scan=scan,
        payload=payload,
        user=user,
    )


@app.post("/api-ledger/scans/{scan_id}/delete")
async def delete_api_ledger_scan(request: Request, scan_id: int) -> RedirectResponse:
    require_admin(request)
    scan = get_scan(scan_id)
    if scan is None or scan.source != "api":
        return RedirectResponse(
            url=redirect_url("/api-ledger", error="API scan not found."),
            status_code=303,
        )
    deleted_scan = delete_scan_record(scan_id)
    if deleted_scan is None:
        return RedirectResponse(
            url=redirect_url("/api-ledger", error="API scan not found."),
            status_code=303,
        )
    return RedirectResponse(
        url=redirect_url("/api-ledger", message=f"Deleted API scan {deleted_scan.original_filename}."),
        status_code=303,
    )


@app.post("/api-ledger/scans/delete")
async def delete_selected_api_scans(
    request: Request,
    scan_ids: list[int] = Form(default=[]),
) -> RedirectResponse:
    require_admin(request)
    if not scan_ids:
        return RedirectResponse(
            url=redirect_url("/api-ledger", error="No API scans were selected."),
            status_code=303,
        )

    deleted_count = 0
    for scan_id in scan_ids:
        scan = get_scan(scan_id)
        if scan is None or scan.source != "api":
            continue
        if delete_scan_record(scan_id) is not None:
            deleted_count += 1

    if deleted_count == 0:
        return RedirectResponse(
            url=redirect_url("/api-ledger", error="No matching API scans could be deleted."),
            status_code=303,
        )

    message = f"Deleted {deleted_count} API scan." if deleted_count == 1 else f"Deleted {deleted_count} API scans."
    return RedirectResponse(
        url=redirect_url("/api-ledger", message=message),
        status_code=303,
    )


@app.get("/system", response_class=HTMLResponse)
def system_page(request: Request, message: str = "", error: str = "") -> str:
    user = require_admin(request)
    return render_system_page(user, message=message, error=error)


@app.post("/system/retention/run")
def run_retention_cleanup(request: Request) -> RedirectResponse:
    require_admin(request)
    policy = retention_policy_from_env()
    cutoff_value = retention_cutoff_value(policy)
    if cutoff_value is None:
        return RedirectResponse(
            url=redirect_url("/system", error="Retention cleanup is disabled."),
            status_code=303,
        )

    expired_scans = list_scans_older_than(cutoff_value, limit=policy.batch_size)
    deleted_count = 0
    for scan in expired_scans:
        if delete_scan_record(scan.id) is not None:
            deleted_count += 1

    message = (
        "No scans matched the retention policy."
        if deleted_count == 0
        else f"Deleted {deleted_count} expired scan." if deleted_count == 1
        else f"Deleted {deleted_count} expired scans."
    )
    return RedirectResponse(url=redirect_url("/system", message=message), status_code=303)


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
def new_scan(request: Request, message: str = "", error: str = "") -> str:
    user = require_user(request)
    notice_html = (
        page_notice("Ready for review", message, "success")
        + page_notice("Upload blocked", error, "danger")
    )
    body = f"""
    {notice_html}
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
    try:
        scan = await enqueue_scan_from_upload(
            sample,
            case_name=case_name,
            priority=priority,
            note=note,
            source="manual",
        )
    except HTTPException as exc:
        if exc.status_code == 413:
            return RedirectResponse(
                url=redirect_url("/scans/new", error=str(exc.detail)),
                status_code=303,
            )
        raise

    return RedirectResponse(url=f"/scans/{scan.id}", status_code=303)


@app.post(
    "/api/v1/scans",
    summary="Submit a file scan",
    description="Accepts a sample upload, creates a scan job, and optionally waits for completion.",
)
async def api_create_scan(
    request: Request,
    sample: UploadFile = File(...),
    case_name: str = Form("Unassigned"),
    priority: str = Form("Normal"),
    note: str = Form(""),
    archive_mode: str = Form(DEFAULT_ARCHIVE_MODE),
    wait_seconds: int = Form(0),
) -> JSONResponse:
    require_api_token(request)
    scan = await enqueue_scan_from_upload(
        sample,
        case_name=case_name,
        priority=priority,
        note=note,
        source="api",
        archive_mode=archive_mode,
    )
    applied_wait_seconds = normalized_api_wait_seconds(wait_seconds)
    current_scan = await wait_for_terminal_scan(scan.id, applied_wait_seconds)
    if current_scan is None:
        raise HTTPException(status_code=500, detail="Scan could not be loaded.")

    headers = {"Location": str(request.url_for("api_scan_status", scan_id=scan.id))}
    status_payload = build_api_scan_status_payload(request, current_scan)
    status_payload["accepted"] = True
    status_payload["wait_seconds_applied"] = applied_wait_seconds

    if scan_is_terminal(current_scan):
        status_payload["detail"] = "Scan completed within the requested wait window."
        status_payload["result"] = build_api_scan_result_payload(request, current_scan)
        return JSONResponse(status_payload, status_code=200, headers=headers)

    headers["Retry-After"] = str(configured_api_retry_after_seconds())
    status_payload["detail"] = "Scan accepted and still processing."
    return JSONResponse(status_payload, status_code=202, headers=headers)


@app.get(
    "/api/v1/scans/{scan_id}",
    name="api_scan_status",
    summary="Fetch scan status",
    description="Returns queue state, engine progress, and links for a previously submitted scan.",
)
def api_scan_status(request: Request, scan_id: int) -> JSONResponse:
    require_api_token(request)
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return JSONResponse(build_api_scan_status_payload(request, scan))


@app.get(
    "/api/v1/scans/{scan_id}/result",
    name="api_scan_result",
    summary="Fetch final scan result",
    description="Returns the normalized result payload after a scan reaches a terminal state.",
)
def api_scan_result(request: Request, scan_id: int) -> JSONResponse:
    require_api_token(request)
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if not scan_is_terminal(scan):
        payload = build_api_scan_status_payload(request, scan)
        payload["detail"] = "Scan result is not ready yet."
        return JSONResponse(
            payload,
            status_code=409,
            headers={"Retry-After": str(configured_api_retry_after_seconds())},
        )
    return JSONResponse(build_api_scan_result_payload(request, scan))


@app.get(
    "/api/v1/batches/{batch_id}",
    name="api_batch_status",
    summary="Fetch batch status",
    description="Returns batch-level queue state and per-scan status for an archive-backed API submission.",
)
def api_batch_status(request: Request, batch_id: int) -> JSONResponse:
    require_api_token(request)
    refresh_scan_batch_counts(batch_id)
    batch = get_scan_batch(batch_id)
    if batch is None or batch.source != "api":
        raise HTTPException(status_code=404, detail="Batch not found.")
    scans = list_scan_batch_scans(batch_id, limit=5000)
    return JSONResponse(build_scan_batch_status_payload(request, batch, scans))


@app.get(
    "/api/v1/batches/{batch_id}/result",
    name="api_batch_result",
    summary="Fetch final batch result",
    description="Returns per-scan normalized results for a completed archive-backed API submission.",
)
def api_batch_result(request: Request, batch_id: int) -> JSONResponse:
    require_api_token(request)
    refresh_scan_batch_counts(batch_id)
    batch = get_scan_batch(batch_id)
    if batch is None or batch.source != "api":
        raise HTTPException(status_code=404, detail="Batch not found.")
    scans = list_scan_batch_scans(batch_id, limit=5000)
    if not scan_batch_is_terminal(batch):
        payload = build_scan_batch_status_payload(request, batch, scans)
        payload["detail"] = "Batch result is not ready yet."
        return JSONResponse(
            payload,
            status_code=409,
            headers={"Retry-After": str(configured_api_retry_after_seconds())},
        )
    return JSONResponse(build_scan_batch_result_payload(request, batch, scans))


def delete_scan_record(scan_id: int) -> ScanRecord | None:
    deleted_scan = delete_scan(scan_id)
    if deleted_scan is not None:
        delete_sample_file(deleted_scan)
    return deleted_scan


@app.post("/scans/delete")
async def delete_selected_scans(
    request: Request,
    scan_ids: list[int] = Form(default=[]),
) -> RedirectResponse:
    require_admin(request)
    if not scan_ids:
        return RedirectResponse(url=redirect_url("/", error="No scans were selected."), status_code=303)
    deleted_count = 0
    for scan_id in scan_ids:
        if delete_scan_record(scan_id) is not None:
            deleted_count += 1
    message = f"Deleted {deleted_count} scan." if deleted_count == 1 else f"Deleted {deleted_count} scans."
    return RedirectResponse(url=redirect_url("/", message=message), status_code=303)


@app.post("/scans/{scan_id}/delete")
async def delete_single_scan(request: Request, scan_id: int) -> RedirectResponse:
    require_admin(request)
    deleted_scan = delete_scan_record(scan_id)
    if deleted_scan is None:
        return RedirectResponse(url=redirect_url("/", error="Scan not found."), status_code=303)
    return RedirectResponse(
        url=redirect_url("/", message=f"Deleted scan {deleted_scan.original_filename}."),
        status_code=303,
    )


@app.post("/scans/{scan_id}/retry")
async def retry_single_scan(request: Request, scan_id: int) -> RedirectResponse:
    require_user(request)
    if not retry_scan_job_record(scan_id):
        return RedirectResponse(
            url=redirect_url(f"/scans/{scan_id}", error="Only completed or failed scans can be retried."),
            status_code=303,
        )
    create_scan_engine_jobs(scan_id, enabled_engines())
    return RedirectResponse(
        url=redirect_url(f"/scans/{scan_id}", message="Scan was queued for another run."),
        status_code=303,
    )


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
def scan_detail(request: Request, scan_id: int, message: str = "", error: str = "") -> str:
    user = require_user(request)
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    engine_results = list_engine_results(scan.id)
    return render_scan_result(scan, engine_results, user, message=message, error=error)


@app.get("/engines", response_class=HTMLResponse)
def engines(request: Request, message: str = "", error: str = "", target: str = "") -> str:
    user = require_admin(request)
    return render_engines_page(user, message=message, error=error, target=target)


@app.post("/engines/add")
def add_engine_route(request: Request, adapter_key: str = Form(...)) -> RedirectResponse:
    require_admin(request)
    try:
        add_engine(adapter_key)
    except KeyError as exc:
        return RedirectResponse(
            url=redirect_url("/engines", error="Unknown engine adapter."),
            status_code=303,
        )
    definition = adapter_definition(adapter_key)
    return RedirectResponse(
        url=redirect_url("/engines", message=f"Added {definition.label}.", target=adapter_key),
        status_code=303,
    )


@app.post("/engines/{adapter_key}/toggle")
def toggle_engine_route(request: Request, adapter_key: str) -> RedirectResponse:
    require_admin(request)
    toggle_engine(adapter_key)
    updated_instance = next(
        (engine for engine in configured_engines() if engine.adapter_key == adapter_key),
        None,
    )
    if updated_instance is None:
        return RedirectResponse(url=redirect_url("/engines", error="Engine not found."), status_code=303)
    state_label = "enabled" if updated_instance.enabled else "disabled"
    return RedirectResponse(
        url=redirect_url(
            "/engines",
            message=f"{updated_instance.display_name} {state_label}.",
            target=adapter_key,
        ),
        status_code=303,
    )


@app.post("/engines/{adapter_key}/delete")
def delete_engine_route(request: Request, adapter_key: str) -> RedirectResponse:
    require_admin(request)
    definition = adapter_definition(adapter_key)
    remove_engine(adapter_key)
    return RedirectResponse(
        url=redirect_url("/engines", message=f"Removed {definition.label}."),
        status_code=303,
    )


@app.post("/engines/{adapter_key}/test", response_class=HTMLResponse)
def test_engine_route(request: Request, adapter_key: str) -> str:
    user = require_admin(request)
    matches = [engine for engine in configured_engines() if engine.adapter_key == adapter_key]
    if not matches:
        raise HTTPException(status_code=404, detail="Engine not found.")
    health = engine_health(matches[0])
    tone = health_tone_for(adapter_key, health)
    notice_tone = tone if tone in {"success", "warning", "danger"} else "success"
    return render_engines_page(
        user,
        health_overrides={adapter_key: health},
        message=str(health["detail"]),
        target=adapter_key,
        notice_tone=notice_tone,
    )


@app.post("/engines/clamav/config")
def save_clamav_config(
    request: Request,
    clamav_host: str = Form(""),
    clamav_port: str = Form("3310"),
    clamav_command: str = Form("clamscan"),
    clamav_timeout_seconds: str = Form("60"),
    clamav_max_file_size_bytes: str = Form("0"),
) -> RedirectResponse:
    require_admin(request)
    update_engine_config(
        "clamav",
        {
            "host": clamav_host.strip(),
            "port": clamav_port.strip() or "3310",
            "command": clamav_command.strip() or "clamscan",
            "timeout_seconds": clamav_timeout_seconds.strip() or "60",
            "max_file_size_bytes": clamav_max_file_size_bytes.strip() or "0",
        },
    )
    return RedirectResponse(
        url=redirect_url("/engines", message="Saved ClamAV settings.", target="clamav"),
        status_code=303,
    )


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
    return RedirectResponse(
        url=redirect_url("/engines", message="Saved YARA settings.", target="yara"),
        status_code=303,
    )


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
    return RedirectResponse(
        url=redirect_url(
            "/engines",
            message="Saved Microsoft Defender settings.",
            target="microsoft_defender",
        ),
        status_code=303,
    )


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
            saved_rule_name = rule_file.filename
        else:
            save_yara_rule(rule_name, rule_body.encode("utf-8"))
            saved_rule_name = rule_name
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return RedirectResponse(
        url=redirect_url("/engines", message=f"Saved YARA rule {saved_rule_name}.", target="yara"),
        status_code=303,
    )


@app.post("/engines/yara/rules/{rule_name}/toggle")
def toggle_yara_rule_route(request: Request, rule_name: str) -> RedirectResponse:
    require_admin(request)
    try:
        toggled_path = toggle_yara_rule(rule_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="YARA rule not found.") from exc
    action = "Disabled" if str(toggled_path.name).endswith(".disabled") else "Enabled"
    return RedirectResponse(
        url=redirect_url("/engines", message=f"{action} YARA rule {rule_name}.", target="yara"),
        status_code=303,
    )


@app.post("/engines/yara/rules/{rule_name}/delete")
def delete_yara_rule_route(request: Request, rule_name: str) -> RedirectResponse:
    require_admin(request)
    try:
        delete_yara_rule(rule_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="YARA rule not found.") from exc
    return RedirectResponse(
        url=redirect_url("/engines", message=f"Deleted YARA rule {rule_name}.", target="yara"),
        status_code=303,
    )


def render_engines_page(
    user: UserRecord,
    health_overrides: dict[str, dict[str, str | bool]] | None = None,
    message: str = "",
    error: str = "",
    target: str = "",
    notice_tone: str = "success",
) -> str:
    overrides = health_overrides or {}
    notice_html = (
        page_notice("Engine action complete", message, notice_tone)
        + page_notice("Action blocked", error, "danger")
    )
    engine_cards_html = "\n".join(
        render_engine_card(instance, overrides, focus_adapter_key=target) for instance in configured_engines()
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
    {notice_html}
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
