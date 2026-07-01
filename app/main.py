import html
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.database import (
    create_sample,
    create_scan_job,
    delete_scan,
    get_scan,
    get_scan_counts,
    init_db,
    list_engine_results,
    list_recent_scans,
    update_scan_assessment,
)
from app.engines.clamav import check_clamav_health, get_clamav_config
from app.engines.yara_engine import check_yara_health, get_yara_config
from app.models import EngineResultRecord, ScanRecord
from app.services.cleanup import delete_sample_file
from app.services.ingest import store_upload
from app.services.scoring import calculate_risk


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
REQUIRED_DETECTION_ENGINES = ("ClamAV", "YARA")

init_db()

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def page_shell(
    title: str,
    active: str,
    body: str,
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
        ("engines", "/engines", "Engines"),
    ]
    nav_html = "\n".join(
        f'<a class="nav-link {"is-active" if key == active else ""}" href="{href}">'
        f'<span class="nav-mark"></span>{label}</a>'
        for key, href, label in nav_items
    )

    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        {refresh_html}
        <title>{title} | MASP</title>
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
            updateBulkDeleteVisibility();
          }};

          const toggleRowSelection = (row) => {{
            setRowSelection(row, !row.classList.contains("is-selected"));
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
            scanRows.forEach((row) => {{
              row.addEventListener("click", (event) => {{
                if (shouldIgnoreRowClick(event)) {{
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
    return detected, len(detection_results)


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

    total = len(REQUIRED_DETECTION_ENGINES)
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

    for engine_name in REQUIRED_DETECTION_ENGINES:
        result = result_map.get(engine_name.lower())
        if result is None:
            unavailable.append(f"{engine_name} missing")
            continue

        if result.status == "completed":
            ran += 1
            continue

        unavailable.append(f"{engine_name} {result.status}")

    return ran, len(REQUIRED_DETECTION_ENGINES), unavailable


def coverage_summary_text(results: list[EngineResultRecord]) -> str:
    ran, total, _ = required_engine_coverage(results)
    return f"{ran} of {total} required engines ran"


def coverage_detail_text(results: list[EngineResultRecord]) -> str:
    _, _, unavailable = required_engine_coverage(results)
    if not unavailable:
        return "All required detection engines completed."
    return "; ".join(unavailable)


def coverage_tone(results: list[EngineResultRecord]) -> str:
    ran, total, unavailable = required_engine_coverage(results)
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
    if tone == "danger":
        return '<span class="pill danger">Engine Failure</span>'
    return '<span class="pill warning">Partial</span>'


def coverage_summary_card_class(scan: ScanRecord, results: list[EngineResultRecord]) -> str:
    return f"summary-wide coverage-summary-card {coverage_tone_for_scan(scan, results)}"


def detection_detail_text(results: list[EngineResultRecord]) -> str:
    names = detected_engine_names(results)
    if names:
        return ", ".join(names)

    _, total = detection_summary(results)
    if total == 0:
        return "Add ClamAV, ICAP, YARA, or vendor adapters to populate this."
    return "No configured detection engine flagged this sample."


def detection_summary_card_class(results: list[EngineResultRecord]) -> str:
    detected, total = detection_summary(results)
    if total == 0:
        return "summary-wide detection-summary-card neutral"
    if detected > 0:
        return "summary-wide detection-summary-card danger"
    return "summary-wide detection-summary-card success"


def render_recent_scan_rows(scans: list[ScanRecord]) -> str:
    if not scans:
        return '<tr><td class="empty-cell" colspan="6">No scans submitted yet.</td></tr>'

    rows = []
    for scan in scans:
        engine_results = list_engine_results(scan.id)
        rows.append(
            f"""
            <tr class="dashboard-scan-row" data-scan-row data-scan-id="{scan.id}" data-scan-url="/scans/{scan.id}" tabindex="0" aria-selected="false">
              <td>
                <div class="table-link">
                  <strong>{html.escape(scan.original_filename)}</strong>
                  <small>{html.escape(scan.case_name)}</small>
                </div>
              </td>
              <td><code class="copyable" data-copy-value="{html.escape(scan.sha256)}" aria-label="Copy SHA256" title="Copy SHA256">{short_hash(scan.sha256)}</code></td>
              <td>{coverage_status_pill(scan, engine_results)}</td>
              <td>{verdict_pill(scan.verdict)}</td>
              <td>
                <span class="detection-count {detection_summary_tone_for_scan(scan, engine_results)}">{html.escape(detection_summary_text_for_scan(scan, engine_results))}</span>
                <small class="coverage-count {coverage_tone_for_scan(scan, engine_results)}">{html.escape(coverage_summary_text_for_scan(scan, engine_results))}</small>
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
    if tone == "success":
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


def render_scan_result(scan: ScanRecord, engine_results: list[EngineResultRecord]) -> str:
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
    return page_shell("Scan Result", "dashboard", body, refresh_seconds=refresh_seconds)


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


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    scans = list_recent_scans()
    counts = get_scan_counts()
    body = f"""
    <section class="metric-grid">
      {metric_card("Samples", str(counts["total"]), "Persisted scan jobs")}
      {metric_card("Active", str(counts["running"]), "Queued or running jobs", "tone-blue")}
      {metric_card("High risk", str(counts["high_risk"]), "All persisted jobs", "tone-red")}
      {metric_card("Engines", "3 / 5", "Configured locally", "tone-green")}
    </section>

    <section class="dashboard-grid">
      <div class="panel wide">
        <div class="panel-header">
          <div>
            <h2>Recent scans</h2>
            <p>Latest submitted samples will appear here.</p>
          </div>
          <div class="panel-actions">
            <form id="bulk-delete-form" action="/scans/delete" method="post" data-bulk-delete-form></form>
            <button class="toolbar-delete" type="submit" form="bulk-delete-form" data-bulk-delete hidden>Delete selected</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>SHA256</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>Engines</th>
                <th>Submitted</th>
              </tr>
            </thead>
            <tbody>
              {render_recent_scan_rows(scans)}
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
    return page_shell("Scan Dashboard", "dashboard", body)


@app.get("/scans/new", response_class=HTMLResponse)
def new_scan() -> str:
    body = """
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
          <span class="pill success">3 active</span>
        </div>
        <div class="engine-list">
          <div class="engine-row">
            <span class="engine-logo">CL</span>
            <div><strong>ClamAV</strong><small>clamd TCP or local CLI adapter</small></div>
            <span class="pill success">Enabled</span>
          </div>
          <div class="engine-row">
            <span class="engine-logo">YR</span>
            <div><strong>YARA</strong><small>Local rule engine adapter</small></div>
            <span class="pill success">Enabled</span>
          </div>
          <div class="engine-row">
            <span class="engine-logo">ST</span>
            <div><strong>Static Metadata</strong><small>Hashes, type, size, headers</small></div>
            <span class="pill success">Enabled</span>
          </div>
          <div class="engine-row muted">
            <span class="engine-logo">AV</span>
            <div><strong>Commercial AV</strong><small>Adapter placeholder</small></div>
            <span class="pill neutral">Pending</span>
          </div>
        </div>
      </aside>
    </section>
    """
    return page_shell("New Scan", "new_scan", body)


@app.post("/scans", response_class=HTMLResponse)
async def create_scan(
    sample: UploadFile = File(...),
    case_name: str = Form("Unassigned"),
    priority: str = Form("Normal"),
    note: str = Form(""),
) -> RedirectResponse:
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
async def delete_selected_scans(scan_ids: list[int] = Form(default=[])) -> RedirectResponse:
    for scan_id in scan_ids:
        delete_scan_record(scan_id)
    return RedirectResponse(url="/", status_code=303)


@app.post("/scans/{scan_id}/delete")
async def delete_single_scan(scan_id: int) -> RedirectResponse:
    delete_scan_record(scan_id)
    return RedirectResponse(url="/", status_code=303)


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: int) -> str:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    engine_results = list_engine_results(scan.id)
    return render_scan_result(scan, engine_results)


@app.get("/engines", response_class=HTMLResponse)
def engines() -> str:
    return render_engines_page()


@app.post("/engines/clamav/test", response_class=HTMLResponse)
def test_clamav_engine() -> str:
    return render_engines_page(clamav_health=check_clamav_health())


@app.post("/engines/yara/test", response_class=HTMLResponse)
def test_yara_engine() -> str:
    return render_engines_page(yara_health=check_yara_health())


def render_engines_page(
    clamav_health: dict[str, str | bool] | None = None,
    yara_health: dict[str, str | bool] | None = None,
) -> str:
    clamav_config = get_clamav_config()
    yara_config = get_yara_config()
    mode = str(clamav_config["mode"])
    health = clamav_health or {
        "ok": False,
        "status": "not tested",
        "detail": "Use Test connection to check the current adapter.",
    }
    health_tone = "success" if health["ok"] else "neutral"
    if health["status"] in {"unreachable", "unexpected"}:
        health_tone = "danger"

    yara_health_state = yara_health or {
        "ok": False,
        "status": "not tested",
        "detail": "Use Test connection to check the current adapter.",
    }
    yara_health_tone = "success" if yara_health_state["ok"] else "neutral"
    if yara_health_state["status"] in {"not configured", "no rules", "unavailable"}:
        yara_health_tone = "danger"

    if mode == "clamd":
        clamav_fields = [
            ("Adapter", "clamd TCP"),
            ("Host", str(clamav_config["host"])),
            ("Port", str(clamav_config["port"])),
            ("Timeout", f'{clamav_config["timeout_seconds"]}s'),
            ("Configured via", "environment"),
        ]
    else:
        clamav_fields = [
            ("Adapter", "local CLI"),
            ("Command", str(clamav_config["command"])),
            ("Timeout", f'{clamav_config["timeout_seconds"]}s'),
            ("Configured via", "environment"),
        ]

    clamav_field_html = "\n".join(
        f"""
        <div>
          <span>{html.escape(label)}</span>
          <strong>{html.escape(value)}</strong>
        </div>
        """
        for label, value in clamav_fields
    )

    yara_fields = [
        ("Adapter", "local CLI"),
        ("Command", str(yara_config["command"])),
        ("Rules", str(yara_config["rules_dir"])),
        ("Rule count", str(yara_config["rule_count"])),
        ("Timeout", f'{yara_config["timeout_seconds"]}s'),
    ]
    yara_field_html = "\n".join(
        f"""
        <div>
          <span>{html.escape(label)}</span>
          <strong>{html.escape(value)}</strong>
        </div>
        """
        for label, value in yara_fields
    )

    body = f"""
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Engine registry</h2>
          <p>Configured adapters, connection settings, and local availability.</p>
        </div>
        <span class="pill success">Node online</span>
      </div>

      <div class="engine-config">
        <div class="engine-config-header">
          <span class="engine-logo">CL</span>
          <div>
            <h2>ClamAV</h2>
            <p>clamd TCP adapter with local CLI fallback.</p>
          </div>
          <span class="pill {health_tone}">{html.escape(str(health["status"]).title())}</span>
        </div>

        <div class="config-grid">
          {clamav_field_html}
        </div>

        <div class="engine-health">
          <div>
            <span>Last check</span>
            <strong>{html.escape(str(health["detail"]))}</strong>
          </div>
          <form action="/engines/clamav/test" method="post">
            <button class="secondary-action" type="submit">Test connection</button>
          </form>
        </div>
      </div>

      <div class="engine-config stacked">
        <div class="engine-config-header">
          <span class="engine-logo">YR</span>
          <div>
            <h2>YARA</h2>
            <p>Local rule engine adapter for pattern-based detection.</p>
          </div>
          <span class="pill {yara_health_tone}">{html.escape(str(yara_health_state["status"]).title())}</span>
        </div>

        <div class="config-grid">
          {yara_field_html}
        </div>

        <div class="engine-health">
          <div>
            <span>Last check</span>
            <strong>{html.escape(str(yara_health_state["detail"]))}</strong>
          </div>
          <form action="/engines/yara/test" method="post">
            <button class="secondary-action" type="submit">Test connection</button>
          </form>
        </div>
      </div>
    </section>

    <section class="panel engine-secondary">
      <div class="panel-header compact">
        <h2>Other adapters</h2>
        <span class="pill neutral">Roadmap</span>
      </div>
      <div class="engine-table">
        <div class="engine-row">
          <span class="engine-logo">ST</span>
          <div><strong>Static Metadata</strong><small>Built-in metadata analyzer</small></div>
          <span class="pill success">Enabled</span>
        </div>
        <div class="engine-row muted">
          <span class="engine-logo">IC</span>
          <div><strong>ICAP</strong><small>Network AV gateway adapter</small></div>
          <span class="pill neutral">Planned</span>
        </div>
        <div class="engine-row muted">
          <span class="engine-logo">API</span>
          <div><strong>Commercial REST AV</strong><small>Vendor API adapter</small></div>
          <span class="pill neutral">Not configured</span>
        </div>
      </div>
    </section>
    """
    return page_shell("Engines", "engines", body)
