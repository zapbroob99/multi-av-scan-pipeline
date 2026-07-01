import html
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.database import (
    create_engine_result,
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
from app.engines.clamav import check_clamav_health, get_clamav_config, run_clamav_engine
from app.engines.static_metadata import run_static_metadata_engine
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

init_db()

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def page_shell(title: str, active: str, body: str) -> str:
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
        <title>{title} | MASP</title>
        <link rel="stylesheet" href="/static/css/app.css">
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
          const selectAll = document.querySelector("[data-select-all]");
          const scanCheckboxes = document.querySelectorAll("[data-scan-checkbox]");
          const bulkDeleteButton = document.querySelector("[data-bulk-delete]");
          const copyTargets = document.querySelectorAll("[data-copy-value]");

          const updateBulkDeleteVisibility = () => {{
            if (!bulkDeleteButton) {{
              return;
            }}

            const hasSelection = Array.from(scanCheckboxes).some((checkbox) => checkbox.checked);
            bulkDeleteButton.hidden = !hasSelection;
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

          if (selectAll && scanCheckboxes.length) {{
            selectAll.addEventListener("change", () => {{
              scanCheckboxes.forEach((checkbox) => {{
                checkbox.checked = selectAll.checked;
              }});
              updateBulkDeleteVisibility();
            }});
          }}

          if (scanCheckboxes.length) {{
            scanCheckboxes.forEach((checkbox) => {{
              checkbox.addEventListener("change", () => {{
                if (selectAll) {{
                  selectAll.checked = Array.from(scanCheckboxes).every((item) => item.checked);
                }}
                updateBulkDeleteVisibility();
              }});
            }});
            updateBulkDeleteVisibility();
          }}

          if (copyTargets.length) {{
            copyTargets.forEach((target) => {{
              target.addEventListener("click", async () => {{
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
        "completed": "success",
        "skipped": "neutral",
        "failed": "danger",
        "running": "warning",
    }
    tone = tone_by_status.get(status, "warning")
    return f'<span class="pill {tone}">{html.escape(status.title())}</span>'


def verdict_pill(verdict: str) -> str:
    tone_by_verdict = {
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


def render_recent_scan_rows(scans: list[ScanRecord]) -> str:
    if not scans:
        return '<tr><td class="empty-cell" colspan="7">No scans submitted yet.</td></tr>'

    rows = []
    for scan in scans:
        rows.append(
            f"""
            <tr>
              <td class="select-cell">
                <input class="row-checkbox" type="checkbox" name="scan_ids" value="{scan.id}" form="bulk-delete-form" data-scan-checkbox>
              </td>
              <td>
                <a class="table-link" href="/scans/{scan.id}">
                  <strong>{html.escape(scan.original_filename)}</strong>
                  <small>{html.escape(scan.case_name)}</small>
                </a>
              </td>
              <td><code class="copyable" data-copy-value="{html.escape(scan.sha256)}" aria-label="Copy SHA256" title="Copy SHA256">{short_hash(scan.sha256)}</code></td>
              <td>{status_pill(scan.status)}</td>
              <td>{verdict_pill(scan.verdict)}</td>
              <td>{html.escape(scan.created_at)}</td>
              <td>
                <div class="row-actions">
                  <a class="row-action" href="/scans/{scan.id}">View</a>
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
        rows.append(
            f"""
            <tr>
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
            <tr class="raw-output-row">
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

    <section class="result-layout">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h2>Scan summary</h2>
            <p>The sample was stored, analyzed by configured engines, and scored.</p>
          </div>
          {verdict_pill(verdict)}
        </div>
        <div class="summary-grid">
          <div><span>Filename</span><strong>{html.escape(scan.original_filename)}</strong></div>
          <div><span>Case</span><strong>{html.escape(scan.case_name)}</strong></div>
          <div><span>Priority</span><strong>{html.escape(scan.priority)}</strong></div>
          <div><span>Size</span><strong>{format_bytes(scan.size_bytes)}</strong></div>
          <div><span>Content type</span><strong>{html.escape(scan.content_type)}</strong></div>
          <div><span>Risk score</span><strong>{score} / 100</strong></div>
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
    return page_shell("Scan Result", "dashboard", body)


def backfill_missing_assessments(limit: int = 250) -> None:
    for scan in list_recent_scans(limit=limit):
        if scan.risk_score is not None:
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
      {metric_card("Running", str(counts["running"]), "Workers not added yet", "tone-blue")}
      {metric_card("High risk", str(counts["high_risk"]), "All persisted jobs", "tone-red")}
      {metric_card("Engines", "2 / 4", "Configured locally", "tone-green")}
    </section>

    <section class="dashboard-grid">
      <div class="panel wide">
        <div class="panel-header">
          <div>
            <h2>Recent scans</h2>
            <p>Latest submitted samples will appear here.</p>
          </div>
          <div class="panel-actions">
            <form id="bulk-delete-form" action="/scans/delete" method="post"></form>
            <button class="toolbar-delete" type="submit" form="bulk-delete-form" data-bulk-delete hidden>Delete selected</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th class="select-cell">
                  <label class="select-all">
                    <input class="row-checkbox" type="checkbox" data-select-all>
                    <span>Select</span>
                  </label>
                </th>
                <th>File</th>
                <th>SHA256</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>Submitted</th>
                <th>Action</th>
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
          <span class="pill success">2 active</span>
        </div>
        <div class="engine-list">
          <div class="engine-row">
            <span class="engine-logo">CL</span>
            <div><strong>ClamAV</strong><small>clamd TCP or local CLI adapter</small></div>
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
    create_engine_result(scan_id, run_static_metadata_engine(scan))
    create_engine_result(scan_id, run_clamav_engine(scan))
    engine_results = list_engine_results(scan_id)
    assessment = calculate_risk(engine_results)
    update_scan_assessment(scan_id, assessment.verdict, assessment.score)

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


def render_engines_page(clamav_health: dict[str, str | bool] | None = None) -> str:
    clamav_config = get_clamav_config()
    mode = str(clamav_config["mode"])
    health = clamav_health or {
        "ok": False,
        "status": "not tested",
        "detail": "Use Test connection to check the current adapter.",
    }
    health_tone = "success" if health["ok"] else "neutral"
    if health["status"] in {"unreachable", "unexpected"}:
        health_tone = "danger"

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
          <span class="engine-logo">YR</span>
          <div><strong>YARA</strong><small>Rule engine adapter</small></div>
          <span class="pill neutral">Planned</span>
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
