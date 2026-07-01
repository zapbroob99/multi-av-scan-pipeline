import html
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.database import (
    create_sample,
    create_scan_job,
    get_scan,
    get_scan_counts,
    init_db,
    list_recent_scans,
)
from app.models import ScanRecord
from app.services.ingest import store_upload


app = FastAPI(
    title="Multi-Engine File Scanning Pipeline",
    description=(
        "Self-hosted orchestration layer for file scanning engines, "
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
        <title>{title} | Sentinel Pipeline</title>
        <link rel="stylesheet" href="/static/css/app.css">
      </head>
      <body>
        <div class="app-shell">
          <aside class="sidebar">
            <a class="brand" href="/">
              <span class="brand-mark">SP</span>
              <span>
                <strong>Sentinel Pipeline</strong>
                <small>On-prem analysis</small>
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
                <p class="eyebrow">Multi-engine orchestration</p>
                <h1>{title}</h1>
              </div>
            </header>
            <main class="content">
              {body}
            </main>
          </div>
        </div>
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
    tone = "success" if status == "completed" else "warning"
    return f'<span class="pill {tone}">{html.escape(status.title())}</span>'


def verdict_pill(verdict: str) -> str:
    tone = "neutral" if verdict == "metadata_only" else "warning"
    return f'<span class="pill {tone}">{html.escape(display_verdict(verdict))}</span>'


def render_recent_scan_rows(scans: list[ScanRecord]) -> str:
    if not scans:
        return '<tr><td class="empty-cell" colspan="6">No scans submitted yet.</td></tr>'

    rows = []
    for scan in scans:
        rows.append(
            f"""
            <tr>
              <td>
                <a class="table-link" href="/scans/{scan.id}">
                  <strong>{html.escape(scan.original_filename)}</strong>
                  <small>{html.escape(scan.case_name)}</small>
                </a>
              </td>
              <td><code>{short_hash(scan.sha256)}</code></td>
              <td>{status_pill(scan.status)}</td>
              <td>{verdict_pill(scan.verdict)}</td>
              <td>{html.escape(scan.created_at)}</td>
              <td><a class="row-action" href="/scans/{scan.id}">View</a></td>
            </tr>
            """
        )
    return "\n".join(rows)


def render_scan_result(scan: ScanRecord) -> str:
    body = f"""
    <section class="result-layout">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h2>Scan intake completed</h2>
            <p>The sample was stored locally and cryptographic hashes were calculated.</p>
          </div>
          <span class="pill success">Completed</span>
        </div>
        <div class="summary-grid">
          <div><span>Filename</span><strong>{html.escape(scan.original_filename)}</strong></div>
          <div><span>Case</span><strong>{html.escape(scan.case_name)}</strong></div>
          <div><span>Priority</span><strong>{html.escape(scan.priority)}</strong></div>
          <div><span>Size</span><strong>{format_bytes(scan.size_bytes)}</strong></div>
          <div><span>Content type</span><strong>{html.escape(scan.content_type)}</strong></div>
          <div><span>Status</span><strong>{html.escape(display_verdict(scan.verdict))}</strong></div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header compact">
          <h2>Hashes</h2>
          <span class="pill neutral">Static metadata</span>
        </div>
        <dl class="hash-list">
          <div><dt>MD5</dt><dd><code>{html.escape(scan.md5)}</code></dd></div>
          <div><dt>SHA1</dt><dd><code>{html.escape(scan.sha1)}</code></dd></div>
          <div><dt>SHA256</dt><dd><code>{html.escape(scan.sha256)}</code></dd></div>
        </dl>
      </div>

      <div class="panel wide">
        <div class="panel-header compact">
          <h2>Next pipeline stage</h2>
          <span class="pill warning">Not scanned yet</span>
        </div>
        <ol class="step-list">
          <li><span>1</span><strong>Worker queue</strong><small>Persist scan jobs and dispatch adapters</small></li>
          <li><span>2</span><strong>Engine adapters</strong><small>Run ClamAV and static analyzers</small></li>
          <li><span>3</span><strong>Risk scoring</strong><small>Calculate explainable analyst verdicts</small></li>
        </ol>
      </div>
    </section>
    """
    return page_shell("Scan Result", "dashboard", body)


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
          <span class="pill neutral">MVP</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
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
      <form class="panel upload-panel" action="/scans" method="post" enctype="multipart/form-data">
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
          <input id="sample-file" name="sample" type="file">
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
          <button class="primary-action" type="submit">Create Scan</button>
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
            <div><strong>ClamAV</strong><small>Signature scan adapter</small></div>
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

    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: int) -> str:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return render_scan_result(scan)


@app.get("/engines", response_class=HTMLResponse)
def engines() -> str:
    body = """
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Engine registry</h2>
          <p>Configured adapters and local availability.</p>
        </div>
        <span class="pill success">Node online</span>
      </div>
      <div class="engine-table">
        <div class="engine-row">
          <span class="engine-logo">CL</span>
          <div><strong>ClamAV</strong><small>clamd TCP adapter</small></div>
          <span class="pill success">Enabled</span>
        </div>
        <div class="engine-row">
          <span class="engine-logo">ST</span>
          <div><strong>Static Metadata</strong><small>Local file inspection</small></div>
          <span class="pill success">Enabled</span>
        </div>
        <div class="engine-row muted">
          <span class="engine-logo">YR</span>
          <div><strong>YARA</strong><small>Rule engine adapter</small></div>
          <span class="pill neutral">Planned</span>
        </div>
        <div class="engine-row muted">
          <span class="engine-logo">AV</span>
          <div><strong>Commercial AV</strong><small>Vendor API adapter</small></div>
          <span class="pill neutral">Not configured</span>
        </div>
      </div>
    </section>
    """
    return page_shell("Engines", "engines", body)
