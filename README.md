# MASP - Multi AV Scan Pipeline

MASP is a self-hosted file scanning orchestration MVP. It is not a malware
scanner itself; it stores submitted samples, normalizes engine outputs, and
shows analyst-friendly scan results.

## Current capabilities

- Web UI for file intake and scan history
- SQLite persistence for samples, scan jobs, and engine results
- Static Metadata engine
- ClamAV integration via clamd TCP when configured
- Local `clamscan` fallback when clamd is not configured
- YARA integration via local CLI and rules in `rules/`
- SQLite-backed scan queue with a separate worker process
- Bulk scan deletion with stored sample cleanup

## Local development

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## Docker Compose

```powershell
docker compose up --build
```

The default compose stack starts:

- `app`: MASP web application
- `clamav`: ClamAV daemon exposed on port `3310`

The Linux container worker is available behind an explicit profile:

```powershell
docker compose --profile linux-worker up --build
```

Use the Linux worker for Linux-compatible engines such as ClamAV and YARA. Do
not use it when you want Microsoft Defender via local CLI to process jobs,
because Defender requires a Windows worker.

The app image installs the `yara` CLI. Docker Compose mounts the local `rules/`
directory into `/app/rules`, so rule edits can be picked up without rebuilding
the image.

The app uses these environment variables in Docker:

```text
MASP_CLAMD_HOST=clamav
MASP_CLAMD_PORT=3310
MASP_CLAMD_TIMEOUT_SECONDS=60
MASP_YARA_RULES_DIR=/app/rules
MASP_WORKER_POLL_SECONDS=2
```

ClamAV may take time to initialize and download/update signatures on first
startup. Until clamd is reachable, MASP records the ClamAV result as skipped
instead of failing the upload.

For local development without Docker, run the web app and worker in separate
terminals:

```powershell
uvicorn app.main:app --reload
python -m app.workers.scan_worker
```

For hybrid Docker + Windows Defender testing, run the web app, ClamAV, and the
Linux worker in Docker, then run a second worker from the Windows virtual
environment:

```powershell
docker compose --profile linux-worker up --build
```

In a separate Windows terminal:

```powershell
.\.venv\Scripts\Activate.ps1
$env:MASP_CLAMD_HOST="127.0.0.1"
$env:MASP_CLAMD_PORT="3310"
$env:MASP_WORKER_ENGINE_KEYS="microsoft_defender"
python -m app.workers.scan_worker
```

In this mode, uploaded samples are stored through the Docker bind mount and the
Windows worker maps `/app/storage/...` paths back to the local `storage\...`
directory before scanning.

The worker capability split is:

- Docker/Linux worker: `static_metadata`, `clamav`, `yara`
- Windows worker: `microsoft_defender`

Each worker only writes results for engines it can run. A scan stays `running`
until every enabled engine has a result.
