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

The compose stack starts:

- `app`: MASP web application
- `worker`: background scan worker that processes queued jobs
- `clamav`: ClamAV daemon exposed on port `3310`

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
