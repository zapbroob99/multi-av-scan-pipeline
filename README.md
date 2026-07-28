# MASP - Multi AV Scan Pipeline

MASP is a self-hosted file scanning orchestration MVP. It is not a malware
scanner itself; it stores submitted samples, normalizes engine outputs, and
shows analyst-friendly scan results.

## Current capabilities

- Web UI for file intake and scan history
- Bearer-token file scan API for service-to-service integrations
- RFC 3507 ICAP REQMOD gateway for synchronous upload gating
- Automation decision output: allow, block, review, or wait
- PostgreSQL persistence for samples, scan jobs, and engine results in Docker
- SQLite fallback for lightweight local development
- Static Metadata engine
- ClamAV integration via clamd TCP when configured
- Local `clamscan` fallback when clamd is not configured
- YARA integration via local CLI and rules in `rules/`
- Database-backed scan queue with separate worker processes
- Bulk scan deletion with stored sample cleanup

## Single-host pilot deployment

The first supported deployment target is a single Ubuntu 22.04 VM running the
admin/API application, ICAP gateway, one Linux worker, ClamAV, YARA, Static
Metadata, and a private bundled PostgreSQL. Defender and ESET are intentionally
out of scope for this first pilot and can be added later as remote workers.

Use [docs/deployment/PILOT.md](docs/deployment/PILOT.md) for host requirements,
release packaging, installation, acceptance checks, ICAP configuration,
backup, restore, and upgrades. Do not treat the local-development compose stack
below as the production runbook.

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
- `postgres`: shared PostgreSQL database exposed on port `5432`
- `clamav`: ClamAV daemon exposed on port `3310`

The Linux worker and ICAP gateway are available behind explicit profiles.
Start the complete local scan stack with:

```powershell
docker compose --profile linux-worker --profile icap up -d --build
```

Use the Linux worker for Linux-compatible engines such as ClamAV and YARA. Do
not use it when you want Microsoft Defender via local CLI to process jobs,
because Defender requires a Windows worker.

The ICAP profile publishes `icap://127.0.0.1:1344/masp` by default. It scans
REQMOD request bodies through the same database-backed queue and engine workers
as the API. The pilot profile forces fail-closed behavior, blocks review
decisions, and rejects archive uploads because clean archive members are not yet
independently scanned on the synchronous path.

For throughput experiments, MASP also provides a split Linux worker profile:

```powershell
docker compose --profile linux-worker-split up --build
```

This starts separate Linux workers for `static_metadata`, `clamav`, and `yara`
so benchmark runs can compare one serial Linux worker against engine-specific
Linux workers.

The app image installs the `yara` CLI. Docker Compose mounts the local `rules/`
directory into `/app/rules`, so rule edits can be picked up without rebuilding
the image.

Docker uses PostgreSQL for shared state. This lets the web app, Linux worker,
and Windows Defender worker all read and write the same scan queue. SQLite is
still available when `MASP_DATABASE_URL` is not set, but do not use SQLite for a
hybrid Docker + Windows worker deployment.

The app uses these environment variables in Docker:

```text
MASP_DATABASE_URL=postgresql://masp:masp_dev_password@postgres:5432/masp
MASP_CLAMD_HOST=clamav
MASP_CLAMD_PORT=3310
MASP_CLAMD_TIMEOUT_SECONDS=180
MASP_CLAMD_READY_TIMEOUT_SECONDS=30
MASP_SCAN_PARTIAL_RESULTS_MAX_WAIT_SECONDS=120
MASP_YARA_RULES_DIR=/app/rules
MASP_API_TOKEN=replace-with-a-long-random-token
MASP_API_MAX_WAIT_SECONDS=15
MASP_API_RETRY_AFTER_SECONDS=2
MASP_UPLOAD_MAX_BYTES=0
MASP_RETENTION_DAYS=0
MASP_RETENTION_BATCH_SIZE=100
MASP_WORKER_POLL_SECONDS=2
MASP_ENGINE_JOB_QUEUE_ENABLED=1
MASP_ENGINE_JOB_LEASE_SECONDS=120
MASP_LEGACY_SCAN_WORKER_FALLBACK_ENABLED=0
MASP_WORKER_TIMING_EVENTS_ENABLED=1
MASP_DB_POOL_ENABLED=1
MASP_DB_POOL_MIN=0
MASP_DB_POOL_MAX=4
MASP_DB_POOL_TIMEOUT_SECONDS=30
MASP_ICAP_SERVICE_NAME=masp
MASP_ICAP_WAIT_SECONDS=30
MASP_ICAP_MAX_BYTES=0
MASP_ICAP_FAIL_MODE_CLOSED=1
MASP_ICAP_BLOCK_ARCHIVES=1
MASP_ICAP_READ_TIMEOUT_SECONDS=60
MASP_ICAP_BODY_TIMEOUT_SECONDS=300
MASP_ICAP_MAX_CONNECTIONS=100
MASP_ICAP_ADMISSION_TIMEOUT_SECONDS=10
```

PostgreSQL connections are reused through a per-process pool (`psycopg_pool`).
`MASP_DB_POOL_MAX` applies per process, so keep
`process count x MASP_DB_POOL_MAX` below the Postgres `max_connections` limit.
Set `MASP_DB_POOL_ENABLED=0` to restore the previous one-connection-per-query
behavior. Details and the measured effect are in
`docs/architecture/WORKER_THROUGHPUT_OPTIMIZATION.md`.

`MASP_RETENTION_DAYS=0` disables retention cleanup. Set it above `0` to enable
manual old scan cleanup from the System page. Cleanup deletes both scan records
and their stored sample files, up to `MASP_RETENTION_BATCH_SIZE` records per run.
`MASP_WORKER_TIMING_EVENTS_ENABLED=1` records compact worker orchestration
events for throughput analysis; set it to `0` to disable those records.
`MASP_ENGINE_JOB_QUEUE_ENABLED=1` enables the only supported worker execution
path: the fenced engine-job queue. The worker refuses to start when this value
is `0` or when `MASP_LEGACY_SCAN_WORKER_FALLBACK_ENABLED=1`, because the legacy
scan-centric path bypasses the crash-safe finalization state machine.

## API

MASP's asynchronous service-integration surface is the file scan API:

- `POST /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `GET /api/v1/scans/{scan_id}/result`

Use `POST /api/v1/scans` as an asynchronous submission endpoint. The response
includes status and result links, `result_ready`, and a recommended polling
interval when the scan is still running.

Integration examples and response details live in
[docs/integrations/API_SCAN_GATEWAY.md](docs/integrations/API_SCAN_GATEWAY.md).

For local throughput testing, use the benchmark helper against the same public
API instead of a private debug endpoint:

```powershell
python tools/benchmark_scans.py `
  --base-url http://localhost:8000 `
  --token $env:MASP_API_TOKEN `
  --sample C:\path\to\eicar.com `
  --requests 20 `
  --concurrency 5 `
  --poll-interval 1 `
  --timeout 300 `
  --output benchmark-results\latest.json
```

The script submits real scans through `POST /api/v1/scans`, polls
`GET /api/v1/scans/{id}`, and prints aggregate latency plus partial-coverage
summary data. The JSON output also includes `engine_timings_ms`, which
summarizes per-engine `duration_ms` values from the sanitized public status API.
Internal worker events are deliberately not exposed through `/api/v1`.

## ICAP

Start the local gateway with the `icap` profile, then probe it from the host:

```powershell
python tools\icap_probe.py --host 127.0.0.1 --port 1344 --options
python tools\icap_probe.py --host 127.0.0.1 --port 1344 --expect allow
python tools\icap_probe.py --host 127.0.0.1 --port 1344 --eicar --expect block
```

The service URI is `icap://<host>:1344/masp`; use `REQMOD` for upload gating.
ICAP is unencrypted TCP, so expose it only on a private network and restrict it
to approved client IPs. A production client must retain the upload on block,
review, timeout, connection failure, or malformed response. The full deployment
and ICAP configuration contract is in
[docs/deployment/PILOT.md](docs/deployment/PILOT.md).

ClamAV may take time to initialize and download/update signatures on first
startup. MASP waits briefly for clamd to accept TCP connections before recording
the ClamAV result. If clamd is still unreachable after that readiness window,
MASP records the ClamAV result as skipped instead of failing the upload.
The Docker ClamAV service raises `StreamMaxLength`, `MaxFileSize`, and
`MaxScanSize` to `512M` so larger samples can be streamed to clamd. If clamd
still closes the stream during a scan, MASP records a failed ClamAV result with
a limit/timeout hint instead of reporting it as a generic connection failure.

If one or more enabled engines never report back, MASP does not leave the scan
running forever. After the orchestration wait window expires, missing engines
are recorded as `skipped` and the scan completes with partial coverage.

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
$env:MASP_DATABASE_URL="postgresql://masp:masp_dev_password@127.0.0.1:5432/masp"
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

Each worker only writes results for engines it can run. A scan remains
non-terminal through `queued`, `running`, and crash-safe `finalizing` states
until every required engine result and any archive-finalization work is settled.
