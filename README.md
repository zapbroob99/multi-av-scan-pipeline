# MASP - Multi AV Scan Pipeline

MASP is a self-hosted file scanning orchestration MVP. It is not a malware
scanner itself; it stores submitted samples, normalizes engine outputs, and
shows analyst-friendly scan results.

## Current capabilities

- Web UI for file intake, archive-aware scans, scan history, reports, and exports
- Local admin/analyst accounts plus optional LDAP/Active Directory login with
  directory-group role mapping
- Admin-managed engine configuration, scan policy, users, YARA rules, and a
  focused persisted security audit trail
- Interactive **Scan Hash** reputation lookup and hash-only VirusTotal
  enrichment for explicitly initiated manual file scans
- Bearer-token file scan API for service-to-service integrations
- RFC 3507 ICAP REQMOD gateway for synchronous upload gating
- Source-aware engine eligibility: token/quota-consuming adapters are excluded
  from REST and ICAP automation
- Automation decision output: allow, block, review, or wait
- PostgreSQL persistence for samples, scan jobs, and engine results in Docker
- SQLite fallback for lightweight local development
- Static Metadata engine
- ClamAV integration via clamd TCP when configured
- Local `clamscan` fallback when clamd is not configured
- YARA integration via local CLI and rules in `rules/`
- Database-backed scan queue with separate worker processes
- Multi-instance engine foundation: separately named and configured ClamAV and
  Defender deployments produce instance-specific queue jobs
- Retention and bulk scan deletion with stored sample cleanup

## Documentation

- [Pilot deployment](docs/deployment/PILOT.md)
- [Production deployment](docs/deployment/PRODUCTION.md)
- [API scan gateway](docs/integrations/API_SCAN_GATEWAY.md)
- [ICAP gateway](docs/integrations/ICAP_GATEWAY.md)
- [Engine support matrix](docs/integrations/SUPPORT_MATRIX.md)
- [Scan execution flow](docs/architecture/SCAN_EXECUTION_FLOW.md)
- [Engine deployment and worker agent architecture](docs/architecture/ENGINE_DEPLOYMENT_AND_WORKER_AGENT.md)
- [Audit trail](docs/security/AUDIT_TRAIL.md)
- [LDAP and Active Directory authentication](docs/security/LDAP_AUTHENTICATION.md)

## Tests

```powershell
python -m unittest discover -s tests
```

Some tests are gated on a throwaway PostgreSQL and skip without one, because
they cover behavior SQLite cannot express (`SELECT ... FOR UPDATE`,
`SKIP LOCKED`, and the concurrency races around job leasing and scan
finalization). Point them at a disposable database — never a real one, they drop
and recreate the `public` schema:

```powershell
docker run -d --name masp-pg -p 55432:5432 `
  -e POSTGRES_DB=masptest -e POSTGRES_USER=masptest -e POSTGRES_PASSWORD=masptestpw `
  postgres:16-alpine
$env:MASP_TEST_POSTGRES_URL="postgresql://masptest:masptestpw@127.0.0.1:55432/masptest"
python -m unittest discover -s tests
```

With the URL set, nothing should skip. On a deployed pilot host, run the same
gate through `./deploy/pilot/run_gated_tests.sh`, which creates and destroys its
own throwaway database.

## Security posture

MASP stores real malware by design, so the sample store and the processes that
parse it are treated as the blast radius:

- The app, worker, and ICAP services run as an unprivileged fixed uid with
  `cap_drop: ALL`, `no-new-privileges`, and a read-only image filesystem; only
  the storage and rules mounts and `/tmp` are writable.
- Samples are stored non-executable and are never served over HTTP; MASP itself
  never executes a sample — engines only read it.
- Archive extraction rejects absolute paths, drive prefixes, `..` segments, and
  non-regular members (symlinks, devices), and enforces count, size, and nesting
  limits. Members are extracted to a staging directory and promoted atomically.
- ICAP defaults to fail-closed: a timeout, oversize body, malformed request, or
  engine error blocks the upload rather than releasing it.
- Admin > Audit provides a focused application-level trail for authentication,
  user/password administration, policy and engine changes, retention, and
  destructive scan deletion. Routine navigation, scan/hash submission, and API
  polling are excluded. Request bodies and secrets are never recorded. See
  [docs/security/AUDIT_TRAIL.md](docs/security/AUDIT_TRAIL.md) for its integrity
  and best-effort delivery boundaries.
- Optional LDAP/Active Directory login uses TLS search plus user bind, maps
  directory groups to MASP roles, and keeps local break-glass accounts. LDAP
  passwords are never stored. See
  [docs/security/LDAP_AUTHENTICATION.md](docs/security/LDAP_AUTHENTICATION.md).
- The sample store needs a host antivirus exclusion, or endpoint protection will
  quarantine the evidence. See
  [docs/deployment/PILOT.md](docs/deployment/PILOT.md#host-antivirus-exclusion).

## Single-host pilot deployment

The first supported deployment target is a single Ubuntu 22.04 VM running the
admin/API application, ICAP gateway, one Linux worker, ClamAV, YARA, Static
Metadata, and a private bundled PostgreSQL. Defender and ESET are intentionally
out of scope for this first pilot and can be added later as remote workers.

The queue supports multiple configured instances of worker-deployed adapters.
The Engines catalog requires a deployment-specific instance name and explicit
adapter setup before it creates or enables a new instance; example values shown
in the form are guidance, not preselected configuration.
Remote workers can use the authenticated HTTPS control API without PostgreSQL
credentials or shared visibility of the sample store. Defender hosts have an SCM
service package, lifecycle tooling, integrity verification, and an evidence-producing
acceptance runner. The remote Defender path remains `lab` until its real-host matrix
and organizational signing gate pass. See the
[engine deployment architecture](docs/architecture/ENGINE_DEPLOYMENT_AND_WORKER_AGENT.md).

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
MASP_CLAMD_STREAM_MAX_LENGTH=512M
MASP_CLAMD_MAX_FILE_SIZE=512M
MASP_SCAN_PARTIAL_RESULTS_MAX_WAIT_SECONDS=120
MASP_YARA_RULES_DIR=/app/rules
MASP_API_TOKEN=replace-with-a-long-random-token
MASP_SECRET_ENCRYPTION_KEY=CHANGE_ME_FERNET_KEY
MASP_API_MAX_WAIT_SECONDS=15
MASP_API_RETRY_AFTER_SECONDS=2
MASP_METRICS_ENABLED=1
MASP_UPLOAD_MAX_BYTES=0
MASP_LDAP_ENABLED=0
MASP_LDAP_HOST=
MASP_LDAP_PORT=636
MASP_LDAP_TLS_MODE=ldaps
MASP_LDAP_BIND_DN=
MASP_LDAP_BIND_PASSWORD=
MASP_LDAP_BASE_DN=
MASP_LDAP_ADMIN_GROUP_DN=
MASP_LDAP_ANALYST_GROUP_DN=
MASP_VIRUSTOTAL_ENABLED=0
MASP_VIRUSTOTAL_API_KEY=
MASP_RETENTION_DAYS=0
MASP_RETENTION_BATCH_SIZE=100
MASP_WORKER_POLL_SECONDS=2
MASP_WORKER_NODE_ID=local-worker
MASP_WORKER_NODE_NAME=Local Worker
MASP_WORKER_AGENT_VERSION=0.1.0
MASP_WORKER_LABELS=site=local,os=linux
MASP_WORKER_CAPACITY=1
MASP_WORKER_HEALTH_INTERVAL_SECONDS=60
MASP_WORKER_HEALTH_LEASE_SECONDS=1200
MASP_WORKER_HEALTH_CHECKS_PER_TICK=2
MASP_WORKER_ENROLLMENT_TOKEN=
MASP_WORKER_AGENT_TOKEN_TTL_DAYS=
MASP_WORKER_CONTROL_REQUIRE_HTTPS=0
MASP_WORKER_TRANSPORT=database
MASP_WORKER_CONTROL_URL=
MASP_WORKER_AGENT_TOKEN_FILE=
MASP_WORKER_CONTROL_CA_FILE=
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

This is the common runtime subset, not the complete configuration reference.
Use [.env.example](.env.example), [.env.pilot.example](.env.pilot.example), or
[.env.production.example](.env.production.example) for all LDAP, VirusTotal,
engine, timeout, pool, and deployment settings. Keep bind passwords, API keys,
and `MASP_SECRET_ENCRYPTION_KEY` outside version control.

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

API and ICAP submissions use only engines eligible for automation. Registry
adapters marked `consumes_external_quota` are excluded before engine jobs are
created and are checked again by workers. VirusTotal is currently in this
class, so it remains available for manual file scans and **Scan Hash**, but it
does not consume tokens for REST file/hash requests or ICAP traffic.

Two operational endpoints sit alongside it: `GET /health` is an unauthenticated
liveness probe, and `GET /metrics` serves Prometheus text-format metrics (queue
depth and latency, worker liveness, per-engine results) behind the same API
bearer token. Alert conditions are listed in
[docs/deployment/PRODUCTION.md](docs/deployment/PRODUCTION.md#monitoring-and-alerting).

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
ICAP is unencrypted TCP, so expose it only on a private network. Restrict
sources with the **host firewall** — that is the authoritative control.
`MASP_ICAP_ALLOWED_IPS` is defense in depth: it matches the address the gateway
observes, and a container port proxy or NAT can replace every client's address
with one gateway address, leaving the allowlist unable to tell clients apart.
The gateway logs the observed source of each connection and flags private-range
addresses, so this can be confirmed from the real client node.

A production client must retain the upload on block, review, timeout,
connection failure, or malformed response. The full deployment and ICAP
configuration contract is in
[docs/deployment/PILOT.md](docs/deployment/PILOT.md).

ClamAV may take time to initialize and download/update signatures on first
startup. MASP waits briefly for clamd to accept TCP connections before recording
the ClamAV result. If clamd is still unreachable after that readiness window,
MASP records the ClamAV result as skipped instead of failing the upload.
The local Docker ClamAV service raises `StreamMaxLength`, `MaxFileSize`, and
`MaxScanSize` to `512M` so larger samples can be streamed to clamd; the pilot
and production profiles default to `64M`.

clamd enforces those caps itself, so MASP is told about them through
`MASP_CLAMD_STREAM_MAX_LENGTH` / `MASP_CLAMD_MAX_FILE_SIZE` and combines them
with the ClamAV adapter's own `max_file_size_bytes` into a single effective
limit. A sample above that limit is skipped *before* it is streamed, and the
skip names the layer that produced the limit — so raising a cap in one place and
seeing no change is diagnosable from the result. If clamd rejects a sample
anyway (its real configuration drifted from what MASP was told), that is
recorded as a **skipped** ClamAV result naming the setting to raise, not as a
generic failure. A genuine clamd error is still a failure. Either way the scan
counts as missing coverage and lands on `review`, never a clean allow.

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
$env:MASP_WORKER_NODE_ID="windows-defender-01"
$env:MASP_WORKER_NODE_NAME="Windows Defender 01"
$env:MASP_WORKER_LABELS="site=local,os=windows"
python -m app.workers.scan_worker
```

In this mode, uploaded samples are stored through the Docker bind mount and the
Windows worker maps `/app/storage/...` paths back to the local `storage\...`
directory before scanning.

For a remote worker that must not receive PostgreSQL credentials or mount MASP
storage, use the HTTPS control transport. Configure a long random
`MASP_WORKER_ENROLLMENT_TOKEN` on the app, publish MASP through a trusted TLS
endpoint, then enroll once on the worker host:

```powershell
$env:MASP_WORKER_CONTROL_URL="https://masp.example/api/v1/worker-control"
$env:MASP_WORKER_ENROLLMENT_TOKEN="<bootstrap token from the MASP operator>"
$env:MASP_WORKER_ENGINE_KEYS="microsoft_defender"
$env:MASP_WORKER_NODE_ID="windows-defender-01"
$env:MASP_WORKER_NODE_NAME="Windows Defender 01"
$env:MASP_WORKER_LABELS="site=istanbul,os=windows"
python -m app.workers.control_api_worker --enroll
```

The command prints the agent token exactly once. Store it in an ACL-protected
file, remove the enrollment token from the worker environment, and start the
normal worker entry point in control mode:

```powershell
$env:MASP_WORKER_TRANSPORT="control_api"
$env:MASP_WORKER_AGENT_TOKEN_FILE="C:\ProgramData\MASP\agent.token"
python -m app.workers.scan_worker
```

The URL must include `/api/v1/worker-control`. Public CA validation is used by
default; set `MASP_WORKER_CONTROL_CA_FILE` for an internal CA. Plain HTTP is
rejected unless `MASP_WORKER_CONTROL_ALLOW_INSECURE_HTTP=1` is explicitly set
for local development. Re-enrolling the same stable node rotates the credential
and immediately revokes its previous active token. The agent claims jobs and
health checks through the control API, downloads only its currently owned sample,
verifies byte count and SHA-256, scans the temporary file locally, and deletes it.
An administrator can immediately invalidate a node token with **System > Managed
worker nodes > Revoke agent**; the node must enroll again before reconnecting.

For a persistent Defender host, build the Windows bundle with
`python tools\package_windows_worker.py` and use its elevated PowerShell
installer. It runs the agent as the `NT SERVICE\MASPWorker` virtual account,
protects token/config files with Windows ACLs, records rotating logs under
`C:\ProgramData\MASP\Worker`, and provides preflight, acceptance evidence,
rotation, upgrade, and uninstall procedures. The acceptance command verifies the
extracted manifest, service identity/startup, Defender/control health, clean and
EICAR API decisions, and records Authenticode state without exposing tokens. See
[Windows Worker Agent](docs/deployment/WINDOWS_WORKER_AGENT.md). The packaging is
available for lab validation; Defender remains `lab` until the real-host
acceptance matrix and release signing are complete.

The worker assignment in the hybrid Compose setup is:

- Docker/Linux worker: `static_metadata`, `clamav`, `yara`, `virustotal`
- Windows worker: `microsoft_defender`

Each worker registers its stable `MASP_WORKER_NODE_ID` in the System page. An
admin can set a node to `draining` or `disabled`; it remains visible and keeps
sending heartbeats but does not claim new jobs. `active` returns it to service.
Offline is derived from heartbeat age and does not overwrite the admin lifecycle
choice. Keep node ids unique and stable across process or container restarts.

The **System** page also manages worker pools. A selector such as
`site=istanbul,os=windows` matches the labels published through
`MASP_WORKER_LABELS`; every selector field must match. Assign an engine instance
to the pool to constrain its jobs to those nodes. Unbound engines continue to run
on any active worker advertising the adapter. Node capacity is enforced across
all worker processes sharing the same stable node id.

Matching workers also execute periodic health probes for each assigned engine
instance. The result includes service/adapter state, available version metadata,
sample-storage access, failure streak, and the last successful real scan. Engine
cards use these worker reports instead of testing Defender/YARA/ClamAV from the
API host. Clicking **Test connection** on a worker-deployed engine requests a new
worker probe. VirusTotal periodic health never performs a live reputation lookup
and therefore does not spend API quota.

Each worker only writes results for engines it can run. A scan remains
non-terminal through `queued`, `running`, and crash-safe `finalizing` states
until every required engine result and any archive-finalization work is settled.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
full terms and [NOTICE](NOTICE) for attribution.

MASP orchestrates third-party scanning engines rather than embedding them.
ClamAV, YARA, Microsoft Defender, and ESET are obtained and licensed separately
by the deploying party and remain subject to their own terms; Apache-2.0 covers
only the source in this repository. Operators who build container images that
bundle an engine are responsible for that engine's license obligations. See
[NOTICE](NOTICE) for details.
