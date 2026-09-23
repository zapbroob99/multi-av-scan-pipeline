# MASP - Multi AV Scan Pipeline

A built-in Hash List engine checks each sample's SHA-256, computed by MASP
itself, against one institution-wide blocklist and allowlist managed at
`/console/engines/hash-list`. A blocklist match is a detection; an allowlist
match is informational and never clears a file other engines flagged. It reads
no sample bytes, so its cost does not depend on file size. The default Linux
worker now runs the File Type and Hash List engines; File Type instances can
also now be created from the Engines page.

Manual and automation scan reports now offer a bounded printable view at
`/console/scans/{id}/print`. Unlike the legacy report it enforces the scan's
source scope and caps each engine's embedded output. Recorded engine output above
the 2 MiB JSON limit downloads as plain text instead of falling back to the legacy
report; `MASP_UI_RAW_OUTPUT_LIMIT` bounds that download (default 32 MiB).

A storage producer that cannot call MASP can now have its uploads scanned by
writing each finished file and then a sibling JSON manifest. MASP polls a
read-only mount for manifests, so the producer holds no credential and waits for
nothing. Start it with `--profile manifest`; see
`docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md`.

Each service client now has a setup view showing whether it is ready to accept
traffic and which endpoints, authorization header and ICAP client key the other
system needs. Ineligible engines explain themselves; credential values are never
shown after they are saved.

A built-in File Type engine now compares each sample's declared extension with
the content family detected from a bounded header read, flagging masquerading
files such as an executable delivered as `.pdf`. It reads at most a few kilobytes
regardless of sample size and reports a finding rather than a malware verdict;
set its mismatch action to `detect` to let a mismatch affect the risk score.

An automation batch larger than the inline JSON view now downloads its complete
integration contract, covering the same 5000 members the API serves;
`MASP_UI_BATCH_DOWNLOAD_LIMIT` bounds it (default 64 MiB).

Admin `/console/audit` now reads the append-only security audit trail with bounded
pages, literal actor/action/target/request-ID search and outcome filtering. The
console cannot edit or delete an event and calculates no total. `/console/about`
gives analysts and admins the product boundary and a non-sensitive runtime
snapshot; service-client totals stay admin-only.

Admin `/console/service-clients` now lists integration clients with bounded pages
and confirms display-name and enabled-state changes. The managed `legacy-default`
client remains read-only. Clicking a client opens a large dialog with Settings,
Connection, Profile routing, Storage and Credentials tabs. Profile routing supports multiple
named profiles, create/rename/disable/delete and default selection, with confirmed
engine assignments and stale-edit protection. Client creation
and credential add/list/revoke now stay in React too. Tokens are supplied by the
admin, never returned, and excluded from the frontend query/mutation cache.
Storage access lets admins retain deployment grants or replace them per client
with whole-backend/prefix permissions; an empty custom list denies access.
Filesystem roots remain deployment-managed and are never exposed by the console.

`/console/api-ledger` now lists API/ICAP submissions for analysts and admins,
with source, exact client ID, unassigned ownership, status, recorded-risk and text
filters. Reads use bounded cursor pages without loading engine output or totals.
Automation reports, bounded engine output, batch overviews and protected single
scan deletion now stay in React. Summary/full JSON/CSV downloads are available
to analysts and admins. Integration payload views and bulk-action parity
is tracked before legacy UI removal.

Admin `/console/scan-policy` now edits API wait time, retry-after interval and the
upload policy cap. Changes use shared backend validation and one atomic save;
blank fields restore environment/default behavior. Deployment HTTP limits still
apply when the upload policy cap is zero. `/console/hash-scan` now provides manual
SHA-256 reputation lookup for analysts/admins, using existing provider quotas and
backend decisions. It uploads no file contents and does not create scan history.

Admin `/console/system` now lists worker nodes with lifecycle controls and agent
credential revocation. `/console/system/pools` adds pool creation, selector/state
editing and protected deletion. All browser UI is planned for incremental frontend migration;
see the [complete UI inventory](docs/architecture/FRONTEND_SEPARATION.md#complete-ui-migration-inventory)
for the remaining screens and cutover gates.
Admin `/console/system/runtime` provides paginated worker runtime and active scans
across submission sources. It refreshes first pages every 30 seconds.
`/console/system/overview` adds cached all-source totals, worker liveness,
read-only retention policy and on-demand historical engine metrics by recorded name.
`/console/system/retention` previews and confirms up to 20 expired inactive records
per run, with per-record protections and explicit deletion/cleanup outcomes.
Historical aggregates and retention previews need
deployment-scale validation before production acceptance.
The console supports light and dark themes from the login screen and signed-in
sidebar. The first visit follows the operating-system preference; an explicit
choice is stored in that browser and applied before React renders.

An independent React/TypeScript console includes a manual Dashboard, admin
Engines management and manual sample submission (`/console/scans/new`).
Manual scan reports now show backend decisions, required-engine coverage and
on-demand technical previews in the console. Archive reports link to paginated
direct-child navigation, literal path search, nested child reports and a bounded
manual batch overview. This lists
registered scans, not a complete/clean archive inventory. `/console/scans/{id}/manage`
offers bounded summary and full JSON/CSV downloads, confirmed retry for analysts/admins
and protected single-scan deletion for admins. Full JSON contains raw engine output,
details and findings; CSV contains normalized report rows. Both have a 2 MiB browser
ceiling and omit sample bytes/storage paths. Admins can confirm deletion of up to
20 selected visible Dashboard scans with per-record stale-state and safety checks;
partial results and storage cleanup failures are reported explicitly. Each engine
result links to a full-output screen in React, with separate 2 MiB source/response
limits and plain-text rendering. Oversized output retains a legacy fallback;
recursive batch actions remain planned. Batch pages use indexed keyset pagination and recorded counters
without loading engine output. Retry queues atomically; acceptance does
not mean completion. Active scans and undelivered notifications are protected.
With the backend running, use `npm --prefix frontend ci` and
`npm --prefix frontend run dev`, then open `http://127.0.0.1:5173/console/dashboard`.
History uses bounded ID-keyset pages; summary totals have a 30-second server cache.
PostgreSQL browser reads and retry/delete locks have transaction-local time budgets;
expired work returns a generic 503 and leaves the transaction rolled back.
The legacy UI is preserved. See [frontend separation](docs/architecture/FRONTEND_SEPARATION.md)
for security, deployment, tests and remaining migration work.
Browser request/response types now come from a versioned OpenAPI snapshot;
`npm --prefix frontend run contracts:check` checks backend/schema/type drift.
See the frontend separation guide for the isolated generator setup. Normal
frontend builds use the checked-in types and do not require Python or a live API.

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
- Admin-managed service clients with hashed/revocable API credentials,
  client-specific engine profiles, immutable routing snapshots, and ledger/API
  isolation
- Deferred large-file references with idempotent `202 Accepted`, read-only
  backend fetch, size/SHA-256 verification, and security-event-only SIEM webhook
  delivery through a transactional outbox
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
- [Service clients and scan profiles](docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md)
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

Browser query/load acceptance has a separate destructive benchmark. It refuses
non-loopback servers and database names without an `_acceptance` or `_test`
suffix, and still requires an explicit schema-reset flag:

```powershell
python tools/benchmark_browser_postgres.py `
  --database-url $env:MASP_TEST_POSTGRES_URL `
  --confirm-reset-public-schema --rows 100000 --archive-rows 100000
```

Never point this command at a deployed MASP database; it drops and recreates the
target database's `public` schema.

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
acceptance runner. Direct-database and HTTPS control-plane clean/EICAR scans have
passed on a Windows 11 development host; the remote Defender path remains `lab`
until its SCM-service, remaining real-host matrix, and organizational signing
gates pass. See the
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
MASP_ICAP_SERVICE_CLIENT_KEY=legacy-default
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
Scans with undelivered SIEM outbox events are preserved until delivery succeeds.
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

Create dedicated integrations from **Service Clients**. Each bearer token maps
to one client. Requests use its default engine profile or select an enabled own
profile using `profile_id` (upload multipart field, deferred JSON field, hash-lookup
query parameter). Status/result reads are limited to that client's scans.
Profile changes affect future submissions; accepted scans and deferred work retain
their routing. Existing environment/settings tokens remain supported and
map to the shared `legacy-default` compatibility client.

API and ICAP submissions use only engines eligible for automation. Registry
adapters marked `consumes_external_quota` are excluded before engine jobs are
created and are checked again by workers. VirusTotal is currently in this
class, so it remains available for manual file scans and **Scan Hash**, but it
does not consume tokens for REST file/hash requests or ICAP traffic.

Large-file clients can use `POST /api/v1/deferred-scans` to submit a
deployment-approved backend/object reference instead of uploading bytes. The
backend must be explicitly mapped to the service client, optional prefix scopes
can constrain shared roots, and the intake worker enforces the configured
maximum byte limit before copying into MASP storage. Client **Storage** settings
can replace `MASP_DEFERRED_BACKEND_CLIENTS_JSON` grants without changing deployment
roots. Upgrade all API and intake processes before using custom grants; see
[storage rollout guidance](docs/deployment/PRODUCTION.md#client-storage-access-rollout).

HTTP uploads authenticate before multipart parsing and have a separate total
body ceiling, `MASP_HTTP_UPLOAD_MAX_BYTES` (64 MiB by default), even when the
sample policy is unlimited. Deferred sources must be regular, non-hardlinked
files without symlink/junction path components. See
[phase 1 hardening and upgrade notes](docs/security/HARDENING_PHASE_1.md), including
the PostgreSQL large-file size migration and remaining scaling validation gates.

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
One ICAP process maps all accepted requests to the service client selected by
`MASP_ICAP_SERVICE_CLIENT_KEY`. Deploy separate listeners for integrations that
need different engine profiles or ledger ownership.
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
available for lab validation. Manual development-host clean/EICAR validation has
passed over the HTTPS control plane, but Defender remains `lab` until installed
SCM-service acceptance, the remaining failure/failover/lifecycle matrix, and
release signing are complete.

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


The React automation report now links to an on-demand integration result JSON
preview for terminal scans. Session-authenticated analyst/admin reads reuse
bounded coherent export admission and the public result projection, with no
private engine output and a 2 MiB serialized response limit. Invalid policy,
active scans and unavailable historical routing fail explicitly. Oversized batch
JSON, remaining UI parity and deployment-scale acceptance are still open; this
adds no worker transport or production support claim.

Automation status JSON now has a separate React view for active/terminal scans.
Scan, polling policy, accepted-instance eligibility and global queue counts use
one bounded repeatable read. Global history aggregates remain subject to statement
timeouts and deployment-scale acceptance; there is no automatic browser polling.
Status requires an accepted engine snapshot, preserves backend coverage decisions
and omits private engine output. Oversized batch JSON and final legacy-action parity remain pending.

React automation batch status/result JSON now supports complete batches of up to
20 members, with exact source/owner consistency and a shared repeatable snapshot.
Result admission caps aggregate engine/snapshot bytes before hydration; response
envelopes stay within 2 MiB. Status reads no engine blobs. Stored counters may lag;
JSON never proves clean coverage by itself. Oversized batches use the overview
and individual reports; complete oversized-payload parity, final legacy-action checks
and deployment acceptance remain open before legacy removal.

Automation archive navigation now stays in React, with direct-child ID-keyset
pages and attempt guards. Parent, nested and upward navigation preserves exact
API/ICAP source, nullable client and batch boundaries. Reads use existing indexed
probes and PostgreSQL snapshot/time budgets, never engine blobs or counter writes.
Empty lists do not prove complete extraction. Final legacy-action and deployment-scale
acceptance remain open; this does not enable recursive deletion or remove legacy.

Admin ledger bulk deletion now confirms at most 20 top-level API/ICAP records with
displayed attempt/job-revision fences. Shared row-locked protections and independent
commits remain authoritative; receipts identify deleted, blocked and cleanup-failed
IDs. Ambiguous writes are never replayed and the UI requires explicit fresh reads
before reselection. This does not delete batches recursively. Ledger revision-probe
load and remaining security/deployment acceptance gates stay open.

Admin React Users now lists bounded local/LDAP metadata and confirms local user
creation with an explicit role and write-only initial password. Password hashes,
directory identifiers and sessions are excluded from list DTOs; shared hashing and
database uniqueness remain authoritative. No automatic creation replay occurs.
Own-password management now uses React Account for local analysts and admins.
Both browser UIs share validation, a password-only conditional update and atomic
session revocation. Local login rechecks the verified hash under a row lock before
creating a session, preventing old-password login from surviving a concurrent
password change/reset. LDAP passwords remain directory-managed. Admin Users now
confirms role changes, optional password resets and removal, with a displayed
management revision checked under shared legacy/browser transaction locks. The
writer rechecks the actor's administrator role, blocks self-management and preserves
the last local administrator across concurrent operations. LDAP shadow removal
revokes MASP sessions but does not disable directory access; a later directory
sign-in may recreate it. Passwords never enter console state or caches; inputs
clear on cancellation/send and uncertain writes are not replayed. Explicit list
refresh is required after management writes. Startup adds the default-zero
users.management_revision column in place; old account data is retained. Roll out
all app processes together so old writers cannot bypass the revision/locking rules.
Startup adds an auth-session user index in place. PostgreSQL password changes use
the existing UI lock timeout; deployment-scale login/revocation acceptance remains
open. No worker topology or engine support status changes.
