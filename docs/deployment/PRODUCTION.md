# MASP Production Deployment Runbook

## What this release runs

- One application image serves the integration API (`/api/v1/*`), remote worker
  control (`/api/v1/worker-control/*`), the browser API (`/api/ui/v1/*`) and the
  browser console at `/console/`, all on port 8000. The image builds the console
  in a Node stage; the host needs neither Node nor a separate web server.
- The server-rendered legacy UI is retired. Former pages such as `/`,
  `/scans/{id}`, `/engines` and `/system` redirect to their console screens, and
  its form endpoints no longer exist. `docker-compose.frontend.yml` (nginx serving
  the same build) remains an optional overlay for local work only.
- Processes: `app`, `worker` (Linux engines), and the opt-in profiles `icap`,
  `deferred` (copies referenced objects), `manifest` (reads upload manifests from
  the same read-only share) and `notifications` (SIEM webhook).

## Upgrade notes

- Rebuild the image and run every API, worker and intake process at the same
  version. Storage grants, user-management locks and fenced scan finalization
  assume no mixed old/new writers.
- Startup migrations add columns, tables and indexes in place and not
  concurrently. On a large existing history, take a backup and schedule a
  maintenance window; see also the one-time `samples.size_bytes` migration in
  the security checklist.
- Tell integrators about two outcome changes: a scan in which no engine
  completed now ends `failed` with no risk score instead of `completed` with zero
  risk, and a clean scan records `info`/0 instead of `low`/10.
  `decision.action` is unchanged.
- `MASP_SHOW_DEV_LOGIN_HINTS` was removed; delete it from the environment file.
- Linux workers also run the built-in `file_type` and `hash_list` engines by
  default. An explicit `MASP_WORKER_ENGINE_KEYS` must list them to run them.
- Set `MASP_FORWARDED_ALLOW_IPS` for the TLS proxy (see
  [TLS reverse proxy](PRODUCTION.md#tls-reverse-proxy)). Without it the console
  cannot save anything behind HTTPS and remote workers are refused.

Console read paths are bounded, which is not a capacity guarantee. Before
promotion, repeat `tools/benchmark_browser_postgres.py` against an isolated
loopback acceptance database with deployment-shaped rows and worker writes; the
tool destroys the target `public` schema and refuses deployed hosts. The history
of individual console slices and their bounds is in
[frontend separation](../architecture/FRONTEND_SEPARATION.md).

Deploys MASP against an **external, operator-managed PostgreSQL** using
`docker-compose.prod.yml` and an operator-managed `.env.production`. The local
`docker-compose.yml` is for development only (bundled dev database, hardcoded
credentials) and must not be used in production.

## Prerequisites

- Docker Engine + Compose v2 on the deployment host.
- A reachable PostgreSQL instance (managed service or dedicated host) and a
  database/user for MASP. MASP creates its own schema on first start. Require
  TLS (`sslmode=require` at minimum; prefer `verify-full` with the corporate
  CA when the database platform supports it).
- A TLS-terminating HTTP reverse proxy or load balancer in front of the REST
  API. MASP itself serves plain HTTP.
- When VirusTotal hash reputation is enabled, a licensed Premium/Enterprise
  API key whose agreement permits this automated organizational workflow, plus
  DNS and outbound HTTPS access from the app container to
  `www.virustotal.com:443`. The Public API is not licensed for this workflow.
- For ICAP, a private routed network path to the MASP host. ICAP is plain RFC
  3507 TCP and must not be treated as HTTP by the API reverse proxy. Restrict it
  with the network firewall, which is the **authoritative** source control:
  `MASP_ICAP_ALLOWED_IPS` matches the address the ICAP process observes, and a
  container port proxy or NAT can replace every client's address with a single
  gateway address, leaving the allowlist unable to distinguish clients. The
  gateway logs the observed source of every connection and flags private-range
  addresses; confirm from the real client node before relying on the allowlist.
- Persistent host directories for sample storage and YARA rules. They must be
  owned by the unprivileged container id `10001:10001` and should be mounted
  `noexec,nosuid,nodev`; the services run as that non-root id with a read-only
  image filesystem and all Linux capabilities dropped.
- A host antivirus exclusion for the storage tree, agreed with the security
  team before the first sample arrives. The directory holds real malware by
  design, so endpoint protection will otherwise quarantine or delete samples,
  corrupting scan records and destroying evidence. Scope the exclusion to the
  path only (for example `/srv/masp/storage/**`), never to the rest of the host,
  and record it in the change ticket so a later endpoint-policy rollout does not
  silently remove it. See the fuller rationale in
  [PILOT.md](PILOT.md#host-antivirus-exclusion).

Required network flows:

| Source | Destination | Port | Purpose |
|---|---|---:|---|
| Storage/API clients | HTTPS proxy or load balancer | 443/TCP | REST scan API |
| Storage ICAP client | MASP private host interface | 1344/TCP | ICAP REQMOD/RESPMOD |
| MASP deployment host | PostgreSQL host | 5432/TCP | Jobs, results, and configuration |
| MASP deployment host | Approved registry/update endpoints | 443/TCP and DNS | Images and ClamAV signatures |
| MASP app container (optional) | `www.virustotal.com` | 443/TCP and DNS | SHA-256-only file reputation lookup |

## 1. Configure

```bash
cp .env.production.example .env.production
# Edit .env.production and set at minimum:
#   MASP_DATABASE_URL   external PostgreSQL DSN
#   MASP_API_TOKEN      strong random token (openssl/secrets)
#   MASP_SECRET_ENCRYPTION_KEY  output of tools/generate_secret_key.py
#   MASP_UPLOAD_MAX_BYTES / MASP_ICAP_MAX_BYTES  size limits
#   MASP_STORAGE_DIR / MASP_RULES_DIR            absolute persistent paths
# Optional environment-based VirusTotal lookup (UI setup is also supported):
#   MASP_VIRUSTOTAL_ENABLED=1
#   MASP_VIRUSTOTAL_API_KEY=<licensed secret>
```

`.env.production` is gitignored. Never commit real credentials. Restrict its
permissions: `chmod 600 .env.production`.

After the app service is restarted, open **Admin > Engines**, add and enable
**VirusTotal**, and configure its API key and policy in the Settings drawer.
UI-managed keys require the same stable `MASP_SECRET_ENCRYPTION_KEY` on both app
and worker, are encrypted in the database, and are never rendered back to the
browser. Use **Test connection** to validate credentials and outbound HTTPS.
VirusTotal participates only in explicitly initiated manual file scans and the
interactive **Scan Hash** page. Its `consumes_external_quota` capability excludes
it from REST file scans, REST hash lookup, and ICAP before engine jobs are
created. File scans send only the SHA-256 computed during intake; no file content
is uploaded to VirusTotal. The engine card reports both this automation exclusion
and configuration state but never renders the API key. In a manual file scan,
no-report, undetected, and stale zero-signal responses are neutral enrichment;
malicious reputation blocks and suspicious reputation reviews. The dedicated
Scan Hash workflow retains its stricter fail-closed reputation policy.

Compose fails fast if `MASP_DATABASE_URL`, `MASP_API_TOKEN`,
`MASP_UPLOAD_MAX_BYTES`, or (for ICAP) `MASP_ICAP_MAX_BYTES` are unset — this
is intentional; there are no insecure defaults for these.

URL-encode special characters in the PostgreSQL username/password. The example
DSN uses `sslmode=require`; use `sslmode=verify-full` only after mounting the
corporate CA and configuring its path in the DSN.

`MASP_UI_READ_TIMEOUT_MS` limits each browser read statement and
`MASP_UI_WRITE_LOCK_TIMEOUT_MS` limits retry/delete row-lock waits. Both default
to 5000 ms and clamp to 100..60000 ms. They use PostgreSQL transaction-local
settings, so a timed-out request cannot poison a later pooled transaction.
Browser reads also force custom plans inside their transaction because archive
parent selectivity varies sharply. Budget expiry returns a sanitized 503; retain
database logs/metrics to distinguish query pressure from lock contention.

`MASP_UI_RAW_OUTPUT_LIMIT` bounds the plain-text engine-output download that
serves recorded output above the 2 MiB browser JSON limit. It defaults to 32 MiB,
clamps to 256 MiB, and is never lowered below the 2 MiB JSON ceiling the download
exists to exceed. Each download reads one recorded result into memory in a worker
thread, so size this against app-container memory and the number of analysts who
may retrieve large output concurrently; it is not a streaming transfer.

`MASP_UI_BATCH_DOWNLOAD_LIMIT` bounds the complete integration batch contract an
operator can download from the console. It defaults to 64 MiB, clamps to 512 MiB,
and is never lowered below the 2 MiB inline ceiling. The document is assembled in
memory from every batch member, which is the same profile the integration API
already has for that batch, but the console makes it operator-reachable: size it
against app-container memory alongside the engine-output download above.

Database pooling is per process. Budget the maximum as:

```text
maximum MASP connections = running MASP process count * MASP_DB_POOL_MAX
```

With `app`, one `worker`, and `icap`, the default maximum is `3 * 4 = 12`.
Each scaled worker adds another `MASP_DB_POOL_MAX` connections. Keep the total
below PostgreSQL `max_connections` after reserving capacity for administration,
monitoring, backups, and migrations.

The REST API defaults to `MASP_APP_BIND=127.0.0.1:8000` and is unreachable from
other hosts until the HTTPS proxy is configured. If that proxy/LB runs on a
different host, bind `MASP_APP_BIND` to a private MASP interface and allow only
the proxy/LB source addresses through the host firewall. ICAP also defaults to
localhost. For a remote ICAP client, set `MASP_ICAP_BIND` to the MASP server's
private interface (or `0.0.0.0:1344` only with host firewall controls) and set
`MASP_ICAP_ALLOWED_IPS` to the approved client addresses.
Bind the gateway to a **Service Clients** identity with
`MASP_ICAP_SERVICE_CLIENT_KEY`. Run separate listeners/containers for consuming
systems that need different engine profiles or ledger ownership; ICAP source IP
is not used as an identity boundary.

### TLS reverse proxy

MASP serves plain HTTP on port 8000. Terminate TLS in front of it and proxy
every path (`/console/`, `/api/`, `/health`) to the app.

- Preserve `Host` and set `X-Forwarded-Proto: https` and `X-Forwarded-For`.
- Set `MASP_FORWARDED_ALLOW_IPS` to the proxy's address as the app container
  sees it: a proxy container's address on the compose network, or, for a proxy on
  the host reaching the published port, that network's Docker gateway. Uvicorn
  ignores forwarded headers from anyone else, and without them the app believes
  it is on plain HTTP: every console save fails the same-origin check and remote
  workers are refused because `MASP_WORKER_CONTROL_REQUIRE_HTTPS=1`. Never use
  `*` on a reachable port.
- Set `MASP_SESSION_SECURE=1` so the session cookie is always `Secure`.
- Body limits: the app itself caps browser JSON at 128 KiB. Only the browser
  upload `POST /api/ui/v1/scans` and the integration upload `POST /api/v1/scans`
  need large bodies, up to `MASP_HTTP_UPLOAD_MAX_BYTES` (default 64 MiB); raise
  the proxy limit for those paths rather than globally.
- ICAP (1344/TCP) is plain TCP and never goes through the HTTP proxy.

## 2. Bring up

REST only:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production up -d --build
```

REST + ICAP:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production \
    --profile icap up -d --build
```

Deferred large-file intake and SIEM delivery are separate opt-in processes:

```bash
# Mount MASP_DEFERRED_SOURCE_DIR from NFS/SMB on the host first.
docker compose -f docker-compose.prod.yml --env-file .env.production \
  --profile deferred --profile notifications up -d --build
```

Set `MASP_DEFERRED_FILESYSTEM_BACKEND_KEY` to the API-visible logical name and
`MASP_DEFERRED_SOURCE_DIR` to its absolute host mount. It is exposed read-only
to the intake container and must be a dedicated integration source. Deferred
storage is fail-closed: map each backend to allowed service-client keys with
`MASP_DEFERRED_BACKEND_CLIENTS_JSON`, for example `{"drive":["drive"]}`. For a
shared root, scope clients to prefixes, for example
`{"shared":{"drive":["drive/inbox"],"large-transfer":["transfer/inbox"]}}`.
Set `MASP_DEFERRED_MAX_BYTES` to the largest deferred object MASP may copy.

Manifest intake runs beside deferred intake when a producer drops a JSON
manifest next to each finished file instead of calling the API:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production \
  --profile deferred --profile manifest --profile notifications up -d --build
```

`MASP_MANIFEST_CLIENT_KEY` must name an existing service client that is granted
`MASP_MANIFEST_BACKEND_KEY` (environment mapping or the client's **Storage**
tab); otherwise every manifest is rejected. The producer gets no feedback, so
watch **System > Deferred intake** for the worker's last cycle, the backlog and
rejected manifests. See
[manifest intake](../architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md#manifest-intake-a-producer-that-never-calls-masp).

### Client storage access rollout

Storage roots and mounts remain deployment-owned. The console's client **Storage**
tab controls only logical backend grants, with optional relative object prefixes.
Existing clients inherit `MASP_DEFERRED_BACKEND_CLIENTS_JSON` until an admin confirms
a custom policy; an empty custom policy denies access. Returning to inheritance is
also an explicit confirmed action. Custom grants never add roots to
`MASP_DEFERRED_STORAGE_BACKENDS_JSON` or alter the single-backend mount variables.

For an existing deployment, upgrade **all API replicas and all deferred-intake
workers to the same version before saving custom grants**. Quiesce deferred
admission/intake during that transition: an older process ignores database grants
and could still use broader environment permissions. Startup creates the new
policy table in place; it neither imports nor deletes environment configuration.
Retain a database backup and inspect pending submissions as part of deployment.

Verify an allowed prefix, a sibling-prefix rejection, explicit deny-all, and
worker rejection of a queued request whose access was revoked. This console screen
does not prove mount reachability. Each process must retain the correct approved
backend key/root configuration; environment inheritance may differ between replicas
if their configuration differs. A copy already authorized and in progress may
continue after an edit. Scan snapshots and completed results remain unchanged.

Before rolling back to an older version, quiesce deferred admission/intake again
and translate the intended effective grants into the old environment configuration
on every API/worker process. Otherwise rollback would silently restore old
environment permissions. The same requirement applies to empty custom deny-all
policies. No automatic downgrade translation is performed.

Set `MASP_SIEM_WEBHOOK_URL` to an HTTPS endpoint; optionally set
`MASP_SIEM_WEBHOOK_SECRET` so each body carries `X-MASP-Signature-SHA256`.
HTTP webhooks are rejected unless `MASP_SIEM_WEBHOOK_ALLOW_HTTP=true` is set
for a lab-only receiver.

The app and worker bootstrap the schema **concurrently and safely** — a
PostgreSQL advisory lock in `init_postgres_db` serializes first-run schema
creation, so no start-ordering workaround is needed.

## 3. Verify

```bash
# Health (through the proxy or the bound port)
curl -fsS http://127.0.0.1:8000/health          # {"status":"ok"}

# Auth is enforced
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/v1/scans/1   # 401

# End-to-end acceptance (clean allow, EICAR block, 202/polling, 409, 413):
python tools/verify_scan_api.py \
    --base-url https://<public-masp-url> \
    --token "$MASP_API_TOKEN" \
    --eicar --archive --expect-max-bytes "$MASP_UPLOAD_MAX_BYTES"

# From an approved client on the private ICAP network:
python tools/icap_probe.py --host <masp-private-ip> --port 1344 --options
python tools/icap_probe.py --host <masp-private-ip> --port 1344 --file README.md
python tools/icap_probe.py --host <masp-private-ip> --port 1344 --eicar
```

ClamAV downloads its signature database on first start (several minutes); its
healthcheck has a 120s start period. Workers wait for clamd to be healthy.

## 4. Operate

- **Logs:** `docker compose -f docker-compose.prod.yml logs -f app worker`
- **Upgrade:** pull/rebuild, then
  `docker compose -f docker-compose.prod.yml --env-file .env.production up -d --build`
- **Scale workers:** `--scale worker=N` (all workers share the external DB).
- **Remote engine hosts:** prefer `MASP_WORKER_TRANSPORT=control_api`. Set a
  strong app-side `MASP_WORKER_ENROLLMENT_TOKEN`, enroll with
  `python -m app.workers.control_api_worker --enroll`, remove the bootstrap
  token from the host, and store the returned agent token in an ACL-protected
  file referenced by `MASP_WORKER_AGENT_TOKEN_FILE`. The control URL includes
  `/api/v1/worker-control`; use `MASP_WORKER_CONTROL_CA_FILE` for an internal CA.
  Re-enrollment rotates and revokes the previous node credential.
  Persistent Defender nodes use the packaged SCM service, integrity verifier,
  lifecycle process, and evidence-producing acceptance runner in
  [Windows Worker Agent](WINDOWS_WORKER_AGENT.md); it remains a lab deployment
  until that document's real-host acceptance and signing gates pass.
- **Node identity:** keep `MASP_WORKER_NODE_ID` stable across restarts and unique
  per independently managed host. Processes intentionally have separate lease
  identities under that node.
- **Maintenance:** set the node to `draining` in **System > Managed worker
  nodes**, wait for its active scan to clear, then stop or upgrade it. `disabled`
  also blocks new claims; `active` restores scheduling.
- **Placement:** publish stable `MASP_WORKER_LABELS`, create exact-match pools in
  **System > Worker pools**, and assign engine instances under **Engine
  placement**. Leave an engine unbound only when any worker advertising that
  adapter is an acceptable target. A disabled pool intentionally has no eligible
  workers.
- **Capacity:** `MASP_WORKER_CAPACITY` is enforced per stable node id across all
  processes on that node. Scale processes and set capacity together; additional
  matching nodes provide failover when one node is full or draining.
- **Engine health:** workers probe matching instances every
  `MASP_WORKER_HEALTH_INTERVAL_SECONDS` and publish service, version, signature,
  storage-access, failure-streak, and last-scan metadata. Alert on
  `masp_engine_node_health{status="unhealthy"}` and sustained
  `masp_engine_node_health_consecutive_failures`; a healthy heartbeat alone is
  not sufficient evidence that the antivirus is usable.
- **Backups:** back up the external PostgreSQL and the `MASP_STORAGE_DIR`
  sample directory as a consistent pair: stop every MASP process that writes
  (`app`, `worker`, `icap`, `deferred-intake`, `manifest-intake`,
  `notification`) first, or take coordinated database and storage snapshots.
  A writer left running changes one side while the other is copied. The
  `clamav-db` volume is a rebuildable cache.
- **Deferred intake:** **System > Deferred intake** shows the manifest worker's
  last cycle, the backlog with its oldest waiting age, rejected manifests and
  submissions that failed before becoming scans. Source outages intentionally
  retain work and retry instead of blocking Drive.
- **Notifications:** monitor `notification_outbox` pending age and delivery
  errors. Webhook downtime never blocks scan completion.

## Monitoring and alerting

`GET /health` is an unauthenticated liveness probe for the load balancer.
`GET /metrics` serves Prometheus text-format metrics and **requires the API
bearer token** (Prometheus sends it via `bearer_token` / `bearer_token_file` in
the scrape config), because the payload reports scan volumes and detection
counts. Set `MASP_METRICS_ENABLED=0` to disable the endpoint entirely.

```yaml
scrape_configs:
  - job_name: masp
    scheme: https
    bearer_token_file: /etc/prometheus/masp-token
    static_configs:
      - targets: ["masp.internal:443"]
```

Alerting matters more here than in a typical service: **ICAP is fail-closed, so
a stalled MASP blocks real user uploads.** A liveness check is not enough — the
process can be up while nothing drains the queue. Alert on at least:

| Condition | Expression | Why |
|---|---|---|
| No worker schedulable | `masp_worker_nodes_schedulable == 0` for 2m | Nodes may still send heartbeats while draining or disabled, but nothing will claim scans; with ICAP fail-closed every upload is blocked. Page on this. |
| Queue stalled | `masp_scan_oldest_queued_age_seconds > 300` for 5m | Distinguishes a stalled queue from a merely busy one. Depth alone does not: a steady depth of 20 is healthy, 20 scans untouched for an hour is an outage. |
| Scan wedged | `masp_scan_oldest_running_age_seconds > 1800` for 10m | A scan running far past any engine timeout indicates a stuck or crashed worker whose lease has not been recovered. |
| Engine failing | `increase(masp_engine_results_total{status="failed"}[15m]) > 0` | One broken engine drags every scan into partial coverage; catch it before the verdicts degrade. |
| Heartbeat aging | `masp_worker_heartbeat_age_seconds > masp_worker_heartbeat_stale_after_seconds` | Early warning that a worker is about to be declared offline. |
| Storage filling | host disk usage on `MASP_STORAGE_DIR` > 80% | Samples are retained until `MASP_RETENTION_DAYS` prunes them; a full disk fails ingest, and with ICAP fail-closed that blocks uploads. |

Also monitor from the host, not from MASP: free disk on the storage
filesystem, and the ClamAV signature age (a silently stale signature database
degrades detection without failing anything).

## Security checklist

For this upgrade, review [phase 1 hardening](../security/HARDENING_PHASE_1.md):
set the total multipart ceiling (`MASP_HTTP_UPLOAD_MAX_BYTES`, default 64 MiB),
replace linked deferred sources with regular files, use non-redirecting control
and webhook URLs, and plan the one-time PostgreSQL `samples.size_bytes` BIGINT
migration. The migration can lock/rewrite the table; schedule it with a backup
and sufficient disk space rather than assuming a zero-downtime restart.

- [ ] `MASP_API_TOKEN` is strong and unique; rotated on a schedule.
- [ ] MASP ports bound to localhost / private network; only the TLS proxy is
      public.
- [ ] `MASP_FORWARDED_ALLOW_IPS` names only the TLS proxy, `MASP_SESSION_SECURE=1`
      is set, and a console save plus a remote worker heartbeat succeed through
      the proxy.
- [ ] PostgreSQL transport uses the database team's required TLS mode and CA;
      the configured pool budget stays below the database connection limit.
- [ ] Remote engine hosts use the HTTPS control transport and have no PostgreSQL
      credential or MASP storage mount. `MASP_WORKER_CONTROL_REQUIRE_HTTPS=1` is
      set on the app, proxy forwarding preserves the HTTPS scheme, agent tokens
      are stored in ACL-protected files, and bootstrap enrollment tokens are
      removed from agents after use.
- [ ] ICAP left at `MASP_ICAP_FAIL_MODE_CLOSED=1` and
      `MASP_ICAP_BLOCK_ON_REVIEW=1` (block on timeout/oversize/error and on
      review verdicts). ICAP is private-network-only and its allowlist is set.
- [ ] `.env.production` is `chmod 600` and never committed.
- [ ] If LDAP is enabled: only LDAPS/StartTLS is used, certificate hostname and
      chain validation pass inside the app container, the bind account is
      read-only, group mappings were tested, and a local break-glass admin still
      works. See [LDAP authentication](../security/LDAP_AUTHENTICATION.md).
- [ ] Upload/ICAP size limits match the integration contract (v1: 50 MiB).
- [ ] Database credentials scoped to the MASP database only.
- [ ] Host antivirus exclusion for the storage tree is in place, scoped to that
      path only, and recorded in the change ticket.
- [ ] ICAP source restriction verified **from the real client node**: the
      gateway's `accepted connection from ...` log shows the client's real
      address, not a NAT/bridge gateway. If it shows a gateway address, the host
      firewall is the only source control — record that decision.
- [ ] Storage and rules directories are owned by `10001:10001`, mode `0750`, on
      a filesystem mounted `noexec,nosuid,nodev`.
- [ ] Services run non-root with `read_only`, `cap_drop: ALL`, and
      `no-new-privileges` (the shipped compose files set this; verify it was not
      overridden locally).
- [ ] `MASP_RETENTION_DAYS` is set above `0`. It defaults to `0`, which keeps
      every sample forever; decide the retention window with the data owner.
      Cleanup applies only to terminal scans, never queued deferred work.
- [ ] Admin > Audit is reviewed after acceptance tests; audit retention, backup,
      export/SIEM forwarding, and legal-hold ownership are documented. The local
      trail is application-level append-only and best effort, not immutable
      storage; see [Audit trail](../security/AUDIT_TRAIL.md).
