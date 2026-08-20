# MASP Production Deployment Runbook

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
Disabling or removing the adapter disables `GET /api/v1/hashes/{sha256}` and
its participation in manual file scans. File scans send only the SHA-256
computed during intake; no file content is uploaded to VirusTotal. The engine
card reports configuration state but never renders the API key.

Compose fails fast if `MASP_DATABASE_URL`, `MASP_API_TOKEN`,
`MASP_UPLOAD_MAX_BYTES`, or (for ICAP) `MASP_ICAP_MAX_BYTES` are unset — this
is intentional; there are no insecure defaults for these.

URL-encode special characters in the PostgreSQL username/password. The example
DSN uses `sslmode=require`; use `sslmode=verify-full` only after mounting the
corporate CA and configuring its path in the DSN.

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
- **Backups:** back up the external PostgreSQL and the `MASP_STORAGE_DIR`
  sample directory. The `clamav-db` volume is a rebuildable cache.

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
| No worker online | `masp_workers_online == 0` for 2m | Nothing will process scans; with ICAP fail-closed every upload is blocked. Page on this. |
| Queue stalled | `masp_scan_oldest_queued_age_seconds > 300` for 5m | Distinguishes a stalled queue from a merely busy one. Depth alone does not: a steady depth of 20 is healthy, 20 scans untouched for an hour is an outage. |
| Scan wedged | `masp_scan_oldest_running_age_seconds > 1800` for 10m | A scan running far past any engine timeout indicates a stuck or crashed worker whose lease has not been recovered. |
| Engine failing | `increase(masp_engine_results_total{status="failed"}[15m]) > 0` | One broken engine drags every scan into partial coverage; catch it before the verdicts degrade. |
| Heartbeat aging | `masp_worker_heartbeat_age_seconds > masp_worker_heartbeat_stale_after_seconds` | Early warning that a worker is about to be declared offline. |
| Storage filling | host disk usage on `MASP_STORAGE_DIR` > 80% | Samples are retained until `MASP_RETENTION_DAYS` prunes them; a full disk fails ingest, and with ICAP fail-closed that blocks uploads. |

Also monitor from the host, not from MASP: free disk on the storage
filesystem, and the ClamAV signature age (a silently stale signature database
degrades detection without failing anything).

## Security checklist

- [ ] `MASP_API_TOKEN` is strong and unique; rotated on a schedule.
- [ ] MASP ports bound to localhost / private network; only the TLS proxy is
      public.
- [ ] PostgreSQL transport uses the database team's required TLS mode and CA;
      the configured pool budget stays below the database connection limit.
- [ ] ICAP left at `MASP_ICAP_FAIL_MODE_CLOSED=1` and
      `MASP_ICAP_BLOCK_ON_REVIEW=1` (block on timeout/oversize/error and on
      review verdicts). ICAP is private-network-only and its allowlist is set.
- [ ] `.env.production` is `chmod 600` and never committed.
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
