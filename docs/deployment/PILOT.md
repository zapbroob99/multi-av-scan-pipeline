# MASP Single-Host Pilot

This runbook deploys a single-host pilot on one Linux VM. The stack
contains the web/admin application, REST API, ICAP gateway, one Linux worker,
ClamAV, YARA, Static Metadata, and a private bundled PostgreSQL. Defender and
ESET are deliberately excluded from this stage.

## Topology

```text
Admin / REST clients --HTTPS/443--> reverse proxy --HTTP/8000--> MASP app
Storage ICAP client ---private TCP/1344-------------------------> MASP ICAP

MASP app + ICAP + worker --> private compose network --> PostgreSQL + ClamAV
                                    |
                                    +--> /srv/masp/storage
```

PostgreSQL has no published host port. Samples use a host directory instead of
an opaque Docker volume so it can later be exported to remote Defender or ESET
workers. Opening PostgreSQL or sharing storage is not required for this pilot.

## Host prerequisites

- Supported enterprise Linux, 8 vCPU, 16 GB RAM, and 150-200 GB disk.
- Docker Engine and Docker Compose v2.
- Static IP, DNS, NTP, and SSH from the administration network.
- Persistent `/srv/masp/storage` and sufficient backup capacity.
- DNS and HTTPS certificate for the admin/REST endpoint.
- Outbound DNS and HTTPS to the approved image registry and ClamAV update
  service, or an institution-managed mirror.
- An agreed host antivirus exclusion for the storage directory (see below).

## Host antivirus exclusion

The storage directory holds real malware by design. Host endpoint protection
will treat it as an active infection: it quarantines or deletes the samples,
which corrupts scan records, destroys evidence, and can leave the platform
looping on files that vanish underneath it. On some products it will also flag
the MASP host itself as compromised.

Before the first sample arrives, agree with the security team on an exclusion
covering the whole storage tree, including the `samples/` and `staging/`
subdirectories:

```text
/srv/masp/storage/**
```

Requirements for the exclusion:

- **Scope it to the path, not to a process**, because samples are written by the
  containerized services and read by the engine containers.
- **Do not exclude the rest of the host.** The exclusion is for the sample store
  only; the operating system, Docker, and MASP binaries stay protected.
- **Compensating control:** the directory is `0750` and owned by the
  unprivileged container id, samples are stored non-executable, and nothing in
  MASP ever executes a sample. The engines are the intended reader.
- **Record it** in the change ticket. An exclusion silently removed during a
  later endpoint-policy rollout is a common cause of "MASP suddenly loses
  samples"; if that symptom appears, re-check the exclusion first.
- Mount the storage filesystem `noexec,nosuid,nodev` so an excluded directory
  still cannot be used to run anything.

Required inbound flows:

| Source | Destination | Port | Purpose |
|---|---|---:|---|
| Admin and REST clients | HTTPS proxy/LB | 443/TCP | Admin UI and REST API |
| Storage ICAP nodes | MASP private IP | 1344/TCP | Upload scanning |
| Admin jump hosts | MASP Linux VM | 22/TCP | Operations |

ICAP is plain RFC 3507 TCP. Keep it on a private network and restrict the host
firewall to the configured storage client nodes.

### The host firewall is the authoritative source restriction

`MASP_ICAP_ALLOWED_IPS` matches the source address the ICAP process *observes*,
which is not always the client's real address. Docker's userland port proxy
rewrites forwarded connections to the bridge gateway, so every client can arrive
as the same private address (`172.18.0.1` was observed on this pilot). When that
happens the allowlist cannot distinguish clients at all — it either accepts
everything that reaches the port or rejects everything — and **only the host
firewall actually restricts sources**. Configure the firewall accordingly and
treat the allowlist as defense in depth, never as the primary control.

MASP cannot determine this from inside the container, so it reports what it
sees. Every connection logs its observed source, and private-range addresses are
flagged as possibly rewritten:

```bash
docker compose -p masp-pilot -f docker-compose.pilot.yml \
  --env-file .env.pilot logs icap | grep -E 'accepted connection|rejected connection'
```

**Verify during acceptance, from the real client node** (not from the host):
connect and read that line. If it shows the client's real address, the allowlist
works as intended. If it shows a gateway address, record that the firewall is
the only source control, and either accept that or make the real address survive
— bind ICAP to the private host interface, disable the userland proxy, or run
the ICAP service with host networking.

## Release contents

The release ZIP is generated from a fixed `masp-pilot` commit/tag:

```bash
python3 tools/package_pilot_release.py --version 0.1.0-pilot.5
```

The bundle contains application source needed for the image build, the pilot
compose/env files, rules, verification tools, and this runbook. It never
contains `.env.pilot`, database contents, samples, or benchmark files.

## Configure

Extract the release under `/opt/masp`, then:

```bash
cd /opt/masp
cp .env.pilot.example .env.pilot
chmod 600 .env.pilot
```

Replace every `CHANGE_ME` value — `MASP_POSTGRES_PASSWORD`, `MASP_API_TOKEN`,
and `MASP_ADMIN_PASSWORD` (the bootstrap admin login). `install.sh` refuses to
proceed while any placeholder remains or a secret is too short. Generate
URL-safe values:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Important settings:

- `MASP_APP_BIND=127.0.0.1:8000` when the HTTPS proxy is on the same host.
  Bind a private interface and firewall it to the proxy when the proxy is
  remote.
- `MASP_ICAP_BIND=<masp-private-ip>:1344` for the storage client connection.
- `MASP_ICAP_SERVICE_CLIENT_KEY=legacy-default` uses compatibility routing. For
  dedicated ownership/routing, first create a client in **Service Clients** and
  set its stable key here. One gateway process maps to one client.
- `MASP_ICAP_ALLOWED_IPS=127.0.0.1,<client-ip-1>,<client-ip-2>`. The current
  allowlist accepts exact IP addresses, not CIDR ranges. Keep loopback for the
  local acceptance probe. **This allowlist is a secondary control — see below.**
- `MASP_STORAGE_DIR=/srv/masp/storage`.
- Keep the 50 MiB upload and ICAP limits for the synchronous pilot.

The compose file hard-codes fail-closed ICAP and block-on-review. They cannot
be disabled through `.env.pilot`.

## Install

Online build/pull:

```bash
./deploy/pilot/install.sh --env-file .env.pilot
```

The script validates Linux, Docker, secrets, paths, ICAP exposure, and compose
configuration before starting services. First startup can take several minutes
while ClamAV downloads signatures.

For an offline target, build and export images on an approved connected Linux
builder using the exact release:

```bash
docker build -t masp-pilot:0.1.0-pilot.5 .
docker pull 'postgres:16-alpine@sha256:e013e867e712fec275706a6c51c966f0bb0c93cfa8f51000f85a15f9865a28cb'
docker pull 'clamav/clamav:stable@sha256:1b6443c4a7b456baa1abfaf9796815f8d21e2fb558dbaed5b682fd4552d8b0c3'
docker save -o masp-pilot-0.1.0-pilot.5-images.tar \
  masp-pilot:0.1.0-pilot.5 postgres:16-alpine clamav/clamav:stable
sha256sum masp-pilot-0.1.0-pilot.5-images.tar > \
  masp-pilot-0.1.0-pilot.5-images.tar.sha256
```

On the target, verify and load the archive, then install without building:

```bash
sha256sum -c masp-pilot-0.1.0-pilot.5-images.tar.sha256
docker load -i masp-pilot-0.1.0-pilot.5-images.tar
./deploy/pilot/install.sh --env-file .env.pilot --no-build
```

Some Docker versions do not preserve repository-digest aliases through
`docker save/load`. In that case, after verifying the signed/checksummed image
archive, set `MASP_POSTGRES_IMAGE=postgres:16-alpine` and
`MASP_CLAMAV_IMAGE=clamav/clamav:stable` in the offline target's env file. The
archive checksum then pins the transferred bytes.

An image archive does not keep ClamAV signatures current. The target still
needs an approved signature-update path before scanning production traffic.

## Verify MASP

Keep storage-client user traffic disabled during acceptance. First run the internal
stack verification:

```bash
./deploy/pilot/verify.sh --env-file .env.pilot
```

It requires all three Linux engines, checks clean/EICAR REST decisions and the
size cap, then checks ICAP OPTIONS, clean allow, and EICAR block. It runs from
inside the application/ICAP containers and does not expose the API token on the
command line. This script does not replace the PostgreSQL concurrency gate or
the real client framing check below.

### PostgreSQL concurrency gate

The PostgreSQL-gated tests deliberately drop and recreate the target database's
`public` schema. **They must never touch the pilot database.** The script below
therefore always creates its own throwaway PostgreSQL, runs the gated modules
against it, and removes it afterwards -- it offers no way to point at an
existing database:

```bash
./deploy/pilot/run_gated_tests.sh
```

The application image does not contain the test suite, by design: it handles
untrusted samples, so its runtime surface is kept minimal. The release bundle
ships `tests/`, and the script bind-mounts it read-only into a one-off container
started from the deployed image. The host does not need a project virtual
environment.

All PostgreSQL-gated cases must **run rather than skip** — a skip means the test
database URL never reached the tests and the gate did not actually execute, so
check the summary reports `0 skipped`. The script exits non-zero on failure.
Retain the output in the pilot acceptance record.

### ICAP functional and fail-closed smoke

Also test from the real network segments:

```bash
python3 tools/verify_scan_api.py \
  --base-url https://masp.example.internal \
  --eicar --expect-max-bytes 52428800 \
  --require-engine static_metadata --require-engine clamav --require-engine yara

python3 tools/icap_probe.py --host <masp-private-ip> --port 1344 --options
python3 tools/icap_probe.py --host <masp-private-ip> --port 1344 --expect allow
python3 tools/icap_probe.py --host <masp-private-ip> --port 1344 --eicar --expect block
```

Set `MASP_API_TOKEN` in the verification shell instead of passing it in shell
history.

The pilot blocks archives because members of a clean container are not yet
independently scanned on the synchronous path. Verify this with a harmless ZIP:

```bash
python3 -c "import zipfile; z=zipfile.ZipFile('/tmp/masp-clean.zip','w'); z.writestr('clean.txt','harmless'); z.close()"
python3 tools/icap_probe.py --host 127.0.0.1 --port 1344 \
  --file /tmp/masp-clean.zip --expect block
rm -f /tmp/masp-clean.zip
```

Also prove a malformed `Encapsulated` header fails closed. The ICAP response is
an outer `200` carrying an encapsulated HTTP `403`; an allow/204 is a failure:

```bash
python3 - <<'PY'
import socket

request = (
    b"REQMOD icap://127.0.0.1:1344/masp ICAP/1.0\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Allow: 204\r\n"
    b"Encapsulated: opt-body=0\r\n"
    b"Connection: close\r\n\r\n"
)
with socket.create_connection(("127.0.0.1", 1344), timeout=10) as client:
    client.sendall(request)
    client.shutdown(socket.SHUT_WR)
    response = client.recv(65536)
if b"403 Forbidden" not in response or response.startswith(b"ICAP/1.0 204"):
    raise SystemExit(f"malformed request did not fail closed: {response[:200]!r}")
print("Malformed ICAP request: fail-closed PASS")
PY
```

## Configure the storage ICAP client

A storage product that already has a generic ICAP client needs no source-code
change. Configure its management console with:

| Field | Value |
|---|---|
| Server/host | MASP private IP or private DNS |
| Port | `1344` |
| Service | `masp` |
| URI, when requested | `icap://<masp-private-host>:1344/masp` |
| Mode | `REQMOD` for upload gating |
| Preview | Disabled initially |
| Allow 204 | Enabled when available |

Use RESPMOD only for a separate download/response scanning policy. Confirm that
the client keeps the upload unavailable until MASP returns allow. A block response,
connection failure, timeout, or malformed response must not release the file.

Before enabling user traffic, send one approved harmless upload from the real
storage-client test node and retain a security-reviewed, sanitized ICAP capture. Confirm
that the REQMOD encapsulated body is the actual file bytes expected by MASP. If
the client sends a `multipart/form-data` envelope, stop acceptance: the current
gateway treats the complete encapsulated body as `application/octet-stream` and
does not extract an individual multipart file part. Captures can contain file
content, hostnames, and addresses; store them only in the approved location,
sanitize before moving them to development, and delete temporary copies.

### Optional LDAP / Active Directory login

LDAP login is app-only and can coexist with local MASP accounts. Configure the
`MASP_LDAP_*` values in `.env.pilot`, ensure the app container trusts the
directory certificate chain, and restart the app. MASP requires LDAPS or
StartTLS, performs a service-account search followed by a user bind, and maps
direct directory group membership to `admin` or `analyst`. Keep the bootstrap
local admin as a tested break-glass account. See
[LDAP and Active Directory authentication](../security/LDAP_AUTHENTICATION.md)
for the complete variables, CA mount example, limitations, and acceptance test.

### Optional manual VirusTotal lookup

VirusTotal is reserved for explicitly initiated manual file scans and the
interactive **Scan Hash** page. API and ICAP submissions never invoke it because
the adapter consumes external quota; the restriction is applied before engine
jobs are created and enforced again by workers. Generate
`MASP_SECRET_ENCRYPTION_KEY` once
with `python tools/generate_secret_key.py`, set it in `.env.pilot`, and restart
the app and worker services. Then open **Admin > Engines**, add **VirusTotal**, enter the API
key and policy in its Settings drawer, save, and use **Test connection**. Permit
DNS plus outbound HTTPS to `www.virustotal.com:443`. The API key is encrypted
in the database and is never displayed again; environment-based
`MASP_VIRUSTOTAL_*` configuration remains supported. Disabling or removing the
engine disables its participation in manual file/hash scans. For manual file
scans, the worker sends only the locally computed SHA-256 and stores VirusTotal
as a normal engine result; it never uploads file content. For this file-scan
view, VirusTotal is enrichment: no report, zero detections, or a stale
zero-signal report does not turn an otherwise-clean local scan into Review.
Malicious reputation still blocks and suspicious reputation still reviews.

Use a licensed Premium/Enterprise API key approved for this organizational
workflow. VirusTotal's Public API terms do not permit automated business
workflows that do not contribute new files. Keep
`MASP_VIRUSTOTAL_ALLOW_UNDETECTED=0` until the data owner explicitly accepts
zero detections as an allow signal for the dedicated **Scan Hash** workflow.
Even then, the default 30-day `MASP_VIRUSTOTAL_MAX_AGE_DAYS` freshness gate
applies there. Timeouts, quota errors, and all non-200 upstream failures remain
real engine failures and reduce file-scan coverage.

The pilot may receive controlled user traffic only after all of these pass:

- disposable-PostgreSQL gated tests;
- internal verification plus clean, EICAR, archive, and malformed ICAP smoke;
- real client body/framing confirmation;
- the observed ICAP source address checked from the real client node, with the
  outcome recorded (real address, or firewall-only restriction);
- fail-closed behavior for timeout, connection failure, block, and malformed
  response;
- a retained backup/restore rehearsal.

## Back up and restore

Create a consistent pilot backup:

```bash
./deploy/pilot/backup.sh --env-file .env.pilot --output-dir /srv/masp/backups
```

The script briefly stops app/worker/ICAP, dumps PostgreSQL, archives sample
storage and mutable YARA rules, writes SHA-256 checksums, and restarts services.
Store `.env.pilot` separately in the approved secret-management system.

Restore is destructive and requires explicit confirmation:

```bash
./deploy/pilot/restore.sh \
  --env-file .env.pilot \
  --backup-dir /srv/masp/backups/masp-pilot-<timestamp> \
  --yes
```

The previous sample directory is retained with a `.pre-restore.<timestamp>`
suffix until the operator removes it.

## Monitor

`GET /health` is an unauthenticated liveness probe. `GET /metrics` serves
Prometheus metrics and requires the API bearer token; it reports queue depth,
the age of the oldest waiting scan, worker liveness, and per-engine result
counts. Disable it with `MASP_METRICS_ENABLED=0` if the pilot has no scraper.

Even in the pilot, set up the two alerts that correspond to a user-visible
outage, because ICAP is fail-closed and a stalled MASP blocks uploads:

- `masp_workers_online == 0` for 2 minutes,
- `masp_scan_oldest_queued_age_seconds > 300` for 5 minutes.

Queue depth alone is not a useful alert: a steady depth is normal under load,
while the *age* of the oldest waiting scan is what separates busy from stalled.
Watch host disk usage on the storage filesystem too. The full alert table is in
[PRODUCTION.md](PRODUCTION.md#monitoring-and-alerting).

Quick manual check:

```bash
curl -sS -H "Authorization: Bearer $MASP_API_TOKEN" \
  http://127.0.0.1:8000/metrics | grep -E '^masp_(workers_online|scan_oldest_queued_age_seconds)'
```

## Operate and upgrade

```bash
docker compose -p masp-pilot -f docker-compose.pilot.yml \
  --env-file .env.pilot ps
docker compose -p masp-pilot -f docker-compose.pilot.yml \
  --env-file .env.pilot logs -f app worker icap clamav
```

Deploy upgrades only from another fixed pilot release. Back up first, load or
build the new images, update `MASP_IMAGE`, run `up -d --wait`, and repeat all
acceptance checks.

**Upgrading from a release whose containers ran as root:** the services now run
as the unprivileged id `10001`, so the existing storage and rules contents must
change ownership or replacing an existing file fails (overwriting a YARA rule is
the case that breaks; reads and deletes keep working because they depend on the
directory). Re-running `install.sh` does this — `pilot_prepare_data_dir` chowns
recursively and is idempotent. To do it by hand:

```bash
chown -R 10001:10001 /srv/masp/storage "$MASP_RULES_DIR"
```

This is the one upgrade step that is not just "swap the image", so verify it
before running the smoke: `ls -l /srv/masp/storage/samples | head` should show
`10001` as the owner.

When more than one host is involved (for example a remote Windows Defender worker),
upgrade in this order: **app/API host first, then the worker hosts.** New workers
register a durable `worker_nodes` row and still publish compatible per-process
heartbeats. A new app reads those rows plus the legacy single/bulk heartbeat
shapes, so it tolerates not-yet-upgraded workers; an old app cannot understand
the managed node inventory. Upgrading app first keeps worker coverage visible
across the transition. Assign every host a unique, restart-stable
`MASP_WORKER_NODE_ID`. The System page can then drain or disable that node
without stopping its heartbeat process.

Do not distribute the pilot PostgreSQL credential or mount pilot sample storage
on a remote engine host. Configure the app-side enrollment token and HTTPS
requirement, then enroll the host against
`https://<pilot-host>/api/v1/worker-control`:

```powershell
$env:MASP_WORKER_CONTROL_URL="https://<pilot-host>/api/v1/worker-control"
$env:MASP_WORKER_ENROLLMENT_TOKEN="<pilot bootstrap token>"
$env:MASP_WORKER_ENGINE_KEYS="microsoft_defender"
$env:MASP_WORKER_NODE_ID="pilot-defender-01"
python -m app.workers.control_api_worker --enroll
```

Store the returned token in an ACL-protected file, remove the enrollment token,
and run `app.workers.scan_worker` with `MASP_WORKER_TRANSPORT=control_api` and
`MASP_WORKER_AGENT_TOKEN_FILE` set. An internal CA is supplied through
`MASP_WORKER_CONTROL_CA_FILE`; disabling certificate verification is not a
supported pilot configuration. Re-enrollment is credential rotation and revokes
the prior active token for that node.

For a persistent Windows pilot node, use the SCM package, virtual service
identity, ACL, preflight, rotation, logging, and uninstall flow in
[Windows Worker Agent](WINDOWS_WORKER_AGENT.md). Do not promote the Defender
integration beyond lab status until every acceptance item there has evidence
from the target Windows image and Defender policy.

After every remote node has registered, create worker pools in the System page
from the labels published in `MASP_WORKER_LABELS`, then assign each remote engine
instance under **Engine placement**. Existing engines are deliberately unbound
after upgrade and retain adapter-key routing until an administrator assigns them.
Verify that every bound instance shows at least one active matching node before
enabling production scan traffic.

Wait for the first worker health interval and verify the managed node reports
healthy engine checks. Control-API workers report authenticated sample delivery
instead of shared-storage access. Use **Engines > Test
connection** to request an immediate worker-side refresh. Confirm the version and
last successful scan fields after the EICAR acceptance scan; heartbeat-only
coverage is not an engine-health acceptance result.
