# MASP session handoff

Updated: 2026-09-29, after storage protection phase 1. This is a workspace
checkpoint, not evidence of a deployment.

## Start here

1. Read the root `AGENTS.md` completely.
2. Inspect `git status`, staged changes and the current diff. Preserve all work;
   do not reset, discard or automatically stage unrelated files.
3. Read `docs/architecture/FRONTEND_SEPARATION.md`, especially the complete UI
   inventory and the latest implementation/validation sections.
4. Read `docs/architecture/ENGINE_DEPLOYMENT_AND_WORKER_AGENT.md` and the remaining
   gates in `docs/security/HARDENING_PHASE_1.md`.
5. If continuing the client-flexibility or large-file work, read
   `docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md` (named profiles,
   client storage access, manifest intake and its console view) and
   `docs/architecture/MAPPED_SOURCE_INSPECTION.md` (steps 1-3 done; steps 4 and 5
   blocked on OPEN decisions).

## Git checkpoint

Checkpoint branch: `feat/frontend-separation-hardening`, not merged to `main`.
`origin/feat/frontend-separation-hardening` was last confirmed at `94f01ed`;
**everything below is local and NOT pushed**. The user authorizes each push
explicitly because the repository is public. The PR to `main` has not been
opened (no `gh` on this host; the user opens it from the compare URL). Confirm
with `git log -1`, `git status` and a fresh `git fetch` before assuming anything
here is still current.

Commits after the last pushed `94f01ed`, oldest first:

- `315cc17` `deploy/pilot/rehearse_tls.sh`: disposable app + PostgreSQL + nginx
  (self-signed) rehearsal of the proxy trust settings; passed locally
- `bbab676` the pilot release bundle ships the console build inputs
  (`frontend/`); without them `install.sh` failed at the Dockerfile's first COPY
- `99ac1b5` `install.sh` refuses the example's placeholder
  `MASP_WORKER_ENROLLMENT_TOKEN` (public value: anyone could enroll a worker) and
  a non-Fernet `MASP_SECRET_ENCRYPTION_KEY`; both may be empty
- `b8a0c1a` hash lookup redesign, technical About (release image, Python,
  database, per-engine versions, agent versions), theme-aware logo;
  `MASP_RELEASE` passed through the compose files
- `33623d6` release named `0.1.0-pilot.7`
- `63ad691` grouped navigation (Operations, Integrations, Infrastructure,
  Administration; phone menu), one UTC timestamp format, heartbeat wording,
  investigation links, copyable `X-Request-ID` on errors, collapsible help.
  Started by a second agent that ran out of credit; reviewed, four tests adapted
  to the intended behaviour, committed here
- `634437a` operations visibility: health checks on System > Overview and in the
  top bar, ClamAV signature version/date in engine health, ICAP gateway activity
  record, System > ICAP and SIEM, intake retry/dismiss, client readiness per
  connection method, name search, ledger client picker, support bundle
- `e4126bd` notifications that nothing ever tried to deliver are "not in use",
  not critical (found on the live local stack)
- `f222418` handoff, AGENTS.md, architecture and deployment docs synced
- `d257cc3` Microsoft Defender marked `supported` (product-owner decision based
  on production use; label only). SCM-service run, failure/failover matrix and
  release signing stay open as hardening, not as done
- `f153ee5` ClamAV on networks without internet access: optional `clamav.env`
  beside the compose file (internal mirror, proxy, or `CLAMAV_NO_FRESHCLAMD`)
  and `deploy/pilot/load_clamav_signatures.sh` (sigtool-verified copy into the
  service volume; TCP `RELOAD` on a running clamd). Rehearsed in Docker's Linux VM
- `4444196` release named `0.1.0-pilot.8`
- `154b131` docs: the pinned ClamAV image ships an old database
- `9af6cda`, `1da505a`: handoff updates
- `3c97d5c` storage protection architecture (`STORAGE_PROTECTION.md`)
- `5d7a28e` storage protection phase 1 core: protection worker, inventory,
  light tier, shared header classifier (`content_types.py`), storage outbox
- `830c5da` browser API under `/api/ui/v1/storage` and a folder scanning
  health check
- `9a1206a` an unreadable stored policy stops only its own location
- `4204904` Folder scanning console screens
- `829b302` `storage-protection` compose profile in all three compose files,
  env examples, README/deployment/architecture docs, handoff
- `ef94971` release named `0.1.0-pilot.9`; bundle and MASP image in `dist/`
  (PostgreSQL/ClamAV unchanged). The image passed a folder-scanning smoke run
  as UID 10001 with a read-only root, no capabilities and a root-owned 755/644
  share (3004 files crawled in 0.8 s, inspected in 9.8 s on a local volume).
  The operator's Turkish upgrade and test steps are `kilavuz/04-pilot9-klasor-tarama.md`
- this commit: handoff

Pre-existing staged files to preserve: `bench_sample.txt`, `sample_30mb.bin`,
`sample_45mb.bin`, `sample_5mb.bin`, `skills-lock.json`. These are intentionally
excluded from every commit and remain staged locally; a plain `git commit -a` or
`git commit` without a pathspec would sweep them in, so every commit in this
branch's history was made with an explicit file list.

`docs/PILOT_FOLLOWUPS.md` must stay UNTRACKED: the repository is public and that
file still carries partner naming. Do not `git add` it.

## Current work

**`1fdf768` Hash List engine.** Decisions made with the user: one global list
(not per engine instance), and an allowlist match is informational only — it
never suppresses another engine or produces an allow decision. The adapter
compares the MASP-computed SHA-256 (never a client value), reads no sample bytes,
is `detection=False` so "not listed" is never coverage, and reports a failed
lookup as `failed`. It reads MASP's database while scanning, so it carries a new
`requires_database` capability: control-API workers neither advertise nor run
it. Two pre-existing `file_type` gaps were found and fixed in the same commit: it
had no Engines-page setup branch (creation always failed) and no default worker
key list included it. Existing deployments with an explicit
`MASP_WORKER_ENGINE_KEYS` in their `.env` must add `file_type,hash_list`
themselves; an admin must also create the Hash List engine and assign it to
profiles — nothing is seeded.

**`ce94ace` deferred intake visibility.** Closes the gate the manifest intake
commit left open. The manifest worker now records each cycle and the
configuration it ran with in the `manifest_intake_last_cycle` setting, because
the API process does not share the worker's environment. Error text for
rejections and cycles is stored and displayed with absolute paths replaced by
`<path>`; OSError messages previously carried the share path into storage. The
view is read-only: nothing is cleared, retried or dismissed from the console.

**`720da8e`: deferred retry no longer depends on live configuration.** A repeat
`client_request_id` is answered from the accepted record before resolving any
live routing, comparing only what the client asserted: backend key, object id,
expected size, expected SHA-256, archive mode and `requested_profile_id` (NULL
means "use the default"). Descriptive metadata is first-write-wins. A genuinely
different request for an existing id is still a `409`, and the frozen snapshot
stays authoritative. Before this, renaming a profile, engine or client turned a
byte-identical retry into a permanent `409`. Full contract in
`SERVICE_CLIENTS_AND_SCAN_PROFILES.md` under "Retrying a deferred submission".

**`98128da` legacy UI retirement.** The console is the only browser UI and is
served by the application image (`d7ad4b2`), so pilot/production need no extra
container. Former GET paths redirect (`/scans/{id}` resolves manual vs automation
only for a signed-in operator). `MASP_SHOW_DEV_LOGIN_HINTS` was removed.

**`73f3264` scan outcomes.** Raised by the user: a scan whose engines all failed
showed "completed" with zero risk, and clean scans showed an orange "low 10".
Scoring added 10 points for a clean result; decisions never depended on it.
Integrators see both changes through the API.

**`93e77ca` deployment fixes.** Found in a go-live review cross-checked with a
second agent: the manifest service was missing from prod/pilot compose; the
pilot backup/restore scripts stopped only `app worker icap`, leaving intake and
notification workers writing during a dump/restore (a fake-docker test now
drives both scripts); and Uvicorn trusted `X-Forwarded-Proto` only from
127.0.0.1, so behind a TLS proxy every console save would fail the same-origin
check and remote workers would be refused. `rehearse_tls.sh` (`315cc17`)
proves the MASP side against a self-signed nginx; a real institutional proxy
has still not been exercised.

**Offline upgrade path (rehearsed 2026-09-25).** The pilot server has no
internet except ClamAV updates, so releases travel as the bundle ZIP plus one
`docker save` of `masp-pilot:<version>` (PostgreSQL and ClamAV digests are
unchanged since pilot.2, and project and volume names never changed). The
upgrade was replayed inside Docker's Linux VM with the real release scripts
from pilot.2 and from pilot.5: old install and verify, old backup, carried env
(`awk` appends keys missing from the new example), new `install.sh --no-build`,
new verify, then rollback (old release on the migrated database, old restore).
All passed. Two findings are written into the operator manual: upgrading from a
root-container release (pilot.2) without `install.sh` leaves storage root-owned
and every upload fails with 500; `restore.sh` restarts services without waiting
for health, so verify after the app is healthy.

**Operations visibility (`634437a`, `e4126bd`).** The health report
(`app/services/health_read.py`, `GET /api/ui/v1/system/health`) evaluates
workers, queue age (with why scans wait), engines (using the Engines screen's
own verdicts), ClamAV signature age, sample storage, manifest and deferred
intake, the ICAP gateway and SIEM notifications. On the live local stack it
immediately surfaced a real problem: ClamAV had not updated for three days
(Docker paused while the host slept). The ICAP gateway now writes
`icap_gateway_status:<client key>:<port>` every 30 seconds; older gateways do
not report, so an upgraded server shows ICAP as "not in use" until the icap
container runs this release.

**Next steps agreed with the user, in order:**

1. Push the commits above and open the PR to `main` -- **only with the user's
   explicit approval**.
2. `0.1.0-pilot.8` is packaged in `dist/` (git-ignored): the bundle, the MASP
   image alone and a full image archive (MASP, PostgreSQL, ClamAV), current
   ClamAV signatures, and an offline apt repository (nginx, cifs-utils, unzip)
   for Ubuntu 22.04 beside the existing offline Docker packages. The user plans
   a second, intranet installation with no internet access at all; ClamAV
   signatures then come from an internal mirror, a proxy, or
   `deploy/pilot/load_clamav_signatures.sh` (`f153ee5`). The pinned ClamAV image
   ships a database from its build date (daily 28045, 2026-06-28), so load
   current signatures before real traffic.
3. On the pilot server (operator-run; the agent has no access): real network
   share manifest test once the firewall allows the pilot host -> file server TCP 445
   (one direction only), a backup/restore rehearsal on the real host, a
   capacity run with realistic file sizes (the local worker was once killed
   with exit 137 under load).
4. Low priority, separate change: remove database helpers that lost their only
   callers with the legacy UI (`list_users`, `update_service_client`,
   `revoke_api_client_credential`, `list_engine_results_by_scan_ids`, ...).

**Open threads with the user (2026-09-29):**

- Trellix and ESET adapters are next, after the intranet install. Blocked on the
  user naming the exact products and licenses the institution has (ESET Server
  Security, ESET PROTECT, Trellix Endpoint Security, Trellix ATD, an ICAP-capable
  gateway) and on test access. Suggested first: a generic ICAP-client adapter,
  validated locally against c-icap + ClamAV, then one response profile per
  vendor. Never write an adapter without real product responses.
- Offered, not started: an offline Windows worker kit (Python installer, wheels
  including pywin32, the agent bundle) and a Turkish manual for a remote
  Defender worker on the intranet. A remote worker needs HTTPS on MASP and
  `MASP_WORKER_ENROLLMENT_TOKEN` set only while enrolling.
- The user asked for server sizing; the answer (not in the repo): 8 vCPU / 16 GB
  for the pilot, ClamAV ~1 GB idle and about double during a reload, disk sized
  as daily files x average size x retention days plus about 20 GB, backups on a
  separate target. No realistic capacity run has been done yet.
- Research ideas discussed, none started: retrohunt (rescan stored samples on
  new signatures and notify SIEM), document analysis and CDR, an engine efficacy
  lab, signed offline update bundles.

**Storage protection (2026-09-29).** Folder-watch intake without manifests is
no longer parked: the user chose a broader "storage protection" feature, agreed in
`docs/architecture/STORAGE_PROTECTION.md`. **Phase 1 is implemented** (crawl mode,
inventory, light tier, findings and SIEM events, browser API, Folder Scanning
screens, health check, `--profile storage`); read "Phase 1 as built" there for the
deliberate differences. Not yet exercised: a real SMB share, a real SIEM receiving
`storage.finding` events, and any capacity run. Phase 2 (full tier: verified
in-place reads, content deduplication, evidence copies) is next, on the user's
go-ahead. The storage team will integrate to MASP's choice, so for their uploads
the deferred API is the recommended path and the manifest the fallback.

The intranet server request was drafted with the user: Ubuntu Server 22.04 x86_64
(the offline kits in `dist/` are `jammy-amd64`), 8 vCPU / 16 GB, 80 GB OS plus a
200 GB data disk at `/srv/masp`, TLS from the internal CA (required because the
Defender worker only talks HTTPS), plus a Windows Server 2022 Defender worker
(4 vCPU / 8 GB / 80 GB, Defender active, cloud sample submission off, signatures
from an internal source, outbound 443 to MASP only). Still to prepare: an offline
Windows worker kit (Python installer and wheels including pywin32) and a Turkish
worker manual in `kilavuz/`.

**Parked for user decisions:** `MAPPED_SOURCE_INSPECTION.md` steps 4
(explicit narrow coverage) and 5 (in-place reading); a "Page N" indicator for
the API ledger; wiring Hash List into the API hash lookup.

**Pilot server state (reported by the user, 2026-09-28).** An Ubuntu pilot
host, offline except ClamAV updates, reached through a PAM client. It was
upgraded from pilot.5 to pilot.6 in place (old install lives in `/opt/masp`, the
new release in `/opt/masp/masp-pilot-0.1.0-pilot.6`, `/opt/masp/current` links
to it, `/usr/local/bin/masp` wraps compose). The app binds `127.0.0.1:8000`
without a proxy (`MASP_SESSION_SECURE` empty). A pilot.7 package was handed over;
whether it is installed is not known. The manifest test against a real share
is blocked: the pilot host can ping the file server but TCP 445 times out
(`mount error(115)`), which needs a firewall rule. `cifs-utils` presence on the
server is unconfirmed. Operator manuals in Turkish live in `kilavuz/`
(`01-kurulum.md`, `02-offline-yukseltme.md`), excluded from git through
`.git/info/exclude` at the user's request.

**Local environment notes:** the live local stack was rebuilt from `e4126bd` on
2026-09-28 (volumes kept) and now also runs the `icap` profile on
`127.0.0.1:1344`. `.env` has `MASP_MANIFEST_CLIENT_KEY=drive` (the
client created in the console is `drive`, id 238, granted `drive`/`uploads/`).
Test drops live in `deferred-source/uploads/2026/09/24/` (git-ignored);
`test-2.json` is a deliberately malformed manifest whose rejection count was
inflated by the spin bug before `8d6c042`. `requirements.txt` shows as modified
only because of line endings; its content is unchanged.

**Deployment gates outstanding:** capacity measurement against realistic
Drive-sized files (tooling exists in `tools/benchmark_*.py`), a real
institutional TLS proxy, production-scale PostgreSQL load, real-client ICAP
framing confirmation, and per-client rate limiting.

## Verification and environment safety

- Full backend: `python -m unittest discover -s tests`. Last full run (working
  tree of `634437a`, SQLite): **957 tests, OK, 121 skipped** (the skips are the
  PostgreSQL-gated modules). New PostgreSQL coverage
  (`tests/test_operations_health.py`, About, health and readiness queries) was
  run against a disposable PostgreSQL 16 and passed. The pilot script tests need
  Git Bash on Windows and are skipped where no POSIX bash exists.
- PostgreSQL tests require `MASP_TEST_POSTGRES_URL` pointing only at a disposable
  database: tests drop/recreate its public schema. Never use the live MASP DB.
  Disposable containers used on this branch (ports 15441-15444, names
  `masp-test-pg-*`) were started with `--rm` and stopped; none should remain
  (`docker ps -a` to check).
- Frontend: `npm --prefix frontend test` (178 tests passing), `run build`,
  `run contracts:check`. Regenerate contracts with
  `npm --prefix frontend run contracts:generate` after browser API changes.
  `run test:e2e` for Playwright (38 workflows; the last full run had one
  failure from outdated expectations in `client-setup.spec.ts`, fixed and
  re-run on its own).
- Browser acceptance uses temporary SQLite and a fixture server, not live data.
  On Windows Playwright teardown may leave fixture processes running; identify
  the exact owned PIDs before stopping them (none were left this session).
- Preserve live containers `masp-app-1`, `masp-worker-1`, `masp-icap-1`,
  `masp-postgres-1`, `masp-clamav-1`, `masp-deferred-intake-1` and
  `masp-manifest-intake-1`. They were rebuilt from `e4126bd` on 2026-09-28;
  volumes were kept.
  Run heavy suites sequentially: running the full suite,
  e2e and a disposable PostgreSQL concurrently previously pushed the live
  containers into exit 137. Never retain real credentials in this handoff or
  test artifacts.

## Open acceptance gates

Production-shaped PostgreSQL load, a real institutional TLS proxy,
large/oversized output handling, per-client rate limiting, and
installed Windows SCM/failure/failover/signing acceptance remain open. Local
tests do not promote production engine support. See "Deployment gates
outstanding" above for what was actually discussed with the user and why each
one is still open.
