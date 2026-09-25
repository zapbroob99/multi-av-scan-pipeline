# MASP session handoff

Updated: 2026-09-25, after the go-live readiness fixes. This is a workspace
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

Checkpoint branch: `feat/frontend-separation-hardening`. The commit that adds
this handoff sits on top of `3c1f42a`. `origin/feat/frontend-separation-hardening`
was last confirmed at `dc841e2`; **everything after it is local and NOT pushed**,
and the branch is not merged to `main`. The user authorizes each push explicitly
because the repository is public. Confirm with `git log -1`, `git status` and a
fresh `git fetch` before assuming anything here is still current.

Commits after the last pushed `dc841e2`, oldest first:

- `06aac8c` legacy parity sweep: dashboard detection filter, bounded hash
  provider detail, engine last-result time, audit detail formatting
- `d7ad4b2` the application image builds and serves the console at `/console/`
- `98128da` **legacy UI retired** (breaking): `app/main.py` ~9100 -> ~1000 lines,
  former GET pages redirect to console screens, legacy form routes gone
- `da0cea0` handoff update
- `2c4c0df` System tab strip rendered once by a shared layout route; Engines only
  under System
- `db4e6be` compact entity lists (Users, worker nodes, pools), audit as a table,
  select-all for bulk deletion on Dashboard and API ledger
- `73f3264` scan outcomes: no engine completed -> `failed`; clean scans record
  `info`/0 instead of `low`/10; `scan_jobs.unavailable_engines`; risk badge reads
  "No detection" / "Incomplete" / "Not scored" (API-visible change)
- `8d6c042` manifest worker no longer spins on a rejected manifest
- `93e77ca` deployment: manifest-intake service in prod/pilot compose, pilot
  backup/restore pause every running writer, proxy trust
  (`MASP_FORWARDED_ALLOW_IPS`, `MASP_SESSION_SECURE`) mapped into the app
- `3c1f42a` production/pilot runbooks rewritten for the retired legacy UI
- this handoff rewrite (docs only)

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
check and remote workers would be refused. The proxy setting is configured and
documented but **not yet exercised behind a real TLS proxy**.

**Next steps agreed with the user, in order:**

1. Push the commits above and open a PR to `main` — **only with the user's
   explicit approval**.
2. Isolated rehearsals: a TLS reverse proxy (self-signed is fine) proving a
   console save, secure cookie and a remote worker heartbeat through HTTPS; a
   capacity run with realistic file sizes (`tools/benchmark_*.py`; the local
   worker was killed with exit 137 under load, so memory sizing matters); and a
   real backup/restore rehearsal on a pilot-shaped stack.
3. Low priority, separate change: remove database helpers that lost their only
   callers with the legacy UI (`list_users`, `update_service_client`,
   `revoke_api_client_credential`, `list_engine_results_by_scan_ids`, ...).

**Parked for user decisions:** folder-watch intake without manifests (waiting
for the Drive team: how files are written, folder layout, daily volume, whether
files change after upload, naming); `MAPPED_SOURCE_INSPECTION.md` steps 4
(explicit narrow coverage) and 5 (in-place reading); a "Page N" indicator for
the API ledger; wiring Hash List into the API hash lookup.

**Local environment notes:** `.env` has `MASP_MANIFEST_CLIENT_KEY=drive` (the
client created in the console is `drive`, id 238, granted `drive`/`uploads/`).
Test drops live in `deferred-source/uploads/2026/09/24/` (git-ignored);
`test-2.json` is a deliberately malformed manifest whose rejection count was
inflated by the spin bug before `8d6c042`. `requirements.txt` shows as modified
only because of line endings; its content is unchanged.

**Deployment gates outstanding, discussed with the user but not started**:
capacity measurement against realistic Drive-sized files (tooling exists in
`tools/benchmark_*.py`; prior runs used only a 7.5 KB sample), TLS/reverse-proxy
termination (template exists, never run against a real proxy), production-scale
PostgreSQL load, real-client ICAP framing confirmation, and per-client rate
limiting.

## Verification and environment safety

- Full backend: `python -m unittest discover -s tests`. Last full run (on the
  working tree committed as `3c1f42a`, with disposable PostgreSQL): **921 tests,
  919 passed, 2 skipped, 0 failures.** The pilot script test needs Git Bash on
  Windows and is skipped where no POSIX bash exists.
- PostgreSQL tests require `MASP_TEST_POSTGRES_URL` pointing only at a disposable
  database: tests drop/recreate its public schema. Never use the live MASP DB.
  Disposable containers used on this branch (ports 15441-15444, names
  `masp-test-pg-*`) were started with `--rm` and stopped; none should remain
  (`docker ps -a` to check).
- Frontend: `npm --prefix frontend test` (157 tests passing), `run build`,
  `run contracts:check`. Regenerate contracts with
  `npm --prefix frontend run contracts:generate` after browser API changes.
  `run test:e2e` for Playwright (36 scenarios passing). The application image
  was rebuilt and smoke-tested at the same point (`/health`, `/console/`, `/`).
- Browser acceptance uses temporary SQLite and a fixture server, not live data.
  On Windows Playwright teardown may leave fixture processes running; identify
  the exact owned PIDs before stopping them (none were left this session).
- Preserve live containers `masp-app-1`, `masp-worker-1`, `masp-postgres-1` and
  `masp-clamav-1`. They were untouched this session and still run pre-`1fdf768`
  code until rebuilt. Run heavy suites sequentially: running the full suite,
  e2e and a disposable PostgreSQL concurrently previously pushed the live
  containers into exit 137. Never retain real credentials in this handoff or
  test artifacts.

## Open acceptance gates

Production-shaped PostgreSQL load, TLS/proxy/static deployment, full legacy
parity, large/oversized output handling, per-client rate limiting, and
installed Windows SCM/failure/failover/signing acceptance remain open. Local
tests do not promote production engine support. See "Deployment gates
outstanding" above for what was actually discussed with the user and why each
one is still open.
