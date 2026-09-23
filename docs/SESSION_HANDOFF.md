# MASP session handoff

Updated: 2026-09-23, after the hash list and deferred-intake visibility
commits. This is a workspace checkpoint, not evidence of a deployment.

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
this handoff sits on top of `ce94ace`. **These commits are local and NOT pushed**:
`origin/feat/frontend-separation-hardening` was last confirmed at `8747ba7`.
Pushing was deliberately left to the user because the repository is public.
Confirm with `git log -1`, `git status` and a fresh `git fetch` before assuming
anything here is still current.

Commits since the last pushed baseline `8747ba7`, oldest first:

- `1fdf768` Hash List engine: one institution-wide SHA-256 blocklist/allowlist,
  managed at `/console/engines/hash-list`; also fixes `file_type` being neither
  creatable from the Engines page nor run by any default worker
- `ce94ace` deferred intake visibility: `/console/system/intake` shows the
  manifest worker's last cycle, deferred backlog, manifest rejections and
  pre-scan failures
- this handoff rewrite (docs only)

Earlier, already pushed (`18123f7`..`8747ba7`): audit/About, printable report and
oversized output, batch download, the mapped-source design draft, the `file_type`
engine, sidebar icons, client readiness, named profiles plus client storage
access, manifest intake, the console UI pass (`6d4ed61`) and the deferred-retry
fix (`720da8e`, narrated below).

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

**Next development candidates**, in the order last discussed with the user:

1. The deferred legacy parity sweep (manual filters, hash provider detail,
   System metric detail) and then the final cutover inventory (retiring
   `app/main.py` HTML rendering). Pure implementation, no open decisions.
2. `MAPPED_SOURCE_INSPECTION.md` step 4 (making "deliberately narrow coverage"
   explicit in reports, exports and the integration contract) and step 5
   (in-place reading). **Both are OPEN decisions for the user**; do not start
   them without explicit direction.

Possible small follow-ups noticed but not done: the Hash List engine does not
yet serve the manual `/console/hash-scan` lookup (it has no `hash_scan_function`,
and allowlist semantics there would need the same informational treatment);
manifest rejections cannot be dismissed from the console by design.

**Deployment gates outstanding, discussed with the user but not started**:
capacity measurement against realistic Drive-sized files (tooling exists in
`tools/benchmark_*.py`; prior runs used only a 7.5 KB sample), TLS/reverse-proxy
termination (template exists, never run against a real proxy), production-scale
PostgreSQL load, real-client ICAP framing confirmation, and per-client rate
limiting.

## Verification and environment safety

- Full backend: `python -m unittest discover -s tests`. Last full run (at
  `ce94ace`, with disposable PostgreSQL): **956 tests, 954 passed, 2 skipped,
  0 failures.**
- PostgreSQL tests require `MASP_TEST_POSTGRES_URL` pointing only at a disposable
  database: tests drop/recreate its public schema. Never use the live MASP DB.
  This session used `masp-test-pg-hashlist` (port 15441) and
  `masp-test-pg-intake` (port 15442), both started with `--rm` and stopped;
  none should remain (`docker ps -a` to check).
- Frontend: `npm --prefix frontend test` (149 tests passing), `run build`,
  `run contracts:check`. Regenerate contracts with
  `npm --prefix frontend run contracts:generate` after browser API changes.
  `run test:e2e` for Playwright (35 scenarios passing).
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
