# MASP session handoff

Updated: 2026-09-23 (rewritten from scratch after 11 commits; the previous
version was several commits stale). This is a workspace checkpoint, not
evidence of a deployment.

## Start here

1. Read the root `AGENTS.md` completely.
2. Inspect `git status`, staged changes and the current diff. Preserve all work;
   do not reset, discard or automatically stage unrelated files.
3. Read `docs/architecture/FRONTEND_SEPARATION.md`, especially the complete UI
   inventory and the latest implementation/validation sections.
4. Read `docs/architecture/ENGINE_DEPLOYMENT_AND_WORKER_AGENT.md` and the remaining
   gates in `docs/security/HARDENING_PHASE_1.md`.
5. If continuing the client-flexibility or large-file work, read
   `docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md` (covers named profiles,
   client storage access and manifest intake) and
   `docs/architecture/MAPPED_SOURCE_INSPECTION.md` (design-only; several OPEN
   decisions block in-place reading specifically).

## Git checkpoint

Checkpoint branch: `feat/frontend-separation-hardening`, HEAD `720da8e`,
**pushed and confirmed equal to `origin/feat/frontend-separation-hardening`**
(verified with `git fetch` + `git rev-parse` before pushing, then re-verified
after). A different clone or machine fetching this branch now receives
everything through `720da8e`. Confirm with `git log -1`, `git status` and a
fresh `git fetch` before assuming this is still current — later work may exist
uncommitted, in further commits, or pushed from elsewhere since this was written.

Commits since the prior pushed baseline `18123f7`, oldest first:

- `76a229c` audit-history and About slice
- `a54ff68` printable-report and oversized-engine-output slice
- `6915912` integration-batch-download slice (closes the oversized family)
- `12229d8` docs only: `docs/architecture/MAPPED_SOURCE_INSPECTION.md` design draft
- `b2ec544` `file_type` header-inspection engine (design doc's step 1)
- `1c0d03c` sidebar icon fix (distinct lucide icon per nav item)
- `fc8738f` client-readiness/setup view per service client
- `8238633` named scan profiles (create/rename/default/delete) + client storage
  access administration (per-client backend/prefix grants, replacing env config)
- `97e78e6` manifest intake: a storage producer drops a finished object plus a
  sibling JSON manifest on a read-only share; a new `manifest-intake` worker
  polls and accepts it as a deferred submission with no credential and no call
  from the producer
- `6d4ed61` console UI pass: risk badges/banner make detections visible on
  Dashboard and API ledger, submit-sample opens the report directly, API ledger
  is a compact table, per-adapter engine icons, explicit back links, and a
  shared tab strip replaces ad-hoc link lists across the five System screens
- `720da8e` **(current HEAD)** fix: a deferred retry no longer depends on live
  configuration — see "Current work" below, this is the most recent substantive
  change and the one most likely to matter if you are picking this up mid-task

Pre-existing staged files to preserve: `bench_sample.txt`, `sample_30mb.bin`,
`sample_45mb.bin`, `sample_5mb.bin`, `skills-lock.json`. These are intentionally
excluded from every commit above and remain staged locally; a plain
`git commit -a` or `git commit` without a pathspec would sweep them in, so every
commit in this branch's history was made with an explicit file list. They are
not required to continue any of the work described here.

`docs/PILOT_FOLLOWUPS.md` must stay UNTRACKED: the repository is public and that
file still carries partner naming. Do not `git add` it.

## Current work

The commit list above is the authoritative index of what exists; this section
gives context only for the parts not already narrated in permanent docs.

**`720da8e`: deferred retry no longer depends on live configuration.** Before
this fix, a repeat `client_request_id` was compared against the *frozen routing
snapshot*, and the endpoint resolved the *current* profile before even looking
for the existing record. Both meant retry safety depended on nothing changing
server-side: adding an engine to a profile, or merely renaming a profile, an
engine or the client, turned a byte-identical retry into a permanent `409`; and
deleting the profile made a retry unanswerable at all (`404` instead of the
accepted record). A producer with a durable send queue — which is what was
asked for in the manifest-intake design conversation — would have wedged on
either failure mode.

The fix: look up the accepted submission by `(service_client_id,
client_request_id)` *before* resolving anything live, and compare only what the
client actually asserted — backend key, object id, expected size, expected
SHA-256, archive mode, and a new `requested_profile_id` column (NULL means "use
the default", which is deliberately distinct from naming the profile that
happened to be default at submission time). Descriptive metadata (case name,
priority, note, filename, content type) is first-write-wins, not compared. A
genuinely different request for an existing id is still a `409`. The frozen
snapshot on the accepted row is untouched by any of this and remains
authoritative for what the work actually runs. Full contract in
`docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md` under "Retrying a
deferred submission"; rule restated in `AGENTS.md`.

This was found and fixed in direct response to the user's large-file/Drive
manifest-intake conversation, where a producer retrying a notification after a
MASP-side config edit was identified as a real failure mode, not a theoretical
one — reproduced concretely against a real submission before the fix, and
against the same scenarios after.

**`97e78e6` manifest intake, in brief** (full contract in
`SERVICE_CLIENTS_AND_SCAN_PROFILES.md`): a storage producer that cannot or
should not call MASP writes its finished object, then writes a sibling `.json`
manifest *last* — the manifest's appearance is the completion signal, nothing
is inferred from file size stability. The `manifest-intake` worker polls a
bounded set of recent dated partitions (never a full recursive walk), resolves
each manifest to an object inside the client's storage grant, and hands it to
the existing deferred-submission path unchanged. The mount stays read-only:
MASP never deletes or marks a manifest processed, and re-reading one is free
because `client_request_id = upload_id` is already unique. Rejected manifests
(malformed JSON, object outside the grant, traversal attempt) are recorded in a
capped `manifest_rejections` table with a reason and occurrence count, because
the producer gets no delivery/error feedback at all — **this table needs
console visibility before the path is relied on in production; that is not yet
built.**

**`6d4ed61` UI pass** was direct response to six specific user requests
(dashboard detections not visible enough, submit-sample dead-ending on an
interstitial, API ledger cards too wide for thousands of rows, engine icons
missing, some pages needing the browser back button, System screens not
tab-like). Three new shared components:
`frontend/src/components/{risk-badge,engine-icon,section-tabs}.tsx`. No backend
changes. Fixed two pre-existing test gaps while making these changes: the
`Engines` component test rendered without a Router (broke once shared tabs
needed `NavLink`), and the ledger-deletion test fixture was missing
contract-required fields (`sha256`, `created_at`) that only mattered once the
row became a table cell instead of a card.

**`8238633` (named profiles + client storage) is the one exception to "read the
permanent docs for narrative"**: it landed as a large already-reviewed diff from
a parallel session rather than being built turn-by-turn in this one, so there is
less first-hand implementation narrative for it here than for the others. It
was reviewed (schema, write-locking, security boundaries, test coverage) before
being committed. `docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md` is
the authoritative description of both features.

**Next development candidate**, per the user's stated priority in the large-file
conversation: the local hash-list adapter (step 2 of the
`MAPPED_SOURCE_INSPECTION.md` sequence — step 1, `file_type`, is done). After
that: manifest-intake console visibility (rejections + intake lag, called out
above as required before production reliance), then the deferred legacy parity
sweep (manual filters, hash provider detail, System metric detail) and the
final cutover inventory (retiring `app/main.py` HTML rendering).

**In-place reading and "deliberately narrow coverage" semantics remain OPEN**
in `MAPPED_SOURCE_INSPECTION.md`. Do not infer authorization to implement those
from the fact that named profiles and client storage administration — which
that design doc also called for — are now done; they were separate,
independently authorized pieces of work.

**Deployment gates outstanding, discussed with the user but not started**:
capacity measurement (real benchmark tooling exists in `tools/benchmark_*.py`
and prior local runs exist in `benchmark-results/`, but only against a 7.5 KB
sample — no measurement yet against realistic Drive-sized files), TLS/reverse-
proxy termination (nginx template and doc exist, never run against a real
proxy), production-scale PostgreSQL load, real-client ICAP framing
confirmation, and per-client rate limiting (a pool-based physical-isolation
workaround was discussed as an interim measure but not implemented).

## Verification and environment safety

- Full backend: `python -m unittest discover -s tests`. Last full run (at
  `720da8e`, with disposable PostgreSQL): **899 tests, 897 passed, 2 skipped,
  0 failures.**
- PostgreSQL tests require `MASP_TEST_POSTGRES_URL` pointing only at a disposable
  database: tests drop/recreate its public schema. Never use the live MASP DB.
  Every disposable container used across this branch's work (ports
  15433-15440, names `masp-test-pg-*` / `masp-review-pg` / `masp-fix-pg`) was
  removed after use; none should remain (`docker ps -a` is the way to check —
  a stale one is a leftover from this branch's work, not a signal of a wider
  problem).
- Frontend: `npm --prefix frontend test` (136 tests passing), `run build`,
  `run contracts:check`. Regenerate contracts with
  `npm --prefix frontend run contracts:generate` after browser API changes.
  `run test:e2e` for Playwright (33 scenarios passing).
- Browser acceptance uses temporary SQLite and a fixture server, not live data.
  On Windows Playwright teardown may leave fixture processes running; identify
  the exact owned PIDs before stopping them.
- Preserve live containers `masp-app-1`, `masp-worker-1`, `masp-postgres-1` and
  `masp-clamav-1`. These were briefly down (exit 137, likely memory pressure
  from running the full suite plus e2e plus a disposable PostgreSQL
  concurrently) during this branch's work and were restarted; volumes
  (`masp_postgres-data`, `masp_clamav-db`) were never at risk. Temporary
  acceptance containers are separate and must be stopped after tests. Never
  retain real credentials in this handoff or test artifacts.

## Open acceptance gates

Production-shaped PostgreSQL load, TLS/proxy/static deployment, full legacy
parity, large/oversized output handling, per-client rate limiting, and
installed Windows SCM/failure/failover/signing acceptance remain open. Local
tests do not promote production engine support. See "Deployment gates
outstanding" above for what was actually discussed with the user and why each
one is still open.
