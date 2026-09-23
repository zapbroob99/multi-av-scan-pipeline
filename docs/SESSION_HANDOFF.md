# MASP session handoff

Updated: 2026-09-23 (client storage access implemented and verified; client dialog, named profiles and storage access remain uncommitted). This is a workspace checkpoint, not evidence of a deployment.

## Start here

1. Read the root `AGENTS.md` completely.
2. Inspect `git status`, staged changes and the current diff. Preserve all work;
   do not reset, discard or automatically stage unrelated files.
3. Read `docs/architecture/FRONTEND_SEPARATION.md`, especially the complete UI
   inventory and the latest implementation/validation sections.
4. Read `docs/architecture/ENGINE_DEPLOYMENT_AND_WORKER_AGENT.md` and the remaining
   gates in `docs/security/HARDENING_PHASE_1.md`.
5. If continuing the client-flexibility or large-file work, read
   `docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md` and
   `docs/architecture/MAPPED_SOURCE_INSPECTION.md` (design-only; several OPEN
   decisions block implementation there).

## Git checkpoint

Checkpoint branch: `feat/frontend-separation-hardening`, HEAD `fc8738f`.
The locally recorded `origin/feat/frontend-separation-hardening` is at `18123f7`;
Git reports ahead by 7 commits. No fetch was performed during the 2026-09-23 check,
so this is the local tracking state, not a fresh verification of the server.
Commits, oldest first:

- `18123f7` trailing-whitespace cleanup (recorded remote baseline; earlier history includes administrative user management)
- `76a229c` audit-history and About slice
- `a54ff68` printable-report and oversized-engine-output slice
- `6915912` integration-batch-download slice (closes the oversized family)
- `12229d8` docs only: `docs/architecture/MAPPED_SOURCE_INSPECTION.md` design draft, nothing implemented
- `b2ec544` `file_type` header-inspection engine (first step of that design doc's sequence)
- `1c0d03c` sidebar icon fix (five items shared `Activity`, two shared `ArrowUpRight`)
- `fc8738f` (current `HEAD`) client-readiness/setup view per service client

Confirm with `git log -1` and `git status` rather than assuming this list is still
current — later work may exist uncommitted or in further commits. A new session
in this same workspace can resume from the files on disk. A different clone or
machine will NOT receive the current client dialog/profile work by fetching:
those changes, including this handoff, have not been committed or pushed.

Implementation files still untracked and required for the current work:
`frontend/src/components/client-navigation.tsx`,
`frontend/src/components/client-workspace.tsx`, and
`tests/test_profile_management.py`; storage adds
`app/services/client_storage_policy.py`, `app/services/client_storage_admin.py`,
`frontend/src/pages/client-storage.tsx`, `frontend/src/pages/client-storage.test.tsx`,
`frontend/e2e/client-storage.spec.ts`, and `tests/test_client_storage.py`.
Preserve them along with the tracked diff.
No commit or deployment was performed in the recovery/handoff check.

Pre-existing staged files to preserve: `bench_sample.txt`, `sample_30mb.bin`,
`sample_45mb.bin`, `sample_5mb.bin`, `skills-lock.json`. These unrelated files are
intentionally excluded from the migration checkpoint and remain staged locally;
they are not required to continue the UI migration.

`docs/PILOT_FOLLOWUPS.md` must stay UNTRACKED: the repository is public and that
file still carries partner naming. It was staged at the previous checkpoint and
has been unstaged; do not add it.

## Current work

**Uncommitted client storage access (2026-09-23).** User authorized continuing
with backend-to-client mapping administration. A new Storage tab and standalone
`/console/service-clients/{id}/storage` show approved backend keys and effective
whole-backend/prefix grants. GET/PUT browser routes enforce admin/pre-body CSRF,
strict bounded JSON, a displayed revision and a visible-environment fingerprint.
Writes replace the grant set under the client lock; stale writes fail and the UI
requires explicit refresh after every outcome. No roots or filesystem probes.

New `service_client_storage_policies` table migrates in place on SQLite/PostgreSQL.
Existing clients inherit `MASP_DEFERRED_BACKEND_CLIENTS_JSON`. A confirmed custom
policy replaces (never unions with) those grants; empty custom grants deny all.
Reset to inheritance keeps a revision row. The legacy compatibility client stays
read-only. Backend roots still come from `MASP_DEFERRED_STORAGE_BACKENDS_JSON` or
the single-backend deployment variables. Runtime authorization is shared by API
admission and the worker before copying, with no cache or permissive DB-error
fallback. Revoked queued work fails before copying; already-started copies may
continue, and accepted scan routing remains unchanged.

Validation at this checkpoint: full suite with disposable PostgreSQL **876 tests
(874 passed, 2 skipped)**, including 22 storage SQLite/PostgreSQL cases and public
deferred admission; **136 frontend tests**; all **8 relevant Edge workflows** passed
(6 existing client workflows plus 2 storage workflows; the storage selectors were
corrected and the 2 storage cases rerun). Build, contract drift, compile and diff
whitespace checks passed. Desktop/mobile storage screenshots were inspected.
Full backend log: `artifacts/storage-full-suite.log`. Browser fixtures are isolated
SQLite; their owned processes were stopped. Test PostgreSQL uses disposable
`masp-test-pg-storage` on port 15438, removed after tests. Live MASP containers
remain untouched.

Coordinated deployment is required: upgrade every API replica and deferred-intake
worker before custom grants are saved; older processes enforce environment only.
Rollback also needs reconciled environment grants. This is documented in
`docs/deployment/PRODUCTION.md#client-storage-access-rollout`. No deployment,
commit, new storage provider, hash-list adapter or in-place reading was performed.

**Uncommitted multiple named profiles (2026-09-22).** User explicitly authorized
implementation. Client Profile routing supports create/rename/enable/disable,
default selection and delete, alongside engine assignment. Browser writes fence
profile revisions and the previous default; shared legacy/browser locks order the
client before profiles. Defaults cannot be disabled/deleted. Deletion tombstones
profiles and keeps names reserved so accepted scans and deferred rows survive.
SQLite/PostgreSQL upgrades add the revision/tombstone columns, client seek index
and partial unique default index with deterministic duplicate-default repair.
New API selection: `profile_id` in upload multipart, deferred JSON or hash query;
only own enabled profiles, generic 404 for unavailable selections, omission uses
the default. ICAP resolves the bound default in the same profile/engine snapshot.
Legacy credentials reject explicit selection. Source/quota and decision semantics
are preserved. No mapped-source reading, hash list or backend mapping UI was added.
See `docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md` and
`docs/integrations/API_SCAN_GATEWAY.md` for the complete contract.

Validation: full backend suite with disposable PostgreSQL ran **848 tests
(846 passed, 2 skipped)**. Added ICAP/new-default and unknown-adapter regressions
after that run; the final focused profile suite covers **27 SQLite/PostgreSQL
tests**, including concurrent default switches, coherent routing reads, in-place
upgrade, deferred-history preservation and real HTTP admission. Browser profile
API checks cover **7 tests**. Frontend: **130 tests**, **6 related Edge workflows**,
production build, browser contract drift check and Python compile/whitespace checks.
Desktop/mobile named-profile screenshots were inspected. Full-suite log:
`artifacts/profile-full-suite.log`; artifacts are ignored. Test PostgreSQL used
only disposable `masp-test-pg-profiles` on port 15437. Cleanup was initially blocked
by the Codex usage-limit approval-review error; on 2026-09-23 the container was
verified and removed. Browser fixture processes had already been stopped.
No live deployment was made.

**Uncommitted client UI refinement (2026-09-22).** The client directory now uses
compact clickable rows. Selecting a client opens a large dialog with Settings,
Connection, Profile routing and Credentials tabs. Existing deep-link pages remain
available. Panels load on first selection and stay mounted while the dialog is open
to preserve write outcomes and refresh requirements; leaving Credentials clears
the token input. Confirmations/pending writes lock tab changes and outer dismissal.
Profile cursors inside the dialog do not change the directory cursor. Setup separates
readiness checks from endpoint reference, routing uses engine selection cards,
and creation groups identity, routing and API access. Styles cover both themes
and mobile widths. API contracts, secret handling, confirmations, mutation fences
and explicit refresh after writes remain unchanged. All 125 frontend tests,
5 Edge workflows, production build and whitespace check passed. Screenshots live
under `artifacts/console-e2e/`; browser tests used the isolated SQLite fixture.
No deployment or backend change was made. Existing staged files remain untouched.

The full narrative for each older slice (audit/About, printable report,
oversized output, integration batch download) lives in
`docs/architecture/FRONTEND_SEPARATION.md`; this section covers only what is
not yet recorded there, i.e. the three most recent commits.

**`1c0d03c` sidebar icons (cosmetic, no backend change).** Fixed five nav items
sharing the `Activity` icon and two sharing `ArrowUpRight`; every sidebar entry
now has a distinct lucide icon. `Users` the icon is imported as `UsersIcon`
because the lazy-loaded `Users` page component already owns that name in
`main.tsx`.

**`b2ec544` `file_type` engine.** New built-in adapter
(`app/engines/file_type.py`) reads a bounded header (default 4096 bytes,
clamped 512..1 MiB) and compares the detected content family against the
declared extension — e.g. an `.exe` renamed to `.pdf`. Registered with
`detection=False`: a masquerading extension is an indicator, not a malware
identification, so it must never contribute detection coverage by default.
`mismatch_action` (`report` default, or `detect`) controls whether a mismatch
also sets `detected=True`, which the shared scoring layer (`calculate_risk`)
weights at 70 points like any other engine detection. See
`docs/integrations/SUPPORT_MATRIX.md` and the "Engine Identity" section of
`AGENTS.md`. This is the first step in the `MAPPED_SOURCE_INSPECTION.md`
sequence (design added at `12229d8`). At that commit no other step was implemented;
the uncommitted named-profile implementation is recorded above.

**`fc8738f` (HEAD) client readiness/setup view.** New
`app/services/client_readiness.py` + `GET
/api/ui/v1/service-clients/{id}/readiness` + `/console/service-clients/{id}/setup`.
Answers "is this client ready, and what does the other system need to be
told?" in one screen: five pass/fail checks (client enabled, enabled default
profile, assigned engines, at least one automation-eligible engine, active
credential), each assigned engine's automation eligibility with a stated
reason when it is excluded (disabled instance, unregistered adapter, no
file-accepting capability, or the metered-reputation exclusion), plus the
scan/status/deferred endpoints, the `Authorization: Bearer` header shape and
the `MASP_ICAP_SERVICE_CLIENT_KEY` value. No credential value is ever
returned — only a hash and fingerprint are stored. Explicitly *not* a
connectivity test: it cannot prove the integration can reach MASP, that its
token is correct, or that an engine is healthy at scan time. Documented in
`docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md`.

Validation for the last three commits together: full Python suite with
disposable PostgreSQL ran **823 tests (821 passed, 2 skipped)**; **124
frontend tests**; **30 Edge workflows** (2 new: `client-setup.spec.ts`);
production build, contract drift check, compileall and diff whitespace check
all passed. Disposable PostgreSQL containers used during this work
(`masp-test-pg-client` and earlier `-audit`/`-print`/`-batch`, ports
15433-15436) were all removed after their runs. Live containers
(`masp-app-1`, `masp-worker-1`, `masp-postgres-1`, `masp-clamav-1`) were never
touched. No deployment was performed.

**Next development candidate:** the local hash-list adapter (step 2 of the
mapped-source sequence), followed by the deferred legacy parity sweep (manual
filters, hash provider detail, System metric detail) and final cutover inventory.
Multiple named profiles and client storage-access administration are now implemented.
Filesystem roots deliberately remain deployment settings. In-place reading and
deliberately narrow coverage semantics remain OPEN; do not infer authorization
to implement those unresolved designs from completion of these admin features.

## Verification and environment safety

- Full backend: `python -m unittest discover -s tests`.
- PostgreSQL tests require `MASP_TEST_POSTGRES_URL` pointing only at a disposable
  database: tests drop/recreate its public schema. Never use the live MASP DB.
- Frontend: `npm --prefix frontend test`, `run build`, `run contracts:check`.
  Regenerate contracts with `npm --prefix frontend run contracts:generate` after
  browser API changes. Use relevant Playwright scenarios via `run test:e2e`.
- Browser acceptance uses temporary SQLite and a fixture server, not live data.
  On Windows Playwright teardown may leave fixture processes running; identify
  the exact owned PIDs before stopping them.
- Preserve live containers `masp-app-1`, `masp-worker-1`, `masp-postgres-1` and
  `masp-clamav-1`. Temporary acceptance containers are separate and must be stopped
  after tests. Never retain real credentials in this handoff or test artifacts.

## Open acceptance gates

Production-shaped PostgreSQL load, TLS/proxy/static deployment, full legacy parity,
large/oversized output handling and installed Windows SCM/failure/failover/signing
acceptance remain open. Local tests do not promote production engine support.
