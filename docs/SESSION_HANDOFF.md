# MASP session handoff

Updated: 2026-09-22. This is a workspace checkpoint, not evidence of a deployment.

## Start here

1. Read the root `AGENTS.md` completely.
2. Inspect `git status`, staged changes and the current diff. Preserve all work;
   do not reset, discard or automatically stage unrelated files.
3. Read `docs/architecture/FRONTEND_SEPARATION.md`, especially the complete UI
   inventory and the latest implementation/validation sections.
4. Read `docs/architecture/ENGINE_DEPLOYMENT_AND_WORKER_AGENT.md` and the remaining
   gates in `docs/security/HARDENING_PHASE_1.md`.

## Git checkpoint

Checkpoint branch: `feat/frontend-separation-hardening`.
The migration through administrative user management is committed at `18123f7`.
The audit/About slice is committed at `76a229c`. The printable-report and
oversized-output slice belongs in the checkpoint commit that carries this handoff;
confirm with `git log -1` and `git status` rather than assuming it landed. Fetch
this branch when resuming from another clone. Verify local/remote branch equality and actual Git status;
this file cannot prove that a push completed or that later work is committed.

Pre-existing staged files to preserve: `bench_sample.txt`, `sample_30mb.bin`,
`sample_45mb.bin`, `sample_5mb.bin`, `skills-lock.json`. These unrelated files are
intentionally excluded from the migration checkpoint and remain staged locally;
they are not required to continue the UI migration.

`docs/PILOT_FOLLOWUPS.md` must stay UNTRACKED: the repository is public and that
file still carries partner naming. It was staged at the previous checkpoint and
has been unstaged; do not add it.

## Current work

Completed before this run: React Account password changes, atomic session
revocation, local-login password fencing, the auth-session user index, and
administrative user role/password editing and deletion through the shared
`user_admin.manage` writer (cross-row last-admin serialization, fresh actor-role
checks, React revision fences, `users.management_revision`). That slice validated
at 784 Python tests (782 passed, 2 skipped) with disposable PostgreSQL and 108
frontend tests.

Completed and committed at `76a229c`: the audit-history and About slice.
Admin `/console/audit` reads the append-only trail through GET `/api/ui/v1/audit`
with bounded descending ID-keyset pages, exact outcome selection, literal
actor/action/target/request-ID search, 4096-character bounded inert details with a
truncation flag, and no total. The router exposes no audit write verb, preserving
the insert/read-only data-layer contract. Startup adds an `(outcome, id DESC)`
seek index in place. `/console/about` is readable by analysts and admins — the
only non-dashboard browser read outside the admin gate — and returns the product
boundary plus a non-sensitive runtime snapshot reading only small configuration
tables; the service-client total is admin-only and null for analysts. The FastAPI
application version is now the single `app.APP_VERSION` constant.

Validation checkpoint (2026-09-22): full suite with disposable PostgreSQL ran
793 Python tests (791 passed, 2 skipped); 114 frontend tests passed. Production
build, contract drift check, compileall and diff whitespace check passed. Focused
Edge acceptance (`frontend/e2e/audit.spec.ts`) pages the trail, applies a literal
`%` search and an outcome filter, opens inert details, refuses an analyst session
and checks admin-scoped About content at a 390px viewport. A new PostgreSQL-gated
`BrowserReadPostgresTests` class exercises both readers on real PostgreSQL, where
`LENGTH(...) > n` returns a boolean rather than 0/1.

Fixed while verifying: `frontend/src/pages/users.test.tsx` passed `exact: true` to
`getByRole`, which is not a `ByRoleOptions` key. It was failing `tsc --noEmit` — and
therefore `npm run build` — at the previous checkpoint, so that checkpoint's
recorded build pass does not hold for the committed tree.

Disposable PostgreSQL containers `masp-test-pg-audit` (15433) and
`masp-test-pg-print` (15434) were removed after their runs. Live containers were
untouched. No deployment was performed.

Also completed and locally verified in this run: the printable-report and
oversized-engine-output slice. `/console/scans/{id}/print` and the automation twin
reuse the full-export snapshot loader and shared payload builder, so the printed
decision, coverage, findings and engine rows come from one repeatable read. Two
legacy defects are closed rather than reproduced: legacy `/scans/{id}/report` had
no source scope at all, and it embedded every engine's raw output with no ceiling.
Each engine preview is now capped at 8 KiB with a truncation flag, findings at 200
rows, and the serialized response keeps the 2 MiB ceiling.

`GET /api/ui/v1/scans/{id}/results/{result_id}/output` and its automation twin
serve one engine's recorded output as attachment `text/plain`, replacing the
"use the legacy report" dead end above the 2 MiB JSON ceiling. These are the only
browser reads outside the typed JSON contract; `tests/test_browser_contracts.py`
now enumerates them so a new non-JSON route cannot appear unnoticed, and still
requires JSON `ErrorPayload` on their errors. `MASP_UI_RAW_OUTPUT_LIMIT` bounds
the download (default 32 MiB, clamped to 256 MiB, never below the JSON ceiling).
Each download reads one result into memory in a worker thread; it is not a
streaming transfer, so it is sized against container memory in PRODUCTION.md.

Printable/oversized validation (2026-09-22): full Python suite with disposable
PostgreSQL ran 798 tests (796 passed, 2 skipped); 119 frontend tests; 28 Edge
workflows; production build and contract drift check passed. The console fixture's
engine output was widened to exercise the new bound, so two existing report
assertions moved from exact-match to containment.

Next: remaining manual filter parity, hash provider detail, System metric parity,
oversized complete integration payloads, then the final cutover inventory. All UI
is the target; legacy links are temporary. Do not remove legacy before parity and
security/performance gates pass. Recursive batch deletion remains separate work.

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
