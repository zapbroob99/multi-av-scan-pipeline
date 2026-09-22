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
The migration through administrative user management is included in the checkpoint
commit containing this handoff, following `e2b90dd`. Use `git log -1` to identify
the exact checkout and fetch this branch when resuming from another clone.
Verify local/remote branch equality and actual Git status; this file cannot prove
that a push completed or that later work is committed.

Pre-existing staged files to preserve: `bench_sample.txt`, `docs/PILOT_FOLLOWUPS.md`,
`sample_30mb.bin`, `sample_45mb.bin`, `sample_5mb.bin`, `skills-lock.json`.
These unrelated files are intentionally excluded from the migration checkpoint
and remain staged locally; they are not required to continue the UI migration.

## Current work

Completed before this run: React Account password changes, atomic session
revocation, local-login password fencing and auth-session user index. Full suite:
766 Python tests (764 passed, 2 skipped); 104 frontend tests; focused Edge account
acceptance, production build and contract check passed.

Completed and locally verified: administrative user role/password editing and
deletion. Both browser UIs use `user_admin.manage`, with
cross-row last-admin serialization, fresh actor-role checks, target revision
fences in React, and atomic password reset/session revocation. Startup adds
`users.management_revision`; own-password/legacy/LDAP writes increment it.
Validation checkpoint (2026-09-22): full suite with disposable PostgreSQL ran
784 Python tests (782 passed, 2 skipped); 108 frontend tests passed. Focused Edge
user-management acceptance, production build, contract drift check and diff
whitespace check passed. PostgreSQL tests exposed an existing dict-row indexing
error in count_users_by_role; it was fixed and the full suite then passed.
Temporary test servers and database were stopped. No pending code/test work remains
in this slice; no deployment was performed. Git delivery is described above.

Next: audit history and About, then remaining
manual/hash/System/oversized-output parity and final cutover inventory. All UI is
the target; legacy links are temporary. Do not remove legacy before parity and
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
