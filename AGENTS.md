# MASP Agent Notes

## Project Direction

MASP is a self-hosted multi-engine malware scan orchestrator. Preserve the
offline-first decision path, normalized engine results, source-aware quota rules,
and crash-safe database queue. Do not turn vendor integrations into user-defined
arbitrary command parsers.

## Current Runtime

- FastAPI app/UI, scan workers, and optional ICAP gateway are separate processes.
- An opt-in React/TypeScript console in `frontend/` serves `/console/dashboard`,
  `/console/engines`, `/console/scans/new`, manual `/console/scans/{id}` reports
  `/console/scans/{id}/children` archive navigation and `/console/batches/{id}`
  manual batch overviews, plus
  `/console/scans/{id}/manage` summary/full exports and single-scan management
  through the session-authenticated `/api/ui/v1` JSON API. Legacy UI remains.
  Share adapter validation through `app/services/engine_setup.py`; preserve
  browser CSRF/admin checks and never expose integration tokens. See
  `docs/architecture/FRONTEND_SEPARATION.md` for migration scope and gates.
- Browser contracts are exported from the router without importing `app.main`
  or accessing deployment data. Keep `frontend/contracts/browser.openapi.json`
  and `frontend/src/lib/api.generated.ts` synchronized with
  `npm --prefix frontend run contracts:generate`; use `contracts:check` in CI.
  Generated types are build-time only. The isolated generator's TypeScript 5
  dependency must not downgrade the console's TypeScript 7 toolchain.
- Dashboard reads are manual/non-child only, session-authenticated for analysts
  and admins. Preserve ID-keyset pagination, bounded preview payloads and the
  30-second per-process aggregate cache; never hydrate raw engine output for
  history. Recorded risk is not coverage or an allow/clean decision. Substring
  search and uncached totals passed the documented local 100k-row PostgreSQL
  acceptance budget, but still require deployment-shaped load validation.
- Browser sample submission is the exact multipart `POST /api/ui/v1/scans` route;
  authenticate and verify CSRF before parsing, share `bounded_upload` admission,
  and use existing manual transactional intake. Never apply the JSON 128 KiB
  cap to sample files or widen multipart exceptions to other browser endpoints.
  HTTP 202 means accepted, not completed.
- Manual report summaries use a consistent database read snapshot and the shared
  backend decision/coverage helpers; React must not calculate an allow decision.
  Raw output/findings are on-demand, bounded text previews. Oversized/invalid
  policy input suppresses the compact decision, never silently permits a scan.
  Preserve legacy report links for the full-output screen and bulk actions.
- Summary exports reuse the coherent bounded report and preserve null decisions;
  they omit raw output/findings/children explicitly. CSV string values are forced
  to text. Full JSON/CSV exports use the same database snapshot and backend report
  builder; JSON includes raw output, details and findings while CSV retains the
  normalized operator rows. Preflight both engine count and source bytes before
  hydrating blobs; enforce the separate 2 MiB serialized-output ceiling, omit
  sample bytes/storage paths and suppress decisions for invalid policy details.
  Retry is analyst/admin; delete is admin-only. Both browser writes
  require CSRF plus the displayed attempt and engine-job revision under a row lock.
  Retry resets results and inserts engine jobs atomically; manual source/quota
  rules and routing snapshots remain authoritative. Delete rejects active scans,
  shared samples and undelivered outbox events; browser deletion also rejects
  parents with registered children. File cleanup follows commit and its failure
  is reported separately. Mutations never automatically retry.
- Archive navigation reads only registered direct manual children in the parent's
  batch, with bounded ID-keyset pages and an attempt guard for later pages. Reuse
  the parent/id index and bounded per-page child-presence probes; do not load
  entire trees, engine blobs or refresh batch counters on GET. PostgreSQL browser
  reads use transaction-local statement budgets and custom plans. Empty lists and
  completed/zero-risk rows never prove clean coverage or successful extraction;
  retries may retain earlier child records.
- Manual batch overviews read all registered manual members, including nested
  members, with `(created_at, id)` keyset pages over `idx_scan_jobs_batch_created`.
  Use a consistent read snapshot and stored batch counters; never refresh counters,
  load engine blobs or expose automation members on GET. Stored counts/recorded risk
  may lag workers and never prove clean coverage or complete extraction.
- PostgreSQL is required for Docker/hybrid deployments; SQLite is local-test only.
- Workers may use the HTTPS control API without database credentials or shared
  sample storage; direct database/shared-filesystem workers remain compatible.
- ClamAV normally uses clamd TCP. Defender executes locally on a Windows worker.
- API and ICAP submissions exclude adapters with `consumes_external_quota`.
- API integrations resolve to a service client and default scan profile; ICAP
  processes may bind to one client with `MASP_ICAP_SERVICE_CLIENT_KEY`.
- Large-file clients may submit client-authorized, deployment-approved
  backend/object references; a separate deferred intake worker copies and
  verifies them before scan intake. Deferred backend access is fail-closed:
  every backend must be explicitly mapped to allowed service clients, and shared
  roots should use prefix scopes.
- Deferred high/critical results enter a transactional notification outbox. The
  optional notification worker performs idempotent SIEM webhook delivery with
  retry/backoff; scan completion must never call a webhook directly. Retention
  and manual deletion must preserve scans with undelivered outbox events.
- Accepted automation scans persist an immutable routing snapshot. Retries,
  workers, coverage, and decisions must use that snapshot rather than the
  profile's current engine set.
- Engine-job ownership uses leases, attempt generations, and fenced result commits.
- HTTP uploads authenticate before multipart parsing and enforce a deployment
  body ceiling independently of sample policy. Deferred paths reject links and
  validate opened sources; worker-control/webhook requests reject redirects.
  See `docs/security/HARDENING_PHASE_1.md` for upgrade notes and remaining gates.

## Engine Identity

- `adapter_key` identifies vendor behavior and is not an instance identity.
- `engine_instances.id` identifies one configured deployment.
- Multiple ClamAV and Defender instances are supported; display names must remain
  unique so compatibility reports and result coverage stay unambiguous.
- The Engines UI creates an instance only after an admin supplies a unique name
  and every adapter-specific initial setting; suggested values are placeholders,
  not silently persisted defaults. Built-in non-configurable adapters are exempt.
- Queue idempotency is `(scan_job_id, engine_instance_id)`.
- Workers advertise adapter keys but must resolve claimed jobs by instance id.
- Keep fallback adapter-key routing only for legacy jobs without an instance id.
- Startup migration must not rebind historical jobs from a deleted instance to a
  different surviving instance that happens to share its adapter key.

## Active Roadmap

The authoritative plan is
`docs/architecture/ENGINE_DEPLOYMENT_AND_WORKER_AGENT.md`.

Multi-integration identity and routing are documented in
`docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md`. Service clients,
hashed/revocable API credentials, default profiles, engine assignments, scan and
batch ownership, API isolation, ledger filtering, and ICAP instance binding are
implemented. Deferred filesystem-reference intake with explicit client/backend
mapping and a transactional global HTTPS SIEM webhook outbox are implemented as
opt-in worker profiles. Next milestones are multiple named profiles, per-client
fairness/rate limits, per-client notification routes, S3-compatible storage, and
review/policy event selection.

Durable worker nodes have stable identity, labels, capacity, advertised adapters,
heartbeat/runtime metadata, and admin-managed lifecycle. Engine instances can be
bound to exact-match label pools; claims enforce node lifecycle and capacity.
Unbound instances intentionally retain adapter-key compatibility routing. Workers
lease and persist per-node/per-instance engine health without spending external
reputation quota. The HTTPS Worker Control API now provides enrollment, hashed
rotatable agent credentials, heartbeat, fenced job/health operations, and
authenticated size/SHA-256-verified sample delivery. The Windows SCM service,
least-privilege/ACL installer, installed-config preflight, lifecycle scripts,
rotating logs, deterministic release bundle, bundle-integrity verifier, and
evidence-producing service/clean/EICAR host acceptance runner are implemented.
Real Windows 11 development-host runs have passed direct-database and HTTPS
control-plane clean/EICAR scanning, including authenticated sample download,
fenced result submission, full clean coverage, and Defender
`Virus:DOS/EICAR_Test_File` detection. The HTTPS run used a temporary elevated
agent rather than the installed SCM service. Next milestone: execute and retain
the SCM identity plus full failure/failover/lifecycle matrix, apply organizational
release signing, and promote support only after those gates pass.
Direct worker database access and shared filesystem paths are compatibility modes,
not the final remote-worker architecture.

## Change Rules

- Maintain in-place SQLite and PostgreSQL upgrade compatibility.
- Retention must never delete queued, running, or finalizing scans; long-lived
  deferred work is an explicit supported state.
- Preserve existing local Docker and hybrid Windows-worker workflows.
- Keep engine configuration and lifecycle actions instance-specific.
- Add clean, detected, timeout/unavailable, migration, and concurrency coverage
  proportional to each adapter or queue change.
- Update README, the architecture document, deployment docs, support matrix, and
  this file when runtime topology or support state changes.

## Verification

Run the SQLite suite with:

```powershell
python -m unittest discover -s tests
```

PostgreSQL-gated concurrency tests require a disposable database through
`MASP_TEST_POSTGRES_URL`; never point them at a real MASP database because the
test harness recreates the public schema.
