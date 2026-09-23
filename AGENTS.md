# MASP Agent Notes

For a fresh chat/session, also read `docs/SESSION_HANDOFF.md` for the workspace/Git
checkpoint and verification status. Always inspect actual Git state and preserve
staged, unstaged and untracked work; the handoff is not a substitute for the diff.

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
  The console has complete light/dark palettes. First load follows the system
  preference; an explicit browser-local selection is applied by the same-origin
  `/console/theme-init.js` before React renders. Keep it compatible with the
  frontend CSP and never put user, scan or secret data in theme storage.
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
- Dashboard bulk deletion is admin-only and limited to 20 unique visible manual
  non-child rows. Preserve CSRF plus per-row attempt/job-revision fences and the
  shared active/child/sample/outbox protections. Each row commits independently;
  report deleted, blocked and cleanup-failed IDs explicitly and never auto-retry
  an ambiguous request. Recursive batch deletion remains separate work.
- Browser sample submission is the exact multipart `POST /api/ui/v1/scans` route;
  authenticate and verify CSRF before parsing, share `bounded_upload` admission,
  and use existing manual transactional intake. Never apply the JSON 128 KiB
  cap to sample files or widen multipart exceptions to other browser endpoints.
  HTTP 202 means accepted, not completed.
- Manual report summaries use a consistent database read snapshot and the shared
  backend decision/coverage helpers; React must not calculate an allow decision.
  Raw output/findings are on-demand, bounded text previews. Oversized/invalid
  policy input suppresses the compact decision, never silently permits a scan.
  Per-result full output is available at `/console/scans/{id}/results/{result_id}`
  through a separate `/api/ui/v1/scans/{id}/results/{result_id}/full` read. Enforce
  manual-source/result ownership and a consistent snapshot for the 2 MiB source
  preflight and hydration; also cap serialized JSON at 2 MiB. Render raw output,
  details and findings as inert text, never policy input. No polling or retained
  output cache; oversized output keeps the legacy fallback.
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
- API integrations resolve to a service client and its default or explicitly
  selected own enabled scan profile. ICAP processes bind to a client's default
  with `MASP_ICAP_SERVICE_CLIENT_KEY`.
- Large-file clients may submit client-authorized, deployment-approved
  backend/object references; a separate deferred intake worker copies and
  verifies them before scan intake. Deferred backend access is fail-closed:
  every backend must be explicitly mapped to allowed service clients, and shared
  roots should use prefix scopes. Client custom storage grants replace environment
  grants; empty custom grants deny all. Deployment retains ownership of roots.
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

The built-in `file_type` adapter inspects a bounded header (default 4096 bytes, clamped
512..1 MiB) and compares the detected content family with the declared extension. Keep its cost
independent of sample size: never read the whole file. It is registered with `detection=False`
because a masquerading extension is an indicator, not a malware identification, so it must not
contribute detection coverage. A mismatch is always a normalized finding; `mismatch_action`
selects whether it also sets `detected`, which the shared scoring layer weights like any engine
detection. Blank configuration values mean unset, matching the ClamAV and Defender resolution.

The built-in `hash_list` adapter checks the sample's MASP-computed SHA-256 against one
institution-wide list in `hash_list_entries`; it reads no sample bytes and never compares a
client-supplied digest. A blocklist match sets `detected`; an allowlist match is an informational
finding that must never suppress another engine's detection or produce an allow decision. It is
`detection=False`: "not listed" proves nothing, so it never contributes coverage. A failed lookup
is a `failed` result, never "not listed". It reads MASP's database live (`requires_database`), so
control-API workers must not advertise or run it. A digest is on at most one list; adding one that
is already listed leaves it unchanged and reports where it is. The default Linux worker keys and
compose engine lists include `file_type` and `hash_list`.

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

Large-file mapped-source inspection is a design-only initiative: see
`docs/architecture/MAPPED_SOURCE_INSPECTION.md` before writing code toward it. Several OPEN
decisions there (copy vs. in-place reading, TOCTOU mitigation, result-semantics for a
deliberately narrow profile, worker-to-backend routing) block implementation; the agreed
sequence starts with header inspection and a local hash list, both of which stay inside
today's copy path, before any in-place reading. The file_type header adapter and the local
hash list (steps 1 and 2) are implemented; multiple named profiles are also implemented
independently. Deliberately narrow coverage semantics and in-place reading remain open.

The frontend target is all browser UI migrated incrementally, not permanent
legacy escape links. Track every remaining screen and cutover gate in the complete
UI inventory in `docs/architecture/FRONTEND_SEPARATION.md`. Admin `/console/system`
now exposes bounded node-ID-keyset worker reads, explicit lifecycle changes and
confirmed credential revocation. Preserve admin/CSRF checks, secret omission,
separate heartbeat/lifecycle status and existing worker ownership semantics.
Admin `/console/system/pools` now provides bounded ID-keyset pool reads and confirmed
create/edit/delete. Share legacy name/selector normalization, never save incomplete
routing previews, and preserve assigned-pool deletion protection and instance bindings.
Admin `/console/system/runtime` shows bounded worker runtime and all-source active
scan pages. Queue reads include queued/running/finalizing records, use the partial
`idx_scan_jobs_active_seek` index and never hydrate results or historical totals.
ID order is not scheduling priority; deferred intake before scan creation is absent.
Admin `/console/system/overview` adds a coherent, 30-second cached all-source
summary and read-only retention policy. Historical engine metrics load on demand,
group by recorded name (not instance identity), cap names/pages and cache one page
per process for 30 seconds. Aggregates still scan history under PostgreSQL statement
budgets; bounded output is not a scale guarantee. Retention/retry deletion can move
the minimum-result-ID group cursor. Keep full-history scale validation open.
Admin `/console/system/retention` previews at most 20 expired inactive scans across
all sources (or the smaller server batch limit). Only confirmed IDs are submitted;
verify current policy, age under the row lock, attempt/job revision, and existing
active/child/shared-sample/outbox protections. Commit each record separately and
report deletion/file-cleanup outcomes. Never auto-replay uncertain requests or
infer recursive deletion. No raw engine data is read for previews. ID pagination
and PostgreSQL read budgets do not waive deployment-scale acceptance.
Admin `/console/scan-policy` reads only the three operational policy overrides and
saves them through strict, CSRF-protected JSON. Reuse `scan_policy.validate` and
`resolve_raw`; validate every field before one atomic save. Blank removes an
override; upload policy zero does not remove the deployment HTTP body ceiling.
Reads must surface database errors rather than presenting fallback defaults as a
successful administrative read. No automatic save retries. Concurrent editing is
last-save-wins; policy environment values can differ between deployed processes.
`/console/hash-scan` supports analyst/admin manual SHA-256 reputation lookup.
GET options never probes providers; POST authenticates and checks CSRF before
parsing, uses manual-source engine selection and existing quota-aware adapters,
and returns only a bounded backend decision projection. Never expose provider
payloads/configuration or convert absent engines/partial failures into allow.
No automatic retries, polling or scan-history records. At most 16 enabled hash
engines per browser lookup; provider latency/quota and inventory scale gates remain.
Admin `/console/service-clients` lists bounded ID-keyset client metadata and confirms
name/enabled-state changes. Never read credential hashes/tokens or full profile
policies for this list. Preserve the SQL-level `legacy-default` update exclusion,
strict admin/CSRF checks and identity-specific updates. Truncated metadata must not
be silently saved by the UI. Client enabled state does not prove valid profile or
credential configuration; edits do not rewrite accepted routing snapshots.
The client list uses compact clickable rows opening a large dialog with Settings,
Connection, Profile routing, Storage and Credentials tabs; standalone deep links remain.
Load panels on first selection and keep visited panels mounted until dialog close
so tab changes preserve write outcomes and explicit refresh requirements. Lock
outer dismissal/tab changes during confirmations and writes. Clear credential
inputs on tab leave; keep profile pagination separate from the client-list cursor.
Admin `/console/service-clients/{id}/storage` reads bounded logical backend keys
and grants; GET/PUT `/api/ui/v1/service-clients/{client_id}/storage` never expose or
probe roots. Existing clients inherit `MASP_DEFERRED_BACKEND_CLIENTS_JSON`. A custom
`service_client_storage_policies` row replaces that client's environment grants;
never union them or treat an empty custom list as inheritance. Returning to
environment mode retains a revision row. Writes require pre-body admin/CSRF checks,
the displayed revision and environment-grant/backend-key fingerprint under the
owning client row lock. Managed compatibility clients remain read-only. Bound to
50 backends/grants, 32 prefixes/grant, 128-character keys, 512-character normalized
prefixes and 64 KiB serialized policy. Invalid/oversized reads must not produce an
editable partial list. Shared API/intake authorization reads current grants without
caching and fails closed on DB/policy errors. Removed deployment backends remain
ineligible. Workers recheck before copying; edits do not cancel an in-progress
copy or rewrite accepted scan snapshots. Upgrade every API/intake process before
using custom grants; older versions only enforce environment configuration.
Admin `/console/service-clients/{id}/profiles` reads a consistent bounded profile/
engine snapshot and confirms replacement routing. Limit pages to 20 profiles and
choices/assignments to 100; disable editing incomplete data. Browser writes check
client ownership, managed-client exclusion and the expected prior engine-ID set
under the shared profile write lock. Keep legacy and browser writes serialized;
selected rows remain required, matching existing editor behavior. Never rewrite
accepted routing snapshots or bypass disabled/source/quota intake filtering.
Admin `/console/service-clients/new` now atomically creates a client, default
profile, explicit engine assignments and first credential. `/credentials` under
an individual client provides 20-row keyset reads, explicit add and scoped revoke.
Secrets are write-only, share legacy token validation, and never enter React state,
query/mutation caches, response DTOs or audit details. Clear the password input
on cancellation/submission; never automatically replay writes. Credential lists
omit both hash and prefix. Preserve the `(service_client_id, id)` seek index,
pre-body admin/CSRF checks and atomic client-scoped revocation predicate.
`/console/api-ledger` now provides analyst/admin API/ICAP non-child history with
bounded ID-keyset pages, exact client/source/status/risk filters and literal search.
Unassigned ownership is explicit; unknown client IDs never widen to all clients.
Reads select only bounded sample/job/client metadata, never results or totals.
Preserve partial ledger ID/client-ID indexes and PostgreSQL statement budgets.
Browser operator visibility matches legacy sessions; service-client bearer tokens
remain outside this API. Manual report/history source restrictions stay intact.
Automation `/console/api-ledger/scans/{id}` reports, per-result full output,
batch overviews and single-scan management now reuse shared bounded readers and
protected deletion. Source scope is server-selected; manual routes remain manual.
Automation batch members must match both batch source and nullable client ID.
Preserve repeatable snapshots, accepted-routing coverage, policy suppression,
result ownership and 2 MiB output limits. Delete is admin/CSRF-only and fences the
displayed attempt/job revision under the shared row lock, protecting active scans,
children, shared samples and undelivered outbox events. Cleanup follows commit;
never replay uncertain writes. No recursive batch deletion is implemented.
Automation management now offers analyst/admin summary/full JSON/CSV downloads
through separate source-scoped browser routes. Reuse shared export builders and
coherent source-byte/engine-count admission plus 2 MiB export-content ceilings.
No raw results in summary exports; CSV strings remain forced to text. Full
historical automation exports without routing snapshots or engine jobs fail
explicitly to the legacy fallback rather than use current configuration. Download
content is not retained in React/query caches. Operator report exports are not
integration status/result JSON contract previews.
Automation reports now link to `/console/api-ledger/scans/{id}/result-json`.
This analyst/admin on-demand terminal-result preview uses shared public projections
and validates the integration result contract. Preserve coherent export admission,
recorded routing, private-field omission and the 2 MiB serialized envelope limit.
Invalid policy, active scans and missing historical routing fail explicitly. No
polling or retained query cache; render JSON as inert text.
`/console/api-ledger/scans/{id}/status-json` now previews the public status contract
for active or terminal automation scans. Read scan/results, current accepted-engine
eligibility, polling override and global queue counters in one repeatable snapshot.
Reuse shared queue queries with the caller connection and PostgreSQL statement
budgets. Expected engines is current eligibility, not required detection coverage.
Require an accepted engine snapshot; never invent a historical profile fallback.
Full-history counts remain a deployment-scale gate. No automatic browser polling.
Automation batch `/status-json` and `/result-json` views now display complete public
contracts for at most 20 registered members. Reject mixed source/client ownership;
never silently omit members or refresh stored counters. Status reads no engine
blobs. Result reads preflight the whole batch (256 results/jobs, 2 MiB combined
engine/snapshot bytes), then reuse per-scan checks in the same repeatable snapshot.
The complete response envelope is capped at 2 MiB; invalid policy, active members
or unavailable historical routing fail explicitly. Preserve inert text and no
polling/output retention. Larger batches use the paginated overview and individual
reports; oversized complete-contract parity remains a cutover gate.
Automation `/console/api-ledger/scans/{id}/children` now reuses bounded archive
navigation. Direct children and nested-presence probes must match the parent's
exact API/ICAP source, nullable client and batch. Validate parent-batch ownership
and suppress invalid upward links. Preserve ID-keyset/attempt fences, literal
filters, per-page indexed probes and repeatable PostgreSQL budgeted reads. Never
hydrate results, extract files or refresh batch counters on these GETs. First-page
active polling follows the existing manual archive rules; historical pages pause.
Admin ledger bulk deletion now accepts at most 20 unique API/ICAP top-level IDs.
Ledger reads project attempt/job revision in the same metadata query, never results.
Reuse the shared per-row locked deletion with fixed server-selected source scope,
CSRF, active/child/shared-sample/outbox guards and post-commit cleanup receipts.
Confirm the displayed ID/fence set, report deleted/blocked/cleanup-failed IDs and
never replay ambiguous writes. Require explicit fresh reads before reselecting;
manual bulk deletion remains manual. This is not recursive batch deletion.
Admin `/console/users` now provides 20-row ID-keyset local/LDAP user metadata
and confirmed local account creation. List queries omit password hashes, external
IDs and session tokens. Reuse existing password hashing and database uniqueness;
creation requires strict admin/CSRF JSON with explicit role and 8 to 4096-character
write-only password. Never retain passwords in React/query/mutation state, audit
or responses; clear on cancel/send and never auto-replay uncertain creation.
LDAP rows remain directory-managed. `/console/account` now lets local analysts
and admins confirm their own password change. Share validation with legacy; update
only the verified password using a hash predicate and revoke sessions atomically.
Local login locks the user row and checks the verified hash before session creation;
legacy admin password resets also revoke sessions within their update transaction.
Preserve the auth-session user index and PostgreSQL password-change lock budget.
No password enters React/query/mutation state, response DTOs or audit details.
Clear all password inputs on cancellation/submission; never auto-replay writes.
Directory users see guidance without a local password form. Admin Users now confirms
role changes, optional password resets and removal. React writes fence the displayed
`management_revision`; own-password changes, legacy updates and LDAP synchronization
advance that revision. Legacy and React management share a transaction-scoped
PostgreSQL advisory lock (SQLite immediate write transaction), ordered actor/target
row locks, fresh actor-role verification and last-local-admin protection. Self-edit
and self-delete are blocked. Password resets revoke sessions atomically. LDAP roles
and passwords remain directory-owned; removing a local LDAP shadow is permitted
like legacy, revokes its sessions and does not disable directory access or prevent
recreation on sign-in. Confirm that distinction. Require a fresh explicit list read
after every write outcome; no automatic replay or secret retention.
Admin `/console/audit` reads the append-only audit trail with bounded descending ID-keyset
pages, exact outcome selection and literal actor/action/target/request-ID search. No total is
calculated and the router exposes no audit write verb: the trail stays insert/read-only. Escape
`%`/`_` so an operator character matches itself. Bound projected columns, cap details at 4096
characters with an explicit truncation flag and render them as inert text. State the recorded
boundary: routine navigation, submission, polling and report reads are excluded, appends are
best effort after the operation, and the source IP is the direct socket peer. Audit retention,
export and legal hold have no application control.
`/console/about` is readable by analysts and admins and is the only non-dashboard browser read
outside the admin gate. Return the product boundary plus a non-sensitive runtime snapshot:
version, queue model, worker transport, directory-login and secret-encryption availability,
bounded engine names with a truncation flag, hash engines and worker-node counts. The
service-client total is admin-only and null for analysts, never omitted. Never expose hosts,
paths, adapter keys, engine configuration or secrets. Read only small configuration tables
under the shared budget; never aggregate scan history for this screen. Enabled engines and
schedulable nodes are configuration state, not proof of complete coverage. `app.APP_VERSION`
is the single version constant.
Admin `/console/engines/hash-list` manages the hash list through GET/POST `/api/ui/v1/hash-list`
and DELETE `/api/ui/v1/hash-list/{entry_id}`. Pages are 20-row descending ID-keyset reads; counts
are computed on the first page only. A full SHA-256 filter is an exact indexed match, shorter text a
literal hash prefix or note substring. Additions take an explicit list, at most 1000 digests and
one note; every digest is validated before one transactional insert. Entries are immutable: moving
a hash between lists is removal plus a fresh addition. Confirm both writes, never auto-replay them.
Changes affect engine jobs that run afterwards and never rewrite completed results.
`/console/scans/{id}/print` and the automation twin render a bounded printable report for
analysts and admins. Reuse the full-export snapshot loader and shared payload builder so the
printed decision, coverage, findings and engine rows come from one repeatable read; React
calculates no decision. Legacy `/scans/{id}/report` had no source scope and embedded every
engine's raw output with no ceiling: keep the server-selected scope so each route refuses the
other history, cap each engine preview at 8 KiB with a truncation flag, cap findings at 200
rows and keep the 2 MiB serialized ceiling. Print only on explicit operator action.
Result output routes serve one engine's recorded raw output as attachment `text/plain`,
replacing the legacy dead end above the 2 MiB JSON ceiling. Keep it outside the typed JSON
contract and out of React state and caches; build the filename from validated integers only.
`MASP_UI_RAW_OUTPUT_LIMIT` bounds it, defaulting to 32 MiB, clamped to 256 MiB and never below
the JSON ceiling it exists to exceed. Source scope, result ownership and read budgets still apply.
The automation batch download route serves the complete public contract as a JSON attachment
for analysts and admins, up to the same 5000 members the integration API serves, so it refuses
only what an integration could not have received either. Share one loader with the inline
preview, parameterized by member and byte limits, and keep ownership, source-consistency,
terminal-state, policy-validity and public-contract validation identical. Validate the whole
document before serving any of it: an invalid member fails explicitly, never a partial
contract. `MASP_UI_BATCH_DOWNLOAD_LIMIT` bounds it (default 64 MiB, clamped to 512 MiB, never
below the inline ceiling). The document is assembled in memory from every member, matching the
integration API's profile for the same batch, but now operator-reachable.
Every untyped browser route is enumerated in the contract test with the exact success content
it may declare; errors stay typed ErrorPayload JSON everywhere.
Next UI slice: a legacy parity sweep over manual filters, hash provider detail, System metric
detail and remaining legacy actions, then the final cutover inventory. Keep legacy System metric/detail parity, legacy audit detail/printable
parity, deployment-shaped audit-trail volume validation and deployment acceptance open;
engine pool assignment already lives in React Engines.

The authoritative plan is
`docs/architecture/ENGINE_DEPLOYMENT_AND_WORKER_AGENT.md`.

Multi-integration identity and routing are documented in
`docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md`. Service clients,
hashed/revocable API credentials, default profiles, engine assignments, scan and
batch ownership, API isolation, ledger filtering, and ICAP instance binding are
implemented. Deferred filesystem-reference intake with explicit client/backend
mapping and a transactional global HTTPS SIEM webhook outbox are implemented as
opt-in worker profiles. Multiple named profiles now support admin create/rename/
enable/delete/default selection and own-profile API selection. Next milestones are
per-client fairness/rate limits, per-client notification routes, S3-compatible storage, and
review/policy event selection.

Profile management keeps 20-profile/100-engine browser bounds and pre-body admin/
CSRF checks. Metadata/default/delete writes fence `management_revision`; engine
writes also fence the previous ID set. Serialize legacy/browser writes through the
owning client row before profile rows (SQLite immediate transaction). Default
switches compare the prior default ID; never disable/delete the current default.
Deletion tombstones the identity, preserving deferred FKs, assignments and accepted
snapshots; deleted names stay reserved. SQLite/PostgreSQL migration repairs duplicate
defaults deterministically and adds the partial unique default index. API upload
multipart, deferred JSON and hash query accept optional own enabled `profile_id`;
unavailable/foreign/deleted selections return the same 404. Legacy tokens reject
explicit selection; ICAP uses its bound default. Capture client/profile/engines in
one repeatable snapshot and preserve source/quota filtering and existing decisions.
No new narrow-profile allow semantics or mapped-source access is implemented.

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

Admin `/console/service-clients/{id}/setup` reports configuration readiness and the values an
integration must be configured with. Read client, default profile, assigned engines and active
credential count in one repeatable snapshot so a concurrent edit cannot show a state that never
existed. Explain every ineligible engine rather than hiding it, keeping the metered-adapter
exclusion adapter-level so the engine stays usable for manual scans. Never return a credential
value: only a hash and fingerprint are stored. State plainly that this is configuration
readiness, not proof that the integration can reach MASP or that an engine is healthy.

Manifest intake (`app/services/manifest_intake.py`, `--profile manifest`) accepts deferred
submissions from a storage producer that never calls MASP: it writes the object, then writes a
sibling JSON manifest last, so the manifest appearing is the completion signal. Keep the source
mount read-only and never mark a manifest processed on the share; `upload_id` becomes
`client_request_id`, so the existing unique constraint makes re-reading one free. A manifest
names what to scan and never grants access: the object must pass `backend_allowed_for_client`
and must sit in the manifest's own directory. Keep discovery bounded to recent dated partitions
and a batch limit rather than walking a growing share. The producer receives no delivery,
backpressure or error feedback, so record every rejection in `manifest_rejections` with a cap,
and clear it when the same manifest is later accepted.

Deferred retry safety must not depend on server-side configuration staying still. Answer a
repeat `client_request_id` from the accepted record before resolving live routing, and compare
only what the client asserted: backend key, object id, expected size/SHA-256, archive mode and
the explicitly requested profile (`requested_profile_id`, NULL meaning "use the default").
Never compare the routing snapshot or descriptive metadata: the snapshot carries display names,
so a rename alone used to make a byte-identical retry conflict permanently. A genuinely
different request for an existing id stays a 409, and the frozen snapshot stays authoritative
for the accepted work.

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
