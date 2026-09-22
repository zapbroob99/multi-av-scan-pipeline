# Engine Deployment and Worker Agent Architecture

## Goal

MASP separates a vendor integration from a configured deployment:

- **Adapter:** MASP code that knows one vendor product and integration method.
- **Engine instance:** one named, configured deployment of an adapter.
- **Worker node:** one machine that can execute one or more adapter types.
- **Worker pool:** a selector-based group of compatible worker nodes.

This lets an operator model deployments such as `ClamAV Istanbul`, `ClamAV DR`,
and `Defender Windows Pool A` without duplicating vendor parser code.

## Current State

The frontend goal covers every browser screen; the complete migration inventory
is maintained in [frontend separation](FRONTEND_SEPARATION.md#complete-ui-migration-inventory).
Admin worker inventory, lifecycle and credential revocation now use the React
System screen and bounded browser API. Pool CRUD is now available through paginated
React System pages, preserving exact label selectors and assigned-pool deletion
protection. The next slice is audit/information, followed by the remaining parity
inventory. Existing acceptance gates
remain in force.
The React runtime screen now provides bounded worker snapshots and all-source
active-queue pages. A partial active-ID index is added in-place for SQLite and
PostgreSQL. No historical aggregates or engine output are loaded by these reads;
the separate overview now provides a coherent cached summary, read-only retention
policy and on-demand metrics grouped by historical engine name. Those names are
not stable instance identities. Summary and one metric page are cached for 30
seconds; historical aggregation remains subject to PostgreSQL time budgets and
deployment-scale acceptance. React retention now previews and confirms at most 20
expired inactive records per run, preserving row-locked age/attempt/job-revision
checks and active/child/shared-sample/outbox protections. Each record commits
separately and file cleanup failures are explicit. No recursive deletion or new
worker protocol is introduced. Engine pool assignment already uses React Engines;
legacy System metric/detail parity remains an acceptance item. Admin scan policy
now uses React with shared validation/resolution, an atomic three-field save and
pre-body CSRF/role checks. Manual hash lookup now uses React with existing source/
quota selection, backend decision aggregation and bounded output. Partial failures
return no complete decision and are never retried automatically. Integration
administration now has a bounded React client inventory with confirmed name/state
updates and managed-client protection. Client profile routing now uses bounded
React reads and confirmed instance assignments. The shared writer serializes
updates and browser writes fence the previous ID set, client ownership and managed
identity. Accepted snapshots and source filtering remain unchanged. Atomic client/default-profile creation and credential add/list/scoped revoke now
use React with write-only secrets and no automatic replay. Automation history now uses bounded React ledger reads with exact ownership/source
filters and partial seek indexes. Automation reports/output, source-and-client-scoped batch reads and fenced
single deletion now reuse shared services through separate browser routes.
Automation summary/full JSON/CSV exports reuse the bounded snapshot builders;
historical full exports without recorded routing keep an explicit legacy fallback; deployment HTTP caps,
source-aware routing and queue semantics are unchanged.

The opt-in [independent console](FRONTEND_SEPARATION.md) uses a versioned
browser API, shared engine setup validation and a bounded manual Dashboard
with ID-keyset pages and cached aggregate totals. Manual sample submission now
uses a CSRF-protected multipart browser endpoint and the same transactional
intake as legacy uploads. Analysts can read the Dashboard and submit files;
engine management remains admin-only. Manual reports now use consistent read
snapshots, shared backend assessment and on-demand bounded technical previews;
registered archive children now have bounded direct-child navigation with an
attempt-fenced cursor and manual/batch scoping. Empty lists never imply clean
extraction. Manual reports now link to bounded JSON/CSV summary and full exports and
confirmed retry/delete management. Analyst/admin retry resets and queues engine
jobs atomically; admin deletion protects active scans, shared samples, registered
children and undelivered notifications. Attempt plus engine-job revision prevents
stale browser actions even when a queued retry settles before a worker starts.
Manual batch overviews now use bounded indexed pages and stored counters without
loading engine output or refreshing counters. Admins may bulk-delete up to 20
visible top-level manual scans with per-row attempt/job-revision fences and partial
receipts. Individual full engine outputs now have a React screen with coherent
2 MiB source/response admission and inert text rendering. Oversized output keeps
a legacy fallback; recursive batch actions remain planned. This changes browser delivery, not worker
transport, scan routing or engine support state. A local disposable PostgreSQL
run passed the documented 100k-row browser query/concurrency budgets. Full-text
indexing and deployment-shaped PostgreSQL load remain gates, not completed work.
Browser contracts now have offline OpenAPI export, generated TypeScript DTOs,
route/method/JSON-body typed calls and read-only drift checks. A Windows/Linux
CI workflow is defined; remote CI acceptance is separate from local validation.
Worker protocols and engine support states are unchanged. Browser read indexes
and the users.management_revision column are additive in-place upgrade work.

The first multi-instance foundation is implemented:

- `engine_instances.adapter_key` is no longer unique.
- Engine display names remain unique so reports are unambiguous during the
  compatibility period.
- ClamAV and Microsoft Defender advertise multi-instance support in their
  capability profiles.
- The Engines catalog performs initial configuration before persistence: admins
  choose the adapter, supply a unique deployment name, and explicitly complete
  its required runtime/connection policy. It does not create an enabled empty
  instance and rely on inherited defaults afterward.
- Queue idempotency is keyed by `(scan_job_id, engine_instance_id)`, not by the
  shared adapter key.
- Workers still advertise adapter capabilities such as `clamav` or
  `microsoft_defender`, but select the exact configured instance by its database
  id after claiming a job.
- Engine toggle, delete, connection-test, and configuration forms carry the
  instance id, so editing one deployment does not alter another deployment of
  the same adapter.
- Existing SQLite and PostgreSQL installations migrate in place. Legacy jobs
  without an instance id are backfilled only when their stored engine name
  matches a surviving adapter instance. Jobs from a deleted named instance stay
  unbound instead of being silently reassigned to another instance with the same
  adapter key; unbound jobs retain compatibility fallback routing.
- Workers register a durable node keyed by `MASP_WORKER_NODE_ID` (hostname is the
  compatibility default) with display name, platform, agent version, labels,
  capacity, advertised adapter keys, runtime state, and last heartbeat.
- Process identity remains separate for queue lease fencing. Multiple process
  heartbeat rows may belong to one stable node across restarts or capacity slots.
- Admins manage node lifecycle from the System page. `draining` and `disabled`
  nodes finish owned work but do not claim new jobs; `offline` is derived from
  heartbeat age and never overwrites the requested lifecycle.
- Legacy single, bulk, and per-process heartbeat settings remain readable during
  rollout. New workers write both the durable node and compatible process row.
- Admins create worker pools in the System view with exact-match node-label
  selectors such as `site=istanbul,os=windows`, then bind engine instances to a
  pool. Unbound instances retain compatibility routing to any capable worker.
- A bound engine job may be claimed only by an active node that advertises the
  adapter and matches every pool selector. Disabled pools fail closed.
- Claim transactions lock the durable node, enforce its configured capacity
  across worker processes, and preserve FIFO job order. A second matching node
  can claim new work when the first is draining, disabled, full, or offline.
- Workers lease due health checks per node and engine instance, run the adapter
  probe locally, and persist normalized status, vendor detail, product/engine/
  signature versions when available, service state, storage access, failure
  streak, and last successful scan timestamp. Fenced commits prevent an expired
  health worker from overwriting a newer probe.

The current release supports two worker transports:

- `control_api` workers use a node-bound agent credential over HTTPS and receive
  no PostgreSQL credential. They register, heartbeat, claim work, renew leases,
  submit fenced results and health reports, and download only their owned sample.
- The sample response is bound to worker id plus attempt generation. The agent
  verifies declared size and SHA-256 before scanning and removes its temporary
  copy afterwards.
- Agent operation URLs may be API-relative or origin-relative, but resolution is
  pinned to the configured control-plane origin so credentials cannot be sent to
  a server-selected external host.
- HTTP redirects are rejected. Heartbeat continues during downloads, scans,
  health probes and result submission; job leases renew from before download
  through result acknowledgment. Finalization uses the scan routing snapshot.
  See [phase 1 hardening](../security/HARDENING_PHASE_1.md) for scope and gates.
- `database` workers retain direct PostgreSQL and shared-filesystem access as a
  compatibility mode for existing Docker and hybrid installations.
- MASP executes Defender on the Windows agent itself; remote PowerShell/WinRM
  command execution is intentionally not supported.
- Heartbeat and engine health remain separate signals: heartbeat proves process
  liveness while `engine_node_health` proves the last worker-executed adapter and
  storage probe.

## Invariants

- Adapter keys describe executable behavior and may be shared by many instances.
- Scan jobs and future assignments use engine instance ids for identity.
- Display names must be unique and stable while jobs referencing them are active.
- A worker may claim only adapter keys supported by its operating system and
  `MASP_WORKER_ENGINE_KEYS` assignment.
- Vendor verdict parsing and normalization remain product-specific MASP code;
  users cannot upload arbitrary command parsers.
- Fenced leases remain authoritative. A superseded worker cannot commit a result.
- Metered adapters remain excluded from API and ICAP automation by capability.

## Delivery Sequence

### 1. Multi-instance foundation — implemented

- Lift adapter uniqueness.
- Preserve unique operator-facing names.
- Queue and route by instance id.
- Make settings and lifecycle actions instance-specific.
- Preserve legacy database and route behavior.

### 2. Managed worker nodes — implemented

- Add the durable `worker_nodes` model and stable enrollment identity.
- Persist platform, version, labels, capacity, adapters, runtime state, active
  scan, process id, and heartbeat timestamp.
- Preserve admin lifecycle across heartbeats and gate new claims accordingly.
- Derive offline state from age while retaining legacy heartbeat readers.
- Expose node inventory and lifecycle controls in the existing System view.

### 3. Worker pools and scheduling — implemented

- Add exact-match label selectors and explicit engine-instance bindings.
- Preserve unrestricted compatibility routing for unbound instances.
- Enforce lifecycle and node-wide capacity in the atomic claim transaction.
- Make timeout/reaper coverage pool-aware and allow deterministic failover to a
  second compatible node.
- Expose pool CRUD and engine placement in the System view.

### 4. Worker-executed health checks — implemented

- Lease and execute probes on matching workers rather than the API host.
- Persist normalized state, product/engine/signature metadata, service and
  storage state, last success, failure streak, and last successful real scan.
- Surface node health summaries in System, use worker reports on engine cards,
  and export node-instance health/failure metrics to Prometheus.
- Keep external-quota adapters offline-safe: their periodic health check validates
  configuration only and never spends a lookup token.

### 5. Worker Control API — implemented

Enrollment uses a separately configured bootstrap token. MASP returns a
high-entropy agent token once, stores only its SHA-256 hash, binds it to the
durable node, and revokes the previous active token when that node re-enrolls.
The HTTPS control plane handles registration, heartbeat, job claim, lease
renewal, fenced result submission, and fenced health reporting. Direct-database
workers remain a compatibility mode.
Admins can immediately revoke a node's active credential from the System page;
reconnection then requires a fresh enrollment.

### 6. Secure sample delivery — local stream implemented

An authorized running-job owner can stream its sample from MASP. Access is bound
to node/process identity and attempt generation; download renews the fenced
lease. The agent enforces the declared byte count, verifies SHA-256, scans a
temporary local copy, and deletes it. An S3-compatible short-lived provider is
still future work.

### 7. Windows Worker Agent — partial real-host acceptance complete

The pywin32 SCM host supports cooperative stop, rotating local logs, automatic
restart policy, a virtual least-privilege service identity, ACL-protected config
and token files, installed-config Defender/control-plane preflight, install,
upgrade, credential rotation, and uninstall tooling. A deterministic ZIP builder
includes a per-file SHA-256 manifest. The extracted-bundle verifier detects
missing or modified files and rejects traversal paths. The host acceptance runner
validates service identity/startup, Defender/control health, clean/EICAR API
behavior, and records JSON evidence plus Authenticode state without persisting
tokens. A Windows 11 development-host run has passed both the compatibility
direct-database path and the HTTPS control-plane clean/EICAR path. The HTTPS run
confirmed authenticated sample download, size/hash verification, fenced result
submission, full clean coverage, and Defender EICAR detection, but used a
temporary elevated agent instead of the installed SCM service. SCM identity,
timeout, permission-denied, offline, failover, stale-result, lifecycle, and
organizational signing gates remain required before Defender can become
`supported`.

### 8. Shared transport libraries and commercial adapters

Build reusable authenticated HTTP, ICAP client, CLI runner, TLS, retry, polling,
and secret-reference services. Keep user-facing integrations tied to an exact
vendor product and validated behavior rather than exposing generic parsers.

## Acceptance Gate for Remote Defender

Remote Defender is production-ready only when all of these pass:

1. A Windows agent enrolls without receiving PostgreSQL credentials.
2. The control plane reports the real Defender, engine, and signature health.
3. The agent downloads a sample over authenticated TLS and verifies SHA-256.
4. Clean, EICAR, timeout, permission-denied, offline, retry, and stale-lease cases
   produce deterministic normalized results.
5. A second compatible Windows node can take new work when the first is draining
   or offline without allowing a stale result commit.
6. Installation, upgrade, credential rotation, logs, and uninstall are documented
   and covered by an operator acceptance run.


The React automation report now links to an on-demand integration result JSON
preview for terminal scans. Session-authenticated analyst/admin reads reuse
bounded coherent export admission and the public result projection, with no
private engine output and a 2 MiB serialized response limit. Invalid policy,
active scans and unavailable historical routing fail explicitly. Oversized batch
JSON, remaining UI parity and deployment-scale acceptance are still open; this
adds no worker transport or production support claim.

Automation status JSON now has a separate React view for active/terminal scans.
Scan, polling policy, accepted-instance eligibility and global queue counts use
one bounded repeatable read. Global history aggregates remain subject to statement
timeouts and deployment-scale acceptance; there is no automatic browser polling.
Status requires an accepted engine snapshot, preserves backend coverage decisions
and omits private engine output. Oversized batch JSON and final legacy-action parity remain pending.

React automation batch status/result JSON now supports complete batches of up to
20 members, with exact source/owner consistency and a shared repeatable snapshot.
Result admission caps aggregate engine/snapshot bytes before hydration; response
envelopes stay within 2 MiB. Status reads no engine blobs. Stored counters may lag;
JSON never proves clean coverage by itself. Oversized batches use the overview
and individual reports; complete oversized-payload parity, final legacy-action checks
and deployment acceptance remain open before legacy removal.

Automation archive navigation now stays in React, with direct-child ID-keyset
pages and attempt guards. Parent, nested and upward navigation preserves exact
API/ICAP source, nullable client and batch boundaries. Reads use existing indexed
probes and PostgreSQL snapshot/time budgets, never engine blobs or counter writes.
Empty lists do not prove complete extraction. Final legacy-action and deployment-scale
acceptance remain open; this does not enable recursive deletion or remove legacy.

Admin ledger bulk deletion now confirms at most 20 top-level API/ICAP records with
displayed attempt/job-revision fences. Shared row-locked protections and independent
commits remain authoritative; receipts identify deleted, blocked and cleanup-failed
IDs. Ambiguous writes are never replayed and the UI requires explicit fresh reads
before reselection. This does not delete batches recursively. Ledger revision-probe
load and remaining security/deployment acceptance gates stay open.

Admin React Users now lists bounded local/LDAP metadata and confirms local user
creation with an explicit role and write-only initial password. Password hashes,
directory identifiers and sessions are excluded from list DTOs; shared hashing and
database uniqueness remain authoritative. No automatic creation replay occurs.
Own-password management now uses React Account for local analysts and admins.
Both browser UIs share validation, a password-only conditional update and atomic
session revocation. Local login rechecks the verified hash under a row lock before
creating a session, preventing old-password login from surviving a concurrent
password change/reset. LDAP passwords remain directory-managed. Admin Users now
confirms role changes, optional password resets and removal, with a displayed
management revision checked under shared legacy/browser transaction locks. The
writer rechecks the actor's administrator role, blocks self-management and preserves
the last local administrator across concurrent operations. LDAP shadow removal
revokes MASP sessions but does not disable directory access; a later directory
sign-in may recreate it. Passwords never enter console state or caches; inputs
clear on cancellation/send and uncertain writes are not replayed. Explicit list
refresh is required after management writes. Startup adds the default-zero
users.management_revision column in place; old account data is retained. Roll out
all app processes together so old writers cannot bypass the revision/locking rules.
Startup adds an auth-session user index in place. PostgreSQL password changes use
the existing UI lock timeout; deployment-scale login/revocation acceptance remains
open. No worker topology or engine support status changes.
