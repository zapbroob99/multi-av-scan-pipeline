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
