# MASP Agent Notes

## Project Direction

MASP is a self-hosted multi-engine malware scan orchestrator. Preserve the
offline-first decision path, normalized engine results, source-aware quota rules,
and crash-safe database queue. Do not turn vendor integrations into user-defined
arbitrary command parsers.

## Current Runtime

- FastAPI app/UI, scan workers, and optional ICAP gateway are separate processes.
- PostgreSQL is required for Docker/hybrid deployments; SQLite is local-test only.
- Workers may use the HTTPS control API without database credentials or shared
  sample storage; direct database/shared-filesystem workers remain compatible.
- ClamAV normally uses clamd TCP. Defender executes locally on a Windows worker.
- API and ICAP submissions exclude adapters with `consumes_external_quota`.
- Engine-job ownership uses leases, attempt generations, and fenced result commits.

## Engine Identity

- `adapter_key` identifies vendor behavior and is not an instance identity.
- `engine_instances.id` identifies one configured deployment.
- Multiple ClamAV and Defender instances are supported; display names must remain
  unique so compatibility reports and result coverage stay unambiguous.
- Queue idempotency is `(scan_job_id, engine_instance_id)`.
- Workers advertise adapter keys but must resolve claimed jobs by instance id.
- Keep fallback adapter-key routing only for legacy jobs without an instance id.

## Active Roadmap

The authoritative plan is
`docs/architecture/ENGINE_DEPLOYMENT_AND_WORKER_AGENT.md`.

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
Next milestone: execute and retain the full real-Windows failure/failover/
lifecycle matrix, apply organizational release signing, and promote support only
after those gates pass.
Direct worker database access and shared filesystem paths are compatibility modes,
not the final remote-worker architecture.

## Change Rules

- Maintain in-place SQLite and PostgreSQL upgrade compatibility.
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
