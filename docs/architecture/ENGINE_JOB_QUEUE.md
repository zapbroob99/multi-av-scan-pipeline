# MASP Engine Job Queue

This document describes the supported engine-level queue and crash-safe
finalization path used by MASP scan workers.

## Current Status

Implemented:

- `scan_engine_jobs` table in SQLite and PostgreSQL init paths.
- `ScanEngineJobRecord` model.
- Idempotent job creation for each enabled engine when a scan is created.
- Job recreation when a completed or failed scan is retried.
- Atomic pending-job claim with owner/generation fencing and renewable leases.
- Recovery of expired jobs with an attempt cap; claim never steals a running job.
- Worker path that claims one compatible engine job, runs the adapter, writes
  the engine result and terminal job state in one fenced transaction, and tries
  to finalize the scan.
- Finalization checks both engine-job terminal coverage and corresponding
  `engine_results` coverage before completing the scan.
- Fenced `queued/running -> finalizing -> completed` scan lifecycle with
  idempotent archive-child intake and recovery after a finalizer crash.
- Startup and periodic maintenance for lease recovery, result backfill,
  finalization sweep, and bounded filesystem cleanup.
- Unit tests for claim, lease expiry, terminal state, retry cleanup, and worker
  engine-job processing/finalization.

The public `/api/v1` status projection intentionally exposes normalized engine
coverage and timing, not internal queue rows, worker IDs, leases, or events.
Queue diagnostics remain available to the operator UI/internal persistence;
adding them to the vendor API is not a pending requirement.

The worker requires `MASP_ENGINE_JOB_QUEUE_ENABLED=1` and
`MASP_LEGACY_SCAN_WORKER_FALLBACK_ENABLED=0`. Any other combination is refused
at startup: the legacy scan-centric path bypasses generation fencing and the
crash-safe finalization state machine.

## Code Map

- Models and status sets: [`app/models.py`](../../app/models.py)
- Queue, fencing, recovery, and finalization persistence:
  [`app/database.py`](../../app/database.py)
- Worker execution and maintenance: [`app/workers/scan_worker.py`](../../app/workers/scan_worker.py)
- Scan intake and retry HTTP paths: [`app/main.py`](../../app/main.py)
- Queue/recovery tests: [`tests/test_scan_engine_jobs.py`](../../tests/test_scan_engine_jobs.py)
- Worker tests: [`tests/test_scan_engine_worker.py`](../../tests/test_scan_engine_worker.py)
- Real concurrency tests:
  [`tests/test_worker_fencing_concurrency.py`](../../tests/test_worker_fencing_concurrency.py)
- Archive finalization integration tests:
  [`tests/test_archive_finalization_integration.py`](../../tests/test_archive_finalization_integration.py)

## State Model

Each scan creates one engine job per enabled engine:

```text
Scan 42 / static_metadata / pending
Scan 42 / clamav          / pending
Scan 42 / yara            / pending
Scan 42 / defender        / pending
```

Job statuses:

```text
pending
claimed
running
completed
failed
skipped
```

The intended transition path:

```text
pending
  -> claimed
  -> running
  -> completed | failed | skipped
```

`claimed` and `running` jobs carry a renewable `lease_expires_at` epoch and an
`attempt_count` generation token. If a worker dies, maintenance moves an expired
job back to `pending` (or fails it at the attempt cap); claim itself never steals
a `claimed` or `running` job. A stale worker cannot commit after recovery because
every state/result write is fenced by worker ID and generation.

## Claim Semantics

Workers claim by engine capability:

```python
claim_next_scan_engine_job(
    engine_keys={"microsoft_defender"},
    worker_id="windows-worker-1",
)
```

The claim query only considers:

- scans with `scan_jobs.status IN ('queued', 'running')`,
- jobs whose `engine_key` is in the worker's engine keys,
- `pending` jobs below the attempt cap.

Ordering remains oldest-scan-first:

```text
scan_jobs.created_at ASC
scan_jobs.id ASC
scan_engine_jobs.id ASC
```

PostgreSQL uses `FOR UPDATE SKIP LOCKED`. SQLite uses `BEGIN IMMEDIATE`.

## Why This Fixes The Main Bottleneck

The old worker loop asks:

```text
Give me active scans.
I will inspect them and decide whether I can do anything.
```

The new queue asks:

```text
Give me the next engine job that my worker can actually run.
```

This avoids:

- repeatedly inspecting scans waiting for another engine,
- head-of-line behavior caused by `ACTIVE_SCAN_LIMIT`,
- queue wait being mistaken for engine execution timeout,
- scaling workers before duplicate work is controlled.

## Worker Execution

The worker execution path is:

```text
claim next compatible engine job
mark scan running
mark engine job running (owner + generation fenced)
renew lease while the adapter runs
run adapter
atomically write engine result + terminal job state if still owned
claim scan finalization
register archive children idempotently, when applicable
complete scan if the finalization generation is still owned
```

Finalization in the engine-job path requires both:

- all scan engine jobs to be terminal: `completed`, `failed`, or `skipped`,
- all enabled engine jobs to have corresponding `engine_results` rows.

This keeps queue state and result/report state consistent. Maintenance creates
an idempotent synthetic failed/skipped result for a terminal job that cannot
produce one, preventing poison or reaped jobs from wedging a scan forever.

The queue path does not create timeout `skipped` results merely because another
worker has not reached an engine yet. Queue wait, adapter timeout, renewable
lease ownership, and the synchronous API/ICAP wait window are separate concepts.

## Background Maintenance

`run_maintenance()` runs at worker startup and on a throttled tick. It recovers
expired engine-job/finalization leases, reaps uncoverable jobs, sweeps
finalize-stuck scans, and cleans up filesystem residue:

- **Stale staging dirs** — per-run archive extraction directories orphaned by a
  crash mid-extraction (`cleanup_stale_staging_dirs`).
- **Orphan child samples** — deterministic `child-*` sample files a fenced-out
  (or crashed) finalizer promoted before it could commit the child row. A file
  is removed only when its parent scan is terminal (`completed`/`failed`) or
  missing **and** no `samples` row references it — re-confirmed under the parent
  scan's row lock at the moment of deletion (`remove_orphan_child_sample`),
  because a retry can flip a terminal parent back to active and a new finalizer
  can re-promote the same path after any unlocked read. A live child's file and
  a finalizing parent's not-yet-committed file are never touched
  (`cleanup_orphan_child_samples`).

### Tunables (environment)

| Variable | Default | Purpose |
| --- | --- | --- |
| `MASP_ENGINE_JOB_QUEUE_ENABLED` | `1` | Use the fenced engine-job queue (only supported path; worker refuses to start if `0`). |
| `MASP_LEGACY_SCAN_WORKER_FALLBACK_ENABLED` | `0` | Legacy scan-centric path; worker refuses to start if `1`. |
| `MASP_ENGINE_JOB_LEASE_SECONDS` | `120` | Per-engine-job lease duration. |
| `MASP_ENGINE_JOB_LEASE_GRACE_SECONDS` | `60` | Grace before an expired lease is reclaimable. |
| `MASP_ENGINE_JOB_MAX_ATTEMPTS` | `5` | Attempts before a job is failed permanently. |
| `MASP_FINALIZE_LEASE_SECONDS` | `120` | Finalization lease duration. |
| `MASP_WORKER_MAINTENANCE_INTERVAL_SECONDS` | `30` | Min seconds between maintenance ticks (floor 5). |
| `MASP_CHILD_SAMPLE_ORPHAN_MAX_AGE_SECONDS` | `21600` (6h) | Min age before an orphan `child-*` sample file is eligible for cleanup (defense in depth on top of the parent-terminal + unreferenced gate). |
