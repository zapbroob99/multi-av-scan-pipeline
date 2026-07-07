# MASP Engine Job Queue

This document describes the engine-level queue foundation for MASP scan
workers. It is the migration path away from scan-centric scheduling.

## Current Status

Implemented:

- `scan_engine_jobs` table in SQLite and PostgreSQL init paths.
- `ScanEngineJobRecord` model.
- Idempotent job creation for each enabled engine when a scan is created.
- Job recreation when a completed or failed scan is retried.
- Atomic claim helper with lease expiry.
- Running and terminal state helpers.
- Worker path that claims one compatible engine job, runs the adapter, writes
  the engine result, marks the job terminal, and tries to finalize the scan.
- Finalization checks both engine-job terminal coverage and corresponding
  `engine_results` coverage before completing the scan.
- Unit tests for claim, lease expiry, terminal state, retry cleanup, and worker
  engine-job processing/finalization.

Still pending:

- `scan_engine_jobs` is not yet exposed in the status API.

The worker uses the engine-job queue by default when
`MASP_ENGINE_JOB_QUEUE_ENABLED=1`. The old scan-centric fallback is disabled by
default through `MASP_LEGACY_SCAN_WORKER_FALLBACK_ENABLED=0` so it cannot
reintroduce timeout/skipped races while the engine queue is active.

## Code Map

- Model: [`app/models.py:93`](../../app/models.py#L93)
- SQLite table: [`app/database.py:260`](../../app/database.py#L260)
- PostgreSQL table: [`app/database.py:421`](../../app/database.py#L421)
- Job creation: [`app/database.py:1290`](../../app/database.py#L1290)
- Job listing: [`app/database.py:1342`](../../app/database.py#L1342)
- Atomic claim: [`app/database.py:1376`](../../app/database.py#L1376)
- Mark running: [`app/database.py:1447`](../../app/database.py#L1447)
- Mark terminal: [`app/database.py:1473`](../../app/database.py#L1473)
- Worker queue tick: [`app/workers/scan_worker.py:112`](../../app/workers/scan_worker.py#L112)
- Worker engine-job processing: [`app/workers/scan_worker.py:150`](../../app/workers/scan_worker.py#L150)
- New scan hook: [`app/main.py:925`](../../app/main.py#L925)
- Retry hook: [`app/main.py:4178`](../../app/main.py#L4178)
- Tests: [`tests/test_scan_engine_jobs.py:23`](../../tests/test_scan_engine_jobs.py#L23)
- Worker tests: [`tests/test_scan_engine_worker.py:11`](../../tests/test_scan_engine_worker.py#L11)

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

`claimed` and `running` jobs carry a `lease_expires_at` epoch. If a worker dies,
another compatible worker can reclaim the job after the lease expires.

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
- `pending` jobs,
- expired `claimed` or `running` jobs.

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
mark engine job running
run adapter
write engine result idempotently
mark engine job terminal
try finalize scan
```

Finalization in the engine-job path requires both:

- all scan engine jobs to be terminal: `completed`, `failed`, or `skipped`,
- all enabled engine jobs to have corresponding `engine_results` rows.

This keeps the queue state and result/report state consistent. A terminal job
without a result does not complete the scan.

The queue path intentionally does not create timeout `skipped` results for
engines merely because another worker has not reached them yet. Queue wait,
execution timeout, lease timeout, and overall scan SLA will be handled as
separate concepts.
