# MASP Worker Throughput Optimization

This document explains how MASP worker throughput works today and how to
optimize it without breaking scan correctness. It is intentionally explicit
because scan orchestration is MASP's core product behavior.

The short version:

- The API is already fast at accepting scans.
- Current latency is mostly worker and engine execution time.
- The current worker model is scan-centric, not engine-work-item-centric.
- The safest next optimization is better evidence first, then targeted
  scheduling changes.

## Code Map

The throughput path depends on these files:

- API scan submission: [`app/main.py:4062`](../../app/main.py#L4062)
- Upload and scan creation helper: [`app/main.py:902`](../../app/main.py#L902)
- API status payload: [`app/main.py:843`](../../app/main.py#L843)
- Scan timing payload exposure: [`app/main.py:773`](../../app/main.py#L773)
- Scan row creation: [`app/database.py:950`](../../app/database.py#L950)
- Idempotent engine result insert: [`app/database.py:1039`](../../app/database.py#L1039)
- Worker timing event insert: [`app/database.py:1170`](../../app/database.py#L1170)
- Worker timing event listing: [`app/database.py:1208`](../../app/database.py#L1208)
- Active scan listing: [`app/database.py:1320`](../../app/database.py#L1320)
- Mark scan running: [`app/database.py:1397`](../../app/database.py#L1397)
- Terminal scan update: [`app/database.py:1441`](../../app/database.py#L1441)
- Existing unused scan claim helper: [`app/database.py:1480`](../../app/database.py#L1480)
- Worker scan processing: [`app/workers/scan_worker.py:100`](../../app/workers/scan_worker.py#L100)
- Serial engine loop: [`app/workers/scan_worker.py:203`](../../app/workers/scan_worker.py#L203)
- Scan finalization: [`app/workers/scan_worker.py:265`](../../app/workers/scan_worker.py#L265)
- Passive finalize gate: [`app/workers/scan_worker.py:309`](../../app/workers/scan_worker.py#L309)
- Partial result wait calculation: [`app/workers/scan_worker.py:338`](../../app/workers/scan_worker.py#L338)
- Worker polling loop: [`app/workers/scan_worker.py:414`](../../app/workers/scan_worker.py#L414)
- Worker capability defaults: [`app/services/worker_capabilities.py:7`](../../app/services/worker_capabilities.py#L7)
- Worker engine key selection: [`app/services/worker_capabilities.py:23`](../../app/services/worker_capabilities.py#L23)
- Completion coverage rule: [`app/services/worker_capabilities.py:69`](../../app/services/worker_capabilities.py#L69)
- Engine routing decisions: [`app/services/routing.py:31`](../../app/services/routing.py#L31)
- Timing calculation: [`app/services/timing.py:30`](../../app/services/timing.py#L30)
- Active worker engine guard: [`app/services/worker_runtime.py:208`](../../app/services/worker_runtime.py#L208)
- Benchmark aggregation: [`app/services/benchmarking.py:44`](../../app/services/benchmarking.py#L44)
- Worker timing aggregation: [`app/services/benchmarking.py:168`](../../app/services/benchmarking.py#L168)
- Benchmark CLI output: [`tools/benchmark_scans.py:699`](../../tools/benchmark_scans.py#L699)

## Current System Behavior

### 1. The API creates durable scan work

The public API route is `POST /api/v1/scans` in
[`api_create_scan`](../../app/main.py#L4052).

The route calls [`enqueue_scan_from_upload`](../../app/main.py#L892). That
helper stores the uploaded file, creates a sample row, and creates a scan job.
The database insert is [`create_scan_job`](../../app/database.py#L914).

The important result is a row like this:

```text
scan_jobs.status = queued
scan_jobs.started_at = NULL
scan_jobs.completed_at = NULL
```

At this point the API is done with the heavy work. A worker must later pick up
the scan and write engine results.

### 2. Workers poll active scans

Each worker runs [`run_forever`](../../app/workers/scan_worker.py#L263), which
repeatedly calls [`process_next_scan_job`](../../app/workers/scan_worker.py#L237).

`process_next_scan_job()` asks the database for active scans through
[`list_active_scans`](../../app/database.py#L1223). Active scans are:

```sql
WHERE scan_jobs.status IN ('queued', 'running')
ORDER BY scan_jobs.created_at ASC, scan_jobs.id ASC
```

This gives the worker an oldest-first scan list. It is not a strict job claim.
It is a scan list that every worker can inspect.

### 3. Workers route missing engine results

For each active scan, the worker calls
[`process_scan`](../../app/workers/scan_worker.py#L100).

`process_scan()` loads enabled engines, loads existing engine results, and
finds which enabled engines are still missing. Then
[`route_engine_for_worker`](../../app/services/routing.py#L31) decides what this
worker can do for each missing engine:

- `run`: this worker can execute the engine.
- `wait`: another worker might execute it.
- `skip`: this engine should be recorded as skipped.

This is what makes the hybrid model work:

- The Docker/Linux worker can run `static_metadata`, `clamav`, and `yara`.
- The Windows worker can run `microsoft_defender`.
- Both workers can look at the same scan and write the engine results they are
  responsible for.

### 4. One worker executes its runnable engines serially

Inside one worker process, runnable engines are executed one after another:

```python
for decision in runnable_decisions:
    engine = decision.engine
    create_engine_result_if_missing(scan.id, run_engine(engine, scan))
```

Reference: [`app/workers/scan_worker.py:203`](../../app/workers/scan_worker.py#L203)

For a Linux worker, this usually means:

```text
Static Metadata
then ClamAV
then YARA
```

For a Windows Defender worker, this usually means:

```text
Microsoft Defender
```

This model is simple and safe, but it means a worker's processing time is close
to the sum of its engine durations.

### 5. Engine result writes are idempotent

Workers write results through
[`create_engine_result_if_missing`](../../app/database.py#L1003).

The database has a unique constraint on:

```text
engine_results(scan_job_id, engine_name)
```

PostgreSQL uses `ON CONFLICT DO NOTHING`. SQLite uses an immediate transaction
and an existence check.

This is important for correctness because multiple workers may inspect the same
active scan. The first worker to write a given engine result wins; duplicate
writes are ignored.

### 6. A scan completes only when every enabled engine has a result

Finalization happens in
[`finalize_scan_if_complete_or_timeout`](../../app/workers/scan_worker.py#L265).

The rule is:

```text
Every enabled engine must have one engine_results row.
```

That row can be:

- `completed`
- `failed`
- `skipped`

The coverage check is
[`all_enabled_engines_have_results`](../../app/services/worker_capabilities.py#L69).

If an enabled engine never reports, the worker can eventually write a skipped
result after the partial-result wait window. The wait is calculated by
[`partial_results_wait_seconds`](../../app/workers/scan_worker.py#L338).

This is the behavior we verified manually: when the Windows Defender worker was
stopped, Linux engines completed and Microsoft Defender became `skipped` after
the wait window instead of leaving the scan stuck forever.

## What The Benchmarks Say

Two local benchmark runs used the same sample:

```text
sample: 0ebc0530f0804356a12f89b1298c8a51_main.py
size:   13,858 bytes
engines: static_metadata, clamav, yara, microsoft_defender
```

### local-run-01

```text
requests:    5
concurrency: 2
completed:   5/5
errors:      0
partials:    0

submit_avg:       192 ms
queue_wait_avg:  2460 ms
processing_avg:  3973 ms
total_avg:       6434 ms
```

### local-run-02

```text
requests:    10
concurrency: 3
completed:   10/10
errors:      0
partials:    0

submit_avg:       272 ms
queue_wait_avg:  3317 ms
processing_avg:  4498 ms
total_avg:       7815 ms
```

### local-run-engine-01

This run used the same sample and request shape as `local-run-02`, after the
status API started exposing per-engine result durations.

```text
requests:    10
concurrency: 3
completed:   10/10
errors:      0
partials:    0

submit_avg:       275 ms
queue_wait_avg:  4023 ms
processing_avg:  6044 ms
total_avg:      10068 ms

engine_timings_ms:
  Static Metadata:      avg 1 ms
  ClamAV:              avg 14 ms
  YARA:                avg 31 ms
  Microsoft Defender:  avg 1177 ms
```

The interpretation:

- API submission is not the bottleneck.
- Queue wait increases as concurrency increases.
- Processing also increases as concurrency increases.
- The system remains correct under this light load.
- The bottleneck is worker and engine execution, not scan acceptance.
- `local-run-engine-01` shows that adapter runtime alone does not explain the
  whole `processing_avg`: Microsoft Defender averaged about 1.2 seconds, while
  scan-level processing averaged about 6.0 seconds. The remainder is
  orchestration, scheduling, DB polling, worker tick timing, and waiting for all
  enabled engine results to exist before finalization.

### local-run-worker-timing-02

This run used split workers after adding worker timing events and the race guard
that prevents timeout `skipped` results while another worker is actively running
that scan engine.

```text
requests:    10
concurrency: 3
completed:   10/10
errors:      0
partials:    0
allow:       10/10
skipped_avg: 0

queue_wait_avg: 13721 ms
processing_avg: 15322 ms
total_avg:      29043 ms

worker_timing_ms:
  load_context: avg 1614 ms
  finalize:     avg 4248 ms
  process_scan: avg 14142 ms
```

Correctness was restored: all scans completed with full coverage and `allow`.
The cost became visible: passive workers were still repeatedly entering scans
only to reload context, attempt finalization, and exit.

### local-run-worker-timing-03

This run used the passive-finalize optimization: if a worker has no runnable or
skippable engine for a scan and the missing-engine timeout window has not
expired, it records `passive_defer` and skips the expensive finalization path.

```text
requests:    10
concurrency: 3
completed:   10/10
errors:      0
partials:    0
allow:       10/10
skipped_avg: 0

queue_wait_avg:  3620 ms
processing_avg:  9285 ms
total_avg:      12906 ms

worker_timing_ms:
  load_context:  avg 793 ms
  finalize:      avg 516 ms
  process_scan:  avg 3027 ms
  passive_defer: avg 2585 ms
```

Compared with `local-run-worker-timing-02`, this kept full correctness and
reduced:

- `queue_wait_avg` from 13.7s to 3.6s,
- `processing_avg` from 15.3s to 9.3s,
- `total_avg` from 29.0s to 12.9s,
- `finalize` worker time from 4.2s to 0.5s,
- `process_scan` worker time from 14.1s to 3.0s.

## How To Read The Timing Numbers

Timing comes from [`build_scan_timing_payload`](../../app/services/timing.py#L30).

Use these definitions consistently:

```text
queue_wait_ms = started_at - created_at
processing_duration_ms = completed_at - started_at
total_duration_ms = completed_at - created_at
```

For completed scans:

```text
total_duration_ms = queue_wait_ms + processing_duration_ms
```

Practical meaning:

- High `submit_*`: API, upload, storage, auth, or DB insert issue.
- High `queue_wait_*`: workers are not starting scans quickly enough.
- High `processing_*`: engines, worker execution, or missing-engine wait.
- High `total_*`: split into queue wait and processing before optimizing.

## Current Bottlenecks

### Bottleneck 1: scan-centric scheduling

The worker currently scans active scan records:

```text
list active scans
find first scan this worker can change
process that scan
end this worker tick
```

Reference:

- [`list_active_scans`](../../app/database.py#L1223)
- [`process_next_scan_job`](../../app/workers/scan_worker.py#L237)

This is correct and simple, but it is not a proper distributed work queue. The
unit of scheduling is effectively "scan" even though the real work is "engine X
for scan Y".

Impact:

- Old scans are revisited frequently.
- A scan waiting for another worker can sit near the front of the list.
- Workers may spend time re-evaluating scans they cannot advance.
- Scaling workers does not guarantee clean work distribution.

### Bottleneck 2: serial engine execution inside one worker

Reference: [`app/workers/scan_worker.py:203`](../../app/workers/scan_worker.py#L203)

For a Linux worker, processing time is roughly:

```text
static_metadata duration
+ clamav duration
+ yara duration
+ DB/result overhead
```

That is acceptable for correctness, but it limits throughput when ClamAV or
YARA is slow.

### Bottleneck 3: capability-specific worker pools

References:

- [`WINDOWS_DEFAULT_ENGINE_KEYS`](../../app/services/worker_capabilities.py#L7)
- [`POSIX_DEFAULT_ENGINE_KEYS`](../../app/services/worker_capabilities.py#L8)
- [`worker_engine_keys`](../../app/services/worker_capabilities.py#L23)

Linux and Windows capacity are not interchangeable:

- More Windows workers do not make ClamAV/YARA faster.
- More Linux workers do not make Defender faster.
- Throughput improves only when the bottleneck engine's worker pool is scaled.

### Bottleneck 4: completion waits for full enabled-engine coverage

Reference:

- [`finalize_scan_if_complete_or_timeout`](../../app/workers/scan_worker.py#L265)
- [`partial_results_wait_seconds`](../../app/workers/scan_worker.py#L338)

If one enabled engine is slow or unavailable, the scan cannot become terminal
until either:

- that engine writes a result, or
- the missing engine is finalized as `skipped` after the wait window.

This is a product decision, not just an implementation detail. It protects
decision quality by requiring explicit coverage accounting.

## Optimization Options

### Option A: scale the existing worker model

Add more worker processes of the bottleneck type.

Examples:

- More Linux workers for `clamav,yara`.
- More Windows workers for `microsoft_defender`.
- Dedicated Linux worker keys, such as one worker for `clamav` and another for
  `yara`.

Why this is attractive:

- Minimal code change.
- Easy to test with benchmarks.
- Preserves current result semantics.

Risks:

- Local AV tools may serialize internally.
- More workers can increase disk and DB contention.
- The scan-centric scheduler may still cause repeated active-scan evaluation.

This is the best first operational test before a scheduler refactor.

### Option B: split workers by engine key

Instead of one Linux worker running `static_metadata,clamav,yara`, run separate
worker processes:

```text
worker A: static_metadata
worker B: clamav
worker C: yara
worker D: microsoft_defender
```

Why this helps:

- Slow engines no longer block faster engines inside the same worker process.
- Benchmark data can isolate which engine is dominating.
- It uses the existing `MASP_WORKER_ENGINE_KEYS` mechanism.

Risks:

- Multiple workers inspect the same active scans.
- The current scan-centric scheduler still remains.
- Engine capacity must be controlled per host.

This is likely the lowest-risk next experiment.

### Option C: engine-level work items

Create explicit work records for each engine on each scan:

```text
scan_engine_jobs
  id
  scan_job_id
  engine_instance_id
  status
  claimed_by
  claimed_until
  attempts
  last_error
```

Then workers claim engine jobs instead of scanning active scans.

The scheduling unit becomes:

```text
Run ClamAV for scan 123
Run YARA for scan 123
Run Defender for scan 123
```

Why this helps:

- Clean distributed scheduling.
- Better horizontal scaling.
- Less head-of-line behavior.
- Direct per-engine queue metrics.
- Easier retries per engine instead of per scan.

Risks:

- Requires a database migration.
- Requires lease expiry/recovery logic.
- Requires careful idempotency with `engine_results`.
- Requires finalization that watches both engine jobs and results.

This is the most correct long-term architecture if MASP needs serious
throughput.

The engine-job queue path is now documented in
[`ENGINE_JOB_QUEUE.md`](ENGINE_JOB_QUEUE.md): `scan_engine_jobs` exists, scan
creation writes engine jobs, retry recreates them, the database layer has atomic
claim/lease helpers, workers use this queue by default, and scan finalization
requires both terminal engine jobs and matching `engine_results` coverage.

### Option D: parallel engines inside one worker

Run independent engines concurrently inside `process_scan()`.

Why this helps:

- Can reduce processing duration for one scan.
- Does not require a new database table immediately.

Risks:

- Local AV tools may not be safe or efficient under parallel execution.
- One worker process becomes a mini scheduler.
- Resource limits become harder to reason about.
- Duplicate prevention remains necessary.

This should not be the first refactor. Engine-level work items are cleaner if
we are already changing scheduling semantics.

### Option E: early decision policy

Allow some decisions before all engines finish.

Examples:

- Early `block` when any high-confidence engine detects malware.
- Keep background scan running for full coverage.
- Do not allow early `allow` unless policy explicitly permits it.

Why this helps:

- Reduces time-to-block for obvious malicious files.
- Useful for enterprise gateway integrations.

Risks:

- API contract becomes more complex.
- Consumers must distinguish preliminary and final decisions.
- Early allow is dangerous and should be avoided unless policy is explicit.

This is a product-policy optimization, not just a throughput optimization.

## Recommended Next Steps

### Step 1: measure with stable conditions

Use the same sample and the same worker layout. Run:

```text
10 requests / concurrency 3
30 requests / concurrency 5
50 requests / concurrency 5
```

Record:

- `submit_avg`, `submit_p50`, `submit_p95`
- `queue_wait_avg`, `queue_wait_p50`, `queue_wait_p95`
- `processing_avg`, `processing_p50`, `processing_p95`
- `total_avg`, `total_p50`, `total_p95`
- `partial_runs`
- failed/skipped engine counts

Do not compare runs where sample size, engine set, worker count, or timeout
policy changed at the same time.

### Step 2: isolate the bottleneck engine

Run workers with narrower `MASP_WORKER_ENGINE_KEYS` assignments:

```text
static_metadata only
clamav only
yara only
microsoft_defender only
```

The goal is to learn which engine contributes most to `processing_duration_ms`.

This does not require a scheduler refactor.

### Step 3: test engine-split workers

Try this worker layout:

```text
Linux worker 1: static_metadata
Linux worker 2: clamav
Linux worker 3: yara
Windows worker: microsoft_defender
```

Expected result:

- `processing_duration_ms` should improve if serial Linux engine execution is
  the bottleneck.
- `queue_wait_ms` may improve if each worker can advance different missing
  engine results.

If this helps enough, we can delay a larger scheduler refactor.

Docker Compose includes this experiment as the `linux-worker-split` profile.
Use this profile instead of `linux-worker` when comparing split-worker
throughput:

```powershell
$env:MASP_API_TOKEN="test-token"
docker compose --profile linux-worker-split up --build
```

Then run the same benchmark command used for the baseline and write the result
to a different file:

```powershell
.\.venv\Scripts\python.exe tools\benchmark_scans.py `
  --base-url http://localhost:8000 `
  --token test-token `
  --sample .\storage\samples\0ebc0530f0804356a12f89b1298c8a51_main.py `
  --requests 10 `
  --concurrency 3 `
  --poll-interval 1 `
  --timeout 240 `
  --output .\benchmark-results\local-run-split-01.json
```

Compare it against the single Linux worker baseline:

```text
single profile: linux-worker
split profile:  linux-worker-split

Compare:
submit_avg
queue_wait_avg
processing_avg
total_avg
engine_timings_ms
worker_timing_ms
partial_runs
failed_engines
skipped_engines
```

Observed local split result from `local-run-split-01`:

```text
requests:    10
concurrency: 3
completed:   10/10
errors:      0
partials:    0

submit_avg:       308 ms
queue_wait_avg:  3096 ms
processing_avg:  7538 ms
total_avg:      10634 ms
```

Compared with `local-run-02`, the split profile reduced average queue wait
slightly, but increased average processing and total duration. That means the
split profile did not improve end-to-end throughput in this local run.

Expected interpretation:

- If `processing_avg` drops, serial Linux engine execution was a real
  bottleneck.
- If `queue_wait_avg` drops, split workers are starting useful engine work
  sooner.
- If both stay similar, the bottleneck is likely inside one engine, the AV
  service, disk IO, or the scan-centric scheduler.
- If failures or skipped engines increase, the split layout is too aggressive
  for the current local engine capacity.
- If `processing_avg` gets worse but individual `engine_timings_ms` do not,
  the extra time is likely orchestration/scheduling wait inside the running
  scan window rather than adapter runtime.

### Step 4: validate engine-level work items

The `scan_engine_jobs` table is now the default worker queue. Validate that it
removes the scan-centric bottleneck under benchmark load.

The migration includes:

- Work item creation when a scan is created.
- Claim/lease fields for safe distributed execution.
- Worker heartbeat or lease recovery.
- Per-engine retry attempts.
- Finalization when all required engine jobs are terminal and matching results
  exist.
- Backward-compatible API payloads.

### Step 5: add per-engine and worker timing to payloads

`engine_results.duration_ms` records adapter runtime for real adapter outcomes:
`completed` and `failed`. A `skipped` result is synthetic coverage state, not
adapter execution. The status API exposes a compact `engine_results` array, and
the benchmark report summarizes non-skipped durations in `engine_timings_ms`:

```json
{
  "engine_timings_ms": {
    "ClamAV": {"samples": 10, "avg": 1200, "p50": 1180, "p95": 1600, "p99": 1600, "min": 900, "max": 1600},
    "YARA": {"samples": 10, "avg": 300, "p50": 280, "p95": 450, "p99": 450, "min": 220, "max": 450},
    "Microsoft Defender": {"samples": 10, "avg": 4200, "p50": 4100, "p95": 6000, "p99": 6000, "min": 3000, "max": 6000}
  }
}
```

This helps distinguish:

- slow queueing,
- slow scan processing,
- one slow engine,
- missing-engine wait.

The worker also records compact orchestration events in `scan_worker_events`.
The status API exposes them as `worker_events`, and the benchmark report
summarizes them in `worker_timing_ms`:

```json
{
  "worker_timing_ms": {
    "load_context": {"samples": 10, "avg": 12, "p50": 10, "p95": 25, "p99": 25, "min": 8, "max": 25},
    "engine_run:Microsoft Defender": {"samples": 10, "avg": 1250, "p50": 1180, "p95": 1900, "p99": 1900, "min": 900, "max": 1900},
    "finalize": {"samples": 10, "avg": 18, "p50": 12, "p95": 50, "p99": 50, "min": 5, "max": 50}
  }
}
```

`engine_timings_ms` tells how long real adapter execution reported. It excludes
`skipped` results so orchestration wait windows do not look like slow AV engine
runtime. `worker_timing_ms` tells how long the worker spent around adapter
execution, result persistence, context reload, and scan finalization. If both are low while
`processing_duration_ms` is high, the remaining time is likely between worker
ticks or waiting for another worker to produce missing engine results.

## Correctness Rules That Must Not Break

Any throughput change must preserve these rules:

- A submitted scan must create durable DB state before returning accepted.
- Every enabled engine must produce exactly one result per scan, unless the
  engine is removed from the enabled set by product policy.
- Duplicate engine execution must not create duplicate result rows.
- A worker crash must not leave scans permanently stuck.
- Missing compatible workers must become explicit `skipped` results after the
  wait window.
- API consumers must be able to tell full coverage from partial coverage.
- `block` decisions must not be hidden by later skipped engines.
- `allow` decisions must not pretend missing engines completed successfully.

## Decision Point

The next engineering decision should be based on benchmark evidence:

```text
If queue_wait grows fastest:
  scale worker count or implement engine-level work claiming.

If processing grows fastest:
  isolate engine timings, split workers by engine, then consider parallelism.

If missing-engine waits dominate:
  tune timeout policy or define a product-level minimum required engine policy.

If submit latency grows:
  investigate API upload/storage/database insert path.
```

For the current local runs, the evidence points to worker and engine execution,
not API submission. The least risky next experiment is engine-split workers
using the existing `MASP_WORKER_ENGINE_KEYS` mechanism.

## Synchronous Upload-Gateway Load Profile

The upload-gateway integration (see
[`API_SCAN_GATEWAY.md`](../integrations/API_SCAN_GATEWAY.md)) uses the
*synchronous* pattern: the client submits with `wait_seconds` and expects an
HTTP `200` with a terminal decision inside that window; if the scan does not
finish in time it gets a `202` and must poll. The key SLA question is
therefore not average latency but the **synchronous completion rate** — what
fraction of requests returned `200` within the wait window versus fell back to
`202`.

The benchmark tool now reports this directly:

```text
Synchronous completions (HTTP 200 within wait window): N/total (rate%)
Async (HTTP 202) fallbacks: N
```

exposed in the summary as `summary.synchronous_completions`,
`summary.synchronous_completion_rate`, and `summary.async_fallbacks`. A run
that finished synchronously (200 at submit) is tracked separately from one
that finished only after polling, which the plain `completed` count conflates.

### Observed break point (dev host)

Local runs: single uvicorn process, SQLite, engines limited to
`static_metadata` + `microsoft_defender` (ClamAV/YARA not installed on this
host), `wait_seconds=30`, 30 requests per step. Worker count was confirmed
authoritatively via `get_worker_status()["online_count"]`, not OS process
counting (on Windows one `python -m` invocation shows as two processes but is
one logical worker).

```text
1 worker:
  concurrency  5:  100.0% sync   submit p95  4.97s   total p95  5s
  concurrency 10:  100.0% sync   submit p95  9.62s   total p95  9s
  concurrency 25:   46.7% sync   submit p95 16.11s   total p95 27s   <- SLA breaks

3 workers:
  concurrency 25:  100.0% sync   submit p95 14.14s   total p95 14s   <- recovered
  concurrency 50:  100.0% sync   submit p95 13.97s   total p95 13s
```

### Interpretation

- With 1 worker the synchronous contract holds up to ~concurrency 10 and
  breaks by 25 (over half the requests fall back to 202, total p95 27s nears
  the 30s window).
- Worker count is the lever: raising 1 → 3 workers moved the concurrency-25
  break point back to 100% synchronous and roughly halved total p95. This is
  the same worker-capacity finding as the async benchmarks, now confirmed for
  the synchronous pattern.
- The synchronous wait does not hard-block the event loop
  ([`wait_for_terminal_scan`](../../app/main.py) uses `await asyncio.sleep`),
  so the ceiling is worker/engine throughput, not connection handling — matching
  the "processing, not submit" conclusion above.

### How to reproduce

Run the ramp against a running stack (Docker stack for all four engines, or a
local app + worker), one variable at a time:

```powershell
foreach ($c in 5,10,25,50) {
  .\.venv\Scripts\python.exe tools\benchmark_scans.py `
    --base-url http://localhost:8000 --token $env:MASP_API_TOKEN `
    --sample .\path\to\small_sample.bin `
    --requests 30 --concurrency $c --wait-seconds 30 --timeout 300 `
    --output .\benchmark-results\sync-c$c.json
}
```

Read `synchronous_completion_rate` and `submit_p95` per step; the break point
is where the rate drops below the acceptable bar or `submit_p95` approaches
`wait_seconds`. To confirm the worker-count lever, rerun the breaking
concurrency with more Defender workers and watch the rate recover.

### What to tell the integrating team

Quote a **safe concurrency** (the highest step that stayed at/above the sync
rate you require) for a given worker count, not a single latency number. If
their expected concurrency exceeds what worker scaling can hold within
`wait_seconds`, the synchronous pattern is the wrong fit and they should either
poll on `202` or move to an async callback (a webhook does not exist yet — see
the handoff notes). The absolute numbers above are dev-host specific; re-run
the ramp on the real deployment (full engine set, Postgres) before quoting
figures.

## PostgreSQL Connection Pooling (2026-07-13)

Every database helper used to open a fresh `psycopg.connect()` per call, so a
single engine job paid TCP + auth + backend-spawn cost roughly 15 times
(claim, mark-running, result insert, terminal mark, finalize, timing events,
heartbeats). Under concurrent ICAP load this connection setup was the dominant
orchestration cost. `app/database.py` now reuses connections through
`psycopg_pool`.

### Behavior

- The pool is **per process** and **lazy**: it is never opened at import time,
  it is created on the first Postgres `connect()` call, and it is rebuilt if
  the PID changes (fork safety). Shutdown closes it via `atexit`.
- `connect()` / `with connect()` semantics are unchanged: commit on clean
  exit, rollback on exception, connection returned to the pool instead of
  closed. The SQLite path is completely untouched.
- The "Postgres not ready yet" startup tolerance is preserved: pool
  acquisition is wrapped in the same
  `MASP_DATABASE_CONNECT_ATTEMPTS` x `MASP_DATABASE_RETRY_DELAY_SECONDS`
  retry loop as the old direct-connect path.
- Each process logs `MASP DB pool enabled (min=N, max=M)` when its pool is
  created. Absence of that line means the process is running direct-connect
  (pool disabled, psycopg_pool missing, or SQLite).

### Configuration

| Env var | Default | Meaning |
|---|---|---|
| `MASP_DB_POOL_ENABLED` | `1` | `0` restores the previous direct-connect behavior exactly (fallback/escape hatch) |
| `MASP_DB_POOL_MIN` | `0` | Connections opened eagerly per pool; `0` = fully lazy |
| `MASP_DB_POOL_MAX` | `4` | Maximum connections **per process** |
| `MASP_DB_POOL_TIMEOUT_SECONDS` | `30` | Wait for a free pooled connection before failing (`PoolTimeout`, caught by the existing `DatabaseOperationalError` handling) |

### Connection budget

`MASP_DB_POOL_MAX` applies per process. Budget the deployment as:

```
(number of MASP processes) x MASP_DB_POOL_MAX  <  Postgres max_connections - reserve
```

A typical local split stack (app + icap + 2 Linux workers + 1 Windows Defender
worker) is 5 processes x 4 = 20 potential connections against the Postgres
default `max_connections = 100`. Raise `max_connections` or lower
`MASP_DB_POOL_MAX` before adding many worker replicas.

### Measured effect

ICAP REQMOD benchmark, 5 MB sample, engine-key split Linux workers
(clamav / static_metadata), YARA disabled, c=10, r=100, warm-up first:

- Cleanest available comparison (Linux worker timing events OFF in both runs):
  **2.37 -> 4.42 files/sec, ~1.86x**, p50 3.45s -> 2.23s.
- Caveats recorded in the benchmark notes: the pooled runs' timing-ON/OFF
  cells were not cleanly isolated (the Windows Defender worker kept timing ON
  and ran unpooled code in both), so "pool + timing ON" vs "pool + timing OFF"
  and any larger multiplier (for example 0.89 -> 4.42) must NOT be quoted as a
  pure pooling effect. A clean re-run would be needed to make those claims;
  the ~1.86x figure is the defensible one.
- With pooling in place, batching/sampling worker timing events showed no
  additional measurable win in these runs, so that optimization is parked
  (hypothesis, not a verdict, for the reason above).
