# Storage protection (folder scanning)

Status: **phase 1 implemented (2026-09-29); phases 2 to 4 are design only.** The
architecture was agreed with the product owner on 2026-09-29. Sections marked
**OPEN** are unresolved and are gated as stated. Each phase is approved
separately; "Phase 1 as built" at the end records what exists and where it
differs from this design.

## Purpose

Today MASP scans what it is sent: a browser upload, an API upload, an ICAP request,
a deferred object reference or a manifest-announced object. Storage protection
adds the opposite direction: MASP is given a storage location and **finds the
files itself**, keeps an inventory of them and scans new and changed files with
the engines of a scan profile.

The expected workload shapes the design:

- a proof of concept with few files;
- real use with continuous small and medium uploads, occasional multi-terabyte
  transfers, and locations that hold very large numbers of very small files;
- some bulk-data locations where a full antivirus scan is neither affordable nor
  needed, and a content-type policy plus a hash-list check is enough.

## Decisions

| Topic | Decision |
|---|---|
| Action on a finding | Detection only. MASP never quarantines, deletes or modifies a source. |
| Rescanning on new signatures | Not in scope now. |
| Record model | A light inventory row per file; a scan record only where a full scan runs. |
| Reading | Whatever access the engines and workers require; **no copy unless one is needed**. |
| Clean content | Never retained in MASP storage. Detected files are retained as evidence. |
| Narrow coverage | Shown in a separate Folder Scanning area, never as a clean result. |
| Location binding | A service client and one of its scan profiles. |
| Type policy | Per location: allowlist or denylist of content families. |
| Archives in the light tier | Per location: full scan (default), allow, or detect. |
| Manifest and crawl | One protection worker reads both into one inventory. |

## Protected locations

A protected location (`storage_locations`) names:

- a display name, unique like other operator-visible names;
- `service_client_id` and `scan_profile_id` (an enabled profile owned by that client);
- `backend_key` and a relative `prefix` inside it;
- a discovery mode: `manifest`, `crawl` or `both`;
- crawl interval, per-cycle budget (entries and seconds) and stability window;
- ignore patterns (defaults such as `*.tmp`, `~$*`, `*.partial`);
- ordered tier rules, the type policy, the archive action, and whether the light
  tier computes a hash (with an optional size ceiling);
- `enabled` and `management_revision` for fenced browser writes.

**Authorization reuses the client storage model.** Every cycle checks
`backend_allowed_for_client(backend_key, client_key, object_id)` in
`app/services/deferred_storage.py`, which already combines deployment backends,
environment grants and custom per-client grants. No new grant model is added. A
removed grant, a disabled client or a disabled profile stops the location
fail-closed, visibly, rather than silently scanning with stale permissions.

**Engines come from the profile** and are frozen into a routing snapshot when work
is accepted, exactly like API and deferred intake. Retries, coverage and decisions
use that snapshot, never the profile's current engine set.

Filesystem roots stay deployment-owned: the console selects a backend key and a
prefix, and never accepts or shows a root path.

## Inventory, separate from scan history

Scan history is one row per submitted file plus one engine job per engine. That is
right for submissions and wrong for a location that may hold millions of files.
Storage protection keeps its own inventory and opens scan records only where a
full scan actually runs.

- **`storage_objects`**: one row per `(location_id, object_id)`, unique. Size,
  `mtime_ns`, file identity where the filesystem provides one, `sha256` (nullable
  until hashed), state, applied tier and policy revision, `content_id`, first seen,
  last seen pass, last change, and a finding summary.
- **`storage_contents`**: one row per SHA-256 and engine-set fingerprint, holding
  the full-scan `scan_job_id` and a result summary. **Content deduplication**: the
  same bytes under the same engine set are scanned once and the result applies to
  every path holding them. MASP has no deduplication today (see the note in
  `app/services/scan_intake.py`), so this is new.
- **`storage_findings`**: type-policy violations, extension/content mismatches,
  hash blocklist matches and engine detections, each with its object, content,
  evidence sample (if captured) and notification link.
- **`storage_passes`**: crawl passes with start, end and counters. An object not
  seen during a *completed* pass is marked `removed`; an interrupted pass removes
  nothing.

Every object is in exactly one state, and the console shows each separately:

| State | Meaning |
|---|---|
| `waiting` | Seen, not yet stable. |
| `light_passed` | Light tier found nothing. **No antivirus scan ran.** |
| `light_detected` | Light tier produced a finding. |
| `scanning` | Full scan queued or running. |
| `full_clean` | Every required detection engine completed without detection. |
| `full_detected` | A full scan detected something. |
| `full_incomplete` | A required engine failed or was skipped. |
| `changed` | Content changed during or after inspection; waiting to stabilize again. |
| `unreadable` | Could not be opened or read; the reason is recorded. |
| `removed` | Absent from a completed pass. Findings remain. |

`light_passed` is never presented, counted or exported as clean, and never feeds
an allow decision. This closes the result-semantics question of
`MAPPED_SOURCE_INSPECTION.md` for storage protection by keeping narrow coverage in
its own model and its own screens instead of inside the scan decision.

## Discovery

A new `storage-protection` process (its own compose profile, present in the
development, production and pilot compose files with settings in both example
environment files) mounts each backend root **read-only** with
`noexec,nosuid,nodev`.

**Crawl.** SMB/CIFS mounts do not deliver remote change notifications to Linux, so
discovery is a periodic walk. It is incremental: a persistent cursor continues where
the previous cycle stopped, and each cycle has an entry and time budget plus a rate
limit so the file server is not overloaded. Symbolic links, reparse points and
hardlinked files are rejected with the rules `_reject_link` and
`open_deferred_source` already enforce.

**Stability.** Without a manifest, the only completion signal is that a file stops
changing. An object is processed only after it was observed at least twice with the
same size and modification time, the observations at least the location's stability
window apart. Ignore patterns exclude well-known temporary names.

**Manifest.** For `manifest` and `both`, the protection worker reuses
`discover`, `read_manifest` and `_resolve_object` from
`app/services/manifest_intake.py`. A manifest-announced object skips the stability
wait (the manifest is the completion signal) and its declared size and SHA-256 must
match what MASP reads; a client-supplied digest may reject but never satisfies a
check. Rejections are recorded in the existing `manifest_rejections` table.

In `both` mode the crawl is the safety net that catches objects whose manifest never
arrived. The shared inventory means an object handled through its manifest is not
scanned again by the crawl.

The existing manifest worker and `POST /api/v1/deferred-scans` stay unchanged for
compatibility. Configuration rejects a protected location and the standalone
manifest worker covering the same backend and prefix.

## Tiers

Each location has ordered rules matching a path pattern and a size range to a tier,
`full` or `light`; the first match wins and the default is `full`. The applied tier
and policy revision are recorded per object.

A file larger than every detection engine's limit cannot be fully scanned (ClamAV
in clamd mode skips anything over `DEFAULT_CLAMD_SIZE_LIMIT`, 64 MiB, unless raised).
In the full tier it ends as `full_incomplete`. Locations that expect very large
files should say so with a size rule to `light`, which makes the narrower
inspection an explicit decision instead of an accident.

### Light tier

The light tier runs **inside the protection worker and creates no engine jobs**.
That is its point: its cost is one bounded header read (plus one streaming read
when hashing is enabled), independent of queue overhead.

- **Content classification.** The header classifier in `app/engines/file_type.py`
  becomes a shared function used by both the `file_type` engine and the protection
  worker, and is extended with LNK, Mach-O, MSI, and OOXML (a zip containing
  `[Content_Types].xml`) distinguished from a plain zip. Scripts (batch,
  PowerShell, JavaScript, VBScript) have no magic bytes: they are classified by
  extension and shebang only, and the console states that limit plainly.
- **Type policy.** Per location, either an allowlist ("only these families may
  appear") or a denylist ("these families must not appear"), built from named
  families: executable, script, archive, macro-capable office, document, image,
  and so on. A violation is a detection. An extension/content mismatch is always
  a finding in both modes.
- **Archives.** The location chooses: send to the full tier (default, because a
  header cannot show what an archive contains), allow, or detect.
- **Hash list.** MASP computes the SHA-256 itself while streaming the file in
  place, and looks it up in `hash_list_entries` in batches (a multi-digest variant
  of `get_hash_list_entry`). A blocklist match is a detection; an allowlist match
  is informational only and never suppresses anything, as everywhere else. The
  location can disable hashing above a size ceiling; the object then records that
  no hash was computed.

### Full tier

The full tier uses the existing queue unchanged: a scan with `source='storage'`,
**one scan per unique content**, the profile's engines, leases, attempt fencing,
fenced finalization, `required_detection_engine_names` coverage and the shared
decision helpers. A scan whose engines all failed or were skipped is `failed`, as
for every other source. Archive handling follows the existing lazy
extract-on-detection behaviour.

## Reading without copying

The rule: **every read an engine consumes is verified against the inventory
digest.** If the bytes an engine actually saw do not hash to the digest recorded for
the object, the result is discarded, the object becomes `changed` and waits to
stabilize again. This replaces the "copy first, then fstat before and after"
guarantee with one that holds for in-place reads, and closes the time-of-check to
time-of-use question of `MAPPED_SOURCE_INSPECTION.md` for this feature.

A storage sample carries a source reference (`source_backend_key`,
`source_object_id`) instead of a file in MASP storage; `storage_path` stays null.
Engines read through a source-reader abstraction instead of `resolve_sample_path`:

- **Worker with the backend configured locally** opens the object with
  `open_deferred_source` and streams it. ClamAV's INSTREAM path hashes the bytes as
  it sends them. An engine that needs a file path (Microsoft Defender, a YARA CLI)
  gets a **worker-local temporary copy**, verified and deleted after the engine
  finishes; it never receives the share path, so the source cannot change under it.
- **Worker without the backend** (a control-API worker such as a remote Defender
  node) downloads through the existing sample delivery route, which the MASP server
  now streams from the source; `download_sample` keeps verifying size and SHA-256.
- **Claim routing.** A direct-database worker that does not have the backend
  configured never claims storage engine jobs. This closes the worker-placement
  question of `MAPPED_SOURCE_INSPECTION.md` without a new routing constraint.

MASP storage receives a copy **only as evidence**: after a detection (light or
full tier) the protection worker makes a verified copy into `samples/`, retained
under the existing retention rules and deletion protections. If the object is gone
or its digest no longer matches, the finding records that evidence could not be
captured. Clean content is never copied into MASP storage.

## Findings and notifications

Findings are written to `storage_findings` and, for severities that notify, to the
existing transactional notification outbox in the same transaction. The rule that
scan completion never calls a webhook directly still applies. Retention and manual
deletion keep preserving scans with undelivered outbox events.

## Console: Folder Scanning

Storage protection gets its own console area, separate from the manual dashboard
and the API ledger:

- **Locations**: status, last cycle, last completed pass, counts per state and tier.
- **Location detail**: coverage by tier and state, waiting, changed and unreadable
  objects, and the location's configuration.
- **Findings**: bounded ID-keyset pages, filters by location, kind and severity.
- **Path search**: literal, bounded, per location.
- **Location management** (admin): create and edit with CSRF, pre-body checks and a
  `management_revision` fence; no automatic replay of writes.
- **Health**: `app/services/health_read.py` gains the protection worker, judged
  like the manifest worker (missing cycle record is `unknown`, an old one stale).

Storage scans never appear in the manual dashboard or the API ledger. A full-tier
report opens through a storage-scoped route that reuses the existing bounded report
readers, following the server-selected source scope pattern.

## Scale

The concern that matters most is a very large number of very small files, where the
per-file overhead dominates, not the bytes.

Today each engine job costs roughly 25–30 database round trips on the direct worker
path (a count of calls, not a measurement), and a control-API worker downloads the
sample once per engine job. Version 1 limits that cost by:

- content deduplication (identical small files are extremely common);
- the light tier creating no engine jobs;
- the inventory being separate from scan history, so no scan record exists for a
  light-tier object;
- a budgeted, rate-limited crawl.

**OPEN (gated on a capacity measurement with realistic small and large files):**

- a multi-object engine job, claiming many small contents at once;
- automatic pruning of clean storage scan records while keeping the content summary;
- default crawl budgets, stability window and tier thresholds.

## Other open points

- **OPEN:** heuristics for scripts beyond extension and shebang.
- **OPEN:** the notification payload for storage findings (reuse of the deferred
  event shape versus a storage-specific event).
- **OPEN:** behaviour when a location's profile is edited: which objects, if any,
  are re-queued. Accepted snapshots are never rewritten either way.

## Acceptance

Each phase adds tests proportional to the change, on SQLite and on a disposable
PostgreSQL through `MASP_TEST_POSTGRES_URL`:

- clean, detected, timeout/unavailable and unreadable objects in both tiers;
- an object that changes during a read (discarded result, `changed` state);
- removal after a completed pass, and no removal after an interrupted one;
- manifest plus crawl on one location scanning each object once;
- content deduplication across paths and locations with the same engine set;
- a revoked storage grant stopping the location fail-closed;
- in-place schema upgrades on SQLite and PostgreSQL;
- concurrency: two protection workers, lost fences, crash mid-cycle;
- a capacity run with realistic file counts and sizes before any scale default is
  fixed.

## Phases

1. **Inventory and light tier.** Schema, protection worker (crawl, stability,
   inventory, light tier, findings, notifications), Folder Scanning read screens and
   location management.
2. **Full tier.** Source-referenced samples, verified in-place reads, content
   deduplication, evidence capture, control-API streaming from the source.
3. **Manifest and `both` modes** in the protection worker.
4. **Capacity measurement**, then the gated scale work above.

## Out of scope

Quarantine, deletion or any modification of the source; rescanning stored content
on new signatures; watching storage the deployment has not approved as a backend.

## Phase 1 as built

Implemented: `storage_locations` and the inventory tables (schema in
`ensure_storage_protection_schema`), the `storage-protection` worker
(`app/workers/storage_protection_worker.py`, `app/services/storage_protection.py`),
the light tier with the shared header classifier (`app/services/content_types.py`)
and policy model (`app/services/storage_policy.py`), findings with a separate
`storage_notification_outbox` delivered by the existing notification worker, the
browser API under `/api/ui/v1/storage`, the Folder Scanning console screens and a
system health check.

Differences from the design above, all deliberate:

- **Crawl mode only.** `manifest` and `both` are accepted by the schema but refused
  by the API and by the worker until phase 3.
- **Full tier waits.** An object routed to the full tier, including an archive the
  location sends there, is recorded as `full_pending` and never read.
- **A separate outbox.** The scan outbox requires a scan and its undelivered rows
  protect scans from deletion, so storage findings use their own table with the
  same webhook, signature, backoff and fencing. Only detected findings of high or
  critical severity are queued.
- **Second observation.** An object is due once its first observation is older than
  the stability window; the inspection's own `fstat` against the recorded size and
  modification time is the confirming observation, and a mismatch sends it back.
- **Classifier limits.** MSI is not distinguished from other OLE2 files by its
  header; the `.msi` extension adds the executable family instead. OOXML is
  recognized when `[Content_Types].xml` appears in the header.
- **Mismatch as detection.** An extension/content mismatch is always a finding and
  is a detection only when the real content is an executable or script.
- **No deletion.** Locations are disabled, not deleted, so findings keep their path.
- **Policy changes** apply to objects inspected afterwards; nothing is re-queued
  (the OPEN point above still stands).
- **Invalid stored policy** stops only its own location, with the reason recorded.

The per-location lease (`MASP_STORAGE_LEASE_SECONDS`, default 300) keeps two workers
off one location; `MASP_STORAGE_CRAWL_SECONDS` bounds each crawl slice and
`MASP_STORAGE_SWEEP_PAUSE_SECONDS` spaces working sweeps. No capacity run has been
done; the scale items above remain OPEN.

