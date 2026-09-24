# Independent browser console: incremental migration

## Current scope

The independent React/TypeScript/Vite application in `frontend/` serves
`/console/dashboard`, `/console/engines`, `/console/scans/new` and manual
`/console/scans/{id}` reports with `/console/scans/{id}/children` archive navigation,
`/console/batches/{id}` manual batch overviews and `/console/scans/{id}/manage`
summary/full exports and single-scan management. Per-engine full text opens at
`/console/scans/{id}/results/{result_id}` with a 2 MiB source/response limit.
It uses React Router, TanStack Query, Tailwind and
project-owned shadcn-style components backed by Radix Dialog. Its lockfile and
build are separate from the legacy root Tailwind build. No external fonts,
scripts, telemetry or CDN are needed at runtime. Installing dependencies needs
registry access or a prepared cache; built assets work with the local MASP API.

Implemented: existing-account login/logout, admin authorization, engine inventory,
explicit adapter setup, instance settings, enable/disable, removal confirmation,
worker-pool assignment, connection-check states, local YARA rule management and
responsive layout. Rules remain files on the MASP server; remote rule deployment
is not implemented. The rule editor accepts UTF-8 files up to 96 KiB; saving an
existing filename overwrites its content. Run a check to validate compilation.

The Dashboard now provides manual history, status/recorded-risk filters, text
search, cached summary cards and cursor pagination. Both analyst and admin
sessions may read it; admins may delete up to 20 selected visible rows with
per-record stale-state fences. Manual sample submission now stays in the console and
returns a visible acceptance receipt. Dashboard and receipt links now open the
React report, showing backend decisions, required coverage and on-demand technical
previews. Submission API `report_url`/Location still retain their legacy URLs for
compatibility; the console constructs its own internal route from the scan ID.

Admin `/console/system` now provides bounded worker inventory, explicit lifecycle
changes and confirmed agent-credential revocation. Heartbeat liveness and lifecycle
are shown separately. `/console/system/pools` adds bounded pool pages and confirmed
create/edit/delete, with engine assignments managed from Engines. Dashboard selection controls use explicit 18 px sizing and
a compact selection column; desktop and mobile browser checks cover the regression.
The complete console has light and dark palettes. First load follows the browser's
system color preference; the accessible toggle is available before and after login,
and an explicit choice persists in local storage. A same-origin pre-render script
applies it before React starts, avoiding a theme flash while remaining compatible
with the frontend nginx `script-src 'self'` policy. Theme preference contains no
account, scan or secret data and does not cross browser profiles.

All browser UI now lives in the independent frontend; the server-rendered
legacy UI has been retired (see "Legacy UI retirement" below). Its former GET
paths redirect to console screens. Integration URLs, worker control, queue
behavior and snapshots are unchanged.
Node is required for building/development, not for serving static production files.

## Complete UI migration inventory

Migrate in the following slices, preserving existing permissions and backend
decision/queue semantics. Each slice includes typed browser contracts, relevant
authorization/regression tests, responsive browser verification and documentation.

| Slice | Current state and remaining work |
| --- | --- |
| Manual scan workflow | Dashboard, submission, reports, archive/batch navigation, summary/full exports, retry, protected single/bulk deletion, a bounded printable report and plain-text access to oversized engine output implemented. Legacy filter parity: an engine-detection filter and the `metadata_only` risk option. |
| Engines | Instance setup/settings, enable/disable/delete, checks, local rules and pool assignment implemented. `/console/engines/hash-list` manages the institution hash list (new; no legacy equivalent). Retain instance identity and secret omission. |
| System — current slice | Worker inventory, lifecycle, credential revocation, worker-pool create/edit/delete and paginated worker runtime/active queue implemented. |
| System — overview | Admin-only cached all-source totals, worker liveness, read-only retention policy and on-demand bounded historical engine-name metrics. Full-history aggregation scale gate remains. |
| System — deferred intake | Admin-only read of the manifest worker's last recorded cycle (stale/failed flagged), deferred queue counts and oldest waiting age, bounded manifest rejections and pre-scan failures with paths redacted. New screen; no legacy equivalent. |
| System — retention | Admin-only bounded preview and confirmed deletion across all sources; age and state fences, active/child/shared-sample/outbox protections, per-record outcomes. No recursive deletion. |
| System — remaining parity | Engine pool assignment is already in React Engines. Engine metrics now include last-result time. Deployment-sized fleet/read validation remains. |
| Scan policy | `/console/scan-policy` implements admin-only reads and confirmed atomic updates of the three operational limits with shared backend validation/resolution. |
| Hash lookup | `/console/hash-scan` provides analyst/admin explicit manual lookup, backend decisions, quota-aware adapters and bounded result summaries, now with legacy provider detail: a bounded provider status, verdict counts, last analysis date, cache source, duration, an HTTPS report link and operator guidance. Free-text provider reasons and policy configuration stay omitted. |
| Integration administration | `/console/service-clients` lists clients and opens a tabbed settings dialog. Named-profile create/edit/disable/delete/default selection, fenced engine assignments, atomic client creation and credential add/list/scoped revocation are implemented. Tokens are supplied by the admin and never returned. `/console/service-clients/{id}/setup` reports coherent configuration readiness and connection details. `/console/service-clients/{id}/storage` manages bounded logical backend/prefix grants with explicit environment inheritance, deny-all and stale-edit protection; roots remain deployment-managed. |
| Automation history | React API/ICAP ledger listing, source/client/unassigned/status/risk/text filters and bounded cursor pages implemented. Automation reports/technical output, batch overview and protected single deletion implemented. Summary/full JSON/CSV exports implemented. Single terminal result JSON preview implemented. Single status JSON preview implemented. Small-batch status/result JSON implemented. Automation direct-child navigation implemented. Confirmed admin bulk deletion implemented. Automation printable reports and oversized engine-output downloads reuse the manual readers under automation scope. A batch contract larger than the inline view downloads in full, up to the same 5000 members the integration API serves. Remaining: final legacy-action parity; preserve ownership and manual-history isolation. |
| Users and account | Bounded inventory, confirmed local creation, administrative role/password edit and deletion, and own-account password change implemented. Shared last-admin/session protections and stale revision fences; LDAP shadow deletion does not disable directory access. Final cutover/deployment acceptance remains. |
| Audit and information | Admin `/console/audit` provides bounded descending ID-keyset audit pages, literal search, outcome filtering and bounded inert details; no total is calculated and no write verb exists. `/console/about` gives analysts and admins the product boundary and a non-sensitive runtime snapshot with admin-scoped client counts. Complete details render indented with sorted keys as legacy did; truncated or non-JSON details stay as recorded. About matches the legacy metrics. Remaining: deployment-shaped trail-volume validation. Legacy audit has no printable view. |
| Cutover | Done: the console is served by the application image, former GET paths redirect to console screens, legacy form routes and HTML rendering are removed, and console errors no longer point at legacy pages. Static deployment behind real TLS and deployment-scale performance remain acceptance gates. |

Inventory covers the legacy login/logout, Dashboard, scans/batches/reports/exports,
engines/rules, System/pools/retention, policy/hash lookup, service clients/profiles/
credentials, API ledger, users/account, audit and About flows in `app.main`.
Recursive batch deletion is separate functionality and requires its own protected
transaction design; it must not be inferred from the existing batch read view.
Migration does not promote engine support or waive security/performance acceptance.

### Client administration presentation (2026-09-22)

The client directory uses compact rows with enabled/managed badges. Selecting a row
opens a large dialog with Settings, Connection, Profile routing, Storage and Credentials tabs.
Keyboard tab navigation, focus return and mobile/light/dark layouts are supported.
Panels load on first selection and remain mounted until close to preserve mutation
outcomes and explicit refresh requirements. Credentials clear their token input when
leaving the tab; confirmations and pending writes lock tab switching and dismissal.
Dialog profile pagination does not modify the directory cursor. Existing deep links
remain available. Readiness checks switch to the relevant tab; endpoint values stay
inert text. Creation separates identity, routing and initial API access. Existing
admin/CSRF checks, confirmations, stale-routing fences and secret lifetime remain.
No API or schema change is needed. Validation: all 125 frontend tests, five Edge
workflows, production build and whitespace check; isolated fixture data only.

## Run locally

Start the existing backend normally. In a second terminal at the repository root:

```powershell
npm --prefix frontend ci
npm --prefix frontend run dev
```

Open `http://127.0.0.1:5173/console/dashboard` with an existing MASP account.
Engines management still requires an admin. `/console/` defaults to Dashboard.
The Vite proxy defaults to `http://127.0.0.1:8000`. Override `MASP_BACKEND_URL` in
`frontend/.env.local` for a different backend. Host/Origin are preserved. Never
put secrets in frontend configuration or `VITE_*` variables; do not expose Vite
publicly. Existing local accounts, LDAP and session expiration are reused.
Both UIs share the cookie name/path; on one hostname, logout affects both.
`localhost` and `127.0.0.1` have separate browser cookie scopes.

## Browser API and security

The boundary is `/api/ui/v1`, with Pydantic/OpenAPI response schemas, a checked-in
snapshot at `frontend/contracts/browser.openapi.json`, generated TypeScript in
`frontend/src/lib/api.generated.ts` and readable type aliases/transport in
`frontend/src/lib/api.ts`.

| Relative route | Method | Purpose |
| --- | --- | --- |
| `/session` | GET | Current user and session-bound CSRF token |
| `/session/login`, `/session/logout` | POST | Login / revoke session |
| `/api-ledger` | GET | Analyst/admin bounded API/ICAP non-child history with scoped filters |
| `/api-ledger/scans/{id}` | GET / DELETE | Automation report / admin-only fenced single deletion |
| `/api-ledger/scans/{id}/summary-export` | GET | Bounded automation report summary JSON/CSV |
| `/api-ledger/batches/{id}/json` | GET | Complete small-batch integration status/result JSON; `kind=status` or `result` |
| `/users` | GET / POST | Admin-only bounded identity metadata / CSRF-protected explicit local creation |
| `/users/{id}` | PUT / DELETE | Admin/CSRF-only revision-fenced role/password update or removal |
| `/account` | GET | Session user's bounded identity metadata and authentication source |
| `/account/password` | POST | CSRF-protected own local password change with atomic session revocation |
| `/api-ledger/scans` | DELETE | Admin/CSRF-only bounded top-level bulk deletion with per-record fences and receipts |
| `/api-ledger/scans/{id}/children` | GET | Source/client/batch-scoped direct children with ID cursor and parent-attempt guard |
| `/api-ledger/scans/{id}/status-json` | GET | Integration status preview; coherent global queue counts under statement budgets |
| `/api-ledger/scans/{id}/result-json` | GET | Terminal integration result JSON preview; analyst/admin, bounded snapshot |
| `/api-ledger/scans/{id}/export` | GET | Snapshot-based full operator JSON/CSV within export limits |
| `/api-ledger/scans/{id}/results/{result_id}` | GET | Bounded on-demand automation technical text |
| `/api-ledger/scans/{id}/results/{result_id}/full` | GET | Ownership-checked full output within 2 MiB ceilings |
| `/api-ledger/batches/{id}` | GET | Bounded automation batch members matching source and client |
| `/dashboard/summary` | GET | Manual/non-child totals, 30-second server cache |
| `/dashboard/scans` | GET | Bounded manual history previews, ID-keyset pagination |
| `/scans/options` | GET | Current file/body limits and eligible enabled engine count |
| `/scans` | POST multipart | Store one manual sample and enqueue; JSON `202` receipt |
| `/scans` | DELETE | Admin-only bounded bulk deletion of selected visible manual scans |
| `/scans/{id}` | GET | Manual report, backend decision and required-engine coverage |
| `/scans/{id}/results/{result_id}` | GET | On-demand bounded technical text previews |
| `/scans/{id}/results/{result_id}/full` | GET | Complete per-engine text within separate 2 MiB source/response limits |
| `/scans/{id}/children` | GET | Registered direct manual archive children, scoped keyset pages |
| `/scans/{id}/summary-export` | GET | Bounded summary JSON/CSV download content in a typed JSON envelope |
| `/scans/{id}/export` | GET | Bounded full JSON/CSV download content in a typed JSON envelope |
| `/batches/{id}` | GET | Bounded registered manual batch members and recorded counters |
| `/scans/{id}/retry` | POST | Analyst/admin confirmed atomic retry; JSON `202` receipt |
| `/scans/{id}` | DELETE | Admin-only protected single-record deletion and sample-cleanup receipt |
| `/engines` | GET / POST | Inventory and catalog / create instance |
| `/engines/{id}/config` | PUT | Validate and save configuration |
| `/engines/{id}/enabled` | PUT | Explicit enabled state, not a retry-sensitive toggle |
| `/engines/{id}/placement` | PUT | Assign/remove worker pool |
| `/engines/{id}` | DELETE | Remove exact instance |
| `/engines/{id}/checks` | POST | Worker request (`202`) or explicit local test (`200`) |
| `/engines/{id}/rules` | GET / POST | List/save local YARA rules |
| `/engines/{id}/rules/{name}/toggle` | POST | Toggle local rule |
| `/engines/{id}/rules/{name}` | DELETE | Delete local rule |
| `/system/workers` | GET | Admin-only bounded durable worker inventory with node-ID keyset pages |
| `/system/workers/lifecycle` | POST | Confirm explicit active/draining/disabled state for one node |
| `/system/workers/credentials/revoke` | POST | Confirm revocation of all current agent credentials for one node |
| `/system/pools` | GET / POST | Bounded admin pool inventory / create an enabled unassigned pool |
| `/system/pools/{id}` | PUT / DELETE | Explicit name/selector/state update / delete only an unassigned pool |
| `/system/queue` | GET | Admin-only all-source active scans, bounded ID-keyset pages |

Engine and System routes require admin browser sessions, not service-client bearer tokens.
The exact Dashboard/options/manual-report/technical/full-output/children/batch/summary/full-export GET routes, manual submission and retry POST routes are additionally
allowed for analysts; this does not widen engine-management permissions or expose
automation history. Bulk and single deletion remain admin-only. Service-client
tokens are not browser credentials.
Anonymous access returns JSON `401`, not HTML redirects. Unsafe methods require
exact same-origin `Origin`, `X-MASP-UI: 1`, and, after login, `X-CSRF-Token` from
the session endpoint. Session cookies remain HttpOnly, never returned in JSON or
kept in localStorage. Private responses are not HTTP-cacheable; private query
data is removed on logout/expiry. Validation errors do not echo input. Vendor
plaintext/ciphertext is omitted from inventory; a blank secret edit preserves an
existing encrypted key. Writes use the existing audit middleware.

Authorization precedes body reading; JSON bodies are capped at 128 KiB.
Only `POST /api/ui/v1/scans` accepts multipart under the deployment upload ceiling.
`engine_setup.py` shares validation with the old UI. Config changes invalidate
old worker health atomically. Partial updates preserve unrelated enable/config
changes. Concurrent deletion cannot recreate an instance through the config API.

## Health and performance

### Manual submission boundary

`/console/scans/new` accepts one file, case (200 characters), priority
(`Normal`, `High`, `Low`) and note (4,000 characters). The server fixes source to
`manual` and archive mode to `lazy_extract_on_detection`, matching legacy intake;
arbitrary source, engine/profile, command and storage-path fields are rejected.
No raw sample is embedded in JSON, base64-encoded or previewed by React.

Browser authentication, same-origin and session-bound CSRF checks run before
multipart parsing. Both old and new upload boundaries share `bounded_upload`:
declared and streamed body size are enforced even if Content-Length is missing
or dishonest. The browser route additionally permits at most one file and three
text parts, bounds each text part to 16 KiB and rejects duplicate/unknown fields.
Parser spool files close on rejection; file-policy failures and intake transaction
failures use existing owned-file cleanup. Parser spooling still consumes RAM/disk
and upload slots: this is not end-to-end zero-copy streaming or global admission.

The endpoint uses `store_upload` and `enqueue_scan_from_stored_sample` without
importing `app.main`, preserving file hashes, source-aware engine selection,
instance-specific jobs, archive/container intake and rollback semantics. Disk
copy/hash work and database intake run in the thread pool; workers execute later.
Successful responses contain only `scan_id`, `status: accepted`, and `report_url`,
with HTTP `202`, `Location` and no-store. This is an acceptance receipt, never an
assertion that engines ran or that the sample is clean. Audit context records the
session actor and scan ID through the existing production audit middleware.

The form disables repeat clicks during a pending upload, preserves input on
failure and never automatically retries. Network/5xx failures warn that intake
may already have committed. There is no request-idempotency key in this slice:
check history before retrying, and keep the page open until acceptance. The UI
does not claim a precise upload percentage or cancel/rollback an accepted scan.
Client size checks are advisory: multipart overhead, proxy limits and policies
may still cause server rejection. Enabled engine count is not worker health.
Manual source retains its existing external reputation/quota behavior.

### Read paths

Manual report summaries run a single read snapshot for the scan, persisted engine
jobs and projected results: PostgreSQL REPEATABLE READ or a SQLite read transaction.
This avoids mixing pre-retry scan state with post-retry results. SQLite read locks
can briefly block writers outside WAL mode; SQLite remains local-test only.
The shared `scan_assessment` helpers compute the decision; `required_detection_engine_names`
uses the accepted routing snapshot first, historical instance-job names second,
and current configuration only for truly legacy records without either. Optional
preloaded inputs let the new reader avoid repeated job queries without changing
existing callers. The UI labels the legacy-configuration fallback explicitly.

The compact reader accepts up to 256 engine results/jobs/required names and a
262,144-character routing snapshot. Larger sets return 413 with a legacy-report
link, never a decision based on an incomplete engine set. The summary query does
not select raw output or findings. It reads up to 65,536 policy-JSON characters
per result to preserve existing adapter review-policy semantics (including manual
VirusTotal enrichment). Oversized, invalid or non-object policy JSON yields a null
decision and explicit warning; it does not silently drop policy and return allow.
This conservative limitation may require the legacy report for unusually large
static/vendor details until normalized policy projections are persisted separately.

Sample filename/case/note/error/signature/decision-reason previews are bounded;
engine identity names are retained without truncation for coverage matching. Scan storage paths and profile
contents are not returned. The technical endpoint selects at most 16,384 characters
each of raw output, details JSON and findings JSON, with truncation indicators.
Truncated JSON is shown as text, not parsed or executed. Both routes require a
browser session; automation-source scans return 404, and technical result IDs
must belong to the requested manual scan. Manual archive children may be opened
directly or reached through the new child-navigation screen.

Active reports (queued/running/finalizing) poll every three seconds; settled reports
stop interval polling and refresh on manual action, remount or stale window focus.
Background intervals are disabled. Fetch failures remove the previous decision card.
Technical output is fetched only on expansion, is not polled and is discarded on
collapse; reopening refreshes it. It is explicitly a separate snapshot, not live
worker output. Coverage/decisions never depend on these truncated technical previews.
No result or queue writes, vendor probes, retention changes or schema changes are
performed by reading reports. This is bounded transfer, not a throughput claim;
database substring/decompression, legacy fallback and connection-pool load remain
PostgreSQL validation concerns.

The separate per-engine full-output screen loads only after an explicit navigation
from a result row, including when the compact policy decision is unavailable.
`GET /scans/{id}/results/{result_id}/full` checks the manual source and result
ownership through the same join for preflight and hydration. A PostgreSQL
REPEATABLE READ or SQLite read transaction keeps both reads on one snapshot.
Before loading text, the database measures UTF-8 bytes across engine name, raw
output, details JSON and findings JSON; sources above 2 MiB return 413. A second
2 MiB serialized JSON check accounts for escaping. Responses never silently
truncate. The DTO includes only scan/result IDs, engine name, attempt and the
three text fields; it contains no sample path, sample bytes or integration settings.

React renders every field as plain text without parsing JSON or HTML. This is a
recorded result snapshot, not live output, coverage or an allow decision. The
screen neither polls nor refreshes on focus/reconnect; explicit refresh hides
earlier output while fetching and after failures. Unmount discards its query
cache, and session expiration/logout clears private queries. Oversized results
retain a legacy link. Statement timeouts remain in force; database TOAST work,
serialization overhead and concurrent viewers still require deployment load
acceptance. The ceiling is not a total process-memory budget.

Inventory GETs never execute vendor probes or spend external quota. A request-level
pool/binding snapshot avoids per-card placement reads. Worker liveness is not
engine health: requested checks are pending/running, missing workers unavailable,
expired reports stale, and returned tests healthy/failed. A failed eligible node
is not hidden by a healthy sibling. HTTP `202` acceptance never means success.

Dashboard, Engines, submission, reports, management and archive navigation are lazy-loaded. One shared inventory query polls every 3 seconds
while pending/running and every 30 seconds otherwise; background-tab interval
polling is disabled. Writes cancel older inventory GETs and invalidate afterward.
Mutations are not automatically retried. Forms require explicit values, including
boolean choices; suggested values remain placeholders.

Dashboard history uses `limit` (default 20, maximum 100) and exclusive `before`
submission ID, ordered by descending ID. No `OFFSET`, exact filtered total or
engine-result hydration is used. The partial `(source, id DESC)` index excludes
archive children; SQLite and PostgreSQL startup upgrades create it idempotently.
A deleted cursor row is harmless; newer submissions do not move older-page
boundaries. This is not a frozen snapshot: deletion/retry/status changes may
change matches between reads. Browser Back/Forward restores URL filters/cursors;
Latest scans resets the cursor. Names/case previews are capped at 512/128
characters, respectively; the original report retains the full values.

`q` is a literal case-insensitive substring (up to 200 characters) across
filename, hashes, case, note and priority. `%`, `_` and `!` are escaped and SQL
values bound. `status=active` includes finalizing. `risk` filters the recorded risk level.
Case folding follows database `LOWER` semantics; SQLite's built-in Unicode
case folding is limited, so non-ASCII matching is not a cross-database parity claim.
The risk level is **not** a detection verdict. Failed/missing coverage is never relabeled
clean; score zero and job completion do not imply policy allow. Snapshot-aware
coverage is available in the console report. This intentional history preview is
not decision/coverage parity; operators must still open the report.

Search runs only on Apply filters, not each keystroke. The latest page polls at
20 seconds; historical pages do not interval-poll. Background-tab intervals are
disabled, abandoned requests receive abort signals, and inactive history query
entries expire after one minute. HTTP abort does not itself cancel running SQL.
Summary polling is every 30 seconds, with a separate single-flight 30-second
per-process cache. It can therefore appear roughly 60 seconds behind under normal
poll timing (longer with hidden tabs/network failures). Refresh does not bypass
the server cache; `generated_at` exposes its age. No cross-user private data is
cached: scope is the same global manual history visible in the legacy Dashboard.

Page payloads are bounded, **database work is not universally bounded**. PostgreSQL
browser reads have a transaction-local, 5-second-per-statement default budget and
force a custom plan; timeout returns a sanitized 503 and rolls back the read.
Cold summary totals still aggregate all manual history; cache misses occur
independently in each API process. Substring/no-match and selective status/risk
queries can scan many rows. Large deployments still need deployment-shaped plans,
indexed search and possibly incrementally maintained counters. Startup
index creation is not concurrent and can block writes on large installations;
schedule an upgrade window. No queue, result or retention semantics changed.

Queue fairness and ICAP streaming remain separate work. Inventory returns all configured
engines; very large deployments need pagination/incremental health updates.
DTO generation and drift checks are implemented; see the contract workflow below.

### Summary/full exports and scan management

The report links to `/console/scans/{id}/manage`. Analysts and admins can download
summary or full JSON/CSV exports and confirm retry; only admins see and may invoke deletion.
The management screen refreshes on entry, focus or explicit action, without an
interval. Server-side mutation checks remain authoritative when the page is stale.
Legacy links preserve oversized full-output access. Recursive batch deletion remains a
separate migration slice.

`GET /scans/{id}/summary-export?format=json|csv` calls the same coherent, bounded
report reader as the report screen. It preserves backend decisions, missing
coverage, null decisions and policy warnings. Its schema-versioned file explicitly
identifies itself as a manual summary: text can be truncated by existing report
limits, and raw output, full findings and archive children are omitted. The CSV
is a field/value representation of that summary, with an apostrophe prefixed to
every string value to force spreadsheet text, including leading control characters.
The API returns a typed JSON envelope (`filename`, `media_type`, `content`); the
browser downloads those server-produced bytes through a temporary Blob URL and
revokes it. It never calculates a decision or downloads sample bytes. Fixed
numeric filenames avoid reflecting uploaded filenames into download metadata.

`GET /scans/{id}/export?format=json|csv` builds the complete operator export from
the same shared backend report code as the legacy route. One PostgreSQL REPEATABLE
READ or SQLite read transaction loads the manual scan, routing evidence, engine
jobs and results, so retry cannot mix generations. The JSON includes full raw
engine output, parsed details and findings. The CSV preserves the normalized
summary, finding and engine-result rows; it does not duplicate raw blobs. Every
untrusted textual CSV cell is forced to spreadsheet text. Neither format returns
sample bytes, stored filenames, storage paths or the routing snapshot, and the read
does not query or add integration configuration/tokens. Fixed numeric filenames and no-store/session rules match the
summary export.

The full reader accepts at most 256 engine results and 256 engine jobs. Before it
hydrates result blobs, a database aggregate rejects more than 2 MiB of UTF-8 source
fields; a separate 2 MiB serialized-output ceiling still applies. PostgreSQL read
budgets cover both the aggregate and blob fetch. Invalid or non-object policy details
produce a null decision and explicit warning while retaining the technical evidence;
they never turn into an allow decision. Oversized records return 413 with the legacy
export as an operator fallback.

Exports are requested only on click, without automatic retry or query-cache
retention. The 2 MiB UTF-8 file limit rejects oversize output with 413; it does not
silently remove engines, policy fields or technical evidence. JSON-envelope escaping
increases wire size. Serialization holds the bounded report and export text in memory;
this is not streaming and does not establish a concurrent export capacity budget.
The report reader's PostgreSQL substring/TOAST and policy-projection gates remain
for deployment-shaped rows, despite the local synthetic acceptance result below.

Retry/delete require exact same-origin browser headers, CSRF and strict JSON
containing the displayed `attempt` and `job_revision`. The latter is the highest
persisted engine-job ID from the report snapshot (zero for no jobs). Both are
checked under the scan row lock, or SQLite BEGIN IMMEDIATE. Job revision prevents
replay of an old confirmation even when a retry settles while still queued and
the scan attempt count has not increased. This is a stale-state guard, not a
request-idempotency key; reconcile network/5xx failures before repeating a write.

Retry rejects active work or no eligible engines. It preserves source-aware
selection and any stored routing snapshot; for manual scans without a snapshot,
it uses current eligible manual engines, as before. Resetting old results/events/
jobs, setting queued and inserting new instance jobs now commit together. Failure
rolls back the reset. Legacy retry also uses this atomic queue operation. HTTP
202 means accepted, not executed/completed. External reputation quota may be spent
by the resulting manual run; existing archive child records remain registered.

Shared database deletion now locks and rechecks state, rejects queued/running/
finalizing scans, shared samples and undelivered notification events. PostgreSQL
also locks the sample against concurrent foreign-key attachment. Browser deletion
additionally rejects parents with any registered direct children, preserving
navigation without traversing a tree. Database commit precedes owned sample-file
cleanup; a missing file or cleanup error produces `sample_removed: false` with
an explicit administrator follow-up message. This is not transactional filesystem
deletion or a new cleanup outbox. Neither action runs adapters in HTTP handlers.

Mutation settlement clears old technical output and resets cached report data,
then invalidates history/archive queries; a previous allow card must not survive
an uncertain retry. Confirmation buttons prevent repeat submissions while pending.
Production audit middleware records the browser actor and scan target. Writes
and read/export payloads keep session isolation and no-store behavior. PostgreSQL
retry/delete row locking and timeout rollback are covered by the disposable test
gate. Sample-reference/outbox lookup plans and deployment concurrency/export
budgets remain required gates; bounded output does not bound those queries. No
table/column migration, new worker transport or engine support promotion is added.

Dashboard bulk deletion uses `DELETE /scans` with one to 20 unique candidates
from the visible page. Each candidate carries the displayed scan ID, attempt and
highest engine-job ID. The server accepts admins only, rejects archive children
from this Dashboard operation, and applies the same manual-source, active-state,
registered-child, shared-sample, undelivered-outbox and row-lock checks as
single-record deletion. Disabled active-row checkboxes are advisory; the locked
server recheck is authoritative.

Candidates commit independently in request order. The response separates deleted,
blocked and post-commit cleanup-failed IDs, so one stale/protected row does not hide
a successful deletion of another. This is deliberately a bounded partial-result
operation, not an atomic multi-row transaction. A network/5xx failure can still be
ambiguous after earlier rows commit; React never retries automatically and tells
the administrator to refresh history before another attempt. Changing filters or
pages clears selection. Production audit context records aggregate requested,
deleted, blocked and cleanup-failed counts. It does not recursively traverse or
delete an archive batch.

### Worker administration boundary

Worker pages default to 20 entries (maximum 100), use the existing node primary
key for exclusive ascending seeks and keep working if the cursor row is deleted.
The browser read budget applies. Display strings and metadata are projected with
SQL substring limits; invalid or oversized labels/adapter lists produce an explicit
incomplete marker. Reads do not probe engines, load health blobs or select credentials.
Heartbeat expiry is distinct from admin lifecycle and proves no engine coverage.

Lifecycle and revocation reuse the existing database operations and audit context.
They require an admin session, same-origin headers and pre-body CSRF checks; strict
JSON rejects unknown fields. Heartbeat updates cannot overwrite an admin lifecycle.
Draining/disabled stops new claims while owned work finishes. Revocation immediately
invalidates current Control API credentials, including running requests' subsequent
operations; re-enrollment is required. Browser actions require confirmation, never
automatically retry, invalidate worker/engine reads after settlement and hide stale
controls after read failures. Inventory refreshes every 30 seconds while visible,
pausing during confirmation. Existing backend concurrency semantics remain; no
cross-administrator compare-and-set or new write-lock budget is claimed here.

### Worker pool administration

Pool management at `/console/system/pools` uses exclusive ascending ID-keyset
pages (20 default, 100 maximum), SQL-bounded name/selector projections and indexed
assignment-existence probes. It does not enumerate worker fleets, engine health or
all bindings. Malformed/oversized stored routing metadata is marked incomplete;
editing is disabled to avoid saving a truncated selector. The list has manual
refresh and no interval polling, and hides cached rows after errors.

Pool writes are admin-only with pre-body CSRF/origin enforcement and strict JSON.
Browser and legacy forms share name/selector normalization. Browser writes also
require a non-empty selector with at most 4096 serialized characters; names allow
100 characters. Selectors use the existing exact label matching semantics. Changes
require confirmation and carry the exact desired fields; there is no automatic
retry. Existing database operations preserve instance bindings and foreign-key
deletion protection, including concurrent assignment rejection. An assigned pool
cannot be deleted; assignments must be removed explicitly in Engines. Disabled
pools stop new claims and do not cancel owned work. New pools are enabled, unassigned
and confer no health/coverage guarantee. Mutations invalidate pool/engine caches.
This slice adds no schema, worker transport or cross-admin update revision fence;
existing duplicate-name race semantics and deployment write/load budgets remain
separate hardening work.

### Generated browser contracts

All non-empty successful browser responses now have explicit models, including
engine mutations, YARA rule metadata and capability fields (reusing the adapter
capability dataclass without dropping existing fields). Worker checks document
both synchronous 200 and queued 202; 204 remains bodyless. Shared error responses
describe `detail: string`, including the browser route's sanitized 422 response,
not FastAPI's default validation-detail array. They describe common application
errors, not guaranteed JSON for proxy failures or unexpected 500s. Auth/CSRF and
role enforcement still run in `BrowserRoute`; schemas are not authorization.

`tools/export_browser_openapi.py` constructs an isolated FastAPI app containing
only the browser router. It never imports `app.main`, starts a server, initializes
the database, reads deployment secrets or runs adapters. JSON is sorted and has
no timestamps or live instance configuration. `--check` compares without writing.
The [openapi-typescript generator](https://openapi-ts.dev/node) then produces
types from that local snapshot; remote/file `$ref` resolution is rejected.
Generated files are source artifacts to keep together in version control; they
contain schema definitions, never actual sessions, keys, rules or sample bytes.

Tool setup, from the repository root in a development environment:

```powershell
python -m pip install -r requirements-browser-contracts.txt
npm --prefix frontend ci
npm --prefix frontend/tools/contracts ci --ignore-scripts
npm --prefix frontend run contracts:generate
npm --prefix frontend run contracts:check
npm --prefix frontend run contracts:test
npm --prefix frontend run typecheck
```

The Python schema baseline pins FastAPI 0.138.2 and Pydantic 2.13.4; this is not
a complete production Python dependency lock. The generator has its own package
manifest/lockfile with openapi-typescript 7.13.0 and its supported TypeScript 5.9.3
peer. The console retains TypeScript 7.0.2; no forced peer override/downgrade is
needed. Installing tools needs a registry or prepared cache. Export, generation
and checks subsequently operate locally. Normal `npm --prefix frontend run build`
uses the committed type artifact and needs neither Python, a live API nor these
isolated generator dependencies. `contracts:types:check` is the Node-only half
of the check; it cannot detect backend-to-snapshot drift by itself.

All console calls use `request()` with generated route, method, path-parameter,
JSON-body and response types. Callers cannot independently assert an unrelated
response DTO. Known writes require a CSRF argument at compile time (login is the
exception); server checks remain authoritative. Session cookies, no-store, abort
signals, encoded paths, JSON/multipart handling, errors and no automatic retry
remain unchanged. Query-string values and multipart field contents are still
validated on the server; TypeScript does not validate incoming JSON at runtime.
The schema is not loaded by browsers and type imports add no runtime validator
or extra network requests. Backend and static assets should be deployed from the
same tested revision; this is not cross-version negotiation or a runtime health check.

`.github/workflows/browser-contracts.yml` defines Windows/Linux jobs for both
drift checks, generator tests, isolated browser API tests, frontend tests and
the production build (including compile-time negative assertions), plus a Linux
job that runs the full suite against a disposable PostgreSQL 16 service. Actions are
pinned to commit IDs, permissions are read-only and checkout credentials are not
persisted. No deployment, external messages or repository writes occur. Remote
workflow execution remains unverified until these changes are pushed through CI;
this task does not push/commit or claim branch-protection enforcement. The job
does not replace PostgreSQL, nginx/TLS, E2E or engine host acceptance gates.

### Registered archive children

The report links to direct-child navigation for scans with a batch. Children use
the same analyst/admin session boundary as manual reports; API/ICAP parents return
404 and children must be manual, have `scan_role=child`, match the exact parent ID
and share its batch (or both be detached). Nested navigation follows scan IDs,
never client-supplied storage paths. Duplicate archive paths retain separate IDs.

`GET /scans/{id}/children` takes `limit` (20 default, 100 maximum), exclusive
ascending `after` ID, literal `q` (200 characters) and `status`. Later pages require
the first page's `attempt_count` as `attempt`; a changed parent attempt returns
409 and the UI offers a first-page reset. A single read transaction keeps parent
attempt/state and child rows coherent within a request. It does not freeze pages
across requests: appends, deletions and status changes can change matches.
The existing `(parent_scan_id, id)` index serves seeks and scoped nested-child
existence checks. Child presence is a second query in the same read snapshot,
with at most `limit + 1` constant index probes; this avoids PostgreSQL choosing a
correlated sequential scan when one archive parent dominates table statistics.
There is no OFFSET, total count, full-tree hydration, engine
result read, filesystem access, extraction or batch-counter write. Paths are
bounded to 1,024 characters with a truncation marker, filenames to 512. Search
escapes SQL wildcard characters; Unicode folding has the Dashboard limitations.
Selective/no-match searches can still scan many children and need deployment-shaped
plan/load acceptance. Bounded output alone is not a bounded database-work claim.

Only the first page polls at three seconds while the parent or a visible child
is active. Historical pages do not interval-poll; hidden-tab polling is disabled.
Filters apply explicitly and reset pagination; URL history preserves navigation.
Inactive queries expire after one minute, and errors hide cached child rows.
Rows show recorded risk, not a policy decision; open each report for coverage.
Empty lists may reflect filtering, skipped/failed/not-triggered lazy extraction,
not a clean archive. Retries can retain older child records. This is registered
scan navigation, not a fresh-extraction inventory or a recursive directory view.
Full engine output is available from each result row within the browser limits.
Single-scan summary/full exports
and retry/delete are available through the report's management link.

### Manual batch overview

`/console/batches/{id}` and `GET /batches/{id}` show one manual batch and all its
registered manual members, including nested archive members. The first query reads
the batch and its persisted counters; the second selects at most 101 compact scan
rows in the same PostgreSQL REPEATABLE READ or SQLite transaction. GET never calls
`refresh_scan_batch_counts`, executes extraction, loads engine results or selects
sample storage paths, free-form batch metadata, profile snapshots or internal errors.
Automation-source batches return 404, and corrupt cross-source members are excluded.

Pages default to 20 rows and allow at most 100. The paired `created_at` and scan-ID
cursor follows `idx_scan_jobs_batch_created`, remains valid if the cursor row is
deleted and avoids OFFSET work for deep pages. Attached scan creation order is
stable; status/risk may change between requests. Active first pages poll every three
seconds, while historical pages pause interval refresh. Stored counters can lag
workers and may include work not visible on the current page. Recorded risk, a
completed batch, a non-empty list or an empty list never establishes policy allow,
full engine coverage or complete archive extraction; each scan report remains the
decision authority. This view adds no batch mutation or recursive deletion.

## Static deployment

The application image now builds the console in a Node stage and serves it at
`/console/` from port 8000 (`app/services/console_static.py`), so pilot and
production deployments need no additional container or port. Headers match the
nginx overlay below: the same CSP, `X-Frame-Options: DENY`, `nosniff`, `no-store`
for the page and public files, and one-year immutable caching for fingerprinted
`/console/assets/*`. A missing asset is a 404, never the single page, so a stale
hash fails visibly. Request paths are resolved inside the build output and
dotfiles are refused. `MASP_CONSOLE_DIST` points elsewhere when needed; without a
build the console answers 503 with the build command. Node is needed only in the
image build stage.

The overlay remains available for local work:

```powershell
npm --prefix frontend run build
docker compose -f docker-compose.yml -f docker-compose.frontend.yml up --build frontend
```

The optional overlay serves `/console/` on loopback port 8080 in a separate
unprivileged nginx container; other paths proxy to `app:8000`. Browser API and UI
stay same-origin without permissive CORS. Port 8000 is unchanged. JSON is capped
at 128 KiB; the exact `/api/ui/v1/scans` upload location and legacy uploads allow
64 MiB request bodies. Rebuild the frontend container when upgrading from the
Dashboard-only slice, or nginx may reject files at 128 KiB. Request buffering is disabled. Fingerprint
assets are cached, not HTML/private API data. Align proxy limits with any approved
larger upload policy.

This is a local/pilot overlay, not production certification. For TLS, restrict
ingress to a trusted proxy, preserve Host/HTTPS scheme end-to-end, and configure
Uvicorn to trust **only actual proxy addresses**. Otherwise origin checks reject
HTTPS browser writes when the backend sees HTTP. Require Secure session cookies;
never fix this with arbitrary origins/public forwarded-header trust. Apply login
rate limits, resource/connection budgets, read-only container configuration and
scanned/pinned image digests before promotion. Docker base tags are moving until
that release gate.

## Verification and next steps

Verified on 2026-09-18 after automation report exports: the full
Python suite ran 729 tests (727 passed, two platform-gated skips) with the disposable
database, including 109 browser API, five contract tests and the 24-test PostgreSQL
reliability module. All 88 frontend tests (two Vitest workers) and all 20 Edge
workflows passed in full runs. Both contract drift checks and compile-time negative
assertions passed. Three generator tests passed in the preceding runtime slice;
the generator implementation is unchanged. Remote Windows/Linux CI has been configured but not executed.
TypeScript/production build and `git diff --check` passed. SQLite WAL retry-race tests
proved coherent report and parent/child snapshots followed by the new attempt
on the next read. SQLite batch snapshot/index checks and PostgreSQL
report/archive/batch consistency, migration, queue
concurrency and browser statement/row-lock budget tests passed against a
disposable PostgreSQL 16 container. Initial JavaScript including its shared UI dependency is
about 99.34 kB gzip; lazy batch overview is 2.19 kB, submission 2.21 kB, archive
navigation 2.26 kB, report 2.65 kB, Dashboard 3.46 kB, management 2.56 kB,
full engine output 1.18 kB, System 2.41 kB, runtime 1.77 kB, System overview 2.04 kB,
retention 1.89 kB, scan policy 1.74 kB, hash lookup 1.38 kB, service clients 1.99 kB,
client profiles 2.06 kB, client creation/credentials 2.61 kB, API ledger 1.89 kB, automation management with exports 2.20 kB,
worker pools 2.36 kB, Engines 4.87 kB, shared dialog 12.82 kB,
shared mutation code 0.96 kB and search
icon 0.30 kB gzip, excluding CSS (about 5.74 kB gzip). Shared dialog code loads
with Dashboard, management, System or Engines.
These are build sizes, not measured user latency. The new exact nginx upload
location is configured but real nginx/TLS upload execution remains a gate.
Docker image execution/TLS and deployment-shaped PostgreSQL validation were not
performed in this slice. Test services used disposable data; no existing MASP configuration was
changed by the browser acceptance test.

```powershell
python -m unittest discover -s tests
npm --prefix frontend run contracts:check
npm --prefix frontend run contracts:test
npm --prefix frontend test
npm --prefix frontend run build
npm --prefix frontend run test:e2e
python tools/benchmark_dashboard.py --rows 100000
python tools/benchmark_browser_postgres.py --database-url $env:MASP_TEST_POSTGRES_URL --confirm-reset-public-schema --rows 100000 --archive-rows 100000
```

Browser acceptance uses Edge on Windows; other systems need Playwright Chromium
installed. It starts a loopback-only fixture on 18765 with its own temporary
SQLite database plus Vite on 5175, refuses to reuse existing servers and never
imports `app.main` or opens existing MASP data. Test credentials are public and
must never be used for real deployment. Screenshots/traces are written under
ignored `artifacts/console-e2e`.
The management fixture uses two separate benign temporary files and detached
manual child records to keep retry/delete independent of history/archive fixtures.
SQLite tests cover atomic retry rollback, two-retry serialization, retry/delete
locking, stale attempts/job revisions and deletion protections. A corresponding
PostgreSQL rollback/locking test passed against the disposable database; it
remains gated when `MASP_TEST_POSTGRES_URL` is absent.
Python 3.14 emitted existing SQLite connection ResourceWarnings; the successful
suite is not evidence that connection-lifecycle cleanup or pool budgets are solved.

Coverage includes login, explicit ClamAV creation, unavailable-worker feedback,
config save, disable, delete, logout, analyst authorization, Dashboard pagination,
URL history/reload, filtering, failure/zero-score display, shared report decisions,
lazy technical text, result ownership, coherent retry snapshots, bounded policy
fallback, historical engine renames, registered archive pagination, duplicate
paths, nested navigation, retry-cursor conflicts, detached batches, archive
read-only/indexed projections, coherent parent/child snapshots, manual batch
authorization/source isolation, persisted counters, paired/deleted cursors,
read-only indexed pages, nested batch members and benign multipart submission,
receipt/history and mobile overflow. Bulk deletion coverage includes pre-body
authentication/CSRF/admin enforcement, strict bounded input, duplicate rejection,
attempt/job-revision fences, locked role/source checks, active/child/parent/shared
sample/outbox protections, partial receipts, cleanup failures, analyst read-only
behavior and a real Edge workflow. Submission tests cover pre-body
auth/CSRF, streamed/declaration limits, duplicate/unknown/excess parts, field
limits, file-policy rejection, no-engine/transaction cleanup and archive intake.
Backend tests cover manual scope, literal SQL search, invalid limits, payload
projection, seek index use/upgrade, concurrent aggregate caching and deleted
cursors. The additional PostgreSQL read-model test passed in the disposable run.
This does not prove real Defender execution, deployment PostgreSQL capacity or
nginx/TLS behavior.

Full-output tests cover session/source/result isolation, multibyte source size,
rejection before blob hydration, serialized control-character expansion and
snapshot consistency across concurrent deletion (SQLite WAL) or oversized update
(PostgreSQL). Frontend tests cover inert HTML/invalid JSON, failure clearing,
oversized fallback, invalid IDs and cache disposal. The Edge report workflow
also navigates to full output, reads beyond the compact preview, reloads the
direct route and checks mobile overflow. No new large-output load benchmark was
run; the read statement timeout and deployment concurrency gates still apply.

Local disposable SQLite benchmark, 100,000 synthetic manual scans, seven
iterations, median service-call time including connection: latest 20 previews
1.922 ms; 90%-deep keyset page 1.658 ms; no-match substring search 371.406 ms;
uncached summary 104.260 ms; cached summary 0.001 ms. A page was 5,088 JSON bytes.
This is one development-host run with synthetic small rows and warm OS cache,
not HTTP/browser latency, a concurrency benchmark or a PostgreSQL capacity claim.
The benchmark never opens deployed data or starts workers.

Previously measured on 2026-09-10: local disposable PostgreSQL 16 benchmark,
100,000 synthetic Dashboard rows plus
100,000 direct archive children, 15 measured iterations and eight-way mixed
reads rotating Dashboard, search and batch requests: latest-page p95 20.606 ms;
90%-deep Dashboard keyset 6.047 ms; no-match Dashboard substring 274.892 ms;
uncached summary 29.788 ms; deep archive page 13.419 ms; no-match archive
substring 128.454 ms; deep batch keyset page 8.313 ms; report 16.090 ms; JSON
summary export 9.984 ms; full JSON export 18.717 ms; mixed-read p95 473.969 ms.
Every checked default budget passed. Dashboard attempt/job-revision plans used
`idx_scan_engine_jobs_scan_instance`, the archive child-presence plan used
`idx_scan_jobs_parent`, and the batch page used `idx_scan_jobs_batch_created`;
the benchmark now fails if these required indexes disappear. This
was a loopback, warm-cache synthetic run without HTTP/TLS/proxy latency or worker
writes.

Worker coverage includes pre-body admin/CSRF enforcement, strict lifecycle input,
node isolation, credential revocation, heartbeat preservation of admin state,
bounded/incomplete metadata and deleted keyset cursors on SQLite and PostgreSQL.
React tests cover confirmation/cancellation, inert node text, CSRF payloads,
pagination and uncertain failures. Edge checks lifecycle persistence, revocation,
analyst denial and mobile layout. The two Dashboard browser workflows were rerun
after the final CSS specificity correction; checkbox dimensions, compact selection
column and search-icon padding passed. Screenshots were visually inspected.

Pool coverage includes admin/pre-body CSRF, malformed/oversized input, duplicate
names, scoped update/delete, assigned-pool protection, incomplete metadata and
deleted cursors. PostgreSQL checks exercise the bounded pool projection and
assignment protection. React covers exact confirmed fields, cancellation,
disabled controls, pagination and uncertain errors without replay. Edge creates,
disables, reloads and deletes a pool, checks analyst denial and mobile overflow;
mobile screenshots were visually inspected. Theme coverage follows the system
preference on first use, persists explicit changes across reload, and checks the
light login, Dashboard, forms and confirmation dialog in real Edge. Light desktop
and mobile screenshots were visually inspected. No fleet-scale benchmark was added.

Runtime/queue migration adds `/console/system/runtime` and `/system/queue` in the
browser API. Admins see queued/running/finalizing scans across manual, automation
and archive-child sources, with 20-row pages (100 maximum), exclusive ascending
ID cursors and bounded filename/priority fields. The partial active-ID index is
created on both SQLite and PostgreSQL upgrades. No result blobs, notes, storage
paths, profile snapshots or historical totals are selected. This is scan-ID order,
not claim order; deferred intake without a scan record is absent. Completion can
remove a row between pages without invalidating the cursor. Worker runtime uses
the existing bounded worker endpoint; the two lists are independent snapshots.
First pages poll every 30 seconds while visible; later pages do not interval-poll.
Errors hide cached rows. Automation rows do not link to manual-only React reports.
Tests cover admin authorization, source/state projection, changing cursor rows,
SQLite/PostgreSQL index upgrades, pagination, stale-error clearing and mobile
overflow. The PostgreSQL index check disables sequential scans only to verify
index eligibility; it is not a fleet-scale planner or throughput acceptance claim.

System overview migration adds `/console/system/overview`, backed by admin-only
`/system/summary` and `/system/engine-metrics` browser endpoints. Summary uses one
repeatable database snapshot for all-source scan counts and worker liveness;
active/online does not imply capacity, pool eligibility or engine coverage.
Summary has a single-flight, 30-second per-process cache. Retention days/batch size
are read-only server policy; cleanup is now in the separate React retention screen.

Historical metrics load only on demand without interval/focus/reconnect polling.
They group retained results by recorded engine name, not current instance identity:
renames split and reused names combine history. Names are capped at 512 characters
with a truncation marker; pages default to 20 groups (100 maximum). No raw output,
findings or storage data are selected. Pages seek by each group's minimum retained
result ID; retention/retry deletion can move that ID and repeat or skip groups
between requests. This is not a frozen historical snapshot. Only one metrics page
is cached per process for 30 seconds, bounding cursor-driven cache memory.
Errors hide stale frontend data. Duration is recorded engine latency, not end-to-end
scan latency; detections/completion do not prove coverage or policy acceptance.

Uncached summary and metrics reads use the existing PostgreSQL statement budget
(five seconds by default). Full-history aggregation work is not bounded by the
response page limit: representative history size, concurrent admin reads and cache
misses still require deployment-shaped validation. No schema/index or retention
mutation is introduced by this slice.
SQLite tests cover admin/analyst boundaries, cache reuse, all-source counts,
heartbeat/lifecycle separation, coherent reads during concurrent updates and
bounded historical names/cursors. PostgreSQL covers aggregate types and metric
pagination. React covers on-demand loading, inert names, unknown latency, cursors
and stale-error clearing. Edge covers admin navigation, analyst denial and mobile
overflow; the light-theme mobile screenshot was visually inspected.

Retention migration adds `/console/system/retention`, `GET /system/retention` and
`POST /system/retention/run` in the browser API. Admin authorization is mandatory;
POST also checks CSRF before parsing strict, bounded JSON. Preview reads at most
20 rows plus a continuation sentinel, or the smaller configured batch size, using
ascending ID pagination and the PostgreSQL read budget. It includes expired
inactive scans across all sources and archive children, without engine output,
profile snapshots or storage paths. This is a candidate list, not a promise that
every row can be deleted. Sparse candidates still require deployment-scale query
validation; no unbounded eligible-count query is added.

Confirmation captures only displayed IDs, attempts/job revisions and server policy
days/batch size. Execution rechecks the current policy, bounds and unique IDs.
The shared delete primitive now optionally applies the age cutoff in its locked
scan read, alongside existing active-state/attempt/job-revision checks. Browser
retention also protects parents with registered children, shared samples and
undelivered notifications. It never recursively deletes an archive. Each record
commits separately; deleted, blocked and file-cleanup-failed IDs are explicit.
Unknown failures may follow earlier committed rows: the UI hides the old preview,
requires refresh/reconciliation and never replays the request automatically.
Policy editing stays in deployment configuration; no schema change is introduced.
Existing legacy cleanup remains compatible. Retention actions populate audit context.
Tests cover pre-body admin/CSRF enforcement, strict limits, disabled/changed/invalid
policy, all-source preview, age/attempt/job-revision guards, active scans, children,
shared samples, undelivered outbox events and post-commit file-cleanup failure.
PostgreSQL acceptance exercises preview types and age rechecking after a concurrent
update. React verifies confirmation/cancellation, exact fenced payloads and uncertain
failure handling. Real Edge deletes a disposable benign fixture, verifies cleanup,
checks analyst denial and mobile overflow; the confirmation screenshot was inspected.

Scan-policy migration adds `/console/scan-policy` and admin-only GET/PUT
`/api/ui/v1/scan-policy`. GET selects only three allowlisted settings, caps stored
text, and uses the same value-resolution helper as runtime policy reads. It reads
overrides in one database statement and reports errors instead of silently showing
defaults. Environment/default provenance is shown without reading deployment
secrets. Oversized stored values require server-side correction before editing.
PUT accepts all three bounded strings explicitly, validates through the existing
policy helper, and writes or removes overrides in one transaction. A blank clears
the override; zero upload policy cap still respects deployment HTTP ceilings.
The UI confirms values, prevents automatic replay and requires reload after a
save/uncertain response. Concurrent edits remain last-save-wins. Legacy policy
routes remain compatible; their existing save behavior is unchanged. Runtime
policy fallbacks and limits, ICAP configuration and schema are unchanged.
Policy tests cover pre-body role/CSRF checks, strict fields, numeric boundaries,
shared fallback/clamping, reset behavior, secret omission, oversized stored values
and rollback of the entire save after a simulated database failure. PostgreSQL
exercises saved-value types and override clearing. React covers confirmation,
cancellation, blank reset values and uncertain responses without replay. Edge
verifies persisted values after reload, clearing overrides, analyst denial and
mobile layout; the mobile screenshot was visually inspected. The first concurrent
frontend test run timed out in an unchanged submission test; the complete suite
passed with two Vitest workers, without changing that test or production behavior.

Hash migration adds `/console/hash-scan`, GET `/api/ui/v1/hash-scan/options` and
POST `/api/ui/v1/hash-scan`. Options never execute probes. Both reads and writes
require a browser session; analysts/admins may submit, and POST checks CSRF before
parsing strict JSON. SHA-256 normalization reuses the existing validator. Selection
uses `enabled_hash_engines(source='manual')`, preserving API/ICAP quota exclusions
and the existing provider reservation/cache behavior. More than 16 enabled hash
engines is rejected before any call. This caps fan-out, not inventory query work
or total provider latency; deployment-shaped validation remains open.

The existing backend aggregator computes the decision. Empty selections and
partial/provider/quota failures produce no completed decision. Earlier successful
calls may already consume quota; the frontend never retries or polls automatically.
Only instance ID, bounded name, found flag and normalized decision reach the UI;
raw provider payloads, exception text, configuration and credentials are omitted.
Input/results are not persisted in browser storage or scan history. Editing the
hash clears the previous result. A reputation allow or missing hash is not full
file-scan coverage. Legacy rich provider-detail display remains a parity item.
API tests use deterministic adapter doubles for allow/review/block, invalid input,
role/CSRF, source selection, engine-count limits, secret omission, quota and partial
failure. React checks explicit submission, inert rendering and no replay. Edge
checks analyst access, disabled submission without engines and mobile layout.
No live provider request or quota expenditure was performed for these checks.

Client inventory migration adds `/console/service-clients`, GET
`/api/ui/v1/service-clients` and PUT `/api/ui/v1/service-clients/{client_id}`.
Admin-only reads use ascending ID-keyset pages (20 default, 100 maximum), bounded
key/name text and the existing PostgreSQL read budget. The query selects only
service-client metadata, never credential hashes/prefixes/tokens, profile policies
or scan history. Oversized metadata is marked incomplete and not editable in the
React form. There is no polling; failed reads hide cached rows. Deleted cursors
remain usable without a lookup of the cursor record.

Updates require pre-body admin/CSRF enforcement and strict explicit name/state
fields. Names use the existing trim/nonblank semantics with a 100-character browser
limit. A single scoped UPDATE excludes `legacy-default` in SQL. Keys, profiles,
credentials, accepted snapshots and queue state are unchanged. The UI confirms
the client identity and new values, never automatically retries and requires a
fresh read after successful or uncertain writes. Concurrent edits are last-save-wins.
Enabled status alone does not establish usable profiles/credentials. Creation,
credentials and profile routing use the separate React routes described below.
No schema migration is added. Deployment-sized integration inventory and concurrent
administrative load still require acceptance.
Client tests cover admin/pre-body CSRF, strict fields, managed-client exclusion,
scoped state updates, bounded/truncated metadata and deleted cursors. SQLite proves
the list works without the credentials table; PostgreSQL verifies projection types,
pagination and managed/scoped updates. React tests confirmation/cancellation,
inert names, scoped CSRF payloads, pagination and uncertain failure without replay.
Edge verifies persisted name/state, analyst denial and mobile overflow. The light
mobile screenshot was visually inspected; all test data was disposable.

Client storage access extends client administration (2026-09-23) with a Storage
tab and standalone `/console/service-clients/{id}/storage`. Admin GET/PUT
`/api/ui/v1/service-clients/{client_id}/storage` expose only logical backend keys,
whole-backend/prefix grants, inheritance mode and write fences. No root paths,
filesystem probes, credential or sample data are returned. Existing environment
grants remain effective until an explicit custom replacement; an empty custom
grant list denies all. Returning to deployment inheritance is confirmed and retains
the revision row. Saves serialize on the client and compare the prior revision
and visible environment-grant/backend-key fingerprint. Boundaries: 50 backends/
grants, 32 prefixes per grant, 128-character keys, 512-character normalized prefixes
and 64 KiB serialized stored policy. Invalid or oversized reads fail explicitly;
they never enable editing a truncated policy. Managed compatibility access remains
read-only. Every write outcome requires an explicit read before further edits;
confirmation/pending writes lock the outer client dialog and tab navigation.

New deferred admission and workers before copying consult the same uncached
policy resolver. Revocation may fail queued work, but does not cancel an already
started copy or change accepted routing. Local backend presence is configuration,
not proof of worker reachability. All API/intake processes require coordinated
upgrade before custom grants are enabled; see deployment rollout/rollback notes.
Storage/profile semantics remain separate from in-place reading or a new engine
support claim. Complete deployment acceptance remains open.

Storage validation: full SQLite/PostgreSQL suite ran 876 tests (874 passed,
2 skipped), including migration, concurrent first saves, inheritance/deny-all,
prefix boundaries, API admission and worker revocation before copy. All 136 React
tests and 8 related Edge client workflows passed; storage scenarios were rerun
after correcting their selectors. Build, generated contracts and whitespace checks
passed. Desktop/mobile storage screenshots were visually inspected. No live
deployment was performed.

Named profiles extend this screen (2026-09-22): admins now create, rename,
enable/disable, delete and choose a default inside the client's Profile routing
tab or the standalone page. POST on the profile collection creates a named profile
with explicit engines; PUT on a profile edits name/state; PUT `/default` switches
the default; DELETE tombstones a non-default profile. All changes require explicit
confirmation and a fresh read after any write outcome. The current default cannot
be disabled/deleted. The form and cards display the integration `profile_id`.

Metadata/default/delete writes fence `management_revision`; engine writes now
add that revision to the existing expected-engine-set fence (the revision remains
optional for compatibility with older routing clients). All shared writers lock
the owning client before profile rows. Default changes also compare the prior
default ID, projected even on later 20-profile pages. The migration adds revisions,
tombstones and a partial unique default index, repairing older duplicate defaults
without changing accepted snapshots. Deletion retains deferred foreign keys and
engine assignments; deleted names remain reserved. Read bounds, policy/config/secret
omission and admin/pre-body CSRF requirements remain intact. Integration API profile
selection is documented in `SERVICE_CLIENTS_AND_SCAN_PROFILES.md`.

Validation for named profiles: full backend suite with disposable PostgreSQL
848 tests (846 passed, 2 skipped), followed by 27 focused SQLite/PostgreSQL profile
checks including the added ICAP/default and unknown-adapter regressions; 7 browser
profile API tests; all 130 frontend tests; 6 related Edge client workflows.
Production build and contract drift check passed. Desktop/mobile screenshots were
visually inspected. Deployment-scale profile/engine inventory and lock-contention
acceptance remain open; these local tests did not change deployment support.

The original profile-routing migration below describes the earlier engine-only
slice; named-profile management supersedes its lock/schema/creation limitations.

Profile routing migration adds `/console/service-clients/{id}/profiles`, a scoped
GET `/api/ui/v1/service-clients/{client_id}/profiles` and PUT
`/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}/engines`. Reads use one
repeatable snapshot, PostgreSQL statement budgets, 20-profile ID-keyset pages,
100 engine choices and 100 assignments/profile with overflow sentinels. Only
identity/state metadata is projected; no profile policy JSON, credentials or engine
configuration. Incomplete assignments, missing choices and inventory overflow disable
saving. Managed compatibility profiles are read-only in the console.

Writes use pre-body admin/CSRF checks, strict unique nonempty IDs and the shared
`set_scan_profile_engines` transaction. All shared writers now serialize via a
PostgreSQL profile-row lock or SQLite BEGIN IMMEDIATE. Browser writes additionally
check client ownership, managed identity and equality of the expected previous
engine-ID set before changing anything. This fences changed selections, not a
monotonic revision of every intermediate edit. Engine existence is checked before
deletion; all assignment changes commit atomically. Selected engines are marked
required, matching legacy behavior. Existing scan snapshots, profile settings,
default state and intake disabled/source/quota filtering remain untouched.
The UI requires explicit confirmation and refresh after successful/uncertain writes,
with no automatic mutation retry. No schema migration is required; deployment-sized
read/lock-contention acceptance remains open. Profile creation/default changes are
not added by this slice.
Profile tests cover admin/pre-body CSRF, client/managed boundaries, strict unique
IDs, stale-selection rejection, missing engines without partial writes, immutable
scan snapshots, scoped pagination, policy omission and overflow protection.
PostgreSQL tests race two writers with the same expected selection and require
exactly one save and one stale rejection. React covers explicit instance payloads,
confirmation/cancellation, incomplete-list disabling and no automatic replay.
Edge verifies checkbox sizing, empty-selection blocking, persistence after reload,
analyst denial and mobile overflow; the mobile screenshot was visually inspected.

Next implementation: automation status/result JSON views and bulk-action parity, then the complete
UI inventory above. In parallel retain deployment-shaped PostgreSQL capacity,
production assets/proxy/TLS, remote contract CI and normalized policy projection
acceptance. Recursive batch actions require a separate protected design.
Remove HTML only after feature/permission parity.
Defender remains `lab`.


### Client creation and credentials

Admin `/console/service-clients/new` uses GET `/service-clients/create-options`
and POST `/service-clients` under `/api/ui/v1`. An explicit nonempty engine set,
client identity, default-profile name, credential label and administrator-supplied
token create one atomic bundle through the legacy database helper. Duplicate keys
or token hashes roll back the entire bundle. `legacy-default` is reserved.
Choices are capped at 100 with an overflow sentinel; incomplete lists cannot save.
Enabled/source/quota filtering at intake and accepted snapshots remain unchanged.

`/console/service-clients/{id}/credentials` uses scoped GET/POST `/credentials`
and POST `/credentials/{credential_id}/revoke`. Reads project only ID, bounded
label and timestamps, in 20-row ascending ID pages. They never select token hashes
or prefixes. An additive `(service_client_id, id)` index supports both active and
revoked pagination on SQLite/PostgreSQL. Revocation uses one client-and-credential
UPDATE predicate, rejects missing/already-revoked rows and preserves accepted scans.
All routes require admin sessions; writes enforce CSRF before parsing. The shared
legacy 32-512 non-whitespace token validator is reused. Stored hashes and the
legacy eight-character prefix remain compatible; neither appears in browser reads.

The password exists in its input until confirmation, then is cleared before the
request. It is never placed in React state, application browser storage, a query
or mutation cache, confirmation text or receipt. Cancellation clears it too.
Responses contain IDs only; audit context contains identity metadata, not secrets.
Writes are never automatically retried. After a successful/uncertain credential
write, require an explicit refresh before another action. After uncertain client
creation, reconcile the client inventory before attempting creation again.
TLS/proxy/CSRF and deployment-sized read/lock budgets remain acceptance gates.
The new startup index requires a normal deployment migration window; bounded
response size alone does not establish production-scale performance.


Credential acceptance (2026-09-17) covers pre-body role/CSRF denial, strict secret
validation, atomic bundle rollback on duplicate credentials, no secret response
fields, client-scoped pagination and revoke, plus real PostgreSQL rollback/types.
React checks cancellation, cleared passwords, empty mutation caches, explicit CSRF
payloads and uncertain failure without replay. Edge creates a client, adds a second
credential, revokes the first, reloads persisted state and denies analyst access.
The light-theme mobile screenshot was visually inspected. All tokens were synthetic;
only disposable test services were used. Contracts, production build and diff checks
passed. Existing staged files were preserved; this does not represent a deployment.


### Automation history listing

`/console/api-ledger` and GET `/api/ui/v1/api-ledger` preserve the legacy operator
visibility: signed-in analysts/admins can see API/ICAP history across clients.
This is not a service-client bearer endpoint, and a client filter is not an
operator authorization boundary. External integration API ownership checks and
manual browser report/source boundaries remain unchanged.

Reads select only API/ICAP non-child metadata, with 20-row default/100-row maximum
ID-descending keyset pages and a one-row continuation sentinel. Exact client ID,
unassigned ownership, source, status, recorded risk and literal filename/hash/case
search are supported. Unknown IDs produce no matches; invalid or contradictory
filters reject rather than widening scope. Client names reflect current metadata;
recorded IDs identify ownership. Names/filenames/case/hash projections are bounded.
No result blobs, profiles, credentials, historical totals or adapter calls occur.
Uncreated deferred intake is absent; stored risk/terminal state is not a clean or
coverage assertion. Read-only navigation never refreshes stored batch counters.

Additive partial `idx_scan_jobs_ledger_seek` and `idx_scan_jobs_ledger_client_seek`
indexes support global/client ID ordering on SQLite/PostgreSQL. PostgreSQL statement
budgets and custom plans remain enabled. Substring/combined filters can still scan
history: deployment-shaped scale and migration lock acceptance remain open.
The UI uses URL filters, explicit refresh and no polling/retry; read errors hide
previous rows. Reports and batches now open the React routes described below.
API payload views, bulk actions, totals and full legacy search parity
remain separate slices.


Ledger verification checks analyst/anonymous boundaries, API/ICAP versus manual/
child separation, exact and nonexistent client filters, unassigned ownership,
deleted cursors, strict filter validation, literal wildcard characters and bounded
metadata. SQLite proves listing works with the engine-results table removed;
PostgreSQL checks scoped keyset reads, projected values and both additive indexes.
React verifies inert rendering, filters across pages, legacy link targets and
hiding cached data on read failure. Edge covers real analyst browsing, ownership
filters, paging and mobile overflow/checkbox size; its mobile screenshot was
visually inspected. The initial ledger test used an over-specific label locator;
its role-based replacement passed on a targeted rerun. The other eighteen browser
workflows passed in the full run. Production-scale filter performance remains open.


### Automation reports, batches and single deletion

Separate `/api/ui/v1/api-ledger/scans/{id}`, per-result preview/full-output and
`/api/ui/v1/api-ledger/batches/{id}` reads admit analyst/admin sessions. Shared
readers use a server-selected API/ICAP scope; existing manual endpoints still
reject automation IDs. Result ownership is enforced by the scan/result join.
React query keys include scope to avoid sharing manual/automation cached reports.
Reports expose source and nullable client ID, never profile policies or storage
paths. Coverage and decisions reuse accepted routing plus backend assessment;
invalid/oversized policy input still suppresses a decision. Report and full-output
reads retain coherent snapshots, bounded engine sets and the 2 MiB output ceilings.

Automation batches retain `(created_at, id)` cursor pages and stored counters,
without hydrating blobs or updating counters on GET. Members must match batch
source and nullable client ownership, including nested records. Counts are stored
batch aggregates and may lag; they do not establish full extraction or coverage.
Shared React report/output/batch components now serve both source scopes. Ledger
links stay in React; oversized-output fallback remains explicit.

DELETE `/api/ui/v1/api-ledger/scans/{id}` requires admin, same-origin CSRF and strict
attempt/job-revision fields. The source-checked shared database deletion keeps its
row lock and active/child/shared-sample/undelivered-outbox guards. Cleanup follows
commit and failures are reported separately. The React management page confirms
the scan identity, never automatically retries, hides stale controls after an
uncertain outcome and requires a fresh read. Analysts see read-only management.
No retry, recursive batch deletion or bulk-delete endpoint is added here.
Automation full exports are covered by the following slice. External service-client bearer authorization/routing is unchanged.

Remaining parity includes legacy status/result JSON views and oversized-output access,
automation bulk actions, direct-child navigation, ledger totals/search differences,
and deployment-scale validation. Legacy HTML removal waits for this inventory,
permission/error-state parity, deep-link redirects and deployment acceptance;
remove UI-specific handlers/assets in reviewable commits while retaining shared
backend services and integration/worker API contracts.


Automation-detail acceptance verifies manual/automation endpoint isolation,
result ownership, policy suppression and oversized full output; batch client/source
filters, cursor validation and no counter writes; admin/pre-body CSRF, stale
attempt/job revision, active/child/shared-sample/outbox guards and post-commit
cleanup failure. PostgreSQL exercises nullable-owner batch reads and fenced
single deletion. React tests automation-specific routes, inert output, analyst
read-only management, confirmation, cleanup receipts and no uncertain replay.
Edge follows ledger -> report -> technical/full output -> batch -> report ->
management, signs in as admin, confirms deletion and verifies the record is gone.
The mobile confirmation screenshot was visually inspected. All data was disposable.


### Automation report exports

Analysts/admins can explicitly download summary/full JSON/CSV from automation
management. New GET `/api/ui/v1/api-ledger/scans/{id}/summary-export` and `/export`
routes reuse shared export builders with server-selected API/ICAP scope. Manual
endpoints still reject automation IDs and vice versa; service-client bearer API
contracts are unchanged. These are operator reports, not vendor-safe integration
status/result JSON previews. Those legacy views remain separately tracked.

Summary exports reuse bounded coherent reports, omit raw output/findings/children,
retain unavailable decisions and identify automation scope. Full JSON includes raw
engine output/details/findings; CSV keeps normalized operator rows and forces
untrusted strings to text. Both omit sample bytes and storage metadata. Full reads
preflight engine count and source bytes in the same snapshot before hydration,
then cap export content at 2 MiB after serialization. JSON envelope escaping adds
wire overhead; limits are not a total memory/concurrent download budget.
Invalid policy details suppress decisions. Full automation exports with neither
an accepted engine snapshot nor historical engine jobs return an explicit legacy
fallback, never invent historical coverage from current global/profile settings.

Downloads fetch fresh data only on click, do not poll or automatically retry,
retain no output in React state/query/mutation caches and revoke Blob URLs after
download initiation. Failures do not produce an empty or partial file. The UI
separates report exports from external API payloads. Deployment-scale export
memory/concurrency, HTTPS/proxy and remaining legacy parity gates stay open.


Export tests cover analyst/anonymous permissions, bidirectional manual/automation
source isolation, invalid formats, null decisions for invalid policy, no storage
metadata, source-byte and serialized-content ceilings, and explicit historical
routing fallback. PostgreSQL repeats scoped JSON/summary reads and source bounds.
React tests explicit routes, downloads without rendering raw content, and failure
without a partial file or replay. Edge downloads actual summary JSON, full CSV and
full JSON as an analyst and checks filenames/content before the existing deletion
workflow. Existing manual export regressions remain in the full suites.


### Single automation integration result preview

`/console/api-ledger/scans/{id}/result-json` now displays terminal API/ICAP result
JSON using the same public projection and scan-summary helper as the integration
API. The browser endpoint uses session authorization, not integration credentials;
embedded external API URLs are inert text and retain integration authentication.
The generated payload is validated against `ScanResultResponse` before delivery.
It omits private engine raw output/details/evidence and storage metadata.

Reads reuse export repeatable snapshots, PostgreSQL statement budgets, accepted
routing and engine/source preflight (256 engines, 2 MiB engine source). This is
conservative: large raw output can reject a preview even though that output is
omitted from the public projection. Missing historical routing, invalid policy or
nonterminal scans produce explicit errors. The complete serialized JSON envelope
is limited to 2 MiB. No polling, automatic retries or retained output cache;
refresh hides the previous JSON, including on failure. Global status queue counts
and batch payload traversal require separate bounded implementations and remain
pending, along with bulk actions, direct-child navigation and deployment load gates.


Result-preview validation (2026-09-18): 111 browser API tests and 89 frontend
tests passed; generated-contract drift check and production build passed. The
focused Edge automation workflow passed, including the new analyst JSON view and
existing full-output, batch, export and protected-deletion steps. Tests cover
manual/automation isolation, authentication, integration-model validation, private
field omission, nonterminal/invalid-policy errors, source/response ceilings,
missing routing, inert rendering, failed refresh and cache disposal. No new
PostgreSQL run was performed for this slice; shared read-budget/snapshot gates
and deployment acceptance remain required.

The complete SQLite/default Python run finished: 731 tests, 688 passed and 43
environment/platform-gated skips. PostgreSQL was not configured for this run.


### Single automation integration status preview

`/console/api-ledger/scans/{id}/status-json` adds analyst/admin status JSON for
active and terminal API/ICAP scans. It uses the public status builder and validates
`ScanStatusResponse`. Manual-source and bearer-token isolation remain unchanged.
The scan/results, accepted-instance eligibility, polling-policy override and queue
counts/position share one repeatable database snapshot. Existing queue helpers now
accept an optional caller connection; default callers keep their existing behavior.
PostgreSQL statement budgets apply to every database read. Global queue counters
scan all sources/history: bounded JSON is not a scale guarantee. Deployment-shaped
load and concurrency acceptance remain open; each statement, not the whole HTTP
request, has a database time budget.

The public `engines.expected` field follows current enabled/file/source-eligible
instances from the accepted snapshot, including metadata engines; it is distinct
from decision coverage based on recorded required names. Current profile edits or
unrelated new instances never replace accepted routing. Status preview requires an
explicit accepted engine list (maximum 256 entries); older records without it
return an explicit error even if a result export can use historical jobs.
Polling interval resolves the bounded override in the same snapshot via shared
policy rules. It is informational: the browser never automatically polls.

Status reuses conservative export admission (including raw source bytes even when
omitted), rejects invalid policy input and caps the complete JSON envelope at
2 MiB. Previous JSON is hidden during refresh/errors; separate status/result query
keys prevent cross-view reuse and output is discarded on exit. Embedded links and
JSON remain inert text. Batch status/result JSON, bulk actions and other parity
items remain separate work.


Status-preview validation (2026-09-21): full Python suite with disposable
PostgreSQL completed 735 tests (733 passed, 2 platform skips); 114 browser API
tests also passed independently. The PostgreSQL concurrency test changes the
scan through a second connection mid-read and verifies the old scan, global
counts and queue position remain coherent, with statement timeout configured.
The database was a dedicated temporary container on localhost:55439, never a
live MASP database. Frontend: 90 tests, contract drift check and production build
passed. Focused Edge automation workflow passed including analyst status/result
navigation, 390px overflow check, exports and protected deletion. Temporary
browser servers and the disposable database container were stopped afterwards.
Deployment-scale global-count load and other remaining acceptance gates are not
waived by these local checks.


### Automation batch integration JSON

React `/console/api-ledger/batches/{id}/status-json` and `/result-json` display the
public batch contracts through analyst/admin GET `/api/ui/v1/api-ledger/batches/{id}/json`.
The `kind` query selects status or result; integration bearer authentication is not
accepted on the browser API. Both shapes are validated against the public models,
use shared safe batch/scan projections and render as inert text. Embedded links
still require integration authentication. Refreshes hide earlier content, including
on failure, and queries neither poll nor retain output after navigation.

The reader admits at most 20 registered members in `(created_at, id)` order using
the existing batch index. It rejects inconsistent source/client ownership rather
than silently returning a partial complete-contract payload. Nullable ownership is
compared explicitly. Batch and all members share a repeatable snapshot with
PostgreSQL statement budgets. Stored counters are preserved, never refreshed by
GET, and may lag workers. Completion or an empty list does not prove clean coverage
or complete extraction. Status reads no engine blobs or routing snapshots.

Result requires a completed batch and terminal members. Before any engine hydration,
a batch-wide preflight limits results and jobs to 256 each and combined engine plus
routing-snapshot bytes to 2 MiB. Each member then uses the existing bounded export
reader in the same connection/snapshot, preserving historical routing and invalid
policy rejection. Public projection omits raw output, internal details/evidence,
storage metadata and operator errors. Both complete response envelopes are capped
at 2 MiB. Filename/path bounds reject rather than truncate contract values.
These are admission limits, not a total process memory or end-to-end time budget.

Oversized batches explicitly direct operators to paginated overviews and individual
reports. Full oversized-contract parity is still a cutover gate; the legacy route
cannot yet be removed. Remaining work groups: automation bulk/direct-child flows;
users/password/LDAP session parity; audit/About; manual/hash/System detail, print
and oversized-output parity; then full route/error/permission inventory, deployment
acceptance and removal of obsolete HTML rendering. Existing runtime/security gates
remain unchanged.


Batch JSON checks (2026-09-21): 92 frontend tests, production build, generated
contract drift check and focused Edge automation workflow passed. Edge opens both
batch contracts as an analyst at mobile width before the existing export/delete
flow. API regressions cover source/owner rejection, role/auth boundaries, public
contract validation, stored-count preservation, no status engine hydration,
active/invalid-policy rejection, member and aggregate source admission, and
serialized response limits. Frontend checks inert content, failed refresh and
output disposal for both kinds. PostgreSQL adds a concurrent membership/status
change between preflight and hydration to verify the original snapshot survives.

Full Python suite with disposable PostgreSQL: 739 tests, 737 passed and 2
platform skips. Temporary database and browser servers were stopped after testing.
Live MASP data was not used; deployment acceptance remains open.


### Automation archive navigation

`/console/api-ledger/scans/{id}/children` now uses the shared archive reader and
React page through a separate analyst/admin browser route. Manual routes remain
manual. Parent reads accept API/ICAP only and validate an attached batch's exact
source and nullable client ownership. Direct children and nested-presence probes
must match the parent's source, client, batch and child role; unrelated/corrupt
cross-boundary records are omitted from navigation. Upward links are suppressed
unless the ancestor matches these source/owner/batch boundaries. No bearer-client
access is introduced; browser operator authorization is unchanged.

Pages retain 20 default / 100 maximum rows, ID-keyset continuation and the displayed
parent attempt for later pages. Literal path filters and active/status filters use
the existing shared logic. Reads use one repeatable snapshot, transaction-local
PostgreSQL budgets/custom plans and bounded per-page parent-index probes. They do
not hydrate engine output, run extraction or refresh batch counters. Active first
pages poll at the existing three-second interval; later pages pause, and no
background-tab interval is enabled. Empty/zero-risk/completed lists still do not
prove clean coverage or complete extraction; earlier children can survive retries.

React report, child, nested, upward and batch links stay in automation routes.
Manual/automation queries have separate keys and failed refreshes hide stale
content. No recursive deletion or new engine behavior is included. Automation
bulk actions, oversized output parity, other inventory screens and deployment
load/cutover gates remain open.


Automation archive validation (2026-09-21): 9 focused archive API tests passed,
including existing manual cases. New cases cover exact source/client/batch filters,
nullable ownership, nested-presence exclusion, upward-link suppression, literal
search and attempt-fenced continuation. PostgreSQL adds a concurrent source change
between child listing and nested probing to verify repeatable-snapshot behavior.
Frontend: 93 tests, production build and generated-contract check passed. The
focused Edge automation workflow navigated report -> children -> nested children
-> up one level -> batch, with mobile overflow validation, then completed the
existing export/deletion path. Engine output is never loaded; stored batch counters are neither loaded nor
mutated by child navigation reads (only batch identity/ownership and archive mode
participate).
Deployment-shaped archive read/polling load remains an acceptance gate.

Full Python run with disposable PostgreSQL: 742 tests, 740 passed and 2 platform
skips. Temporary database and browser servers stopped; live MASP data was not used.


### Automation ledger bulk deletion

Admins can select up to 20 visible API/ICAP ledger records, review their IDs in a
confirmation dialog and submit one DELETE `/api/ui/v1/api-ledger/scans` request.
Analysts remain read-only. Strict JSON, pre-body session/admin/CSRF checks and the
existing 128 KiB browser cap apply. Duplicate IDs, empty/oversized lists and invalid
fences are rejected before any deletion. The browser freezes the displayed
attempt/job-revision values at confirmation; changing filters clears selection.

Ledger metadata now includes attempt count and maximum engine-job ID in its single
read statement, retaining source/owner filters, bounded pages and PostgreSQL budgets.
No engine output is read. The extra indexed revision probes still require
production-shaped read-load acceptance. Backend scope is fixed to API/ICAP and
standalone/container roles; manual and child IDs cannot use this deletion route.
Each record uses the shared row lock and attempt/revision checks, plus active,
registered-child, shared-sample and undelivered-outbox guards. Records commit
independently; filesystem cleanup follows commit. Receipts list deleted, blocked
and cleanup-failed IDs separately. Manual bulk semantics remain unchanged.

The UI never automatically retries a write. After success or failure it hides
old rows, clears selection and requires an explicit successful refresh before
reselection. An uncertain response warns that some deletions may have completed.
No optimistic deletion, recursive batch deletion or automatic replay is introduced.
Existing size/load and security gates remain open. Users/account is implemented
below; audit/information and the remaining parity/cutover inventory are next.


Ledger bulk-delete validation (2026-09-21): full Python suite with disposable
PostgreSQL ran 745 tests (743 passed, 2 platform skips). New cases exercise
pre-body admin/CSRF checks, duplicate/size/strict-type admission, manual/child
exclusion, active/parent/stale fences, metadata-only revision reads and explicit
cleanup failures. PostgreSQL verifies a stale row remains while another record
commits deletion. Existing shared-sample/outbox/manual regressions remain in the
full suite. Frontend: 96 tests, production build and contract drift check passed.
The focused Edge test selects an ICAP leaf and API parent, confirms at mobile
width, verifies separate deleted/blocked IDs and refreshes to confirm actual state.
Component tests verify readonly analysts, displayed fence/CSRF submission and no
write replay or reselection before refresh after both success and uncertain failure.
Temporary test servers/database were stopped; no live MASP data was used. Ledger
revision-probe load remains a deployment-shaped acceptance gate.


### User inventory and local creation

Admin `/console/users` now lists local and LDAP identity metadata in 20-row ID-keyset
pages. GET `/api/ui/v1/users` projects bounded names, role, authentication source and
recorded timestamps under PostgreSQL read budgets. The list query never selects
password hashes, external directory IDs or session tokens; it performs no directory
probe or aggregate count. Username truncation is explicit. The existing legacy
username identity/uniqueness semantics are retained.

POST `/api/ui/v1/users` requires session admin authorization and CSRF before parsing,
strict fields, explicit admin/analyst role, a nonblank trimmed username up to 128
characters and an initial password of 8 to 4096 characters. Passwords use SecretStr
request fields and the shared hash/database creation path. Database uniqueness
settles duplicate/concurrent requests without modifying an existing account.
Audit details contain identity/role, never password material. New accounts are
local; callers cannot create or modify LDAP identities through extra fields.

The browser confirms public username/role while the password remains only in its
uncontrolled input until submission. Cancellation and send clear the input. Direct
transport avoids React/query/mutation secret retention. No automatic write retry
or success inference follows an uncertain response; creation stays disabled until
an explicit successful list refresh. Failed reads hide cached list content.

Own-password and administrative management are covered below. Legacy removal
remains gated by the full inventory and deployment/security acceptance.

User inventory/creation validation (2026-09-21): full Python suite with disposable
PostgreSQL ran 749 tests (747 passed, 2 skipped), including concurrent duplicate
creation, pre-body admin/CSRF checks, strict validation, secret omission, keyset
paging and login with the created local account. Frontend: 99 tests, production
build and contract drift check passed. The focused Edge test verifies confirmed
creation at mobile width, password clearing, explicit refresh, new-account login
and denial of administrator access to an analyst. Component tests cover cancelled
confirmation and successful/uncertain writes without automatic replay or secret
retention in query/mutation caches. Temporary test servers/database were stopped;
no live MASP data was used. Deployment-shaped acceptance gates remain open.


### Own-account password management

`/console/account` exposes only the session user's bounded identity metadata.
Local analysts and admins can confirm a password change through the exact
`POST /api/ui/v1/account/password` route. Authentication and CSRF precede body
parsing; strict SecretStr fields cap all passwords at 4096 characters, require
at least eight for the new password, reject mismatch/reuse and never echo input.
LDAP identities get directory guidance with no local password form. No caller
can supply a different user ID or role.

Legacy `/account/password` and React share the same validator and writer. The
writer updates only the password matching the verified prior hash and local
source, then deletes that user's sessions in the same transaction. This preserves
concurrent role edits, rejects a stale change after another change/reset and rolls
back the password if revocation fails. Legacy administrative password replacement
also now revokes sessions inside its update transaction. Local login locks the
user row (SQLite write transaction / PostgreSQL FOR UPDATE), rechecks the verified
hash and creates the session before releasing that lock. A login ordered before
a password change is revoked; one verified against an old hash but ordered after
it is rejected. Already-authorized in-flight requests are not cancelled.

Startup adds `idx_auth_sessions_user` without rewriting existing account/session
records. Password changes use the existing PostgreSQL UI write-lock budget; index
creation and login/revocation under deployment-sized session inventories still
require deployment acceptance. The later administrative-management slice also
adds the revision column described below.

The form keeps passwords in uncontrolled inputs until direct submission, with no
React/query/mutation cache storage. Cancel/send clears every password input.
Confirmation contains no secrets. Success clears private console queries and
returns to sign-in; interrupted/error responses never trigger automatic replay.
An explicit session check is required before another attempt. Administrative
role editing/reset/deletion now use the shared writer described below. Remaining
security, fleet/SCM, TLS and performance gates are unchanged.

Own-account validation (2026-09-22): full Python suite with disposable PostgreSQL
ran 766 tests (764 passed, 2 skipped). SQLite/PostgreSQL tests cover competing
password changes, login/revocation serialization, rejection of previously verified
old credentials, rollback on revocation failure, role preservation and in-place
session-index upgrades. PostgreSQL also verifies lock-budget rollback. Browser API
tests cover pre-body authorization/CSRF, strict secret validation, LDAP denial,
cookie clearing and all-session revocation; legacy own-password uses the same
writer. Frontend: 104 tests, production build and contract drift check passed.
The focused Edge test checks cancellation/mobile layout, two distinct sessions
revoked by one change, rejection of the old password and successful new-password
login. Temporary test servers/database were stopped; live MASP data was not used.


### Administrative user editing, reset and removal

Admin `/console/users` now confirms role changes, optional password replacement
and account removal for a selected non-self row. PUT/DELETE `/api/ui/v1/users/{id}`
require admin/CSRF before parsing, strict JSON and the displayed management revision.
Optional passwords use bounded SecretStr fields; omission/null keeps the password.
The browser keeps the password in an uncontrolled input until direct submission,
never a query/mutation cache. Cancel/send clears it. Outcomes hide old rows and
require an explicit successful refresh before another action; uncertain responses
are not replayed. Account IDs remain visible when usernames are truncated.

The shared `user_admin.manage` writer also serves legacy edit/delete routes. It
serializes administrative updates with a transaction-level PostgreSQL advisory
lock or SQLite BEGIN IMMEDIATE, locks actor/target rows in ID order, rechecks the
actor's current administrator role and protects the last local administrator.
Self-edit/delete is rejected. Browser revision mismatch returns 409; legacy forms
retain their existing last-save behavior but cannot bypass shared permission and
last-admin guards. Password replacements and session deletion commit together;
role-only changes preserve sessions whose authorization reads the current role.
User removal uses the existing session FK cascade. Existing in-flight requests
are not cancelled. The PostgreSQL UI lock budget also covers the admin mutex.

Directory roles/passwords cannot be edited here. Existing legacy parity permits
removing a local directory shadow; both review and confirmation explain that the
directory account remains enabled and a later LDAP sign-in can recreate the row.
This operation is not a directory credential revocation.

Startup adds `users.management_revision BIGINT NOT NULL DEFAULT 0` in place.
Administrative writes, own-password changes, low-level compatibility updates and
LDAP synchronization advance it. No password hash is exposed as a revision token.
Deploy all app processes together; old binaries do not participate in these guards.
Migration lock time and production-shaped user/session load remain acceptance
items. Full legacy removal, large-output parity, worker SCM, TLS and other security
and performance gates remain open. Next screen group: audit history and About,
implemented in the section at the end of this document.

Administrative-management validation (2026-09-22): full Python suite with disposable
PostgreSQL ran 784 tests (782 passed, 2 skipped). New checks cover concurrent last
local-admin removal, reciprocal demotion with actor-role rechecks, revision conflicts
after own-password changes, reset/revocation rollback, session cascade, LDAP shadow
removal, shared legacy guards, lock-budget rejection and in-place revision upgrade.
The pre-existing PostgreSQL user-count helper's dict-row access was corrected.
Frontend: 108 tests, production build and contract drift check passed. Focused Edge
acceptance changes a role, resets a password, confirms prior-session revocation,
signs in with the replacement, removes the account and verifies session revocation
again; the confirmation fits a mobile viewport. Component tests cover revision/CSRF
submission, secret omission from caches, LDAP confirmation and no uncertain-write
replay. Test servers and disposable PostgreSQL were stopped; live MASP data was not
used. See `docs/SESSION_HANDOFF.md` for fresh-session continuation.

### Audit history and About

Admin `/console/audit` reads the append-only `audit_events` trail through
GET `/api/ui/v1/audit` with bounded descending ID-keyset pages of at most 100
records (the console requests 20), exact outcome selection and literal actor/
action/target/request-ID search. The route is admin-only before any parsing and
the router exposes no audit write verb, matching the data layer's insert/read-only
contract: the console cannot edit or delete an event. Reads apply the shared
PostgreSQL statement budget and custom plans. A partial `(outcome, id DESC)` seek
index is added in place alongside the existing created/action indexes.

No total is calculated. Counting a full institutional trail is unbounded
administrative work, and the bounded page is the record an operator acts on;
newer events can arrive while older pages are read. Search escapes `%` and `_`
so an operator character matches itself — the legacy page passed the raw term to
`LIKE`, which silently widened the filter instead of matching. Projected columns
are length-capped and `details_json` is bounded to 4096 characters with an
explicit truncation flag; details are rendered as inert text, never markup or
policy input. Recorded details already pass the write-time redactor, so this is a
display bound, not the privacy control.

The trail deliberately excludes routine navigation, scan and hash submission,
polling, report/export reads, health checks and metrics scrapes, and events are
appended after the handled operation on a best-effort basis. The console states
both limits: an absent record does not prove an action did not happen, and the
source IP is the direct socket peer, not a forwarded client address. Audit
retention, export and legal hold remain institutional decisions with no
application control; see `docs/security/AUDIT_TRAIL.md`.

`/console/about` is readable by analysts and admins through GET
`/api/ui/v1/about`, the only non-dashboard browser read outside the admin gate in
this slice. It returns product boundary text plus a non-sensitive runtime
snapshot: application version, queue model, worker transport, directory-login and
secret-encryption availability, enabled engine count with at most five display
names and a truncation flag, hash-engine count, and registered/schedulable worker
nodes. The service-client total is admin-only and is `null` for analysts rather
than omitted, so the contract stays stable. Deployment hosts, filesystem paths,
adapter keys, engine configuration and secrets never appear.

About reads two small configuration tables (`worker_nodes`, `service_clients`)
under the shared read budget and never aggregates scan history, so it needs no
cache; the payload states when it was read. Enabled engines and schedulable nodes
are configuration state and do not prove a scan will reach complete coverage. The
application version is now the single `app.APP_VERSION` constant that also titles
the FastAPI application.

Audit/About validation (2026-09-22): full Python suite with disposable PostgreSQL
ran 793 tests (791 passed, 2 skipped). New SQLite checks cover admin-only access,
absent write verbs, cursor/limit/outcome/search validation, descending keyset
paging, literal search, outcome filtering, detail bounding, analyst-readable About
and admin-scoped client counts. A new PostgreSQL-gated class exercises both readers
on real PostgreSQL, where `LENGTH(...) > n` returns a boolean rather than 0/1 and
`SUBSTR` over NULL columns must stay null. Frontend: 114 tests, production build
and contract drift check passed. Focused Edge acceptance pages the trail, applies
a literal `%` search and an outcome filter, opens inert details, refuses an analyst
session and checks admin-scoped About content at a mobile viewport. A pre-existing
`ByRoleOptions`/`exact` type error in the user-management test was corrected; it
was failing `tsc --noEmit` at the previous checkpoint. Test servers and disposable
PostgreSQL were stopped; live MASP data and containers were not used.

Remaining in this group: legacy audit detail/printable parity, deployment-shaped
trail volume validation (this is the largest append-only table in a long-running
deployment) and About metric parity are cutover gates. Next: remaining manual,
hash, System and oversized-output parity, then the final cutover inventory.

### Printable report and oversized engine output

`/console/scans/{id}/print` and `/console/api-ledger/scans/{id}/print` render a
print-oriented view for analysts and admins. The reader reuses the existing
full-export snapshot loader and the shared report payload builder, so the printed
decision, coverage, findings and engine rows come from one repeatable read and the
same backend helpers as the report and exports; React calculates no decision.

Two legacy defects are closed rather than reproduced. Legacy `/scans/{id}/report`
applied **no source scope**: a manual URL rendered an API or ICAP scan to any
signed-in user. The browser routes use the server-selected scope, so each route
refuses the other history with 404. Legacy also embedded **every engine's raw
output with no ceiling**, so one verbose result produced an unbounded page. Each
engine preview is now capped at 8 KiB with an explicit truncation flag, findings
are capped at 200 rows, and the serialized response keeps the shared 2 MiB
ceiling. Printing is invoked only by the operator; nothing prints automatically.
Print styling hides console chrome and expands output blocks for paper.

`GET /api/ui/v1/scans/{id}/results/{result_id}/output` (and its automation twin)
serves one engine's recorded raw output as `text/plain` with an attachment
disposition. This replaces the "use the legacy report" dead end that the 2 MiB
JSON reader produced: JSON escaping of scanner output can multiply its size and
React would hold the whole string, while plain text has neither cost and is
streamed by the browser without entering React state, the query cache or the
typed JSON contract. The filename is built only from validated integers, so no
sample or engine name reaches the `Content-Disposition` header.

The download is still explicitly bounded, unlike legacy. `MASP_UI_RAW_OUTPUT_LIMIT`
sets the byte ceiling, defaulting to 32 MiB, clamped to 256 MiB and never below
the 2 MiB JSON ceiling this path exists to exceed; an invalid value falls back to
the default. Source scope, result ownership and the shared PostgreSQL read budget
apply as they do to every other result read.

Printable/oversized validation (2026-09-22): full Python suite with disposable
PostgreSQL ran 798 tests (796 passed, 2 skipped). New checks cover analyst access,
both source-scope refusals, absent write verbs, per-engine output bounding,
storage-metadata omission, decision suppression on invalid policy, a download that
serves output the JSON reader refuses, cross-scan and cross-source refusal, and
the configured-limit clamps. Frontend: 119 tests; 28 Edge workflows including a new
printable/download scenario that checks inert output, the mobile viewport, print
media and the served plain-text response. Production build and contract drift check
passed. The console fixture's engine output was widened to exercise the new bound,
so two existing report assertions moved from exact-match to containment.

Remaining here: legacy manual filter parity, oversized complete integration
payloads, and deployment-shaped validation of very large recorded outputs. Legacy
`/scans/{id}/report` can be retired with the rest of the HTML rendering at cutover.

With this slice every legacy HTML route has a React equivalent, so no screen is
missing. What remains before legacy removal is parity of behaviour inside those
screens, the cutover inventory and the deployment gates, not new pages.

### Complete integration batch contracts

`GET /api/ui/v1/api-ledger/batches/{batch_id}/download?kind=status|result` serves
the complete public batch contract as a downloadable JSON document for analysts
and admins. It closes the last gap in the oversized family.

The inline `/json` preview stops at 20 members, 256 results/jobs and 2 MiB
because React renders and holds it. The integration API
`/api/v1/batches/{id}/result` serves up to 5000 members with no byte ceiling, so
before this the console could not show what any larger batch actually returned
and the refusal pointed at the paginated overview instead of the contract. The
download uses the same member cap as that API, so it refuses only what an
integration could not have received either; the inline refusals now name the
download rather than a dead end.

Both paths share one loader, parameterized by member and byte limits, so the
ownership, source-consistency, terminal-state, policy-validity and public-contract
validation are identical. The whole document is validated against
`BatchStatusResponse`/`BatchResultResponse` before any of it is served: an invalid
member fails the request explicitly rather than producing a partial contract. The
attachment never enters React state, the query cache or the typed JSON envelope,
and its filename is built from validated integers and a literal kind only.

`MASP_UI_BATCH_DOWNLOAD_LIMIT` bounds the aggregate engine/source bytes and the
serialized document, defaulting to 64 MiB, clamped to 512 MiB and never below the
2 MiB inline ceiling it exists to exceed; an invalid value falls back to the
default. Unlike the plain-text output download, this document is assembled in
memory from every member, which is the memory profile the integration API already
has for the same batch — but it is now reachable by an operator, so size it in
deployment accordingly.

The contract test's download allowlist now records the exact success content each
untyped route may declare, covering both plain-text output routes and this JSON
document, so a new untyped route cannot appear unnoticed. Errors remain typed
`ErrorPayload` JSON on all of them.

Integration-contract validation (2026-09-22): full Python suite with disposable
PostgreSQL ran 801 tests (799 passed, 2 skipped). New checks cover a 21-member
batch the inline view refuses and the download serves, source scope and kind
validation, absent write verbs, explicit failure when a member cannot satisfy the
contract, and the configured-limit clamps. Frontend: 119 tests; 28 Edge workflows,
with the automation batch scenario extended to fetch and inspect the served
document. Production build and contract drift check passed.

Remaining in this group: final legacy-action parity. Deployment-shaped validation
of very large batches and outputs stays a cutover gate.

### Institution hash list

Admin `/console/engines/hash-list` manages the single institution-wide SHA-256
list that the built-in Hash List engine checks. It has no legacy equivalent. GET
`/api/ui/v1/hash-list` returns 20-row descending ID-keyset pages (at most 100)
filtered by list and a literal query; a full digest is an exact match on the
unique index, shorter text matches a hash prefix or a note substring with `%` and
`_` escaped. Block/allow counts are returned on the first page only, because
counting is a full scan of the list. Reads use the shared PostgreSQL budget.

POST `/api/ui/v1/hash-list` takes an explicit list, 1 to 1000 digests and one
optional note of at most 256 characters. Every digest is validated before one
transactional insert, so a malformed entry rejects the whole request. A digest
already on either list is left unchanged and reported with the list it is on:
silently moving a blocked hash to the allowlist is the edit this must never make.
DELETE `/api/ui/v1/hash-list/{entry_id}` removes one entry; entries are otherwise
immutable. Both writes are admin/CSRF-checked, audited (`hash_list.add`,
`hash_list.remove`), confirmed in a dialog and never automatically replayed.

The page states the semantics next to the controls: a blocklist match is a
detection, an allowlist match never suppresses another engine or produces an
allow decision, an unlisted hash proves nothing, and changes apply only to engine
jobs that run afterwards. It warns when no enabled Hash List engine exists, since
entries are then stored but checked by nothing.

Hash list validation (2026-09-23): full Python suite with disposable PostgreSQL
ran 937 tests (935 passed, 2 skipped), including PostgreSQL variants of the
adapter, storage and admin-read tests. Frontend: 142 tests; 34 Edge workflows,
with a new scenario covering explicit-list addition, the already-listed report,
confirmed removal, phone-width layout and the engine-readiness warning clearing
once a Hash List engine is created from the Engines page. Production build and
contract drift check passed.

### Deferred intake

Admin `/console/system/intake` reads GET `/api/ui/v1/system/intake` in one
budgeted snapshot: the manifest worker's last recorded cycle, deferred queue
counts with the oldest waiting age, the newest 50 manifest rejections with their
total, and the newest 20 submissions that failed permanently before becoming
scans. The route has no write verb and the page never polls. A missing worker
record reads as "no cycle recorded", an unreadable one as invalid, and a cycle
older than four poll intervals as stale, so a stopped worker is never shown as
healthy. Absolute paths in stored error text are replaced with `<path>` on write
and again on read. See `SERVICE_CLIENTS_AND_SCAN_PROFILES.md` for the contract.

Validation (2026-09-23): full Python suite with disposable PostgreSQL ran 956
tests (954 passed, 2 skipped), including PostgreSQL variants of the intake
reader. Frontend: 149 tests; 35 Edge workflows, with a new scenario covering a
stopped worker, backlog, rejection and pre-scan failure with every seeded path
redacted, phone-width layout and analyst refusal. Build and contract drift
check passed.

### Legacy parity sweep

Before retiring the server-rendered UI, each remaining legacy feature was
compared with its console screen.

- Dashboard: the legacy verdict filter loaded every manual scan and all of its
  results into memory. The console now offers `detection=detected|undetected`
  on GET `/api/ui/v1/dashboard/scans`, answered by one indexed `EXISTS` probe
  on recorded engine results per candidate row, and `metadata_only` joins the
  recorded-risk options. "Undetected" means a finished scan with no recorded
  detection; it is not coverage or a clean verdict, and active scans never match.
  The default query still never touches `engine_results`.
- Hash lookup: each engine row adds a provider status restricted to known values
  (anything else becomes `other`), verdict counts, last analysis date, cache
  source, duration and an HTTPS-only report link, plus the legacy operator
  guidance derived from the decision. Free-text provider reasons remain
  omitted, as the existing contract required, because adapter text can carry
  deployment details.
- System: historical engine metrics carry the legacy last-result time.
- Audit: complete JSON details are indented with sorted keys; truncated or
  non-JSON details are shown exactly as recorded.
- About already matched the legacy metrics.

Parity validation (2026-09-23): full Python suite with disposable PostgreSQL
ran 958 tests (956 passed, 2 skipped). Frontend: 150 tests, 35 Edge workflows,
build and contract drift check.

### Legacy UI retirement

With parity closed and the console served from the application image, the
server-rendered UI was removed. `app/main.py` went from about 9100 lines to about
1000: it keeps the integration API (`/api/v1/*`), `/health`, `/metrics`, the
audit middleware and startup, and nothing that renders HTML. `app/static` and the
root Tailwind build are gone; the root `package.json` keeps only `cloc`.

Every former GET page redirects (301) to its console screen: `/` to the Dashboard,
`/login` to `/console/`, and `/engines`, `/system`, `/users`, `/service-clients`,
`/audit`, `/account`, `/about`, `/hash-scan`, `/scan-policy`, `/api-ledger` and
`/scans/new` to their counterparts. `/batches/{id}`, `/api-ledger/batches/{id}` and
the ledger status/result views map to their console routes. Legacy `/scans/{id}`
served every source while the console separates manual and automation reports, so
that redirect (302) looks up the scan's source only for a signed-in operator;
anonymous requests go to the manual route without a lookup, so an ID cannot be
probed for its source. `/report` maps to the printable report and the old export
paths to scan management. Legacy form POSTs answer 404/405, and the audit policy
no longer lists their paths.

The login page used to announce directory sign-in; the console now reads that
from the unauthenticated GET `/api/ui/v1/session/options`, which returns only that
flag. The development login hint (`MASP_SHOW_DEV_LOGIN_HINTS`) had no console
equivalent and was removed.

Console messages that once sent operators to a legacy page now name a real
alternative or state the limit: oversized engine output points to the raw output
download, oversized full exports to individual engine outputs, and historical
automation scans without routing snapshots state that no full export exists
rather than reconstructing coverage from today's configuration. Editors that
refuse incomplete or oversized metadata say so instead of pointing elsewhere.

Tests that only rendered legacy HTML were removed; tests of service logic they
contained were kept or moved to the service they exercise, and the VirusTotal
missing-encryption-key refusal is now covered through the console API.

Cutover validation (2026-09-24): full Python suite with disposable PostgreSQL ran
911 tests (909 passed, 2 skipped); the count fell because legacy HTML tests were
removed. Frontend: 150 tests; 35 Edge workflows, with the report scenario now
asserting that no legacy link remains. Build and contract drift check passed.
The application image was rebuilt and smoke-tested: `/health` 200,
`/console/dashboard` 200, `/` 301 to the console Dashboard.

### System navigation

Every System screen (Overview, Worker nodes, Worker pools, Runtime and queue,
Retention, Deferred intake, Engines, Hash list) renders inside one admin-only
layout route, `SystemLayout` in `components/section-tabs.tsx`. It draws the tab
strip once and gives the pages their own `Suspense`, so switching tabs no longer
redraws the strip at each page's heading height or hides it while a page chunk
loads. Engines is reached only through System: the sidebar has no separate entry
and keeps System highlighted on `/engines` screens. An Edge workflow asserts the
strip keeps the same position on every tab.

### Entity lists and page selection

Lists of people and machines no longer render as stacks of large cards. Users,
worker nodes and worker pools use one compact row pattern (`.entity-list`,
`.entity-row`, `.tag` in `styles.css`): an avatar or icon, name and secondary
line, a few facts such as last login or heartbeat age, and status tags. A row
opens a dialog with the full details and every control, so creation and edit
forms appear only when asked for ("New local user", "New pool"). Confirmation
steps, password clearing, stale-state fences and no-replay behaviour are
unchanged. Audit events are a compact table with expandable details.

Dashboard and API ledger add a header checkbox that selects every deletable
scan on the current page (active scans excluded, capped at the 20-row bulk
limit), clears them when all are selected and shows a mixed state for a
partial selection. It never reaches beyond the visible page.

Validation: 152 frontend tests, 36 Edge workflows, build and contract check.
