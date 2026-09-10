# Independent browser console: incremental migration

## Current scope

The independent React/TypeScript/Vite application in `frontend/` serves
`/console/dashboard`, `/console/engines`, `/console/scans/new` and manual
`/console/scans/{id}` reports with `/console/scans/{id}/children` archive navigation,
`/console/batches/{id}` manual batch overviews and `/console/scans/{id}/manage`
summary/full exports and single-scan management.
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
sessions may read it. Manual sample submission now stays in the console and
returns a visible acceptance receipt. Dashboard and receipt links now open the
React report, showing backend decisions, required coverage and on-demand technical
previews. Submission API `report_url`/Location still retain their legacy URLs for
compatibility; the console constructs its own internal route from the scan ID.

This is **not the whole frontend migration**. Bulk actions, detection-verdict
filters, worker detail, full-output views, bulk actions, System,
users and policies still use legacy HTML. `/` and `/engines` remain available.
Integration URLs, worker control, queue behavior and snapshots are unchanged.
Node is required for building/development, not for serving static production files.

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
| `/dashboard/summary` | GET | Manual/non-child totals, 30-second server cache |
| `/dashboard/scans` | GET | Bounded manual history previews, ID-keyset pagination |
| `/scans/options` | GET | Current file/body limits and eligible enabled engine count |
| `/scans` | POST multipart | Store one manual sample and enqueue; JSON `202` receipt |
| `/scans/{id}` | GET | Manual report, backend decision and required-engine coverage |
| `/scans/{id}/results/{result_id}` | GET | On-demand bounded technical text previews |
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

Engine routes require admin browser sessions, not service-client bearer tokens.
The exact Dashboard/options/manual-report/children/batch/summary/full-export GET routes, manual submission and retry POST routes are additionally
allowed for analysts; this does not widen engine-management permissions or expose
automation history. Service-client tokens are not browser credentials.
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
coverage is available in the console report. This intentional history preview is not legacy
Dashboard parity and cannot replace its decision/coverage or bulk-action UI yet.

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

### Summary/full exports and single-scan management

The report links to `/console/scans/{id}/manage`. Analysts and admins can download
summary or full JSON/CSV exports and confirm retry; only admins see and may invoke deletion.
The management screen refreshes on entry, focus or explicit action, without an
interval. Server-side mutation checks remain authoritative when the page is stale.
Legacy links preserve the full-output view. This slice does
not provide recursive batch deletion or bulk actions.

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
The full-output view still uses the legacy UI. Single-scan summary/full exports
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

Verified on 2026-09-10 after PostgreSQL browser acceptance: the full Python suite
ran 670 tests (668 passed, two platform-gated skips) with the disposable database,
including 63 browser API and five contract tests. All 42 frontend tests, three
generator tests and six
real Edge workflows passed. Both contract drift checks and compile-time negative
assertions passed. Remote Windows/Linux CI has been configured but not executed.
TypeScript/production build and `git diff --check` passed. SQLite WAL retry-race tests
proved coherent report and parent/child snapshots followed by the new attempt
on the next read. SQLite batch snapshot/index checks and PostgreSQL
report/archive/batch consistency, migration, queue
concurrency and browser statement/row-lock budget tests passed against a
disposable PostgreSQL 16 container. Initial JavaScript including its shared UI dependency is
about 97.85 kB gzip; lazy batch overview is 2.09 kB, submission 2.21 kB, archive
navigation 2.26 kB, report 2.47 kB, Dashboard 2.51 kB, management 2.55 kB,
Engines 4.87 kB, shared dialog 12.82 kB, shared mutation code 0.96 kB and search
icon 0.30 kB gzip, excluding CSS (about 4.81 kB gzip). Shared dialog code loads
with either management or Engines.
These are build sizes, not measured user latency. The new exact nginx upload
location is configured but real nginx/TLS upload execution remains a gate.
Docker image execution/TLS and deployment-shaped PostgreSQL validation were not
performed in this slice. Test services used disposable data; no existing MASP configuration was
changed by the browser acceptance test. Changes remain uncommitted.

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
receipt/history and mobile overflow. Submission tests cover pre-body
auth/CSRF, streamed/declaration limits, duplicate/unknown/excess parts, field
limits, file-policy rejection, no-engine/transaction cleanup and archive intake.
Backend tests cover manual scope, literal SQL search, invalid limits, payload
projection, seek index use/upgrade, concurrent aggregate caching and deleted
cursors. The additional PostgreSQL read-model test passed in the disposable run.
This does not prove real Defender execution, deployment PostgreSQL capacity or
nginx/TLS behavior.

Local disposable SQLite benchmark, 100,000 synthetic manual scans, seven
iterations, median service-call time including connection: latest 20 previews
1.922 ms; 90%-deep keyset page 1.658 ms; no-match substring search 371.406 ms;
uncached summary 104.260 ms; cached summary 0.001 ms. A page was 5,088 JSON bytes.
This is one development-host run with synthetic small rows and warm OS cache,
not HTTP/browser latency, a concurrency benchmark or a PostgreSQL capacity claim.
The benchmark never opens deployed data or starts workers.

Local disposable PostgreSQL 16 benchmark, 100,000 synthetic Dashboard rows plus
100,000 direct archive children, 15 measured iterations and eight-way mixed
reads rotating Dashboard, search and batch requests: latest-page p95 14.160 ms;
90%-deep Dashboard keyset 4.837 ms; no-match Dashboard substring 175.564 ms;
uncached summary 24.268 ms; deep archive page 11.391 ms; no-match archive
substring 87.914 ms; deep batch keyset page 6.639 ms; report 11.266 ms; JSON
summary export 9.009 ms; full JSON export 11.862 ms; mixed-read p95 310.289 ms.
Every checked default budget passed. The archive child-presence plan used
`idx_scan_jobs_parent`; the batch page used `idx_scan_jobs_batch_created`. This
was a loopback, warm-cache synthetic run without HTTP/TLS/proxy latency or worker
writes.

Next: deployment-shaped PostgreSQL capacity acceptance, production assets/proxy/TLS
validation, remote contract CI acceptance, normalized policy read projections,
bulk result management, recursive batch actions and remaining management screens.
Remove HTML only after feature/permission parity.
Defender remains `lab`.
