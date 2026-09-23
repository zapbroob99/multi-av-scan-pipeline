# MASP Engine Support Matrix

This matrix tracks engine integrations by product and integration method. A vendor name alone is not a supported integration. Each row must identify the product and how MASP talks to it.

Support states:

- `supported`: Implemented, documented, and tested with fixtures or lab access.
- `lab`: Implemented against a real product but still under validation.
- `planned`: Selected for future work; no production claim.
- `research`: Documentation is being reviewed.
- `blocked`: Waiting on license, product access, docs, or sample responses.
- `not_supported`: Known unsuitable or intentionally excluded.

## Current Support

React client inventory and confirmed name/state updates preserve integration
identity, accepted routing snapshots and existing source/quota rules. They do not
expose credentials or change adapter/worker support states. React profile routing
now adds bounded metadata and confirmed assignments with client ownership and stale
selection checks. Multiple named profiles and credential management are now also
available in React. Intake source/quota filtering is unchanged.

Client Storage administration adds database-backed access grants for the existing
filesystem deferred backend. It supports explicit environment inheritance,
whole-backend/prefix grants and empty custom deny-all. It introduces no S3 backend,
in-place scan mode, new mount capability or engine support promotion. Deployment
roots and secure copy/verification remain authoritative. API and intake processes
must be upgraded together before custom grants are used.

React manual hash lookup reuses the existing hash-capable adapters and quota
mechanism. It introduces no provider, arbitrary command execution or support
promotion. API/ICAP source exclusions remain unchanged. Browser results contain a
bounded reputation decision summary; no raw provider data or integration secrets.

React scan-policy administration preserves the shared operational limits and
source-aware intake rules. Policy editing does not change ICAP startup tuning,
vendor capabilities, worker protocols or any integration support state.

React System now includes bounded worker inventory, lifecycle and agent-credential
revocation using existing worker identity/authorization semantics. Remaining System
and other browser screens are tracked in the full frontend migration inventory.
This adds no worker protocol or engine support promotion.
Worker-pool CRUD is also available in React; exact-match routing and deletion
protection for assigned pools reuse existing backend operations.
React runtime/active-queue reads now cover all scan sources for administrators.
These views add no engine support state or worker transport change.
React overview adds cached scan/worker totals and on-demand historical metrics.

The built-in File Type inspector adds no vendor dependency, no network access and
no command execution. It reads a bounded header and compares the detected content
family with the declared extension, so its cost is independent of sample size.
It is registered as a non-detection adapter: a masquerading extension is an
indicator an analyst judges, not a malware identification, and it therefore never
contributes detection coverage. Operators who want a mismatch to reach the shared
risk score set `mismatch_action` to `detect` on the instance.
Metrics group by recorded engine name; renamed or reused names must not be treated
as stable instance identity, coverage or an allow decision. No support state changes.
React retention cleanup includes all sources with admin confirmation, stale-state
fences and existing active/archive/sample/outbox protections. It changes neither
source-aware routing nor engine support state.

The opt-in [React Dashboard/Engines console](../architecture/FRONTEND_SEPARATION.md) preserves
existing adapters and worker protocols. Its Dashboard is a bounded manual-scan
slice; manual submission reuses existing source-aware intake and lazy archive
handling. Manual reports now expose shared backend decisions and required coverage,
with bounded on-demand technical output. Registered manual archive children have
paginated direct/nested navigation; reading never extracts files and an empty
list does not prove clean coverage. Bounded summary/full JSON/CSV downloads and
confirmed single-scan retry/delete now use the browser API. Full JSON includes raw
engine output/details/findings without sample bytes, storage paths or integration
configuration; CSV remains normalized and spreadsheet-safe. Bounded manual batch
overviews include registered nested members without reading engine output or
changing vendor routing. Admin-only bounded Dashboard deletion is migrated;
per-engine full output is also migrated within 2 MiB source/response limits.
Oversized output keeps a legacy fallback; recursive batch actions remain planned. This is not
full UI parity. Browser acceptance does not promote
Defender or certify a new engine integration.
The browser now uses generated OpenAPI types and contract drift checks. These
cover browser schemas only, not service-client/worker protocol certification;
no engine support state is promoted by type generation or CI configuration.

[Phase 1 hardening](../security/HARDENING_PHASE_1.md) adds upload admission,
deferred source isolation, redirect rejection and continuous HTTPS worker
liveness. These changes do not promote Defender beyond `lab` or certify
production throughput; PostgreSQL, Linux and installed-SCM acceptance gates
remain environment-specific.

| Integration | Vendor | Product | Method | State | Notes |
| --- | --- | --- | --- | --- | --- |
| Static Metadata | MASP | Built-in metadata analyzer | local | supported | Extracts hashes, size, content type, and storage metadata. Not a detection engine. |
| File Type | MASP | Built-in header inspector | local | supported | Reads a bounded header (default 4096 bytes, never the whole file) and compares the detected content family against the declared extension. Not a detection engine: a mismatch is a masquerade indicator, recorded as a normalized finding. `mismatch_action=detect` additionally marks the result detected so the shared scoring layer treats it like any engine detection; the default `report` does not. Cost does not grow with sample size. |
| ClamAV via clamd | Cisco Talos | ClamAV clamd | TCP clamd protocol | supported | Preferred ClamAV runtime in Docker/on-prem deployments. Multiple named clamd instances may use distinct host, port, timeout, and size settings. |
| ClamAV via clamscan | Cisco Talos | ClamAV CLI | local CLI | supported | Local fallback when `clamscan` exists on PATH. |
| YARA via local CLI | VirusTotal/community | YARA | local CLI | supported | Requires local YARA binary and local rule files. |

## Validation and Candidate Commercial Integrations

These are not production-supported yet. An implemented `lab` or `blocked`
adapter may be visible for controlled validation when its support state and
operational blocker are explicit; visibility is not a production support claim.
Research/planned rows have no usable adapter until implementation and lab gates
are complete.

| Candidate | Vendor | Product | Likely Method | State | Required Before Implementation |
| --- | --- | --- | --- | --- | --- |
| VirusTotal file reputation | Google/VirusTotal | VirusTotal API v3 | SHA-256 report lookup | blocked | Registry-managed, quota-consuming reputation adapter for interactive Scan Hash and manual file scans only. REST and ICAP automation exclude it before job creation. Includes encrypted admin-UI credentials, live connection test, environment fallback, and mock coverage. File scans reuse the locally computed SHA-256 and never upload content. Not production-supported until a licensed Premium/Enterprise key and real API fixtures validate found/unknown/auth/quota responses. Scan Hash is fail-closed; manual file scans treat unknown/zero-signal reputation as neutral enrichment while malicious blocks and suspicious reviews. |
| Microsoft Defender via local CLI | Microsoft | Microsoft Defender Antivirus | PowerShell/CLI | lab | Multiple named configurations are supported. The HTTPS Windows service agent uses a node-bound token, no database credential, authenticated size/SHA-256-verified sample download, a virtual service identity, ACL-protected config, rotating logs, preflight, lifecycle scripts, bundle-integrity verification, and an evidence-producing clean/EICAR acceptance runner; direct-queue/shared-storage remains compatible. Windows 11 development-host runs passed direct-database and HTTPS control-plane clean/EICAR scanning with an elevated temporary agent. Installed-SCM-service, failure/timeout/failover/lifecycle acceptance and signed releases are still required before `supported`. See [Windows Worker Agent](../deployment/WINDOWS_WORKER_AGENT.md). |
| ESET Server Security via ICAP | ESET | ESET Server Security or ICAP-capable gateway product | ICAP | research | Confirm exact product, ICAP service behavior, clean/detected responses, headers, licensing, and file size limits. |
| ESET PROTECT via API | ESET | ESET PROTECT | REST API | research | Confirm whether file submission/scanning is supported or only management/telemetry APIs are available. |
| Trellix ATD via API | Trellix | Advanced Threat Defense / Malware Analysis | REST API | research | Confirm submission flow, polling model, verdict schema, auth, rate limits, and report retrieval. |
| Trellix via ICAP | Trellix | ICAP-capable gateway product | ICAP | research | Confirm product name, ICAP mode, response semantics, and detection headers. |
| Sophos via local CLI | Sophos | Sophos Protection for Linux or endpoint product | local CLI | research | Confirm command availability, supported OS, exit codes, and output format. |
| Sophos via API | Sophos | Sophos Central / related product | REST API | research | Confirm whether file scanning/submission is available for this use case. |
| Trend Micro via ICAP | Trend Micro | ICAP-capable gateway product | ICAP | research | Confirm product name, service names, status codes, and detection headers. |
| Kaspersky via ICAP | Kaspersky | ICAP-capable gateway product | ICAP | research | Confirm product name, deployment model, and ICAP response behavior. |
| Fortinet via API or ICAP | Fortinet | FortiSandbox or gateway product | REST API / ICAP | research | Confirm target product and whether MASP should submit files or query existing verdicts. |

## Integration Admission Rules

An integration may move to `lab` only when:

- Product and version are identified.
- Official documentation or vendor-provided integration notes are available.
- Required config fields are known.
- Clean, detected, and error response examples are available.
- A health check strategy is defined.

An integration may move to `supported` only when:

- Adapter is implemented.
- Fixtures exist for clean, detected, auth failure, unavailable/timeout, and malformed responses.
- Parser tests pass.
- Health check is implemented.
- Secrets are redacted.
- Report/export output is verified.
- The support matrix row links to the integration spec.

## Fixture Layout

Recommended fixture paths:

```text
tests/fixtures/engines/<integration-key>/
  clean.response
  detected_eicar.response
  auth_failure.response
  unavailable.response
  malformed.response
  README.md
```

Use product-specific filenames when the vendor returns multiple response types, such as:

```text
submit_detected.json
poll_pending.json
poll_completed_malicious.json
report_malicious.json
```

## Notes

- Static metadata should not count toward required detection engine coverage.
- Worker-deployed integrations register durable node identity, platform,
  version, labels, capacity, advertised adapters, lifecycle, and heartbeat.
  Exact-match worker pools and engine-instance bindings use that inventory for
  placement and capacity-aware scheduling. Worker-executed probes separately
  persist per-node/per-instance service, version, signature, storage, failure,
  and last-scan health. Vendor support state still requires the adapter-specific
  validation gates above; a green generic probe does not promote a lab adapter.
- Control-API workers receive no PostgreSQL credentials. Their one-time agent
  token is stored server-side only as a hash; job/result/health writes retain
  lease-generation fencing, and sample download is limited to the current owner.
- MASP REST consumers can use distinct service clients, hashed/revocable tokens,
  and engine profiles. ICAP identity is process-bound with
  `MASP_ICAP_SERVICE_CLIENT_KEY`; separate listeners are required for distinct
  client routing/ownership. This orchestration boundary does not change any
  vendor adapter's support state.
- Large-file REST consumers can submit idempotent deferred filesystem-object
  references. This opt-in path uses a deployment-mounted read-only source,
  isolated copy/hash verification, normal engine routing, and a transactional
  high/critical SIEM webhook outbox. S3 backends and remediation are roadmap.
- Generic ICAP, generic REST, and custom command engines are internal engineering tools only unless a future product decision explicitly changes this.
- Implemented `lab` or `blocked` integrations may be exposed for controlled
  validation with an explicit support-state warning. Production operators must
  enable only integrations approved for their license, network, and acceptance
  test scope.


React integration administration also provides atomic client/default-profile/
initial-credential creation and bounded credential add/list/revoke. Admin-supplied
tokens are write-only; preserve HTTPS, pre-body admin/CSRF checks, no-store responses
and no automatic write replay. Lists omit hashes and prefixes. The additive
`idx_api_client_credentials_client_seek` index needs a deployment migration window;
validate inventory size and concurrent administrative reads/writes before cutover.
No vendor support promotion or remote-worker acceptance gate is implied.


The React API ledger now provides bounded analyst/admin API/ICAP history with
exact client/source filters and explicit unassigned ownership. It does not expose
engine blobs or use service-client bearer authentication. Partial global/client
ID seek indexes are additive startup migrations; retain deployment-shaped filter
load and migration lock validation. Automation details and deletion remain legacy
parity work. This does not change scan decisions, routing or adapter support.


Automation report/output and batch overview now use React with the shared bounded,
coherent readers. Batch members match source and nullable client ownership.
Single deletion is admin/CSRF-protected with attempt/job fences, active/child/
shared-sample/outbox checks and separate cleanup outcomes. No automatic replay or
recursive deletion. Preserve manual-source boundaries, output ceilings and
production load/TLS gates; payload/export and bulk-action parity remain before
retiring legacy HTML. No adapter or worker support state is promoted.


Automation management now provides analyst/admin summary/full report JSON/CSV
exports with shared source-scoped snapshot reads and separate source/content
limits. Historical full exports lacking recorded routing keep a legacy fallback.
Exports are operator reports, not integration API status/result contract previews.
Retain deployment export-memory/concurrency gates and remaining payload/bulk parity;
this does not promote engine support or authorize legacy HTML removal.


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
