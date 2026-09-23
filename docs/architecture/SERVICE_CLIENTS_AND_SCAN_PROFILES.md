# Service clients and scan profiles

MASP can serve multiple consuming systems without treating every bearer token as
the same integration. The current model is:

```text
Service client
  -> multiple named scan profiles (one enabled default)
       -> explicit engine instance assignments
  -> one or more revocable API credentials
  -> API/ICAP scans, batches and ledger rows
```

Examples of a service client are a Drive integration, a large-file transfer
service, or an ICAP gateway dedicated to one storage platform. A service client
is an operational/security boundary, not a human UI account.

## Current behavior

- Admins manage clients from **Service Clients**, and each client links to a
  setup view showing readiness and connection details.
- A client key is stable and machine-oriented; the display name can change.
- API tokens are stored only as SHA-256 hashes plus an eight-character
  fingerprint. Raw tokens cannot be read back from MASP.
- Every custom client has an enabled default profile and may have additional
  named profiles, each with an explicit set of engine instance IDs.
- API authentication resolves the bearer token to exactly one client and its
  default profile.
- Scan and archive-batch rows persist `service_client_id`, `scan_profile_id`, and
  a bounded profile snapshot.
- The snapshot records client/profile labels and engine identities, but no
  engine configuration or secret. A later profile edit affects only new scans.
- API status/result routes return `404` for a scan or batch owned by another
  client. This avoids both data disclosure and ID-existence disclosure.
- API Ledger can filter and label rows by service client.
- API and ICAP still exclude adapters marked `consumes_external_quota`, even if
  such an adapter is selected in a profile.

Existing `MASP_API_TOKEN`, `MASP_API_TOKENS`, and settings-backed tokens map to
the managed `legacy-default` compatibility client. Its routing follows globally
configured automation-safe engines. Move integrations to database-managed
credentials before relying on per-client isolation.

## Named profile management and selection

Open a client from the Service Clients list, then its **Profile routing** tab.
Admins can create, rename, enable/disable and delete named profiles, replace
their engine assignments, and select the default. Standalone
`/console/service-clients/{id}/profiles` remains available. The current default
cannot be disabled or deleted: first select another enabled profile with engines.
Creating a named profile leaves the current default unchanged.

An integration using a stored client credential can supply its own enabled
`profile_id` as a multipart field on `POST /api/v1/scans`, a JSON integer on
`POST /api/v1/deferred-scans`, or a query parameter on `GET /api/v1/hashes/{sha256}`.
Omission uses the client's current default. Invalid IDs, another client's IDs,
disabled profiles and deleted profiles receive the same `404`; malformed IDs
receive `422`. Environment/settings compatibility tokens cannot select an explicit
profile. ICAP continues to use its bound client's default, without a request-level
override. Profile selection never bypasses disabled-engine, capability or quota
filtering; a metadata-only profile does not prove malware detection coverage.

Client, selected profile and engine rows are read in one repeatable snapshot
before accepting new API/ICAP work. Accepted routing is persisted as before;
renaming, changing defaults, editing engines or deleting a profile does not rewrite
existing scans, batches or deferred submissions. Deletion retains the profile
identity and engine rows because deferred work and older reports reference them.
Deleted names remain reserved for that client. Deferred idempotency also includes
the captured routing: changed profile selection or routing under an existing
`client_request_id` returns `409`; reconcile via its status URL.

Browser writes require admin/CSRF checks before parsing. Client-row locking
serializes profile changes on PostgreSQL; SQLite uses an immediate write
transaction. Metadata/default/delete changes carry `management_revision`;
routing also fences the displayed engine IDs. The default switch compares the
displayed prior default ID, even on later profile pages. Stale writes return `409`
and are never replayed automatically. Legacy engine edits take the same lock and
advance the revision. Reads remain capped at 20 profiles and 100 engine choices
or assignments, with incomplete data disabling editing.

Startup migration adds revision/deletion columns and a partial unique default
index in place. If an older database has multiple defaults, it retains the first
enabled default by ID (or the first default if none is enabled), demotes the others
and preserves historical snapshots. For compatibility, a legacy/custom database
without a flagged enabled default retains its pre-existing first-enabled-profile
fallback; the setup screen still reports the missing explicit default.

## Connecting a client

`/console/service-clients/{id}/setup` answers one question in one place: is this
client ready, and what does the other system need to be told? Everything it shows
already existed, spread across the client list, the profile routing editor and the
credential page, and the endpoint to point an integration at was not shown at all.

It reports five configuration checks, each pass or fail with its own reason: the
client is enabled, an enabled default profile exists, that profile has assigned
engines, at least one assigned engine is eligible for automation, and an active
credential exists. An assigned engine that cannot run automation work says why -
a disabled instance, an unregistered adapter, an adapter that cannot accept a
submitted file, or a metered reputation adapter that API and ICAP exclude before
job creation. That last exclusion is adapter-level policy, so the engine can stay
assigned for manual use.

Alongside the checks it shows the submission, status and deferred endpoints, the
authorization header shape, and the `MASP_ICAP_SERVICE_CLIENT_KEY` value for a
gateway bound to this client. No credential value appears: MASP stores only a
hash and a fingerprint, so a lost token is replaced, never recovered.

All reads happen in one repeatable snapshot, so a concurrent profile edit cannot
produce a readiness state that never existed. The route is admin-only and
read-only.

This is configuration readiness, not a connectivity test. It cannot prove the
integration can reach MASP, that its token is correct, or that an assigned engine
is healthy at scan time. Network reachability, TLS and firewall rules stay outside
MASP.

## ICAP mapping

ICAP has no MASP bearer token. A gateway process is therefore bound to one
service client with:

```text
MASP_ICAP_SERVICE_CLIENT_KEY=large-file-transfer
```

The default is `legacy-default`. Run a separate ICAP listener/container (unique
bind address/port and service name) for each client that needs different routing
or ledger ownership. Do not infer identity from an untrusted ICAP header or from
source IP behind NAT. Host firewall restrictions remain mandatory.

## Retrying a deferred submission

`client_request_id` is the idempotency key, unique per service client. A retry
carrying the same id and the same assertions returns the accepted record with
`202` and creates no second scan.

Only what the client asserted is compared: backend key, object id, expected size,
expected SHA-256, archive mode, and the profile it explicitly selected (absent
meaning "use the default", which is not the same as naming the profile that
happened to be default). Descriptive metadata — case name, priority, note,
filename, content type — is first-write-wins, because a producer that rebuilds a
note is not making a different request.

The accepted routing snapshot is deliberately excluded from that comparison, and
the endpoint answers a retry before resolving live routing at all. Both matter:
the snapshot embeds client, profile and engine display names, so previously a
mere rename turned a byte-identical retry into a `409` the producer could never
clear, and resolving the current profile first made a retry unanswerable once
that profile had been removed. Retry safety must not depend on server-side
configuration holding still.

A genuinely different request for an existing id is still `409`. The frozen
snapshot on the accepted row remains authoritative for the work itself, so an
operator edit never changes what an accepted submission will run.

## Manifest intake: a producer that never calls MASP

Some storage producers cannot, or should not, call MASP at all. A file server or
drive application can instead write each finished object and then drop a sibling
JSON manifest next to it. MASP polls for manifests and accepts them as deferred
submissions; the producer waits for nothing and holds no credential.

The ordering is the contract. The producer writes the object first and the
manifest last, so **a manifest appearing is the completion signal**. Without it
MASP would have to guess whether an upload is still being written, and no
size-stability heuristic makes that guess safe.

```text
producer writes object      uploads/2026/09/23/UP-1.pdf
producer writes manifest    uploads/2026/09/23/UP-1.json   <- completion signal
  -> manifest intake worker accepts a deferred submission
  -> existing deferred intake worker copies, verifies size/SHA-256, queues engines
```

A manifest carries `upload_id`, `original_filename`, and optionally `object_id`,
`sha256`, `size_bytes`, `content_type`, `uploaded_at`, `user_id`, `user_display`
and `tenant_id`. Unknown keys are ignored so the producer can extend the format
without a MASP release. `upload_id` becomes the `client_request_id`, so the
existing `UNIQUE (service_client_id, client_request_id)` constraint makes
re-reading a manifest free.

That matters because **the mount stays read-only**. MASP never deletes, moves or
rewrites anything on the share, so it cannot mark a manifest as processed. It
does not need to: the second read of a manifest resolves to the existing
submission.

### Boundaries

A manifest names what to scan. It never grants access:

- The object must resolve inside the client's approved backend prefix, checked
  with the same `backend_allowed_for_client` policy the copying worker re-checks
  before it reads a byte.
- The object must sit in the manifest's own directory. A manifest cannot point
  across the share even within one grant.
- Traversal, absolute paths, symlinks and junctions are rejected by the existing
  `resolve_source_path` checks.
- A declared `sha256` is verified against the bytes MASP copies. It can reject a
  mismatch; it cannot satisfy a check MASP did not perform itself.

### Bounded discovery

A full recursive walk of a share that only grows is not a backstop; it is the
most expensive part of such a system. Each cycle scans a fixed set of recent
partitions (`MASP_MANIFEST_DATE_LAYOUT`, `MASP_MANIFEST_LOOKBACK_DAYS`) and reads
at most `MASP_MANIFEST_BATCH` manifests, so cycle cost is predictable regardless
of share size. Widening the lookback picks up older partitions without any
rewrite. Set an empty date layout when the producer does not partition by date.

### What this trades away

The producer gets no delivery confirmation, no backpressure and no error
feedback: it wrote a file and moved on. A rejected manifest is therefore
invisible to it, so rejections are recorded in `manifest_rejections` with the
reason, first/last seen and an occurrence count, capped so a misconfigured
producer cannot grow the table without bound. A rejection clears once the same
manifest is accepted. **Operators must watch this**: it is the only place a
malformed or unauthorized drop becomes visible.

Admin `/console/system/intake` shows this state (GET `/api/ui/v1/system/intake`,
read-only). The worker records each cycle, success or failure, in the
`manifest_intake_last_cycle` setting together with the configuration it actually
ran with, because the API process does not share the worker's environment. A
cycle older than four poll intervals (and at least a minute) is flagged stale:
without the record a stopped worker looks exactly like a quiet share. The page
also shows deferred queue counts with the oldest waiting age, the newest 50
rejections with the total, and the newest 20 submissions that failed
permanently before becoming scans, which no scan report can show. Error text is
stored and shown with absolute paths replaced by `<path>`; deployment roots are
never displayed. Nothing on the page writes, retries or clears a record.

## Request and execution flow

```text
API bearer token / ICAP gateway config
  -> resolve service client
  -> resolve own selected profile or enabled default
  -> filter assigned engines by source and quota capability
  -> persist scan + profile snapshot + engine jobs atomically
  -> workers execute only snapshot engine instance IDs
  -> decision/coverage uses snapshot-required detection engines
  -> ledger and API reads enforce client ownership
```

Retry also uses the stored snapshot. Profile edits cannot silently change the
engine set of an already accepted scan.

## Concurrency boundary

Multiple clients can submit concurrently. PostgreSQL, the fenced engine-job
queue, worker leases, node capacity, and ICAP admission control protect execution
correctness. This release does not yet provide per-client queue fairness, rate
limits, quotas, or reserved capacity. A noisy client can therefore increase
another client's queue latency even though records and credentials are isolated.

## Deferred large-file path

`POST /api/v1/deferred-scans` accepts metadata only and immediately returns
`202 Accepted`. The request carries a client-scoped idempotency key, a
deployment-approved backend key, and a relative object id. Raw URLs, UNC paths,
and arbitrary host paths are not accepted. Backend-to-service-client
authorization is explicit and fail-closed; shared roots may additionally scope
each client to object prefixes so one tenant cannot reference another tenant's
folder.

### Client storage administration

The client's **Storage** tab (also `/console/service-clients/{id}/storage`) shows
logical backend keys and their allowed object prefixes. It never returns, browses
or changes filesystem roots. `MASP_DEFERRED_STORAGE_BACKENDS_JSON` or the single
`MASP_DEFERRED_FILESYSTEM_BACKEND_KEY`/`MASP_DEFERRED_FILESYSTEM_ROOT` pair still
defines deployment-approved roots separately on the API and intake processes.

Each client starts in **Deployment settings** mode, preserving
`MASP_DEFERRED_BACKEND_CLIENTS_JSON` behavior. An admin may confirm **Custom client
access**, which replaces that client's environment grants with whole-backend or
relative-prefix grants stored in `service_client_storage_policies`. The sources
are never unioned: an empty custom list denies all backend access even when the
environment grants access. Returning to deployment settings explicitly previews
the grants that this API process will inherit. The managed `legacy-default` client
remains read-only. No existing deployment grants are imported automatically.

Both public deferred admission and the intake worker resolve the current policy
without a retained cache. Backend keys must still exist in that process's local
deployment catalog. Removed backends are unavailable, even if a persisted grant
still names them. Prefixes match a complete object key or descendants across a `/`
boundary, never a sibling with the same initial letters; they are literal relative
paths, not glob patterns. Blank prefix lists never mean whole-backend access.
Malformed/oversized stored grants or database failures fail closed rather than
restoring environment access. Filesystem link, traversal, opened-handle and
copy/hash/size checks remain unchanged.

Policy changes apply to new admission and pending deferred work before copying.
Revoking a queued submission's access causes the worker to fail it before file I/O.
A copy already in progress may continue; this is not cancellation, and no existing
scan/routing snapshot is rewritten. Check deployment configuration on all processes:
the console reports this API server's catalog, not worker reachability or mount health.

Admin/CSRF checks precede JSON parsing. A write replaces the entire custom grant
set atomically under the owning client row lock (SQLite immediate transaction),
fencing both the displayed policy revision and a fingerprint of visible deployment
grants/backend keys. Returning to inheritance retains a revision row, so an earlier
edit cannot overwrite a custom→environment transition. Conflicts return `409`;
the UI requires an explicit refresh after every write outcome and never replays it.
Limits: 50 configured backend keys/50 grants, 32 prefixes per grant, 128-character
backend keys, 512-character normalized prefixes, and a 64 KiB serialized stored
policy. Incomplete/invalid deployment configuration is an explicit read error,
not a truncated editable list. No root, credential, file listing or sample data
is included in these DTOs or audit details.

Upgrade all API and deferred-intake processes before enabling custom policies;
older processes know only the environment mappings. See the coordinated rollout
instructions in `../deployment/PRODUCTION.md`.

The opt-in deferred intake worker mounts one approved source root read-only. It
rejects traversal, symlinks/junctions and hardlinked files (even within the same
backend), validates the opened source handle, copies the bytes into MASP storage,
checks that the source did not change during copy, verifies optional expected
size/SHA-256, enforces the configured maximum byte limit, and atomically creates
the sample, scan, routing snapshot, and engine jobs. Unavailable sources retry
with bounded exponential backoff; immutable-reference, policy and hash
mismatches fail explicitly. If any engine in the immutable routing snapshot is
unavailable before intake, MASP fails the deferred submission before copying instead of
silently creating partial coverage.

Deferred scans carry `security_events_only` in their immutable snapshot. A
high/critical completion inserts `malware.detected` into `notification_outbox`
in the same transaction as completion. A separate worker posts the event to the
operator-configured SIEM webhook with an idempotency key, optional HMAC-SHA256,
and retry/backoff. The webhook must use HTTPS unless HTTP is explicitly enabled
for a lab receiver. Redirect responses are rejected and retried, never treated as
delivery acknowledgment. Clean/low results do not create an event. Retention and
manual deletion preserve scans with undelivered outbox events.

This is eventual detection, not preventive blocking: the source application may
have released the file before detection. Quarantine/delete remediation requires
an explicitly authorized source-system integration and is not performed here.

## Next milestones

1. Add per-client admission/rate limits, weighted fairness, and quota metrics.
2. Extend global webhook delivery with per-client SIEM routes, delivery
   metrics/audit, review/policy event selection, and a dead-letter UI.
3. Add S3-compatible deferred backends, resumable fetch and bandwidth scheduling.
4. Add client-scoped policy overrides after precedence and snapshot semantics are
   defined. Global safety ceilings must remain authoritative.

The preferred remote-engine transport remains the authenticated HTTPS worker
control plane. Workers download a generation-bound sample to temporary local
storage and verify SHA-256. Direct database/shared-filesystem workers remain a
compatibility mode; SMB/NFS is not required for remote Defender nodes.
