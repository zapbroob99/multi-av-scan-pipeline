# Service clients and scan profiles

MASP can serve multiple consuming systems without treating every bearer token as
the same integration. The current model is:

```text
Service client
  -> one enabled default scan profile
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
- Every custom client has an enabled default profile with an explicit set of
  engine instance IDs.
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

## Request and execution flow

```text
API bearer token / ICAP gateway config
  -> resolve service client
  -> resolve enabled default profile
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

1. Add multiple named profiles per client and allow an authorized API request to
   select among its own profiles.
2. Add per-client admission/rate limits, weighted fairness, and quota metrics.
3. Extend global webhook delivery with per-client SIEM routes, delivery
   metrics/audit, review/policy event selection, and a dead-letter UI.
4. Add S3-compatible deferred backends, resumable fetch and bandwidth scheduling.
5. Add client-scoped policy overrides after precedence and snapshot semantics are
   defined. Global safety ceilings must remain authoritative.

The preferred remote-engine transport remains the authenticated HTTPS worker
control plane. Workers download a generation-bound sample to temporary local
storage and verify SHA-256. Direct database/shared-filesystem workers remain a
compatibility mode; SMB/NFS is not required for remote Defender nodes.
