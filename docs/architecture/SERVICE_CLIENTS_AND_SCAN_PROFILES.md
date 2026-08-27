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

- Admins manage clients from **Service Clients**.
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

## Next milestones

1. Add multiple named profiles per client and allow an authorized API request to
   select among its own profiles.
2. Add per-client admission/rate limits, weighted fairness, and quota metrics.
3. Add a transactional notification outbox with per-client SIEM/webhook routes,
   retry/backoff, idempotency keys, and delivery audit.
4. Add an explicit notification-only submission mode. `POST /api/v1/scans`
   already returns `202` without waiting when `wait_seconds=0`; notification-only
   means the caller need not poll and receives only configured security events.
5. Add client-scoped policy overrides after precedence and snapshot semantics are
   defined. Global safety ceilings must remain authoritative.

The preferred remote-engine transport remains the authenticated HTTPS worker
control plane. Workers download a generation-bound sample to temporary local
storage and verify SHA-256. Direct database/shared-filesystem workers remain a
compatibility mode; SMB/NFS is not required for remote Defender nodes.
