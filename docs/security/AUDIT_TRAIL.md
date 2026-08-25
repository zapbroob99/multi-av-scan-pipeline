# Audit trail

MASP persists an application-level security audit trail in the `audit_events`
table. Administrators can review it from **Admin > Audit** and filter by actor,
action, target, request ID, or outcome.

## Recorded activity

- Login attempts and logout.
- User administration and password changes.
- Scan-policy, engine configuration/lifecycle, worker-node lifecycle, and YARA
  rule administration.
- Retention execution and destructive scan deletion.
- Actor type and identifier, outcome, direct peer IP, request ID, route, status,
  target, timestamp, and bounded event-specific metadata.

The audit table is intentionally not an HTTP access log. Normal page navigation,
scan or hash submission, API status/result polling, report/export reads,
health checks, and metrics scrapes are excluded. If those access records are
required, retain them in the reverse proxy or platform logging system with its
own shorter retention policy.

The response includes `X-Request-ID`. MASP accepts a syntactically safe incoming
`X-Request-ID` for cross-service correlation or generates a random value. The
source IP is the direct socket peer; MASP deliberately does not trust
`X-Forwarded-For` without an explicit trusted-proxy model.

If a future audited administrative API uses bearer authentication, its token is
represented only by a short SHA-256 fingerprint; the raw value is never stored.

## Data minimization

The middleware does not read or persist request bodies. Uploaded samples,
passwords, session cookies, authorization headers, API keys, engine raw output,
and file contents are excluded. Event-specific metadata passes through a
recursive deny-list redactor and strict depth, item-count, string-length, and
serialized-size limits.

Query parameter names may be recorded, but their values are not. Path parameters
may be recorded as targets only for routes included in the focused audit policy.

## Integrity and availability boundary

Audit rows have no foreign keys to users or scans, so normal account deletion,
scan deletion, and sample retention do not cascade into the audit trail. The
application data layer exposes insert and read operations only; the UI has no
audit update or delete action.

This is application-level append-only behavior, not tamper-proof storage. A
database administrator can still alter the table. For stronger institutional
assurance, forward events to an access-controlled SIEM or immutable/WORM target
and add integrity signing or database-level controls.

Audit insertion currently occurs after the handled operation and is best effort.
If the audit database write fails, MASP logs the failure but does not turn a
successful scan or configuration change into an ambiguous client error. A future
transactional outbox should be used where audit-write atomicity is mandatory.

There is intentionally no application retention/delete control for audit events.
Define audit retention, export, backup, and legal-hold rules with the institution's
security and data-governance owners before production rollout.
