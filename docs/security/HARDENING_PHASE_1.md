# Security and reliability hardening: phase 1

This phase closes specific intake and worker-control failure paths. It is not a
throughput certification or a promotion of Defender beyond `lab` support.

## HTTP upload admission

`POST /scans`, `POST /api/v1/scans`, and `POST /engines/yara/rules` authenticate
before multipart parsing. The application rejects oversized declared bodies
before reading them and counts actual received bytes for chunked or misleading
Content-Length requests. Partial parser spool files are closed on limit failure.

`MASP_HTTP_UPLOAD_MAX_BYTES` is a positive deployment-wide multipart-body ceiling
(default `67108864`, 64 MiB). The effective body limit is the smaller of that
ceiling and the configured sample limit plus 1 MiB of multipart overhead; when
the sample policy is unlimited, the deployment ceiling still applies. Extra
file parts and form fields count toward the same body limit. File content is
also checked against the sample policy during persistence. Rejection is `413`;
an invalid deployment ceiling fails closed with `503`.

Upgrades that previously allowed unlimited HTTP uploads now have a finite
ceiling. Raise it explicitly, with multipart overhead, if the approved file
contract requires more than 64 MiB. This does not change the separate deferred
source or ICAP limits. Keep proxy body limits, upload timeouts, connection limits,
and spool disk budgets aligned; the application boundary is not a substitute
for ingress concurrency/rate controls.

Sample copying/hashing, upload routing/enqueue database work, and terminal-state
wait reads execute in the thread pool instead of the API event-loop thread.
Multipart spooling still precedes persistence; this is not single-pass streaming
or a fully asynchronous database implementation.

## Deferred reference isolation

Backend/client/prefix authorization remains mandatory. Inside a trusted configured
backend root, every path component must be link-free: symlinks, Windows reparse
points/junctions, and hardlinked source files are rejected, including links to
another location inside the same backend. Drive/alternate-stream syntax and NUL
bytes are rejected in object ids.

POSIX opens components relative to pinned directory descriptors with no-follow
flags. Windows validates the final pathname of the opened file handle before
reading. Size, timestamps, and content hashes are checked using that same open
handle. The configured root and its ancestors remain administrator-controlled
trust anchors; use filesystem permissions to prevent unauthorized writes across
client prefixes. Expected SHA-256 is recommended when the producer can supply it.

These restrictions intentionally reject some previously accepted linked sources.
Publish regular files into an approved client prefix instead. An unavailable
snapshot engine causes a permanent deferred submission failure before copying
potentially multi-GiB content; it never silently substitutes another engine.

## Worker transport and routing

Worker-control requests and SIEM webhook delivery reject HTTP redirects,
including same-origin redirects. Configure final endpoints directly: redirects
must not forward credentials/payloads or turn a POST into a successful GET.
Webhook failures remain in the retrying outbox, not marked delivered.

HTTPS worker heartbeat runs independently during download, engine execution,
health probes, and result submission. Job lease renewal starts before sample
download and remains active until result acknowledgment. Renewal failure prevents
starting a scan or submitting its result once observed; server-side attempt
fencing remains authoritative. Interrupted response bodies become recoverable
worker-control errors. Engine health remains distinct from process liveness.

Server-side result finalization receives the scan's routing snapshot, not the
current global engine list. Snapshot display names survive instance renames;
an explicit empty engine snapshot never falls back to the current profile.

## PostgreSQL upgrade

`samples.size_bytes` is `BIGINT`. Startup migrates existing `INTEGER` columns in
place and skips the alteration when already upgraded. Existing rows are retained;
SQLite remains compatible without a type migration. The first PostgreSQL
alteration can lock/rewrite the samples table: take a backup, provision free
space, and schedule a maintenance window appropriate to database size. Do not
assume a zero-downtime upgrade for a large existing installation.

The migration regression uses metadata larger than 2 GiB without creating a
large sample file. Run PostgreSQL-gated tests only with `MASP_TEST_POSTGRES_URL`
pointing to a disposable database: their harness recreates its public schema.

Browser reads now apply a transaction-local statement timeout and force custom
plans; retry/delete apply a transaction-local row-lock timeout. Defaults are 5
seconds and values clamp to 100..60000 ms. Budget expiry is returned to the
browser as a generic 503 without database text. The settings revert at transaction
end, including on pooled connections.

## Remaining gates

Local verification on 2026-09-10 exercised the PostgreSQL migration, queue
concurrency, browser snapshot and lock/statement-budget tests against a disposable
PostgreSQL 16 container. The full suite ran 672 tests with 670 passing and two
platform-gated skips. A destructive synthetic benchmark with 100,000 Dashboard
rows and 100,000 archive children, including bounded full-export and indexed deep
batch-page reads, passed its default single-query and eight-way
mixed-read budgets. This was loopback, warm-cache traffic without worker writes;
no live MASP database migration or installed-SCM acceptance was performed.

- Repeat Windows installed-SCM identity and failure/failover acceptance; unit
  heartbeat coverage does not replace real Defender/service-policy validation.
- Validate POSIX no-follow behavior on Linux, not only Windows handle checks.
- Validate browser queries with production row widths/cardinality, worker writes,
  database telemetry and p95/p99 HTTP/TLS traffic; add indexed search or maintained
  aggregates before the measured budgets require them.
- Isolate heavy finalization/maintenance, introduce client fairness/backpressure,
  and stream ICAP intake.
- Measure concurrent uploads and queue drain with p95/p99 latency, event-loop
  lag, DB load, memory, disk I/O, and complete-versus-partial engine coverage.
