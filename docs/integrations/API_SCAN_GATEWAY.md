# API Scan Gateway

MASP exposes an authenticated file scan API for service-to-service integrations.
The primary workflow is:

1. Submit a sample with `POST /api/v1/scans`
2. Read the returned `links.status` URL until `result_ready` is `true`
3. Fetch the normalized final payload from `links.result`

## Upload-Gateway Integration Pattern (v1)

For integrations that scan a file before allowing an action elsewhere (for
example, a file storage product scanning an upload before accepting it), the
recommended v1 pattern is a **size-capped synchronous scan**:

```text
1. Client submits the file directly via POST /api/v1/scans with wait_seconds
   set high enough to cover a typical scan (see tuning below).
2. 200 OK  -> scan finished inside the wait window; read decision.action.
3. 202 Accepted -> did not finish in time; poll links.status until
   result_ready=true (or treat as a timeout per your own policy).
4. 413 Payload Too Large -> file exceeds MASP_UPLOAD_MAX_BYTES; the client
   decides what to do with oversized files (this API does not scan them).
```

Recommended server configuration for this pattern:

```text
MASP_UPLOAD_MAX_BYTES=52428800      # 50 MB — reject anything larger with 413
MASP_API_MAX_WAIT_SECONDS=30        # upper bound a client may request to wait
```

The client should pass `wait_seconds` explicitly on every request (it defaults
to `0`, i.e. fire-and-poll, if omitted). 30 seconds comfortably covers a
single small-file scan across all eligible engines under normal load; raise it if
your engine mix or host is slower, but stay mindful that the request holds a
connection open for the full wait.

There is no separate "scan and wait" endpoint — this is `POST /api/v1/scans`
used with `wait_seconds` set, which the API already supports. Nothing else in
the request shape changes.

For a file above the upload cap, the integrating system must follow its own
approved fail-closed or manual-review policy. MASP does not invoke metered
external reputation services from API or ICAP traffic.

## SHA-256 reputation lookup

`GET /api/v1/hashes/{sha256}` runs enabled adapters whose registry capabilities
declare `supports_hash_lookup` **and do not** declare
`consumes_external_quota`. MASP never spends a third-party token/quota for API
or ICAP automation. If no eligible non-metered hash adapter exists, the endpoint
returns `503`.

VirusTotal declares `consumes_external_quota=True`, so it is deliberately
excluded from this endpoint, REST file scans, and ICAP scans. Adding or enabling
VirusTotal does not change that automation policy.

Interactive users can still perform an explicitly initiated lookup from the
**Scan Hash** navigation tab. Manual file scans may also run VirusTotal using the
locally computed SHA-256. Neither path uploads file content. UI-managed keys are
encrypted and require a stable `MASP_SECRET_ENCRYPTION_KEY` on app and worker.

```bash
curl -fsS \
  -H "Authorization: Bearer $MASP_API_TOKEN" \
  "https://masp.example/api/v1/hashes/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
```

With VirusTotal as the only hash adapter, the automation response is:

```json
{
  "detail": "No non-metered hash-capable engine is available for API use."
}
```

Interactive **Scan Hash** status and decision semantics:

| Status | Meaning | Default action |
|---|---|---|
| `malicious` | Malicious count meets `MASP_VIRUSTOTAL_MALICIOUS_THRESHOLD` | `block` |
| `suspicious` | Suspicious signal or a malicious count below the threshold | `review` |
| `undetected` | A report exists with no malicious/suspicious engines | `review` |
| `stale` | Zero detections, but the report is missing a date or older than the freshness limit | `review` |
| `unknown` | No report exists, or the report has no usable engine statistics | `review` |

A valid VirusTotal no-report response is a completed lookup. **Scan Hash** keeps
it fail-closed as Review. In an ordinary manual file scan, VirusTotal is only
reputation enrichment: `unknown`, `undetected`, and stale zero-signal reports do
not override otherwise-clean local engines. They display as **No report** or
**No detections**. Malicious still blocks, suspicious still reviews, and actual
configuration/network/quota/timeout/malformed-response failures reduce coverage.

`MASP_VIRUSTOTAL_ALLOW_UNDETECTED=1` changes only `undetected` to `allow`.
This is deliberately off by default: zero detections is not proof that a file
is clean. Even when enabled, the report must have an analysis date no older
than `MASP_VIRUSTOTAL_MAX_AGE_DAYS` (default 30); older or undated reports are
`stale + review`. It never changes `unknown`, `stale`, upstream errors, or quota
failures into an allow result.

Recommended large-file automation flow:

```text
1. Do not assume a VirusTotal lookup will run through MASP automation.
2. Apply the integration owner's size-limit policy.
3. Route oversized files to quarantine/manual review or another approved local,
   non-metered engine path.
4. Treat `503` from the hash endpoint as unavailable and fail closed.
```

Interactive Scan Hash responses are cached in the app process; manual
file-scan reputation responses are cached in the worker process. Known reports
default to 3600 seconds and unknown hashes to 300 seconds. Configure with
`MASP_VIRUSTOTAL_CACHE_SECONDS` and
`MASP_VIRUSTOTAL_UNKNOWN_CACHE_SECONDS`; the LRU is bounded by
`MASP_VIRUSTOTAL_CACHE_MAX_ENTRIES` (default 10000). Cache is intentionally
process-local and is lost on restart. Interactive Scan Hash lookups are not
persisted as scan records. Ordinary manual file scans do persist their
normalized VirusTotal engine result and bounded technical details with the scan
report, just like other engine results.

Manual VirusTotal use still requires an appropriately licensed plan and approved
DNS/outbound HTTPS access. The Public API must not be used for an organizational
workflow that its license does not permit.

## Authentication

Use a bearer token in the `Authorization` header.

```text
Authorization: Bearer <token>
```

For new integrations, an administrator creates a client in **Service Clients**,
selects its engine instances, and registers a long random token. MASP stores
only the token hash and a short fingerprint. A token can read only scans and
batches owned by its client; cross-client IDs return `404`. Profile changes
apply to new submissions only because every accepted scan keeps a routing
snapshot.

The following compatibility sources are still accepted and map to the shared
`legacy-default` client:

- `MASP_API_TOKEN`
- `MASP_API_TOKENS`
- `api.tokens` in MASP settings storage

Do not use shared compatibility tokens when client-level isolation is required.

## Environment

Common API-related settings:

```text
MASP_API_TOKEN=replace-with-a-long-random-token
MASP_SECRET_ENCRYPTION_KEY=CHANGE_ME_FERNET_KEY
MASP_API_MAX_WAIT_SECONDS=15
MASP_API_RETRY_AFTER_SECONDS=2
MASP_UPLOAD_MAX_BYTES=0
MASP_VIRUSTOTAL_ENABLED=0
MASP_VIRUSTOTAL_API_KEY=
MASP_VIRUSTOTAL_TIMEOUT_SECONDS=10
MASP_VIRUSTOTAL_CACHE_SECONDS=3600
MASP_VIRUSTOTAL_UNKNOWN_CACHE_SECONDS=300
MASP_VIRUSTOTAL_CACHE_MAX_ENTRIES=10000
MASP_VIRUSTOTAL_MALICIOUS_THRESHOLD=1
MASP_VIRUSTOTAL_ALLOW_UNDETECTED=0
MASP_VIRUSTOTAL_MAX_AGE_DAYS=30
```

Generate the encryption key once with
`python tools/generate_secret_key.py`, store it in the deployment secret
manager, and keep it stable across restarts and restores. Losing or rotating it
without re-entering integration keys makes existing encrypted credentials
unreadable. `MASP_VIRUSTOTAL_API_KEY` is optional when the key is saved in the
engine UI.

- `MASP_API_MAX_WAIT_SECONDS`: upper bound for client-requested blocking wait time
- `MASP_API_RETRY_AFTER_SECONDS`: recommended poll interval returned in API responses
- `MASP_UPLOAD_MAX_BYTES`: `0` disables the upload limit; set a real cap (for
  example `52428800` for 50 MB) for upload-gateway integrations

## Submit a Scan

```bash
curl -X POST "http://localhost:8000/api/v1/scans" \
  -H "Authorization: Bearer $MASP_API_TOKEN" \
  -F "sample=@./sample.bin" \
  -F "case_name=IR-2026-001" \
  -F "priority=Normal" \
  -F "note=Uploaded by gateway integration" \
  -F "wait_seconds=5"
```

Possible responses:

- `200 OK`: the scan completed inside the requested wait window
- `202 Accepted`: the scan is still processing
- `401 Unauthorized`: bearer token missing or invalid
- `413 Payload Too Large`: upload exceeded `MASP_UPLOAD_MAX_BYTES`
- `503 Service Unavailable`: no API token is configured

Example `202 Accepted` body:

```json
{
  "accepted": true,
  "completed": false,
  "result_ready": false,
  "recommended_poll_seconds": 2,
  "detail": "Scan accepted and still processing.",
  "wait_seconds_applied": 5,
  "scan": {
    "id": 29,
    "filename": "eicar.com",
    "status": "running",
    "verdict": "pending"
  },
  "links": {
    "status": "http://localhost:8000/api/v1/scans/29",
    "result": "http://localhost:8000/api/v1/scans/29/result",
    "ui": "http://localhost:8000/scans/29"
  }
}
```

The `Location` header points to the status endpoint. MASP also returns `Retry-After`
when a scan is still running.

## Read Scan Status

```bash
curl -H "Authorization: Bearer $MASP_API_TOKEN" \
  "http://localhost:8000/api/v1/scans/29"
```

Status responses include:

- `completed`
- `result_ready`
- `decision`
- `recommended_poll_seconds`
- `scan`
- `queue`
- `engines`
- `engine_results`
- `worker_events`
- `links`

`result_ready=true` means `GET /api/v1/scans/{id}/result` is expected to succeed.

The `engines` object contains aggregate coverage counts. The `engine_results`
array contains compact per-engine observability data while polling:

```json
{
  "engines": {
    "expected": 4,
    "reported": 3,
    "completed": 3,
    "failed": 0,
    "skipped": 0,
    "detections": 0
  },
  "engine_results": [
    {
      "engine_name": "ClamAV",
      "status": "completed",
      "detected": false,
      "duration_ms": 1240,
      "created_at": "2026-07-06 08:21:00+00:00"
    }
  ]
}
```

Use `engine_results[].duration_ms` for per-engine adapter performance analysis
only when `status` is `completed` or `failed`. A `skipped` result is synthetic:
it records coverage/accounting state, not adapter execution time.
Use `worker_events[].duration_ms` to analyze orchestration time inside the
worker processing window:

```json
{
  "worker_events": [
    {
      "event_name": "engine_run",
      "worker_id": "worker-clamav-1",
      "worker_engine_keys": "clamav",
      "engine_name": "ClamAV",
      "duration_ms": 18,
      "created_at": "2026-07-06 08:21:00+00:00"
    },
    {
      "event_name": "finalize",
      "worker_id": "worker-clamav-1",
      "worker_engine_keys": "clamav",
      "engine_name": null,
      "duration_ms": 3,
      "created_at": "2026-07-06 08:21:00+00:00"
    }
  ]
}
```

Use the final result endpoint when you need full raw output, findings, and
details.

The `decision` object is the automation-friendly outcome:

- `wait`: scan is still queued or running
- `allow`: no detection and required engine coverage completed
- `block`: one or more engines detected malicious content, or risk is high
- `review`: result is partial, metadata-only, failed, or elevated but not blocking

Use `decision.action` for workflow routing and `decision.reasons` for audit text.

## Read Final Result

```bash
curl -H "Authorization: Bearer $MASP_API_TOKEN" \
  "http://localhost:8000/api/v1/scans/29/result"
```

Possible responses:

- `200 OK`: normalized result payload
- `404 Not Found`: scan id is unknown
- `409 Conflict`: the scan has not reached a terminal state yet

The `409` response repeats the status payload and includes a `Retry-After` header.

## Integration Notes

- Treat `POST /api/v1/scans` as asynchronous by default
- Use `wait_seconds` only as a convenience for short-running scans
- Prefer polling `links.status` until `result_ready=true`
- Persist the returned `scan.id` in the calling system for audit and traceability
- For size-capped upload-gateway integrations, see "Upload-Gateway Integration
  Pattern (v1)" above
