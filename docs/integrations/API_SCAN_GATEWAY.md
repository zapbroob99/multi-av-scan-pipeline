# API Scan Gateway

MASP exposes an authenticated file scan API for service-to-service integrations.
The primary workflow is:

1. Submit a sample with `POST /api/v1/scans`
2. Read the returned `links.status` URL until `result_ready` is `true`
3. Fetch the normalized final payload from `links.result`

## Authentication

Use a bearer token in the `Authorization` header.

```text
Authorization: Bearer <token>
```

Configure one or more tokens with:

- `MASP_API_TOKEN`
- `MASP_API_TOKENS`
- `api.tokens` in MASP settings storage

## Environment

Common API-related settings:

```text
MASP_API_TOKEN=replace-with-a-long-random-token
MASP_API_MAX_WAIT_SECONDS=15
MASP_API_RETRY_AFTER_SECONDS=2
MASP_UPLOAD_MAX_BYTES=0
```

- `MASP_API_MAX_WAIT_SECONDS`: upper bound for client-requested blocking wait time
- `MASP_API_RETRY_AFTER_SECONDS`: recommended poll interval returned in API responses
- `MASP_UPLOAD_MAX_BYTES`: `0` disables the upload limit

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
- `links`

`result_ready=true` means `GET /api/v1/scans/{id}/result` is expected to succeed.

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
