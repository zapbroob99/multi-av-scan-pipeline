# MASP ICAP Gateway

MASP can accept files over **ICAP** (RFC 3507) in addition to the REST API.
A storage system (e.g. storage client) that already speaks ICAP configures MASP as
a generic ICAP service in its management console — no custom client code — and
MASP answers **allow** or **block** for each file before the upload is stored.

The ICAP gateway is a second entry point in front of the same scan pipeline
(same engines, same decision logic, same database) as the REST API. It does not
replace the REST API.

## How it works

1. The storage system sends the file to MASP over ICAP (`REQMOD` for uploads,
   `RESPMOD` for served content — both are supported).
2. MASP stores the bytes, creates a scan (`source=icap`), and runs the enabled
   engines through the normal worker queue.
3. MASP waits up to `MASP_ICAP_WAIT_SECONDS` for a verdict and replies:
   - **allow** → `204 No Content` when the client offered `Allow: 204` (or
     sent a preview); otherwise the original message is echoed back unchanged
     in a `200 OK` (RFC 3507 §4.6 forbids a bare `204` in that case).
   - **block** → `200 OK` carrying a replacement `HTTP 403` response.

ICAP-submitted scans appear in the **API Ledger** (`source=icap`), alongside
REST submissions.

## Decision mapping

| Scan outcome | ICAP reply |
|---|---|
| Completed, verdict allows (`allow`) | allow (`204`, or `200` echo without `Allow: 204`) |
| Completed, uncertain (`review`) | allow (unless `MASP_ICAP_BLOCK_ON_REVIEW=1`) |
| Completed, malicious (`block`) | `200` block |
| Did not finish within the wait window | **fail-closed:** `200` block |
| File over the size cap | **fail-closed:** `200` block |
| Scan/orchestration error | **fail-closed:** `200` block |

Fail-closed is the default: if MASP cannot get a definitive clean answer, it
blocks. Set `MASP_ICAP_FAIL_MODE_CLOSED=0` to fail-open (allow on timeout/error)
instead — the scan still completes in the background and is visible in MASP.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MASP_ICAP_HOST` | `0.0.0.0` | Bind address |
| `MASP_ICAP_PORT` | `1344` | Bind port (ICAP standard) |
| `MASP_ICAP_SERVICE_NAME` | `masp` | Service path (`icap://host:1344/masp`) |
| `MASP_ICAP_WAIT_SECONDS` | `30` | Max seconds to hold the connection for a verdict |
| `MASP_ICAP_MAX_BYTES` | falls back to `MASP_UPLOAD_MAX_BYTES` | Size cap; over-cap is fail-closed |
| `MASP_ICAP_FAIL_MODE_CLOSED` | `1` | `1` = block on timeout/error, `0` = allow |
| `MASP_ICAP_BLOCK_ON_REVIEW` | `0` | `1` = also block uncertain verdicts |
| `MASP_ICAP_ALLOWED_IPS` | (empty) | Comma-separated client IP allowlist; empty = allow all |
| `MASP_ICAP_PREVIEW_BYTES` | `0` | Preview size advertised in OPTIONS |

### Authentication

ICAP has no standard auth. Trust is network-level: run the gateway on a private
network/subnet and, if needed, restrict clients with `MASP_ICAP_ALLOWED_IPS`.
There is no bearer token as in the REST API.

## Running it

Docker (opt-in `icap` profile, shares the DB and storage volume with `app`):

```bash
docker compose --profile linux-worker --profile icap up --build
```

Standalone:

```bash
python -m app.icap.server
```

## Testing locally

With `c-icap-client` (from the c-icap-client package):

```bash
# Clean file -> ICAP 204 (allow), assuming a worker completes the scan in time
c-icap-client -i 127.0.0.1 -p 1344 -s masp -f clean.bin -req http://x/clean.bin

# EICAR file -> ICAP 200 block
c-icap-client -i 127.0.0.1 -p 1344 -s masp -f eicar.com -req http://x/eicar.com

# Capabilities handshake
c-icap-client -i 127.0.0.1 -p 1344 -s masp -w 0
```

If the Defender/ClamAV workers are stopped so the scan cannot finish, the reply
is a fail-closed `200` block within `MASP_ICAP_WAIT_SECONDS`.

## Notes / limits (v1)

- Preview is not advertised by default (`MASP_ICAP_PREVIEW_BYTES=0`): AV needs
  the whole payload, so a preview only adds a `100 Continue` round trip. If a
  client previews anyway, MASP pulls the full file before deciding — there is no
  early-allow from a partial preview. Set `MASP_ICAP_PREVIEW_BYTES` above `0`
  only if a client requires a preview to be offered.
- Unsupported methods get `405 Method Not Allowed`; unparseable messages get
  `400 Bad Request`. All responses (including these) carry an `ISTag`.
- ICAP archive uploads create a batch like REST archive uploads, but the
  `/api/v1/batches` endpoints are REST-scoped; inspect ICAP archives via the
  API Ledger.
- The ICAP concurrency ceiling has not been load-tested yet; size it with a
  ramp like the REST synchronous profile before quoting figures.
