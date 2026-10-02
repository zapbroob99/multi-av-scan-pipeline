# MASP ICAP Gateway

MASP can accept files over **ICAP** (RFC 3507) in addition to the REST API.
A storage system that already speaks ICAP configures MASP as
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

ICAP carries no file name of its own, so MASP takes it from the encapsulated
HTTP message: the `Content-Disposition` file name of the response, then of the
request (RFC 6266 `filename*` first), then the first part of a multipart upload
body, then the last segment of the request URL when it has an extension (an
upload endpoint such as `POST /api/upload` names the endpoint, not the file).
Without any of these the sample is named `icap_reqmod.bin` or
`icap_respmod.bin`. The name is client-supplied: it is reduced to a bare file
name, bounded, and used only for display and the `file_type` extension check.
The content type comes from the response (RESPMOD) or request (REQMOD) header.

## Decision mapping

| Scan outcome | ICAP reply |
|---|---|
| Completed, verdict allows (`allow`) | allow (`204`, or `200` echo without `Allow: 204`) |
| Completed, uncertain (`review`) | allow (unless `MASP_ICAP_BLOCK_ON_REVIEW=1` or the client profile blocks review) |
| Completed, malicious (`block`) | `200` block |
| Content the client profile does not accept, scanned | `200` block |
| Content the client profile rejects without scanning, or over the profile's size limit | `200` block, no scan, whatever the fail mode |
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
| `MASP_ICAP_SERVICE_CLIENT_KEY` | `legacy-default` | Service client whose default scan profile owns and routes this gateway's scans |
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

Identity is deployment-bound. Set `MASP_ICAP_SERVICE_CLIENT_KEY` to a client
created in **Service Clients**. If multiple consuming systems need distinct
engine profiles or ledger ownership, run separate ICAP instances with unique
listeners/service names and bind each instance to its own client key. Do not
derive client identity from arbitrary ICAP headers or NAT-obscured source IPs.

The key is resolved on every request, exactly as **System > ICAP and SIEM**
shows it beside each gateway: an enabled client with an enabled profile, the
`legacy-default` compatibility client (scans land under "Legacy API / ICAP",
usually because the setting never reached the icap container), or nothing. A
key that names no client, a disabled client or one without an enabled profile
makes every request fail; a fail-closed gateway then blocks every upload, and
the health check reports it as critical. The client's Setup tab names any
gateway reporting under another key.

The bound client's default profile also carries that client's scan policy
(Service Clients > Profile routing > Scan policy): a size limit, accepted
content families, disguised files and what to do with files that could not be
fully assessed. A profile set to block those overrides
`MASP_ICAP_BLOCK_ON_REVIEW` for its client; left at the deployment behaviour,
the environment setting applies. Content the profile rejects without scanning is
answered with a block whatever the fail mode, creates no scan, and is counted as
"Rejected by policy" with an event on System > ICAP and SIEM.

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
