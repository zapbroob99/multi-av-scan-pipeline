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

| Integration | Vendor | Product | Method | State | Notes |
| --- | --- | --- | --- | --- | --- |
| Static Metadata | MASP | Built-in metadata analyzer | local | supported | Extracts hashes, size, content type, and storage metadata. Not a detection engine. |
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
- Generic ICAP, generic REST, and custom command engines are internal engineering tools only unless a future product decision explicitly changes this.
- Implemented `lab` or `blocked` integrations may be exposed for controlled
  validation with an explicit support-state warning. Production operators must
  enable only integrations approved for their license, network, and acceptance
  test scope.
