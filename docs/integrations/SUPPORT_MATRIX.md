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
| ClamAV via clamd | Cisco Talos | ClamAV clamd | TCP clamd protocol | supported | Preferred ClamAV runtime in Docker/on-prem deployments. |
| ClamAV via clamscan | Cisco Talos | ClamAV CLI | local CLI | supported | Local fallback when `clamscan` exists on PATH. |
| YARA via local CLI | VirusTotal/community | YARA | local CLI | supported | Requires local YARA binary and local rule files. |

## Candidate Commercial Integrations

These are not supported yet. They require official documentation review and product/lab validation before appearing as addable engines in production UI.

| Candidate | Vendor | Product | Likely Method | State | Required Before Implementation |
| --- | --- | --- | --- | --- | --- |
| Microsoft Defender via local CLI | Microsoft | Microsoft Defender Antivirus | PowerShell/CLI | lab | Adapter implemented and locally validated with healthy status, clean scan, and EICAR detection fixtures. Still needs broader failure/timeout fixtures before `supported`. |
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
- Generic ICAP, generic REST, and custom command engines are internal engineering tools only unless a future product decision explicitly changes this.
- UI should not expose commercial vendor integrations until they are at least `lab` quality, and production builds should only show `supported` engines by default.
