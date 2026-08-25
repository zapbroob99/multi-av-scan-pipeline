# MASP Engine Integration Standard

MASP must treat vendor engines as product-grade integrations, not as user-defined custom parsers. Users should select a supported vendor/product integration and provide only the configuration required for that product. Generic protocol details such as ICAP, REST, CLI execution, retries, parsing, and normalization stay inside MASP.

## Core Rule

An engine is only shown as supported when it is implemented against a specific product, integration method, and tested behavior.

Examples:

- Supported: `Microsoft Defender via local CLI`
- Supported: `ClamAV via clamd TCP`
- Supported: `YARA via local CLI`
- Not enough: `ESET`
- Not enough: `Trellix`
- Not enough: `Generic ICAP`

For commercial products, the integration target must be explicit:

- Vendor
- Product name
- Product version or tested version range
- Integration method
- Required license or feature
- Official documentation source
- Lab test status

## User-Facing Model

The UI should show vendor/product integrations, not low-level protocol adapters.

Good user-facing labels:

- `ESET Server Security via ICAP`
- `Trellix Advanced Threat Defense via REST API`
- `Microsoft Defender via local CLI`
- `Sophos Protection for Linux via local CLI`

Avoid user-facing labels like:

- `Generic ICAP`
- `Generic REST`
- `Custom command parser`
- `Vendor profile`

## Internal Architecture

Vendor adapters may share transport and utility code.

Recommended structure:

```text
app/engines/
  base.py
  clamav.py
  yara_engine.py
  static_metadata.py
  vendors/
    microsoft_defender_cli.py
    eset_server_security_icap.py
    trellix_atd_api.py

app/services/
  icap_client.py
  http_client.py
  command_runner.py
  findings.py

tests/fixtures/engines/
  eset_server_security_icap/
  trellix_atd_api/
```

Vendor-specific adapter files own product behavior:

- Config schema
- Health check
- Scan flow
- Vendor response parsing
- Detection semantics
- Normalized findings
- Error mapping

Shared services own reusable mechanics:

- ICAP request/response handling
- HTTP request/retry/timeout handling
- Local command execution
- JSON/XML parsing helpers
- Common finding/evidence constructors

## Capability and Submission-Source Eligibility

Every adapter must declare capabilities in the registry instead of relying on
endpoint-specific vendor checks. At minimum, document and implement:

- Whether it is a detection engine.
- Supported input modes and operating-system platforms.
- File-upload, hash-lookup, and file-hash-scan support.
- Archive support and network requirements.
- Execution model and worker/deployment placement.
- Whether a call consumes a paid token, licensed quota, or another externally
  metered resource (`consumes_external_quota`).

REST and ICAP automation must exclude adapters that consume external quota
before jobs are created, with worker/finalization checks as defense in depth.
Interactive/manual workflows may use them when explicitly initiated and
licensed. New adapters inherit this source policy from capabilities; routes,
workers, or reports must not hard-code a vendor name to enforce it.

## Required Adapter Contract

Every engine adapter must produce `EngineResultInput` with these fields normalized:

- `engine_name`
- `engine_version`
- `signature_version`
- `status`
- `detected`
- `signature`
- `severity`
- `confidence`
- `raw_output`
- `error_message`
- `duration_ms`
- `details_json`
- `findings_json`

Allowed `status` values:

- `completed`: Engine ran and produced a clean or detected result.
- `skipped`: Engine was configured but could not run due to a known unavailable dependency or reachable-but-not-ready service.
- `failed`: Engine ran or was attempted but hit an unexpected error.

`detected` must only be true when the vendor result clearly indicates a malicious, infected, blocked, or matched verdict according to documented semantics or verified lab output.

## Required Integration Spec

Each vendor integration must have a short spec before it is implemented.

Required fields:

- Integration key
- User-facing display name
- Vendor
- Product
- Tested product version
- Integration method
- Required license/features
- Official documentation links or internal document references
- Authentication model
- Network direction and required ports
- TLS/certificate requirements
- File size limits
- Timeout behavior
- Rate limits or concurrency limits
- Supported deployment modes
- Known unsupported modes
- Submission-source eligibility (`manual`, `api`, `icap`)
- External token/quota consumption

## Config Schema Requirements

The adapter must define exactly which fields the user can configure.

Each config field needs:

- Key
- Label
- Type
- Required/optional
- Default value, if any
- Secret flag, if sensitive
- Validation rule
- Help text

Examples:

```text
host: required string
port: required integer
service_name: required string
timeout_seconds: required integer, default 60
api_token: required secret string
verify_tls: required boolean, default true
```

Sensitive values must not be written into `raw_output`, `details_json`, logs, reports, CSV export, or HTML pages.

## Health Check Requirements

Health check must verify the engine is usable, not only that a host is reachable.

A valid health check should confirm as many of these as the product supports:

- Network connectivity
- Authentication success
- Correct service or endpoint
- Product version or service banner
- Scan capability enabled
- License or feature availability
- Signature/database state when exposed by product

Health check output must include:

- `ok`
- `status`
- `detail`

The `detail` message should be actionable for the operator.

## Detection Semantics

Before implementing parser logic, document how the product reports:

- Clean result
- Detected/infected result
- Blocked/quarantined result
- Suspicious/PUA/adware result
- Pending/submitted result
- Timeout
- Auth failure
- Service unavailable
- Malformed response

Severity mapping must be conservative. If the vendor does not expose severity, use stable defaults:

- Known malware/infected: `high`
- Suspicious or PUA: `medium`
- Clean: `info`
- Adapter failure: `info`, with `status=failed` or `status=skipped`

Confidence mapping must be documented per adapter. If no vendor confidence exists:

- Signature-based detection: `90`
- Rule match: `85`
- Suspicious/heuristic result: `60-75`
- Clean result: `100`
- Failed/skipped: `0`

## Findings Requirements

Detected results should populate `findings_json` using normalized findings.

Each finding should include:

- `title`
- `type`
- `source`
- `severity`
- `confidence`
- `action`
- `category`
- `tags`
- `evidence`
- `vendor_details`

The evidence section should include the smallest useful proof, not the whole raw response unless necessary.

## Raw Output Rules

`raw_output` is for analyst troubleshooting and parser verification.

Rules:

- Preserve vendor response enough to debug adapter behavior.
- Redact secrets and tokens.
- Avoid adding MASP-only interpretation to raw vendor output.
- Store large structured responses in `raw_output` only when needed.
- CSV export should stay summary-focused; full raw output belongs in JSON export and report detail views.

## Required Test Fixtures

Every commercial/vendor adapter needs fixtures before it can be marked supported.

Minimum fixture set:

- Clean sample response
- EICAR or known test detection response
- Auth failure response
- Timeout or service unavailable response
- Malformed or unexpected response

Additional fixtures when relevant:

- PUA/adware response
- Heuristic/suspicious response
- File too large response
- License expired response
- TLS/certificate failure
- Rate limit response

Fixtures should not contain secrets, customer identifiers, internal hostnames, or proprietary data that cannot be committed.

## Support States

Use these states in documentation and planning:

- `supported`: Implemented, documented, and tested with fixtures or lab access.
- `lab`: Implemented against a real product but still under validation.
- `planned`: Selected for future work; no production claim.
- `research`: Documentation is being reviewed.
- `blocked`: Waiting on license, product access, docs, or sample responses.
- `not_supported`: Known unsuitable or intentionally excluded.

Only `supported` integrations should appear as normal addable engines in production UI.

## Definition Of Done

An integration is done only when all items are true:

- Integration spec exists.
- Config schema exists and validates user input.
- Health check is implemented.
- Scan flow is implemented.
- Clean/detected/error semantics are documented.
- Normalized `EngineResultInput` is produced.
- Findings are populated for detections.
- Secrets are redacted.
- Fixtures cover minimum cases.
- Parser tests pass.
- UI copy is product-specific.
- Support matrix is updated.

## Review Checklist

Before merging a vendor engine, review:

- Are we using official docs or verified lab responses?
- Is the product/version explicit?
- Can a clean result be confused with an error?
- Can an error be confused with clean?
- Can a blocked/quarantined result be missed?
- Are secrets redacted everywhere?
- Does health check prove scan readiness?
- Are timeouts and unavailable states visible to users?
- Does the adapter avoid making unsupported malware-family claims?
- Does the report/export output remain analyst-friendly?
