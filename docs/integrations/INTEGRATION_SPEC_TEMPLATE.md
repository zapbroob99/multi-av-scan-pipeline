# Integration Spec Template

Copy this file when starting a new vendor/product integration.

## Identity

- Integration key:
- User-facing display name:
- Vendor:
- Product:
- Tested version:
- Integration method:
- Support state: `research`

## Scope

- Supported deployment mode:
- Unsupported deployment modes:
- Required license or feature:
- Operating system requirements:
- Network direction:
- Required ports:

## Registry Capabilities

- Detection engine: `yes/no`
- Input modes:
- Supported platforms:
- Execution model:
- Supports file upload: `yes/no`
- Supports hash lookup: `yes/no`
- Supports file-hash scan: `yes/no`
- Supports archives: `yes/no`
- Requires network: `yes/no`
- Consumes external token/quota: `yes/no`
- Eligible submission sources: `manual/api/icap`
- Source exclusions and reason:

## Documentation

- Official documentation:
- Vendor notes:
- Internal lab notes:
- Last reviewed:

## Configuration Schema

| Key | Label | Type | Required | Secret | Default | Validation | Help |
| --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |  |  |

## Health Check

What the health check proves:

- [ ] Network connectivity
- [ ] Authentication
- [ ] Correct service or endpoint
- [ ] Scan capability
- [ ] License or feature availability
- [ ] Version or signature state, if exposed

Expected healthy response:

```text
TBD
```

Expected failure responses:

```text
TBD
```

## Scan Flow

Describe the exact scan/submission flow:

1. TBD

## Detection Semantics

| Vendor result | MASP status | MASP detected | Severity | Confidence | Notes |
| --- | --- | --- | --- | --- | --- |
| Clean | completed | false | info | 100 |  |
| Detected | completed | true | high | 90 |  |
| Auth failure | failed | false | info | 0 |  |
| Timeout | skipped/failed | false | info | 0 |  |
| Malformed response | failed | false | info | 0 |  |

## Normalized Findings

Expected finding fields:

- title:
- type:
- source:
- severity:
- confidence:
- action:
- category:
- tags:
- evidence:
- vendor_details:

## Required Fixtures

- [ ] `clean.response`
- [ ] `detected_eicar.response`
- [ ] `auth_failure.response`
- [ ] `unavailable.response`
- [ ] `malformed.response`

Additional fixtures:

- [ ] PUA/adware response
- [ ] suspicious/heuristic response
- [ ] file too large response
- [ ] license expired response
- [ ] TLS/certificate failure
- [ ] rate limit response

## Security Notes

- Secret fields:
- Redaction rules:
- Sensitive headers:
- Sensitive response fields:

## Definition Of Done

- [ ] Spec completed.
- [ ] Config schema implemented.
- [ ] Registry capabilities and source eligibility implemented.
- [ ] Health check implemented.
- [ ] Scan flow implemented.
- [ ] Parser fixtures added.
- [ ] Parser tests added.
- [ ] Secrets redacted.
- [ ] Report/export output verified.
- [ ] Support matrix updated.
