# Microsoft Defender Fixture Plan

This plan defines the fixture set required before `Microsoft Defender via local CLI` can move from `research` to `lab`.

## Goal

We need enough real output samples to answer two questions safely:

1. What does Microsoft Defender return in each important operating state?
2. Which signals are reliable enough for MASP to classify as clean, detected, skipped, or failed?

The most important risk is false clean classification. Microsoft documents scan start commands, but documented return behavior alone is not enough to distinguish clean from "detected and remediated" in every case. Fixtures must close that gap.

## Fixture Storage

Store fixtures under:

```text
tests/fixtures/engines/microsoft_defender_local_cli/
```

Recommended files:

```text
README.md
status_healthy.txt
status_access_denied.txt
status_disabled.txt
status_signature_outdated.txt
scan_clean_start_mpscan.txt
scan_clean_mpcmdrun.txt
scan_detected_eicar_start_mpscan.txt
scan_detected_eicar_mpcmdrun.txt
scan_detected_eicar_postscan_status.txt
scan_ambiguous_success.txt
scan_access_denied.txt
scan_timeout.txt
scan_command_not_found.txt
scan_malformed_output.txt
```

Use `.txt` or `.json` according to the real command output. Preserve the original format whenever possible.

## Required Fixture Set

### 1. Healthy status fixture

Command source:

- `Get-MpComputerStatus`

Purpose:

- Confirms which fields are consistently present.
- Provides the baseline for engine health.

Must capture:

- `AMServiceEnabled`
- `AntivirusEnabled`
- `AMEngineVersion`
- `AMProductVersion`
- `AntivirusSignatureVersion`
- `AntivirusSignatureAge`
- `RealTimeProtectionEnabled`

Target file:

- `status_healthy.txt`

### 2. Defender disabled or degraded status fixture

Command source:

- `Get-MpComputerStatus`

Purpose:

- Teaches MASP how to recognize a host where Defender is installed but not usable.

Examples:

- service disabled
- antivirus disabled
- real-time protection disabled

Target files:

- `status_disabled.txt`
- optionally `status_realtime_disabled.txt`

### 3. Access denied status fixture

Command source:

- `Get-MpComputerStatus`

Purpose:

- Confirms the exact failure shape when the MASP worker can reach the cmdlet but lacks sufficient privilege.

Observed on local validation:

- `Get-MpComputerStatus : Access denied`
- `HRESULT 0x80041003`

Target file:

- `status_access_denied.txt`

### 4. Signature outdated status fixture

Command source:

- `Get-MpComputerStatus`

Purpose:

- Lets MASP show a warning or degraded health when signatures are stale.

Target file:

- `status_signature_outdated.txt`

### 5. Clean scan fixture

Command source:

- `Start-MpScan -ScanType CustomScan -ScanPath <sample>`
- `MpCmdRun.exe -Scan -ScanType 3 -File <sample>`

Purpose:

- Captures what a true clean path looks like.

Must record:

- command used
- stdout
- stderr
- return code
- whether a second command was needed to confirm no threat

Target files:

- `scan_clean_start_mpscan.txt`
- `scan_clean_mpcmdrun.txt`

### 6. EICAR detection fixture

Command source:

- same scan commands as clean path
- plus any follow-up command needed to retrieve threat or remediation evidence

Purpose:

- Establishes the minimal reliable proof for `detected=True`.

Must record:

- direct scan output
- return code
- post-scan threat/status output
- threat name if present
- remediation state if present

Target files:

- `scan_detected_eicar_start_mpscan.txt`
- `scan_detected_eicar_mpcmdrun.txt`
- `scan_detected_eicar_postscan_status.txt`

### 7. Ambiguous success fixture

Purpose:

- Captures cases where command success does not prove a clean result.

This fixture matters because Microsoft documents that one success code can represent more than one outcome for `MpCmdRun.exe`.

Target file:

- `scan_ambiguous_success.txt`

### 8. Access denied / privilege failure fixture

Purpose:

- Distinguishes misconfiguration from malware-related outcomes.

Examples:

- PowerShell execution denied
- Defender cmdlet access denied
- `MpCmdRun.exe` requires elevation

Target file:

- `scan_access_denied.txt`

### 9. Command unavailable fixture

Purpose:

- Shows how the worker should behave when the host is not a valid Defender node.

Examples:

- `powershell.exe` missing
- `Get-MpComputerStatus` cmdlet unavailable
- `MpCmdRun.exe` not found

Target file:

- `scan_command_not_found.txt`

### 10. Timeout fixture

Purpose:

- Defines the error shape for long-running or hung commands.

Target file:

- `scan_timeout.txt`

### 11. Malformed or unexpected output fixture

Purpose:

- Verifies parser resilience when output is truncated, localized unexpectedly, or otherwise different from known shapes.

Target file:

- `scan_malformed_output.txt`

## Capture Checklist

For every fixture, record:

- Windows version
- Defender product version
- Engine version
- Signature version
- Command line used
- Exit code
- stdout
- stderr
- Whether MASP should classify the outcome as `completed`, `skipped`, or `failed`
- Whether MASP should classify the outcome as `detected=True/False`

## Redaction Rules

Before committing fixtures:

- Replace hostnames with placeholders
- Replace usernames with placeholders
- Replace non-test sample paths when possible
- Remove tenant or organization identifiers
- Preserve the exact values needed for parser behavior

Do not redact:

- threat names
- documented state fields
- return codes
- generic sample paths when they are part of the parser contract

## Exit Criteria

Fixture collection is complete enough to start implementation when:

- healthy status fixture exists
- degraded status fixture exists
- clean scan fixture exists
- EICAR detection fixture exists
- ambiguous success fixture exists
- access denied fixture exists
- timeout fixture exists
- at least one post-scan threat evidence fixture exists if scan output alone is ambiguous

At that point, we can implement parser tests and health check logic without guessing.
