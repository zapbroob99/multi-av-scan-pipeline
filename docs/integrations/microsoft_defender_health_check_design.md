# Microsoft Defender Health Check Design

This document describes how MASP should decide whether `Microsoft Defender via local CLI` is usable on a given worker node.

## Goal

The health check must answer:

- Is this worker a valid Windows node for Defender execution?
- Is Microsoft Defender Antivirus installed and enabled?
- Can MASP run the required local commands?
- Is scan execution likely to succeed?

The health check must not claim success when Defender is merely present but unavailable for scanning.

## Non-Goals

- The health check does not prove that every sample will scan successfully.
- The health check does not replace full lab validation of detection semantics.
- The health check does not evaluate cloud reputation or signature quality.

## Inputs

Expected config:

- `execution_mode`
- `powershell_path`
- `mpcmdrun_path`
- `default_scan_type`
- `timeout_seconds`
- `update_before_scan`
- `require_real_time_enabled`

## Output Contract

Return:

```text
{
  "ok": <bool>,
  "status": <short state>,
  "detail": <operator-facing message>
}
```

Recommended status values:

- `available`
- `degraded`
- `disabled`
- `unsupported`
- `not configured`
- `unavailable`
- `permission denied`
- `unexpected`

## Decision Flow

### Step 1. Verify operating system

Check:

- worker is running on Windows

Outcomes:

- not Windows -> `ok=false`, `status=unsupported`
- Windows -> continue

Reason:

- this adapter is local-execution only

### Step 2. Resolve PowerShell

Check:

- configured `powershell_path` exists, or `powershell.exe` is resolvable on PATH

Outcomes:

- not found -> `ok=false`, `status=not configured`
- found -> continue

Reason:

- `Get-MpComputerStatus` is the primary status source

### Step 3. Run `Get-MpComputerStatus`

Command shape:

```powershell
Get-MpComputerStatus | ConvertTo-Json -Compress
```

Implementation note:

- prefer JSON conversion to reduce parser brittleness
- force non-interactive execution
- capture stdout, stderr, and exit code

Outcomes:

- command not found / module unavailable -> `ok=false`, `status=unavailable`
- access denied -> `ok=false`, `status=permission denied`
- timeout -> `ok=false`, `status=unavailable`
- malformed JSON/output -> `ok=false`, `status=unexpected`
- valid status object -> continue

### Step 4. Validate critical status fields

Required minimum fields:

- `AMServiceEnabled`
- `AntivirusEnabled`

Useful additional fields:

- `RealTimeProtectionEnabled`
- `AMEngineVersion`
- `AMProductVersion`
- `AntivirusSignatureVersion`
- `AntivirusSignatureAge`

Decision rules:

- `AMServiceEnabled != True` -> `ok=false`, `status=disabled`
- `AntivirusEnabled != True` -> `ok=false`, `status=disabled`
- `require_real_time_enabled == true` and `RealTimeProtectionEnabled != True` -> `ok=false`, `status=degraded`
- otherwise continue

### Step 5. Resolve `MpCmdRun.exe` when required

When to check:

- always, if `execution_mode=mpcmdrun`
- optionally, if MASP wants fallback availability even in PowerShell mode

Resolution strategy:

1. use configured `mpcmdrun_path` if not `auto`
2. otherwise check:
   `C:\ProgramData\Microsoft\Windows Defender\Platform\<latest>\MpCmdRun.exe`
3. fallback:
   `C:\Program Files\Windows Defender\MpCmdRun.exe`

Outcomes:

- not found and required -> `ok=false`, `status=not configured`
- found -> continue

### Step 6. Evaluate signature freshness

Check:

- `AntivirusSignatureAge`

Policy:

- exact threshold should be configurable later
- initial recommendation:
  `<= 3` days -> healthy
  `> 3` days -> degraded

Outcome:

- stale signatures should not necessarily block the engine
- stale signatures should surface as `ok=true`, `status=degraded` unless product behavior or customer policy requires blocking

### Step 7. Final health result

Healthy state:

- `ok=true`, `status=available`
- detail includes engine version, product version, signature version, and real-time state

Degraded state examples:

- signatures stale
- real-time disabled when policy requires it
- secondary scan executable missing but primary mode still usable

Failure state examples:

- not Windows
- PowerShell unavailable
- Defender service disabled
- Antivirus disabled
- permission denied
- status command malformed

## Detail Message Design

The `detail` field should be actionable and compact.

Good examples:

- `Defender available. Engine 1.1.x, product 4.x, signatures 1.429.x, real-time protection enabled.`
- `Defender service is installed but disabled on this node.`
- `Get-MpComputerStatus succeeded, but real-time protection is disabled.`
- `PowerShell was found, but the Defender module command failed with access denied.`
- `MpCmdRun.exe could not be resolved from configured path or default Defender locations.`

Avoid:

- raw stack traces as the primary message
- ambiguous messages like `command failed`

## Logging And Evidence

Store in `details_json`:

- resolved `powershell_path`
- resolved `mpcmdrun_path`, if checked
- parsed status fields used for health evaluation
- command exit code
- stderr or PowerShell error summary

Do not store secrets. This adapter should not require secrets for local mode.

## Mapping To MASP UI

Suggested UI tones:

- `available` -> success
- `degraded` -> neutral or warning
- `disabled` -> danger
- `unsupported` -> neutral
- `not configured` -> neutral
- `permission denied` -> danger
- `unexpected` -> danger

The UI detail should help the operator answer:

- Is this the wrong node?
- Is Defender disabled?
- Is the service healthy but stale?
- Does MASP need elevation or a path fix?

## Open Questions For Lab Validation

- Does `Get-MpComputerStatus` always exist in all supported Windows/Defender combinations we care about?
- Is local admin required for all scan modes or only some?
- Is real-time protection a hard requirement for local custom scanning?
- Which health state should be used when signatures are stale but scanning still works?
- Should `MpCmdRun.exe` be mandatory even if PowerShell scan flow works?

## Exit Criteria

The health check design is ready to implement when:

- fixture plan has healthy, disabled, permission denied, timeout, and malformed status samples
- we confirm the JSON conversion path for `Get-MpComputerStatus`
- we decide whether `MpCmdRun.exe` is mandatory or fallback-only in v1
