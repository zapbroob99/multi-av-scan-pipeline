# Microsoft Defender via Local CLI

## Identity

- Integration key: `microsoft_defender_local_cli`
- User-facing display name: `Microsoft Defender via local CLI`
- Vendor: Microsoft
- Product: Microsoft Defender Antivirus
- Tested version: TBD in lab; documentation reviewed on 2026-07-03
- Integration method: local PowerShell + `MpCmdRun.exe`
- Support state: `research`

## Scope

- Supported deployment mode: Windows host with Microsoft Defender Antivirus enabled and local administrative execution available for MASP worker runtime.
- Unsupported deployment modes: Linux/macOS workers, remote-only execution, Microsoft Defender for Endpoint cloud-only workflows without local Defender Antivirus scan capability.
- Required license or feature: Microsoft Defender Antivirus available on host; exact Defender for Endpoint licensing requirement depends on deployment and needs lab validation.
- Operating system requirements: Windows. Exact minimum supported versions for MASP integration should be validated in lab.
- Network direction: local execution on MASP node; optional outbound Microsoft update/cloud connectivity for signature updates and MAPS validation.
- Required ports: none for local scan execution; outbound connectivity may be needed for updates/cloud reputation outside MASP scope.

## Documentation

- Official documentation:
  `https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus`
  `https://learn.microsoft.com/en-us/powershell/module/defender/start-mpscan`
  `https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus`
- Vendor notes: none yet.
- Internal lab notes: none yet.
- Last reviewed: 2026-07-03

## Product Notes From Documentation

- `MpCmdRun.exe` is the Microsoft-supported command-line tool for running scans, managing security intelligence updates, and other local Defender operations.
- `MpCmdRun.exe` typically runs from one of these locations:
  `C:\Program Files\Windows Defender`
  `C:\ProgramData\Microsoft\Windows Defender\Platform\<platform-version>`
- Microsoft documents `MpCmdRun.exe -Scan -ScanType 2` for full scan execution.
- Microsoft documents `-ScanType` values:
  `1` quick
  `2` full
  `3` custom
- Microsoft documents `Start-MpScan` with:
  `-ScanType FullScan|QuickScan|CustomScan`
  `-ScanPath <path>` for file/folder/custom path scanning
- Microsoft documents `Get-MpComputerStatus` as the primary local status cmdlet and exposes fields such as:
  `AMServiceEnabled`
  `AntivirusEnabled`
  `AntivirusSignatureVersion`
  `RealTimeProtectionEnabled`

## Configuration Schema

| Key | Label | Type | Required | Secret | Default | Validation | Help |
| --- | --- | --- | --- | --- | --- | --- | --- |
| execution_mode | Execution mode | select | Yes | No | powershell | `powershell` or `mpcmdrun` | Prefer PowerShell for status checks; keep `MpCmdRun.exe` fallback for scan execution. |
| powershell_path | PowerShell path | text | No | No | powershell.exe | Existing executable path | Override when the worker needs a fully qualified PowerShell path. |
| mpcmdrun_path | MpCmdRun path | text | No | No | auto | Existing file path or `auto` | Use `auto` to resolve the latest Defender platform path. |
| default_scan_type | Default scan type | select | Yes | No | custom | `custom`, `quick`, or `full` | MASP file scanning should prefer `custom`. |
| timeout_seconds | Timeout seconds | number | Yes | No | 900 | Integer `30-86400` | Upper bound needs lab validation for large samples. |
| update_before_scan | Update signatures before scan | boolean | Yes | No | false | boolean | Optional signature refresh before scanning. |
| require_real_time_enabled | Require real-time protection | boolean | Yes | No | true | boolean | Fail or warn when Defender is installed but not actively protecting. |

## Health Check

What the health check proves:

- [x] Network connectivity
  Not applicable for local execution.
- [ ] Authentication
  Local process execution and required privileges still need lab validation.
- [x] Correct service or endpoint
  `Get-MpComputerStatus` should confirm Defender service presence and active product state.
- [x] Scan capability
  Health check should verify that Defender service is enabled and scan command is callable.
- [ ] License or feature availability
  Needs lab validation because local Defender behavior differs across Windows editions and management states.
- [x] Version or signature state, if exposed
  `Get-MpComputerStatus` exposes engine/product/signature fields.

Planned health check sequence:

1. Verify worker is running on Windows.
2. Resolve `powershell.exe`.
3. Run `Get-MpComputerStatus`.
4. Parse and validate at minimum:
   `AMServiceEnabled == True`
   `AntivirusEnabled == True`
5. Capture useful status metadata:
   `AMEngineVersion`
   `AMProductVersion`
   `AntivirusSignatureVersion`
   `AntivirusSignatureAge`
   `RealTimeProtectionEnabled`
6. If configured, resolve `MpCmdRun.exe` and verify it is executable.

Expected healthy response:

```text
Get-MpComputerStatus returns an object and confirms AMServiceEnabled=True and AntivirusEnabled=True.
```

Expected failure responses:

```text
PowerShell command not found
Get-MpComputerStatus cmdlet unavailable
Defender service disabled
AntivirusEnabled=False
Access denied / insufficient privilege
MpCmdRun.exe not found when execution_mode requires it
```

## Scan Flow

Planned implementation path:

1. Resolve local execution mode.
2. For health/status, prefer `Get-MpComputerStatus`.
3. For file scanning, start with one of these documented flows:
   `Start-MpScan -ScanType CustomScan -ScanPath <sample-path>`
   or
   `MpCmdRun.exe -Scan -ScanType 3 -File <sample-path>`
4. Record command duration and raw stdout/stderr or PowerShell error output.
5. Determine whether Microsoft Defender exposes the detection result directly in command output or whether MASP must query post-scan threat state.
6. If post-scan threat lookup is required, add a second documented retrieval step after lab validation.
7. Normalize result into `EngineResultInput`.

Important unresolved point:

- The safest detection source still needs lab confirmation.
- `Start-MpScan` documentation confirms scan start semantics, but does not by itself document a simple detection-oriented return payload.
- `MpCmdRun.exe` documentation confirms scan return codes, but a return code of `0` can mean either no malware found or malware found and successfully remediated.
- Because of that ambiguity, MASP must not treat `returncode == 0` as clean without secondary evidence.

## Detection Semantics

Current conservative mapping for research phase:

| Vendor result | MASP status | MASP detected | Severity | Confidence | Notes |
| --- | --- | --- | --- | --- | --- |
| Scan executed, no threat evidence, clean state confirmed by secondary evidence | completed | false | info | 100 | Requires verified clean interpretation path. |
| Threat found and threat name/verdict available | completed | true | high | 90 | Threat name should populate `signature`. |
| Scan command returned ambiguous success without secondary evidence | failed | false | info | 0 | Do not misclassify as clean. |
| Access denied / privilege failure | failed | false | info | 0 | Health check should also surface this. |
| Timeout | failed or skipped | false | info | 0 | Final rule should match other local engine behavior. |
| Cmdlet/command unavailable | skipped | false | info | 0 | Not configured or unsupported worker environment. |
| Unexpected output / parse failure | failed | false | info | 0 | Preserve raw output for analyst/debugging. |

## Normalized Findings

Expected finding fields:

- title: Microsoft threat name if available
- type: `antivirus_signature` or a more specific Defender finding type after lab validation
- source: `Microsoft Defender`
- severity: `high` for confirmed malware, `medium` only if Microsoft exposes a lower-confidence suspicious class and lab confirms it
- confidence: default `90` for confirmed signature-based detection
- action: `detected` or Microsoft-specific remediation state after validation
- category: `malware`, `test_file`, or vendor-specific mapping
- tags: `["av", "signature", "microsoft_defender"]`
- evidence: minimal useful proof such as threat name, remediation state, command output, and file path
- vendor_details: raw Microsoft fields used for normalization

## Required Fixtures

- [ ] `clean.response`
- [ ] `detected_eicar.response`
- [ ] `auth_failure.response`
- [ ] `unavailable.response`
- [ ] `malformed.response`

Additional fixtures:

- [ ] remediated detection response
- [ ] ambiguous success response with no detection payload
- [ ] real-time protection disabled state
- [ ] signature outdated state
- [ ] suspicious/heuristic response, if product exposes one

Suggested fixture capture sources:

- `Get-MpComputerStatus` healthy output
- `Get-MpComputerStatus` disabled/degraded output
- `Start-MpScan` output and errors
- `MpCmdRun.exe` stdout/stderr and return codes
- Any post-scan threat retrieval output used to disambiguate clean vs remediated detection

## Security Notes

- Secret fields: none expected for local execution.
- Redaction rules: redact local usernames, hostnames, tenant identifiers, or filesystem locations if fixtures leave the lab environment.
- Sensitive headers: not applicable.
- Sensitive response fields: local file paths and host metadata may need trimming in fixtures and reports.

## Definition Of Done

- [x] Spec completed.
- [ ] Config schema implemented.
- [ ] Health check implemented.
- [ ] Scan flow implemented.
- [ ] Parser fixtures added.
- [ ] Parser tests added.
- [ ] Secrets redacted.
- [ ] Report/export output verified.
- [ ] Support matrix updated.
