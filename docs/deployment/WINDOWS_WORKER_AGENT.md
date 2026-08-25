# MASP Windows Worker Agent

## Scope and support state

The Windows agent executes Microsoft Defender locally while all orchestration
stays on the MASP server. It uses outbound HTTPS only and receives neither a
PostgreSQL credential nor a shared-storage mount. The current implementation is
`lab`: service packaging and automated lifecycle tooling exist, but a signed
release and the real-host acceptance matrix must pass before production support.

## Security model

- The agent enrolls with a short-lived operator-provided bootstrap token.
- MASP returns the node credential once and stores only its SHA-256 hash.
- The installer writes the credential to
  `C:\ProgramData\MASP\Worker\agent.token` without a UTF-8 BOM.
- Token and config ACLs grant access only to Administrators, SYSTEM, and the
  `NT SERVICE\MASPWorker` virtual service identity.
- The service has no inbound listener. Allow outbound HTTPS only to MASP.
- TLS certificate validation is mandatory. Internal CAs use
  `MASP_WORKER_CONTROL_CA_FILE`; certificate verification cannot be disabled by
  the service installer.
- Sample access is bound to the current worker/process and attempt generation.
  The agent verifies byte count and SHA-256, scans a temporary copy, and removes
  it after the adapter finishes. Do not add an antivirus exclusion for that
  temporary directory.
- Engine secret fields are not sent through this control-plane version.

## Prerequisites

1. Windows Server/Windows with Microsoft Defender Antivirus and PowerShell.
2. Python 3.11 or newer, preferably in a dedicated virtual environment.
3. An elevated PowerShell session for install, upgrade, rotation, and uninstall.
4. A MASP HTTPS endpoint whose URL ends in `/api/v1/worker-control`.
5. `MASP_WORKER_ENROLLMENT_TOKEN` configured on the MASP app.
6. A Defender engine instance and a worker pool matching this node's labels.

The default service identity is deliberately not LocalSystem. If Defender
policy denies the virtual account, capture the preflight/worker health output
and approve any identity change through the host security owner; do not silently
promote the service to LocalSystem.

## Build the agent bundle

From a reviewed MASP checkout:

```powershell
python tools\package_windows_worker.py
```

This creates `dist\masp-windows-worker-0.1.0.zip`. The archive includes Python
sources, PowerShell lifecycle scripts, requirements, documentation, and
`windows-worker-manifest.json` with a SHA-256 digest for every packaged file.
The bundle includes `tools\verify_windows_worker_bundle.py`, the public scan API
verifier, and the Windows acceptance runner. The manifest detects accidental
corruption; it is not a code-signing substitute.

## Install and enroll

Extract the bundle to a stable, administrator-owned directory. Do not run the
service from a user's Downloads or temporary directory.

```powershell
Set-Location C:\Program Files\MASP Worker
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

$enrollment = Read-Host "MASP enrollment token" -AsSecureString
.\tools\windows_worker\Install-MaspWorker.ps1 `
  -PythonExe ".\.venv\Scripts\python.exe" `
  -ProjectRoot (Get-Location).Path `
  -ControlUrl "https://masp.example/api/v1/worker-control" `
  -NodeId "defender-istanbul-01" `
  -NodeName "Defender Istanbul 01" `
  -Labels "site=istanbul,os=windows,tier=primary" `
  -EnrollmentToken $enrollment
```

For an internal CA, also pass `-CaFile C:\ProgramData\MASP\ca.pem`.

The installer:

1. Validates elevation, HTTPS URL, Python, pywin32, and the package root.
2. Stops an older service before rotating its credential.
3. Enrolls without printing the returned agent token.
4. Writes ACL-protected token/config files and a Python `.pth` import path.
5. Runs the same Defender health probe used by the adapter and authenticates a
   preflight heartbeat to MASP.
6. Installs an automatic Windows service under `NT SERVICE\MASPWorker`, enables
   restart-on-failure, and starts it.

Verify:

```powershell
Get-Service MASPWorker
Get-Content 'C:\ProgramData\MASP\Worker\logs\worker.log' -Tail 100
.\tools\windows_worker\Test-MaspWorkerPreflight.ps1 `
  -PythonExe ".\.venv\Scripts\python.exe" -ControlCheck
```

`-ControlCheck` now loads the installed ACL-protected `worker.env` itself. It does
not depend on environment variables left behind by the installer shell.

In MASP, confirm that the stable node is online, the expected labels/adapters
are present, and the Defender instance reports product, engine, and signature
versions. Bind the Defender instance to the intended worker pool before sending
test samples.

## Logs and restart behavior

- Application log: `C:\ProgramData\MASP\Worker\logs\worker.log`
- Rotation: 10 MiB per file, five backups.
- Service lifecycle/errors are also reported to the Windows Application event
  log by the pywin32 service host.
- SCM recovery restarts after 5 seconds, then 15 seconds. Repeated failure is
  left stopped for operator investigation.
- A normal service stop sets a cooperative stop event. Drain the node in MASP
  before maintenance so a long Defender scan does not delay shutdown.

Never log or paste `agent.token`. Control API errors use status/detail only and
do not include the Authorization header.

## Credential rotation

Set the node to `draining` in MASP and wait for its active scan to clear. Then:

```powershell
$enrollment = Read-Host "New enrollment token" -AsSecureString
.\tools\windows_worker\Rotate-MaspWorkerCredential.ps1 `
  -PythonExe ".\.venv\Scripts\python.exe" `
  -EnrollmentToken $enrollment
```

The script stops the service, re-enrolls the same stable node, replaces the
token file, and starts the service. MASP revokes the previous credential as soon
as enrollment succeeds. If local replacement fails after that point, rerun
rotation; the previous token cannot be restored.

An administrator can revoke immediately from **System > Managed worker nodes >
Revoke agent**. A revoked node cannot heartbeat, renew a lease, download a
sample, or submit a result until it enrolls again.

## Upgrade

1. Set the node to `draining` and wait until no scan is active.
2. Stop `MASPWorker`.
3. Back up the current extracted program directory, not `agent.token`.
4. Extract the reviewed new bundle to the stable program directory.
5. Update the virtual environment from the new `requirements.txt`.
6. Rerun `Install-MaspWorker.ps1` with the same node id and a current enrollment
   token. Reinstallation rotates the agent credential.
7. Repeat preflight and clean/EICAR acceptance, then set the node `active`.

Changing `MASP_WORKER_NODE_ID` creates a different scheduling identity. Do not
change it during a routine upgrade.

## Uninstall

Drain the node first, then run:

```powershell
.\tools\windows_worker\Uninstall-MaspWorker.ps1 `
  -PythonExe ".\.venv\Scripts\python.exe"
```

This removes the service and Python `.pth` entry but retains config/logs for
investigation. `-PurgeData` additionally removes the fixed
`C:\ProgramData\MASP\Worker` directory after a path safety check. In both cases,
revoke the node credential in MASP System; deleting the local file alone does
not revoke its server-side hash.

## Required acceptance before production

Run and record all cases on the target Windows/Defender build:

1. Local and authenticated preflight with real product/engine/signature versions.
2. Clean sample produces a completed clean Defender result.
3. EICAR produces a completed detected result without remediation deleting the
   evidence before MASP records it.
4. Defender command timeout produces a deterministic failed result and the lease
   remains fenced.
5. Permission denied and Defender-disabled states produce explicit health/result
   details, never a false clean.
6. Invalid CA, revoked token, offline MASP, and interrupted download recover
   without accepting an unverified sample.
7. Drain/failover to a second matching node and stale-result rejection.
8. Service restart, host reboot, credential rotation, upgrade, log rotation, and
   uninstall/reinstall.
9. Release archive and PowerShell scripts are signed according to the deploying
   organization's Windows code-signing policy.

### Automated host evidence

After binding the Defender instance to this node's pool, run from an elevated
PowerShell session on the installed host:

```powershell
$apiToken = Read-Host "MASP API bearer token" -AsSecureString
.\tools\windows_worker\Invoke-MaspWorkerAcceptance.ps1 `
  -BaseUrl "https://masp.example" `
  -ApiToken $apiToken `
  -PythonExe ".\.venv\Scripts\python.exe"
```

The runner keeps the API token out of command-line arguments and evidence files.
It verifies the extracted package manifest, records every PowerShell Authenticode
status, confirms that `MASPWorker` is running automatically under
`NT SERVICE\MASPWorker`, runs installed-config Defender/control preflight, and
exercises clean, asynchronous, and EICAR scans through the public API while
requiring a completed Microsoft Defender result. Evidence is written below
`C:\ProgramData\MASP\Worker\acceptance\<timestamp>`.

Use `-RequireSignedScripts` for the release gate; the run fails unless every
packaged PowerShell script has a `Valid` Authenticode signature. Without it,
signature state is recorded but does not fail a lab run. `-SkipEicar` exists only
for environments where test traffic has not yet been approved and does not count
as production acceptance. The remaining timeout, permission-denied, offline,
failover, reboot, rotation, upgrade, and uninstall cases still require controlled
operator execution and retained evidence.
