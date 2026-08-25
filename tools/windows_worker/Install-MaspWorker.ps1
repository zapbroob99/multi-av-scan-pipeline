[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ControlUrl,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]{1,128}$')]
    [string]$NodeId,
    [string]$NodeName = $env:COMPUTERNAME,
    [string]$Labels = "os=windows",
    [string]$PythonExe = "python",
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$CaFile = "",
    [SecureString]$EnrollmentToken,
    [SecureString]$AgentToken,
    [switch]$InstallDependencies,
    [switch]$SkipStart
)

$ErrorActionPreference = "Stop"
$ServiceName = "MASPWorker"
$ProgramDataRoot = Join-Path $env:ProgramData "MASP\Worker"
$TokenPath = Join-Path $ProgramDataRoot "agent.token"
$ConfigPath = Join-Path $ProgramDataRoot "worker.env"
$LogPath = Join-Path $ProgramDataRoot "logs"
$ServiceAccount = "NT SERVICE\MASPWorker"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from an elevated PowerShell session."
    }
}

function Convert-SecureValue([SecureString]$Value) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Write-Utf8NoBom([string]$Path, [string]$Value) {
    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Protect-AdminFile([string]$Path) {
    & icacls.exe $Path /inheritance:r /grant:r `
        "SYSTEM:(F)" "BUILTIN\Administrators:(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to protect $Path with Windows ACLs." }
}

function Grant-ServiceFileAccess([string]$Path, [string]$Access) {
    & icacls.exe $Path /grant:r "${ServiceAccount}:($Access)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to grant the service access to $Path." }
}

Assert-Administrator
$uri = [Uri]$ControlUrl
if ($uri.Scheme -ne "https") { throw "The Windows service requires an HTTPS control URL." }
if ($uri.UserInfo -or $uri.Query -or $uri.Fragment) {
    throw "ControlUrl must not contain credentials, a query, or a fragment."
}
if ($uri.AbsolutePath.TrimEnd('/') -ne "/api/v1/worker-control") {
    throw "ControlUrl must end with /api/v1/worker-control."
}
if ($NodeName.Length -gt 128 -or $NodeName.Contains("`r") -or $NodeName.Contains("`n")) {
    throw "NodeName must be a single line of at most 128 characters."
}
if ($Labels.Contains("`r") -or $Labels.Contains("`n")) {
    throw "Labels must be a single line."
}
if ($EnrollmentToken -and $AgentToken) {
    throw "Supply either EnrollmentToken or AgentToken, not both."
}
if ($CaFile -and -not (Test-Path -LiteralPath $CaFile -PathType Leaf)) {
    throw "CA file not found: $CaFile"
}
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "app\workers\windows_service.py"))) {
    throw "ProjectRoot is not a MASP worker package: $ProjectRoot"
}

$pythonCommand = Get-Command $PythonExe -ErrorAction Stop
$resolvedPython = $pythonCommand.Source
if ($InstallDependencies) {
    & $resolvedPython -m pip install -r (Join-Path $ProjectRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) { throw "Python dependency installation failed." }
}
& $resolvedPython -c "import win32serviceutil"
if ($LASTEXITCODE -ne 0) {
    throw "pywin32 is missing. Re-run with -InstallDependencies or install requirements.txt."
}

New-Item -ItemType Directory -Force -Path $ProgramDataRoot, $LogPath | Out-Null
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus("Stopped", [TimeSpan]::FromMinutes(5))
}
$previousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = $ProjectRoot
$plainEnrollment = $null
$plainAgent = $null
try {
    if ($AgentToken) {
        $plainAgent = Convert-SecureValue $AgentToken
    } else {
        if (-not $EnrollmentToken) {
            $EnrollmentToken = Read-Host "Worker enrollment token" -AsSecureString
        }
        $plainEnrollment = Convert-SecureValue $EnrollmentToken
        $env:MASP_WORKER_CONTROL_URL = $ControlUrl.TrimEnd('/')
        $env:MASP_WORKER_ENROLLMENT_TOKEN = $plainEnrollment
        $env:MASP_WORKER_ENGINE_KEYS = "microsoft_defender"
        $env:MASP_WORKER_NODE_ID = $NodeId
        $env:MASP_WORKER_NODE_NAME = $NodeName
        $env:MASP_WORKER_LABELS = $Labels
        if ($CaFile) { $env:MASP_WORKER_CONTROL_CA_FILE = $CaFile }
        $output = @(& $resolvedPython -m app.workers.control_api_worker --enroll 2>&1)
        if ($LASTEXITCODE -ne 0) { throw "Worker enrollment failed: $($output -join ' ')" }
        $plainAgent = [string]$output[-1]
        if (-not $plainAgent.StartsWith("masp_wa_")) {
            throw "Worker enrollment returned an unexpected credential."
        }
    }

    Write-Utf8NoBom $TokenPath $plainAgent
    $config = @(
        "MASP_WORKER_TRANSPORT=control_api"
        "MASP_WORKER_CONTROL_URL=$($ControlUrl.TrimEnd('/'))"
        "MASP_WORKER_AGENT_TOKEN_FILE=$TokenPath"
        "MASP_WORKER_ENGINE_KEYS=microsoft_defender"
        "MASP_WORKER_NODE_ID=$NodeId"
        "MASP_WORKER_NODE_NAME=$NodeName"
        "MASP_WORKER_LABELS=$Labels"
        "MASP_WORKER_CAPACITY=1"
        "MASP_WORKER_AGENT_VERSION=0.1.0"
        "MASP_WORKER_POLL_SECONDS=2"
    )
    if ($CaFile) { $config += "MASP_WORKER_CONTROL_CA_FILE=$CaFile" }
    Write-Utf8NoBom $ConfigPath (($config -join "`n") + "`n")
    Protect-AdminFile $TokenPath
    Protect-AdminFile $ConfigPath
    & icacls.exe $LogPath /inheritance:r /grant:r `
        "SYSTEM:(OI)(CI)(F)" "BUILTIN\Administrators:(OI)(CI)(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to protect the worker log directory." }

    $sitePackages = & $resolvedPython -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
    Write-Utf8NoBom (Join-Path $sitePackages "masp-worker.pth") $ProjectRoot

    $env:MASP_WORKER_AGENT_TOKEN_FILE = $TokenPath
    $env:MASP_WORKER_CONTROL_URL = $ControlUrl.TrimEnd('/')
    $env:MASP_WORKER_NODE_ID = $NodeId
    $env:MASP_WORKER_NODE_NAME = $NodeName
    $env:MASP_WORKER_LABELS = $Labels
    $env:MASP_WORKER_ENGINE_KEYS = "microsoft_defender"
    if ($CaFile) { $env:MASP_WORKER_CONTROL_CA_FILE = $CaFile }
    & $resolvedPython -m app.workers.windows_agent --control-check
    if ($LASTEXITCODE -ne 0) { throw "Defender/control-plane preflight failed." }

    if ($existing) {
        & $resolvedPython -m app.workers.windows_service remove | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Unable to remove the previous MASP worker service." }
    }
    & $resolvedPython -m app.workers.windows_service --startup auto install | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to install the MASP worker service." }
    & sc.exe config $ServiceName obj= $ServiceAccount password= "" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to set the MASP service identity." }
    & sc.exe sidtype $ServiceName unrestricted | Out-Null
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/""/0 | Out-Null
    Grant-ServiceFileAccess $TokenPath "R"
    Grant-ServiceFileAccess $ConfigPath "R"
    & icacls.exe $LogPath /grant:r "${ServiceAccount}:(OI)(CI)(M)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to grant service log access." }
    if (-not $SkipStart) {
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus("Running", [TimeSpan]::FromMinutes(1))
    }
    Write-Host "MASP Worker installed. Logs: $LogPath\worker.log"
} finally {
    $env:PYTHONPATH = $previousPythonPath
    Remove-Item Env:\MASP_WORKER_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    $plainEnrollment = $null
    $plainAgent = $null
}
