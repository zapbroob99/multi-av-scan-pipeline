[CmdletBinding()]
param(
    [SecureString]$EnrollmentToken,
    [string]$PythonExe = "python"
)

$ErrorActionPreference = "Stop"
$ServiceName = "MASPWorker"
$WorkerRoot = Join-Path $env:ProgramData "MASP\Worker"
$ConfigPath = Join-Path $WorkerRoot "worker.env"
$TokenPath = Join-Path $WorkerRoot "agent.token"

function Convert-SecureValue([SecureString]$Value) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "MASP worker config not found: $ConfigPath"
}
if (-not $EnrollmentToken) {
    $EnrollmentToken = Read-Host "Worker enrollment token" -AsSecureString
}
$config = @{}
foreach ($line in Get-Content -LiteralPath $ConfigPath) {
    if ($line -and -not $line.StartsWith("#")) {
        $key, $value = $line.Split("=", 2)
        $config[$key] = $value
    }
}
$service = Get-Service -Name $ServiceName -ErrorAction Stop
if ($service.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus("Stopped", [TimeSpan]::FromMinutes(5))
}

$plainEnrollment = Convert-SecureValue $EnrollmentToken
$tempToken = "$TokenPath.new"
try {
    $env:MASP_WORKER_CONTROL_URL = $config["MASP_WORKER_CONTROL_URL"]
    $env:MASP_WORKER_ENROLLMENT_TOKEN = $plainEnrollment
    $env:MASP_WORKER_ENGINE_KEYS = $config["MASP_WORKER_ENGINE_KEYS"]
    $env:MASP_WORKER_NODE_ID = $config["MASP_WORKER_NODE_ID"]
    $env:MASP_WORKER_NODE_NAME = $config["MASP_WORKER_NODE_NAME"]
    $env:MASP_WORKER_LABELS = $config["MASP_WORKER_LABELS"]
    if ($config["MASP_WORKER_CONTROL_CA_FILE"]) {
        $env:MASP_WORKER_CONTROL_CA_FILE = $config["MASP_WORKER_CONTROL_CA_FILE"]
    }
    $output = @(& $PythonExe -m app.workers.control_api_worker --enroll 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Credential rotation failed: $($output -join ' ')" }
    $newToken = [string]$output[-1]
    if (-not $newToken.StartsWith("masp_wa_")) { throw "Enrollment returned an invalid token." }
    [IO.File]::WriteAllText($tempToken, $newToken, [Text.UTF8Encoding]::new($false))
    & icacls.exe $tempToken /inheritance:r /grant:r `
        "SYSTEM:(F)" "BUILTIN\Administrators:(F)" "NT SERVICE\MASPWorker:(R)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to protect the new token file." }
    Move-Item -LiteralPath $tempToken -Destination $TokenPath -Force
    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus("Running", [TimeSpan]::FromMinutes(1))
    Write-Host "MASP worker credential rotated successfully."
} finally {
    Remove-Item -LiteralPath $tempToken -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\MASP_WORKER_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    $plainEnrollment = $null
}
