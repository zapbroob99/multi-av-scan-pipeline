[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$PythonExe = "python",
    [switch]$PurgeData
)

$ErrorActionPreference = "Stop"
$ServiceName = "MASPWorker"
$WorkerRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData "MASP\Worker"))
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from an elevated PowerShell session."
}

if ($PSCmdlet.ShouldProcess($ServiceName, "Stop and remove Windows service")) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus("Stopped", [TimeSpan]::FromMinutes(2))
    }
    if ($service) {
        & $PythonExe -m app.workers.windows_service remove | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Unable to remove the MASP worker service." }
    }
}

$sitePackages = & $PythonExe -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
$pthPath = Join-Path $sitePackages "masp-worker.pth"
if (Test-Path -LiteralPath $pthPath) { Remove-Item -LiteralPath $pthPath -Force }

if ($PurgeData -and $PSCmdlet.ShouldProcess($WorkerRoot, "Delete token, config, and logs")) {
    $expected = [IO.Path]::GetFullPath((Join-Path $env:ProgramData "MASP\Worker"))
    if ($WorkerRoot -ne $expected -or -not $WorkerRoot.StartsWith([IO.Path]::GetFullPath($env:ProgramData))) {
        throw "Refusing to recursively remove an unexpected path: $WorkerRoot"
    }
    if (Test-Path -LiteralPath $WorkerRoot) {
        Remove-Item -LiteralPath $WorkerRoot -Recurse -Force
    }
    Write-Host "Removed local worker credentials and logs. Revoke the node credential in MASP System."
} else {
    Write-Host "Service removed. Local config/logs retained at $WorkerRoot."
    Write-Host "Revoke the node credential from MASP System if this host is retired."
}
