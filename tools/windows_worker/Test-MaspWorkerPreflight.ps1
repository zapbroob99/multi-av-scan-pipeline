[CmdletBinding()]
param(
    [string]$PythonExe = "python",
    [switch]$ControlCheck,
    [string]$ConfigPath = (Join-Path $env:ProgramData "MASP\Worker\worker.env")
)

$arguments = @("-m", "app.workers.windows_agent")
if ($ControlCheck) {
    $arguments += @("--service-config", $ConfigPath)
}
& $PythonExe @arguments
exit $LASTEXITCODE
