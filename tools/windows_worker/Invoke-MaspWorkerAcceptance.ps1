[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [string]$BaseUrl,
    [SecureString]$ApiToken,
    [string]$PythonExe = "python",
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$ConfigPath = (Join-Path $env:ProgramData "MASP\Worker\worker.env"),
    [string]$EvidenceDirectory = (Join-Path $env:ProgramData (
        "MASP\Worker\acceptance\" + (Get-Date -Format "yyyyMMdd-HHmmss")
    )),
    [switch]$RequireSignedScripts,
    [switch]$SkipEicar,
    [int]$TotalTimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"
$ServiceName = "MASPWorker"

function Convert-SecureValue([SecureString]$Value) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

if ($env:OS -ne "Windows_NT") { throw "Windows worker acceptance must run on Windows." }
$baseUri = [Uri]$BaseUrl
if (-not $baseUri.IsAbsoluteUri -or $baseUri.Scheme -ne "https" -or
    $baseUri.UserInfo -or $baseUri.Query -or $baseUri.Fragment -or
    $baseUri.AbsolutePath.Trim('/')
) {
    throw "BaseUrl must be an HTTPS origin without credentials, path, query, or fragment."
}
$NormalizedBaseUrl = $BaseUrl.TrimEnd('/')
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Installed worker config not found: $ConfigPath"
}
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "windows-worker-manifest.json") -PathType Leaf)) {
    throw "Extracted bundle manifest not found below ProjectRoot: $ProjectRoot"
}
if (-not $ApiToken) { $ApiToken = Read-Host "MASP API bearer token" -AsSecureString }

New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
$startedAt = (Get-Date).ToUniversalTime().ToString("o")
$checks = [Collections.Generic.List[object]]::new()

function Add-Check([string]$Name, [bool]$Ok, [object]$Detail) {
    $checks.Add([ordered]@{ name = $Name; ok = $Ok; detail = $Detail })
    $marker = if ($Ok) { "PASS" } else { "FAIL" }
    Write-Host "[$marker] $Name"
    if (-not $Ok) { throw "$Name failed: $Detail" }
}

function Write-AcceptanceSummary([string]$Outcome, [string]$Failure = "") {
    $summary = [ordered]@{
        schema_version = 1
        started_at = $startedAt
        completed_at = (Get-Date).ToUniversalTime().ToString("o")
        host = $env:COMPUTERNAME
        project_root = $ProjectRoot
        base_url = $NormalizedBaseUrl
        eicar_executed = -not [bool]$SkipEicar
        signature_enforcement = [bool]$RequireSignedScripts
        checks = $checks
        outcome = $Outcome
        failure = if ($Failure) { $Failure } else { $null }
    }
    $summaryPath = Join-Path $EvidenceDirectory "acceptance-summary.json"
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding utf8
    return $summaryPath
}

$plainApiToken = Convert-SecureValue $ApiToken
$previousApiToken = $env:MASP_API_TOKEN
try {
    $bundleReport = Join-Path $EvidenceDirectory "bundle-integrity.json"
    & $PythonExe (Join-Path $ProjectRoot "tools\verify_windows_worker_bundle.py") `
        --root $ProjectRoot --report $bundleReport
    Add-Check "bundle-integrity" ($LASTEXITCODE -eq 0) $bundleReport

    $scriptSignatures = @(
        Get-ChildItem -LiteralPath (Join-Path $ProjectRoot "tools\windows_worker") -Filter "*.ps1" |
            ForEach-Object {
                $signature = Get-AuthenticodeSignature -LiteralPath $_.FullName
                [ordered]@{
                    file = $_.Name
                    status = [string]$signature.Status
                    signer = if ($signature.SignerCertificate) {
                        $signature.SignerCertificate.Subject
                    } else { $null }
                }
            }
    )
    $signatureReport = Join-Path $EvidenceDirectory "powershell-signatures.json"
    $scriptSignatures | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $signatureReport -Encoding utf8
    $invalidSignatures = @($scriptSignatures | Where-Object { $_.status -ne "Valid" })
    if ($RequireSignedScripts) {
        Add-Check "powershell-signatures" ($invalidSignatures.Count -eq 0) `
            "$($scriptSignatures.Count - $invalidSignatures.Count)/$($scriptSignatures.Count) valid"
    } else {
        Add-Check "powershell-signatures-recorded" $true `
            "$($scriptSignatures.Count - $invalidSignatures.Count)/$($scriptSignatures.Count) valid; enforcement disabled"
    }

    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if (-not $service) { Add-Check "service-installed" $false "Service not found." }
    $serviceEvidence = [ordered]@{
        name = $service.Name
        state = $service.State
        start_mode = $service.StartMode
        start_name = $service.StartName
        path_name = $service.PathName
    }
    $serviceEvidence | ConvertTo-Json | Set-Content `
        -LiteralPath (Join-Path $EvidenceDirectory "service.json") -Encoding utf8
    Add-Check "service-running" ($service.State -eq "Running") $service.State
    Add-Check "service-startup" ($service.StartMode -eq "Auto") $service.StartMode
    Add-Check "service-identity" ($service.StartName -eq "NT SERVICE\MASPWorker") $service.StartName

    $preflightReport = Join-Path $EvidenceDirectory "preflight.json"
    $preflightOutput = @(& $PythonExe -m app.workers.windows_agent `
        --service-config $ConfigPath 2>&1)
    $preflightOutput | Set-Content -LiteralPath $preflightReport -Encoding utf8
    Add-Check "defender-control-preflight" ($LASTEXITCODE -eq 0) $preflightReport

    $env:MASP_API_TOKEN = $plainApiToken
    $apiReport = Join-Path $EvidenceDirectory "scan-api-report.json"
    $apiCapture = Join-Path $EvidenceDirectory "scan-api-responses"
    $apiArguments = @(
        (Join-Path $ProjectRoot "tools\verify_scan_api.py"),
        "--base-url", $NormalizedBaseUrl,
        "--require-engine", "Microsoft Defender",
        "--total-timeout", [string]$TotalTimeoutSeconds,
        "--capture-dir", $apiCapture,
        "--report", $apiReport
    )
    if (-not $SkipEicar) { $apiArguments += "--eicar" }
    & $PythonExe @apiArguments
    Add-Check "clean-eicar-scan-contract" ($LASTEXITCODE -eq 0) $apiReport

    $summaryPath = Write-AcceptanceSummary "passed"
    Write-Host "Windows worker acceptance passed. Evidence: $EvidenceDirectory"
} catch {
    $summaryPath = Write-AcceptanceSummary "failed" $_.Exception.Message
    Write-Error "Windows worker acceptance failed. Evidence: $summaryPath" -ErrorAction Continue
    throw
} finally {
    if ($null -eq $previousApiToken) {
        Remove-Item Env:\MASP_API_TOKEN -ErrorAction SilentlyContinue
    } else {
        $env:MASP_API_TOKEN = $previousApiToken
    }
    $plainApiToken = $null
}
