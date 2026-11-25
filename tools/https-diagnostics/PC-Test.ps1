param(
    [string]$Panel,
    [string]$TargetIP,
    [ValidateRange(1,10)][int]$Attempts = 10
)
$ErrorActionPreference = 'Stop'
if (-not $Panel) { $Panel = Read-Host 'Tarayicidaki panel adresi (https://...)' }
if ($Panel -notmatch '://') { $Panel = "https://$Panel" }
$uri = [uri]$Panel
if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.Port -ne 443 -or $uri.UserInfo) {
    throw 'HTTPS 443 panel adresini girin.'
}
$panelName = $uri.DnsSafeHost
$curl = (Get-Command curl.exe -CommandType Application).Source
$addresses = @([Net.Dns]::GetHostAddresses($panelName) |
    Where-Object AddressFamily -eq InterNetwork | ForEach-Object IPAddressToString)
Write-Host "DNS IPv4: $($addresses -join ', ')"
if (-not $TargetIP) {
    if (-not $addresses.Count) { throw 'IPv4 adresi bulunamadi.' }
    $TargetIP = $addresses[0]
    if ($addresses.Count -gt 1) {
        $choice = Read-Host "Test-NetConnection RemoteAddress (Enter = $TargetIP)"
        if ($choice) { $TargetIP = $choice.Trim() }
    }
}
$ip = [Net.IPAddress]::Parse($TargetIP)
if ($ip.AddressFamily -ne 'InterNetwork' -or $ip.IPAddressToString -notin $addresses) {
    throw 'Panel adina ait listelenen IPv4 adreslerinden birini secin.'
}
$target = $ip.IPAddressToString
$stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
$log = Join-Path $PSScriptRoot "masp-pc-$stamp.csv"
# Use the same IP for both probes while preserving HTTPS hostname and certificate checks.
$pin = '{0}:443:{1}' -f $panelName, $target
$url = 'https://{0}/health' -f $panelName
$format = 'peer=%{remote_ip} local=%{local_ip}:%{local_port} HTTP=%{http_code} tcp_s=%{time_connect} tls_s=%{time_appconnect} first_byte_s=%{time_starttransfer} total_s=%{time_total}'
Write-Host "Hedef: $target TCP 443   Rapor: $log"
for ($i = 1; $i -le $Attempts; $i++) {
    $start = [DateTime]::UtcNow.ToString('o')
    $socket = New-Object Net.Sockets.TcpClient
    $source = ''
    $tcp = 'TIMEOUT'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $socket.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Any, 0))
        $source = $socket.Client.LocalEndPoint.ToString()
        $pending = $socket.ConnectAsync($ip, 443)
        if ($pending.Wait(3000)) {
            $source = $socket.Client.LocalEndPoint.ToString()
            $tcp = 'OK'
        }
    } catch {
        $tcp = $_.Exception.GetBaseException().Message
    } finally {
        $timer.Stop()
        $socket.Close()
    }
    $httpsStart = [DateTime]::UtcNow.ToString('o')
    # Windows PowerShell 5 converts native stderr to ErrorRecord; retain curl's exit code.
    $ErrorActionPreference = 'Continue'
    try {
        $lines = @(& $curl --disable --noproxy '*' --resolve $pin --connect-timeout 3 --max-time 6 --silent --show-error --output NUL --write-out $format --url $url 2>&1)
        $curlCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = 'Stop' }
    $detail = ($lines | ForEach-Object { $_.ToString() }) -join ' '
    $row = [pscustomobject]@{
        attempt=$i; tcp_utc=$start; panel=$panelName; dns_ipv4=($addresses -join ' ')
        target=$target; tcp_source=$source; tcp_result=$tcp; tcp_ms=$timer.ElapsedMilliseconds
        https_utc=$httpsStart; curl_exit=$curlCode; https_result=$detail
    }
    $row | Export-Csv -LiteralPath $log -NoTypeInformation -Append -Encoding UTF8
    Write-Host "[$i] $start TCP=$tcp curl=$curlCode $detail"
    if ($i -lt $Attempts) { Start-Sleep -Seconds 2 }
}
Write-Host "Tamamlandi: $log"
