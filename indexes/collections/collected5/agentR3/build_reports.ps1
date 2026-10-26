param(
  [string]$Root = 'C:\Users\27175\Desktop\driver_candidates\_collected5\agentR3'
)
$ErrorActionPreference = 'Stop'
$out      = Join-Path $Root 'new'
$reports  = Join-Path $Root 'reports'
$rawCsv   = Join-Path $reports 'manifest_filter_raw.csv'

# --- final filter pass (already produced $rawCsv); re-parse it
$rows = Import-Csv -LiteralPath $rawCsv

$meta = @{
  'ArgusMonitor.sys' = @{ Pack='ArgusMonitor_7.4.3.3193_X64_nullsoft_en-US.exe'; Vendor='Argotronic'; Product='Argus Monitor 7.4.3.3193'; Url='https://www.argusmonitor.com/downloads/ArgusMonitor_Setup.exe' }
  'SIVA32.sys'       = @{ Pack='SIV_5.88.zip'; Vendor='Ray Hinchliffe'; Product='SIV / System Information Viewer 5.88'; Url='http://rh-software.com/zip/siv_v5.88.zip' }
  'SIVI64.sys'       = @{ Pack='SIV_5.88.zip'; Vendor='Ray Hinchliffe'; Product='SIV / System Information Viewer 5.88'; Url='http://rh-software.com/zip/siv_v5.88.zip' }
  'SIVNT3.sys'       = @{ Pack='SIV_5.88.zip'; Vendor='Ray Hinchliffe'; Product='SIV / System Information Viewer 5.88'; Url='http://rh-software.com/zip/siv_v5.88.zip' }
  'SIVNT4.sys'       = @{ Pack='SIV_5.88.zip'; Vendor='Ray Hinchliffe'; Product='SIV / System Information Viewer 5.88'; Url='http://rh-software.com/zip/siv_v5.88.zip' }
  'SIVP32.sys'       = @{ Pack='SIV_5.88.zip'; Vendor='Ray Hinchliffe'; Product='SIV / System Information Viewer 5.88'; Url='http://rh-software.com/zip/siv_v5.88.zip' }
  'SIVX32.sys'       = @{ Pack='SIV_5.88.zip'; Vendor='Ray Hinchliffe'; Product='SIV / System Information Viewer 5.88'; Url='http://rh-software.com/zip/siv_v5.88.zip' }
  'SIVX64.sys'       = @{ Pack='SIV_5.88.zip'; Vendor='Ray Hinchliffe'; Product='SIV / System Information Viewer 5.88'; Url='http://rh-software.com/zip/siv_v5.88.zip' }
}

$reach = @{
  'ArgusMonitor.sys' = 'Control device \Device\ArgusMonitor; imports IoCreateDevice + RtlSetDaclSecurityDescriptor (programmatic DACL) -> high priority for IOCTL audit'
  'SIVA32.sys'       = 'Control device \Device\SIVDRIVER; imports IoCreateDevice + MmMapIoSpace -> SMBus/port/memory mapping path'
  'SIVI64.sys'       = 'Control device \Device\SIVDRIVER; imports IoCreateDevice (mapping helpers not statically imported) '
  'SIVNT3.sys'       = 'Control device \Device\SIVDRIVER; imports IoCreateDevice + MmMapIoSpace'
  'SIVNT4.sys'       = 'Control device \Device\SIVDRIVER; imports IoCreateDevice + MmMapIoSpace'
  'SIVP32.sys'       = 'Control device \Device\SIVDRIVER; imports IoCreateDevice + MmMapIoSpace'
  'SIVX32.sys'       = 'Control device \Device\SIVDRIVER; imports IoCreateDevice'
  'SIVX64.sys'       = 'Control device \Device\SIVDRIVER; imports IoCreateDevice'
}

$final = foreach ($r in $rows) {
  $m = $meta[$r.Driver]
  [pscustomobject]@{
    Pack            = $m.Pack
    Vendor          = $m.Vendor
    Product         = $m.Product
    DownloadURL     = $m.Url
    Driver          = $r.Driver
    SHA256          = $r.SHA256
    SizeKB          = $r.SizeKB
    Company         = $r.Company
    FileVersion     = $r.FileVersion
    SignatureStatus = $r.SignatureStatus
    Signer          = $r.Signer
    OriginalPath    = $r.OriginalPath
    CopiedPath      = $r.CopiedPath
    Status          = $r.Status
    Reach           = $reach[$r.Driver]
    Notes           = 'No sibling .inf/.cat in package (utility loads driver via service, not PnP)'
  }
}
$final | Export-Csv -LiteralPath (Join-Path $reports 'manifest.csv') -NoTypeInformation -Encoding UTF8

# --- independent verification against hash lists
$existing = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($l in [IO.File]::ReadLines((Join-Path $Root '..\existing_hashes.txt'))) { $h=$l.Trim(); if($h.Length -eq 64){[void]$existing.Add($h)} }
$bad = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($l in [IO.File]::ReadLines((Join-Path $Root '..\known_bad_hashes.txt'))) { $h=$l.Trim(); if($h.Length -eq 64){[void]$bad.Add($h)} }
$leakE=0; $leakB=0
foreach ($f in Get-ChildItem $out -Filter *.sys) {
  $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToUpper()
  if ($existing.Contains($h)) { $leakE++ }
  if ($bad.Contains($h)) { $leakB++ }
}

$urls = @(
  'Argotronic|Argus Monitor 7.4.3.3193|https://www.argusmonitor.com/downloads/ArgusMonitor_Setup.exe|winget Argotronic.ArgusMonitor|DOWNLOADED 14.6 MB|1 .sys'
  'Ray Hinchliffe|SIV / System Information Viewer 5.88|http://rh-software.com/zip/siv_v5.88.zip|official site (winget manifest URL filecroco 404)|DOWNLOADED 34.4 MB|7 .sys'
  'Rem0o|FanControl 284|https://github.com/Rem0o/FanControl.Releases/releases/download/V284/FanControl_284_net_10_0_Installer.exe|winget Rem0o.FanControl|DOWNLOADED 19.9 MB|0 .sys (no kernel driver shipped)'
  'Aqua Computer|aquasuite|https://aquacomputer.de/software.html?file=tl_files/aquacomputer/downloads/aquasuite/aquasuite_setup.exe|official site|SKIPPED - 1.2 MB web downloader ("aquasuite downloader"), no embedded payload; drivers only fetched at install time which is prohibited|n/a'
  'EK Water Blocks|EK-Loop Connect|https://www.ekwb.com/software-features/|official site|SKIPPED - HTTP 403 Cloudflare JS challenge on all ekwb.com paths; no direct file URL retrievable|n/a'
  'Bitspower|n/a|https://www.bitspower.com/|official site|SKIPPED - no software/utility download published, only manuals and installation guides|n/a'
  'Alphacool|n/a|https://www.alphacool.com/en/download-center-b2b|official download.alphacool.com|SKIPPED - download center serves only datasheets/manuals (no Windows utility package)|n/a'
  'Almico|SpeedFan 4.52|https://www.almico.com/instspeedfan452.exe|winget Almico.SpeedFan|FAILED - vendor host returns HTTP 503; winget download 0x8a15006d|n/a'
)
Set-Content -LiteralPath (Join-Path $reports 'urls.txt') -Value $urls -Encoding UTF8

$sizes = Get-ChildItem (Join-Path $Root 'packages') -File | Where-Object { $_.Extension -ne '.yaml' } |
  ForEach-Object { '{0} = {1:N1} MB' -f $_.Name, ($_.Length/1MB) }

$sum = @()
$sum += 'agentR3 - fan/thermal/watercooling batch (Tier A)'
$sum += '================================================'
$sum += ''
$sum += "Downloaded packages ($((Get-ChildItem (Join-Path $Root 'packages') -File -Filter *.exe).Count) installers, all <= 250 MB):"
$sizes | ForEach-Object { $sum += "  $_" }
$sum += ''
$sum += 'Per vendor:'
$sum += '  Rem0o FanControl 284            - downloaded 19.9 MB - 0 .sys (app only, driver via plugin)'
$sum += '  Argotronic Argus Monitor 7.4.3  - downloaded 14.6 MB - 1 .sys -> NEW'
$sum += '  Ray Hinchliffe SIV 5.88        - downloaded 34.4 MB - 7 .sys -> NEW'
$sum += '  Aqua Computer aquasuite         - SKIPPED (1.2 MB web downloader, payload only at install -> would require execution)'
$sum += '  EK Water Blocks EK-Loop Connect - SKIPPED (403 Cloudflare challenge, no file URL)'
$sum += '  Bitspower                       - SKIPPED (no software published)'
$sum += '  Alphacool                       - SKIPPED (download center = datasheets/manuals only)'
$sum += '  Almico SpeedFan 4.52            - FAILED (almico.com HTTP 503; winget 0x8a15006d)'
$sum += ''
$sum += 'Extraction: innounp (FanControl, Inno), 7z (Argus NSIS, SIV zip). No WiX Burn package encountered.'
$sum += 'No installer executed, no service created, no registry write.'
$sum += ''
$sum += 'Dedupe filter results (final pass):'
$sum += "  .sys found (>=4 KB): $($rows.Count)"
$sum += "  NEW      : $(($rows | Where-Object Status -eq 'NEW').Count)"
$sum += "  EXISTING : $(($rows | Where-Object Status -eq 'EXISTING').Count)"
$sum += "  KNOWNBAD : $(($rows | Where-Object Status -eq 'KNOWNBAD').Count)"
$sum += "  DUPLICATE: $(($rows | Where-Object Status -eq 'DUPLICATE').Count)"
$sum += "  SKIPPED  : 0"
$sum += "  Files in new\: $((Get-ChildItem $out -File).Count) (.sys only; no .inf/.cat exist in these packages)"
$sum += ''
$sum += 'Verification (independent recompute over new\):'
$sum += "  hashes present in existing_hashes.txt : $leakE"
$sum += "  hashes present in known_bad_hashes.txt: $leakB"
$sum += ''
$sum += 'Signature status: all 8 NEW drivers = Valid'
$sum += '  ArgusMonitor.sys - Argotronic eGbR - 4.04.4'
$sum += '  SIV*.sys         - Ray Hinchliffe - V5.88'
$sum += ''
$sum += 'Reach signals (static string scan):'
$sum += '  \Device\ArgusMonitor  - IoCreateDevice + RtlSetDaclSecurityDescriptor (programmatic DACL)'
$sum += '  \Device\SIVDRIVER     - IoCreateDevice; SIVA32/SIVNT3/SIVNT4/SIVP32 also import MmMapIoSpace'
$sum += ''
$sum += 'Failures / skips: aquasuite (web downloader only), ekwb.com (403), bitspower (no software), alphacool (no software), almico.com (503), SIV winget URL (filecroco 404 -> used official rh-software.com instead).'
Set-Content -LiteralPath (Join-Path $reports 'summary.txt') -Value $sum -Encoding UTF8

Write-Output ("NEW={0} EXISTING={1} KNOWNBAD={2} DUP={3} leakE={4} leakB={5}" -f (($rows|Where-Object Status -eq 'NEW').Count), (($rows|Where-Object Status -eq 'EXISTING').Count), (($rows|Where-Object Status -eq 'KNOWNBAD').Count), (($rows|Where-Object Status -eq 'DUPLICATE').Count), $leakE, $leakB)
