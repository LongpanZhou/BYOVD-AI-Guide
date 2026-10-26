# t5_load.ps1 (agent t5) - Phase A steps 2+3: copy+hash, service create+start, PoC compile.
# Evidence: t5_load.txt (progressive appends; survives a mid-script guest death).
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_load.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

$expected = '506AB485FE0DA85C6DF6D0B7ABBAD412ACA6A8EB3F575DFC2C81662107054792'  # triage_index.csv / vpnva.md SHA-256
$src = "$work\vpnva64-6.sys"                                   # host->guest staging copy (vmrun CopyFileFromHostToGuest)
$dst = 'C:\Windows\System32\drivers\vpnva64-6.sys'

WA ("=== t5 load {0} ===" -f (Get-Date -Format o))
Marker 'load-start'

if (-not (Test-Path $src)) { WA ("FATAL: staging copy missing: " + $src); exit 3 }
$h1 = (Get-FileHash $src -Algorithm SHA256).Hash
WA ("guest staging SHA256 : " + $h1)
WA ("audited SHA256       : " + $expected)
if ($h1 -ne $expected) { WA "FATAL: staging hash MISMATCH - aborting before any deployment"; exit 4 }
WA "staging hash MATCH"

if (Test-Path $dst) {
  $pre = (Get-FileHash $dst -Algorithm SHA256).Hash
  WA ("PRE-EXISTING dst: $dst  SHA256=$pre")
  if ($pre -eq $expected) { WA "  -> identical to audited binary; no overwrite needed" }
  else { Copy-Item $dst "$dst.t5bak" -Force; WA "  -> DIFFERENT from audited binary: original saved to vpnva64-6.sys.t5bak; overwriting" }
} else { WA ("dst absent: " + $dst) }

Copy-Item -Force $src $dst
$h2 = (Get-FileHash $dst -Algorithm SHA256).Hash
WA ("dst SHA256 after copy: " + $h2)
if ($h2 -ne $expected) { WA "FATAL: dst hash mismatch after copy"; exit 5 }
WA "dst hash verified OK"

WA "--- sc create t5_vpnva type= kernel start= demand ---"
sc.exe create t5_vpnva type= kernel start= demand binPath= 'C:\Windows\System32\drivers\vpnva64-6.sys' 2>&1 | ForEach-Object { WA ("  " + $_) }
WA ("  sc create exit: " + $LASTEXITCODE)

WA "--- sc start t5_vpnva (DriverEntry -> NdisMRegisterMiniportDriver only; no devnode yet) ---"
sc.exe start t5_vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
WA ("  sc start exit: " + $LASTEXITCODE)
Start-Sleep -Seconds 3

WA "--- sc query t5_vpnva ---"
sc.exe query t5_vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }

WA "--- driverquery /v rows matching vpnva ---"
driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva' | ForEach-Object { WA ("  " + $_.Line) }

WA "--- compile PoC ---"
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (Test-Path $csc) {
  $out = & $csc /nologo /out:"$work\t5_poc.exe" "$work\t5_poc.cs" 2>&1
  $out | ForEach-Object { WA ("  csc: " + $_) }
  WA ("  csc exit: " + $LASTEXITCODE)
} else { WA ("  csc NOT FOUND: " + $csc) }
if (Test-Path "$work\t5_poc.exe") { WA "  t5_poc.exe compiled OK" } else { WA "  t5_poc.exe MISSING after compile" }

Marker 'load-done'
