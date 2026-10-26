# t5_ioctl.ps1 (agent t5) - Phase A step 7: IOCTL reachability battery.
# Order per directive: SAFE informational codes first, then 0x22200A MDL-map
# EXACTLY as audit documents (small 0x8000 B user ring covering count*0x800 span),
# then pump trigger 0x222027. Admin session first, then restricted-token session.
# Evidence: t5_ioctl.txt (+ t5_ioctl_restricted.txt pulled separately)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_ioctl.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"

function StatsSnap($label) {
  W ("--- adapter statistics snapshot: " + $label + " ---")
  try {
    Get-NetAdapterStatistics -ErrorAction Stop | Where-Object { $_.Name -match '.' } |
      Format-Table Name,ReceivedBytes,ReceivedUnicastPackets,SentBytes,SentUnicastPackets -AutoSize | Out-String -Width 200 | ForEach-Object { W $_ }
  } catch { W ("  Get-NetAdapterStatistics ERROR: " + $_.Exception.Message) }
}

W ("=== t5 ioctl battery {0} ===" -f (Get-Date -Format o))
Marker 'ioctl-start'
StatsSnap 'BEFORE admin session'

W "--- ADMIN SESSION BATTERY (see battery lines appended below; skipped codes documented in PoC header) ---"
& $exe $log session '\\.\VPNVA' 2>&1 | Out-Null
W ("  session exit=" + $LASTEXITCODE + " (0=completed, 2=open failed)")
if (Test-Path $log) { $log2 = Get-Content $log; $start = [Math]::Max(0, $log2.Count - 200); $log2 | Select-Object -Skip $start | ForEach-Object { W ('  poc: ' + $_) } }

Marker 'ioctl-after-admin'
StatsSnap 'AFTER admin session'

W "--- event log tail after admin session ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 5 -ErrorAction Stop | ForEach-Object { W ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } } catch { W ("  ERROR: " + $_.Exception.Message) }

W "--- RESTRICTED-TOKEN SESSION BATTERY (runas /trustlevel:0x20000) ---"
$restrLog = "$work\t5_ioctl_restricted.txt"
if (Test-Path $restrLog) { Remove-Item $restrLog -Force }
$inner = '"' + $exe + '" ' + $restrLog + ' session \\.\VPNVA'
$ra = & runas.exe /trustlevel:0x20000 $inner 2>&1
$ra | ForEach-Object { W ('  runas: ' + $_) }
# session battery may legitimately take ~30 s (bounded waits on the parked IRP)
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 5
  if ((Test-Path $restrLog) -and ((Get-Content $restrLog -Raw) -match 'SESSION DONE')) { break }
}
if (Test-Path $restrLog) { Get-Content $restrLog | ForEach-Object { W ('  restricted: ' + $_) } }
else { W '  restricted run produced NO output file (open likely denied; runas spawn issue)' }

Marker 'ioctl-after-restricted'
StatsSnap 'AFTER restricted session'

W "--- event log tail after restricted session ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 5 -ErrorAction Stop | ForEach-Object { W ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } } catch { W ("  ERROR: " + $_.Exception.Message) }

Marker 'ioctl-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
