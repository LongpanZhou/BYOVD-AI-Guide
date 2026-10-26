# t9_lwf_start_diag.ps1 - capture the exact start failure for VBoxNetLwf
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_lwf_start_diag.txt"
"t9_lwf_start_diag $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

Log "--- sc start VBoxNetLwf (full output) ---"
Log (& sc.exe start VBoxNetLwf 2>&1 | Out-String)
Log ("exit=" + $LASTEXITCODE)
Log "--- sc query ---"
Log (& sc.exe query VBoxNetLwf 2>&1 | Out-String)
Log "--- sc qc ---"
Log (& sc.exe qc VBoxNetLwf 2>&1 | Out-String)
Log "--- system event log: last 40 items 7000/7001/7026/7031/7034/7043/7045 ---"
Log (& powershell.exe -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7000,7001,7026,7031,7034,7043,7045} -MaxEvents 40 -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, ProviderName, LevelDisplayName, Message" 2>&1 | Out-String)
Log "--- setupapi.dev.log tail around VBoxNetLwf install (200 lines) ---"
$sapi = 'C:\Windows\INF\setupapi.dev.log'
if (Test-Path $sapi) {
  $lines = Get-Content $sapi
  $n = $lines.Count
  Log (($lines[($n-200)..($n-1)]) -join "`r`n")
}
exit 0
