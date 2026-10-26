# t8_cleanup.ps1 - stop/delete t8_amdpsp service, remove pushed binaries, verify, marker
# run in guest: powershell.exe -NoProfile -ExecutionPolicy Bypass -File <work>\t8_cleanup.ps1
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t8_work'
$out  = "$work\t8_cleanup.txt"
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
"t8_cleanup $(Get-Date -Format o)" | Out-File $out -Encoding ascii
$svc = 't8_amdpsp'

Log "--- sc stop $svc ---"
$s = sc.exe stop $svc 2>&1 | Out-String
Log ("stop exit=" + $LASTEXITCODE + " out: " + $s.Trim())
Start-Sleep -Seconds 2

Log "--- sc delete $svc ---"
$s = sc.exe delete $svc 2>&1 | Out-String
Log ("delete exit=" + $LASTEXITCODE + " out: " + $s.Trim())

Log "--- verification: sc query (expect 1060 not-exist / 1062 not-started) ---"
$q = sc.exe query $svc 2>&1 | Out-String
Log ("query: " + $q.Trim())

Log "--- verification: driverquery rows for t8_amdpsp (expect none) ---"
$dq = driverquery.exe /v 2>&1 | Out-String
$hit = $false
foreach ($line in ($dq -split "`r?`n")) {
  if ($line -match 't8_amdpsp') { Log ("  STILL PRESENT: " + $line); $hit = $true }
}
if (-not $hit) { Log "  t8_amdpsp absent from driverquery (clean)" }

Log "--- pre-existing services untouched (print only) ---"
foreach ($p in @('vmci', 'vsock', 'b06bdrv')) {
  $pq = sc.exe query $p 2>&1 | Out-String
  Log ("  " + $p + ": " + (($pq -split "`r?`n")[1..3] -join ' ').Trim())
}

Log "--- delete pushed binaries (keep t8_work + logs + scripts) ---"
foreach ($f in @("$work\t8_poc.exe", "$work\amdpsp.sys")) {
  if (Test-Path $f) { Remove-Item $f -Force; Log ("  deleted " + $f) } else { Log ("  already absent " + $f) }
}
Log ("  t8_poc.exe gone: " + (-not (Test-Path "$work\t8_poc.exe")))
Log ("  amdpsp.sys gone: " + (-not (Test-Path "$work\amdpsp.sys")))

Log "--- final aliveness marker ---"
"t8_cleanup COMPLETE $(Get-Date -Format o)" | Out-File "$work\t8_alive.txt" -Encoding ascii
Get-Content "$work\t8_alive.txt" | ForEach-Object { Log ("  alive: " + $_) }
exit 0
