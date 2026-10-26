# t10_cleanup.ps1 - stop+delete service, remove pushed files (keep t10_work + logs), verify, marker
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t10_work'
$log  = "$work\t10_cleanup.txt"
function Log([string]$s) { [IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker([string]$m) { Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

[IO.File]::WriteAllText($log, ("=== t10_cleanup {0} ===`r`n" -f (Get-Date -Format o)))
Marker 'cleanup-start'

Log '--- sc stop ---'
& sc.exe stop t10_iastrv 2>&1 | ForEach-Object { Log ('  ' + $_) }
Log ('  stop exit=' + $LASTEXITCODE)
Start-Sleep -Seconds 2

Log '--- sc delete ---'
& sc.exe delete t10_iastrv 2>&1 | ForEach-Object { Log ('  ' + $_) }
Log ('  delete exit=' + $LASTEXITCODE)

Log '--- sc query (expect 1060 absent) ---'
& sc.exe query t10_iastrv 2>&1 | ForEach-Object { Log ('  ' + $_) }

Log '--- delete pushed files (keep t10_work dir + *.txt logs) ---'
foreach ($f in @('iaStorV.sys', 't10_poc.exe', 't10_poc.cs', 't10_load.ps1', 't10_discover.ps1', 't10_dacl.ps1',
                 't10_open_unpriv.ps1', 't10_battery.ps1', 't10_sweep.ps1', 't10_cleanup.ps1', 't10_kd_dispatch.ps1')) {
  $p = "$work\$f"
  if (Test-Path $p) { Remove-Item $p -Force; Log ('  removed: ' + $f) } else { Log ('  (absent): ' + $f) }
}

Log '--- driverquery verify (expect no t10 rows) ---'
& driverquery.exe /v 2>&1 | ForEach-Object {
  if ($_ -match 't10_') { Log ('  RESIDUAL: ' + $_) }
}

Log '--- qobj residual check ---'
& "$work\t10_poc.exe" $log qobj '\Device' 't10|IAAST|T10IAST' 2>&1 | Out-Null

Log '--- retained files ---'
Get-ChildItem $work -ErrorAction SilentlyContinue | ForEach-Object { Log ('  ' + $_.Name) }

Marker 'cleanup-done'
exit 0
