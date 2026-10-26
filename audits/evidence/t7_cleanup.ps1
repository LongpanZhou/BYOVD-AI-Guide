# t7 cleanup: remove t7_bxv service + devnode + enum keys; verify guest clean
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t7_work\t7_cleanup.txt'
"t7_cleanup $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
$work = 'C:\Users\vmdebug\Desktop\t7_work'

Log "=== remove devnode ROOT\T7BXV\0000 ==="
Log (pnputil.exe /remove-device 'ROOT\T7BXV\0000' 2>&1 | Out-String)

Log "=== remove leftover enum keys ==="
foreach ($k in 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T7BXV') {
  if (Test-Path $k) { Remove-Item -Recurse -Force $k; Log "removed $k (now present: $(Test-Path $k))" } else { Log "$k already absent" }
}

Log "=== stop + delete t7_bxv service ==="
Log (sc.exe stop t7_bxv 2>&1 | Out-String)
Log (sc.exe delete t7_bxv 2>&1 | Out-String)

Log "=== verification ==="
Log ("t7_bxv query: " + ((sc.exe query t7_bxv 2>&1 | Out-String) -replace "`r`n", ' | '))
Log ("b06bdrv query (pre-existing, expect STOPPED untouched): " + ((sc.exe query b06bdrv 2>&1 | Out-String) -replace "`r`n", ' | '))
Log ("vmci query (expect RUNNING): " + ((sc.exe query vmci 2>&1 | Out-String) -replace "`r`n", ' | '))
Log ("vsock query (expect RUNNING): " + ((sc.exe query vsock 2>&1 | Out-String) -replace "`r`n", ' | '))
Log ("Enum\ROOT\T7BXV present: " + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T7BXV'))
Log ("DeviceClasses {2AF67184} present: " + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{2af67184-48d3-4e8e-a3ff-969eff740ed2}'))
& "$work\t7_poc.exe" $out qobj '\Device' 't7|bxv|qlogic|b06|audio|nv'
Log ("t7 services remaining: " + ((driverquery.exe /v /FO CSV 2>&1 | Select-String 't7_') | Measure-Object).Count)
Log ("t7_work kept: " + (Test-Path $work))
"t7 final aliveness $(Get-Date -Format o)" | Out-File "$work\t7_alive.txt" -Encoding ascii
Log "=== end cleanup ==="
exit 0
