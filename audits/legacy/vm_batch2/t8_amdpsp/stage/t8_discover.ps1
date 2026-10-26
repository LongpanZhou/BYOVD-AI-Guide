# t8_discover.ps1 - device-surface discovery for amdpsp (qobj + driverquery + logs)
# run in guest: powershell.exe -NoProfile -ExecutionPolicy Bypass -File <work>\t8_discover.ps1
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t8_work'
$out  = "$work\t8_discover.txt"
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
"t8_discover $(Get-Date -Format o)" | Out-File $out -Encoding ascii

Log "--- qobj \Device (amd|psp) ---"
& "$work\t8_poc.exe" $out qobj '\Device' 'amd|psp'
Log "  poc exit=$LASTEXITCODE"
Log "--- qobj \DosDevices (amd|psp) ---"
& "$work\t8_poc.exe" $out qobj '\DosDevices' 'amd|psp'
Log "--- qobj \GLOBAL?? (amd|psp) ---"
& "$work\t8_poc.exe" $out qobj '\GLOBAL??' 'amd|psp'
Log "--- qobj \?? (amd|psp) ---"
& "$work\t8_poc.exe" $out qobj '\??' 'amd|psp'
Log "--- qobj \Device (amdp|pspt catch-all) ---"
& "$work\t8_poc.exe" $out qobj '\Device' 'amdp|pspt|tee'

Log "--- open probes \\.\amdpsp (admin) ---"
& "$work\t8_poc.exe" $out open '\\.\amdpsp' c0000000 3
& "$work\t8_poc.exe" $out open '\\.\amdpsp' 12019f 3
& "$work\t8_poc.exe" $out open '\\.\amdpsp' 0 3
Log "--- NT-path opens ---"
& "$work\t8_poc.exe" $out open '\Device\amdpsp' 12019f 3

Log "--- DACL pulls (resolves Everyone-SDDL question) ---"
& "$work\t8_poc.exe" $out dacl '\\.\amdpsp'
& "$work\t8_poc.exe" $out dacl '\Device\amdpsp'

Log "--- driverquery rows (amdpsp / t8_amdpsp) ---"
$dq = driverquery.exe /v 2>&1 | Out-String
foreach ($line in ($dq -split "`r?`n")) {
  if ($line -match 'amdpsp|t8_amdpsp') { Log ("  " + $line) }
}

Log "--- device interface GUID {D41D854A-3877-4471-A889-B0D551B1125B} in registry ---"
$dc = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{D41D854A-3877-4471-A889-B0D551B1125B}'
if (Test-Path $dc) { Log ("  interface key EXISTS:"); Get-ChildItem $dc | ForEach-Object { Log ("    " + $_.PSChildName) } }
else { Log "  interface key NOT present" }

Log "--- setupapi.dev.log tail (60 lines) ---"
try { Get-Content 'C:\Windows\INF\setupapi.dev.log' -Tail 60 | ForEach-Object { Log ("  " + $_) } } catch { Log ("  (setupapi.dev.log read failed: " + $_.Exception.Message + ")") }

Log "--- event log System 7000/7026 tail (last 15 min) ---"
try {
  $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = @(7000, 7026); StartTime = (Get-Date).AddMinutes(-15) } -ErrorAction Stop
  foreach ($e in $ev) { Log ("  [{0}] id={1} src={2}" -f $e.TimeCreated.ToString('o'), $e.Id, $e.ProviderName) }
} catch {
  Log ("  (no 7000/7026 events: " + $_.Exception.Message + ")")
}

"t8_discover boundary $(Get-Date -Format o)" | Out-File "$work\t8_alive.txt" -Encoding ascii
exit 0
