# t6_cleanup.ps1 (agent t6) - Phase A step 8: cleanup. Evidence: t6_cleanup.txt
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$log  = "$work\t6_cleanup.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t6_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

W ("=== t6 cleanup {0} ===" -f (Get-Date -Format o))
Marker 'cleanup-start'

W '--- remove devnodes ---'
foreach ($id in @('ROOT\T6NVHDA\0000','ROOT\T6NVHDA2\0000')) {
  if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$id") {
    $r = pnputil /remove-device $id 2>&1
    $r | ForEach-Object { W ("  $id : " + $_) }
  } else { W ("  $id : already absent") }
}
Start-Sleep 5

W '--- service stop + delete ---'
$s = & sc.exe stop t6_nvhda 2>&1; $s | ForEach-Object { W ('  stop: ' + $_) }
Start-Sleep 3
$s = & sc.exe delete t6_nvhda 2>&1; $s | ForEach-Object { W ('  delete: ' + $_) }

W '--- delete driver copy ---'
try {
  Remove-Item 'C:\Windows\System32\drivers\nvhda64v.sys' -Force -ErrorAction Stop
  W '  deleted'
} catch { W ('  delete ERROR: ' + $_.Exception.Message) }
$f = Get-Item 'C:\Windows\System32\drivers\nvhda64v.sys' -ErrorAction SilentlyContinue
if ($f) { W ('  STILL PRESENT!') } else { W '  verified gone' }

W '--- remove leftover enum keys ---'
foreach ($k in @('T6NVHDA','T6NVHDA2','T6NVHDA3')) {
  $p = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$k"
  if (Test-Path $p) { Remove-Item $p -Recurse -Force; W ("  removed: " + $p) } else { W ("  clean: $k absent") }
}

W '--- remove orphan DeviceClasses children created for T6NVHDA ---'
$dcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses'
try {
  foreach ($g in (Get-ChildItem $dcRoot -ErrorAction Stop)) {
    $mine = Get-ChildItem $g.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match 'T6NVHDA' }
    foreach ($c in $mine) { Remove-Item $c.PSPath -Recurse -Force; W ("  removed: " + $g.PSChildName + "\" + $c.PSChildName) }
    $left = Get-ChildItem $g.PSPath -ErrorAction SilentlyContinue
    if ((Get-ChildItem $g.PSPath -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0 -and ($g.PSChildName -match 'T6NVHDA|audioprot|audioparam')) {
      # only remove the GUID ROOT if WE created it (marked by the T6NVHDA-ish name) - conservative
      W ("  (GUID root " + $g.PSChildName + " now empty; left in place unless clearly ours)")
    }
  }
} catch { W ("DeviceClasses cleanup ERROR: " + $_.Exception.Message) }

W '--- final verification ---'
try { $rows = driverquery /v /fo csv 2>&1 | Select-String -Pattern 't6_nvhda|nvhda'; if ($rows) { $rows | ForEach-Object { W ('  DRIVERQUERY STILL SHOWS: ' + $_.Line) } } else { W '  driverquery: no nvhda rows (clean)' } }
catch { W ("driverquery ERROR: " + $_.Exception.Message) }
try {
  $d = Get-PnpDevice | Where-Object { $_.InstanceId -match 'T6NVHDA' }
  if ($d) { $d | ForEach-Object { W ('  PNP DEVICE STILL PRESENT: ' + $_.InstanceId + ' ' + $_.Status) } } else { W '  Get-PnpDevice: no T6NVHDA devices (clean)' }
} catch { W ("pnp ERROR: " + $_.Exception.Message) }
foreach ($k in @('T6NVHDA','T6NVHDA2')) {
  if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$k") { W ("  ENUM KEY STILL PRESENT: $k") } else { W "  enum key $k absent" }
}
$sq = & sc.exe query t6_nvhda 2>&1
if ($sq -match '1060') { W '  service deleted (query -> 1060)' } else { $sq | ForEach-Object { W ('  sc query: ' + $_) } }
foreach ($n in @('audioprotection','audioparameters')) {
  $p = "\\.\" + $n
  $h = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) 2>&1
  if ($?) { W ("  $p : STILL OPENABLE (unexpected!)") } else { W ("  $p : fail (expected post-cleanup): " + ($h | Out-String).Trim()) }
}

Marker 'cleanup-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
