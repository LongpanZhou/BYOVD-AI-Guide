# t4_cleanup.ps1 (agent t4) - Phase A step 9: full teardown of t4 artifacts. Evidence: t4_cleanup.txt
$log = 'C:\Users\vmdebug\Desktop\t4_work\t4_cleanup.txt'
$work = 'C:\Users\vmdebug\Desktop\t4_work'
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t4_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

W ("=== t4 cleanup {0} ===" -f (Get-Date -Format o))
Marker 'cleanup-start'

W '--- pnputil /remove-device (created devnodes) ---'
foreach ($id in @('ROOT\T4SILABSER\0000','ROOT\T4SILABSER2\0000')) {
  W ('  device: ' + $id)
  pnputil /remove-device $id 2>&1 | ForEach-Object { W ('    ' + $_) }
}

W '--- sc stop + sc delete t4_silabser ---'
sc.exe stop t4_silabser 2>&1 | ForEach-Object { W ('    ' + $_) }
Start-Sleep 2
sc.exe delete t4_silabser 2>&1 | ForEach-Object { W ('    ' + $_) }

W '--- delete drivers\silabser.sys copy ---'
if (Test-Path 'C:\Windows\System32\drivers\silabser.sys') { Remove-Item 'C:\Windows\System32\drivers\silabser.sys' -Force; W '  deleted' } else { W '  already absent' }

W '--- remove leftover enum keys ---'
foreach ($k in @('T4SILABSER','T4SILABSER2')) {
  $p = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$k"
  if (Test-Path $p) { Remove-Item $p -Recurse -Force; W ('  removed ' + $p) } else { W ('  absent ' + $p) }
}

W '--- DeviceClasses: remove T4 instance keys; delete GUID roots only if empty ---'
foreach ($g in @('{a2a39220-39f4-4b88-aecb-3d86a35dc748}','{86e0d1e0-8089-11d0-9ce4-08003e301f73}')) {
  $root = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\$g"
  if (Test-Path $root) {
    $t4 = Get-ChildItem $root -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '*T4SILABSER*' }
    foreach ($t in $t4) { Remove-Item $t.PSPath -Recurse -Force; W ('  removed instance key: ' + $t.PSChildName) }
    $left = (Get-ChildItem $root -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($left -eq 0) { Remove-Item $root -Force; W ('  removed EMPTY GUID root: ' + $g) }
    else { W ('  GUID root kept (' + $left + ' non-t4 children remain): ' + $g) }
  } else { W ('  absent GUID root: ' + $g) }
}

W '--- verify: no t4/silabser services ---'
sc.exe query t4_silabser 2>&1 | ForEach-Object { W ('    ' + $_) }
driverquery /v /fo csv 2>&1 | Select-String -Pattern 'silabser|t4_' | ForEach-Object { W ('    driverquery: ' + $_.Line) }

W '--- verify: no T4SILABSER pnp devices ---'
$d = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match 'T4SILABSER' }
if ($d) { $d | ForEach-Object { W ('    STILL PRESENT: ' + $_.InstanceId + ' ' + $_.Status) } } else { W '    (clean)' }

W '--- verify: DeviceClasses GUID roots gone ---'
foreach ($g in @('{a2a39220-39f4-4b88-aecb-3d86a35dc748}','{86e0d1e0-8089-11d0-9ce4-08003e301f73}')) {
  W ('  {0}: {1}' -f $g, (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\$g"))
}

W '--- verify: drivers\silabser.sys gone ---'
W ('  ' + (-not (Test-Path 'C:\Windows\System32\drivers\silabser.sys')))

W '--- SERIALCOMM DeviceMap (post-cleanup) ---'
$ser = Get-ItemProperty 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM' -ErrorAction SilentlyContinue
if ($ser) { $ser.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { W ('  {0} = {1}' -f $_.Name, $_.Value) } }
else { W '  (absent)' }

W '--- kept: t4_work\ scripts + staged phase-B files (per instructions) ---'
Get-ChildItem $work | ForEach-Object { W ('  ' + $_.Name) }

Marker 'cleanup-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
