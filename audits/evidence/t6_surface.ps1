# t6_surface.ps1 (agent t6) - Phase A step 5: surface observation. Evidence: t6_surface.txt
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$log  = "$work\t6_surface.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t6_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t6_poc.exe"

W ("=== t6 surface {0} ===" -f (Get-Date -Format o))
Marker 'surface-start'

W "--- devnode statuses ---"
foreach ($id in @('ROOT\T6NVHDA\0000','ROOT\T6NVHDA2\0000')) {
  if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$id") {
    & $exe "$work\t6_surface_devstat.txt" devstat $id 2>&1 | Out-Null
    if (Test-Path "$work\t6_surface_devstat.txt") { Get-Content "$work\t6_surface_devstat.txt" | ForEach-Object { W ('  ' + $_) } }
    foreach ($kn in @('DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus','DEVPKEY_Device_Service')) {
      $p = Get-PnpDeviceProperty -InstanceId $id -KeyName $kn -ErrorAction SilentlyContinue
      if ($p) { W ("    $kn = " + $p.Data) }
    }
  } else { W ("  (devnode key absent: $id)") }
}

W "--- service state ---"
& sc.exe query t6_nvhda 2>&1 | ForEach-Object { W ('  ' + $_) }

W "--- DeviceClasses scan: any T6NVHDA instance under ANY GUID root ---"
$dcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses'
$found = 0
try {
  foreach ($g in (Get-ChildItem $dcRoot -ErrorAction Stop)) {
    foreach ($c in (Get-ChildItem $g.PSPath -ErrorAction SilentlyContinue)) {
      if ($c.PSChildName -match 'T6NVHDA') {
        $found++
        W ("  " + $g.PSChildName + "  ->  " + $c.PSChildName)
        $v = Get-ItemProperty $c.PSPath -ErrorAction SilentlyContinue
        if ($v) { W ("      DeviceInstance = " + $v.DeviceInstance) }
      }
    }
  }
  if ($found -eq 0) { W '  (none)' }
} catch { W ("DeviceClasses scan ERROR: " + $_.Exception.Message) }

W "--- DeviceClasses GUID diff vs baseline (t6_dc_before.txt) ---"
try {
  $before = Get-Content "$work\t6_dc_before.txt" -ErrorAction SilentlyContinue
  $now = (Get-ChildItem $dcRoot).PSChildName | Sort-Object
  $new = $now | Where-Object { $before -notcontains $_ }
  if ($new) { $new | ForEach-Object { W ("  NEW GUID root: " + $_) } } else { W '  (no new GUID roots)' }
} catch { W ("diff ERROR: " + $_.Exception.Message) }

W "--- SetupAPI: all present device interfaces matching 'T6NVHDA' ---"
& $exe "$work\t6_surface_ifall.txt" ifall 'T6NVHDA' 2>&1 | Out-Null
if (Test-Path "$work\t6_surface_ifall.txt") { Get-Content "$work\t6_surface_ifall.txt" | ForEach-Object { W ('  ' + $_) } }

W "--- Kernel object directory probes ---"
foreach ($d in @('\Device','\GLOBAL??')) {
  foreach ($f in @('nvhda','NvHDA','audio','protection','parameters')) {
    & $exe "$work\t6_surface_qobj.txt" qobj $d $f 2>&1 | Out-Null
    if (Test-Path "$work\t6_surface_qobj.txt") { Get-Content "$work\t6_surface_qobj.txt" | ForEach-Object { W ('  ' + $_) } }
  }
}

W "--- audio devices (Win32_SoundDevice) after start attempt ---"
try { Get-CimInstance Win32_SoundDevice -ErrorAction Stop | Format-Table -AutoSize Name,Manufacturer,Status,PNPDeviceID | Out-String -Width 200 | ForEach-Object { W $_ } }
catch { W ("Win32_SoundDevice ERROR: " + $_.Exception.Message) }

W "--- System event log (last 12) ---"
try { Get-WinEvent -LogName System -MaxEvents 12 -ErrorAction Stop | ForEach-Object { W ("  [{0}] id={1} prov={2} lvl={3}`n      {4}" -f $_.TimeCreated, $_.Id, $_.ProviderName, $_.Level, ($_.Message -replace '\r?\n',' | ')) } }
catch { W ("  event ERROR: " + $_.Exception.Message) }

W "--- Kernel-PnP/Configuration log (last 20) ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 20 -ErrorAction Stop | ForEach-Object { W ("  [{0}] id={1} lvl={2}`n      {3}" -f $_.TimeCreated, $_.Id, $_.Level, ($_.Message -replace '\r?\n', ' | ')) } }
catch { W ("  ERROR: " + $_.Exception.Message) }

W "--- setupapi.dev.log tail (last 80 lines) ---"
try { Get-Content 'C:\Windows\INF\setupapi.dev.log' -Tail 80 -ErrorAction Stop | ForEach-Object { W ('  ' + $_) } }
catch { W ("  setupapi.dev.log ERROR: " + $_.Exception.Message) }

Marker 'surface-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
