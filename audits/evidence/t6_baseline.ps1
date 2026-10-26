# t6_baseline.ps1 (agent t6) - Phase A step 1: pre-load baseline. Evidence: t6_baseline.txt
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$log  = "$work\t6_baseline.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t6_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

W ("=== t6 baseline {0} ===" -f (Get-Date -Format o))
Marker 'baseline-start'

W "--- Get-PnpDevice (full list) ---"
try { Get-PnpDevice -ErrorAction Stop | Sort-Object Class,InstanceId | Format-Table -AutoSize -Wrap | Out-String -Width 220 | ForEach-Object { W $_ } }
catch { W ("Get-PnpDevice ERROR: " + $_.Exception.Message) }

W "--- DeviceClasses GUID keys ---"
try { (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses' -ErrorAction Stop).PSChildName | ForEach-Object { W $_ } }
catch { W ("DeviceClasses ERROR: " + $_.Exception.Message) }

# machine-readable copy for the post-load diff
try { (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses' -ErrorAction Stop).PSChildName | Sort-Object | Set-Content "$work\t6_dc_before.txt" } catch { W ("dc_before save ERROR: " + $_.Exception.Message) }

W "--- HKLM\SYSTEM\CCS\Enum\ROOT children ---"
try { (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT' -ErrorAction Stop).PSChildName | ForEach-Object { W $_ } }
catch { W ("Enum ROOT ERROR: " + $_.Exception.Message) }

W "--- driverquery rows matching nvhda (none = absent) ---"
try { $rows = driverquery /v /fo csv 2>&1 | Select-String -Pattern 'nvhda'; if ($rows) { $rows | ForEach-Object { W $_.Line } } else { W '(no nvhda rows)' } }
catch { W ("driverquery ERROR: " + $_.Exception.Message) }

W "--- nv*/t6_* service keys (pre-existing check) ---"
try {
  $svc = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop | Where-Object { $_.PSChildName -match '^nv|^t6_' }
  if ($svc) { $svc | ForEach-Object { W ("  service key: " + $_.PSChildName); $v = Get-ItemProperty $_.PSPath; W ("    ImagePath: " + $v.ImagePath); W ("    Start: " + $v.Start + "  Type: " + $v.Type) } }
  else { W '  (no nv*/t6_* service keys)' }
}
catch { W ("service scan ERROR: " + $_.Exception.Message) }

W "--- audio devices (Win32_SoundDevice) ---"
try { Get-CimInstance Win32_SoundDevice -ErrorAction Stop | Format-Table -AutoSize Name,Manufacturer,Status,PNPDeviceID | Out-String -Width 200 | ForEach-Object { W $_ } }
catch { W ("Win32_SoundDevice ERROR: " + $_.Exception.Message) }

W "--- audio-related pnp classes present? (Media children count) ---"
try { $media = Get-PnpDevice -Class Media -ErrorAction SilentlyContinue; W ("Media-class devices: " + ($media | Measure-Object).Count); $media | ForEach-Object { W ("  " + $_.Status + "  " + $_.InstanceId) } }
catch { W ("Media class scan ERROR: " + $_.Exception.Message) }

W "--- existing C:\Windows\System32\drivers\nvhda64v.sys ---"
try {
  $f = Get-Item 'C:\Windows\System32\drivers\nvhda64v.sys' -ErrorAction SilentlyContinue
  if ($f) { W ("  EXISTS size=" + $f.Length + " hash=" + (Get-FileHash $f.FullName -Algorithm SHA256).Hash) }
  else { W '  absent' }
}
catch { W ("file check ERROR: " + $_.Exception.Message) }

W "--- baseline probes of the static-audit control names (driver not loaded yet -> expect FILE_NOT_FOUND) ---"
foreach ($n in @('audioprotection','audioparameters')) {
  $p = "\\.\" + $n
  $h = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) 2>&1
  if ($?) { W ("  $p : OPENED?! (unexpected at baseline)") } else { W ("  $p : fail (expected): " + ($h | Out-String).Trim()) }
}

W "--- t6 enum-key leftovers (expect none) ---"
foreach ($k in @('T6NVHDA','T6NVHDA2','T6NVHDA3')) {
  $p = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$k"
  if (Test-Path $p) { W ("  LEFTOVER PRESENT: " + $p) } else { W ("  clean: $k absent") }
}

Marker 'baseline-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
