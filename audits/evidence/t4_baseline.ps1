# t4_baseline.ps1 (agent t4) - Phase A step 1: pre-load baseline. Evidence: t4_baseline.txt
$log = 'C:\Users\vmdebug\Desktop\t4_work\t4_baseline.txt'
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path 'C:\Users\vmdebug\Desktop\t4_work\t4_alive.txt' -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

W ("=== t4 baseline {0} ===" -f (Get-Date -Format o))
Marker 'baseline-start'

W "--- Get-PnpDevice (full list) ---"
try { Get-PnpDevice -ErrorAction Stop | Sort-Object Class,InstanceId | Format-Table -AutoSize -Wrap | Out-String -Width 220 | ForEach-Object { W $_ } }
catch { W ("Get-PnpDevice ERROR: " + $_.Exception.Message) }

W "--- DeviceClasses GUID keys ---"
try { (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses' -ErrorAction Stop).PSChildName | ForEach-Object { W $_ } }
catch { W ("DeviceClasses ERROR: " + $_.Exception.Message) }

W "--- HKLM\SYSTEM\CCS\Enum\ROOT children ---"
try { (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT' -ErrorAction Stop).PSChildName | ForEach-Object { W $_ } }
catch { W ("Enum ROOT ERROR: " + $_.Exception.Message) }

W "--- driverquery /v rows matching silabser (none = absent) ---"
try { $rows = driverquery /v /fo csv 2>&1 | Select-String -Pattern 'silabser'; if ($rows) { $rows | ForEach-Object { W $_.Line } } else { W '(no silabser rows)' } }
catch { W ("driverquery ERROR: " + $_.Exception.Message) }

W "--- silab*/t4_* service keys (pre-existing check; T4 leftovers check) ---"
try {
  $svc = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop | Where-Object { $_.PSChildName -match 'silab|t4_' }
  if ($svc) { $svc | ForEach-Object { W ("  service key: " + $_.PSChildName); $v = Get-ItemProperty $_.PSPath; W ("    ImagePath: " + $v.ImagePath); W ("    Start: " + $v.Start + "  Type: " + $v.Type) } }
  else { W '  (no silab*/t4_* service keys)' }
}
catch { W ("service scan ERROR: " + $_.Exception.Message) }

W "--- existing C:\Windows\System32\drivers\silabser.sys ---"
try {
  $f = Get-Item 'C:\Windows\System32\drivers\silabser.sys' -ErrorAction SilentlyContinue
  if ($f) { W ("  EXISTS size=" + $f.Length + " hash=" + (Get-FileHash $f.FullName -Algorithm SHA256).Hash) }
  else { W '  absent' }
}
catch { W ("file check ERROR: " + $_.Exception.Message) }

W "--- SERIALCOMM DeviceMap (baseline) ---"
try {
  $ser = Get-ItemProperty 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM' -ErrorAction SilentlyContinue
  if ($ser) { $ser.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { W ("  {0} = {1}" -f $_.Name, $_.Value) } }
  else { W '  (absent)' }
}
catch { W ("SERIALCOMM ERROR: " + $_.Exception.Message) }

W "--- t4 enum-key leftovers (expect none) ---"
foreach ($k in @('T4SILABSER','T4SILABSER2')) {
  $p = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$k"
  if (Test-Path $p) { W ("  LEFTOVER PRESENT: " + $p) } else { W ("  clean: $k absent") }
}

Marker 'baseline-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
