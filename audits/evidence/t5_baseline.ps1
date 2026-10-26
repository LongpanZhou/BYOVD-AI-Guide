# t5_baseline.ps1 (agent t5) - Phase A step 1: pre-load baseline. Evidence: t5_baseline.txt
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log = Join-Path $work 't5_baseline.txt'
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

W ("=== t5 baseline {0} ===" -f (Get-Date -Format o))
Marker 'baseline-start'

W "--- Get-PnpDevice (full list) ---"
try { Get-PnpDevice -ErrorAction Stop | Sort-Object Class,InstanceId | Format-Table -AutoSize -Wrap | Out-String -Width 220 | ForEach-Object { W $_ } }
catch { W ("Get-PnpDevice ERROR: " + $_.Exception.Message) }

W "--- Get-PnpDevice rows matching VPN/VA/Net-class Cisco (highlight) ---"
try { Get-PnpDevice -ErrorAction Stop | Where-Object { ($_.InstanceId -match 'VPN|T5VPNVA') -or ($_.FriendlyName -match 'Cisco|VPN') } | Format-Table -AutoSize | Out-String -Width 200 | ForEach-Object { W $_ } }
catch { W ("highlight ERROR: " + $_.Exception.Message) }

W "--- DeviceClasses GUID keys ---"
try {
  $dc = (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses' -ErrorAction Stop).PSChildName
  $dc | ForEach-Object { W $_ }
  $dc | Set-Content "$work\t5_dc_before.txt"   # snapshot for the post-load diff in t5_surface
}
catch { W ("DeviceClasses ERROR: " + $_.Exception.Message) }

W "--- HKLM\SYSTEM\CCS\Enum\ROOT children ---"
try { (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT' -ErrorAction Stop).PSChildName | ForEach-Object { W $_ } }
catch { W ("Enum ROOT ERROR: " + $_.Exception.Message) }

W "--- driverquery /v rows matching vpnva (none = absent) ---"
try { $rows = driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva'; if ($rows) { $rows | ForEach-Object { W $_.Line } } else { W '(no vpnva rows)' } }
catch { W ("driverquery ERROR: " + $_.Exception.Message) }

W "--- vpnva*/t5_* service keys (pre-existing check) ---"
try {
  $svc = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop | Where-Object { $_.PSChildName -match '^vpnva|^t5_' }
  if ($svc) { $svc | ForEach-Object { W ("  service key: " + $_.PSChildName); $v = Get-ItemProperty $_.PSPath; W ("    ImagePath: " + $v.ImagePath); W ("    Start: " + $v.Start + "  Type: " + $v.Type) } }
  else { W '  (no vpnva*/t5_* service keys)' }
}
catch { W ("service scan ERROR: " + $_.Exception.Message) }

W "--- existing C:\Windows\System32\drivers\vpnva64-6.sys ---"
try {
  $f = Get-Item 'C:\Windows\System32\drivers\vpnva64-6.sys' -ErrorAction SilentlyContinue
  if ($f) { W ("  EXISTS size=" + $f.Length + " hash=" + (Get-FileHash $f.FullName -Algorithm SHA256).Hash) }
  else { W '  absent' }
}
catch { W ("file check ERROR: " + $_.Exception.Message) }

W "--- t5 enum-key leftovers (expect none) ---"
foreach ($k in @('T5VPNVA','T5VPNVA2')) {
  $p = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$k"
  if (Test-Path $p) { W ("  LEFTOVER PRESENT: " + $p) } else { W ("  clean: $k absent") }
}

W "--- network adapter list (baseline, before load) ---"
try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object Name | Format-Table Name,InterfaceDescription,Status,MediaConnectState,ifIndex,DriverVersionString -AutoSize | Out-String -Width 200 | ForEach-Object { W $_ } }
catch { W ("Get-NetAdapter ERROR: " + $_.Exception.Message) }

W "--- netsh interface show interface (compact) ---"
try { netsh interface show interface 2>&1 | ForEach-Object { W ("  " + $_) } }
catch { W ("netsh ERROR: " + $_.Exception.Message) }

W "--- netsh i i show all (FULL output saved to t5_netsh_before.txt) ---"
try {
  netsh i i show all 2>&1 | Out-String | Set-Content "$work\t5_netsh_before.txt"
  W ("  saved; contains-Cisco-AnyConnect mentions: " + ([regex]::Matches((Get-Content "$work\t5_netsh_before.txt" -Raw), 'Cisco AnyConnect')).Count)
}
catch { W ("netsh-all ERROR: " + $_.Exception.Message) }

Marker 'baseline-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
