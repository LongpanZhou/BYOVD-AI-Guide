# t5_surface.ps1 (agent t5) - Phase A step 5: surface observation after devnode restart.
# KEY QUESTION: did the NDIS miniport instantiate and register its control device
# \Device\VPNVA (static audit vpnva.md section 2: registered exactly once from
# MiniportInitializeEx, no device-interface GUID is published)?
# Evidence: t5_surface.txt (+ t5_netsh_after.txt full netsh dump)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_surface.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"

function Poc($c, $a1, $a2) {
  & $exe $log $c $a1 $a2 2>&1 | Out-Null
  return $LASTEXITCODE
}

W ("=== t5 surface {0} ===" -f (Get-Date -Format o))
Marker 'surface-start'

W "--- sc query t5_vpnva ---"
sc.exe query t5_vpnva 2>&1 | ForEach-Object { W ("  " + $_) }

W "--- driverquery /v rows matching vpnva ---"
driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva' | ForEach-Object { W ("  " + $_.Line) }

W "--- devnode status (both variants) ---"
$rc = Poc 'devstat' 'ROOT\T5VPNVA\0000' '';  W ("  T5VPNVA devstat exit=" + $rc)
$rc = Poc 'devstat' 'ROOT\T5VPNVA2\0000' ''; W ("  T5VPNVA2 devstat exit=" + $rc + " (3=not found = variant not created)")

W "--- kernel object probes: \\Device + \\GLOBAL?? filtered 'VPNVA' ---"
$rc = Poc 'qobj' '\Device' 'VPNVA';    W ("  \\Device    matched=" + ($rc -eq 0))
$rc = Poc 'qobj' '\GLOBAL??' 'VPNVA';  W ("  \\GLOBAL??  matched=" + ($rc -eq 0) + " (DOS symlink \\.\VPNVA)")

W "--- CreateFile probe \\.\VPNVA (RW, admin full token) ---"
$rc = Poc 'open' '\\.\VPNVA' 'C0000000'; W ("  open exit=" + $rc + " (0=open OK)")

W "--- security descriptor of \\.\VPNVA (MAXIMUM_ALLOWED + SDDL) ---"
$rc = Poc 'sd' '\\.\VPNVA' ''; W ("  sd exit=" + $rc)

W "--- Get-NetAdapter -IncludeHidden (full) ---"
try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object Name | Format-Table -AutoSize -Wrap | Out-String -Width 220 | ForEach-Object { W $_ } }
catch { W ("Get-NetAdapter ERROR: " + $_.Exception.Message) }

W "--- Get-NetAdapterStatistics ---"
try { Get-NetAdapterStatistics -ErrorAction Stop | Format-Table Name,ReceivedBytes,ReceivedUnicastPackets,SentBytes,SentUnicastPackets -AutoSize | Out-String -Width 200 | ForEach-Object { W $_ } }
catch { W ("Get-NetAdapterStatistics ERROR: " + $_.Exception.Message) }

W "--- netsh interface show interface (compact) ---"
try { netsh interface show interface 2>&1 | ForEach-Object { W ("  " + $_) } } catch { W ("netsh ERROR: " + $_.Exception.Message) }

W "--- netsh i i show all (FULL -> t5_netsh_after.txt; summary here) ---"
try {
  netsh i i show all 2>&1 | Out-String | Set-Content "$work\t5_netsh_after.txt"
  $raw = Get-Content "$work\t5_netsh_after.txt" -Raw
  W ("  saved; 'Cisco AnyConnect' mentions: " + ([regex]::Matches($raw, 'Cisco AnyConnect')).Count)
  W ("  interface names list:")
  netsh interface show interface 2>&1 | ForEach-Object { W ("    " + $_) }
} catch { W ("netsh-all ERROR: " + $_.Exception.Message) }

W "--- DeviceClasses GUID delta (vs t5_dc_before.txt) ---"
try {
  $before = Get-Content "$work\t5_dc_before.txt" -ErrorAction SilentlyContinue
  $now = (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses' -ErrorAction Stop).PSChildName
  $new = $now | Where-Object { $before -notcontains $_ }
  if ($new) { $new | ForEach-Object { W ("  NEW GUID: " + $_) } }
  else { W ("  none (count before=" + $before.Count + " now=" + $now.Count + ") - expected: audit documents NO device-interface GUID") }
}
catch { W ("DeviceClasses delta ERROR: " + $_.Exception.Message) }

W "--- Kernel-PnP/Configuration log (last 15) ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 15 -ErrorAction Stop | ForEach-Object { W ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } }
catch { W ("  ERROR: " + $_.Exception.Message) }

W "--- System log events mentioning ndis/vpnva (last 40 scan) ---"
try { Get-WinEvent -LogName System -MaxEvents 40 -ErrorAction Stop | Where-Object { ($_.ProviderName -match 'ndis|vpnva') -or ($_.Message -match 'ndis|VPNVA|Cisco') } | ForEach-Object { W ("  [{0}] id={1} prov={2} {3}" -f $_.TimeCreated, $_.Id, $_.ProviderName, ($_.Message -replace '\r?\n', ' | ')) } }
catch { W ("  ERROR: " + $_.Exception.Message) }
W "--- Microsoft-Windows-NDIS/Operational (may not exist) ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-NDIS/Operational' -MaxEvents 10 -ErrorAction Stop | ForEach-Object { W ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } }
catch { W ("  (log absent or empty: " + $_.Exception.Message + ")") }

Marker 'surface-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
