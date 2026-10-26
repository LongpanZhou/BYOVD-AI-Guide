# t5_inf2.ps1 (agent t5) - Phase A step 4b (fix): seed ROOT\VPNVA\0000 hardware ID and restart.
# t5_inf.txt showed the devnode restart hit CM_PROB 1 (NOT_CONFIGURED) because the seed step
# was skipped (PowerShell captured PoC stdout instead of exit code). The INF package is now
# installed in the guest as oem9.inf (WHQL-signed, class Net) - restart should now match it.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_inf.txt"
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"

WA ("=== t5 inf-deploy fix {0} ===" -f (Get-Date -Format o))
Marker 'inf2-start'

# --- seed the existing ROOT\VPNVA\0000 enum key ---
$k = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\VPNVA\0000'
if (-not (Test-Path $k)) { WA "ABORT: enum key ROOT\VPNVA\0000 absent (create first)"; exit 5 }
New-ItemProperty -Path $k -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $k -Name 'HardwareID' -Value 'VPNVA' -PropertyType MultiString -Force | Out-Null
WA "seeded ConfigFlags=0 (DWORD) + HardwareID=VPNVA (MULTI_SZ)"
(Get-ItemProperty $k) | Select-Object * -ExcludeProperty PS* | Out-String -Width 200 | ForEach-Object { WA ("  " + $_) }

# --- restart -> PnP INF match -> install (oem9.inf) -> miniport init ---
Marker 'inf2-BEFORE-restart'
WA "--- pnputil /restart-device ROOT\VPNVA\0000 ---"
pnputil /restart-device 'ROOT\VPNVA\0000' 2>&1 | ForEach-Object { WA ("  " + $_) }
Start-Sleep -Seconds 15
Marker 'inf2-after-restart'

# --- checks ---
WA "--- checks ---"
& $exe $log devstat 'ROOT\VPNVA\0000' '' 2>&1 | Out-Null
WA ("  devstat exit=" + $LASTEXITCODE)
& $exe $log qobj '\Device' 'VPNVA' 2>&1 | Out-Null
WA ("  qobj \\Device VPNVA matched=" + ($LASTEXITCODE -eq 0))
& $exe $log open '\\.\VPNVA' 'C0000000' 2>&1 | Out-Null
WA ("  open \\.\VPNVA RW exit=" + $LASTEXITCODE)
try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object Name | Format-Table Name,InterfaceDescription,Status,MediaConnectState,ifIndex -AutoSize | Out-String -Width 200 | ForEach-Object { WA $_ } } catch { WA ("Get-NetAdapter ERROR: " + $_.Exception.Message) }
WA "--- sc query vpnva ---"
sc.exe query vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
WA "--- driverquery rows ---"
driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva' | ForEach-Object { WA ("  " + $_.Line) }
WA "--- devnode properties ---"
foreach ($key in @('DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus','DEVPKEY_Device_DriverInfPath','DEVPKEY_Device_Service','DEVPKEY_Device_ClassGuid')) {
  try { $p = Get-PnpDeviceProperty -InstanceId 'ROOT\VPNVA\0000' -KeyName $key -ErrorAction Stop; WA ("  {0} = {1}" -f $key, $p.Data) } catch { WA ("  {0} = <failed>" -f $key) }
}
WA "--- Kernel-PnP/Configuration log (last 8) ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 8 -ErrorAction Stop | ForEach-Object { WA ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } } catch { WA ("  ERROR: " + $_.Exception.Message) }

Marker 'inf2-done'
