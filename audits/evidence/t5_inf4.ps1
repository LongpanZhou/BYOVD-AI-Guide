# t5_inf4.ps1 (agent t5) - Phase A step 4d: full INF install of the matched devnode.
# Uses UpdateDriverForPlugAndPlayDevicesW(INSTALLFLAG_FORCE) on hw-id VPNVA with the real
# Cisco INF - this runs the complete install path (class installer, netcfg, driver key,
# service) exactly as a genuine AnyConnect deployment, then checks the miniport surface.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_inf4.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"
$devnode = 'ROOT\VPNVA\0000'

WA ("=== t5 inf4 (full INF install) {0} ===" -f (Get-Date -Format o))
Marker 'inf4-start'

& $exe $log instdev 'VPNVA' "$work\vpnva-6.inf" 2>&1 | Out-Null
$rc = $LASTEXITCODE
WA ("  instdev exit=" + $rc)
Start-Sleep -Seconds 20
Marker 'inf4-after-install'

WA "--- checks ---"
& $exe $log devstat $devnode '' 2>&1 | Out-Null
WA ("  devstat exit=" + $LASTEXITCODE)
& $exe $log qobj '\Device' 'VPNVA' 2>&1 | Out-Null
WA ("  qobj \\Device VPNVA matched=" + ($LASTEXITCODE -eq 0))
& $exe $log qobj '\GLOBAL??' 'VPNVA' 2>&1 | Out-Null
WA ("  qobj \\GLOBAL?? VPNVA matched=" + ($LASTEXITCODE -eq 0))
& $exe $log open '\\.\VPNVA' 'C0000000' 2>&1 | Out-Null
WA ("  open \\.\VPNVA RW exit=" + $LASTEXITCODE)
foreach ($key in @('DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus','DEVPKEY_Device_DriverInfPath','DEVPKEY_Device_Service','DEVPKEY_Device_ClassGuid')) {
  try { $p = Get-PnpDeviceProperty -InstanceId $devnode -KeyName $key -ErrorAction Stop; WA ("  {0} = {1}" -f $key, $p.Data) } catch { WA ("  {0} = <failed>" -f $key) }
}

WA "--- Get-NetAdapter -IncludeHidden ---"
try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object Name | Format-Table Name,InterfaceDescription,Status,MediaConnectState,ifIndex -AutoSize | Out-String -Width 200 | ForEach-Object { WA $_ } } catch { WA ("Get-NetAdapter ERROR: " + $_.Exception.Message) }

WA "--- services ---"
sc.exe query vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
sc.exe query t5_vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
WA "--- driverquery rows ---"
driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva' | ForEach-Object { WA ("  " + $_.Line) }

WA "--- netcfg state (System\Control\Network tree for the new adapter) ---"
try {
  $nw = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}' -ErrorAction Stop
  $nw | ForEach-Object {
    $conn = Get-ItemProperty "$($_.PSPath)\Connection" -ErrorAction SilentlyContinue
    if ($conn) { WA ("  {0}: Name={1} PnpInstanceID={2}" -f $_.PSChildName, $conn.Name, $conn.PnpInstanceID) }
  }
} catch { WA ("  netcfg tree ERROR: " + $_.Exception.Message) }

WA "--- Kernel-PnP/Configuration log (last 8) ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 8 -ErrorAction Stop | ForEach-Object { WA ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } } catch { WA ("  ERROR: " + $_.Exception.Message) }

Marker 'inf4-done'
