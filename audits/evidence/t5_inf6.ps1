# t5_inf6.ps1 (agent t5) - Phase A step 4f: start NetSetupSvc (class-config engine) and
# restart the configured devnode so the Net class config completes and the miniport starts.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_inf6.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"
$devnode = 'ROOT\VPNVA\0000'

WA ("=== t5 inf6 {0} ===" -f (Get-Date -Format o))
Marker 'inf6-start'

WA "--- start NetSetupSvc + netman (demand-start services, normally running on a real host) ---"
sc.exe start NetSetupSvc 2>&1 | ForEach-Object { WA ("  " + $_) }
sc.exe start netman 2>&1 | ForEach-Object { WA ("  " + $_) }
Start-Sleep -Seconds 3

WA "--- pnputil /restart-device ROOT\VPNVA\0000 ---"
Marker 'inf6-BEFORE-restart'
pnputil /restart-device $devnode 2>&1 | ForEach-Object { WA ("  " + $_) }
Start-Sleep -Seconds 20
Marker 'inf6-after-restart'

WA "--- checks ---"
& $exe $log devstat $devnode '' 2>&1 | Out-Null
WA ("  devstat exit=" + $LASTEXITCODE)
& $exe $log qobj '\Device' 'VPNVA' 2>&1 | Out-Null
WA ("  qobj \\Device VPNVA matched=" + ($LASTEXITCODE -eq 0))
& $exe $log open '\\.\VPNVA' 'C0000000' 2>&1 | Out-Null
WA ("  open \\.\VPNVA RW exit=" + $LASTEXITCODE)
foreach ($key in @('DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus','DEVPKEY_Device_HasProblem')) {
  $p = Get-PnpDeviceProperty -InstanceId $devnode -KeyName $key -ErrorAction SilentlyContinue
  if ($p) { WA ("  {0} = {1}" -f $key, $p.Data) } else { WA ("  {0} = <none>" -f $key) }
}

WA "--- Get-NetAdapter -IncludeHidden ---"
try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object Name | Format-Table Name,InterfaceDescription,Status,MediaConnectState,ifIndex -AutoSize | Out-String -Width 200 | ForEach-Object { WA $_ } } catch { WA ("Get-NetAdapter ERROR: " + $_.Exception.Message) }

WA "--- services ---"
sc.exe query vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva' | ForEach-Object { WA ("  " + $_.Line) }

WA "--- netcfg tree (VPNVA connection) ---"
try {
  $nw = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}' -ErrorAction Stop
  $nw | ForEach-Object {
    $conn = Get-ItemProperty "$($_.PSPath)\Connection" -ErrorAction SilentlyContinue
    if ($conn -and $conn.PnpInstanceID -match 'VPNVA') { WA ("  FOUND: {0}: Name={1} PnpInstanceID={2}" -f $_.PSChildName, $conn.Name, $conn.PnpInstanceID) }
  }
} catch { WA ("  netcfg tree ERROR: " + $_.Exception.Message) }

WA "--- Kernel-PnP/Configuration log (last 5) ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 5 -ErrorAction Stop | ForEach-Object { WA ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } } catch { WA ("  ERROR: " + $_.Exception.Message) }

Marker 'inf6-done'
