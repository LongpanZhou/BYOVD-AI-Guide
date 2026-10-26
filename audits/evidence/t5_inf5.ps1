# t5_inf5.ps1 (agent t5) - Phase A step 4e: clean restart of the INF-configured devnode.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_inf5.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"
$devnode = 'ROOT\VPNVA\0000'

WA ("=== t5 inf5 {0} ===" -f (Get-Date -Format o))
Marker 'inf5-start'

WA "--- INF-installed driver key contents ---"
$drvLink = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\VPNVA\0000' -Name Driver -ErrorAction SilentlyContinue).Driver
WA ("  Driver link: " + $drvLink)
if ($drvLink) {
  $dk = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$drvLink"
  (Get-ItemProperty $dk -ErrorAction SilentlyContinue) | Select-Object * -ExcludeProperty PS* | Out-String -Width 220 | ForEach-Object { WA ("  " + $_) }
  Get-ChildItem $dk -ErrorAction SilentlyContinue | ForEach-Object {
    WA ("  SUBKEY: " + $_.PSChildName)
    (Get-ItemProperty $_.PSPath | Select-Object * -ExcludeProperty PS*) | Out-String -Width 220 | ForEach-Object { WA ("    " + $_) }
  }
}
WA "--- enum key values ---"
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\VPNVA\0000') | Select-Object * -ExcludeProperty PS* | Out-String -Width 220 | ForEach-Object { WA ("  " + $_) }
WA "--- service vpnva key ---"
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\vpnva' -ErrorAction SilentlyContinue) | Select-Object Start,Type,ErrorControl,ImagePath,Group,DisplayName | Out-String -Width 220 | ForEach-Object { WA ("  " + $_) }

WA "--- pnputil /restart-device ROOT\VPNVA\0000 ---"
Marker 'inf5-BEFORE-restart'
pnputil /restart-device $devnode 2>&1 | ForEach-Object { WA ("  " + $_) }
Start-Sleep -Seconds 15
Marker 'inf5-after-restart'

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
try { Get-CimInstance Win32_PnPEntity -Filter "DeviceID='ROOT\\VPNVA\\0000'" -ErrorAction Stop | ForEach-Object { WA ("  Win32_PnPEntity: Status={0} ConfigManagerErrorCode={1}" -f $_.Status, $_.ConfigManagerErrorCode) } } catch { WA ("  PnPEntity ERROR: " + $_.Exception.Message) }

WA "--- Get-NetAdapter -IncludeHidden (Cisco rows highlighted) ---"
try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.InterfaceDescription -match 'Cisco|VPN|AnyConnect' -or $_.Name -match 'VPN' } | Format-Table -AutoSize | Out-String -Width 200 | ForEach-Object { WA $_ }
  $all = Get-NetAdapter -IncludeHidden -ErrorAction Stop
  WA ("  total adapters: " + $all.Count)
} catch { WA ("Get-NetAdapter ERROR: " + $_.Exception.Message) }

WA "--- services + driverquery ---"
sc.exe query vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva' | ForEach-Object { WA ("  " + $_.Line) }

WA "--- System log NDIS/VPNVA events since 17:36 ---"
try {
  $t0 = Get-Date '2026-10-23 17:36:00'
  Get-WinEvent -LogName System -MaxEvents 200 -ErrorAction Stop | Where-Object { $_.TimeCreated -ge $t0 } | ForEach-Object {
    WA ("  [{0}] id={1} prov={2} lvl={3}" -f $_.TimeCreated, $_.Id, $_.ProviderName, $_.Level)
    ($_.Message -replace '\r?\n', ' | ') | ForEach-Object { WA ("      " + $_) }
  }
} catch { WA ("  ERROR: " + $_.Exception.Message) }

WA "--- Kernel-PnP/Configuration log (last 6) ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 6 -ErrorAction Stop | ForEach-Object { WA ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } } catch { WA ("  ERROR: " + $_.Exception.Message) }

Marker 'inf5-done'
