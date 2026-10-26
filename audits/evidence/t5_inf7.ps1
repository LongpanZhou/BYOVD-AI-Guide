# t5_inf7.ps1 (agent t5) - Phase A step 4g: retry class config with services confirmed RUNNING.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_inf7.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"
$devnode = 'ROOT\VPNVA\0000'
$ek = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\VPNVA\0000'

function Check($label) {
  WA "--- checks: $label ---"
  & $exe $log devstat $devnode '' 2>&1 | Out-Null
  WA ("  devstat exit=" + $LASTEXITCODE)
  & $exe $log qobj '\Device' 'VPNVA' 2>&1 | Out-Null
  WA ("  qobj \\Device VPNVA matched=" + ($LASTEXITCODE -eq 0))
  & $exe $log open '\\.\VPNVA' 'C0000000' 2>&1 | Out-Null
  WA ("  open \\.\VPNVA RW exit=" + $LASTEXITCODE)
  $p = Get-PnpDeviceProperty -InstanceId $devnode -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue
  WA ("  ProblemCode = " + $p.Data)
}

WA ("=== t5 inf7 {0} ===" -f (Get-Date -Format o))
Marker 'inf7-start'

WA "--- service states now ---"
sc.exe query NetSetupSvc 2>&1 | Select-String -Pattern 'STATE' | ForEach-Object { WA ("  NetSetupSvc " + $_.Line.Trim()) }
sc.exe query netman 2>&1 | Select-String -Pattern 'STATE' | ForEach-Object { WA ("  netman " + $_.Line.Trim()) }

WA "--- clear CONFIGFLAG_FAILEDINSTALL (0x80000) ---"
New-ItemProperty -Path $ek -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
WA "  ConfigFlags=0"

Marker 'inf7-BEFORE-restart1'
WA "--- pnputil /restart-device (attempt 1 with services running) ---"
pnputil /restart-device $devnode 2>&1 | ForEach-Object { WA ("  " + $_) }
Start-Sleep -Seconds 30
Marker 'inf7-after-restart1'
Check 'after restart 1'

$pc = (Get-PnpDeviceProperty -InstanceId $devnode -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue).Data
if ($pc -ne 0) {
  WA "--- disable + enable cycle ---"
  pnputil /disable-device $devnode 2>&1 | ForEach-Object { WA ("  " + $_) }
  Start-Sleep -Seconds 5
  New-ItemProperty -Path $ek -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
  pnputil /enable-device $devnode 2>&1 | ForEach-Object { WA ("  " + $_) }
  Start-Sleep -Seconds 30
  Marker 'inf7-after-enable'
  Check 'after disable/enable cycle'
}

$pc = (Get-PnpDeviceProperty -InstanceId $devnode -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue).Data
if ($pc -ne 0) {
  WA "--- scan-devices ---"
  pnputil /scan-devices 2>&1 | ForEach-Object { WA ("  " + $_) }
  Start-Sleep -Seconds 20
  Marker 'inf7-after-scan'
  Check 'after scan'
}

WA "--- netcfg tree (VPNVA connection search) ---"
try {
  Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}' -ErrorAction Stop | ForEach-Object {
    $conn = Get-ItemProperty "$($_.PSPath)\Connection" -ErrorAction SilentlyContinue
    if ($conn -and $conn.PnpInstanceID -match 'VPNVA') { WA ("  FOUND: {0}: Name={1} PnpInstanceID={2}" -f $_.PSChildName, $conn.Name, $conn.PnpInstanceID) }
  }
  WA "  (search done)"
} catch { WA ("  netcfg tree ERROR: " + $_.Exception.Message) }

Marker 'inf7-done'
