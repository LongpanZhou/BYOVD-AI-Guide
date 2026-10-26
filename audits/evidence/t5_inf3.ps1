# t5_inf3.ps1 (agent t5) - Phase A step 4c: get the miniport to instantiate.
# Attempt B: pnputil /scan-devices (trigger the pending INF install - event 430 said
#   "requires further installation").
# Attempt C (if B fails): hand-build the driver key exactly as the real host install has it
#   (template from host ROOT\NET\0000: Control\Class\{4d36e972}\0013) and link the devnode.
# Evidence: t5_inf3.txt (progressive)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_inf3.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"
$netClass = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$devnode = 'ROOT\VPNVA\0000'
$ek = "HKLM:\SYSTEM\CurrentControlSet\Enum\$devnode"

function Check($label) {
  WA "--- checks: $label ---"
  & $exe $log devstat $devnode '' 2>&1 | Out-Null
  WA ("  devstat exit=" + $LASTEXITCODE)
  & $exe $log qobj '\Device' 'VPNVA' 2>&1 | Out-Null
  WA ("  qobj \\Device VPNVA matched=" + ($LASTEXITCODE -eq 0))
  & $exe $log open '\\.\VPNVA' 'C0000000' 2>&1 | Out-Null
  WA ("  open \\.\VPNVA RW exit=" + $LASTEXITCODE)
  foreach ($key in @('DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus','DEVPKEY_Device_DriverInfPath','DEVPKEY_Device_Service','DEVPKEY_Device_ClassGuid')) {
    try { $p = Get-PnpDeviceProperty -InstanceId $devnode -KeyName $key -ErrorAction Stop; WA ("  {0} = {1}" -f $key, $p.Data) } catch { WA ("  {0} = <failed>" -f $key) }
  }
}

WA ("=== t5 inf3 {0} ===" -f (Get-Date -Format o))
Marker 'inf3-start'

# ---------- Attempt B: scan-devices ----------
WA "=== Attempt B: pnputil /scan-devices (trigger pending INF install) ==="
pnputil /scan-devices 2>&1 | ForEach-Object { WA ("  " + $_) }
Start-Sleep -Seconds 12
Marker 'inf3-after-scan'
Check 'after scan-devices'
$svc = (Get-PnpDeviceProperty -InstanceId $devnode -KeyName 'DEVPKEY_Device_Service' -ErrorAction SilentlyContinue).Data
if ($svc) {
  WA ("Attempt B SUCCESS: device configured with Service=" + $svc)
} else {
  WA "Attempt B failed (Service still empty) -> Attempt C"

  # ---------- Attempt C: hand-built driver key (host ROOT\NET\0000 template) ----------
  WA "=== Attempt C: hand-built driver key ==="
  # next free 4-digit index under the Net class
  $clsRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$netClass"
  $idx = 0
  Get-ChildItem $clsRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' } | ForEach-Object { $n = [int]$_.PSChildName; if ($n -gt $idx) { $idx = $n } }
  $idx = $idx + 1
  $idxName = '{0:D4}' -f $idx
  $dk = "$clsRoot\$idxName"
  WA ("  driver key: $dk")
  New-Item -Path $dk -Force | Out-Null
  $guid = [guid]::NewGuid().Guid
  New-ItemProperty -Path $dk -Name 'DriverDesc' -Value 'Cisco AnyConnect Virtual Miniport Adapter for Windows x64' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'ProviderName' -Value 'Cisco Systems' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'DriverDate' -Value '12-14-2021' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'DriverVersion' -Value '4.10.5040.0' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'InfPath' -Value 'oem9.inf' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'InfSection' -Value 'Cisco.ndi.NTamd64' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'MatchingDeviceId' -Value 'VPNVA' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $dk -Name '*IfType' -Value 6 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $dk -Name '*MediaType' -Value 0 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $dk -Name '*PhysicalMediaType' -Value 0 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'Characteristics' -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'IfTypePreStart' -Value 6 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'ComponentId' -Value 'VPNVA' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'NetCfgInstanceId' -Value ('{' + $guid + '}') -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'NetLuidIndex' -Value 32774 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'MTU' -Value 1500 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $dk -Name 'DefaultLinkState' -Value 0 -PropertyType DWord -Force | Out-Null
  # Ndi subkeys (INF Cisco.reg section)
  New-Item -Path "$dk\Ndi" -Force | Out-Null
  New-ItemProperty -Path "$dk\Ndi" -Name 'Service' -Value 't5_vpnva' -PropertyType String -Force | Out-Null
  New-Item -Path "$dk\Ndi\Interfaces" -Force | Out-Null
  New-ItemProperty -Path "$dk\Ndi\Interfaces" -Name 'DefUpper' -Value 'ndis5' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path "$dk\Ndi\Interfaces" -Name 'DefLower' -Value 'ethernet' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path "$dk\Ndi\Interfaces" -Name 'UpperRange' -Value 'ndis5' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path "$dk\Ndi\Interfaces" -Name 'LowerRange' -Value 'ethernet' -PropertyType String -Force | Out-Null
  WA ("  built (NetCfgInstanceId={" + $guid + "})")

  # enum key: link + class + service
  New-ItemProperty -Path $ek -Name 'Driver' -Value ($netClass + '\' + $idxName) -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'Class' -Value 'Net' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'ClassGUID' -Value $netClass -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'Service' -Value 't5_vpnva' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'DeviceDesc' -Value 'Cisco AnyConnect Virtual Miniport Adapter for Windows x64' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'Mfg' -Value 'Cisco Systems' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'FriendlyName' -Value 'Cisco AnyConnect Virtual Miniport Adapter for Windows x64' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'Capabilities' -Value 0 -PropertyType DWord -Force | Out-Null
  WA "  enum key linked (Driver=$netClass\$idxName, Class=Net, Service=t5_vpnva)"

  # service needs the NDIS load order group like the real install
  New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\t5_vpnva' -Name 'Group' -Value 'NDIS' -PropertyType String -Force | Out-Null
  WA "  service t5_vpnva: Group=NDIS added"

  # driver must be loaded (it was unloaded after the earlier AddDevice failure)
  WA "--- sc start t5_vpnva (reload after earlier stop) ---"
  sc.exe start t5_vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
  Start-Sleep -Seconds 3

  Marker 'inf3-BEFORE-restart2'
  WA "--- pnputil /restart-device ROOT\VPNVA\0000 (2nd attempt with driver key) ---"
  pnputil /restart-device 'ROOT\VPNVA\0000' 2>&1 | ForEach-Object { WA ("  " + $_) }
  Start-Sleep -Seconds 15
  Marker 'inf3-after-restart2'
  Check 'after hand-built driver key'

  WA "--- Get-NetAdapter -IncludeHidden ---"
  try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object Name | Format-Table Name,InterfaceDescription,Status,MediaConnectState,ifIndex -AutoSize | Out-String -Width 200 | ForEach-Object { WA $_ } } catch { WA ("Get-NetAdapter ERROR: " + $_.Exception.Message) }
  WA "--- sc query t5_vpnva ---"
  sc.exe query t5_vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
  WA "--- driverquery rows ---"
  driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva' | ForEach-Object { WA ("  " + $_.Line) }
  WA "--- Kernel-PnP/Configuration log (last 8) ---"
  try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 8 -ErrorAction Stop | ForEach-Object { WA ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } } catch { WA ("  ERROR: " + $_.Exception.Message) }
}

Marker 'inf3-done'
