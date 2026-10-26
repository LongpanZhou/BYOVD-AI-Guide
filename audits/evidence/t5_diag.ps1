# t5_diag.ps1 (agent t5) - diagnose why the NDIS miniport did not instantiate after
# devnode restart (problem=0x1F on both ROOT\T5VPNVA\0000 and ROOT\T5VPNVA2\0000).
# Evidence: t5_diag.txt
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_diag.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

WA ("=== t5 diag {0} ===" -f (Get-Date -Format o))
Marker 'diag-start'

foreach ($id in @('ROOT\T5VPNVA\0000','ROOT\T5VPNVA2\0000')) {
  WA ("--- devnode properties: " + $id + " ---")
  foreach ($key in @('DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus','DEVPKEY_Device_HasProblem','DEVPKEY_Device_Driver','DEVPKEY_Device_DriverInfPath','DEVPKEY_Device_DriverProvider','DEVPKEY_Device_Service','DEVPKEY_Device_ClassGuid','DEVPKEY_Device_Class','DEVPKEY_Device_ConfigFlags','DEVPKEY_Device_IsPresent','DEVPKEY_Device_Manufacturer','DEVPKEY_Device_HardwareIds')) {
    try {
      $p = Get-PnpDeviceProperty -InstanceId $id -KeyName $key -ErrorAction Stop
      WA ("  {0} = {1} (type {2})" -f $key, $p.Data, $p.Type)
    } catch { WA ("  {0} = <query failed: {1}>" -f $key, $_.Exception.Message) }
  }
  WA ("  enum-key values:")
  $rk = "HKLM:\SYSTEM\CurrentControlSet\Enum\$id"
  if (Test-Path $rk) { (Get-Item $rk).Property | ForEach-Object { $v = (Get-ItemProperty $rk -Name $_).$_; if ($v -is [array]) { $v = ($v -join ', ') }; WA ("    $_ = $v") } } else { WA "    (key absent)" }
}

WA "--- pnputil /enum-devices (T5VPNVA context) ---"
try {
  $all = pnputil /enum-devices 2>&1 | Out-String
  $lines = $all -split "`r?`n"
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match 'T5VPNVA') {
      $from = [Math]::Max(0, $i - 2); $to = [Math]::Min($lines.Count - 1, $i + 14)
      for ($j = $from; $j -le $to; $j++) { WA ("  " + $lines[$j]) }
      WA "  ---"
    }
  }
} catch { WA ("  pnputil enum ERROR: " + $_.Exception.Message) }

WA "--- System event log (events since 17:27:00 local) ---"
try {
  $t0 = Get-Date '2026-10-23 17:27:00'
  Get-WinEvent -LogName System -MaxEvents 120 -ErrorAction Stop | Where-Object { $_.TimeCreated -ge $t0 } | ForEach-Object {
    WA ("  [{0}] id={1} prov={2} lvl={3}" -f $_.TimeCreated, $_.Id, $_.ProviderName, $_.Level)
    ($_.Message -replace '\r?\n', ' | ') | ForEach-Object { WA ("      " + $_) }
  }
} catch { WA ("  ERROR: " + $_.Exception.Message) }

WA "--- sc query t5_vpnva / driverquery ---"
sc.exe query t5_vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva' | ForEach-Object { WA ("  " + $_.Line) }

Marker 'diag-done'
