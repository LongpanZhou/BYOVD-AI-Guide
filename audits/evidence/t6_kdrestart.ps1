# t6_kdrestart.ps1 (agent t6) - attempt #2 (Class=System) while the kernel debugger watches.
# Creates+seeds ROOT\T6NVHDA2\0000, restarts it, waits, records status. Read-only kd usage.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$log  = "$work\t6_kd_restart.txt"
$exe  = "$work\t6_poc.exe"
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t6_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

WA ("=== t6 kdrestart {0} (attempt #2: ROOT\T6NVHDA2\0000, Class=System) ===" -f (Get-Date -Format o))
Marker 'kdrestart-start'

$id = 'ROOT\T6NVHDA2\0000'
# (a) clean enum keys
$ep = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T6NVHDA2'
if (Test-Path $ep) { Remove-Item $ep -Recurse -Force; WA ("  removed stale key: " + $ep) } else { WA '  enum key clean' }

# (b) devnode first
& $exe "$work\t6_kd_create.txt" mkdev $id 2>&1 | Out-Null
if (Test-Path "$work\t6_kd_create.txt") { Get-Content "$work\t6_kd_create.txt" | ForEach-Object { WA ('  ' + $_) } }

# (c) seed after
$reg = "HKLM:\SYSTEM\CurrentControlSet\Enum\$id"
if (Test-Path $reg) {
  Set-ItemProperty -Path $reg -Name ConfigFlags -Value 0 -Type DWord
  Set-ItemProperty -Path $reg -Name Class      -Value 'System' -Type String
  Set-ItemProperty -Path $reg -Name ClassGUID  -Value '{4d36e97d-e325-11ce-bfc1-08002be10318}' -Type String
  Set-ItemProperty -Path $reg -Name DeviceDesc -Value 't6 NVIDIA HDMI Audio stand-in (System class)' -Type String
  Set-ItemProperty -Path $reg -Name HardwareID -Value @('ROOT\T6NVHDA2') -Type MultiString
  Set-ItemProperty -Path $reg -Name Service    -Value 't6_nvhda' -Type String
  WA ('  seeded ' + $reg)
} else { WA ('  FATAL: enum key not auto-created: ' + $reg) }

# (d) restart - the driver image will load on demand (sxe ld should catch it in kd)
WA '--- pnputil /restart-device ---'
pnputil /restart-device $id 2>&1 | ForEach-Object { WA ('  ' + $_) }
Start-Sleep -Seconds 20
& $exe "$work\t6_kd_status.txt" devstat $id 2>&1 | Out-Null
if (Test-Path "$work\t6_kd_status.txt") { Get-Content "$work\t6_kd_status.txt" | ForEach-Object { WA ('  ' + $_) } }
$p = Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue
WA ("  ProblemCode = " + $p.Data)
$p2 = Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_ProblemStatus' -ErrorAction SilentlyContinue
WA ("  ProblemStatus = " + $p2.Data)
sc.exe query t6_nvhda 2>&1 | ForEach-Object { WA ('  ' + $_) }
Marker 'kdrestart-done'
