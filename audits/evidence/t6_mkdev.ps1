# t6_mkdev.ps1 (agent t6) - Phase A step 4: root devnode creation.
# Recipe = t1/t3/t4 proven order: (a) clean enum keys, (b) CM_Create_DevNodeW(flags=0,
# parent=HTREE\ROOT\0) FIRST, (c) seed auto-created enum key AFTER, (d) pnputil /restart-device.
# Evidence: t6_mkdev.txt (each invocation appends)
param([string]$Id   = 'ROOT\T6NVHDA\0000',
      [string]$Hwid = 'ROOT\T6NVHDA',
      [string]$Class = 'Media',
      [string]$ClassGuid = '{4d36e96c-e325-11ce-bfc1-08002be10318}',
      [string]$Desc = 't6 NVIDIA HDMI Audio stand-in',
      [string]$LogName = 't6_mkdev.txt')
$ErrorActionPreference = 'Continue'
$log = "C:\Users\vmdebug\Desktop\t6_work\$LogName"
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t6_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

W ("=== t6 mkdev {0}  id={1} class={2} ({3}) ===" -f (Get-Date -Format o), $Id, $Class, $ClassGuid)
Marker ("mkdev-start-" + $Id)

$svc = 't6_nvhda'
W ("service binding: " + $svc)

# (a) ensure no stale enum keys for this devnode root
$root = $Id.Substring(0, $Id.IndexOf('\'))
$ep = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$root"
if (Test-Path $ep) { W ("removing stale enum key: " + $ep); Remove-Item $ep -Recurse -Force } else { W ("enum key clean: $ep absent") }

# compile poc (once)
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$exe = "$work\t6_poc.exe"
if (-not (Test-Path $exe)) {
  W '--- compiling t6_poc.cs ---'
  & $csc /nologo /out:$exe "$work\t6_poc.cs" 2>&1 | ForEach-Object { W ('csc: ' + $_) }
}
if (Test-Path $exe) { W 'poc exe ready' } else { W 'FATAL: compile failed'; [System.IO.File]::AppendAllText($log,$sb.ToString()); exit 1 }

# (b) create devnode FIRST (flags=0; pre-seeding -> CR=0x1E per t3/t4 evidence)
W '--- (b) CM_Create_DevNodeW (devnode first) ---'
& $exe "$work\t6_mkdev_create.txt" mkdev $Id 2>&1 | Out-Null
if (Test-Path "$work\t6_mkdev_create.txt") { Get-Content "$work\t6_mkdev_create.txt" | ForEach-Object { W ('  ' + $_) } }

# (c) seed the auto-created enum key
W '--- (c) seeding enum key ---'
$reg = "HKLM:\SYSTEM\CurrentControlSet\Enum\$Id"
if (Test-Path $reg) {
  Set-ItemProperty -Path $reg -Name ConfigFlags -Value 0 -Type DWord
  Set-ItemProperty -Path $reg -Name Class      -Value $Class -Type String
  Set-ItemProperty -Path $reg -Name ClassGUID  -Value $ClassGuid -Type String
  Set-ItemProperty -Path $reg -Name DeviceDesc -Value $Desc -Type String
  Set-ItemProperty -Path $reg -Name HardwareID -Value @($Hwid) -Type MultiString
  Set-ItemProperty -Path $reg -Name Service    -Value $svc -Type String
  W ('  seeded ' + $reg)
  $v = Get-ItemProperty $reg
  W ('    ConfigFlags=' + $v.ConfigFlags + '  Class=' + $v.Class + '  ClassGUID=' + $v.ClassGUID)
  W ('    DeviceDesc=' + $v.DeviceDesc + '  Service=' + $v.Service + '  HardwareID=' + (($v.HardwareID) -join ';'))
} else { W ('  FATAL: enum key NOT auto-created: ' + $reg) }

# (d) restart-device -> AddDevice fires
W '--- (d) pnputil /restart-device ---'
$rd = pnputil /restart-device $Id 2>&1
$rd | ForEach-Object { W ('  ' + $_) }
Start-Sleep 5
W '--- devnode status after restart ---'
& $exe "$work\t6_mkdev_status.txt" devstat $Id 2>&1 | Out-Null
if (Test-Path "$work\t6_mkdev_status.txt") { Get-Content "$work\t6_mkdev_status.txt" | ForEach-Object { W ('  ' + $_) } }
W '--- PnP problem properties ---'
try {
  foreach ($kn in @('DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus')) {
    $p = Get-PnpDeviceProperty -InstanceId $Id -KeyName $kn -ErrorAction SilentlyContinue
    if ($p) { W ('  ' + $kn + ' = ' + $p.Data) }
  }
} catch { W ("  PnP property ERROR: " + $_.Exception.Message) }
W '--- service state now ---'
& sc.exe query t6_nvhda 2>&1 | ForEach-Object { W ('  ' + $_) }
Marker ("mkdev-done-" + $Id)
[System.IO.File]::AppendAllText($log, $sb.ToString())
