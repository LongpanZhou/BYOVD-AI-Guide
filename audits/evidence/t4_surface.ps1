# t4_surface.ps1 (agent t4) - Phase A step 5: AddDevice outcome / device-surface observation.
# Key phase-A question: does the device surface materialize without USB hardware?
# Evidence: t4_surface.txt
$log = 'C:\Users\vmdebug\Desktop\t4_work\t4_surface.txt'
$work = 'C:\Users\vmdebug\Desktop\t4_work'
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t4_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t4_poc.exe"

function PocRun($sub, $args2) {
  $tmp = "$work\t4_surface_poc.txt"
  if (Test-Path $tmp) { Remove-Item $tmp -Force }
  & $exe $tmp $sub $args2 2>&1 | Out-Null
  if (Test-Path $tmp) { Get-Content $tmp | ForEach-Object { W ('  ' + $_) } }
}

function DumpGuidRoot($g) {
  $root = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\$g"
  if (-not (Test-Path $root)) { W ('  absent: ' + $root); return }
  Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
    $c = $_
    W ('  child: ' + $c.PSChildName)
    $v = Get-ItemProperty $c.PSPath
    if ($v.DeviceInstance) { W ('    DeviceInstance = ' + $v.DeviceInstance) }
    $kids = (Get-ChildItem $c.PSPath -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }) -join ', '
    if ($kids) { W ('    subkeys: ' + $kids) }
    $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { W ('    value ' + $_.Name + ' = ' + $_.Value) }
  }
}

W ("=== t4 surface observation {0} ===" -f (Get-Date -Format o))
Marker 'surface-start'

W '--- devnode status/problem (poc devstat ROOT\T4SILABSER\0000) ---'
PocRun devstat 'ROOT\T4SILABSER\0000'

W '--- Get-PnpDevice (T4SILABSER instances) ---'
try { Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -match 'T4SILABSER' } | Format-List Status,Class,FriendlyName,InstanceId,Problem,ProblemDescription | Out-String -Width 200 | ForEach-Object { W $_ } } catch { W ('ERROR: ' + $_.Exception.Message) }
W '(empty above = devnode not visible in PnP)'

W '--- Get-PnpDeviceProperty (problem keys) ---'
try { Get-PnpDeviceProperty -InstanceId 'ROOT\T4SILABSER\0000' -KeyName 'DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus','DEVPKEY_Device_Service','DEVPKEY_Device_Class','DEVPKEY_Device_HasProblem' -ErrorAction Stop | Format-Table -AutoSize | Out-String | ForEach-Object { W $_ } } catch { W ('ERROR: ' + $_.Exception.Message) }

W '--- DeviceClasses {a2a39220-39f4-4b88-aecb-3d86a35dc748} (SILABUSBSERIALBRIDGE) ---'
DumpGuidRoot '{a2a39220-39f4-4b88-aecb-3d86a35dc748}'
W '--- DeviceClasses {86e0d1e0-8089-11d0-9ce4-08003e301f73} (GUID_DEVINTERFACE_COMPORT) ---'
DumpGuidRoot '{86e0d1e0-8089-11d0-9ce4-08003e301f73}'

W '--- SetupDi interface enumeration (authoritative; T4 instances) ---'
PocRun ifenum '{a2a39220-39f4-4b88-aecb-3d86a35dc748}'
PocRun ifenum '{86e0d1e0-8089-11d0-9ce4-08003e301f73}'

W '--- kernel object directory \Device (filter Silabser) ---'
PocRun qobj '\Device' 'Silabser'
W '--- kernel object directory \GLOBAL?? (filter COM) ---'
PocRun qobj '\GLOBAL??' 'COM'

W '--- SERIALCOMM DeviceMap ---'
$ser = Get-ItemProperty 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM' -ErrorAction SilentlyContinue
if ($ser) { $ser.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { W ('  {0} = {1}' -f $_.Name, $_.Value) } }
else { W '  (absent)' }

W '--- event log: Kernel-PnP/Configuration (T4SILABSER/silabser) ---'
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 80 -ErrorAction Stop | Where-Object { $_.Message -match 'T4SILABSER|silabser' } | Select-Object -First 12 | ForEach-Object { W ('  [{0}] id={1} {2}' -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } } catch { W ('  ERROR: ' + $_.Exception.Message) }

W '--- event log: System, last 20 min (silabser/T4SILABSER or Error-level) ---'
try { Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-20)} -ErrorAction Stop | Where-Object { ($_.Message -match 'T4SILABSER|silabser') -or ($_.LevelDisplayName -eq 'Error') } | Select-Object -First 15 | ForEach-Object { W ('  [{0}] {1} id={2} lvl={3}: {4}' -f $_.TimeCreated, $_.ProviderName, $_.Id, $_.LevelDisplayName, ($_.Message -replace '\r?\n', ' | ')) } } catch { W ('  ERROR: ' + $_.Exception.Message) }

# ---- fallback (only if devnode problem = AddDevice/start failure) ----
$pc = $null
try { $pc = (Get-PnpDeviceProperty -InstanceId 'ROOT\T4SILABSER\0000' -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction Stop).Data } catch {}
W ("--- AddDevice outcome gate: ProblemCode.Data = {0} ---" -f $pc)
if ($pc -in @(10, 28, 31, 24)) {
  W ('AddDevice/devnode problem ' + $pc + ' -> running ONE fallback: ROOT\T4SILABSER2\0000 with HardwareID=USB\VID_10C4&PID_EA60')
  & "$work\t4_devnode.ps1" -Id 'ROOT\T4SILABSER2\0000' -Hwid 'USB\VID_10C4&PID_EA60' -Desc 't4 Silabser CP210x (USB HWID fallback)' -LogName 't4_mkdev_fallback.txt'
  if (Test-Path "$work\t4_mkdev_fallback.txt") { W '--- fallback devnode log ---'; Get-Content "$work\t4_mkdev_fallback.txt" | ForEach-Object { W ('  ' + $_) } }
  W '--- fallback surface re-check ---'
  PocRun devstat 'ROOT\T4SILABSER2\0000'
  PocRun ifenum '{a2a39220-39f4-4b88-aecb-3d86a35dc748}'
} else {
  W ('no AddDevice failure code (' + $pc + ') - fallback not needed')
}

Marker 'surface-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
