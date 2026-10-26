# t4_open.ps1 (agent t4) - Phase A step 6: open tests (admin full token + restricted token).
# Context: AddDevice failed (CM_PROB 10, NTSTATUS 0xC0000010); interface registry entries
# exist but are NOT enabled; no named \Device\Silabser<N>; no COM symlink.
# We document exact errors for: interface paths (registry links), raw named-device paths,
# plus one pnputil /enable-device restart attempt + raw Kernel-PnP log.
# Evidence: t4_open.txt
$log = 'C:\Users\vmdebug\Desktop\t4_work\t4_open.txt'
$work = 'C:\Users\vmdebug\Desktop\t4_work'
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t4_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t4_poc.exe"

function PocRun($a1, $a2, $a3) {
  $tmp = "$work\t4_open_last.txt"
  if (Test-Path $tmp) { Remove-Item $tmp -Force }
  & $exe $tmp $a1 $a2 $a3 2>&1 | Out-Null
  if (Test-Path $tmp) { Get-Content $tmp | ForEach-Object { W ('    ' + $_) } }
}

function TryLink($label, $link) {
  if (-not $link) { W ('--- ' + $label + ' --- (no link resolved, skipped)'); return }
  W ('--- ' + $label + ' ---')
  W ('  path: ' + $link)
  foreach ($acc in @('C0000000','80000000','40000000')) {
    PocRun open $link $acc
  }
}

W ("=== t4 open tests {0} ===" -f (Get-Date -Format o))
Marker 'open-start'

$bridgeRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{a2a39220-39f4-4b88-aecb-3d86a35dc748}'
$comRoot    = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{86e0d1e0-8089-11d0-9ce4-08003e301f73}'

$bridgeChild = Get-ChildItem $bridgeRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '*T4SILABSER*' } | Select-Object -First 1
$comChild    = Get-ChildItem $comRoot    -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '*T4SILABSER*' } | Select-Object -First 1

$bridgeLink = $null; $comLink = $null
if ($bridgeChild) { $bridgeLink = '\\?\' + $bridgeChild.PSChildName.Substring(4); TryLink 'custom SILABUSBSERIALBRIDGE interface path (admin token)' $bridgeLink }
else { W ('no T4SILABSER bridge interface child under ' + $bridgeRoot) }

if ($comChild) { $comLink = '\\?\' + $comChild.PSChildName.Substring(4); TryLink 'GUID_DEVINTERFACE_COMPORT interface path (admin token)' $comLink }
else { W ('no T4SILABSER comport interface child under ' + $comRoot) }

# raw named-device probes (device object may exist even for a non-started devnode)
foreach ($n in @('Silabser0','Silabser1','Silabser2')) {
  TryLink ('raw named device \\.\' + $n) ('\\.\' + $n)
}

# \DosDevices\COM<N> if published (SERIALCOMM)
$ser = Get-ItemProperty 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM' -ErrorAction SilentlyContinue
$comName = $null
if ($ser) {
  $m = $ser.PSObject.Properties | Where-Object { $_.Value -match 'Silabser' } | Select-Object -First 1
  if ($m) { W ('SERIALCOMM entry: ' + $m.Name + ' = ' + $m.Value); $comName = $m.Name; TryLink ('DOS device ' + $comName) ('\\.\' + $comName) }
  else { W 'no Silabser entry in SERIALCOMM DeviceMap (no DOS name published - probe \\.\COM1..COM3 anyway for completeness)'
    foreach ($n in @('COM1','COM2','COM3')) { TryLink ('probe \\.\' + $n + ' (should hit baseline COM1 or fail)') ('\\.\' + $n) }
  }
} else { W 'SERIALCOMM DeviceMap absent' }

# one enable attempt per devnode (non-destructive re-start attempt)
W '--- pnputil /enable-device attempts (re-start attempt; NOT a power/snapshot op) ---'
foreach ($id in @('ROOT\T4SILABSER\0000','ROOT\T4SILABSER2\0000')) {
  W ('  device: ' + $id)
  pnputil /enable-device $id 2>&1 | ForEach-Object { W ('    ' + $_) }
}
Start-Sleep 3
W '--- post-enable ifenum bridge + SERIALCOMM recheck ---'
PocRun ifenum '{a2a39220-39f4-4b88-aecb-3d86a35dc748}' $null
$ser2 = Get-ItemProperty 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM' -ErrorAction SilentlyContinue
if ($ser2) { $ser2.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { W ('    SERIALCOMM: {0} = {1}' -f $_.Name, $_.Value) } }
else { W '    SERIALCOMM absent' }
W '--- post-enable raw \\.\Silabser0 recheck ---'
PocRun open '\\.\Silabser0' 'C0000000'

# raw Kernel-PnP/Configuration log tail (unfiltered, for the record)
W '--- Kernel-PnP/Configuration log (raw last 15) ---'
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 15 -ErrorAction Stop | ForEach-Object { W ('  [{0}] id={1} {2}' -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } } catch { W ('  ERROR: ' + $_.Exception.Message) }

# restricted-token open (interface path if any)
$restrTarget = $bridgeLink; if (-not $restrTarget) { $restrTarget = $comLink }
if ($restrTarget) {
  W '--- restricted-token open (runas /trustlevel:0x20000) ---'
  $restrLog = "$work\t4_open_restricted.txt"
  if (Test-Path $restrLog) { Remove-Item $restrLog -Force }
  $inner = '"' + $exe + '" ' + $restrLog + ' open ' + $restrTarget + ' C0000000'
  $ra = & runas.exe /trustlevel:0x20000 $inner 2>&1
  $ra | ForEach-Object { W ('  runas: ' + $_) }
  Start-Sleep 3
  if (Test-Path $restrLog) { Get-Content $restrLog | ForEach-Object { W ('  restricted: ' + $_) } }
  else { W '  restricted run produced NO output file (runas may have failed to spawn in this session)' }
} else {
  W 'no interface link available - restricted-token open skipped'
}

Marker 'open-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
