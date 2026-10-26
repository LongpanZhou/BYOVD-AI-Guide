# t5_control.ps1 (agent t5) - Phase A step 4i: CONTROL EXPERIMENT.
# Install the in-box "KM-TEST Loopback" NDIS miniport (known-good, root-enum netcard)
# through the SAME pipeline (devnode + UpdateDriverForPlugAndPlayDevices + restart).
# If it starts: pipeline is good -> vpnva failure is driver-internal (H1).
# If it fails the same way: environment issue (H2).
# The control device is REMOVED at the end of the script. Evidence: t5_control.txt
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_control.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"

WA ("=== t5 control {0} ===" -f (Get-Date -Format o))
Marker 'control-start'

WA "--- find in-box loopback INF ---"
$infFile = $null
Get-ChildItem 'C:\Windows\INF\*.inf' | ForEach-Object {
  $head = (Get-Content $_.FullName -TotalCount 60 -ErrorAction SilentlyContinue) -join "`n"
  if ($head -match 'Loopback' -and $head -match '4d36e972') { WA ("  candidate: " + $_.Name); $infFile = $_.FullName }
}
if (-not $infFile) { WA "ABORT: no loopback INF found"; exit 5 }
WA ("  using INF: " + $infFile)

WA "--- extract model hw-id from INF ---"
$hwid = $null
foreach ($line in (Get-Content $infFile)) {
  if ($line -match '^%[^%]+%\s*=\s*[^,]+,\s*(.+)$') {
    $cand = $Matches[1].Trim()
    if ($cand -notmatch 'NT|Service|CoInstallers|HW|\.reg') { $hwid = $cand }
  }
}
if ($hwid -match ',') { $hwid = ($hwid -split ',')[0].Trim() }
WA ("  hw-id parsed: '" + $hwid + "'")
if (-not $hwid) { WA "ABORT: could not parse hw-id"; exit 6 }

WA "--- create devnode ROOT\TESTLOOP\0000 + seed ---"
& $exe $log mkdev 'ROOT\TESTLOOP\0000' '' 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { WA "ABORT: mkdev failed"; exit 7 }
$k = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\TESTLOOP\0000'
New-ItemProperty -Path $k -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $k -Name 'HardwareID' -Value $hwid -PropertyType MultiString -Force | Out-Null
WA "  seeded ConfigFlags=0 + HardwareID=$hwid"

Marker 'control-BEFORE-install'
WA "--- UpdateDriverForPlugAndPlayDevices ---"
& $exe $log instdev $hwid $infFile 2>&1 | Out-Null
WA ("  instdev exit=" + $LASTEXITCODE)
Start-Sleep -Seconds 30
Marker 'control-after-install'

WA "--- checks (loopback adapter should appear / devnode should start) ---"
& $exe $log devstat 'ROOT\TESTLOOP\0000' '' 2>&1 | Out-Null
& $exe $log qobj '\Device' 'LOOP' 2>&1 | Out-Null
$p = Get-PnpDeviceProperty -InstanceId 'ROOT\TESTLOOP\0000' -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue
WA ("  ProblemCode = " + $p.Data)
try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.InterfaceDescription -match 'Loopback' } | Format-Table Name,InterfaceDescription,Status -AutoSize | Out-String -Width 200 | ForEach-Object { WA $_ } } catch { WA ("  adapter query ERROR: " + $_.Exception.Message) }
try { $rows = driverquery /v /fo csv 2>&1 | Select-String -Pattern 'kmtest|loopback'; if ($rows) { $rows | ForEach-Object { WA ("  " + $_.Line) } } else { WA "  (no kmtest/loopback driver rows)" } } catch { }

WA "--- remove control device ---"
pnputil /remove-device 'ROOT\TESTLOOP\0000' 2>&1 | ForEach-Object { WA ("  " + $_) }
if (Test-Path $k) { Remove-Item -Recurse -Force $k; WA "  leftover enum key removed" }
Start-Sleep -Seconds 5

Marker 'control-done'
