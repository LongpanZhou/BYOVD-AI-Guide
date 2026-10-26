# t10_battery.ps1 - documented-code batteries with shaped structs for iaStorV (t10 namespace)
# Expected: 0x4D014/0x4D004 user-issued -> 0xC000000D (MinorFunction gate, IRP_MN_SCSI_CLASS==1 required)
# All shapes in-bounds: 0x48-byte METHOD_BUFFERED buffer, sense area at +0x38.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t10_work'
$log  = "$work\t10_battery.txt"
$devs = "$work\t10_devices.txt"
function Log([string]$s) { [IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker([string]$m) { Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

[IO.File]::WriteAllText($log, ("=== t10_battery {0} ===`r`n" -f (Get-Date -Format o)))
Marker 'battery-start'

# pick the primary device (first line of devices.txt, else \\.\Scsi0: fallback)
$dev = '\\.\Scsi0:'
if (Test-Path $devs) {
  foreach ($p in [IO.File]::ReadAllLines($devs)) { if ($p.Trim().Length -gt 0) { $dev = $p.Trim(); break } }
}
Log ('battery device: ' + $dev)

Log '--- battery 1: 0x4D014 SCSI_PASS_THROUGH_DIRECT sense shapes (sil x sioff) ---'
foreach ($sioff in @(0x38, 0x40)) {
  foreach ($sil in @(0, 16)) {
    & "$work\t10_poc.exe" $log stptd $dev 4D014 $sil $sioff 0 0 '00' 2>&1 | Out-Null
  }
}

Log '--- battery 2: 0x4D004 SCSI_PASS_THROUGH DataIn shapes (DataBufferOffset in-bounds) ---'
& "$work\t10_poc.exe" $log stpt $dev 4D004 0 40 0 '2A00000000000000' 2>&1 | Out-Null
& "$work\t10_poc.exe" $log stpt $dev 4D004 1 40 16 '2800000000000000' 2>&1 | Out-Null

Log '--- battery 3: 0x4D008 SCSI_MINIPORT SRB shapes (signatures) ---'
foreach ($sig in @('IntelMpd', 'IntelATA', 'PIIXIDE')) {
  & "$work\t10_poc.exe" $log srb $dev 4D008 $sig 0 0 2>&1 | Out-Null
}

Log '--- battery 4: 0x41018 GET_ADDRESS ---'
& "$work\t10_poc.exe" $log ioctl $dev 41018 0 8 2>&1 | Out-Null
& "$work\t10_poc.exe" $log ioctl $dev 41018 0 1000 2>&1 | Out-Null

Log '--- battery 5: custom codes raw (in 16 zeros / out 0x1000) ---'
foreach ($c in @('4100C', '41010', '41020', '4D02C', '4D030', '70000', '2D1400', 'C3512010', 'C3512018')) {
  & "$work\t10_poc.exe" $log ioctl $dev $c 10 1000 2>&1 | Out-Null
}
Log '--- battery 5b: 0xC3512014 shaped 0x54 (passes length checks, copies into global) ---'
& "$work\t10_poc.exe" $log ioctl $dev C3512014 54 54 2>&1 | Out-Null

Marker 'battery-done'
exit 0
