# t5_cleanup.ps1 (agent t5) - Phase A step 8: full cleanup + clean-state verification.
# Order: remove-device (runs HaltEx -> NdisDeregisterDeviceEx) -> sc stop/delete ->
# delete driver copies -> remove leftover enum keys -> verify.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_cleanup.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"

function Poc($c, $a1, $a2) {
  & $exe $log $c $a1 $a2 2>&1 | Out-Null
  return $LASTEXITCODE
}

W ("=== t5 cleanup {0} ===" -f (Get-Date -Format o))
Marker 'cleanup-start'

W "--- pnputil /remove-device (HaltEx -> NdisDeregisterDeviceEx path) ---"
foreach ($id in @('ROOT\T5VPNVA\0000','ROOT\T5VPNVA2\0000')) {
  W ("  device: " + $id)
  pnputil /remove-device $id 2>&1 | ForEach-Object { W ("    " + $_) }
  Marker ("cleanup-removed-" + ($id -replace '\\', '_'))
}
Start-Sleep -Seconds 5

W "--- sc stop + sc delete t5_vpnva ---"
sc.exe stop t5_vpnva 2>&1 | ForEach-Object { W ("  " + $_) }
Start-Sleep -Seconds 5
sc.exe delete t5_vpnva 2>&1 | ForEach-Object { W ("  " + $_) }
Start-Sleep -Seconds 3

W "--- delete driver copies ---"
$dst = 'C:\Windows\System32\drivers\vpnva64-6.sys'
if (Test-Path "$dst.t5bak") {
  Move-Item -Force "$dst.t5bak" $dst
  W ("  restored original vpnva64-6.sys from .t5bak (hash=" + (Get-FileHash $dst -Algorithm SHA256).Hash + ")")
} elseif (Test-Path $dst) {
  Remove-Item -Force $dst
  W ("  deleted " + $dst)
} else { W "  dst already absent" }
$src = "$work\vpnva64-6.sys"
if (Test-Path $src) { Remove-Item -Force $src; W ("  deleted staging copy " + $src) } else { W "  staging copy already absent" }

W "--- remove leftover enum keys ---"
foreach ($k in @('T5VPNVA','T5VPNVA2')) {
  $p = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$k"
  if (Test-Path $p) { Remove-Item -Recurse -Force $p; W ("  removed leftover key: " + $p) }
  else { W ("  clean: $k absent") }
}

W "--- CLEAN-STATE VERIFICATION ---"
W "  sc query t5_vpnva (expect failure):"
sc.exe query t5_vpnva 2>&1 | ForEach-Object { W ("    " + $_) }
W "  driverquery vpnva rows:"
$rows = driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva'
if ($rows) { $rows | ForEach-Object { W ("    " + $_.Line) } } else { W "    (none)" }
W "  drivers file:"
if (Test-Path $dst) { W ("    STILL PRESENT: " + $dst) } else { W "    absent - OK" }
W "  enum keys:"
foreach ($k in @('T5VPNVA','T5VPNVA2')) {
  if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$k") { W ("    LEFTOVER: $k") } else { W ("    absent: $k - OK") }
}
W "  \\Device\\VPNVA object:"
$rc = Poc 'qobj' '\Device' 'VPNVA'
W ("    matched=" + ($rc -eq 0) + " (expect False after removal)")
W "  network adapters (no VPNVA/Cisco expected):"
try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.InterfaceDescription -match 'Cisco|VPN' } | ForEach-Object { W ("    STILL PRESENT: " + $_.Name + " " + $_.InterfaceDescription) } } catch { }
$cnt = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'Cisco|VPN' }).Count
W ("    Cisco/VPN adapter count: " + $cnt)
W "  DeviceClasses delta:"
try {
  $before = Get-Content "$work\t5_dc_before.txt" -ErrorAction SilentlyContinue
  $now = (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses' -ErrorAction Stop).PSChildName
  $new = $now | Where-Object { $before -notcontains $_ }
  if ($new) { $new | ForEach-Object { W ("    LEFTOVER GUID: " + $_) } } else { W ("    none - OK") }
} catch { W ("    ERROR: " + $_.Exception.Message) }

Marker 'cleanup-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
