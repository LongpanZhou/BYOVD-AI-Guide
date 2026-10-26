# t5_inf8.ps1 (agent t5) - Phase A step 4h: NDIS error events + bcdedit debug probe +
# long-wait restart. Evidence: t5_inf8.txt (progressive)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_inf8.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"
$devnode = 'ROOT\VPNVA\0000'

WA ("=== t5 inf8 {0} ===" -f (Get-Date -Format o))
Marker 'inf8-start'

WA "--- System events (last 40 min, all providers - driver/NDIS error hunt) ---"
try {
  $t0 = (Get-Date).AddMinutes(-40)
  Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$t0} -ErrorAction Stop | ForEach-Object {
    WA ("  [{0}] id={1} prov={2} lvl={3}" -f $_.TimeCreated, $_.Id, $_.ProviderName, $_.Level)
    ($_.Message -replace '\r?\n', ' | ') | ForEach-Object { WA ("      " + $_.Substring(0, [Math]::Min(300, $_.Length))) }
  }
} catch { WA ("  ERROR: " + $_.Exception.Message) }

WA "--- bcdedit /enum {current} (READ-ONLY probe: is kernel debugging enabled?) ---"
bcdedit /enum '{current}' 2>&1 | ForEach-Object { WA ("  " + $_) }
WA "--- bcdedit /dbgsettings (READ-ONLY probe) ---"
bcdedit /dbgsettings 2>&1 | ForEach-Object { WA ("  " + $_) }

Marker 'inf8-BEFORE-restart'
WA "--- pnputil /restart-device (long wait for netcfg) ---"
pnputil /restart-device $devnode 2>&1 | ForEach-Object { WA ("  " + $_) }
Start-Sleep -Seconds 45
Marker 'inf8-after-restart'

WA "--- checks ---"
& $exe $log devstat $devnode '' 2>&1 | Out-Null
WA ("  devstat exit=" + $LASTEXITCODE)
& $exe $log qobj '\Device' 'VPNVA' 2>&1 | Out-Null
WA ("  qobj \\Device VPNVA matched=" + ($LASTEXITCODE -eq 0))
& $exe $log open '\\.\VPNVA' 'C0000000' 2>&1 | Out-Null
WA ("  open \\.\VPNVA RW exit=" + $LASTEXITCODE)
foreach ($key in @('DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus')) {
  $p = Get-PnpDeviceProperty -InstanceId $devnode -KeyName $key -ErrorAction SilentlyContinue
  if ($p) { WA ("  {0} = {1}" -f $key, $p.Data) } else { WA ("  {0} = <none>" -f $key) }
}

WA "--- setupapi.dev.log tail (post-vpnva sections) ---"
try {
  $raw = Get-Content 'C:\Windows\INF\setupapi.dev.log' -Raw
  $idx = $raw.IndexOf('17:53')
  $tail = if ($idx -ge 0) { $raw.Substring($idx) } else { $raw.Substring([Math]::Max(0, $raw.Length - 3000)) }
  ($tail -split "`r?`n") | Select-Object -Last 60 | ForEach-Object { WA ("  " + $_) }
} catch { WA ("  ERROR: " + $_.Exception.Message) }

Marker 'inf8-done'
