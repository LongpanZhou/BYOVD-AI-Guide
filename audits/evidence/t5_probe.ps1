# t5_probe.ps1 (agent t5) - independent state probe while the INF install hangs.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_probe.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"

WA ("=== t5 probe {0} ===" -f (Get-Date -Format o))
Marker 'probe-start'

$sw = [System.Diagnostics.Stopwatch]::StartNew()
& $exe $log devstat 'ROOT\VPNVA\0000' '' 2>&1 | Out-Null
WA ("  devstat exit=" + $LASTEXITCODE + "  elapsed=" + $sw.ElapsedMilliseconds + " ms")

& $exe $log qobj '\Device' 'VPNVA' 2>&1 | Out-Null
WA ("  qobj matched=" + ($LASTEXITCODE -eq 0))

foreach ($key in @('DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus','DEVPKEY_Device_DriverInfPath','DEVPKEY_Device_Service')) {
  $p = Get-PnpDeviceProperty -InstanceId 'ROOT\VPNVA\0000' -KeyName $key -ErrorAction SilentlyContinue
  if ($p) { WA ("  {0} = {1}" -f $key, $p.Data) } else { WA ("  {0} = <none>" -f $key) }
}

WA "--- relevant processes ---"
tasklist /v /fo csv | Select-String -Pattern 't5_poc|drvinst|pnputil|rundll32' | ForEach-Object { WA ("  " + $_.Line) }

WA "--- sc query t5_vpnva ---"
sc.exe query t5_vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }

Marker 'probe-done'
