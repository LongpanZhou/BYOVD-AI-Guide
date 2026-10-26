# t5_kdrestart.ps1 (agent t5) - restart the devnode while the kernel debugger watches.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_kd_restart.txt"
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"

WA ("=== t5 kdrestart {0} ===" -f (Get-Date -Format o))
Marker 'kdrestart-start'
pnputil /restart-device 'ROOT\VPNVA\0000' 2>&1 | ForEach-Object { WA ("  " + $_) }
WA ("  pnputil exit: " + $LASTEXITCODE)
Start-Sleep -Seconds 25
& $exe $log devstat 'ROOT\VPNVA\0000' '' 2>&1 | Out-Null
WA ("  devstat exit=" + $LASTEXITCODE)
$p = Get-PnpDeviceProperty -InstanceId 'ROOT\VPNVA\0000' -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue
WA ("  ProblemCode = " + $p.Data)
sc.exe query vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
Marker 'kdrestart-done'
