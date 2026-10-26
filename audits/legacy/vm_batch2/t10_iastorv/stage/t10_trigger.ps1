# t10_trigger.ps1 - in-guest one-shot: send ONE shaped 0x4D014 (for the kd dispatch watch)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t10_work'
$log  = "$work\t10_trigger.txt"
[IO.File]::AppendAllText($log, ("=== t10_trigger {0} ===`r`n" -f (Get-Date -Format o)))
$dev = '\\.\Scsi0:'
$devs = "$work\t10_devices.txt"
if (Test-Path $devs) {
  foreach ($p in [IO.File]::ReadAllLines($devs)) { if ($p.Trim().Length -gt 0) { $dev = $p.Trim(); break } }
}
& "$work\t10_poc.exe" $log stptd $dev 4D014 16 38 0 0 '00' 2>&1 | Out-Null
Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} trigger-sent" -f (Get-Date -Format o))
exit 0
