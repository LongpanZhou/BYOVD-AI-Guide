# t10_dn3.ps1 - step 1 only: wipe, create devnode, seed immediately (no restart here)
$ErrorActionPreference = 'Continue'
$w = 'C:\Users\vmdebug\Desktop\t10_work'
$log = "$w\t10_dn3.txt"
[IO.File]::WriteAllText($log, ("=== t10_dn3 (mkdev+seed) {0} ===`r`n" -f (Get-Date -Format o)))
function Log([string]$s) { [IO.File]::AppendAllText($log, $s + "`r`n") }
$ep = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T10IAST'
if (Test-Path $ep) { Remove-Item $ep -Recurse -Force; Log '  removed stale enum keys' }
& pnputil.exe /remove-device 'ROOT\T10IAST\0000' 2>&1 | ForEach-Object { Log ('  remove-device: ' + $_) }
& "$w\t10_poc.exe" $log mkdev 'ROOT\T10IAST\0000' 'HTREE\ROOT\0' 2>&1 | Out-Null
$ek = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T10IAST\0000'
if (-not (Test-Path $ek)) { Log '  FATAL: enum key missing after mkdev'; exit 1 }
New-ItemProperty -Path $ek -Name ConfigFlags -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $ek -Name Class -Value 'System' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ek -Name ClassGUID -Value '{4d36e97d-e325-11ce-bfc1-08002be10318}' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ek -Name DeviceDesc -Value 't10 iaStorV stand-in (System class)' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ek -Name HardwareID -Value 'ROOT\T10IAST' -PropertyType MultiString -Force | Out-Null
New-ItemProperty -Path $ek -Name Service -Value 't10_iastrv' -PropertyType String -Force | Out-Null
Log ('  seeded: ' + ((Get-ItemProperty $ek).Service) + ' / ' + ((Get-ItemProperty $ek).HardwareID -join ';'))
Add-Content -Path "$w\t10_alive.txt" -Value ("alive {0} dn3-mkdev-seed-done" -f (Get-Date -Format o))
exit 0
