# t10_dn2.ps1 - atomic devnode recipe: mkdev -> seed -> restart -> status -> probes (one shot)
$ErrorActionPreference = 'Continue'
$w = 'C:\Users\vmdebug\Desktop\t10_work'
$log = "$w\t10_dn2.txt"
[IO.File]::WriteAllText($log, ("=== t10_dn2 {0} ===`r`n" -f (Get-Date -Format o)))
function Log([string]$s) { [IO.File]::AppendAllText($log, $s + "`r`n") }
Add-Content -Path "$w\t10_alive.txt" -Value ("alive {0} dn2-start" -f (Get-Date -Format o))

# (a) wipe stale devnode + keys
$ep = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T10IAST'
if (Test-Path $ep) { Remove-Item $ep -Recurse -Force; Log '  removed stale enum keys' }
& pnputil.exe /remove-device 'ROOT\T10IAST\0000' 2>&1 | ForEach-Object { Log ('  remove-device: ' + $_) }

# (b) devnode + seed in immediate sequence
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

# (c) restart (AddDevice trigger)
Log '  --- pnputil /restart-device ---'
& pnputil.exe /restart-device 'ROOT\T10IAST\0000' 2>&1 | ForEach-Object { Log ('    ' + $_) }
Start-Sleep -Seconds 5

# (d) status
& "$w\t10_poc.exe" $log devstat 'ROOT\T10IAST\0000' 2>&1 | Out-Null
& sc.exe query t10_iastrv 2>&1 | ForEach-Object { Log ('  svc: ' + $_) }

# (e) existence probes (real access mask for admin-openable objects)
& "$w\t10_poc.exe" $log ntopen '\Device\Ide\iaStor0' 12019F
& "$w\t10_poc.exe" $log ntopen '\Device\ScsiPort4' 12019F
& "$w\t10_poc.exe" $log ntopen '\Device\Ide\IAAStorageDevice-0' 12019F
& "$w\t10_poc.exe" $log openlink '\??\Scsi0:'
& "$w\t10_poc.exe" $log openlink '\??\Scsi1:'

# (f) transient-surface check in \Device (poc v2 batch scan)
& "$w\t10_poc.exe" $log qobj '\Device' 'iaStor|ScsiPort|IAAStorage|Ide|t10'

Add-Content -Path "$w\t10_alive.txt" -Value ("alive {0} dn2-done" -f (Get-Date -Format o))
exit 0
