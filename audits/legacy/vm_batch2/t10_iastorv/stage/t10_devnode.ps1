# t10_devnode.ps1 - create devnode FIRST, seed enum key AFTER, restart (t1/t3/t6 proven recipe)
# Usage: only needed if the plain service load created no device objects (PnP plane required).
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t10_work'
$log  = "$work\t10_devnode.txt"
function Log([string]$s) { [IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker([string]$m) { Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

[IO.File]::WriteAllText($log, ("=== t10_devnode {0} ===`r`n" -f (Get-Date -Format o)))
Marker 'devnode-start'

$id = 'ROOT\T10IAST\0000'
# (a) clean stale enum keys
$ep = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T10IAST'
if (Test-Path $ep) { Remove-Item $ep -Recurse -Force; Log ('  removed stale key: ' + $ep) } else { Log '  enum key clean' }

# (b) devnode first
& "$work\t10_poc.exe" "$work\t10_dn_create.txt" mkdev $id 'HTREE\ROOT\0' 2>&1 | Out-Null
if (Test-Path "$work\t10_dn_create.txt") { Get-Content "$work\t10_dn_create.txt" | ForEach-Object { Log ('  ' + $_) } }

# (c) seed after
$reg = 'HKLM:\SYSTEM\CurrentControlSet\Enum\' + $id
if (Test-Path $reg) {
  Set-ItemProperty -Path $reg -Name ConfigFlags -Value 0 -Type DWord
  Set-ItemProperty -Path $reg -Name Class -Value 'System' -Type String
  Set-ItemProperty -Path $reg -Name ClassGUID -Value '{4d36e97d-e325-11ce-bfc1-08002be10318}' -Type String
  Set-ItemProperty -Path $reg -Name DeviceDesc -Value 't10 iaStorV stand-in (System class)' -Type String
  Set-ItemProperty -Path $reg -Name HardwareID -Value @('ROOT\T10IAST') -Type MultiString
  Set-ItemProperty -Path $reg -Name Service -Value 't10_iastrv' -Type String
  Log ('  seeded ' + $reg)
} else { Log ('  FATAL: enum key not auto-created: ' + $reg); exit 1 }

# (d) restart - AddDevice will run (wcsstr PCI\VEN_8086 check -> non-Intel path 57c64)
Log '--- pnputil /restart-device ---'
& pnputil.exe /restart-device $id 2>&1 | ForEach-Object { Log ('  ' + $_) }
Start-Sleep -Seconds 10
& "$work\t10_poc.exe" "$work\t10_dn_status.txt" devstat $id 2>&1 | Out-Null
if (Test-Path "$work\t10_dn_status.txt") { Get-Content "$work\t10_dn_status.txt" | ForEach-Object { Log ('  ' + $_) } }
& sc.exe query t10_iastrv 2>&1 | ForEach-Object { Log ('  ' + $_) }

Marker 'devnode-done'
exit 0
