# t8_mkdev2.ps1 - attempt 2: devnode under a real ACPI parent (acpi.sys supplies BUS_INTERFACE_STANDARD)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t8_work'
$out  = "$work\t8_mkdev2.txt"
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
"t8_mkdev2 $(Get-Date -Format o)" | Out-File $out -Encoding ascii

# find a live ACPI devnode parent (acpi.sys PDOs answer BUS_INTERFACE_STANDARD)
Log "--- candidate ACPI parents ---"
$acpi = Get-PnpDevice 2>$null | Where-Object { $_.InstanceId -like 'ACPI\PNP*' -and $_.Status -eq 'OK' } | Select-Object -First 5
$parent = $null
foreach ($d in $acpi) {
  Log ("  candidate: " + $d.InstanceId + " | " + $d.Status + " | " + $d.FriendlyName)
  if (-not $parent) { $parent = $d.InstanceId }
}
if (-not $parent) { Log "  FATAL: no ACPI parent found"; exit 1 }
Log ("chosen parent: " + $parent)

$dn = 'ACPI\AMDPSP\0000'
# scrub any stale enum key first (a pre-existing entry blocks create: t3 lesson)
$ek = "HKLM:\SYSTEM\CurrentControlSet\Enum\$dn"
if (Test-Path $ek) { Log "  stale enum key exists - removing first"; Remove-Item $ek -Recurse -Force }

Log "--- step 1: create devnode $dn parent=$parent flags=0 ---"
& "$work\t8_poc.exe" $out mkdev $dn $parent
Log "  mkdev exit=$LASTEXITCODE"

Log "--- step 2: seed enum key ---"
if (Test-Path $ek) {
  New-ItemProperty -Path $ek -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'Class' -Value 'System' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'ClassGUID' -Value '{4d36e97d-e325-11ce-bfc1-08002be10318}' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'DeviceDesc' -Value 'AMD PSP T8 test node' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'HardwareID' -Value @('ACPI\AMDPSP', 'ROOT\AMDPSP') -PropertyType MultiString -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'Service' -Value 't8_amdpsp' -PropertyType String -Force | Out-Null
  Log "  seeded OK"
} else {
  Log "  FATAL: enum key not auto-created; abort"
  exit 1
}

Log "--- step 3: pnputil /restart-device ---"
$pn = pnputil.exe /restart-device $dn 2>&1 | Out-String
Log ($pn.Trim())
Log ("  pnputil exit: " + $LASTEXITCODE)
Start-Sleep -Seconds 8

Log "--- step 4: post-state ---"
& "$work\t8_poc.exe" $out devstat $dn
Log "--- open probes ---"
& "$work\t8_poc.exe" $out open '\\.\amdpsp' c0000000 3
& "$work\t8_poc.exe" $out open '\\.\amdpsp' 12019f 3
& "$work\t8_poc.exe" $out open '\Device\amdpsp' 12019f 3
Log "--- DACL pulls (load-bearing) ---"
& "$work\t8_poc.exe" $out dacl '\\.\amdpsp'
& "$work\t8_poc.exe" $out dacl '\Device\amdpsp'
Log "--- service state ---"
Log (sc.exe query t8_amdpsp 2>&1 | Out-String)
Log "--- driverquery row ---"
$dq = driverquery.exe /v 2>&1 | Out-String
foreach ($line in ($dq -split "`r?`n")) { if ($line -match 't8_amdpsp|amdpsp') { Log ("  " + $line) } }

"t8_mkdev2 boundary $(Get-Date -Format o)" | Out-File "$work\t8_alive.txt" -Encoding ascii
exit 0
