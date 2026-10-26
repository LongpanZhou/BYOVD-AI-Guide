# t8_mkdev3.ps1 - attempt 3 (final): devnode under a real PCI devnode (pci.sys PDO supplies
# BUS_INTERFACE_STANDARD via IRP_MN_QUERY_INTERFACE). Empty resource list = D0Entry resource
# loop skipped (static: returns bus-iface status) -> device should start.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t8_work'
$out  = "$work\t8_mkdev3.txt"
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
"t8_mkdev3 $(Get-Date -Format o)" | Out-File $out -Encoding ascii

Log "--- candidate PCI parents ---"
$pci = Get-PnpDevice 2>$null | Where-Object { $_.InstanceId -like 'PCI\*' -and $_.Status -eq 'OK' } | Select-Object -First 6
$parent = $null
foreach ($d in $pci) {
  Log ("  candidate: " + $d.InstanceId + " | " + $d.FriendlyName)
  if (-not $parent) { $parent = $d.InstanceId }
}
if (-not $parent) { Log "  FATAL: no PCI parent found"; exit 1 }
Log ("chosen parent: " + $parent)

$dn = 'PCI\AMDPSP\0000'
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
  New-ItemProperty -Path $ek -Name 'HardwareID' -Value @('PCI\AMDPSP', 'ACPI\AMDPSP', 'ROOT\AMDPSP') -PropertyType MultiString -Force | Out-Null
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
Start-Sleep -Seconds 10

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

"t8_mkdev3 boundary $(Get-Date -Format o)" | Out-File "$work\t8_alive.txt" -Encoding ascii
exit 0
