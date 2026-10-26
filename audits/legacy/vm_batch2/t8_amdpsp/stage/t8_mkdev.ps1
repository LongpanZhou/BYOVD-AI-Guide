# t8_mkdev.ps1 - t3-proven synthetic devnode recipe so amdpsp EvtDeviceAdd fires:
#   1) CM_Create_DevNodeW(ROOT\AMDPSP\0000, parent HTREE\ROOT\0, flags=0)  [FIRST]
#   2) seed auto-created enum key (ConfigFlags=0, Class=System, ClassGUID, DeviceDesc, HardwareID, Service=t8_amdpsp)
#   3) pnputil /restart-device ROOT\AMDPSP\0000
#   4) post-state: devstat + open probes + DACL pulls (resolves Everyone-SDDL on the LIVE object)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t8_work'
$out  = "$work\t8_mkdev.txt"
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
"t8_mkdev $(Get-Date -Format o)" | Out-File $out -Encoding ascii
$dn = 'ROOT\AMDPSP\0000'

Log "--- step 1: create devnode (flags=0) ---"
& "$work\t8_poc.exe" $out mkdev $dn 'HTREE\ROOT\0'
Log "  mkdev exit=$LASTEXITCODE"

Log "--- step 2: seed enum key ---"
$k = "HKLM:\SYSTEM\CurrentControlSet\Enum\$dn"
if (Test-Path $k) {
  New-ItemProperty -Path $k -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $k -Name 'Class' -Value 'System' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $k -Name 'ClassGUID' -Value '{4d36e97d-e325-11ce-bfc1-08002be10318}' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $k -Name 'DeviceDesc' -Value '@t8_amdpsp.DeviceDesc;t8 AMD PSP test node' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $k -Name 'HardwareID' -Value @('ROOT\AMDPSP') -PropertyType MultiString -Force | Out-Null
  New-ItemProperty -Path $k -Name 'Service' -Value 't8_amdpsp' -PropertyType String -Force | Out-Null
  Log ("  seeded: " + ((Get-ItemProperty $k | Out-String) -replace "`r`n", ' | '))
} else {
  Log "  FATAL: enum key $k was NOT auto-created; abort"
  exit 1
}

Log "--- step 3: pnputil /restart-device ---"
$pn = pnputil.exe /restart-device $dn 2>&1 | Out-String
Log ($pn.Trim())
Log ("  pnputil exit: " + $LASTEXITCODE)
Start-Sleep -Seconds 8

Log "--- step 4: post-state ---"
& "$work\t8_poc.exe" $out devstat $dn
Log "  devstat exit=$LASTEXITCODE"
Log "--- open probes ---"
& "$work\t8_poc.exe" $out open '\\.\amdpsp' c0000000 3
& "$work\t8_poc.exe" $out open '\\.\amdpsp' 12019f 3
& "$work\t8_poc.exe" $out open '\Device\amdpsp' 12019f 3
Log "--- DACL pulls (load-bearing) ---"
& "$work\t8_poc.exe" $out dacl '\\.\amdpsp'
& "$work\t8_poc.exe" $out daclnt '\Device\amdpsp'
Log "--- driverquery row ---"
$dq = driverquery.exe /v 2>&1 | Out-String
foreach ($line in ($dq -split "`r?`n")) { if ($line -match 't8_amdpsp|amdpsp') { Log ("  " + $line) } }

"t8_mkdev boundary $(Get-Date -Format o)" | Out-File "$work\t8_alive.txt" -Encoding ascii
exit 0
