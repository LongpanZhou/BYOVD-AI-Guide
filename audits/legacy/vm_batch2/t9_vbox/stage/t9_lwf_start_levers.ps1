# t9_lwf_start_levers.ps1 - two documented levers to get VBoxNetLwf running (binding-plane diagnosis)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_lwf_start_levers.txt"
"t9_lwf_start_levers $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

Log "=== lever A: LoadOrderGroup=NDIS + retry ==="
Log (& sc.exe config VBoxNetLwf group= NDIS 2>&1 | Out-String)
Log (& sc.exe start VBoxNetLwf 2>&1 | Out-String)
Log ("exit=" + $LASTEXITCODE)
Log (& sc.exe query VBoxNetLwf 2>&1 | Out-String)

Log "=== lever B: seed INF Ndi template under Control\Network (netcfg rollback left none) ==="
$ck = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}\{7af6b074-048d-4444-bfce-1ecc8bc5cb76}'
if (-not (Test-Path $ck)) {
  New-Item -Path $ck -Force | Out-Null
  New-Item -Path "$ck\Ndi" -Force | Out-Null
  New-Item -Path "$ck\Ndi\Interfaces" -Force | Out-Null
  New-ItemProperty -Path $ck -Name 'Service' -Value 'VBoxNetLwf' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ck -Name 'ComponentId' -Value 'VBoxNetLwf' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path "$ck\Ndi" -Name 'FilterClass' -Value 'compression' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path "$ck\Ndi" -Name 'FilterType' -Value 0x2 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "$ck\Ndi" -Name 'FilterRunType' -Value 2 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "$ck\Ndi" -Name 'HelpText' -Value 'VirtualBox NDIS6 Bridged Networking Driver' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path "$ck\Ndi" -Name 'CoServices' -Value 'VBoxNetLwf' -PropertyType MultiString -Force | Out-Null
  New-ItemProperty -Path "$ck\Ndi\Interfaces" -Name 'UpperRange' -Value 'noupper' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path "$ck\Ndi\Interfaces" -Name 'LowerRange' -Value 'nolower' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path "$ck\Ndi\Interfaces" -Name 'FilterMediaTypes' -Value 'ethernet' -PropertyType String -Force | Out-Null
  Log ("Ndi template seeded at " + $ck)
} else {
  Log ("Ndi config key already present at " + $ck + " (not touched)")
}
Log (& sc.exe start VBoxNetLwf 2>&1 | Out-String)
Log ("exit=" + $LASTEXITCODE)
Log (& sc.exe query VBoxNetLwf 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out ntopen '\Device\VBoxNetLwf' 12019F 2>&1 | Out-String)
Log "=== end levers ==="
exit 0
