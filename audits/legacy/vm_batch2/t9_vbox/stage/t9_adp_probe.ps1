# t9 adp_probe: negative-surface pack for VBoxNetAdp6 (no own device object expected)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_adp_probe.txt"
"t9_adp_probe $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

Log "--- step 1: qobj \Device filter adp|VBox|Host|NetAdp ---"
Log (& "$work\t9_poc.exe" $out qobj '\Device' 'adp|VBox|Host' 2>&1 | Out-String)

Log "--- step 2: open probes of plausible names (expect all FILE_NOT_FOUND / no device) ---"
foreach ($n in @('\\.\VBoxNetAdp6', '\\.\VBoxNetAdp', '\\.\VirtualBox\HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter')) {
  Log (& "$work\t9_poc.exe" $out open $n 12019F 3 2>&1 | Out-String)
}

Log "--- step 3: NDIS miniport enumeration details ---"
Log (& powershell.exe -NoProfile -Command "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { `$_.InterfaceDescription -match 'VBox|VirtualBox' } | Format-List *" 2>&1 | Out-String)
Log "--- registry miniport instances ---"
Log (& powershell.exe -NoProfile -Command "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue | ForEach-Object { `$p = Get-ItemProperty `$_.PSPath; if (`$p.DriverDesc -match 'VBox') { '--- ' + `$_.PSChildName; `$p | Format-List DriverDesc, Service, NdisDeviceType, MediaType, *IfType, BusNumber } }" 2>&1 | Out-String)

Log "--- step 4: devnode + service state ---"
Log (& powershell.exe -NoProfile -Command "Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { `$_.InstanceId -match 'SUN_VBOXNETADP' } | Format-List InstanceId, Status, Class, Problem, ProblemDescription, Service" 2>&1 | Out-String)
Log (& sc.exe query VBoxNetAdp 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out devstat 'ROOT\SUN_VBOXNETADP\0000' 2>&1 | Out-String)

Log "--- step 5: supdrv device surface (kernel client of \Device\VBoxDrv - read-only checks) ---"
Log (& "$work\t9_poc.exe" $out daclnt '\Device\VBoxDrv' 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out ntopen '\Device\VBoxDrv' 12019F 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out daclnt '\Device\VBoxDrvU' 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out ntopen '\Device\VBoxDrvU' 12019F 2>&1 | Out-String)

"t9_adp_probe boundary $(Get-Date -Format o)" | Out-File "$work\t9_alive.txt" -Encoding ascii
exit 0
