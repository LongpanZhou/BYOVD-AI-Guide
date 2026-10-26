# t9 discover: object/adapter/service inventory for the t9 VBox surfaces
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_discover.txt"
"t9_discover $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

Log "--- qobj \Device filter VBox|adp|lwf|sup (BEST-EFFORT: poc qobj mode is BLOCKED, AVs fast, parent continues; see t9_qobj_blocked.txt) ---"
Log (& "$work\t9_poc.exe" $out qobj '\Device' 'VBox|adp|lwf|sup' 2>&1 | Out-String)
Log "qobj exit=$LASTEXITCODE"

Log "--- netcfg /s t (all net components) ---"
Log (& netcfg.exe /s t 2>&1 | Out-String)

Log "--- Get-NetAdapter (all, incl. hidden/broken) ---"
Log (& powershell.exe -NoProfile -Command "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Format-Table -AutoSize Name, InterfaceDescription, Status, DriverVersion, DriverInformation" 2>&1 | Out-String)

Log "--- driverquery VBox rows ---"
Log (& driverquery.exe /v 2>&1 | Select-String -Pattern 'VBox' | Out-String)

Log "--- sc query t9_vboxsup / VBoxNetAdp / VBoxNetLwf ---"
Log (& sc.exe query t9_vboxsup 2>&1 | Out-String)
Log (& sc.exe query VBoxNetAdp 2>&1 | Out-String)
Log (& sc.exe query VBoxNetLwf 2>&1 | Out-String)

Log "--- registry: Net class instances with VBox ---"
Log (& powershell.exe -NoProfile -Command "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue | ForEach-Object { `$p = Get-ItemProperty `$_.PSPath; if (`$p.DriverDesc -match 'VBox') { `$_.PSChildName + ' : ' + `$p.DriverDesc + ' : svc=' + `$p.Service } }" 2>&1 | Out-String)
Log "--- registry: NetService class instances with VBox ---"
Log (& powershell.exe -NoProfile -Command "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue | ForEach-Object { `$p = Get-ItemProperty `$_.PSPath; if (`$p.DriverDesc -match 'VBox') { `$_.PSChildName + ' : ' + `$p.DriverDesc + ' : svc=' + `$p.Service } }" 2>&1 | Out-String)
Log "--- DeviceClasses: filter VBox GUIDs ---"
Log (& powershell.exe -NoProfile -Command "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses' -ErrorAction SilentlyContinue | Where-Object { `$_.PSChildName -match '^#?\{?\??.*[Vv]Box' -or (`$_.Name -match 'VBOX') } | Select-Object -ExpandProperty PSChildName" 2>&1 | Out-String)
"t9_discover boundary $(Get-Date -Format o)" | Out-File "$work\t9_alive.txt" -Encoding ascii
exit 0
