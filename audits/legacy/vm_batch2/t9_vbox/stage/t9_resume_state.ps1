# t9_resume_state.ps1 - sanity check of surviving t9 state after the external power-off
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_resume_state.txt"
"t9_resume_state $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

Log "--- services ---"
Log (& sc.exe query t9_vboxsup 2>&1 | Out-String)
Log (& sc.exe query VBoxNetAdp 2>&1 | Out-String)
Log (& sc.exe query VBoxNetLwf 2>&1 | Out-String)
Log "--- driverquery rows ---"
Log (& driverquery.exe /v 2>&1 | Select-String -Pattern 't9_vboxsup|VBox' | Out-String)
Log "--- driver store packages (oem9/oem10) ---"
Log (& pnputil.exe /enum-drivers 2>&1 | Out-String)
Log "--- deployed copies ---"
Log ("drivers\VBoxNetAdp6.sys present: " + (Test-Path 'C:\Windows\System32\drivers\VBoxNetAdp6.sys'))
Log ("drivers\VBoxNetLwf.sys present: " + (Test-Path 'C:\Windows\System32\drivers\VBoxNetLwf.sys'))
Log ("hash VBoxNetAdp6.sys: " + (Get-FileHash 'C:\Windows\System32\drivers\VBoxNetAdp6.sys' -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash)
Log "--- devnode ---"
Log (& powershell.exe -NoProfile -Command "Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { `$_.InstanceId -match 'SUN_VBOXNETADP' } | Format-List InstanceId, Status, Class, Problem" 2>&1 | Out-String)
Log "--- device surfaces by name ---"
Log (& "$work\t9_poc.exe" $out ntopen '\Device\VBoxDrv' 12019F 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out ntopen '\Device\VBoxDrvU' 12019F 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out ntopen '\Device\VBoxNetLwf' 12019F 2>&1 | Out-String)
Log "--- staged levers script present in guest? ---"
Log ("t9_lwf_start_levers.ps1: " + (Test-Path "$work\t9_lwf_start_levers.ps1"))
Log ("t9_verify.ps1: " + (Test-Path "$work\t9_verify.ps1"))
"t9_resume_state boundary $(Get-Date -Format o)" | Out-File "$work\t9_alive.txt" -Encoding ascii
exit 0
