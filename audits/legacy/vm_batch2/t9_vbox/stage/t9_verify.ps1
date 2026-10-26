# t9 verify: post-run state verification (object dir, services, net components)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_verify.txt"
"t9_verify $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

Log "--- qobj \Device filter VBox|adp|lwf|sup|t9 ---"
& "$work\t9_poc.exe" $out qobj '\Device' 'VBox|adp|lwf|sup|t9'
Log "exit = $LASTEXITCODE (0xC0000005 = -1073741819 would be AV)"
Log "--- sc / driverquery / netcfg final state ---"
Log (& sc.exe query t9_vboxsup 2>&1 | Out-String)
Log (& driverquery.exe /v 2>&1 | Select-String -Pattern 't9_|VBox' | Out-String)
Log (& netcfg.exe /s t 2>&1 | Out-String)
Log "--- t9 files left in guest (t9_work only, per policy) ---"
Log (& powershell.exe -NoProfile -Command "Get-ChildItem 'C:\Users\vmdebug\Desktop\t9_work' | Select-Object -ExpandProperty Name" 2>&1 | Out-String)
Log "=== end verify ==="
exit 0
