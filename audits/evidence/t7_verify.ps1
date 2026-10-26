# t7 final verification: object directory clean + poc exit codes (script-file invocation)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t7_work'
$out = "$work\t7_verify.txt"
"t7_verify $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

Log "--- qobj \Device filter t7|bxv|qlogic|b06|audio|nv ---"
& "$work\t7_poc.exe" $out qobj '\Device' 't7|bxv|qlogic|b06|audio|nv'
Log "exit = $LASTEXITCODE (0xC0000005=-1073741819 would be AV)"
Log "--- qobj \Device filter vmci|vsock (expect the two VMware surfaces only) ---"
& "$work\t7_poc.exe" $out qobj '\Device' 'vmci'
Log "exit = $LASTEXITCODE"
Log "=== end verify ==="
exit 0
