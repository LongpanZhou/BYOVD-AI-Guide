# t7 debug: characterize the qobj crash
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t7_work'
$out = "$work\t7_dbg.txt"
"t7_dbg $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

Log "--- run A: filter t7|bxv|qlogic|b06 ---"
& "$work\t7_poc.exe" $out qobj '\Device' 't7|bxv|qlogic|b06'
Log "exit A = $LASTEXITCODE"
Log "--- run B: filter vmci (same as earlier successful scan) ---"
& "$work\t7_poc.exe" $out qobj '\Device' 'vmci'
Log "exit B = $LASTEXITCODE"
Log "--- run C: filter . (match all) ---"
& "$work\t7_poc.exe" $out qobj '\Device' '.'
Log "exit C = $LASTEXITCODE"
Log "=== end dbg ==="
exit 0
