# t7 phase A1: compile PoC + object inventory + open/DACL probes for vmci & vsock surfaces
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t7_work\t7_qobj.txt'
"t7_qobj $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

$work = 'C:\Users\vmdebug\Desktop\t7_work'
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

# compile
if (-not (Test-Path "$work\t7_poc.exe") -or ((Get-Item "$work\t7_poc.cs").LastWriteTime -gt (Get-Item "$work\t7_poc.exe").LastWriteTime)) {
  Log "compiling t7_poc.cs ..."
  $c = & $csc /nologo /out:"$work\t7_poc.exe" /target:exe "$work\t7_poc.cs" 2>&1
  Log ($c | Out-String)
  Log "compile exit=$LASTEXITCODE exe=$([System.IO.File]::Exists("$work\t7_poc.exe"))"
}

# aliveness marker
"t7_qobj boundary $(Get-Date -Format o)" | Out-File "$work\t7_alive.txt" -Encoding ascii

# object inventory
& "$work\t7_poc.exe" $out qobj '\Device' 'vmci|vsock|vmx'
& "$work\t7_poc.exe" $out qobj '\GLOBAL??' 'vmci|vsock'
& "$work\t7_poc.exe" $out qobj '\??' 'vmci|vsock'

Log "=== open probes (admin token) ==="
# open matrix on candidate device names
foreach ($p in '\\.\VMCIDev', '\\.\VMCIGuestDev', '\\.\VMCIHostDev', '\\.\vmci') {
  & "$work\t7_poc.exe" $out open $p c0000000 3
  & "$work\t7_poc.exe" $out open $p 120089 3
  & "$work\t7_poc.exe" $out open $p 0 3
}
Log "=== NT-path opens (direct device names) ==="
& "$work\t7_poc.exe" $out ntopen '\Device\VMCIHostDev' 12019f
& "$work\t7_poc.exe" $out ntopen '\Device\VMCIGuestDev' 12019f
& "$work\t7_poc.exe" $out ntopen '\Device\vmci' 12019f
& "$work\t7_poc.exe" $out ntopen '\Device\VMCIDev' 12019f
Log "=== DACL pulls (READ_CONTROL) ==="
foreach ($p in '\\.\VMCIDev', '\\.\VMCIGuestDev', '\\.\vmci') {
  & "$work\t7_poc.exe" $out dacl $p
}
Log "=== wsock AF_VSOCK provider probe ==="
& "$work\t7_poc.exe" $out wsock
Log "=== end t7_qobj ==="
exit 0
