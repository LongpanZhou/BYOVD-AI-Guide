# t7 phase A2: DACL pulls (fixed) + restricted-token open probes
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t7_work\t7_open_restr.txt'
"t7_open_restr $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

$work = 'C:\Users\vmdebug\Desktop\t7_work'
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

# recompile (poc changed)
Log "recompiling t7_poc.cs ..."
$c = & $csc /nologo /out:"$work\t7_poc.exe" /target:exe "$work\t7_poc.cs" 2>&1
Log ($c | Out-String); Log "compile exit=$LASTEXITCODE"

# admin DACL pulls
Log "=== DACL pulls (admin, READ_CONTROL) ==="
& "$work\t7_poc.exe" $out daclnt '\Device\VMCIGuestDev'
& "$work\t7_poc.exe" $out dacl \\.\VMCIDev
& "$work\t7_poc.exe" $out dacl \\.\vmci

# restricted token
Log "=== restricted-token probes (runas /trustlevel:0x20000) ==="
$restrOut = "$work\t7_restr.txt"
Remove-Item $restrOut -ErrorAction SilentlyContinue
$cmds = @(
  "$work\t7_poc.exe $restrOut open \\.\VMCIDev c0000000 3",
  "$work\t7_poc.exe $restrOut open \\.\VMCIDev 120089 3",
  "$work\t7_poc.exe $restrOut open \\.\vmci c0000000 3",
  "$work\t7_poc.exe $restrOut open \\.\vmci 120089 3",
  "$work\t7_poc.exe $restrOut dacl \\.\VMCIDev",
  "$work\t7_poc.exe $restrOut dacl \\.\vmci",
  "$work\t7_poc.exe $restrOut qobj \Device vmci|vsock"
)
foreach ($c2 in $cmds) {
  Log "runas: $c2"
  Start-Process -FilePath "$env:SystemRoot\System32\runas.exe" -ArgumentList "/trustlevel:0x20000 `"$c2`"" -Wait
  if (Test-Path $restrOut) { Log (Get-Content $restrOut | Out-String); Remove-Item $restrOut -ErrorAction SilentlyContinue }
  else { Log "  (no output file produced)" }
}
Log "=== end ==="
"t7_open_restr boundary $(Get-Date -Format o)" | Out-File "$work\t7_alive.txt" -Encoding ascii
exit 0
