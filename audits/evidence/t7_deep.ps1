# t7 phase D: deep-dive the 3 success codes + restricted-token reachability confirmation
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t7_work\t7_deep.txt'
"t7_deep $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
$work = 'C:\Users\vmdebug\Desktop\t7_work'

Log "=== admin: input-variation matrix on success codes (bounded: in<=64, out<=0x1000) ==="
foreach ($code in '81032004','81032024','81032054') {
  & "$work\t7_poc.exe" $out ioctl \\.\VMCIDev $code 0 40
  & "$work\t7_poc.exe" $out ioctl \\.\VMCIDev $code 10 40 4141414141414141414141414141414
  & "$work\t7_poc.exe" $out ioctl \\.\VMCIDev $code 40 40 41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
  & "$work\t7_poc.exe" $out ioctl \\.\VMCIDev $code 40 1000 41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
}

Log "=== restricted-token (runas /trustlevel:0x20000) on success codes ==="
$restrOut = "$work\t7_restr.txt"
foreach ($code in '81032004','81032024','81032054') {
  Remove-Item $restrOut -ErrorAction SilentlyContinue
  $cmd = "$work\t7_poc.exe $restrOut ioctl \\.\VMCIDev $code 10 40"
  Log "runas: $cmd"
  Start-Process -FilePath "$env:SystemRoot\System32\runas.exe" -ArgumentList "/trustlevel:0x20000 `"$cmd`"" -Wait
  if (Test-Path $restrOut) { Log (Get-Content $restrOut | Out-String) } else { Log "  (no output)" }
}
Log "=== restricted-token: 2 of the denied band (confirm denial is not admin-only artifact) ==="
foreach ($code in '81032008','8103201c') {
  Remove-Item $restrOut -ErrorAction SilentlyContinue
  $cmd = "$work\t7_poc.exe $restrOut ioctl \\.\VMCIDev $code 10 40"
  Log "runas: $cmd"
  Start-Process -FilePath "$env:SystemRoot\System32\runas.exe" -ArgumentList "/trustlevel:0x20000 `"$cmd`"" -Wait
  if (Test-Path $restrOut) { Log (Get-Content $restrOut | Out-String) } else { Log "  (no output)" }
}
Log "=== end t7_deep ==="
"t7_deep boundary $(Get-Date -Format o)" | Out-File "$work\t7_alive.txt" -Encoding ascii
exit 0
