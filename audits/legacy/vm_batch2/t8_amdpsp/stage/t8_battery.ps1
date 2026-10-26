# t8_battery.ps1 - documented-code batteries for amdpsp (all bounded: in<=0x38 shaped, out<=0x1000)
# run in guest: powershell.exe -NoProfile -ExecutionPolicy Bypass -File <work>\t8_battery.ps1
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t8_work'
$out  = "$work\t8_battery.txt"
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
"t8_battery $(Get-Date -Format o)" | Out-File $out -Encoding ascii
if (-not (Test-Path "$work\t8_poc.exe")) { Log "FATAL: t8_poc.exe missing"; exit 1 }
$dev = '\\.\amdpsp'

function LEHex([uint64]$v, [int]$bytes) {
  $s = ('{0:x' + ($bytes * 2) + '}') -f $v
  $le = ''
  for ($i = $s.Length - 2; $i -ge 0; $i -= 2) { $le += $s.Substring($i, 2) }
  return $le
}

Log "=== A. 0x9c422002 contiguous-alloc ladder (size in both dwords; free after each) ==="
foreach ($sz in @(0x10, 0x100, 0x1000, 0x10000, 0x40000)) {
  $ih = (LEHex $sz 4) + (LEHex $sz 4)
  Log "--- ladder size=0x$('{0:x}' -f $sz) ---"
  & "$work\t8_poc.exe" $out wrtest $dev 9c422002 $ih 38 free
  Log "  exit=$LASTEXITCODE"
}

Log "=== B. slot register family (in=8: int[0]=slot index 1..16) ==="
& "$work\t8_poc.exe" $out ioctl $dev 9c422004 8 38 0100000000000000
& "$work\t8_poc.exe" $out ioctl $dev 9c422005 8 38 0100000000000000
& "$work\t8_poc.exe" $out ioctl $dev 9c422004 8 38 0000000000000000
& "$work\t8_poc.exe" $out ioctl $dev 9c422004 8 38 1100000000000000
& "$work\t8_poc.exe" $out ioctl $dev 9c422005 8 38 1100000000000000

Log "=== C. 0x9c422003 free-by-VA probes ==="
& "$work\t8_poc.exe" $out ioctl $dev 9c422003 8 38 0000000000000000
& "$work\t8_poc.exe" $out ioctl $dev 9c422003 8 38 0000000000f07f
Log "  (expect C000000D both: VA=0 immediate, bogus VA scan-miss)"

Log "=== D. 0x9c422009 register (ptr,len) probe (in=0x10: qword0=ptr, dword8=len) ==="
& "$work\t8_poc.exe" $out probe $dev 9c422009 10 8 0 38
& "$work\t8_poc.exe" $out ioctl $dev 9c422009 10 38 00000000000000000000000000000000

Log "=== E. shaped probe-capture family (user-VA ptrs only; driver probes user mode) ==="
& "$work\t8_poc.exe" $out probe $dev 9c422000 18 4 10 38
& "$work\t8_poc.exe" $out probe $dev 9c422006 10 4 8 38
& "$work\t8_poc.exe" $out probe $dev 9c422007 38 ff 30 38
& "$work\t8_poc.exe" $out probe $dev 9c422008 20 8 18 38
& "$work\t8_poc.exe" $out probe $dev 9c422808 10 0 8 38
& "$work\t8_poc.exe" $out probe $dev 9c422834 20 10 18 38

Log "=== F. 0x9c422820 shaped 0x168 mapping probe (size@0x158=0x1000; out=0x158) ==="
& "$work\t8_poc.exe" $out wrtest $dev 9c422820 shape820 158

Log "=== U. restricted-token probes (runas /trustlevel:0x20000) - load-bearing ==="
$restrOut = "$work\t8_restr.txt"
foreach ($c2 in @(
  "$work\t8_poc.exe $restrOut open \\.\amdpsp c0000000 3",
  "$work\t8_poc.exe $restrOut open \\.\amdpsp 12019f 3",
  "$work\t8_poc.exe $restrOut open \\.\amdpsp 0 3",
  "$work\t8_poc.exe $restrOut dacl \\.\amdpsp",
  "$work\t8_poc.exe $restrOut dacl \Device\amdpsp",
  "$work\t8_poc.exe $restrOut wrtest \\.\amdpsp 9c422002 1000000010000000 38 free",
  "$work\t8_poc.exe $restrOut qobj \Device amd|psp"
)) {
  Log "runas: $c2"
  Remove-Item $restrOut -ErrorAction SilentlyContinue
  Start-Process -FilePath "$env:SystemRoot\System32\runas.exe" -ArgumentList "/trustlevel:0x20000 `"$c2`"" -Wait
  if (Test-Path $restrOut) { Log (Get-Content $restrOut | Out-String); Remove-Item $restrOut -ErrorAction SilentlyContinue }
  else { Log "  (no output file produced)" }
}

"t8_battery boundary $(Get-Date -Format o)" | Out-File "$work\t8_alive.txt" -Encoding ascii
exit 0
