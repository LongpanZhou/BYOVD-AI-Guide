# t8_sweep.ps1 - chunked bounded sweep runner (t7 pattern)
# usage: powershell -File t8_sweep.ps1 -mode A|B|C -chunk <n> [-dev \\.\amdpsp]
# A: low band 0x9c422000-0x9c42200C, in{0,16} x out{0,0x38,0x1000} -> 6 chunks
# B: method/access variants of documented codes (single chunk)
# C: band 0x9c422800-0x9c42283F, 3 header variants x 2 halves -> 6 chunks
param(
  [Parameter(Mandatory=$true)][string]$mode,
  [Parameter(Mandatory=$true)][string]$chunk,
  [string]$dev = '\\.\amdpsp'
)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t8_work'
$out = "$work\t8_sweep.txt"
if (-not (Test-Path $out)) { "t8_sweep log $(Get-Date -Format o)" | Out-File $out -Encoding ascii }
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

if ($mode -eq 'A') {
  $n = [int]$chunk
  if ($n -lt 0 -or $n -gt 5) { Log "sweepA bad chunk $n"; exit 1 }
  $ins  = @('0', '0', '0', '10', '10', '10')
  $outs = @('0', '38', '1000', '0', '38', '1000')
  Log "sweepA chunk $n dev=$dev in=0x$($ins[$n]) out=0x$($outs[$n]) $(Get-Date -Format o)"
  & "$work\t8_poc.exe" $out sweepA $dev 9c422000 9c42200c $ins[$n] $outs[$n]
  Log "sweepA chunk $n exit=$LASTEXITCODE $(Get-Date -Format o)"
}
elseif ($mode -eq 'B') {
  Log "sweepB chunk 0 dev=$dev $(Get-Date -Format o)"
  & "$work\t8_poc.exe" $out sweepB $dev
  Log "sweepB exit=$LASTEXITCODE $(Get-Date -Format o)"
}
elseif ($mode -eq 'C') {
  $n = [int]$chunk
  if ($n -lt 0 -or $n -gt 5) { Log "sweepC bad chunk $n"; exit 1 }
  $vs   = @('0', '0', '1', '1', '2', '2')
  $lo   = @('9c422800', '9c422820', '9c422800', '9c422820', '9c422800', '9c422820')
  $hi   = @('9c42281f', '9c42283f', '9c42281f', '9c42283f', '9c42281f', '9c42283f')
  Log "sweepC chunk $n dev=$dev variant=$($vs[$n]) range=$($lo[$n])..$($hi[$n]) $(Get-Date -Format o)"
  & "$work\t8_poc.exe" $out sweepC $dev $lo[$n] $hi[$n] $vs[$n]
  Log "sweepC chunk $n exit=$LASTEXITCODE $(Get-Date -Format o)"
}
else { Log "unknown mode $mode"; exit 1 }

"t8_sweep boundary $(Get-Date -Format o)" | Out-File "$work\t8_alive.txt" -Encoding ascii
exit 0
