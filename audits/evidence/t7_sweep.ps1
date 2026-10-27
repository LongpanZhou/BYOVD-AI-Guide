# t7 phase C: structured function-code sweep - parameterized chunk runner
# usage: powershell -File t7_sweep.ps1 -dev '\\.\VMCIDev' -startfn 800 -endfn 8ff [-inlen 16] [-outlen 1000]
param(
  [Parameter(Mandatory=$true)][string]$dev,
  [Parameter(Mandatory=$true)][string]$startfn,
  [Parameter(Mandatory=$true)][string]$endfn,
  [string]$inlen = '10',
  [string]$outlen = '1000'
)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t7_work'
$out = "$work\t7_sweep.txt"
if (-not (Test-Path $out)) { "t7_sweep log $(Get-Date -Format o)" | Out-File $out -Encoding ascii }
"sweep chunk $dev fn $startfn..$endfn in=$inlen out=$outlen $(Get-Date -Format o)" | Out-File $out -Append -Encoding ascii
& "$work\t7_poc.exe" $out sweep $dev $startfn $endfn $inlen $outlen
"sweep chunk $dev $startfn..$endfn exit=$LASTEXITCODE $(Get-Date -Format o)" | Out-File $out -Append -Encoding ascii
"t7_sweep boundary $(Get-Date -Format o)" | Out-File "$work\t7_alive.txt" -Encoding ascii
exit 0
