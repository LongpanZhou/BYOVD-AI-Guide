# t10_sweep.ps1 - structured raw-code sweep bands (chunked runner, one band per invocation)
# usage: powershell -File t10_sweep.ps1 -start 4d000 -end 4d0fc [-step 4] [-inlen 10] [-outlen 1000]
param(
  [Parameter(Mandatory=$true)][string]$start,
  [Parameter(Mandatory=$true)][string]$end,
  [string]$step = '4',
  [string]$inlen = '10',
  [string]$outlen = '1000'
)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t10_work'
$out  = "$work\t10_sweep.txt"
$devs = "$work\t10_devices.txt"
if (-not (Test-Path $out)) { [IO.File]::WriteAllText($out, ("t10_sweep log {0}`r`n" -f (Get-Date -Format o))) }
[IO.File]::AppendAllText($out, ("sweep chunk {0}..{1} step {2} in={3} out={4} {5}`r`n" -f $start, $end, $step, $inlen, $outlen, (Get-Date -Format o)))

$dev = '\\.\Scsi0:'
if (Test-Path $devs) {
  foreach ($p in [IO.File]::ReadAllLines($devs)) { if ($p.Trim().Length -gt 0) { $dev = $p.Trim(); break } }
}
& "$work\t10_poc.exe" $out sweepc $dev $start $end $step $inlen $outlen 2>&1 | Out-Null
[IO.File]::AppendAllText($out, ("sweep chunk {0}..{1} exit={2} {3}`r`n" -f $start, $end, $LASTEXITCODE, (Get-Date -Format o)))
Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} sweep {1}-{2}" -f (Get-Date -Format o), $start, $end)
exit 0
