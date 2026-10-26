# t9_netcfg_retry.ps1 - deep setupapi tail + verbose netcfg retry
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_netcfg_retry.txt"
"t9_netcfg_retry $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

$sapi = 'C:\Windows\INF\setupapi.dev.log'
if (Test-Path $sapi) {
  $lines = Get-Content $sapi
  $n = $lines.Count
  Log ("setupapi.dev.log total lines: " + $n)
  Log '--- last 140 lines ---'
  Log (($lines[($n-140)..($n-1)]) -join "`r`n")
}

Log "--- netcfg -v -l ... -c s -i VBoxNetLwf (retry, verbose) ---"
$nc = & netcfg.exe -v -l "$work\VBoxNetLwf.inf" -c s -i VBoxNetLwf 2>&1 | Out-String
Log $nc
Log ("netcfg exit=" + $LASTEXITCODE)

Log "--- post state ---"
Log (& netcfg.exe -q VBoxNetLwf 2>&1 | Out-String)
Log (& sc.exe query VBoxNetLwf 2>&1 | Out-String)
Log ("drivers\VBoxNetLwf.sys present: " + (Test-Path 'C:\Windows\System32\drivers\VBoxNetLwf.sys'))
Log (& "$work\t9_poc.exe" $out ntopen '\Device\VBoxNetLwf' 12019F 2>&1 | Out-String)
exit 0
