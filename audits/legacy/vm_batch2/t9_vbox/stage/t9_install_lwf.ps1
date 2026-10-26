# t9 install_lwf: netcfg install of the VBoxNetLwf NDIS lightweight filter (production path)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_install_lwf.txt"
"t9_install_lwf $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

$inf = "$work\VBoxNetLwf.inf"
Log "--- step 0: sanity ---"
Log ("inf present: " + (Test-Path $inf))
Log ("sys hash: " + (Get-FileHash "$work\VBoxNetLwf.sys" -Algorithm SHA256).Hash)
Log ("inf hash: " + (Get-FileHash $inf -Algorithm SHA256).Hash)
Log ("pre-existing drivers\VBoxNetLwf.sys: " + (Test-Path 'C:\Windows\System32\drivers\VBoxNetLwf.sys'))

Log "--- step 1: netcfg -l VBoxNetLwf.inf -c s -i VBoxNetLwf ---"
$nc = & netcfg.exe -l $inf -c s -i VBoxNetLwf 2>&1 | Out-String
Log $nc
Log "netcfg exit=$LASTEXITCODE"

Log "--- step 2: post-install state ---"
Log (& netcfg.exe /s t 2>&1 | Out-String)
Log (& sc.exe query VBoxNetLwf 2>&1 | Out-String)
Log (& driverquery.exe /v 2>&1 | Select-String -Pattern 'VBoxNetLwf' | Out-String)
Log ("drivers\VBoxNetLwf.sys now present: " + (Test-Path 'C:\Windows\System32\drivers\VBoxNetLwf.sys'))

Log "--- step 2b: netcfg component presence query ---"
Log (& netcfg.exe -q VBoxNetLwf 2>&1 | Out-String)

Log "--- step 2c: FALLBACK - t7 service recipe (filter device surface is created in DriverEntry; bindings are the netcfg-gated layer) ---"
Log (& sc.exe create VBoxNetLwf type= kernel start= demand binPath= "$work\VBoxNetLwf.sys" 2>&1 | Out-String)
Log (& sc.exe start VBoxNetLwf 2>&1 | Out-String)
Log (& sc.exe query VBoxNetLwf 2>&1 | Out-String)
Log (& driverquery.exe /v 2>&1 | Select-String -Pattern 'VBoxNetLwf' | Out-String)

Log "--- step 3: device object check ---"
Log (& "$work\t9_poc.exe" $out ntopen '\Device\VBoxNetLwf' 12019F 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out daclnt '\Device\VBoxNetLwf' 2>&1 | Out-String)

Log "--- step 4: setupapi.dev.log VBox lines (t5 forensics) ---"
$sapi = 'C:\Windows\INF\setupapi.dev.log'
if (Test-Path $sapi) {
  $lines = Get-Content $sapi -ErrorAction SilentlyContinue
  $hits = @(); for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'VBoxNetLwf') { $hits += $i } }
  if ($hits.Count -gt 0) {
    $from = [Math]::Max(0, $hits[0] - 12)
    $to = [Math]::Min($lines.Count - 1, $hits[$hits.Count - 1] + 24)
    Log ("setupapi lines " + $from + ".." + $to + ":")
    Log (($lines[$from..$to] | Select-Object -First 90) | Out-String)
  } else { Log 'no VBoxNetLwf lines in setupapi.dev.log' }
} else { Log 'setupapi.dev.log not present' }
"t9_install_lwf boundary $(Get-Date -Format o)" | Out-File "$work\t9_alive.txt" -Encoding ascii
exit 0
