# t10_load.ps1 - verify pushed iaStorV.sys, create+start service t10_iastrv, record exact outcomes
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t10_work'
$log  = "$work\t10_load.txt"
function Log([string]$s) { [IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker([string]$m) { Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

[IO.File]::WriteAllText($log, ("=== t10_load {0} ===`r`n" -f (Get-Date -Format o)))
Marker 'load-start'

$bin = "$work\iaStorV.sys"
$expect = '30BEE94794953E2DBF0FC5AFCE0566F335AF022E89819DE145329E7C09C636BD'
if (-not (Test-Path $bin)) { Log ('FATAL: binary missing: ' + $bin); exit 1 }
$h = (Get-FileHash -Algorithm SHA256 $bin).Hash
Log ('SHA-256 in-guest: ' + $h)
Log ('SHA-256 expected: ' + $expect)
if ($h -ne $expect) { Log 'FATAL: SHA mismatch - DRIFT, aborting load'; Marker 'load-sha-abort'; exit 2 }
Log 'SHA OK - proceeding'

Log '--- sc create ---'
& sc.exe create t10_iastrv type= kernel start= demand binPath= "$bin" 2>&1 | ForEach-Object { Log ('  ' + $_) }
Log ('  sc create exit=' + $LASTEXITCODE)

Log '--- sc query (pre-start) ---'
& sc.exe query t10_iastrv 2>&1 | ForEach-Object { Log ('  ' + $_) }

Log '--- sc start ---'
& sc.exe start t10_iastrv 2>&1 | ForEach-Object { Log ('  ' + $_) }
Log ('  sc start exit=' + $LASTEXITCODE)
Start-Sleep -Seconds 3

Log '--- sc query (post-start) ---'
& sc.exe query t10_iastrv 2>&1 | ForEach-Object { Log ('  ' + $_) }
Log ('  sc query exit=' + $LASTEXITCODE)

Log '--- driverquery /v (filtered) ---'
& driverquery.exe /v 2>&1 | ForEach-Object {
  if ($_ -match 'iaStor|t10_') { Log ('  ' + $_) }
}

Log '--- events 7000/7026 (last 10 min, ASCII-folded) ---'
try {
  Get-WinEvent -FilterHashtable @{ LogName='System'; Id=7000,7026; StartTime=(Get-Date).AddMinutes(-10) } -ErrorAction Stop |
    ForEach-Object {
      $m = ($_.Message -replace '[^\x20-\x7E]', '?')
      Log ('  id=' + $_.Id + ' t=' + $_.TimeCreated.ToString('o') + ' src=' + $_.ProviderName + ' msg=' + $m)
    }
} catch { Log ('  (no events: ' + $_.Exception.Message.Replace([char]10,' ').Replace([char]13,'') + ')') }

Log '--- object dir quick probe (device names, admin) ---'
& "$work\t10_poc.exe" $log qobj '\Device' 'iaStor|ScsiPort|IAAStorage|Ide' 2>&1 | Out-Null
& "$work\t10_poc.exe" $log qobj '\DosDevices' 'iaStor|ScsiPort|IAAStorage|Scsi' 2>&1 | Out-Null

Marker 'load-done'
exit 0
