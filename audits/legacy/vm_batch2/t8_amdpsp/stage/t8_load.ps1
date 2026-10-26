# t8_load.ps1 - create + start t8_amdpsp kernel service from t8_work copy; capture SCM codes
# run in guest: powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\vmdebug\Desktop\t8_work\t8_load.ps1
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t8_work'
$out  = "$work\t8_load.txt"
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
"t8_load $(Get-Date -Format o)" | Out-File $out -Encoding ascii

# SHA-256 verify pushed driver (drift disclosure)
$sys = "$work\amdpsp.sys"
if (Test-Path $sys) {
  Log ("amdpsp.sys SHA256 = " + (Get-FileHash $sys -Algorithm SHA256).Hash)
  Log ("amdpsp.sys size   = " + (Get-Item $sys).Length)
} else {
  Log "FATAL: $sys missing - abort"
  exit 1
}

# create service (never overwrite pre-existing service: t8_amdpsp is namespaced)
$svc = 't8_amdpsp'
Log "--- sc create $svc ---"
$pre = sc.exe query $svc 2>&1 | Out-String
Log ("pre-create query: " + $pre.Trim())
if ($pre -match 'STATE\s*:.*RUNNING') {
  Log "service already exists and is RUNNING - will not recreate; proceeding to probes"
} elseif ($pre -match 'SERVICE_EXISTS_OR_STOPPED' -or $pre -match 'STATE') {
  Log "service exists (stopped) - using it as-is"
} else {
  $c = sc.exe create $svc type= kernel start= demand binPath= "$sys" 2>&1 | Out-String
  Log ("create exit=" + $LASTEXITCODE + " out: " + $c.Trim())
}

Log "--- sc start $svc ---"
$s = sc.exe start $svc 2>&1 | Out-String
Log ("start exit=" + $LASTEXITCODE + " out: " + $s.Trim())

Log "--- sc query $svc ---"
$q = sc.exe query $svc 2>&1 | Out-String
Log ("query: " + $q.Trim())

Log "--- driverquery rows (t8_amdpsp / amdpsp) ---"
$dq = driverquery.exe /v /fo csv 2>&1 | Out-String
foreach ($line in ($dq -split "`r?`n")) {
  if ($line -match 't8_amdpsp|amdpsp') { Log ("  " + $line) }
}

Log "--- event log System 7000/7026 tail (last 15 min) ---"
try {
  $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = @(7000, 7026); StartTime = (Get-Date).AddMinutes(-15) } -ErrorAction Stop
  foreach ($e in $ev) {
    Log ("  [{0}] id={1} src={2}" -f $e.TimeCreated.ToString('o'), $e.Id, $e.ProviderName)
    Log ("    " + ($e.Message -replace "`r`n", " | "))
  }
} catch {
  Log ("  (no 7000/7026 events: " + $_.Exception.Message + ")")
}

"t8_load boundary $(Get-Date -Format o)" | Out-File "$work\t8_alive.txt" -Encoding ascii
exit 0
