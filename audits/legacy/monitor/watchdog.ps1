# Watchdog v2 — agent liveness with process-level attribution
# Cycle (every 5 min): ledger staleness per agent + java/analysis-process enumeration
# with command-line attribution (which .sys each is analyzing) + CPU deltas.
# Exits (wakes orchestrator) on: ledger staleness > per-agent threshold,
# OR analysis processes alive but 0 CPU across 2 consecutive cycles while ledgers quiet.
$logDir = 'C:\Users\27175\Desktop\driver_candidates\audits\monitor'
$log = Join-Path $logDir 'watchdog.log'
$agents = [ordered]@{
  'B'  = @{ file = 'C:\Users\27175\Desktop\driver_candidates\audits\_ledger_agentB.md'; threshold = 90 }
}
$prevCpu = @{}
$zeroCpuStreak = 0
# baseline-relative alarms: capture staleness at start; alarm only when silence GROWS past the threshold
# (prevents immediate re-alarm after an intervention/relaunch)
$baseline = @{}
foreach ($k in $agents.Keys) {
  if (Test-Path $agents[$k].file) { $baseline[$k] = ((Get-Date) - (Get-Item $agents[$k].file).LastWriteTime).TotalMinutes } else { $baseline[$k] = 0 }
}
while ($true) {
  $now = Get-Date
  $stale = @()
  $line = $now.ToString('HH:mm:ss') + ' | '
  # --- ledger staleness ---
  $maxStaleAge = 0
  foreach ($k in $agents.Keys) {
    $a = $agents[$k]
    if (Test-Path $a.file) {
      $age = ($now - (Get-Item $a.file).LastWriteTime).TotalMinutes
      if ($age -gt $maxStaleAge) { $maxStaleAge = $age }
      $line += ("{0}:{1:n0}m " -f $k, $age)
      if ((($age - $baseline[$k]) -gt $a.threshold)) { $stale += ("{0} ledger silent {1:n0}m (+{2:n0}m since watchdog start, thr {3})" -f $k, $age, ($age - $baseline[$k]), $a.threshold) }
    } else { $line += ("{0}:missing " -f $k) }
  }
  # --- analysis processes: attribution + CPU delta ---
  $procs = Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue
  $anyBusy = $false; $anyProc = $false
  foreach ($p in $procs) {
    $tgt = ''
    if ($p.CommandLine -match '([A-Za-z0-9_\-\.]+\.sys)') { $tgt = $Matches[1] }
    elseif ($p.CommandLine -match '([A-Za-z0-9_\-\.]+\.i64|target-[0-9a-f]{8}[^ ]*)') { $tgt = $Matches[1] }
    else { $tgt = '(no-target)' }
    $cpuNow = 0.0
    try { $cpuNow = (Get-Process -Id $p.ProcessId -ErrorAction Stop).CPU } catch { $cpuNow = -1 }
    $delta = if ($prevCpu.ContainsKey($p.ProcessId)) { $cpuNow - $prevCpu[$p.ProcessId] } else { -1 }
    $prevCpu[$p.ProcessId] = $cpuNow
    $anyProc = $true
    if ($delta -gt 0.2) { $anyBusy = $true }
    $line += ("| {0}({1})={2} dCPU={3:n1} " -f 'PROC', $p.ProcessId, $tgt, $delta)
  }
  # prune dead PIDs
  foreach ($procId in @($prevCpu.Keys)) { if (-not ($procs | Where-Object ProcessId -eq $procId)) { $prevCpu.Remove($procId) } }
  # --- zero-compute hang detection: processes alive, none computing, ledgers quiet ---
  if ($anyProc -and -not $anyBusy -and $maxStaleAge -gt 20) { $zeroCpuStreak++ } else { $zeroCpuStreak = 0 }
  if ($zeroCpuStreak -ge 2) {
    $stale += ("HARD-HANG: analysis processes alive but 0 CPU for 2 cycles while ledgers quiet {0:n0}m" -f $maxStaleAge)
  }
  Add-Content -Path $log -Value $line
  if ($stale.Count -gt 0) {
    Add-Content -Path $log -Value ('STALL: ' + ($stale -join ' ; '))
    Write-Output ('STALL: ' + ($stale -join ' ; '))
    exit 0
  }
  Start-Sleep -Seconds 300
}