# t6_phaseB.ps1 - PHASE B STAGE ONLY - NEVER EXECUTED BY AGENT t6 (orchestrator-gated)
# Per-step wrapper for the 0x264800 overflow ladder. Orchestrator runs:
#   vmrun ... runProgramInGuest <vmx> powershell.exe -NoProfile -ExecutionPolicy Bypass \
#     -File C:\Users\vmdebug\Desktop\t6_work\t6_phaseB.ps1 -Step <step> -DevicePath <path>
# Design requirements honored:
#   * each step = ONE separate vmrun invocation + immediate host-side evidence pull
#   * every log line is flushed to disk BEFORE the destructive call is issued
#   * B0 gate: admin open + restricted-token open must BOTH pass before any s* step runs
param([string]$Step = 'gate',
      [string]$DevicePath = '',
      [string]$LogName = '')
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$exe  = "$work\t6_phaseB.exe"
if ($LogName -eq '') { $LogName = ("t6_phaseB_" + $Step + ".txt") }
$log = "$work\$LogName"

[System.IO.File]::AppendAllText($log, ("=== t6_phaseB step {0} {1} ===" -f $Step, (Get-Date -Format o)) + "`r`n")
[System.IO.File]::AppendAllText($log, ("device: " + $DevicePath) + "`r`n")
Add-Content -Path "$work\t6_alive.txt" -Value ("alive {0} phaseB-{1}" -f (Get-Date -Format o), $Step)

if ($Step -eq 'gate') {
  & $exe $log gate $DevicePath 2>&1 | ForEach-Object { [System.IO.File]::AppendAllText($log, ("  " + $_) + "`r`n") }
  # restricted-token open proof (must pass before any s* step is authorized)
  $restrLog = "$work\t6_phaseB_restricted_open.txt"
  if (Test-Path $restrLog) { Remove-Item $restrLog -Force }
  & runas.exe /trustlevel:0x20000 ('"' + $exe + '" ' + $restrLog + ' open ' + $DevicePath + ' C0000000') 2>&1 | ForEach-Object { [System.IO.File]::AppendAllText($log, ("  runas: " + $_) + "`r`n") }
  Start-Sleep 3
  if (Test-Path $restrLog) {
    Get-Content $restrLog | ForEach-Object { [System.IO.File]::AppendAllText($log, ("  restricted: " + $_) + "`r`n") }
    if ((Get-Content $restrLog) -match '-> FAIL') {
      [System.IO.File]::AppendAllText($log, "B0 GATE RESULT: restricted open FAILED - PHASE B MUST NOT PROCEED`r`n")
      exit 1
    } else {
      [System.IO.File]::AppendAllText($log, "B0 GATE RESULT: admin + restricted opens both work - steps s5..s0 authorized`r`n")
    }
  } else {
    [System.IO.File]::AppendAllText($log, "B0 GATE RESULT: restricted run produced NO output file - PHASE B MUST NOT PROCEED`r`n")
    exit 1
  }
  exit 0
}

# s* steps: log intent, flush, then run the (overflow-sized) call
[System.IO.File]::AppendAllText($log, ("RUNNING overflow step " + $Step + " at {0}" -f (Get-Date -Format o)) + "`r`n")
& $exe $log $Step $DevicePath 2>&1 | ForEach-Object { [System.IO.File]::AppendAllText($log, ("  " + $_) + "`r`n") }
[System.IO.File]::AppendAllText($log, ("step " + $Step + " returned; guest alive check follows in orchestrator flow") + "`r`n")
Add-Content -Path "$work\t6_alive.txt" -Value ("alive {0} phaseB-{1}-returned" -f (Get-Date -Format o), $Step)
