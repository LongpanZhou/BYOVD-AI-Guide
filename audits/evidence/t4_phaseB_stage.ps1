# t4_phaseB_stage.ps1 (agent t4) - Phase A step 10: PHASE-B staging (compile-only).
# t4_phaseB.exe is built to validate the staged source compiles - it is NEVER executed
# by agent t4. Phase B is orchestrator-gated. Evidence: t4_phaseB_staging.txt
$log = 'C:\Users\vmdebug\Desktop\t4_work\t4_phaseB_staging.txt'
$work = 'C:\Users\vmdebug\Desktop\t4_work'
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t4_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
W ("=== t4 PHASE-B STAGING (compile-only, NEVER executed) {0} ===" -f (Get-Date -Format o))
Marker 'phaseB-staging-start'
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$exe = "$work\t4_phaseB.exe"
& $csc /nologo /out:$exe "$work\t4_phaseB.cs" 2>&1 | ForEach-Object { W ('csc: ' + $_) }
if (Test-Path $exe) { W ("t4_phaseB.exe built OK (STAGED - NOT RUN; size=" + (Get-Item $exe).Length + " bytes)") } else { W 'COMPILE FAILED' }
W '--- staged phase-B files in t4_work ---'
Get-ChildItem $work -Filter 't4_phaseB*' | ForEach-Object { W ('  {0}  {1} bytes' -f $_.Name, $_.Length) }
W '--- execution policy note ---'
W '  t4_phaseB.exe was NOT executed by agent t4. PHASE B IS ORCHESTRATOR-GATED (solo phase).'
W '  Run pattern per step (B0/B1/B2/B3), see t4_phaseB.ps1 header:'
W '    vmrun -T ws -gu vmdebug -gp 123456 runProgramInGuest <vmx> powershell.exe -NoProfile'
W '      -ExecutionPolicy Bypass -File C:\Users\vmdebug\Desktop\t4_work\t4_phaseB.ps1 -Step <step>'
W '    then immediately CopyFileFromGuestToHost t4_phaseB_<step>.txt to host evidence dir.'
Marker 'phaseB-staging-done'
[IO.File]::WriteAllText($log, $sb.ToString())
