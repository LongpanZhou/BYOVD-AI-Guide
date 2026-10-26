# t6_phaseB_stage.ps1 (agent t6) - Phase A step 9: stage Phase B WITHOUT executing it.
# Compiles t6_phaseB.exe, verifies the build, writes the staged-state manifest.
# NO destructive call is ever issued by this script (it does not touch the device at all).
# Evidence: t6_phaseB_staging.txt
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$log  = "$work\t6_phaseB_staging.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t6_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

W ("=== t6 phase-B staging {0} ===" -f (Get-Date -Format o))
Marker 'phaseB-staging-start'

W '--- compile t6_phaseB.cs -> t6_phaseB.exe (compile-verified build, NOT RUN) ---'
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $csc /nologo /out:"$work\t6_phaseB.exe" "$work\t6_phaseB.cs" 2>&1 | ForEach-Object { W ('csc: ' + $_) }
$e = "$work\t6_phaseB.exe"
if (Test-Path $e) {
  $f = Get-Item $e
  W ("  build OK: {0} bytes, {1}" -f $f.Length, $f.LastWriteTime)
  W ("  sha256  : " + (Get-FileHash $e -Algorithm SHA256).Hash)
} else { W '  FATAL: compile failed' }

W '--- staged files manifest ---'
foreach ($p in @("$work\t6_phaseB.cs","$work\t6_phaseB.exe","$work\t6_phaseB.ps1")) {
  if (Test-Path $p) { $f = Get-Item $p; W ("  {0}  {1} B" -f $p, $f.Length) } else { W ("  MISSING: $p") }
}

W '--- ladder definition (FOR THE ORCHESTRATOR - each step = ONE vmrun invocation + immediate pull) ---'
W '  B0  gate : t6_phaseB.ps1 -Step gate -DevicePath <audioprotection path>   (admin+restricted open proof; MUST pass first)'
W '  B1  s5   : in=5 out=5   -> allocation 5 B -> 1-byte OOB'
W '  B2  s4   : in=4 out=4   -> allocation 4 B -> 2-byte OOB'
W '  B3  s3   : in=3 out=3   -> allocation 3 B -> 3-byte OOB'
W '  B4  s2   : in=2 out=2   -> allocation 2 B -> 4-byte OOB'
W '  B5  s1   : in=1 out=1   -> allocation 1 B -> 5-byte OOB'
W '  B6  s0   : in=0 out=0   -> allocation 0 B (SystemBuffer possibly NULL) -> full 6-byte write; HIGHEST bugcheck risk'
W '  NEVER run out of ladder order; run SOLO; snapshot-restore is orchestrator-owned.'
W ''
W '--- escalation-value honesty note (pre-computed) ---'
W '  Overflow extent is at most 6 bytes past a <=5-byte non-paged pool allocation.'
W '  Overflow content: channelConfig dword (member of {0x107,0x33,0x3F,0x60F,0x63F,0xFF}) +'
W '  channels word (2..8) - semi-fixed small values. A 5-B request occupies a >=8-B pool'
W '  chunk, so spilled bytes land in chunk slack or the adjacent pool header. Adjacent-pool'
W '  corruption is possible but tiny and low-control; the finding may remain WRITE-MEDIUM'
W '  even if the overflow is empirically confirmed.'
W ''
W '--- t6 agent statement ---'
W '  Agent t6 did NOT execute any of gate/s5..s0 and will not. Phase B is orchestrator-gated.'

Marker 'phaseB-staging-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
