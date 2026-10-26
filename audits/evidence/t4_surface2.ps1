# t4_surface2.ps1 (agent t4) - corrected kernel-object-directory probes
# (t4_surface.ps1's PocRun helper dropped the filter arg -> args[3] out of range).
# Read-only. Evidence: t4_surface2.txt
$log = 'C:\Users\vmdebug\Desktop\t4_work\t4_surface2.txt'
$work = 'C:\Users\vmdebug\Desktop\t4_work'
$exe = "$work\t4_poc.exe"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t4_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
function PocRun2([string[]]$pocArgs) {
  $tmp = "$work\t4_surface2_poc.txt"
  if (Test-Path $tmp) { Remove-Item $tmp -Force }
  & $exe $tmp @pocArgs 2>&1 | Out-Null
  if (Test-Path $tmp) { Get-Content $tmp | ForEach-Object { W ('  ' + $_) } }
}
W ("=== t4 surface2 (fixed object-dir probes) {0} ===" -f (Get-Date -Format o))
Marker 'surface2-start'
W '--- \Device filter Silabser ---'
PocRun2 @('qobj','\Device','Silabser')
W '--- \Device filter COM (context) ---'
PocRun2 @('qobj','\Device','COM')
W '--- \GLOBAL?? filter COM ---'
PocRun2 @('qobj','\GLOBAL??','COM')
W '--- \GLOBAL?? filter Silabser ---'
PocRun2 @('qobj','\GLOBAL??','Silabser')
W '--- ifenum bridge GUID (recheck) ---'
PocRun2 @('ifenum','{a2a39220-39f4-4b88-aecb-3d86a35dc748}')
Marker 'surface2-done'
[IO.File]::WriteAllText($log, $sb.ToString())
