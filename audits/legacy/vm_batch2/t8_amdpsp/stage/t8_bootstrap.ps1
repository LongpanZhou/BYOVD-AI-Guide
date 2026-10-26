# t8_bootstrap.ps1 ? work dir + aliveness marker + SHA-256 verify of pushed artifacts (roundtrip)
# run in guest: powershell.exe -NoProfile -ExecutionPolicy Bypass -File <work>\t8_bootstrap.ps1
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t8_work'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$out = "$work\t8_bootstrap.txt"
"t8_bootstrap $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

Log ("workdir: " + (Test-Path $work))
Log ("whoami: " + (whoami))

$expect = @{}
$expect['amdpsp.sys']  = '0A3AF18439B6BB4AF119C8020A3D0220ED6CC8AE04E20032F846E77777700A0A'
$expect['t8_poc.exe']  = 'E223879A27C80C153BEE8D750E2C15C0531BFBFF7160F48F31523ED4FB6C4D2D'
foreach ($k in @('amdpsp.sys', 't8_poc.exe', 't8_load.ps1', 't8_discover.ps1', 't8_battery.ps1', 't8_sweep.ps1', 't8_cleanup.ps1')) {
  $p = Join-Path $work $k
  if (Test-Path $p) {
    $h = (Get-FileHash $p -Algorithm SHA256).Hash
    Log ("present $k SHA256=" + $h + ($(if ($expect.ContainsKey($k)) { if ($h -eq $expect[$k]) { '  MATCH' } else { '  *** DRIFT ***' } } else { ' (no pinned hash; informational)' })))
  } else {
    Log ("MISSING $k")
  }
}

"t8_alive $(Get-Date -Format o)" | Out-File "$work\t8_alive.txt" -Encoding ascii
Log ("alive marker: " + (Test-Path "$work\t8_alive.txt"))
exit 0
