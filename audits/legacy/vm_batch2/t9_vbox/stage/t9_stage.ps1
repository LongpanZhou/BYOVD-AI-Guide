# t9 stage: verify pushed files in-guest (SHA-256) + demand-start VBoxSup via isolated service
# Run: powershell -NoProfile -ExecutionPolicy Bypass -File t9_stage.ps1
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_stage.txt"
"t9_stage $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

# expected hashes of pushed files (host-computed before push; drift is disclosed, never silently accepted)
$expect = @{
  'VBoxSup.sys'      = '73FA8B463EE9A95930D98DA3F9DD0637E63F06E8CD510BCAA285D91E4DCAE2C7'
  'VBoxNetAdp6.sys'  = '4E619BB6370F4BC4BE52F43D6C43F3A86E3E2CE7BB04BAADFF17D3B731F18F3F'
  'VBoxNetLwf.sys'   = 'CD3AF3B853C27626FCFC85997FEEAD0A48E56D618E2129F62FE1B96A203A44C7'
  'VBoxNetAdp6.inf'  = '68FCA318C6F63B1D46F3A75AD62AEDF1977D135411D82E850F09A6E6E7E8765D'
  'VBoxNetAdp6.cat'  = 'A27FFE3F719B5F87C694B273AF7E5796CF93A495CD195AFF25E44E24FECF8E1B'
  'VBoxNetLwf.inf'   = 'DBCC2C6F3DC2A68EABC698D2D7D94837E9F79711DD13B414299E20C00C016779'
  'VBoxNetLwf.cat'   = 'E308CFC6EDF3B6E969A115EEB111D0FEFE0BE93E00856AB1280459DD83A9F93F'
  'VBoxSup.inf'      = 'B24D35B010526A896DDD4108F10E235054593D79F5939A2D484DA12517D351A0'
  'VBoxSup.cat'      = 'DD54BDD004785DC8E0B0824F49B6EC0665AC0D4623162C3D9DD636EC11DD3A25'
}
$drift = 0
Log '--- SHA-256 verification of pushed files ---'
foreach ($k in $expect.Keys) {
  $p = Join-Path $work $k
  if (-not (Test-Path $p)) { Log "MISSING $k"; $drift = $drift + 1; continue }
  $h = (Get-FileHash $p -Algorithm SHA256).Hash
  if ($h -eq $expect[$k]) { Log "OK $k" }
  else { Log "DRIFT $k got=$h want=$($expect[$k])"; $drift = $drift + 1 }
}
Log "drift count = $drift (0 required to proceed; nonzero means DISCLOSED drift)"

# pre-existing collision check (rule: never overwrite pre-existing guest files)
Log '--- pre-existing file check ---'
Log ("drivers\VBoxSup.sys exists: " + (Test-Path 'C:\Windows\System32\drivers\VBoxSup.sys'))
Log ("drivers\VBoxNetAdp6.sys exists: " + (Test-Path 'C:\Windows\System32\drivers\VBoxNetAdp6.sys'))
Log ("drivers\VBoxNetLwf.sys exists: " + (Test-Path 'C:\Windows\System32\drivers\VBoxNetLwf.sys'))

# VBoxSup demand-start (isolated t9 namespace; proven t7 recipe)
Log '--- sc create t9_vboxsup ---'
Log (& sc.exe create t9_vboxsup type= kernel start= demand binPath= "$work\VBoxSup.sys" 2>&1 | Out-String)
Log '--- sc start t9_vboxsup ---'
Log (& sc.exe start t9_vboxsup 2>&1 | Out-String)
Log '--- sc query t9_vboxsup ---'
Log (& sc.exe query t9_vboxsup 2>&1 | Out-String)
Log '--- sc qc t9_vboxsup ---'
Log (& sc.exe qc t9_vboxsup 2>&1 | Out-String)
Log '--- driverquery filter VBoxSup ---'
Log (& driverquery.exe /v 2>&1 | Select-String -Pattern 'VBoxSup' | Out-String)
"t9_stage boundary $(Get-Date -Format o)" | Out-File "$work\t9_alive.txt" -Encoding ascii
exit 0
