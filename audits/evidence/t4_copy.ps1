# t4_copy.ps1 (agent t4) - Phase A steps 2-3: copy driver, hash-verify, service create+start. Evidence: t4_load.txt
$log = 'C:\Users\vmdebug\Desktop\t4_work\t4_load.txt'
$work = 'C:\Users\vmdebug\Desktop\t4_work'
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t4_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

W ("=== t4 copy+load {0} ===" -f (Get-Date -Format o))
Marker 'load-start'

$src = "$work\silabser.sys"
$dst = 'C:\Windows\System32\drivers\silabser.sys'
$expected = '9393781CF3FD66C9EA21380EC8EC1AFFA6D84EB27C7EAEB14064BD90D32F27B2'

# existing silabser service? (adapt; do NOT overwrite)
$existing = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\silabser' -ErrorAction SilentlyContinue
if ($existing) {
  W "PRE-EXISTING 'silabser' service detected - adapting: using existing service, NOT overwriting its configuration"
  W ("  ImagePath: " + $existing.ImagePath + "  Start: " + $existing.Start)
  $svcName = 'silabser'
} else {
  $svcName = 't4_silabser'
  W "no pre-existing silabser service - using service name t4_silabser"
}
Set-Content -Path "$work\t4_svcname.txt" -Value $svcName

W "--- step 2: copy + hash ---"
if (Test-Path $src) {
  $h1 = (Get-FileHash $src -Algorithm SHA256).Hash
  W ("  guest src hash:  " + $h1)
  W ("  expected        : " + $expected)
  W ("  src match: " + ($h1 -eq $expected))
  Copy-Item -Force $src $dst
  $h2 = (Get-FileHash $dst -Algorithm SHA256).Hash
  W ("  dst  hash: " + $h2)
  W ("  copy match: " + ($h1 -eq $h2))
} else { W ("  FATAL: $src missing (push failed)") }

W "--- step 3: service ---"
if ($svcName -eq 't4_silabser') {
  W ("  sc create $svcName type= kernel start= demand binPath= $dst")
  sc.exe create $svcName type= kernel start= demand binPath= $dst 2>&1 | ForEach-Object { W ("    " + $_) }
} else { W ("  (create skipped - pre-existing service used as-is)") }
W ("  sc start $svcName")
sc.exe start $svcName 2>&1 | ForEach-Object { W ("    " + $_) }
Start-Sleep 2
W ("  sc query $svcName")
sc.exe query $svcName 2>&1 | ForEach-Object { W ("    " + $_) }
W "--- driverquery /v verify ---"
driverquery /v /fo csv 2>&1 | Select-String -Pattern 'silabser' | ForEach-Object { W ("    " + $_.Line) }
Marker 'load-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
