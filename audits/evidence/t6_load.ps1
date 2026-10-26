# t6_load.ps1 (agent t6) - Phase A steps 2-3: copy + hash + service. Evidence: t6_load.txt
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$log  = "$work\t6_load.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t6_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$expect = '20C53E79AE686FDCABCE253350345B7EF8E0B2EEB4C7B54C53DD9FD97F4C4F80'

W ("=== t6 load {0} ===" -f (Get-Date -Format o))
Marker 'load-start'

W "--- step 2: hash guest copy in t6_work ---"
$src = "$work\nvhda64v.sys"
try {
  $h1 = (Get-FileHash $src -Algorithm SHA256).Hash
  W ("  t6_work hash : " + $h1)
  W ("  expected     : " + $expect)
  W ("  MATCH        : " + ($h1 -eq $expect))
  if ($h1 -ne $expect) { W 'FATAL: hash mismatch in t6_work - ABORTING before any system copy'; [System.IO.File]::WriteAllText($log, $sb.ToString()); exit 1 }
}
catch { W ("hash ERROR: " + $_.Exception.Message); [System.IO.File]::WriteAllText($log, $sb.ToString()); exit 1 }

W "--- step 2b: copy to C:\Windows\System32\drivers + re-verify ---"
try {
  Copy-Item -Force $src 'C:\Windows\System32\drivers\nvhda64v.sys'
  $h2 = (Get-FileHash 'C:\Windows\System32\drivers\nvhda64v.sys' -Algorithm SHA256).Hash
  W ("  drivers hash : " + $h2)
  W ("  MATCH        : " + ($h2 -eq $expect))
  if ($h2 -ne $expect) { W 'FATAL: hash mismatch after copy'; [System.IO.File]::WriteAllText($log, $sb.ToString()); exit 1 }
  $f = Get-Item 'C:\Windows\System32\drivers\nvhda64v.sys'
  W ("  size         : " + $f.Length)
}
catch { W ("copy ERROR: " + $_.Exception.Message); [System.IO.File]::WriteAllText($log, $sb.ToString()); exit 1 }

W "--- step 3: sc create t6_nvhda ---"
$sc = & sc.exe create t6_nvhda type= kernel start= demand binPath= 'C:\Windows\System32\drivers\nvhda64v.sys' 2>&1
$sc | ForEach-Object { W ('  ' + $_) }

W "--- step 3b: sc start t6_nvhda ---"
$st = & sc.exe start t6_nvhda 2>&1
$st | ForEach-Object { W ('  ' + $_) }
Start-Sleep 3

W "--- step 3c: sc query t6_nvhda ---"
$q = & sc.exe query t6_nvhda 2>&1
$q | ForEach-Object { W ('  ' + $_) }

W "--- step 3d: driverquery verify ---"
try { $rows = driverquery /v /fo csv 2>&1 | Select-String -Pattern 't6_nvhda|nvhda'; if ($rows) { $rows | ForEach-Object { W ('  ' + $_.Line) } } else { W '(no nvhda rows after start!)' } }
catch { W ("driverquery ERROR: " + $_.Exception.Message) }

W "--- step 3e: System event log (last 10, service/driver entries) ---"
try { Get-WinEvent -LogName System -MaxEvents 10 -ErrorAction Stop | ForEach-Object { W ("  [{0}] id={1} prov={2} lvl={3}`n      {4}" -f $_.TimeCreated, $_.Id, $_.ProviderName, $_.Level, ($_.Message -replace '\r?\n',' | ')) } }
catch { W ("  event ERROR: " + $_.Exception.Message) }

Marker 'load-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
