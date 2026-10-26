# t6_inf.ps1 (agent t6) - setupapi.dev.log sections mentioning T6NVHDA + recent System events
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$log  = "$work\t6_inf.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t6_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

W ("=== t6 inf {0} ===" -f (Get-Date -Format o))
Marker 'inf-start'

W '--- setupapi.dev.log: sections mentioning T6NVHDA (context 3 lines each) ---'
try {
  $log = 'C:\Windows\INF\setupapi.dev.log'
  Select-String -Path $log -Pattern 'T6NVHDA' -Context 3,3 -ErrorAction Stop | Select-Object -First 40 | ForEach-Object {
    foreach ($l in @($_.Context.PreContext) + @($_.Line) + @($_.Context.PostContext)) { W ('  ' + $l) }
    W '  ---'
  }
  if (-not (Select-String -Path $log -Pattern 'T6NVHDA' -ErrorAction Stop)) { W '  (no T6NVHDA mentions in setupapi.dev.log)' }
} catch { W ("  setupapi.dev.log ERROR: " + $_.Exception.Message) }

W '--- System event log: entries mentioning t6_nvhda (last 24h) ---'
try {
  $ev = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-24)} -ErrorAction Stop | Where-Object { $_.Message -match 't6_nvhda|nvhda' }
  if ($ev) { $ev | ForEach-Object { W ("  [{0}] id={1} prov={2} lvl={3}`n      {4}" -f $_.TimeCreated, $_.Id, $_.ProviderName, $_.Level, ($_.Message -replace '\r?\n',' | ')) } }
  else { W '  (none)' }
} catch { W ("  event ERROR: " + $_.Exception.Message) }

W '--- Kernel-PnP/Configuration: entries mentioning T6NVHDA ---'
try {
  $ev = Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -ErrorAction Stop | Where-Object { $_.Message -match 'T6NVHDA' } | Select-Object -First 20
  if ($ev) { $ev | ForEach-Object { W ("  [{0}] id={1} lvl={2}`n      {3}" -f $_.TimeCreated, $_.Id, $_.Level, ($_.Message -replace '\r?\n',' | ')) } }
  else { W '  (none)' }
} catch { W ("  ERROR: " + $_.Exception.Message) }

Marker 'inf-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
