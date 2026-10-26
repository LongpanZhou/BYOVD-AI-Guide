# t8_sapi.ps1 — post-mortem of the failed devnode start: setupapi.dev.log tail + problem codes + events
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t8_work'
$out  = "$work\t8_sapi.txt"
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
"t8_sapi $(Get-Date -Format o)" | Out-File $out -Encoding ascii

Log "--- setupapi.dev.log tail 150 ---"
try { Get-Content 'C:\Windows\INF\setupapi.dev.log' -Tail 150 -ErrorAction Stop | ForEach-Object { Log ("  " + $_) } } catch { Log ("  read failed: " + $_.Exception.Message) }

Log "--- devnode problem details ---"
foreach ($dn in @('ROOT\AMDPSP\0000', 'ACPI\AMDPSP\0000')) {
  $p = Get-PnpDeviceProperty -InstanceId $dn -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue
  $s = Get-PnpDeviceProperty -InstanceId $dn -KeyName 'DEVPKEY_Device_ProblemStatus' -ErrorAction SilentlyContinue
  Log ("  $dn ProblemCode=" + $(if ($p) { $p.Data } else { '?' }) + " ProblemStatus=" + $(if ($s) { ('0x{0:X}' -f $s.Data) } else { '?' }))
}

Log "--- service state ---"
Log (sc.exe query t8_amdpsp 2>&1 | Out-String)

Log "--- event log System last 15 min (all, compact) ---"
try {
  $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddMinutes(-15) } -ErrorAction Stop | Select-Object -First 20
  foreach ($e in $ev) {
    Log ("  [{0}] id={1} src={2} lvl={3}" -f $e.TimeCreated.ToString('HH:mm:ss'), $e.Id, $e.ProviderName, $e.LevelDisplayName)
    $m = $e.Message -replace "`r`n", ' | '
    Log ("    " + $m.Substring(0, [Math]::Min(300, $m.Length)))
  }
} catch { Log ("  (no events: " + $_.Exception.Message + ")") }

"t8_sapi boundary $(Get-Date -Format o)" | Out-File "$work\t8_alive.txt" -Encoding ascii
exit 0
