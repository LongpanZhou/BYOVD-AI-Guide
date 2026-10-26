# t7 phase E2: bxvbda AddDevice failure forensics + nvhda64v in-guest object probe + phaseB staging
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t7_work\t7_bxv2.txt'
"t7_bxv2 $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
$work = 'C:\Users\vmdebug\Desktop\t7_work'

Log "=== setupapi.dev.log tail for T7BXV (search) ==="
$sapi = 'C:\Windows\INF\setupapi.dev.log'
if (Test-Path $sapi) {
  $lines = Get-Content $sapi
  $hits = @(); for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'T7BXV|t7_bxv|bxvbda') { $hits += $i } }
  if ($hits.Count -eq 0) { Log "  no T7BXV/t7_bxv/bxvbda mentions in setupapi.dev.log" }
  foreach ($h in $hits) {
    $from = [Math]::Max(0, $h - 3); $to = [Math]::Min($lines.Count - 1, $h + 25)
    Log ("--- context around line $h ---")
    Log (($lines[$from..$to] | Out-String))
  }
} else { Log "  setupapi.dev.log absent" }

Log "=== System event log: t7_bxv / driver-load events (last hour) ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 't7_bxv|bxvbda|T7BXV' } | Select-Object -First 10 |
  ForEach-Object { Log ("evt {0} id={1} src={2}: {3}" -f $_.TimeCreated, $_.Id, $_.ProviderName, ($_.Message -replace "`r`n", ' | ')) }

Log "=== service state now ==="
Log (sc.exe query t7_bxv 2>&1 | Out-String)

Log "=== qobj \Device for any t7/bxv/qlogic objects ==="
& "$work\t7_poc.exe" $out qobj '\Device' 't7|bxv|qlogic|b06'

Log "=== TARGET 4: nvhda64v in-guest probe ==="
Log "--- driverquery nvhda ---"
$dq = driverquery.exe /v /FO CSV 2>&1
foreach ($l in $dq) { if ($l -match 'nvhda|nvvhci|nvvad') { Log $l } }
Log "--- service keys ---"
foreach ($svc in 'nvhda64v','NVHDA','nvvad64v','nvvhci') {
  $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
  if (Test-Path $k) { $p = Get-ItemProperty $k; Log ("{0}: Start={1} ImagePath={2}" -f $svc, $p.Start, $p.ImagePath) } else { Log "$svc : key ABSENT" }
}
Log "--- qobj \Device audio/nv objects ---"
& "$work\t7_poc.exe" $out qobj '\Device' 'audio|nv'
Log "--- \GLOBAL?? audio/nv symlinks ---"
& "$work\t7_poc.exe" $out qobj '\GLOBAL??' 'audio|nv'

Log "=== end t7_bxv2 ==="
exit 0
