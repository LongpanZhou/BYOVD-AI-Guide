# t10_open_unpriv.ps1 - admin + restricted-token (runas /trustlevel:0x20000) open probes
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t10_work'
$log  = "$work\t10_open.txt"
$devs = "$work\t10_devices.txt"
function Log([string]$s) { [IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker([string]$m) { Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

[IO.File]::WriteAllText($log, ("=== t10_open_unpriv {0} ===`r`n" -f (Get-Date -Format o)))
Marker 'open-start'

# collect candidate names (NT paths from devices.txt + fallback grid)
$cands = New-Object System.Collections.Generic.List[string]
if (Test-Path $devs) {
  foreach ($p in [IO.File]::ReadAllLines($devs)) { if ($p.Trim().Length -gt 0) { $cands.Add($p.Trim()) } }
} else {
  foreach ($i in 0..3) {
    $cands.Add('\Device\Ide\iaStor' + $i)
    $cands.Add('\Device\ScsiPort' + $i)
    $cands.Add('\Device\Ide\IAAStorageDevice-' + $i)
  }
}

Log '--- admin opens (NT paths) ---'
foreach ($p in $cands) {
  & "$work\t10_poc.exe" $log ntopen $p 0xC0000000 2>&1 | Out-Null
  & "$work\t10_poc.exe" $log ntopen $p 0x12019F 2>&1 | Out-Null
  & "$work\t10_poc.exe" $log ntopen $p 0 2>&1 | Out-Null
}
Log '--- admin opens (\\.\ScsiN:) ---'
foreach ($i in 0..3) {
  & "$work\t10_poc.exe" $log open ('\\.\Scsi' + $i + ':') 0xC0000000 2>&1 | Out-Null
  & "$work\t10_poc.exe" $log open ('\\.\Scsi' + $i + ':') 0x12019F 2>&1 | Out-Null
}

Log '--- restricted-token probes (runas /trustlevel:0x20000) ---'
$restrOut = "$work\t10_restr.txt"
$restrDone = 0
foreach ($p in $cands) {
  if ($restrDone -ge 12) { Log '  (restricted probe cap reached, t7 loop-breaker)'; break }
  $restrDone++
  foreach ($c in @(
    "$work\t10_poc.exe $restrOut ntopen $p C0000000",
    "$work\t10_poc.exe $restrOut ntopen $p 12019F",
    "$work\t10_poc.exe $restrOut daclnt $p"
  )) {
    Log ('  runas: ' + $c)
    Remove-Item $restrOut -ErrorAction SilentlyContinue
    Start-Process -FilePath runas.exe -ArgumentList "/trustlevel:0x20000 `"$c`"" -Wait -WindowStyle Hidden
    if (Test-Path $restrOut) { Log (Get-Content $restrOut | Out-String).Trim() }
  }
}

Marker 'open-done'
exit 0
