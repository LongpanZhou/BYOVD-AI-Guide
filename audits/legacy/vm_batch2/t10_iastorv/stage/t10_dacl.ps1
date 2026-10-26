# t10_dacl.ps1 - pull kernel object security for every discovered device object
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t10_work'
$log  = "$work\t10_dacl.txt"
$devs = "$work\t10_devices.txt"
function Log([string]$s) { [IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker([string]$m) { Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

[IO.File]::WriteAllText($log, ("=== t10_dacl {0} ===`r`n" -f (Get-Date -Format o)))
Marker 'dacl-start'

if (Test-Path $devs) {
  foreach ($p in [IO.File]::ReadAllLines($devs)) {
    if ($p.Trim().Length -gt 0) {
      Log ('--- device: ' + $p + ' ---')
      & "$work\t10_poc.exe" $log daclnt $p 2>&1 | Out-Null
    }
  }
} else {
  Log 't10_devices.txt missing - fixed candidate grid'
  foreach ($i in 0..5) {
    foreach ($p in @('\Device\Ide\iaStor' + $i, '\Device\ScsiPort' + $i, '\Device\Ide\IAAStorageDevice-' + $i)) {
      Log ('--- candidate: ' + $p + ' ---')
      & "$work\t10_poc.exe" $log daclnt $p 2>&1 | Out-Null
    }
  }
}

# also try the DOS-side names (\\.\ScsiN:) for the Scsi%d: symlinks
Log '--- win32-name probes (\\.\ScsiN:) ---'
foreach ($i in 0..3) {
  & "$work\t10_poc.exe" $log dacl ('\\.\Scsi' + $i + ':') 2>&1 | Out-Null
}

Marker 'dacl-done'
exit 0
