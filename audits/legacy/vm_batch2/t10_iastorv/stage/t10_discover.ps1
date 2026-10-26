# t10_discover.ps1 - inventory device objects/symlinks created by iaStorV; setupapi.dev.log tail
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t10_work'
$log  = "$work\t10_discover.txt"
$devs = "$work\t10_devices.txt"
function Log([string]$s) { [IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker([string]$m) { Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

[IO.File]::WriteAllText($log, ("=== t10_discover {0} ===`r`n" -f (Get-Date -Format o)))
Marker 'discover-start'

Log '--- qobj \Device (filter iaStor|ScsiPort|IAAStorage|Ide|t10) ---'
& "$work\t10_poc.exe" $log qobj '\Device' 'iaStor|ScsiPort|IAAStorage|Ide|t10' 2>&1 | Out-Null
Log ('  poc exit=' + $LASTEXITCODE)

Log '--- qobj \Device\Ide (full) ---'
& "$work\t10_poc.exe" $log qobj '\Device\Ide' '.' 2>&1 | Out-Null

Log '--- qobj \DosDevices (filter iaStor|Scsi|IAA|t10) ---'
& "$work\t10_poc.exe" $log qobj '\DosDevices' 'iaStor|Scsi|IAA|t10' 2>&1 | Out-Null

Log '--- build t10_devices.txt (NT device names) from the scans ---'
[IO.File]::WriteAllText($devs, '')
$found = 0
foreach ($line in [IO.File]::ReadAllLines($log)) {
  # poc entry lines: "\Device\Ide -> iaStor0 [Device]"
  if ($line -match '^\\Device\\.*-> ' -and $line -match 'iaStor|ScsiPort|IAAStorage|Ide') {
    $name = $line.Substring(0, $line.IndexOf(' -> ')).Trim()
    $leaf = $line.Substring($line.IndexOf(' -> ') + 4)
    $leaf = $leaf.Substring(0, $leaf.IndexOf(' [')).Trim()
    [IO.File]::AppendAllText($devs, ($name + '\' + $leaf + "`r`n"))
    $found++
  }
  # poc RAWSTR lines: "qobj \Device\Ide -> RAWSTR 'iaStor0'"
  if ($line -match "^qobj (\\\\Device(?:\\\\Ide)?) -> RAWSTR '([^']+)'$") {
    $dir2 = $Matches[1]; $nm = $Matches[2]
    if ($nm -match 'iaStor|ScsiPort|IAAStorage') {
      [IO.File]::AppendAllText($devs, ($dir2 + '\' + $nm + "`r`n"))
      $found++
    }
  }
}
Log ('  recorded ' + $found + ' device object(s) to t10_devices.txt')

Log '--- setupapi.dev.log tail (last 150 lines, ASCII-folded) ---'
$sd = 'C:\Windows\INF\setupapi.dev.log'
if (Test-Path $sd) {
  $tail = [IO.File]::ReadAllLines($sd)
  $n = [Math]::Min(150, $tail.Length)
  $k = 0
  foreach ($l in $tail[($tail.Length - $n)..($tail.Length - 1)]) {
    $k++
    Log ('  ' + ($l -replace '[^\x20-\x7E]', '?'))
    if ($k -ge $n) { break }
  }
} else { Log '  setupapi.dev.log not found' }

Marker 'discover-done'
exit 0
