# t10_probe.ps1 - open-based existence probes (no qobj)
$ErrorActionPreference = 'Continue'
$w = 'C:\Users\vmdebug\Desktop\t10_work'
$log = "$w\t10_probe.txt"
[IO.File]::WriteAllText($log, ("=== t10_probe {0} ===`r`n" -f (Get-Date -Format o)))
$p = "$w\t10_poc.exe"
& $p $log openlink '\??\Scsi0:'
& $p $log openlink '\??\Scsi1:'
& $p $log ntopen '\Device\Ide\iaStor0' 0
& $p $log ntopen '\Device\Ide\iaStor1' 0
& $p $log ntopen '\Device\ScsiPort4' 0
& $p $log ntopen '\Device\Ide\IAAStorageDevice-0' 0
& $p $log ntopen '\Device\ScsiPort0' 0
Add-Content -Path "$w\t10_alive.txt" -Value ("alive {0} probe-done" -f (Get-Date -Format o))
exit 0
