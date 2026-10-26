# t9 cleanup: undo everything t9 installed (LWF via netcfg -u, adp devnode + package, t9_vboxsup service)
# Pre-existing guest services/files untouched. Risky removals are marked for orchestrator snapshot-restore.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_cleanup.txt"
"t9_cleanup $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

Log "--- step 1: find our driver-store packages ---"
$enum = & pnputil.exe /enum-drivers 2>&1 | Out-String
Log $enum
$targets = @()
foreach ($line in ($enum -split "`r?`n")) {
  if ($line -match '^Published Name\s*:\s*(oem\d+\.inf)') { $cur = $Matches[1] }
  if ($line -match '^Original Name\s*:\s*(VBoxNetAdp6\.inf|VBoxNetLwf\.inf|VBoxSup\.inf)') { $targets += ,@($cur, $Matches[1]) }
}
Log ("our packages: " + (($targets | ForEach-Object { $_[0] + '=' + $_[1] }) -join ', '))

Log "--- step 2: stop services FIRST (free files for the store delete) ---"
Log (& sc.exe stop VBoxNetAdp 2>&1 | Out-String)
Log (& sc.exe stop VBoxNetLwf 2>&1 | Out-String)
Log (& sc.exe stop t9_vboxsup 2>&1 | Out-String)
Start-Sleep -Seconds 2
Log (& sc.exe query VBoxNetAdp 2>&1 | Out-String)
Log (& sc.exe query VBoxNetLwf 2>&1 | Out-String)
Log (& sc.exe query t9_vboxsup 2>&1 | Out-String)

Log "--- step 3: netcfg -u VBoxNetLwf (component was never installed - documents the negative) ---"
Log (& netcfg.exe -u VBoxNetLwf 2>&1 | Out-String)
Log "netcfg -u exit=$LASTEXITCODE"
Log ("device object \Device\VBoxNetLwf gone check:")
Log (& "$work\t9_poc.exe" $out ntopen '\Device\VBoxNetLwf' 12019F 2>&1 | Out-String)

Log "--- step 4: adp devnode removal (only if t9-created) ---"
if ((Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\SUN_VBOXNETADP\0000') -and (Test-Path "$work\t9_adp_created.txt")) {
  Log (& pnputil.exe /remove-device 'ROOT\SUN_VBOXNETADP\0000' 2>&1 | Out-String)
  Log ("enum key still present after remove-device: " + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\SUN_VBOXNETADP\0000'))
  if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\SUN_VBOXNETADP\0000') {
    Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\SUN_VBOXNETADP\0000' -Recurse -Force -ErrorAction SilentlyContinue
    Log ("enum key after explicit delete: " + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\SUN_VBOXNETADP\0000'))
  }
} else {
  Log 'devnode not t9-created or already absent - SKIPPED (no removal attempted)'
}

Log "--- step 5: driver-store package deletion (files now free) ---"
foreach ($t in $targets) {
  if ($t[1] -eq 'VBoxSup.inf') { continue }
  Log ("pnputil /delete-driver " + $t[0] + " /uninstall:")
  Log (& pnputil.exe /delete-driver $t[0] /uninstall 2>&1 | Out-String)
  Log ("  exit=" + $LASTEXITCODE)
}

Log "--- step 6: delete t9-created services ---"
Log (& sc.exe delete t9_vboxsup 2>&1 | Out-String)
Log (& sc.exe delete VBoxNetAdp 2>&1 | Out-String)
Log (& sc.exe delete VBoxNetLwf 2>&1 | Out-String)
Start-Sleep -Seconds 1
Log ("post-check sc query t9_vboxsup (expect 1060):")
Log (& sc.exe query t9_vboxsup 2>&1 | Out-String)
Log ("post-check sc query VBoxNetAdp (expect 1060):")
Log (& sc.exe query VBoxNetAdp 2>&1 | Out-String)
Log ("post-check sc query VBoxNetLwf (expect 1060):")
Log (& sc.exe query VBoxNetLwf 2>&1 | Out-String)

Log "--- step 7: final verification ---"
Log (& "$work\t9_poc.exe" $out qobj '\Device' 'VBox|adp|lwf|sup' 2>&1 | Out-String)
Log (& driverquery.exe /v 2>&1 | Select-String -Pattern 't9_|VBox' | Out-String)
Log (& netcfg.exe /s t 2>&1 | Out-String)
Log ("guest files touched: t9_work only; drivers\VBoxSup.sys pre-existing=" + (Test-Path 'C:\Windows\System32\drivers\VBoxSup.sys') + " VBoxNetAdp6.sys=" + (Test-Path 'C:\Windows\System32\drivers\VBoxNetAdp6.sys') + " VBoxNetLwf.sys=" + (Test-Path 'C:\Windows\System32\drivers\VBoxNetLwf.sys'))
"t9_cleanup boundary $(Get-Date -Format o)" | Out-File "$work\t9_alive.txt" -Encoding ascii
exit 0
