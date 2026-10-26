# t9_sup_names.ps1 - name-based device surface check for the four VBoxSup devices
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_sup_names.txt"
"t9_sup_names $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
foreach ($d in @('\Device\VBoxDrv', '\Device\VBoxDrvU', '\Device\VBoxDrvStub', '\Device\VBoxDrvErrorInfo')) {
  Log (& "$work\t9_poc.exe" $out ntopen $d 12019F 2>&1 | Out-String)
  Log (& "$work\t9_poc.exe" $out daclnt $d 2>&1 | Out-String)
}
"t9_sup_names boundary $(Get-Date -Format o)" | Out-File "$work\t9_alive.txt" -Encoding ascii
exit 0
