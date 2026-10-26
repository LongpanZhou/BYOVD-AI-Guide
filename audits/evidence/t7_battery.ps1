# t7 phase A3: documented-code battery on VMCIDev (vmci) and vmci (vsock)
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t7_work\t7_battery.txt'
"t7_battery $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

$work = 'C:\Users\vmdebug\Desktop\t7_work'
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
Log "recompiling ..."
Log (& $csc /nologo /out:"$work\t7_poc.exe" /target:exe "$work\t7_poc.cs" 2>&1 | Out-String)
Log "compile exit=$LASTEXITCODE"

"t7_battery boundary $(Get-Date -Format o)" | Out-File "$work\t7_alive.txt" -Encoding ascii

Log "=== vmci device (\\.\VMCIDev) documented codes ==="
& "$work\t7_poc.exe" $out ioctl \\.\VMCIDev 81032004 0 40
& "$work\t7_poc.exe" $out ioctl \\.\VMCIDev 81032004 10 40
& "$work\t7_poc.exe" $out ioctl \\.\VMCIDev 81032008 10 40
& "$work\t7_poc.exe" $out ioctl \\.\VMCIDev 81032008 40 40
& "$work\t7_poc.exe" $out ioctl \\.\VMCIDev 81032018 10 40
& "$work\t7_poc.exe" $out ioctlsink \\.\VMCIDev 81032018 18 8 4
Log "=== vsock device (\\.\vmci) documented codes ==="
& "$work\t7_poc.exe" $out ioctlsink \\.\vmci 81032074 18 10 4
& "$work\t7_poc.exe" $out ioctlsink \\.\vmci 81032074 20 10 4
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032080 10 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032088 10 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 8103208c 10 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032094 10 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032098 10 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 8103209c 10 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 810320c0 10 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 810320c7 10 1000
Log "--- InLen==OutLen variants (common dispatch gate) ---"
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032080 1000 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032088 1000 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 8103208c 1000 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032094 1000 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032098 1000 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 8103209c 1000 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 810320c0 1000 1000
& "$work\t7_poc.exe" $out ioctl \\.\vmci 810320c7 1000 1000
Log "=== end t7_battery ==="
exit 0
