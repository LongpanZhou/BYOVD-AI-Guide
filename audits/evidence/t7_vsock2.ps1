# t7 phase F: corrected well-formed vsock probes (exact lengths from guest-binary static resolve)
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t7_work\t7_vsock2.txt'
"t7_vsock2 $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
$work = 'C:\Users\vmdebug\Desktop\t7_work'
"t7_vsock2 boundary $(Get-Date -Format o)" | Out-File "$work\t7_alive.txt" -Encoding ascii

Log "=== FsContext-free getters (in=out=4, exact per static) ==="
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032058 4 4
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032068 4 4
& "$work\t7_poc.exe" $out ioctl \\.\vmci 8103206c 4 4
Log "=== 0x81032074 prop-write: exact in=out=0x2C, sink at +0x10 (attempt 3/3) ==="
& "$work\t7_poc.exe" $out ioctlsink \\.\vmci 81032074 2c 10 4 2c
Log "=== 0x8103207C buffer-setup shape: in=out=0x48, sink at +0x10 ==="
& "$work\t7_poc.exe" $out ioctlsink \\.\vmci 8103207c 48 10 4 48
Log "=== 0x81032098: in=out=0x2C, sink at +0x10 ==="
& "$work\t7_poc.exe" $out ioctlsink \\.\vmci 81032098 2c 10 4 2c
Log "=== 0x8103209C: in=out=0xC ==="
& "$work\t7_poc.exe" $out ioctl \\.\vmci 8103209c c c
Log "=== 0x81032080: in=out=0xC ==="
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032080 c c
Log "=== 0x81032088/94: in=out=0x38 ==="
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032088 38 38
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032094 38 38
Log "=== 0x81032064/70: in=out=0x1C ==="
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032064 1c 1c
& "$work\t7_poc.exe" $out ioctl \\.\vmci 81032070 1c 1c
Log "=== 0x8103205C: in=out=0x20 ==="
& "$work\t7_poc.exe" $out ioctl \\.\vmci 8103205c 20 20
Log "=== 0x810320C7: in=out=0 ==="
& "$work\t7_poc.exe" $out ioctl \\.\vmci 810320c7 0 0
Log "=== 0x8103208C (registration, in=out=0x624): NOT SENT (0x624 struct unknown; staged) ==="
Log "=== end t7_vsock2 ==="
exit 0
