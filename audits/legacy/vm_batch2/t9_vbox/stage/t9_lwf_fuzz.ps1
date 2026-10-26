# t9 lwf_fuzz: DACL pull + unpriv open + structured fn-code sweep on \Device\VBoxNetLwf
# Expectation (static): dispatch returns 0xC00000BB for every DEVICE_CONTROL code.
# Sweep forms (per mission): code = CTL_CODE(dev 0x12, fn, method 0, access 0) = 0x120000 + fn*4
# plus raw band 0x00000000 + fn*4. All inputs <= 64 B, outputs <= 0x1000.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_lwf_fuzz.txt"
"t9_lwf_fuzz $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

$dev = '\Device\VBoxNetLwf'
$devw = '\\.\VBoxNetLwf'

Log "--- step 1: DACL pulls ---"
Log (& "$work\t9_poc.exe" $out daclnt $dev 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out dacl $devw 2>&1 | Out-String)

Log "--- step 2: admin opens (RW / R / zero-access) ---"
Log (& "$work\t9_poc.exe" $out open $devw 12019F 3 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out open $devw 120089 3 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out open $devw 0 3 2>&1 | Out-String)

Log "--- step 3: restricted-token open + dacl (runas /trustlevel:0x20000) ---"
$restrOut = "$work\t9_lwf_restr.txt"
Remove-Item $restrOut -ErrorAction SilentlyContinue
$cmds = @(
  "$work\t9_poc.exe $restrOut open $devw 12019F 3",
  "$work\t9_poc.exe $restrOut open $devw 120089 3",
  "$work\t9_poc.exe $restrOut open $devw 0 3",
  "$work\t9_poc.exe $restrOut dacl $devw"
)
foreach ($c2 in $cmds) {
  Log "runas: $c2"
  Start-Process -FilePath "$env:SystemRoot\System32\runas.exe" -ArgumentList "/trustlevel:0x20000 `"$c2`"" -Wait
  if (Test-Path $restrOut) { Log (Get-Content $restrOut | Out-String); Remove-Item $restrOut -ErrorAction SilentlyContinue }
  else { Log "  (no output file produced)" }
}

Log "--- step 4: single documented probes (fn 0x000 and 0x001, dev 0x12) ---"
Log (& "$work\t9_poc.exe" $out ioctl $devw 120000 16 1000 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out ioctl $devw 120004 16 1000 2>&1 | Out-String)

Log "--- step 5: structured sweep dev 0x12, fn 0x000..0xFFF, 8 chunks ---"
foreach ($start in @(0, 512, 1024, 1536, 2048, 2560, 3072, 3584)) {
  $end = $start + 511
  Log ("chunk fn 0x{0:X3}..0x{1:X3} start" -f $start, $end)
  & "$work\t9_poc.exe" $out sweep $devw 12 $start $end 16 1000
  Log ("chunk done, poc exit=" + $LASTEXITCODE)
}

Log "--- step 6: raw band sweep (code = fn*4, device 0), fn 0x000..0x3FF in 2 chunks ---"
foreach ($start in @(0, 512)) {
  $end = $start + 511
  Log ("raw chunk fn 0x{0:X3}..0x{1:X3} start" -f $start, $end)
  & "$work\t9_poc.exe" $out rsweep $devw 0 $start $end 16 1000
  Log ("raw chunk done, poc exit=" + $LASTEXITCODE)
}

Log "--- step 7: documented extra: dev 0x22 (FILE_DEVICE_UNKNOWN) spot probes, fn 0x000..0x00F ---"
Log (& "$work\t9_poc.exe" $out sweep $devw 22 0 15 16 1000 2>&1 | Out-String)

"t9_lwf_fuzz boundary $(Get-Date -Format o)" | Out-File "$work\t9_alive.txt" -Encoding ascii
exit 0
