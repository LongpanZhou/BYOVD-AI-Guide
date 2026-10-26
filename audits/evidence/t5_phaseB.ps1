# ============================================================================
# t5_phaseB.ps1 - DESTRUCTIVE PHASE B (staged by agent t5 during Phase A).
# NOT EXECUTED BY AGENT t5. Orchestrator-gated solo phase ONLY.
#
# Under test: vpnva64-6.sys IOCTL 0x22200A MDL->system-VA mapping + parked IRP
# (static audit vpnva.md sections 3.1 + 5.1). The audit explicitly documents the
# lifetime hole: "the parked IRP + stale mapping lifetimes are the usual race
# window" (cancel path FUN_1400038c0 -> FUN_140003320 vs receive-pump timer
# FUN_140005280 reading the mapped VA).
#
# PREREQUISITE: a working miniport instantiation. Phase A (vpnva.dynamic.md)
# could NOT instantiate the miniport in the test VM - NdisMAddDevice returned
# STATUS_UNSUCCESSFUL before the driver's own init code ever ran. B0 enforces
# this gate and aborts if the control device is not openable.
#
# Usage - ONE vmrun runProgramInGuest invocation PER STEP, then pull the
# per-step evidence file to the host IMMEDIATELY (evidence must survive a
# mid-sequence guest death / BSOD):
#   vmrun -T ws -gu vmdebug -gp 123456 runProgramInGuest <vmx> \
#     "C:\Windows\System32\cmd.exe" \
#     "/c powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\vmdebug\Desktop\t5_work\t5_phaseB.ps1 -Step B0 > C:\Users\vmdebug\Desktop\t5_work\t5_pw_phaseB.txt 2>&1"
#   ... then CopyFileFromGuestToHost t5_phaseB_B0.txt ... repeat for B1, B2, B3.
#
# Steps:
#   B0 (safe):  \.\VPNVA open RW + 0x22201C query + 0x222004 {8,8}; abort if any fails
#   B1 (race):  5x park 0x22200A -> pump 0x222027 -> immediate CancelIoEx -> reap
#               (stale-VA read window; bugcheck possible, vpnva64-6.sys expected in stack)
#   B2 (stale): park -> pump -> unpin/drop/GC + 64 MB pressure -> pump again -> cancel
#               (probes VA-after-page-lifetime)
#   B3 (soak):  30 rapid cycles (only if B1/B2 survivable)
# The C# helper pre-flushes every log line BEFORE the destructive call.
# After any step: do NOT reboot/power-cycle from agent scripts - orchestrator-only.
# ============================================================================
param([Parameter(Mandatory=$true)][ValidateSet('B0','B1','B2','B3')][string]$Step)

$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$ev   = Join-Path $work ("t5_phaseB_{0}.txt" -f $Step)
$exe  = Join-Path $work 't5_phaseB.exe'

function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }

Write-Output ("=== t5 PHASE B step {0}  {1} ===" -f $Step, (Get-Date -Format o))
Write-Output "DESTRUCTIVE phase - staged by agent t5; execution is orchestrator-gated"
Marker ("phaseB-" + $Step + "-start")

& $exe $ev $Step.ToLower() 2>&1 | Out-Null
$rc = $LASTEXITCODE
Write-Output ("  t5_phaseB.exe exit: " + $rc)

Start-Sleep -Seconds 3
Marker ("phaseB-" + $Step + "-done")
Write-Output ("STEP COMPLETE rc=" + $rc + " - pull " + $ev + " NOW (guest may be dead if the race bugchecked)")
