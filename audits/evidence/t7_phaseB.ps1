# ============================================================================
# t7_phaseB — STAGED, NOT EXECUTED (2026-10-23, t7 fuzz agent)
# bxvbda.sys 0x80002024 beyond-BAR escalation ladder — ORCHESTRATOR-GATED, SOLO
# ============================================================================
# Preconditions (B0 gate — ALL must hold, else DO NOT RUN):
#   1. bxvbda.sys (SHA-256 FEB2771428706126FEA1CC9A50EBE3CF4F8E8FB6FCB3CA19996497CA44FDAC45)
#      loaded as kernel service (t7_bxv or b06bdrv) with a STARTED devnode whose
#      AddDevice completed (interface {2AF67184-48d3-4e8e-a3ff-969eff740ed2}
#      registered AND openable). In the t7 phase-A run this NEVER happened:
#      ROOT\T7BXV\0000 -> CM_PROB_FAILED_START (problem=10), no interface, no objects.
#   2. VM snapshot taken AFTER this file was staged (orchestrator restores on BSOD).
#   3. SOLO phase per standing protocol (pool-corruption-class test kills the VM).
#
# Ladder (each step: dispatch -> evidence pull -> aliveness marker -> orchestrator
# decision before next step; STOP on first unexpected status or guest unresponsiveness):
#
#   B1  0x80002050 (ctx-ptr leak, fixed-size getter): in=16 zeros, out=0x40
#       -> record kernel adapter-ctx pointer (BAR mapping base region hint).
#   B2  0x80002024 SAFE IN-WINDOW: in = {00 7f 00 00 | 01 00 00 00 | 00 00 00 00}
#       (offset 0x7F00 < 0x8000 window, count 1, data 0)
#       -> expect st=0 ret=0; device-register integrity unchanged (value 0 write
#          to an offset the sibling 0x8000201C kit considers legal).
#   B3  BEYOND-BAR single probes at increasing offsets, data=0, count=1 each:
#       B3a offset 0x00080000
#       B3b offset 0x00100000
#       B3c offset 0x00200000
#       B3d offset 0x00400000 + 0x100   (past the max BAR clamp)
#       Each probe = one DeviceIoControl call on the interface handle:
#         t7_poc.exe <out> ioctl <ifpath> 80002024 10 40 <inhex>
#         inhex = LE(offset) | 01 00 00 00 | 00 00 00 00
#       Expected failure mode per static audit: PAGE_FAULT_IN_NONPAGED_AREA
#       bugcheck naming bxvbda.sys at FUN_14000479c loop (ALL 3095-3119).
#       A bugcheck here is the CONFIRMATION EVIDENCE for the WRITE-HIGH verdict.
#
# Safety rules encoded in the ladder: count=1 (4-byte write), data=0, one probe
# per step, no multi-offset loops, evidence pulled between every step.
# ============================================================================
"t7_phaseB staged $(Get-Date -Format o) - NOT EXECUTED" | Out-File 'C:\Users\vmdebug\Desktop\t7_work\t7_phaseB_STAGED.txt' -Encoding ascii
exit 0
