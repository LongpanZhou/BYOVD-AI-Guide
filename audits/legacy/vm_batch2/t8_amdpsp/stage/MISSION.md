# MISSION.md - t8 amdpsp.sys dynamic phase (Phase 2 runbook)

Target: amdpsp.sys (AMD Platform Security Processor driver, KMDF), project copy
`C:\Users\<scrubbed>\Desktop\driver_candidates\amdpsp.sys`
SHA-256 `0A3AF18439B6BB4AF119C8020A3D0220ED6CC8AE04E20032F846E77777700A0A`
Static audit: `audits\amdpsp.md` (WRITE-HIGH candidate, provisional). This run: VM confirmation.
NEVER execute Phase B (staged) items. Orchestrator owns VM power/snapshots (`pre-driver-tests`).

## Static ground truth (Phase 1 Ghidra assist, base 0x140000000)

- Device name `\Device\amdpsp` (VA 0x1400091f0); symlink `\DosDevices\amdpsp` created for instance 0
  only (FUN_14001d1e0 @ 0x14001d1e0). Win-path open target: `\\.\amdpsp`.
- **SDDL IS applied**: `RtlInitUnicodeString(0x140009210)` then WDF table call
  `(*DAT_14001a3e0)(WdfGlobals, deviceInit, &sddl)` = WdfDeviceInitAssignSDDLString, before
  `(*DAT_14001a418)` = WdfDeviceCreate(&init, attrs(0x38), &dev). String grants
  `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)` - Everyone RWX.
- Device interface GUID (WdfDeviceCreateDeviceInterface via DAT_14001a428, GUID at 0x1400091e0):
  `{D41D854A-3877-4471-A889-B0D551B1125B}`.
- **Allocator has NO size cap**: FUN_140002b50/FUN_140002c30 = MmAllocateContiguousMemorySpecifyCache
  (uint size, 0, 0xFFFFFFFFF, boundary 0x4000000, cached/noncached). Only guard: size != 0.
- 0x9c422002 (FUN_140003020): in EXACTLY 8 B, out EXACTLY 0x38. Output: err@+0, **userVA@+8**
  (MmMapLockedPagesSpecifyCache UserMode). PA is computed internally but NOT propagated in this
  path (audit drift; see below). Slot table: 100 slots x 32 B @ ctx+0x1280
  (kernelVA@+0, flag@+0x10, userVA@+0x18, size@+0x28 per slot i).
- 0x9c422003 (FUN_140003810): in EXACTLY 8 B = **user VA to free** (matches slot userVA field);
  free = MmFreeContiguousMemory. Unknown VA -> scan-miss -> 0xC000000D; VA=0 -> immediate 0xC000000D.
  Cross-process free-by-VA / double-free = STAGED ONLY (destructive pool ops).
- 0x9c422004 (register+enable): in EXACTLY 8 B, dword0 = slot index 1..16 (16-slot table @ ctx+0x94,
  stride 0x120). On success: PoFxActivateComponent + busy-wait + FUN_140005980(ctx, slot, 1) enable.
  0x9c422005 = register only. Slot 0 / >16 -> 0xC0000008.
- 0x9c422000 (in 0x18: dword@4=len, qword@0x10=ptr), 0x9c422006 (in 0x10: dword@4=len, qword@8=ptr),
  0x9c422007 (in 0x38: qword@0x30=ptr, len fixed 0x40), 0x9c422008 (in 0x20: dword@8=len, qword@0x18=ptr),
  0x9c422009 (in 0x10: qword@0=ptr, dword@8=len), 0x9c422808 (in 0x10: dword@0=len, qword@8=ptr),
  0x9c422834 (in 0x20: dword@0x10=len, qword@0x18=ptr):
  all = probe-capture family (DAT_14001aa70/aa78 = WdfRequestProbeAndCaptureUserPointerForRead/Write)
  + WdfMemoryGetBuffer -> **writes the kernel VA of the captured buffer back into the caller's input
  struct** (buffered copy-back). User-VA pointers are probed = safe; only pass committed user VAs or zeros.
- 0x9c422820 (FUN_140006920): in EXACTLY **0x168**, out EXACTLY **0x158** (NOT a 0x28-B header -
  drift vs dispatch table). Size field @ input+0x158 (uint). Outputs: PA high @ input+0x160, PA low @
  input+0x164 (input copy-back), user VA @ output+0x18. 10-slot table (ctx+0x70 area, stride 40 B).
  Non-cached contiguous alloc + UserMode map. Same primitive family as 0x9c422002 + PA disclosure.
- 0x9c422804/80C/810/814/818/828/830/838/83C/844: accepted no-ops (success, no buffer touch).
- Any code > 0x9c422800 -> FUN_1400026a0 band; codes below -> low switch (default 0xC0000010);
  0x9c422001 and == 0x9c422800 -> 0xC000000D/0xC0000010.
- PSP mailbox architecture: FUN_140003dc0 (TEE-log init) programs a **contiguous alloc's physical
  address into MMIO registers 0x48/0x4C** (FUN_140002eb0) and polls 0x44 (FUN_140002e50) - the PSP
  consumes kernel queues by physical address. Driver-side strings: "Wrong queue indexes from register,
  OutQueueWrtPtr = %08x, OutQueueRdPtr = %08x", "Tee interrupt call back function", "TeeLogPollingWorker".
  FUN_140005980 is only a per-slot enable toggle (writes slot+0x9c); FUN_140002e20 is only
  MmFreeContiguousMemory. The kernel-side write consumer of the 100-slot user-mapped table remains
  UNTRACED (time-boxed; dynamic wrtest evidence stands in).

## Hard rules for the guest (from project protocol)

- All guest commands via `powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script>`.
  cmd.exe is broken in-guest. Scripts are ASCII-only (PS 5.1 codepage hazard).
- vmrun (host): `C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe`; VMX:
  `C:\Users\<scrubbed>\Downloads\Vmware\Windows 10 x64.vmx`; `-gu vmdebug -gp 123456`.
- runProgramInGuest blocks until exit. Use CopyFileFromHostToGuest / CopyFileFromGuestToHost /
  fileExistsInGuest / listProcessesInGuest.
- Wedge rule: any step > 2 min without log growth -> listProcessesInGuest -> elevated
  `taskkill /F /IM <proc>`; mark BLOCKED; continue.
- Loop-breaker: max 3 attempts per tool/technique -> mark BLOCKED, commit partial.
- SHA-256 verify every pushed file in-guest (t8_bootstrap.ps1, pinned hashes embedded).
- NEVER overwrite pre-existing guest files. If a name exists in t8_work, use a `_b` variant and
  adjust the invoking path (for amdpsp.sys also adjust the service binPath).
- Buffers: input <= 64 B (0x168-shaped 0x9c422820 header excepted), output <= 0x1000.
  Allocation ladder hard cap 0x40000. No oversized-input probes, no beyond-window writes,
  no pool-corruption attempts (free-by-foreign-VA and double-free are STAGED).
- Pull all evidence to `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\dynamic_evidence\`
  with `t8_` prefix. Deliverables: `audits\amdpsp.dynamic.md` + `t8_*` evidence + this stage dir.
- Do not touch vgk.sys / NvModuleTracker.sys / other agents' work dirs. No subagents.

## Phase 2 runbook (execute ONLY when continued with orchestrator authorization)

vmrun base: `& 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' -T ws -gu vmdebug -gp 123456 ...`

### Step 1 - Push + aliveness + SHA verify
1. `vmrun list` -> VM must be RUNNING. If not running: STOP -> request orchestrator boot. (ABORT A0)
2. `CreateDirectoryInGuest` `C:\Users\vmdebug\Desktop\t8_work` (harmless if exists).
3. For each of the 8 staged files: `fileExistsInGuest` first. Copy `t8_bootstrap.ps1`,
   `t8_load.ps1`, `t8_discover.ps1`, `t8_battery.ps1`, `t8_sweep.ps1`, `t8_cleanup.ps1`,
   `t8_poc.exe`, `amdpsp.sys` (skip+rename `_b` if a same-named file pre-exists).
4. `runProgramInGuest` `powershell.exe` args `-NoProfile -ExecutionPolicy Bypass -File C:\Users\vmdebug\Desktop\t8_work\t8_bootstrap.ps1`.
5. `CopyFileFromGuestToHost` t8_bootstrap.txt + t8_alive.txt -> dynamic_evidence as
   `t8_bootstrap.txt` / `t8_alive.txt`.
- Expected: all SHA MATCH (amdpsp.sys = 0A3AF1..., t8_poc.exe = E22387...). Any DRIFT -> disclose,
  do not proceed with that artifact. (ABORT A0b on amdpsp.sys drift)

### Step 2 - Load (expected: may FAIL START - that is a valid finding)
- `runProgramInGuest` powershell `-File ...\t8_load.ps1`; pull `t8_load.txt` as `t8_load.txt`.
- Expected outcome A (no AMD PSP hardware in the VMware guest): service start fails -
  record exact SCM exit code + System event 7000/7026 message verbatim. Then run cleanup
  (Step 8) and report: "amdpsp.sys does not start in a VMware guest" = negative gate finding.
- Expected outcome B: RUNNING -> discovery. If query shows STOPPED after start with no error text,
  re-run `sc.exe query` once, then continue to discovery anyway (driver may be loaded w/o service state).
- (ABORT A1: any BSOD/wedge during load -> mark, do NOT retry, report; orchestrator owns recovery.)

### Step 3 - Discovery
- `runProgramInGuest` `-File ...\t8_discover.ps1`; pull `t8_discover.txt` -> `t8_discover.txt`.
- Expected: `\Device` qobj lists `amdpsp` entries; `\\.\amdpsp` opens OK; DACL line printed
  (RESOLVES the Everyone-SDDL question on the live object).
- (ABORT A2: no device object anywhere -> cleanup + report "loads but exposes no object".)

### Step 4 - Documented batteries
- `runProgramInGuest` `-File ...\t8_battery.ps1`; pull `t8_battery.txt` (+ any `t8_restr.txt`
  content is already inlined into the battery log by the script).
- Expected:
  - Ladder (0x9c422002 sizes 0x10..0x40000): st=0, `VA-CANDIDATE` printed with `USER-MAP WRITABLE=True`
    (4-byte write + readback + restore at the returned user VA). PA field in output expected ZERO
    (drift). If 0x40000 fails, record exact status - ladder position = cap evidence.
  - Free probes: zeros -> 0xC000000D; bogus VA -> 0xC000000D; ladder-alloc + `free` -> expect st=0.
  - Register family: statuses per table above (slot 1 register/enable attempts; 0xC0000008 for 0/17).
  - Shaped probe-capture: `probe` lines - watch `struct-after` for a KERNEL VA (0xFFFFF...) written
    back into the input struct (kernel-address disclosure finding) and `sink ... DRIVER WROTE` markers.
  - Restricted-token section: the LOAD-BEARING verdict test - if restricted `open` succeeds and the
    restricted `wrtest` shows `USER-MAP WRITABLE=True`, the WRITE-HIGH candidate is CONFIRMED
    (unpriv user maps kernel-owned contiguous memory RW). If open is denied, capture the DACL
    mismatch (SDDL applied but object DACL differs) -> verdict drops to WRITE-MEDIUM.
- (ABORT A3: wedge > 2 min -> kill + mark; BSOD -> stop, report, orchestrator recovers.)

### Step 5 - Bounded sweeps (12 chunks total, one runProgramInGuest each)
- Chunks A0..A5 (band 0x9c422000-0x9c42200C, in {0,16} x out {0,0x38,0x1000}), then B (variants),
  then C0..C5 (band 0x9c422800-0x9c42283F, 3 header variants x 2 halves, out 0x1000).
- Each: `runProgramInGuest` powershell `-File ...\t8_sweep.ps1 -mode <M> -chunk <n>`.
- Expected: exact-length gates (0x28-B inputs on band C -> uniform 0xC000000D except the
  accepted no-op codes 804/80C/810/814/818/828/830/838/83C/844 which return SUCCESS with
  in=0x28? NO - the no-ops accept ANY length: they never retrieve input. Watch for st=0 lines
  at those codes); low-band default 0xC0000010; variants: method/access bit swaps mostly
  length-gate or invalid-param. Any unexpected st=0 with attacker-influenced output -> flag
  in report (bounded, do not chase).
- Pull `t8_sweep.txt` once after all chunks.

### Step 6 - kd read-only verification (optional, <= 3 attempts)
- Attach via the t5 kd-over-serial plumbing (see audits\dynamic_evidence\t5_kdrestart.ps1 +
  t5 reports). Read-only goals:
  1. `!object \Device\amdpsp` (+ DACL view) - cross-check Step 3.
  2. After a ladder alloc WITHOUT free (rerun one wrtest with no `free` arg, size 0x1000):
     compare `MmGetPhysicalAddress` view - `!pte` / physical read at the returned PA vs the
     user VA bytes (`db <userVA> L20` inside the guest context of the test process via
     `.process /p`). Record whether the physical page backs the user mapping.
- 3 attempts max -> BLOCKED. This step is OPTIONAL; do not wedge the run for it.

### Step 7 - STAGED Phase B (NEVER EXECUTED BY t8)
- PSP-mailbox submit escalation: write into the mapped view + trigger submission
  (0x9c422004 enable -> PSP consumes by PA).
- Allocations > 0x40000 (ladder above hard cap).
- Free-by-foreign-VA / double-free (0x9c422003 cross-slot UAF chain).
- 0x9c422824-shaped 0x170 leak probe + band codes beyond 0x9c42283F.
- Marker: `stage\t8_phaseB_STAGED.txt` (already written). Escalations belong to the orchestrator's
  solo phase only. Describe, never run.

### Step 8 - Cleanup + evidence pull + report
1. `runProgramInGuest` `-File ...\t8_cleanup.ps1` (sc stop + delete; driverquery + sc query verify;
   deletes t8_poc.exe + amdpsp.sys; keeps t8_work + logs; prints final aliveness marker).
2. Pull logs: t8_alive.txt, t8_load.txt, t8_discover.txt, t8_battery.txt, t8_sweep.txt,
   t8_cleanup.txt, t8_bootstrap.txt -> `audits\dynamic_evidence\t8_*`.
3. Verify cleanup state: `sc.exe query t8_amdpsp` + `driverquery /v` (no t8_amdpsp row) - record.
4. Write `audits\amdpsp.dynamic.md` (structure like audits\t7_fuzz.md): header table
   (File/SHA-256/Method/Verdict), ground-truth drift disclosure (PA non-return on 0x9c422002,
   0x168/0x158 shapes, 100-slot table, no-op band codes, no size cap), per-section evidence,
   sweep matrix, verdict delta (WRITE-HIGH candidate -> confirmed/medium/no-write per restricted
   wrtest + DACL), staged escalations, cleanup verification.

## Abort-point summary
- A0: VM not running / not authorized -> stop, request orchestrator.
- A0b: SHA drift on amdpsp.sys or t8_poc.exe -> stop with that artifact.
- A1: load wedges or BSODs -> stop, report; no retry.
- A2: no device object -> cleanup + negative report.
- A3: battery/sweep wedge > 2 min -> kill process, mark BLOCKED, continue next section; BSOD -> stop.
- B-gate: all Phase B items are STAGED - never executed by t8.
