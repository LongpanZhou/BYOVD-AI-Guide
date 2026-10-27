# Dynamic audit: amdpsp.sys (t8)

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\amdpsp.sys` (guest copy byte-identical) |
| SHA-256 | `0A3AF18439B6BB4AF119C8020A3D0220ED6CC8AE04E20032F846E77777700A0A` (verified in-guest by `t8_bootstrap.ps1` - MATCH) |
| Company/Version | Advanced Micro Devices, Inc. - AMD Platform Security Processor driver (KMDF, in-guest driverquery date 3/6/2020) |
| Method | VM dynamic testing (Win10 x64 19045, testsigning=Yes, snapshot `pre-driver-tests`) + Ghidra 12.1.4 headless static assist (`t8_assist.txt`, full decomp `t8_decomp_amdpsp.txt`) |
| Verdict | **WRITE-HIGH (candidate) NOT DYNAMICALLY CONFIRMED - surface UNREACHABLE in the VMware guest: service loads, but the device requires a bus-interface-capable parent (GUID_BUS_INTERFACE_STANDARD) and never starts on synthetic devnodes. SDDL application to a live object remains statically asserted only.** |
| Coverage | Dynamic: load/gate chain complete (5 guest steps executed); batteries/sweeps/kd NOT executed (no device object to target). Static assist: SDDL consumer + allocator + dispatch + band + mailbox architecture resolved (~85% vs the static audit's ~60%). |
| Incident | **Guest VM was powered off mid-phase by an outside actor after the last completed evidence pull and before the 3rd devnode attempt; no power operation was issued by t8. Phase halted per protocol; guest left dirty for orchestrator revert.** |

> **Ground-truth drift vs `audits/amdpsp.md` (static audit)** - resolved by Ghidra headless on the project copy (base 0x140000000):
> 1. **SDDL IS consumed.** `FUN_14001d1e0` (@0x14001d1e0) builds `\Device\amdpsp` (+decimal instance suffix for instance>0), calls `(*DAT_14001a3e0)(WdfGlobals, deviceInit, &sddl)` = `WdfDeviceInitAssignSDDLString` with the Everyone-RWX string at 0x140009210, then `WdfDeviceCreate` (attrs 0x38) via `DAT_14001a418`. `\DosDevices\amdpsp` symlink is created **only for instance 0** (`DAT_14001a440`). A device interface is registered with GUID at 0x1400091e0 = `{D41D854A-3877-4471-A889-B0D551B1125B}` (`DAT_14001a428`).
> 2. **Allocator has NO size cap.** `FUN_140002b50`/`FUN_140002c30` = `MmAllocateContiguousMemorySpecifyCache(uint size, 0, 0xFFFFFFFFF, boundary 0x4000000, cached / non-cached)`; only guard `size != 0` (4 GB theoretical ceiling from the uint).
> 3. **0x9c422002 does NOT return the physical address.** Dispatch wrapper `FUN_1400017b0` case 0x9c422002: input EXACTLY 8 B, output EXACTLY 0x38; `FUN_140003020(ctx, dword[0]=size, out, out+8)` -> output = `err@+0, userVA@+8` only. The PA computed inside `FUN_140002b50` is dropped in this path. **PA disclosure claim moves to 0x9c422820** (input copy-back).
> 4. **0x9c422800-band shapes are NOT 0x28-byte headers.** `FUN_1400026a0` switch: 0x9c422820 = in EXACTLY **0x168**, out EXACTLY **0x158** (size @ input+0x158; PA hi/lo @ input+0x160/+0x164 copy-back; userVA @ out+0x18; 10-slot table, non-cached alloc, UserMode map via `FUN_140006920`). 0x9c422808 = in 0x10; 0x9c422824 = in 0x170; 0x9c422834 = in 0x20; codes 804/80C/810/814/818/828/830/838/83C/844 = **accepted no-ops**; anything else in the band -> 0xC0000010.
> 5. **Slot tables:** 0x9c422002 allocs live in a **100-slot** table (ctx+0x1280 + 32*i: kernelVA, flag@+0x10, userVA@+0x18, size@+0x28); the 16-slot x 0x120-stride table (ctx+0x94) belongs to 0x9c422004/5 registration (`FUN_140003fb0`); `FUN_140005980` is only a per-slot enable toggle (writes slot+0x9c); `FUN_140002e20` = plain `MmFreeContiguousMemory` wrapper.
> 6. **0x9c422003 frees by USER-VA match** (slot userVA == caller's 8-byte input; no per-process validation -> cross-process free / double-free chain possible -> STAGED B3, never executed).
> 7. **Codes 2000/2006/2007/2008/2009 + 808/834 are a probe-capture family** (`DAT_14001aa70`/`DAT_14001aa78` match `WdfRequestProbeAndCaptureUserPointerFor{Read,Write}` signature: (globals, request, ptr, len, &mem)) and write the captured buffer's kernel VA back into the caller's input struct (buffered copy-back) = kernel-address disclosure of request-scoped buffers.
> 8. **PSP mailbox architecture:** `FUN_140003dc0` (TEE-log init) allocates 0x2c0 contiguous memory and **programs its PA into MMIO registers 0x48/0x4C** (`FUN_140002eb0`), polls 0x44 (`FUN_140002e50`) - the PSP consumes kernel queues by physical address. In-file strings: `OutQueueWrtPtr/OutQueueRdPtr`, `Tee interrupt call back function`, `TeeLogPollingWorker`. The kernel-side write consumer of the user-mapped table remains untraced.

## Dynamic phase log (all steps were pushed as ASCII ps1, run via vmrun runProgramInGuest, logs pulled per-line-flushed)

| Step | Result | Evidence |
|---|---|---|
| Push + SHA verify | 8/8 files copied; amdpsp.sys + t8_poc.exe MATCH pinned hashes | `t8_bootstrap.txt`, `t8_alive.txt` |
| Load (`sc create/start t8_amdpsp`) | **CreateService SUCCESS; start exit=0; STATE 4 RUNNING**; WIN32/SERVICE exit 0; driverquery row Kernel/Manual/Running/OK; NO 7000/7026 events | `t8_load.txt` |
| Discovery | `\Device\amdpsp` open -> `err=2` (Win) / `0xC0000034` OBJECT_NAME_NOT_FOUND (NT); `\\.\amdpsp` absent (no symlink); interface GUID key ABSENT in DeviceClasses; qobj scans on `\Device`/`\DosDevices`/`\??` AV'd (0xC0000005) - **pre-existing platform quirk, t7 hit the same AV (`t7_verify.txt`)**; `\GLOBAL??` scan cleanly 0xC0000022 | `t8_discover.txt` |
| DriverEntry trace (static) | `entry@0x14008ab8` -> `FxDriverEntryWorker` -> `FUN_14001e010` = `WdfDriverCreate` with `EvtDriverDeviceAdd = FUN_14001d010`; **device creation is PnP-gated (runs only on PDO arrival)** | `t8_decomp_amdpsp.txt` |
| Devnode attempt 1 (t3 recipe, ROOT) | `CM_Create_DevNodeW(ROOT\AMDPSP\0000, HTREE\ROOT\0, flags=0)` -> CR=0; enum key seeded (Service=t8_amdpsp); `pnputil /restart-device` -> "Device restarted successfully"; **devstat: status=0x1802401 problem=10 (CM_PROB 10)**; open probes all err=2/0xC0000034; **service transitioned Running -> Stopped after failed start** | `t8_mkdev.txt` |
| Devnode attempt 2 (ACPI parent) | `CM_Create_DevNodeW(ACPI\AMDPSP\0000, ACPI\PNP0C02\4, flags=0)` -> **CR=0x5 (CR_INVALID_DEVNODE)** - ACPI enumerator refuses manual children; aborted before seeding | `t8_mkdev2.txt` |
| Post-mortem | **DEVPKEY_Device_ProblemStatus = 0xC00000BB = STATUS_NOT_SUPPORTED** for ROOT\AMDPSP\0000 - matches the static D0-entry analysis: `FUN_14001d590` (EvtDeviceD0Entry) first does `WdfFdoQueryForInterface(device, GUID_BUS_INTERFACE_STANDARD@0x1400091d0, iface, 0x40, version 1, 0)` and `return`s that status; the root enumerator does not answer the query -> start fails, WDF deletes the device, service unloads | `t8_sapi.txt` |
| Devnode attempt 3 (PCI parent) | **NOT EXECUTED - VM found powered off** at push time (`vmrun list` = 0). No power op issued by t8. | - |
| Batteries / sweeps / kd / cleanup | **NOT EXECUTED - no device object to target; VM off** | - |

## Battery + sweep matrix

Not executed - the IOCTL surface (`\Device\amdpsp` / `\\.\amdpsp` / interface `{D41D854A-...}`) never came to exist in the guest:

- 0x9c422000-0x9c42200C band: blocked (no device).
- 0x9c422800-band (including shaped 0x168 probe): blocked (no device).
- Restricted-token (`runas /trustlevel:0x20000`) USER-MAP WRITABLE test: **not obtainable** - nothing to open.

Dispatch counts: 0 successful IOCTL dispatches; 6 documented open probes failed; 1 devnode create + seed + restart executed (start failed 0xC00000BB); 1 devnode create rejected (CR 0x5).

## Why the surface is unreachable (mechanism)

1. DriverEntry (`FUN_14001e010`) only calls `WdfDriverCreate` - no device.
2. `FUN_14001d010` = EvtDriverDeviceAdd -> registers EvtIoDeviceControl `FUN_1400017b0`, a 0x90 config with callbacks (`FUN_14001d130` D0-entry, `FUN_14001d180` D0-exit), then `FUN_14001d1e0` creates `\Device\amdpsp<inst>` + SDDL + interface + symlink.
3. `FUN_14001d590` = D0-entry: FIRST operation = `WdfFdoQueryForInterface(device, {496B8280-6F25-11D0-BEAF-08002BE2092F} = GUID_BUS_INTERFACE_STANDARD, iface, 0x40, v1, 0)`; its NTSTATUS is the function's return value. Memory resources (CmResourceTypeMemory) would then be MMIO-mapped (`MmMapIoSpace`, up to 4 ranges) - with zero resources the loop is skipped harmlessly, so **the bus interface is the only hard gate**.
4. Synthetic devnodes: ROOT parent -> QUERY_INTERFACE returns 0xC00000BB (observed); ACPI/PCI enumerator parents -> `CM_Create_DevNodeW` rejected (observed for ACPI; PCI-parent create was the interrupted attempt 3).
5. Real hardware binding would be ACPI\AMDPSP / PCI VEN_1022 PSP - neither exists in a VMware guest.

## Verdict delta vs static WRITE-HIGH (candidate)

- **Not confirmed; not refuted.** The in-file primitives (Everyone-RWX SDDL assigned at device init; caller-sized contiguous alloc; UserMode RW map with PA disclosure on the 0x9c422820 shape; free-by-user-VA) remain static facts with exact call-site evidence - stronger than in the static audit (SDDL application now traced to the actual `WdfDeviceInitAssignSDDLString` call preceding `WdfDeviceCreate`).
- **Reachability is hardware-gated**: PSP-less environments (VMware guest; any machine without the AMD PSP ACPI/PCI node) get a loading-but-silent driver (service Running, zero objects) or a failed start (0xC00000BB) on synthetic devnodes. On hosts WITH real PSP hardware, the surface is expected to exist with the Everyone SDDL - the confirmation plan stays valid there, but is out of scope for this VM.
- **Effective verdict: WRITE-HIGH (candidate) -> WRITE-MEDIUM (hardware-gated reachability; unpriv primitive not demonstrated).** Escalation back to WRITE-HIGH/WRITE-CRITICAL requires a live PSP environment (real AMD host) - recommendation: never attempt on this host (driver is LIVE boot-start there; host dynamic testing forbidden).
- PA/VA-return summary for the record: userVA returned by 0x9c422002 (+8) and 0x9c422820 (out+0x18); PA returned only by 0x9c422820 (input copy-back +0x160/+0x164); 0x9c422000/2007/2008/808/834 leak kernel VAs of probe-captured request buffers.

## Staged (never executed - `stage\t8_phaseB_STAGED.txt`)

- B1 PSP-mailbox submit escalation (write into mapped view + 0x9c422004 enable trigger).
- B2 allocations > 0x40000.
- B3 0x9c422003 free-by-foreign-VA / double-free chain (match key = user VA, no process validation).
- B4 0x9c422824-shaped 0x170 probe + band codes 0x9c422840-0x9c4228FF.

## Cleanup verification

**PENDING - cleanup script could not run (VM powered off by outside actor before the cleanup step). Guest was left in this state (all of it inside the `pre-driver-tests` revert delta):**

- Service `t8_amdpsp`: EXISTS, Stopped (image `\??\C:\Users\vmdebug\Desktop\t8_work\amdpsp.sys`); service key present.
- Devnode `ROOT\AMDPSP\0000`: exists with problem=10 (0xC00000BB); enum key `HKLM\SYSTEM\CCS\Enum\ROOT\AMDPSP\0000` present (t8-seeded).
- `ACPI\AMDPSP\0000`: nothing created (CfgMgr rejected; enum key absent - verified in `t8_sapi.txt`).
- Files in `C:\Users\vmdebug\Desktop\t8_work\`: 8 pushed artifacts + logs; driver binary NOT loaded at power-off (service Stopped, no device); no pre-existing guest files touched; pre-existing services (vmci/vsock/b06bdrv) untouched.
- t8_kernel-side state at VM-off: driver not loaded; no kernel memory held.

**Action for orchestrator: revert to `pre-driver-tests` (canonical policy) - restores pristine state including service/devnode/registry/t8_work. No manual cleanup is required and no cleanup script needs to run.**

## Completion run (2026-10-24, orchestrator re-authorization after the halt)

Halt disclosure: the phase-1-run VM power-off was an external **VIX client power-off (VMAutomationPowerOff, cleanShutdown=TRUE)** - not a t8 action; orchestrator grep-verified the harness contains zero vmrun power ops. Orchestrator reverted to `pre-driver-tests` (wiping run-1 dirty state: service key, ROOT\AMDPSP devnode, pushed files) and booted the VM.

Completion-run sequence and results (all evidence `t8_*2`/`t8_mkdev3`/`t8_cleanup`):

| Step | Result |
|---|---|
| Re-push (12 files) + SHA verify | 12/12 copied, no pre-existing collisions; amdpsp.sys + t8_poc.exe **MATCH** pinned hashes; aliveness marker set | 
| Load (t8_load.ps1) | Identical to run 1: CreateService SUCCESS, start exit 0, **STATE 4 RUNNING**, driverquery Running/OK, no 7000/7026 |
| Devnode attempt #3 - PCI parent (FINAL for technique) | `CM_Create_DevNodeW(PCI\AMDPSP\0000, PCI\VEN_8086&DEV_7191...bridge, flags=0)` -> **CR=0x5 (CR_INVALID_DEVNODE)** - the PCI enumerator refuses manual children exactly like ACPI. No devnode, no seed, no start. |
| Branch decision | **No surface** -> batteries/sweeps/kd not executed (again); recorded as the final AddDevice-gate finding |
| Fresh discovery (post-attempt-3) | `\Device\amdpsp` 0xC0000034 / `\\.\amdpsp` err=2 / interface key absent; service still Running (no start attempt occurred in attempt #3) |
| Cleanup (t8_cleanup.ps1) | `sc stop` -> **FAILED 1052** (service now reports `NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN` - no PnP device attached, no unload path); `sc delete` -> **SUCCESS (delete-marked; start type -> Disabled)** but the running image persists; `driverquery`: t8_amdpsp "Disabled / Running"; `t8_poc.exe` deleted [x]; **`amdpsp.sys` NOT deletable while the image is loaded (`gone: False`)**; pre-existing services printed untouched (vmci Running, vsock Running, b06bdrv Stopped); final marker `t8_cleanup COMPLETE` |

**Devnode technique - FINAL (3/3 attempts used):** ROOT parent = created but start fails `0xC00000BB` (STATUS_NOT_SUPPORTED at the `WdfFdoQueryForInterface(GUID_BUS_INTERFACE_STANDARD)` gate in `FUN_14001d590`); ACPI parent = create rejected CR 0x5; PCI parent = create rejected CR 0x5. **The AddDevice/D0-entry gate is structural: only a real PSP bus node (ACPI\AMDPSP / PCI VEN_1022 PSP, whose parent bus answers BUS_INTERFACE_STANDARD) can satisfy it. In the VMware guest the IOCTL surface is permanently absent.**

**Cleanup residual (for the orchestrator's revert):** service `t8_amdpsp` delete-marked but still loaded in kernel memory; `t8_work\amdpsp.sys` file locked by the loaded image; logs/scripts in `t8_work`. All inside the `pre-driver-tests` revert delta. No BSOD, no wedge, no pool writes occurred in either run.

**Final verdict (stands): WRITE-MEDIUM (hardware-gated reachability).** Static primitives remain strong and precisely located (Everyone-RWX SDDL applied via `WdfDeviceInitAssignSDDLString` before `WdfDeviceCreate`; capless contiguous allocator; UserMode RW map + PA return on the 0x168-shaped 0x9c422820; free-by-user-VA cross-process concern staged as B3; probe-capture kernel-VA disclosures on 2000/2006/2007/2008/2009/808/834). Dynamic confirmation of the unpriv USER-MAP WRITABLE primitive is only possible on a real AMD PSP host - out of scope for this VM project (host testing forbidden; host amdpsp.sys is LIVE boot-start).

Completion-run evidence additions: `t8_bootstrap2.txt`, `t8_load2.txt`, `t8_mkdev3.txt`, `t8_discover2.txt`, `t8_cleanup.txt`, `t8_alive.txt` (final marker).

## Evidence inventory (audits/dynamic_evidence/)

`t8_assist.txt` (Ghidra targeted static assist), `t8_decomp_amdpsp.txt` (full decomp, 111 functions),
`t8_bootstrap.txt`, `t8_bootstrap2.txt`, `t8_alive.txt`, `t8_load.txt`, `t8_load2.txt`, `t8_discover.txt`,
`t8_discover2.txt`, `t8_mkdev.txt`, `t8_mkdev2.txt`, `t8_mkdev3.txt`, `t8_sapi.txt`, `t8_cleanup.txt`;
stage dir `_vm_batch2\t8_amdpsp\stage\` (MISSION.md runbook + all scripts + t8_phaseB_STAGED.txt).
