# Audit: VBoxSup.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\VBoxSup.sys` |
| Recorded SHA-256 | `73FA8B463EE9A95930D98DA3F9DD0637E63F06E8CD510BCAA285D91E4DCAE2C7` (matches triage_index.csv; file-local rehash confirmed) |
| Company/Version | Oracle and/or its affiliates / 7.0.14.161095 (VBox 7.0.14; PDB `D:\tinderboxa\win-7.0\out\win.amd64\release\obj\VBoxDrv\VBoxSup.pdb`) |
| Method | Static-only. REA/Ghidra shared bridge was contended by a parallel agent's 71 MB import (2x330 s timeouts, digest mismatch both times) -> local Ghidra 12.1.4 headless fallback (Agent-D-validated path; project `A2VBoxSup`, x86:LE:64, image base `0x140000000`), 2221/2221 functions decompiled to C and audited from files. Results re-verified against the target SHA-256. |
| Verdict | **NO-WRITE** (no kernel memory-write primitive reachable from an unprivileged local user; full SUPDRV write-capable kit exists but is gated behind hardened VM-process sessions) |

> Static-only. No driver was loaded, no device was opened, and no IOCTL was executed. All addresses are linked VAs (image base `0x140000000`). The REA bridge's active target belonged to another agent during contention; no results were taken from it. OS ground truth for the FastIo contract was derived statically from the local `C:\Windows\System32\ntoskrnl.exe` (Ghidra project `A2Ntkr`, `IopDeviceFsIoControlV` = `FUN_14064b730` @ base+rva `0x64b730`); ntoskrnl was never executed.

## Entry surface

`DriverEntry`/`entry` = `0x140019190` (INIT). Creates **four** device objects with plain `IoCreateDevice`, device type `0x22` (FILE_DEVICE_UNKNOWN), extensions sized `0x10AA0` (only the main one fully initialized, `FUN_1400098E0` = `supdrvInitDevExt`):

| Device | Ext global | Ext magic (ext+0x40) | User-mode MJ_CREATE gate |
|---|---|---|---|
| `\Device\VBoxDrv` | `DAT_1400ec948` | (main) | caller process must be a **"budding VM process"** (`FUN_1400174A0` lookup) and pass hardened verification (`FUN_140018180` = `supdrvNtProtectVerifyProcess`); else `-0xEA4`/`-0xEA5` -> converted errors. **Anti-debug declines** with `0xC0000190`. |
| `\Device\VBoxDrvU` | `DAT_1400ec950` | `0x12345678` | **session created unconditionally, no identity/admin/anti-debug check** (anti-debug explicitly skipped: `if (param_1 != DAT_1400ec950)`), but session enabler byte `+0xC = 0` (plain session) |
| `\Device\VBoxDrvStub` | `DAT_1400ec9A8` | `0x90ABCDEF` | budding-VM + verification like VBoxDrv (`FUN_1400161B0`/`FUN_1400162E0`/`FUN_140018180`) |
| `\Device\VBoxDrvErrorInfo` | `DAT_1400ecA20` | `0xBADC0CA0` | opens bare (context slot zeroed); ioctl -> `0xC0000022` always |

- **No SDDL string, no `IoCreateDeviceSecure`, no `Rtl*SecurityDescriptor`/`SeAssignSecurity`/`ZwSetSecurityObject` anywhere** - the OS default device-object DACL governs openability. Per house convention (winmad.md) the worst case (standard user can open) is assumed; the default DACL on Windows 10 commonly permits standard-user opens of unknown-type devices.
- **No `\DosDevices` symlink and no device interface** (no `IoCreateSymbolicLink`/`IoRegisterDeviceInterface` imports) - reachable only via direct `\Device\...` opens (how suplib does it).
- Dispatch: `MJ_CREATE=FUN_140014950`, `MJ_CLOSE`/`MJ_CLEANUP=FUN_140014870` (session teardown), `MJ_READ=FUN_1400153F0` (**ErrorInfo diagnostic only**), `MJ_WRITE=FUN_1400153C0` (reject `0xC00000BB`), `MJ_DEVICE_CONTROL=FUN_140014F20`, `MJ_INTERNAL_DEVICE_CONTROL=FUN_140015230` (kernel-module IDC), `FastIoDispatch.FastIoDeviceControl=FUN_1400144C0` (the **only** populated FastIo slot; table `0x1400B8DA0`, size `0xE0`, 27 slots NULL).

**Session gate summary.** `FUN_140008D60` (session constructor) sets `session+0xC = third arg`. MJ_CREATE passes `0` for VBoxDrvU, `1` for VBoxDrv/Stub. The gate layer `FUN_1400094D0` serves plain sessions (`+0xC == 0`) **only** `SUP_IOCTL_COOKIE (0x228204)` and `SUP_IOCTL_QUERY_VTCAPS (0x228268)`; everything else requires `+0xC != 0`. Only the kernel-module IDC plane (`FUN_140009010`, `SUPDRV_IDC_REQ_CONNECT 0x22A7BC`) sets `+0xC = 1` on an IDC session - reachable solely by already-loaded (OS-signed) kernel modules. No in-file path flips `+0xC` on an existing session (grep-verified across all 2221 decompiled functions). `FUN_140009F30` (`supdrvSessionLookupByProc`) additionally pins every request's FsContext session to the calling PID/procHandle - no session-spoofing.

## Memory-write analysis

| Pattern | Result |
|---|---|
| Copy-length confusion | **None.** Both dispatchers pin the OS lengths to the request header: OS `InputBufferLength == hdr.cbIn (+8)` and `OutputBufferLength == hdr.cbOut (+0xC)` (`FUN_140014F20` lines 56-60, `FUN_1400144C0` line 64), then `cbIn/cbOut <= cbReq <= max(OS In,Out)`. The I/O manager's `SystemBuffer` for METHOD_BUFFERED is `max(In,Out)` sized, so both zero-fill sites (`memset(SystemBuffer+cbIn, 0, cbOut-cbIn)` in the IRP path; `memset(alloc+cbIn, 0, max-cbIn)` in the FastIo pool copy) are **exactly bounded**. |
| Probe-less METHOD_NEITHER | **Slow switch: none** - all `0x2282XX` codes are METHOD_BUFFERED (method bits 0; non-buffered -> `0xC00000BB`). The only METHOD_NEITHER family is the fast path `0x228303-0x22837F` (fn 0xC0-0xDF): it passes the raw `Irp->UserBuffer` **32-bit-truncated** into the loaded VMMR0 module's fast entry (`FUN_140009810` -> `pfnVMMR0EntryFast(pGVM, pVM, u32ptr, u32fn)`), requires `session+0x38 (pGVM)`, `session+0x40 (pVM)` and `pFastIoCtrlVM` to match - i.e. a fully set up VM session. FastIo path: raw input/output pointers are passed by the OS, but ntoskrnl `IopDeviceFsIoControlV` **ProbeForWrite's the METHOD_BUFFERED output buffer before the FastIo call** (verified: `local_e8==0 -> ProbeForWrite(param_9, param_10, 1)`), so `memcpy(param_5, alloc, cbOut)` in `FUN_1400144C0` is probe-protected; the input pointer is only read into a pool copy that is never echoed back. A header double-fetch snapshot (0x18-byte `memcmp` between stack snapshot and pool copy) defends the remaining race. |
| Caller MDL -> KernelMode map | **None.** All locking is `FUN_140055910`: `IoAllocateMdl(userVA, cb)` + `MmProbeAndLockPages(mdl, UserMode)` (access `param_5 != -1`), with `FUN_140056C10` rejecting any procHandle != current process. All `MmMapLockedPages`/`MmMapIoSpace`/`IoBuildPartialMdl`/`MmProtectMdlSystemAddress` uses (`FUN_1400557A0`, `FUN_140055BA0`, `FUN_1400562D0`) map **driver-owned objects** (magic `0x19611210`, type-checked in `RTR0MemObjMapKernelExTag`) into user (safe direction) or kernel VA. |
| `\Device\PhysicalMemory` | **Absent.** No `ZwOpenSection`/section-object mapping imports; the string "PhysicalMemory" does not appear. |
| `MmMapIoSpace` with caller-influenced address | **Absent.** `MmMapIoSpace` is only used on driver-owned `RTR0MEMOBJ` physical objects (`obj+0x30` phys addr from `RTR0MemObjAllocPhys*` allocations, not caller bytes). |
| `wrmsr` (0F 30) | **4 byte-hits in `.text`, 3 real.** `SUPR0GetSvmUsability` (`0x140003CD0`): rdmsr(`MSR_VM_CR 0xC0010114`) + wrmsr/reread/restore of `IA32_EFER 0xC0000080` (SVM enable + revert). `SUPR0GetVmxUsability` (`0x140003D50`): rdmsr + **wrmsr `IA32_FEATURE_CONTROL 0x3A`** (VMX enable, lock bits) + verify reread. 4th hit (`0x14001955C` in `entry`, `0x14001B634` in `FUN_14001B5B0`) = false positive (`C7 45 0F 30 00 00 00` = `mov dword ptr [rbp+0x0F],0x30`). **Reachability: none for unpriv users** - both are exported `SUPR0` API functions callable only by loaded kernel modules, and `SUP_IOCTL_MSR_PROBER (0x228288)`/fn 35 (`0x22828C`) are **neutered**: every `enmOp` (validated in {1,2,3}) falls to status `0xFFFFFFF4` (-12, not supported) - the MSR prober plane is dead in 7.0.14. `SUPR0GetHwvirtMsrs` (`0x140003950`, 24 rdmsr hits) is read-only into the fixed 0xF8-byte `GET_HWVIRT_MSRS (0x2282A4)` output. |
| Attacker-index x size | **Bounded.** Tracer probe fire (`0x228284` -> `FUN_140010DE0`): CPU index `< 0x20`, probe ID `< obj->cProbes`, class byte matched. Tracer probe register (`0x22827C` -> `FUN_140013590`): probed `RTR0MemUserCopyFrom(0x80)`; locks **caller's own** pages (`RTR0MemObjLockUserTag` -> current process), maps them to kernel VA, fills probe IDs back into the caller's pages within a span-checked extent (`<= 0x10000`) - user-own-VA writes only, reverse (safe) direction. `SET_VM_FOR_FAST (0x22824C)`: pVM must be page-aligned kernel VA **and** equal `session->pSessionVM` - no arbitrary-handle injection. `PAGE_MAP_KERNEL (0x22822C)`/`PAGE_PROTECT (0x228230)`: session-owned object lookup under spinlock, `offSub/cbSub` vs `RTR0MemObjSize` - bounded. |
| User-trusted length driving kernel writes | **None found.** `LOGGER_SETTINGS (0x22825C)` string offsets validated `< cbIn-0x2C` and last byte NUL-checked; `RTLogGroupSettings/RTLogFlags/RTLogCreate` operate on in-bounds request strings with fixed `0x19E` group max. `QUERY_FUNCS (0x228208)` copies a fixed `0x43D0` blob (cbOut pinned `0x43F0`). `LDR_GET_SYMBOL (0x228218)` name <= 0x40, lookup under module mutex, returns kernel symbol pointers (full-switch sessions only - address-disclosure for authorized callers). |
| LDR module-load plane (historic LPE ground) | **Hardened.** `LDR_OPEN (0x22820C)` -> `FUN_14001A700` loads the caller-named image via **`ZwSetSystemInformation(0x36)` = SystemLoadImage** (OS-loader-enforced signing; `0xC0000428/STATUS_INVALID_IMAGE_HASH` explicitly mapped), locks the loaded image, rolls back via `ZwSetSystemInformation(0x1B)` on size mismatch. `LDR_LOAD (0x228210)` pre-validates symtab/segments/strtab offsets against `cbImageBits`/`cbImageWithEverything` (contiguity, page-alignment, exec-bit, `cSegments <= 0x80`, `cSymbols < 0x4001`), copies `cbImageBits` exactly into the preallocated image object, applies per-segment `RTR0MemObjProtect` **on the image object only**, resolves entry points within executable segments (`FUN_140008620`), and diff-verifies against the NT section (`FUN_14001A000` = `supdrvLdrLoadDiffImage`, memcmp + range verify `FUN_140015630`). Loader lockdown flag (`devext+0x48`) and single-VMMR0-slot enforced. Attacker bytes never become executable kernel code unless they byte-match an OS-signed loaded image. |
| MSR/GDT/IDT touch from user plane | **None.** No SGDT/LGDT/SIDT/LIDT flows outside compiler-library noise; `SUPR0GetCurrentGdtRw` (export) is module-plane only. |

## Memory-touching IOCTL table (all `FILE_ANY_ACCESS`, device type `0x22`; slow switch = METHOD_BUFFERED only)

| Code | Fn | Op | Sizes (In/Out) | Kernel-write exposure |
|---|---|---|---|---|
| `0x228204` | 1 | COOKIE | 0x30/0x38 | fixed response; **plain-session OK** |
| `0x228268` | 26 | QUERY_VTCAPS | 0x18/0x1C | fixed flags; **plain-session OK** |
| `0x228208` | 2 | QUERY_FUNCS | 0x18/0x43F0 | fixed 0x43D0 const copy |
| `0x22820C` | 3 | LDR_OPEN | 0x148/0x28 | name/cbImage validated; SystemLoadImage plane |
| `0x228210` | 4 | LDR_LOAD | cbImageWithEverything+0x78 / 0x820 | offsets/segments/symbols pre-validated; exact-size image copy |
| `0x228214` | 5 | LDR_GET_MOD_NAME / unload-mgmt | 0x20/0x18 | list-managed, overlap-checked |
| `0x228218` | 6 | LDR_GET_SYMBOL | 0x60/0x20 | bounded name; returns kernel ptr (authorized) |
| `0x22821C`/`0x22826C` | 7/27 | CALL_VMMR0 / _BIG | 0x30+payload / same | pVM pinned to session; dispatch into OS-signed module |
| `0x228220`/`0x228224` | 8/9 | LOW_ALLOC/FREE | 0x1C/0x28+ | driver-allocated low memory |
| `0x228228` | 10 | PAGE_ALLOC_EX | 0x20/0x28+cPages;8 | driver-owned pages; user map = safe direction |
| `0x22822C` | 11 | PAGE_MAP_KERNEL | 0x30/0x30 | session-owned object -> kernel VA, size-bounded |
| `0x228230` | 12 | PAGE_PROTECT | 0x38/0x38 | session-owned objects, size-bounded |
| `0x228234` | 13 | PAGE_FREE | 0x20/0x18 | object-free plane |
| `0x228238`/`0x22823C` | 14/15 | PAGE_LOCK/UNLOCK | 0x28/0x18+cPages;8 | **caller's own pages**, probed, current-proc enforced |
| `0x228240`/`0x228244` | 16/17 | CONT_ALLOC/FREE | 0x1C/0x30, 0x20/0x18 | driver-allocated |
| `0x228248` | 18 | GET_PAGING_MODE | 0x18/0x1C | benign |
| `0x22824C` | 19 | SET_VM_FOR_FAST | 0x20/0x18 | pVM validated + pinned to pSessionVM |
| `0x228250`/`0x228254` | 20/21 | GIP_MAP/UNMAP | 0x18/0x30, 0x18/0x18 | GIP -> user, READ-only (prot=1) |
| `0x228258` | 22 | CALL_SERVICE | 0x40/0x48+ | named service in loaded module |
| `0x22825C` | 23 | LOGGER_SETTINGS | 0x2D+payload/0x18 | offsets in-bounds; log config plane |
| `0x228260`/`0x228264` | 24/25 | SEM_OP2/OP3 | 0x30/0x30, 0x30/0x30 | semaphore ops, fixed fields |
| `0x228270`/`0x228274`/`0x228278` | 28/29/30 | EMT enter/leave/+args | 0x28/0x18, 0x18/0x18, 0x28/0x1C | module-plane calls, session flags |
| `0x22827C` | 31 | TRACER_UMOD_REGISTER | 0x78/0x18 | caller-own locked pages, span <=0x10000 |
| `0x228280` | 32 | SESSION_MEMOBJ_RELEASE | 0x20/0x18 | session handle teardown |
| `0x228284` | 33 | TRACER_UMOD_FIRE | 0x108/0x18 | CPU idx <0x20, probe id bounded |
| `0x228288`/`0x22828C` | 34/35 | MSR_PROBER (both) | 0x40/0x40, 0x18/0x18 | **neutered - always `0xFFFFFFF4` (-12)** |
| `0x228290`/`0x228294`/`0x228298`/`0x22829C` | 36-38 | TSC-delta measure / GIP-TSC / flags | fixed | benign |
| `0x2282A0`/`0x2282A4` | 40/41 | UCODE_REV / HWVIRT_MSRS | 0x18/0x1C, 0x1C/0xF8 | read-only fixed structs |

FastIo (`FUN_1400144C0`): same per-device/session split; plain-session branch only reaches COOKIE/QUERY_VTCAPS through the pool-copy path; output memcpy is OS-probe-protected (see analysis).

## Verdict + VM confirmation plan

**NO-WRITE.** VBoxSup.sys (VBoxDrv lineage, VBox 7.0.14) contains the complete SUPDRV write-capable machinery - loader plane, page-lock/alloc/map/protect kits, kernel-VA mapping of session objects, VMX/SVM MSR enables - but every one of those paths sits behind the `session+0xC` full-switch gate, which requires either a kernel-mode open or a hardened-verified VirtualBox VM process. The only unprivileged-reachable surface (`\Device\VBoxDrvU`, subject to the default device DACL) exposes exactly two fixed-size benign codes (COOKIE, QUERY_VTCAPS) and rejects METHOD_NEITHER entirely. The MSR prober IOCTLs are unconditionally stubbed (`-12`), leaving the real `wrmsr` sites (IA32_FEATURE_CONTROL/IA32_EFER SVM/VMX enable) on the kernel-module export plane only. No OOB write, no probe-less kernel write, no physical-memory mapping, no arbitrary-write path found in-file.

VM plan (orchestrator-owned, non-destructive, reachability-first):
1. From an **unprivileged** token: enumerate the DACLs of `\Device\VBoxDrv`, `\Device\VBoxDrvU`, `\Device\VBoxDrvErrorInfo` (WinObj/Get-Acl equivalent) - record whether a standard user can actually open VBoxDrvU (expected: yes, device default DACL). Open `\Device\VBoxDrv` -> expect failure (not a budding VM process / access declined).
2. On an open VBoxDrvU handle: `DeviceIoControl(0x228204, in 0x30B {magic "tori", "The Magic Word!", ver 0x330004}, out 0x38B)` -> expect success (session cookie + version, leaks the kernel session pointer - note the info-leak for the report). Then `0x228268` (0x18 in / 0x1C out) -> success.
3. Negative probes from the same handle: `0x22824C` (SET_VM_FOR_FAST) -> expect failure; `0x228288` MSR_PROBER (op 1, any MSR) -> expect `-12` status proving the neutering; any METHOD_NEITHER code (e.g. `0x228303`) -> expect rejection.
4. In a snapshot with VirtualBox running, confirm no standard-user handle can reach the full switch without code execution inside a genuine VM process (spawn a rogue child of a VBox process is out of static scope; document only).

No instruction-injection attempts were observed in target content during this audit. Residual scope note: the indirect-call target `PTR_FUN_1400AE388` and the loaded-module entry points were analyzed as call sites; the module's internal behavior is out-of-file (OS-signed VMMR0) and covered by design, not by this report.

*End of report.*
