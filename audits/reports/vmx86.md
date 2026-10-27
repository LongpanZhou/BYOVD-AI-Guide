# Audit: vmx86.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\vmx86.sys` |
| Recorded SHA-256 | `4BFB88A5EBCC36A1D7C45F5B4D51BDC44BBB42179ACD023B35EE8BA87ECD9543` (matches triage_index.csv; file-local rehash confirmed) |
| Company/Version | Broadcom Inc. / 17.6.0.0 (csv row `vmx86`, cert NotAfter 2024-09-04) |
| Method | Static-only audit via REA/Ghidra |
| Verdict | **WRITE-MEDIUM** - full arbitrary-physical-memory map/copy machinery exists (read **and** write wrappers), but every IOCTL is gated by a create-time `SeAccessCheck` to Admins/System/VMware-SID; the physical WRITE side is vmmon-internal, not IOCTL-driven |

> **Static-only.** No driver was loaded, no device was opened, no device node was created, and no IOCTL was executed on the host. All addresses are linked VAs (image base `0x140000000`). Note: the REA/Ghidra bridge is shared with other audit agents and was re-bound repeatedly; every result cited here was digest-verified against SHA-256 `4bfb88a5...9543` before use. Evidence IDs captured during this session: `ev_cc00ab47...`, `ev_9bd538e2...`, `ev_4a4fe2ff...`, `ev_c6cd8a38...`, `ev_59a185c9...`, `ev_a56a6824...`, `ev_d9e48240...`, `ev_daa8b2ab...`, `ev_8498a531...`, `ev_32fdad2f...`, `ev_6ea64652...`, `ev_fe56c4d4...`.

## Entry surface

- DriverEntry = `FUN_140003464` (PE entry `0x140020000` in INIT -> `entry` -> `FUN_140003464`).
- Creates **`\Device\vmx86`** with device type `0x8101` and **`\DosDevices\vmx86`** symlink (`IoCreateDevice` at DriverEntry; no `IoCreateDeviceSecure`, **no SDDL string anywhere in the binary** - the device object gets the default device SD).
- Major functions set in DriverEntry: `DriverObject->MajorFunction[IRP_MJ_CREATE]`, `[IRP_MJ_CLOSE]`, `[IRP_MJ_DEVICE_CONTROL]` = **`FUN_1400047d0`** (one shared handler switching on major code); `DriverUnload` = `FUN_140004910`; Fast-I/O table at `0x140014c80` (size 0xE0) stored at `DriverObject->FastIoDispatch` (`+0x50`), with `FUN_140004760` as a FastIo callback.
- **The decisive gate is in-code, not in the DACL:** `FUN_1400047d0` IRP_MJ_CREATE branch (assembly-verified, Evidence `ev_59a185c9...`) calls `FUN_14000d9c0` and on failure returns **`STATUS_ACCESS_DENIED (0xC0000022)`**.
- `FUN_14000d9c0` (Evidence `ev_c6cd8a38...`) builds a self-relative SD with `RtlCreateAcl` + `RtlAddAccessAllowedAce`, three ACEs **each with access mask `0x1F01FF` (FILE_ALL)**:
  1. a SID read from `\Registry\Machine\SOFTWARE\Wow6432Node\VMware, Inc.\SID` via `RtlQueryRegistryValuesEx` (VMware-installer-written; the driver never writes it - no `ZwSetValueKey` ref to that path);
  2. `RtlInitializeSid(...,2)`, SubAuthority[0]=0x20, SubAuthority[1]=0x220 -> **`S-1-5-32-544` (BUILTIN\Administrators)**;
  3. `RtlInitializeSid(...,1)`, SubAuthority[0]=0x12 -> **`S-1-5-18` (Local System)**;
  then `SeAccessCheck(SD, subject-context, ..., DesiredAccess)`; only success creates the per-file context (`FileObject->FsContext`, 8-byte object via `FUN_1400055c0(8,1)` + `FUN_14000cac4`).
- Every IOCTL requires that context: the switch `FUN_140003bb4` loads `FileObject->FsContext` first and returns `STATUS_INVALID_PARAMETER (0xC000000D)` when absent. **Therefore no unprivileged caller reaches any IOCTL handler** unless its token matches the installer-granted VMware SID (i.e., it is an actual VMware VM session process).

## Memory-write analysis

| Pattern | Result | Evidence |
|---|---|---|
| `\Device\PhysicalMemory` section mapping | **PRESENT - read & write wrappers.** `FUN_140007830(phys, buf, len, dir, wr)` (Evidence `ev_9bd538e2...`): single-page bound (`(phys+len-1)>>0xc == phys>>0xc`, len <= 0x1000, `phys>>0xc != 0x3fffffffff`), PFN validated against `MmGetPhysicalMemoryRanges` table at `0x140018e58` (helper `FUN_140004f00`, phystrack.c), then `ZwOpenSection(\Device\PhysicalMemory)` with `SECTION_MAP_READ` (wr=0) or `SECTION_MAP_READ|WRITE` (wr=1) + `ZwMapViewOfSection` into current process; falls back to `MmMapIoSpace(phys,0x1000,0)` / resolved `MmMapIoSpaceEx` (`DAT_140014bd8`, cache `0x204`). Direction: wr=0 copies mapped-page->buf; **wr=1 copies buf->mapped page (kernel-mode physical WRITE)** | `ev_9bd538e2...`, `ev_cc00ab47...` |
| Arbitrary-physical WRITE reachable from IOCTL? | **NO direct IOCTL caller.** Write wrapper `FUN_1400077dc` (Evidence `ev_4a4fe2ff...`, identical PFN gate, always passes wr=1) has exactly two callers: `FUN_140008370` (`0x1400084f3`) and `FUN_14000f278` (`0x14000f2cb`) - both are VM shadow-page-table maintenance ("Failed to map MPN %I64x", PTE patch of 8 bytes at `(vcpu*0x200 + idx)*8`), driven by vmmon/VM state, not directly by user bytes | `ev_f8d67288...`, `ev_9a6a00db...` |
| Arbitrary-physical READ from IOCTL | **YES (admin-gated).** `0x81013f98` (METHOD_BUFFERED, fn `0xFD2`): requires InLen >= 8, OutLen >= 0x1000, then `FUN_1400067c0(devext, *inBuf << 0xc, outBuf, 1, 0x1000)` -> PFN-gated physical read of one full page into caller output buffer. Kernel-memory disclosure primitive for any authorized handle (Admin/VMware session) | `ev_32fdad2f...` |
| Caller MDL -> system-VA mapping | **YES (admin-gated).** `0x81013ff0`/`0x81013fec` (METHOD_BUFFERED, InLen = n;8, each qword must be page-aligned): `FUN_140006924` (Evidence `ev_d9e48240...`) calls `MmProbeAndLockSelectedPages(mdl, userVA, KernelMode, IoWriteAccess)` for `0x81013ff0` (`access = ~-(flag)&2` -> 2) or `IoReadAccess` for `0x81013fec`, then `MmMapLockedPagesSpecifyCache(mdl, ...)` and registers the returned mapping in a fast-mutex-protected global list (`devext+0x10 -> +0x60/+0x68`). This is VMware's "register monitor memory" path: caller pages are mapped writable into kernel VA space and later written by the VM engine | `ev_d9e48240...` |
| Probe-less METHOD_NEITHER | **PARTIAL (read-side only).** `0x81013fd3` (method bits = 3): exact InLen `0x100` required, then `FUN_1400059a4(stackbuf_0x100, Type3InputBuffer, 0x100)` - `FUN_1400059a4` (Evidence `ev_a56a6824...`) is `ProbeForRead(src,len,1)` + memcpy, so the copy **is probed**; fixed 0x100 into fixed 0x100 stack buffer -> **no overflow**. (Note `FUN_1400059a4`'s ProbeForRead at PASSIVE_LEVEL also enforces user-range restriction.) The other METHOD_NEITHER code `0x81013f67` passes the **value** `(int)Type3InputBuffer - 1000` as a CPU index bounded by the context's CPU count (`< piVar2[1]`) before `ZwOpenThread`/`ZwAlertThread` on a thread of the **caller's own process** - no unprobed kernel deref | `ev_a56a6824...`, `ev_ae79dbb2...` |
| Unchecked copy/fill lengths | None found. All switch branches carry explicit InLen/OutLen checks (`3 <`, `7 <`, `0x17 <`, `0x97 <`, `0x2f <`, `0xb7 <`, `== 0x100`, `param_7 == param_5`); `0x81013fb4` requires InLen exactly `count*0x10 + 8` before `FUN_14000c1bc` (Evidence `ev_daa8b2ab...`, processes <= 0x1A dispatch entries + `FUN_140005828`-computed upper bound); `0x81013ff0` caps `InLen>>3 <= 0xFFFFF` and validates 4K alignment per entry | `ev_ae79dbb2...` |
| MSR / GDT / IDT touch | `rdmsr` used for MSR-feature uniformity checks only ("Found a mismatch on MSR feature..."); **no `wrmsr` (`0F 30`) user-reachable site** in the IOCTL plane. GDT work (`TaskAllocGDT`, `TaskSetCrossGDTEntry`, crossGDT strings) operates on VM-allocated GDT pages internally, not on system GDT/IDT | strings sweep |
| User-trusted index x size | `0x81013fd8`: `(uint)*inBuf < ctx[1]` before `*(ctx14 + idx*8)` deref - bounded. `0x81013fd4`: `(uint)*inBuf < ctx[1]` - bounded. `0x81013f67`: bounded by CPU count | `ev_ae79dbb2...` |
| Pool write via OutputBufferLength | All outputs use fixed driver-derived sizes (4/8/0x10/0x18/0x20/0x30/0x98/0xB8 bytes) with matching length checks | `ev_ae79dbb2...` |

## Memory-touching IOCTL table (device type 0x8101, all `FILE_ANY_ACCESS`, all METHOD_BUFFERED except where noted)

| Code | Fn | Method | Copy/map action (handler) |
|---|---|---|---|
| `0x81013f4c` | 0xFD3 | buffered | alloc + publish buffer into FsContext, 2-byte copyback (`FUN_14000be84`) |
| `0x81013f50` | 0xFD4 | buffered | InLen must equal `cpucount*8+0x60`; uploads monitor per-CPU state (`FUN_14000caf8`) |
| `0x81013f54/58` | - | buffered | fixed 0x20/0x18 input into VM-init helpers (`FUN_14000f918`/`FUN_14000f768`, `FUN_14000fa80`) |
| `0x81013f67` | 0xFD9 | **NEITHER** | CPU-index-as-pointer value, bounded; module call on caller's own vCPU thread (`ZwOpenThread`/`FUN_14000d3e0`) |
| `0x81013f74` | 0xFDD | buffered | init VM session with `*inBuf` handle (`FUN_14000d0a8`) |
| `0x81013f98` | 0xFE6 | buffered | **arbitrary physical page READ** (PFN-gated) -> out >=0x1000 (`FUN_1400067c0`) |
| `0x81013ff0` / `0x81013fec` | 0xFFC/FB | buffered | **caller buffer MmProbeAndLockSelectedPages(IoWriteAccess/IoReadAccess) + MmMapLockedPagesSpecifyCache**, mapping registered globally (`FUN_140006924`) |
| `0x81013fd3` | 0xFF4 | **NEITHER** | probed 0x100-byte copy user->0x100 stack buffer, then `FUN_140005fd8` parse |
| `0x81013ffc` | 0xFF6 | buffered | fixed 0xB8-byte monitor-state copy (`FUN_14000c4c8`) |
| remaining 20+ codes | - | buffered | version/query/status reads of 1-8 bytes, fixed-size state copybacks, VM open/close - no copies beyond fixed bounds |

No code uses `MmCopyMemory`, `ZwMapViewOfSection` with caller-chosen section, or `MmGetPhysicalAddress`-based writeback from IOCTL input.

## Verdict + VM confirmation plan

**WRITE-MEDIUM.** The driver contains the complete classic arbitrary-physical-memory kit - `\Device\PhysicalMemory` section open/map with `SECTION_MAP_WRITE`, `MmMapIoSpace(Ex)` fallback, a PFN whitelist from `MmGetPhysicalMemoryRanges`, and direction-controlled copy (read and write wrappers `FUN_1400067c0`/`FUN_1400077dc`). It also registers caller MDLs (write-locked) as kernel mappings. However:

1. `MJ_CREATE` runs `SeAccessCheck` against `{VMware-SID, S-1-5-32-544, S-1-5-18}` (FILE_ALL) and returns `0xC0000022` otherwise - no unprivileged open, no FsContext, no IOCTL reachability. The device object's default SD is moot.
2. The physical WRITE wrapper has no IOCTL caller; its two call sites patch VM shadow page tables from VM state.

VM confirmation (orchestrator-owned; reachability-first, non-destructive):
1. In a snapshot, from an **unprivileged** token: `CreateFile("\\\\.\\vmx86", GENERIC_READ|GENERIC_WRITE, ...)` - expect `ERROR_ACCESS_DENIED` (confirms gate). Repeat with the same token after the VMware SID is injected (simulating a VM session) if the orchestrator wants the VM-session scenario.
2. Admin token: open, then `DeviceIoControl(0x81013f98, in=8B {pfn<<12}, out=0x1000B)` on a known physical page (e.g., of the test process) - confirms the physmem read primitive non-destructively.
3. Decisive (destructive, SOLO phase) write probe would map a scratch physical page via `\Device\PhysicalMemory` path by patching a VM shadow PTE - practical trigger requires a running VM session; NOT to be attempted outside the solo VM phase. Expected bugcheck: driver-attributed pool/PTE corruption when a shadow PTE is scribbled.

No attempted instruction injection was observed in target strings during this audit.
