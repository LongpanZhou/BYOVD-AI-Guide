# Audit: NZXT / Netac / HyperX / PawnIO families - kernel memory-write re-audit (current scope)

| Field | Value |
|---|---|
| File(s) | `cam_driver_mb_A9C246FD.sys`, `SiLib_DD2C9A1D.sys`, `SiUSBXp_A8BE9E3F.sys`, `SMI_IO_32_B198D7E1.sys`, `SMI_IO_64_89A4F4DC.sys`, `vachpxkd_94A275C1.sys`, `vachpxkd_F56EF5B5.sys`, `PawnIO_4383A699.sys` |
| SHA-256(s) | see section 1 (all eight re-hashed and matched against the file names) |
| Analysis date | 2026-10-25 |
| Method | Static-only: local Ghidra 12.1.4 headless (full decompile of every function in all eight images) + `llvm-objdump` for exact instruction addresses + local PE parsing. No driver loaded, no service created, no registry write, no device opened, no IOCTL issued. No web access. **REA was not used**: four REA audits were already active, so this pass is the offline Ghidra/objdump path recorded in `audits/STATUS.md` section In flight item 7. |
| Reach tier | **R2** is the highest tier at which a memory write is reachable (SMI_IO, both builds). R3 for the two gated writes (HyperX `vachpxkd` x64, SiUSBXp). |
| Setup required | `service` (NZXT CAM driver, SMI_IO), `devnode` (HyperX `vachpxkd`, PawnIO), `hardware` (SiUSBXp/SiLib) |
| Write quality | **W2** (max; unbounded kernel-stack copy in SMI_IO). Also W2 (HyperX METHOD_NEITHER write-what-where), W2 (SiUSBXp caller-length USB transfer), W3P (SMI_IO physical map), W0 elsewhere. |
| Verdict | **MW2 - overall.** Netac `SMI_IO` (both builds) exposes an unbounded kernel-stack copy reachable by an administrator-opened handle. Two further **MW3** findings: HyperX `vachpxkd` x64 (unprobed `METHOD_NEITHER` output-pointer write to a caller-chosen address) and NZXT `SiUSBXp` (caller-controlled USB transfer length over a pool-sized system buffer). `cam_driver_mb`, `SiLib`, `PawnIO` are **NO-MEMORY-WRITE**; `vachpxkd` ARM64 is **BLOCKED** (architecture). |

**Scope note.** This pass re-derives the old verdicts under the current scope (`R2` included, setup a severity
field, hardware-only writes excluded). The historical reports were used only as pointers to code; every
verdict below rests on the re-disassembled image. Three historical conclusions changed materially and are
flagged inline:

1. `cam_driver_mb`'s Everyone SDDL is **live but unusable** - a create-time `SeSinglePrivilegeCheck`
   (`SeSystemProfilePrivilege`) gates the open (old report: "openable by Everyone").
2. `SiUSBXp` **does have an IOCTL surface** (`IRP_MJ_DEVICE_CONTROL` at `+0xE0`), which the old report
   declared "not applicable". That surface contains a caller-controlled transfer length.
3. `SMI_IO`'s unbounded input-length stack copy is the **primary** primitive, not a side note, and under
   `R2` it is reachable (old report: "blocked by DACL", i.e. no finding).

## 1 Files, hashes, build data

All hashes were computed locally with `Get-FileHash -Algorithm SHA256` on
`C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\` and match the name suffixes.

| # | File | SHA-256 | Arch | PE TS | Size |
|---|---|---|---|---|---|
| 1 | `cam_driver_mb_A9C246FD.sys` | `A9C246FD1466C017AC61768E75BFC19DFE7BEE5AF683935BF78716EFF5F3794E` | AMD64 | 2024-12-16 | 72,224 |
| 2 | `SiLib_DD2C9A1D.sys` | `DD2C9A1D25C408B1CF2DFC9BC5CC96F64AC1BD5B6C431B59E149ED6177FDF125` | AMD64 | 2010-07-15 | 34,992 |
| 3 | `SiUSBXp_A8BE9E3F.sys` | `A8BE9E3F5A3913BA80B4C7D9FCF6B39ED8509193D1FEA924F48344C274578789` | AMD64 | 2010-07-15 | 29,872 |
| 4 | `SMI_IO_32_B198D7E1.sys` | `B198D7E19ACE2080A86F6F855CA745B71CBFBFD6FD0E21850FE3864A19E6F072` | I386 | 2016-03-18 | 16,056 |
| 5 | `SMI_IO_64_89A4F4DC.sys` | `89A4F4DC8D3FF97993DB965760B708A48863135075BF0CE7A9A8CC8EE9B7A5E8` | AMD64 | 2016-03-18 | 16,056 |
| 6 | `vachpxkd_94A275C1.sys` | `94A275C1B8612050EE33D97222A31AE88712A1A049656341B8E12B30C4EED3A1` | **ARM64** | 2025-09-17 | 230,064 |
| 7 | `vachpxkd_F56EF5B5.sys` | `F56EF5B54955DFCB6E3AFC697BC5DDE49FCEE908839EBE9BE2D8F413DCEE811E` | AMD64 | 2025-09-17 | 242,352 |
| 8 | `PawnIO_4383A699.sys` | `4383A699EED9DE0CF73ECA3739B227DC07769E964381867DD482BF0760BF94CC` | AMD64 | 2006-08-15 (metadata anomaly) | 126,016 |

All eight carry an embedded Authenticode blob (non-zero Security Directory). The signer chain and WHQL
status were **not** validated statically; no image is listed in `indexes/dedupe/known_bad_hashes.txt`
(spot-checked by hash prefix).

## 2 Per-file verdict table

| File | Device / entry | Effective DACL | Open gate | Setup | Reach | Write | Verdict |
|---|---|---|---|---|---|---|---|
| `cam_driver_mb` | KMDF control device `\Device\CAMDriverMB` + `\DosDevices\CAMDriverMB` | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)` - **Everyone GRGW** | **`SeSystemProfilePrivilege` required in EvtFileCreate** (SDDL is neutralised) | service | R2 | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| `SiLib` | none (support library; no `IoCreateDevice`) | n/a | n/a | hardware | R3 | W0 | **NO-MEMORY-WRITE** |
| `SiUSBXp` | unnamed exclusive FDO, device interface, DC at `+0xE0` | none set in binary -> default device SD (INF Security not in corpus) | interface handle | hardware | R3 | W2 | **MW3** |
| `SMI_IO_32` | `\Device\SMI_IO` + `\DosDevices\SMI_IO` (`DeviceType 0x8033`) | default device SD (no SDDL, plain `IoCreateDevice`) | admin (R2) | service | R2 | W2 (+W3P) | **MW2** |
| `SMI_IO_64` | same | same | admin (R2) | service | R2 | W2 (+W3P) | **MW2** |
| `vachpxkd` ARM64 | PortCls adapter (PnP) | not in package | audio devnode | devnode | R3 | W2 (reference) | **BLOCKED** (ARM64) |
| `vachpxkd` x64 | PortCls adapter, KS filter; DC via thunk `0x1B690` -> `0x1B350` | not in package; PortCls audio default (user-openable by design) | audio devnode + spoofable `audiodg` name check | devnode | R3 | W2 | **MW3** |
| `PawnIO` | `\Device\PawnIO` + `\DosDevices\PawnIO` (unnamed FDO + symlinks), `DeviceType 0xA1B2` | INF-declared `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (INF not in corpus) + default device SD | admin (R2) | devnode | R2 | W0 | **NO-MEMORY-WRITE** (RSA-gated) |

## 3 NZXT `cam_driver_mb_A9C246FD.sys` - NO-MEMORY-WRITE (HW-ONLY)

### 3.1 Internals
KMDF driver (Rust, `cam-driver-mb\src\device.rs`), bound through `WdfVersionBind`; all WDF services are
indirect calls through the function table at `DAT_18000D338`. PE entry `0x180009420` is a CRT/init wrapper
that reaches `DriverEntry` at `0x18000F000`.

### 3.2 Device, effective DACL, and the gate that actually matters
`DriverEntry` creates a **control device**, not a PnP FDO:

* `0x18000F19A  LEA R8,[0x18000B1E8]`
  `0x18000F1A4  CALL qword ptr [RAX+0xC8]` -> `WdfControlDeviceInitAllocate(driver, &SDDL)`.
* The UNICODE_STRING at `0x18000B1E8` has `Length=0x72`, `MaximumLength=0x74`, `Buffer=0x18000B170`; the
  buffer decodes exactly to `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)`.
* `0x18000B220` -> `\Device\CAMDriverMB` (`WdfDeviceInitAssignName`, table `+0x218`);
  `0x18000B280` -> `\DosDevices\CAMDriverMB` (table `+0x280`); `WdfDeviceCreate` (table `+0x258`).

So the SDDL requested is real and permissive: **Everyone `GRGW`**, i.e. `GENERIC_READ|GENERIC_WRITE`.
That is *not* the effective gate, however. `DriverEntry` also installs a file-object config:

* `0x18000F35A  LEA RAX,[0x1800013E0]` -> stored as `EvtFileCreate`; `0x18000F3A0  CALL [RAX+0x238]`
  (`WdfDeviceInitSetFileObjectConfig`), with `WDF_FILEOBJECT_CONFIG.Size = 0x28`,
  `EvtFileCreate = 0x1800013E0`, `EvtFileClose = EvtFileCleanup = NULL`, `FileObjectClass = 2`,
  `AutoForwardCleanupClose = 4` (packed `0x400000002`).
* `FUN_1800013E0` (EvtFileCreate) does:
  `WdfRequestGetRequestorMode` (table `+0x8C0`), then `SeSinglePrivilegeCheck(10, mode != KernelMode)`;
  failure completes the create with `0xC0000022` (`STATUS_ACCESS_DENIED`).

LUID 10 is `SeSystemProfilePrivilege`. The SDDL therefore only describes the DACL; the **effective open
gate is `SeSystemProfilePrivilege`**, which a standard user does not hold and an administrator can enable.
Reach is **R2**, not R1. This corrects the historical report.

### 3.3 IOCTL surface
Dispatcher `FUN_180002CB0` (12.2 KB, state machine). Range check:

```
180002D93  LEA EAX,[RBX+0x7FFF6000]      ; code - 0x8000A000
180002D99  CMP EAX,0x18
180002D9C  JA  default
180002DA2  LEA RCX,[0x18000C204]         ; 25-entry jump table
180002DAD  ADD RAX,RCX / JMP RAX
```

| IOCTL | Method | Access | Handler | Kernel action |
|---|---|---|---|---|
| `0x8000A000` | BUFFERED | WRITE | `0x180002DB2` | min input 1; sub-command 0..4 selects a fixed SIO descriptor index; Super-I/O port writes (0x2E/0x2F) and reads; chip-ID `0xD428/0xD800` triggers per-channel MMIO |
| `0x8000A004` | BUFFERED | WRITE | `0x1800034DA` | 1 byte in / 1 byte out, device-state machine |
| `0x80006008` | BUFFERED | READ | `0x180003A39` | 0x2D-byte sensor snapshot |
| `0x8000A00C` | BUFFERED | WRITE | `0x180003615` | 0xB-byte input, state-gated |
| `0x80006010` | BUFFERED | READ | `0x180003442` | 4-byte in / 4-byte out |
| `0x8000A014` | BUFFERED | WRITE | `0x180003845` | 3-byte input, state-gated |
| `0x8000A018` | BUFFERED | WRITE | `0x1800038D3` | `WdfRequestRetrieveInputBuffer(..., 0x22)`; validates bytes 0, 0x1F, 0x20/0x21, then a 5-entry jump table at `0x18000C268` |
| other method variants | NEITHER/DIRECT | - | `0x180003C14` | completes with current status, no action |

Every retrieval is length-checked by KMDF against an explicit minimum
(`0x180002DED MOV R8D,1`; `0x180003650 MOV R8D,0xB`; `0x18000390E MOV R8D,0x22`;
`0x180003A74 MOV R8D,0x2D`), so there is no caller-length copy anywhere in the file (no `memcpy`,
`RtlCopyMemory`, `MmCopyMemory`, or MDL import at all).

### 3.4 Write sinks (all hardware or context)
* **Port I/O**: `OUT 0x2E/0x2F` sequences in `FUN_180001490` and the dispatcher (detection, register
  programming). Fixed port pair, fixed register sequences, values from the user buffer - hardware write.
* **MMIO**: `MmMapIoSpaceEx(0xFEC40000, 0xC, 0x204)` for the LPC/eSPI window, and per-channel
  `MmMapIoSpaceEx((uint)*puVar37 + iVar21 + (uint)(byte)puVar37[1] * 0x10000, 4, 0x204)`.
  `puVar37 = (&PTR_DAT_18000B680)[uVar36 * 3]`, `iVar21 = *(int *)(&UNK_18000B690 + uVar36*0x18)`.
  The index is **not** user data: the sub-command switch at `0x180002EE7` assigns
  `uVar20 = CONCAT71(uVar44, n)` with `n in {1,2,3,4}` (case 0 -> 4), and `uVar36 = uVar20 & 0xFF`.
  All five indices are in-table. The MMIO base is therefore chip-table-derived and bounded, not
  caller-chosen.
* **Device context**: fixed offsets (`+0x28`, `+0x260 + idx*0x10`, ...).

`HalGetBusDataByOffset` is used read-only for PCI config. No `HalSetBusData*`, no `MmGetPhysicalAddress`,
no `KeStackAttachProcess`, no `ZwMapViewOfSection`.

### 3.5 Verdict
**NO-MEMORY-WRITE (HW-ONLY), R2, setup=service, W0.** The permissive Everyone DACL is a real SDDL and is
genuinely applied, but `EvtFileCreate` requires `SeSystemProfilePrivilege`, so only an administrator (or
SYSTEM) can open the device. What is exposed behind that gate is fan/RGB/GPIO/Super-I/O control, not a
memory write.

## 4 NZXT `SiLib` + `SiUSBXp` - support library plus a hardware-gated pool OOB

### 4.1 `SiLib_DD2C9A1D.sys` - NO-MEMORY-WRITE
Silicon Laboratories "Generic" support library. Complete decompile: 80 functions, all `Generic*`
(dispatch PnP/power, request queues, idle detection, `IoRegisterDeviceInterface`). It imports no
`IoCreateDevice`, no `IoCreateSymbolicLink`, no `Mm*` memory API, and owns no device object or IOCTL
handler of its own. It is a component of `SiUSBXp`; on its own it is inert. **W0, NO-MEMORY-WRITE.**

### 4.2 `SiUSBXp_A8BE9E3F.sys` - device and gate
`DriverEntry` `0x15008` (PE entry `0x19064` -> `FUN_00015008`) installs:

| Slot | Routine |
|---|---|
| `DriverUnload` (`+0x68`) | `LAB_000137D4` |
| `AddDevice` (`DriverExtension+0x8`) | `FUN_000137E8` |
| `IRP_MJ_CREATE` (`+0x70`) | `FUN_00013DB4` |
| `IRP_MJ_CLOSE` (`+0x80`) | `FUN_00013F9C` |
| `IRP_MJ_WRITE` (`+0x90`) | `FUN_00014834` |
| `IRP_MJ_CLEANUP` (`+0x100`) | `FUN_00013D68` |
| **`IRP_MJ_DEVICE_CONTROL` (`+0xE0`)** | **`FUN_00013008`** |
| `IRP_MJ_INTERNAL_DEVICE_CONTROL` (`+0xE8`) | `FUN_000110F4` |
| `IRP_MJ_PNP` (`+0x148`) | `FUN_00013BF8` |

`AddDevice` `0x137E8` calls
`IoCreateDevice(DriverObject, GetSizeofGenericExtension()+0x240, NULL, 0x22, 0x80 /*exclusive*/, 0, ...)`:
unnamed, no SDDL, `DO_BUFFERED_IO` set (`+0x30 |= 4`) and `DO_DEVICE_INITIALIZING` cleared. User reach is
the device interface registered by `GenericRegisterInterface(ext, &DAT_00016160)` (interface GUID lives in
SiLib's generic extension). The literal `\DosDevices\USBINT` is copied into the extension but **never
published as a symlink**. The binary sets no DACL; the effective DACL is the default device SD unless the
package INF overrides it (INF not in corpus). Either way the surface requires the physical USB device:
`Setup = hardware`, reach **R3**.

### 4.3 IOCTL table (`FUN_00013008`, all METHOD_BUFFERED, `FILE_ANY_ACCESS`, device `0x2220`)
`SystemBuffer = Irp->AssociatedIrp.SystemBuffer`; `+0x8` = OutputBufferLength, `+0x10` = InputBufferLength,
`+0x18` = IoControlCode.

| IOCTL | Check | Action |
|---|---|---|
| `0x222008` | out >= 0x12 | copy 0x12 bytes of extension state to `SystemBuffer` |
| `0x22200C` | out >= 9 | copy 9 bytes of extension state |
| `0x222014` | out > 0x2F | copy 0x30 bytes of extension state |
| `0x222018` | out >= ext->`+0x88` | zero output length, copy `ext->+0x88` bytes (bounded) |
| **`0x222024`** | **out != 0 only** | **build an URB from the input and submit it; `TransferBuffer = SystemBuffer+8`, `TransferBufferLength = *(u16*)(input+6)`** |
| **`0x222028`** | **out != 0 only** | same URB pattern; `TransferBuffer = SystemBuffer+8`, length from `input+6` (or a descriptor word) |
| `0x222080` | out != 0 | queue/read state, length clamped to `min(state, out)` |
| `0x222084` | out != 0 | **write 4 bytes to `SystemBuffer`** (state dword) |
| `0x222088` | in != 0 | reset/select from `*SystemBuffer` (reads 8 bytes) and submit a class URB; no system-buffer write |

### 4.4 Caller-controlled length -> pool OOB (W2)
At `0x222024` the handler reads the URB descriptor from the **input** buffer but the transfer buffer is the
**output/system** buffer plus 8:

```
local_57 = *(u8  *)(SystemBuffer + 1);      // direction/type selector
local_56 = *(u16 *)(SystemBuffer + 2);      // pipe / index
local_54 = *(u16 *)(SystemBuffer + 4);
local_b4 = *(u16 *)(SystemBuffer + 6);      // TransferBufferLength  <-- caller
local_b0 = SystemBuffer + 8;                // TransferBuffer
... FUN_000141A8(devobj, &urb) -> IoBuildDeviceIoControlRequest(0x220003, lower, ...)
```

For `METHOD_BUFFERED` the I/O manager allocates exactly `max(InputBufferLength, OutputBufferLength)`. The
handler only requires `OutputBufferLength != 0`; it never requires the allocation to cover
`8 + TransferBufferLength`. A caller can therefore send an 8-byte input (controlling the 16-bit length)
with a 1-byte output, producing a URB whose transfer buffer starts exactly at the end of the pool block and
whose length is up to 0xFFFF. The USB stack maps that buffer by VA/length; a USB device that answers with
more data than the block holds causes the host controller to write past the allocation into adjacent
non-paged pool. `0x222028` has the same shape.

Constraints: the driver only exists when a matching Silicon Labs USB device enumerates (`Setup = hardware`);
the *data* written is supplied by the device, so the attacker needs a device they control (or a
controllable device firmware). The *length* is caller-controlled and unchecked. This is a constrained,
hardware-gated pool OOB: **W2 / MW3**. It is not a caller-chosen kernel destination.

### 4.5 Secondary
`0x222084` writes 4 bytes to `SystemBuffer` after checking only `OutputBufferLength != 0`; with
`InputBufferLength < 4` the allocation can be smaller than 4 bytes (<=3-byte pool overrun). Fixed size,
fixed value -> W3, not the verdict driver. `0x222088` reads 8 bytes after checking only
`InputBufferLength != 0` (OOB read).

### 4.6 Verdict
`SiUSBXp`: **MW3 - reach=R3 setup=hardware write=W2**. `SiLib`: **NO-MEMORY-WRITE (W0)**.

## 5 Netac `SMI_IO` (Silicon Motion) - MW2, both builds

### 5.1 Device and effective DACL
Both builds are 16,056 bytes and share the same logic, with the expected x86/x64 differences.

* x64 `DriverEntry` `FUN_00011150` @ `0x11150`:
  `RtlInitUnicodeString(&u, L"\\Device\\SMI_IO")`; `IoCreateDevice(DriverObject, 0, &u, 0x8033, 0, 0, &dev)`;
  then `MajorFunction[0x0E] = MajorFunction[2] = MajorFunction[0] = FUN_00011270`,
  `DriverUnload = FUN_000115B0`; `\DosDevices\SMI_IO` symlink.
* x86 `DriverEntry` `FUN_00011010` @ `0x11010`: same logic; `MajorFunction[0x0E] = MajorFunction[2] =
  MajorFunction[0] = FUN_000110C0`, `DriverUnload = FUN_00011480`.

Plain `IoCreateDevice` with no SDDL and no `IoCreateDeviceSecure`: the effective DACL is the I/O manager's
default device descriptor (owner SYSTEM; full control SYSTEM + Builtin\Administrators; no Everyone/Users
ACE). **R2** is the reach (the requester is a local administrator). Neither build imports
`SeSinglePrivilegeCheck`, `SeTokenIsAdmin`, or `IoValidateDeviceIoControlAccess`; `IRP_MJ_CREATE` returns
success unconditionally, so the DACL is the only gate and no `FILE_WRITE_ACCESS` check exists.

### 5.2 IOCTL table
x64 dispatcher `FUN_00011270` @ `0x11270`; `IO_STACK+0x10` = InputBufferLength, `+0x18` = IoControlCode.
All METHOD_BUFFERED, `FILE_ANY_ACCESS`.

| IOCTL | x64 handler | x86 handler | Gate | Action |
|---|---|---|---|---|
| `0x803320CC` | `FUN_00011600` | `FUN_000114D0` | `in != 0` | `MmMapIoSpace(phys, size, MmNonCached)` -> `IoAllocateMdl` -> `MmBuildMdlForNonPagedPool` -> `MmMapLockedPages(mdl, TRUE)`; user VA returned in the output buffer |
| `0x803320D0` | `FUN_00011830` | `FUN_00011720` | `in != 0` | unmap by VA (table lookup) |
| `0x803320D4` | - | inline | none | **x86 only**: `MmAllocateNonCachedMemory(0x2000)` = zeroed IOPM -> `Ke386IoSetAccessProcess` + `Ke386SetIoAccessMap(1, map)` |
| `0x803320D8` | - | inline | none | **x86 only**: IOPM teardown |
| `0x803320DC` | inline | inline | `in != 0` | port read (byte/word/dword), result written as 4 bytes to `SystemBuffer` |
| `0x803320E0` | inline | inline | `in != 0` | port write (byte/word/dword) |

`phys` and `size` for `0x803320CC` come straight from the input struct (`{u32 size; u32 pad; u64 phys}`)
with no `MmGetPhysicalMemoryRanges` check, no window check, no size cap. `MmMapLockedPages(..., TRUE)`
creates a user-accessible mapping and the VA is copied back. That is arbitrary physical read/write - a
**W3P** primitive -> MW3 on its own.

### 5.3 Primary primitive: unbounded input-length copy onto the kernel stack (W2)
All four data handlers copy **InputBufferLength** bytes from `SystemBuffer` into a small stack local.

x64 `FUN_00011270`:

```
112DC   MOV EAX,[RAX+0x10]          ; InputBufferLength
...
11497   MOV ECX,[RSP+0x20]          ; length
1149B   LEA RDI,[RSP+0x28]          ; 8-byte local
114A0   MOV RSI,[RSP+0x70]          ; SystemBuffer
114A5   REP MOVSB                   ; unbounded
...
11594   ADD RSP,0x98 / POP RDI / POP RSI / RET   ; no GS cookie check
```

Equivalent unbounded `REP MOVSB` sites exist for the other three cases (`0x11372`, `0x113FE`, `0x11530`);
the copy-back at `0x114DE` uses the same length. Frame is `0xA8` bytes below the return address and the
destination starts at `RSP+0x28`, so a length above ~0x80 overwrites saved registers and the return
address; the epilogue has **no `/GS` cookie check**, so the overwrite reaches `RET` directly.

x86 `FUN_000110C0` @ `0x110C0` is the same shape with `memcpy`:

```
11309   MOV ECX,[EBP-0x4]          ; InputBufferLength
1130D   MOV EDX,[EBP-0x40]         ; SystemBuffer
11311   LEA EAX,[EBP-0x1C]         ; 8-byte local
11315   CALL memcpy
...
113DD   MOV ESP,EBP / POP EBP / RET 8   ; no cookie check
```

Frame is `0x50`; the destination is `EBP-0x1C`, so a length above ~0x20 overwrites saved `EBP`, the return
address and the callee's arguments. The same `memcpy(local, SystemBuffer, InLength)` pattern is used by
`0x803320D0`, `0x803320DC` and `0x803320E0` (destinations of 8, 7 and 7 bytes respectively), so all four
codes are usable as the overflow trigger.

Caller controls: length (32-bit, only tested `!= 0`), content (all bytes), destination (fixed stack
region, then linear). This is a kernel stack buffer overflow - the Sandboxie `SbieDrv` class of finding -
so **W2**. Rated on its own it is MW2 at R2. No KASLR leak is needed because the target is the stack, not
an absolute address; the return-address value is the only address the attacker must know, which is the
normal stack-overflow caveat.

### 5.4 Secondary x64 write
`0x803320DC` does `*SystemBuffer = value` (4 bytes) after checking only `InputBufferLength != 0`. With a
small output length the system buffer can be 1-3 bytes, giving a <=3-byte pool overrun. Fixed size and
driver-derived value -> W3.

### 5.5 Build differences (material)
* `0x803320D4/D8` (IOPM grant/revoke) exist only in the **x86** build. They hand the calling process a
  zeroed 8 KB I/O permission bitmap (all 65,536 ports at CPL3) with no token check - hardware-only, but a
  strong port-I/O enabler. `HW-ONLY`.
* x64 has inline `in`/`out` helpers (`FUN_00011010`-`FUN_000110C0`) for `0x803320DC/E0`; x86 uses
  `READ_PORT_*`/`WRITE_PORT_*`.
* Both share the stack overflow and the physical map. There is no other material difference.

### 5.6 Verdict
**MW2 - reach=R2 setup=service write=W2 load=signed** (both builds). The physical map alone would be
**MW3/W3P**; the unbounded stack copy raises the file to MW2. The x86 IOPM IOCTLs are HW-ONLY.

## 6 HyperX / HP `vachpxkd` - MW3 (x64); BLOCKED (ARM64)

### 6.1 Device and DACL
PortCls/KS virtual audio driver (`"HyperX Virtual Audio Device ..."`, `"Virtual Audio Cable"`).

* `DriverEntry` `FUN_0001B750` @ `0x1B750`: creates a fixed 0xC000 section
  (`MmCreateSection` -> `MmMapViewInSystemSpace`), `PcInitializeAdapterDriver`, then hooks
  `IRP_MJ_CREATE = 0x1B330`, `IRP_MJ_CLOSE = 0x1A7D0`, `IRP_MJ_DEVICE_CONTROL = 0x1B690`.
* The DC thunk at `0x1B690` tail-jumps to `FUN_0001B350` @ `0x1B350`.
* No `IoCreateDevice` and no `IoCreateSymbolicLink` import; the adapter FDO is created by
  `PcAddAdapterDevice` when the devnode starts. There is no legacy control device.

No INF is in the corpus and the image contains no `D:P(...)` string, so the effective DACL is the
PortCls/KS default for an audio devnode (audio endpoints are user-openable by design). `Setup = devnode`,
reach **R3**. This is an inference from the surface type, not an observed DACL.

### 6.2 Property / IOCTL surface (`FUN_0001B350`)
`FUN_0001B350` first gives the IRP to `FUN_000126C0` (PortCls path); only on
`STATUS_INVALID_DEVICE_REQUEST` (`0xC0000016`) does it handle its own codes.

| IOCTL | Method | Handler | Notes |
|---|---|---|---|
| `0x2F0003` | NEITHER | `FUN_00022160`, `FUN_00025A10`, `FUN_0002A8F0` | `IOCTL_KS_PROPERTY`; input `KSPROPERTY` probed with `ProbeForRead` (0x18 bytes, `in >= 0x18`) |
| `0x2F001B` | NEITHER | `FUN_000245B0` | `IOCTL_KS_RESET_STATE` |
| `0x2F4017` | NEITHER | `FUN_00024D80` | `IOCTL_KS_READ_STREAM`; `KsProbeStreamIrp` first |
| `0x2F8013` | NEITHER | `FUN_00024D80` | `IOCTL_KS_WRITE_STREAM`; `KsProbeStreamIrp` first |
| other | - | `PcDispatchIrp` | standard PortCls |

The audio set `{45FFAAA0-6E1B-11D0-BCF2-444553540000}` (ids 5/0x32) goes to `FUN_00025A10`, which uses
`FUN_0001B950`/`FUN_0001B9D0` - both probe correctly (`ProbeForRead`/`ProbeForWrite` at `0x1B950`/`0x1B9D0`).
The stream path runs `KsProbeStreamIrp` first.

### 6.3 The write: `FUN_00022160` writes to a raw `Irp->UserBuffer`
For a property set that is neither of the two known sets, `FUN_0001B350` leaves the request class at
"vendor" and calls `FUN_00022160` @ `0x22160`. That function re-reads the property header from
`IrpSp->Type3InputBuffer` (unprobed, so a double-fetch of the header) and, for
set `{8C134960-51AD-11CF-878A-94F801C10000}` (`0x221AC`), id 8, flags bit 0 set (GET):

```
22199   MOV RAX,[RDX+0xB8]          ; IrpSp
221A0   MOV R12D,[RAX+0x8]          ; OutputBufferLength
221A8   MOV R14,[RDI+0x70]          ; R14 = Irp->UserBuffer  (raw caller output pointer)
22225   CMP byte ptr [ctx+0x9C2],0
22234   CALL IoGetCurrentProcess / CMP PsInitialSystemProcess
22249   CMP R12D,8 ; JB fail        ; OutputBufferLength >= 8
2225E   CALL 0x1BA70                ; ZwQueryInformationProcess(ProcessImageFileName) -> base name
22273   CALL _wcsicmp(name, L"audiodg")
22299   MOV R11,[R13+0x40]
2229D   MOV EAX,[R11+0x4B4]         ; value = driver "CurrentCount" field
222A4   MOV [R14],EAX               ; <-- 4 bytes at caller-chosen address
222A7   MOV [R14+4],EBX             ; <-- 4 zero bytes
```

There is **no** `ProbeForWrite` on `R14`; the only `ProbeForWrite` in the whole image is inside
`FUN_0001B9D0`. `Irp->UserBuffer` is the raw `OutputBuffer` argument: in the local `ntoskrnl` artifact,
`IopXxxControlFile` stores it unmodified for METHOD_NEITHER
(`0x14060666E MOV RAX,[RSP+0x190]`; `0x140606676 MOV [RSI+0x70],RAX`). The only pre-dispatch clamp in that
function is applied to the *I/O status block* (`0x140605CA1`-`0x140605CBE`, clamp to `0x7FFFFFFF0000`), and
the only `ProbeForWrite` is on the METHOD_BUFFERED output path (`0x140605CE1`). So a caller-supplied kernel
address reaches the driver as-is.

Primitive: **8-byte write, arbitrary kernel address, constrained value** (`{driver count dword, 0}`), no
probe, no alignment check. Constraints/gates:

* the virtual audio devnode must exist (`Setup = devnode`);
* a per-adapter flag at `ctx+0x9C2` must be zero (default) and the caller must not be the system process;
* `OutputBufferLength >= 8`;
* current process image base name must be `audiodg` (checked with `_wcsicmp` after stripping path and
  extension). This is an image-name check, **not** a signer or protected-process check: any local process
  whose executable is named `audiodg.exe` satisfies it. The gate is effectively cosmetic;
* the value is a driver field (the "global cable instance count"), not attacker data.

Because the target is an absolute kernel address and the driver exposes no kernel pointer leak on the
reviewed paths, the write needs a separately obtained KASLR leak. Conservative rating: **W2** (arbitrary
target, constrained value) at **R3** -> **MW3**. If the devnode is treated as already present and a leak is
available, this is a straight MW2-class write-what-where.

### 6.4 ARM64 build `vachpxkd_94A275C1.sys`
COFF machine `0xAA64`, image base `0x140000000`. It is the same source: the same three property-set GUIDs
are present as literals (vendor/audio/`1D58C920`), and the reviewed x64 functions have direct counterparts.
It cannot load on an x64 host: **BLOCKED (architecture)**, with the same W2 primitive recorded as a
reference only. It is not counted in the group total.

## 7 PawnIO `PawnIO_4383A699.sys` - NO-MEMORY-WRITE (RSA-gated by design)

### 7.1 Device and DACL
`AddDevice` `FUN_1400019C0` @ `0x1400019C0`:

```
IoCreateDevice(DriverObject, 0x10, NULL, 0xA1B2, 0, 0, &dev)   // unnamed FDO
IoGetDeviceProperty(PDO, DevicePropertyPhysicalDeviceObjectName=0xB, ...)
IoCreateSymbolicLink(\Device\PawnIO   -> \Device\000000xx)
IoCreateSymbolicLink(\DosDevices\PawnIO -> \Device\000000xx)
```

The binary contains no SDDL literal. The device is admin-only by two independent routes: the historical INF
declares `D:P(A;;GA;;;SY)(A;;GA;;;BA)` under `[Custom_Security]`, and the FDO created with a NULL SD takes
the default device descriptor (SYSTEM + Administrators). The INF is no longer in the corpus, so the DACL
statement is INF-plus-default rather than a fresh observation. Reach **R2**, setup **devnode**
(`Root\PawnIO`, `SoftwareDevice`).

### 7.2 IOCTL table (`FUN_140001BD0` @ `0x140001BD0`, all METHOD_BUFFERED)
| IOCTL | Handler | Gate |
|---|---|---|
| `0xA1B22084` | `FUN_140010EA0` -> `FUN_140010FE0` | RSA signature over the module; one module per handle |
| `0xA1B22104` | `FUN_140010BA0` | requires a loaded module; interpreter, input and output are the same system buffer |
| `0xA1B22184` | inline | `OutputBufferLength == 4`; writes version `0x20200` |
| `IRP_MJ_CREATE`/`CLOSE` | `FUN_140001BD0` | close frees the module |

### 7.3 Signature gate (no bypass found)
`FUN_140010FE0` @ `0x140010FE0`:

1. `len > 3`, `sig_len = *(u32*)in`, `sig_len <= len - 4`;
2. body = `in + 4 + sig_len`, body length = `len - sig_len - 4`; SHA-256 via `FUN_140003320`;
3. loop over the embedded public-key table (`DAT_140012950`, `PTR_DAT_140012B70`) calling
   `FUN_140003480` @ `0x140003480`: `BCryptImportKeyPair(RSAPUBLICBLOB)` +
   `BCryptVerifySignature(key, "SHA256", hash, 0x20, sig, sig_len, 2)` (PKCS#1 v1.5);
4. any failure returns before the `ExAllocatePoolWithTag`/`FUN_1400119C0` copy.

The key blobs are in the driver's read-only data; there is no alternate loader, flag, or unsigned branch.
The module body is copied with a bounded helper.

### 7.4 Host API reachable only from a signed module
The interpreter exposes `physical_read_*`/`physical_write_*` (1-8 bytes, via `MmGetVirtualForPhysical` or
`MmMapIoSpace`), `io_space_map`, `virtual_read_*`/`virtual_write_*`, `pci_config_read_*`/`pci_config_write_*`
(`HalSetBusDataByOffset`), `msr_read`/`msr_write` (`rdmsr`/`wrmsr`), and `cr_*`/`dr_*`/`xcr_*`. These are
real arbitrary physical/PCI/MSR primitives, but they are reachable only by a module carrying a valid PawnIO
signature. A holder of the vendor signing key (or a legitimately signed module that itself fails to filter
its arguments) would inherit them; an administrator without such a module cannot.

### 7.5 Verdict
**NO-MEMORY-WRITE - reach=R2 setup=devnode write=W0 load=signed.** The admin-only DACL is no longer a
barrier under the current scope, but the RSA signature gate is: no unsigned path to the host API exists in
the image. The conditional capability is recorded here as a design property, not as a finding.

## 8 Family comparison - material differences only

| Family / build | Interface | Reach | Gate that actually binds | Primitive | Verdict |
|---|---|---|---|---|---|
| NZXT `cam_driver_mb` | KMDF control device, Everyone-GRGW SDDL | R2 | `SeSystemProfilePrivilege` in EvtFileCreate | port I/O + table-fixed MMIO | NO-MEMORY-WRITE (HW-ONLY) |
| NZXT `SiLib` | none | - | - | none | NO-MEMORY-WRITE |
| NZXT `SiUSBXp` | unnamed FDO + interface, DC `+0xE0` | R3 | physical device | caller 16-bit transfer length over `SystemBuffer+8` | MW3 (W2) |
| Netac `SMI_IO_64` | `\Device\SMI_IO`, default SD | R2 | admin DACL only | unbounded `REP MOVSB` (4 codes) + arbitrary phys map | **MW2** (W2/W3P) |
| Netac `SMI_IO_32` | same | R2 | admin DACL only | unbounded `memcpy` (4 codes) + phys map + IOPM | **MW2** (W2/W3P) |
| HyperX `vachpxkd` x64 | PortCls KS filter (devnode) | R3 | devnode + spoofable `audiodg` name | unprobed `Irp->UserBuffer` 8-byte write | MW3 (W2) |
| HyperX `vachpxkd` ARM64 | same source | - | not loadable | same reference | BLOCKED (arch) |
| PawnIO | `\Device\PawnIO`, admin-only | R2 | RSA signature on modules | physical/PCI/MSR only via signed module | NO-MEMORY-WRITE |

The eight builds do not share code. The only cross-family pattern worth noting is that the two strongest
surfaces are **old, small, non-WDF WDM drivers** (`SMI_IO` 2016; `SiUSBXp` 2010) whose dispatch routines
copy or transfer `InputBufferLength`-derived lengths with only a `!= 0` test, while the two modern WDF/PortCls
drivers (`cam_driver_mb`, `vachpxkd`) use exact-length retrievals and probe their inputs - their weak points
are respectively an over-broad DACL that a create-time privilege check happens to cover, and one handler
that bypasses the driver's own probe helper.

## 9 Limitations and unresolved paths

1. **No dynamic confirmation.** Nothing was loaded, installed, or opened. Every "reachable" statement is a
   static reachability argument; the device DACLs for `vachpxkd`, `SiUSBXp` and `PawnIO` depend on INFs that
   are not in the corpus (historical evidence used for PawnIO). The `cam_driver_mb` gate, by contrast, is
   read directly from `EvtFileCreate` and does not depend on the INF.
2. **REA not used.** Four REA sessions were active; this pass is Ghidra/objdump only, as permitted by
   `STATIC_ANALYSIS_AGENT_PROMPT.md` rule 6 and required by the task. No REA evidence IDs exist for this
   report.
3. **SMI_IO stack overflow.** The write is unconditional (length/content controlled) and the dispatchers have
   no `/GS` check, but reliable control-flow hijack still depends on the target build's stack layout and on
   defeating kernel CFG/SMEP after the return. The verdict does not rely on a working chain - the
   out-of-bounds kernel-stack write itself is the finding.
4. **SiUSBXp.** The OOB is only reachable with a Silicon Labs USB device enumerated on the stack, and the
   write payload comes from the device side. The 16-bit length and the `SystemBuffer+8` placement are
   caller-controlled; the *data* is not. The exact USBD/HCD behaviour for a class-request URB with an
   overlarge `TransferBufferLength` was not observed.
5. **HyperX.** `FUN_00022160` is a double-fetch of the unprobed property header; only the write path was
   fully traced. Other custom property handlers (`FUN_0002A8F0` callers, the stream path) were reviewed at
   the level of their buffer helpers; no second unprobed write was found, but the 532-function image was not
   proven free of one. `FUN_00022160`'s `audiodg` gate is spoofable but was not exercised.
6. **Signatures.** Embedded Authenticode is present in all eight images; the chains were not validated and
   no image was checked against the Microsoft vulnerable-driver blocklist beyond a hash-prefix spot check.
   None of the eight is in `indexes/dedupe/known_bad_hashes.txt`.
7. **`SMI_IO` port I/O and `SiUSBXp` 4-byte system-buffer write** are recorded as secondary (HW-ONLY / W3);
   neither changes a family verdict.

## 10 Overall verdict

**MW2 - reach=R2 setup=service write=W2 load=signed.**

The group's strongest reachable kernel memory write is in **Netac `SMI_IO` (both builds)**: four
`METHOD_BUFFERED` IOCTLs copy the caller-supplied `InputBufferLength` into an 8-byte kernel-stack local with
only a non-zero test, on dispatchers that have no `/GS` cookie check; the same driver also maps an arbitrary
physical range read/write into the caller (`W3P`). Under the current scope the default admin-only DACL does
not block the requester, so this is no longer a "blocked by DACL" reference.

Two **MW3** primitives sit below it:
* **HyperX `vachpxkd` x64** - an unprobed `METHOD_NEITHER` output write (`0x222A4`) to `Irp->UserBuffer`,
  i.e. an arbitrary-address 8-byte write of a constrained value, behind a devnode and a spoofable image-name
  check; the ARM64 sibling is BLOCKED.
* **NZXT `SiUSBXp`** - a caller-controlled 16-bit URB transfer length over `SystemBuffer+8`, giving a
  hardware-gated pool OOB via the USB host controller.

The remaining four files are **NO-MEMORY-WRITE**: `cam_driver_mb` is HW-ONLY behind a
`SeSystemProfilePrivilege` create gate (the Everyone SDDL is real but not usable), `SiLib` is an inert
support library, and `PawnIO`'s physical/PCI/MSR API is reachable only through RSA-signed modules.
