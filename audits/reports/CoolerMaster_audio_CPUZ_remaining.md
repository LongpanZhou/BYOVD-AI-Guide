# Audit: CoolerMaster C-Media audio (6 builds) + remaining CPU-Z builds (3)

> **Per-file disposition (overrides the family summary):** `CMUAC` x4 are **BLOCKED** (unsigned;
> static W0). `CMTAC_83986D97` x64 is **NO-MEMORY-WRITE**; `CMTAC_F6772F57` i386 is
> **BLOCKED (architecture)**. CPU-Z x86/IA-64 dispositions are unchanged.

| Field | Value |
|---|---|
| File(s) | `drivers/CMTAC_83986D97.sys`, `drivers/CMTAC_F6772F57.sys`, `drivers/CMUAC_00D7F507.sys`, `drivers/CMUAC_2F75117C.sys`, `drivers/CMUAC_C2A3B919.sys`, `drivers/CMUAC_D5F01449.sys` |
| SHA-256(s) | `83986D97...` (CMTAC_83986D97)<br>`F6772F57...` (CMTAC_F6772F57)<br>`00D7F507...` (CMUAC_00D7F507)<br>`2F75117C...` (CMUAC_2F75117C)<br>`C2A3B919...` (CMUAC_C2A3B919)<br>`D5F01449...` (CMUAC_D5F01449)? |
| Analysis date | 2026-10-25 |
| Method | Ghidra 12.1.4 headless decompile of the six CoolerMaster builds. The CPU-Z x86/IA-64 fan-out was exported: nothing loaded, installed, executed, or written. |
| Reach tier | **R3** - hardware + devnode (the CPU-Z x86 rows are in the offline export set) |
| Setup required | **hardware** / **devnode** - CoolerMaster only |
| Write quality | **W0** - CoolerMaster only |
| Verdict | **NO-MEMORY-WRITE** - all six CoolerMaster builds | **NO-MEMORY-WRITE** - all six CoolerMaster builds (four also **BLOCKED**: unsigned)<br>
> Static-only audit. This report records gates and primitives. It contains no test code, no exploit code, and no operating steps. Nothing was loaded or run.
>
> **Tool disclosure:** four REA audits were already active when this task started. Per the task constraint and `STATIC_ANALYSIS_AGENT_PROMPT.md` section 6, this audit used only local Ghidra headless and llvm-objdump/PE parsing, and **no REA cross-check was performed**.

## 0. Per-file table

| File | Arch | Size | Signer / load | Reach | Setup | Write | Severity |
|---|---|---:|---|---|---|---|---|
| `CMTAC_83986D97.sys` | x64 | 3,810,136 | MS WHCP attestation, valid | R3 | hardware + devnode | **W0** | **NO-MEMORY-WRITE** |
| `CMTAC_F6772F57.sys` | x86 | 3,163,528 | MS WHCP attestation, valid | R3 | hardware + devnode | **W0** | **NO-MEMORY-WRITE** |
| `CMUAC_00D7F507.sys` | x64 | 613,888 | **NotSigned** (no cert table) | R3 | hardware + devnode | **W0** | **BLOCKED** (static W0) |
| `CMUAC_2F75117C.sys` | x64 | 646,656 | **NotSigned** | R3 | hardware + devnode | **W0** | **BLOCKED** (static W0) |
| `CMUAC_C2A3B919.sys` | x86 | 476,160 | **NotSigned** | R3 | hardware + devnode | **W0** | **BLOCKED** (static W0) |
| `CMUAC_D5F01449.sys` | x86 | 444,416 | **NotSigned** | R3 | hardware + devnode | **W0** | **BLOCKED** (static W0) |

All nine SHA-256 values were recomputed from the corpus files and match the file-name suffixes.

## 1. CoolerMaster (C-Media USB audio) - internals

All six are **PortCls audio miniports**, not standalone control drivers:

| | CMTAC_83986D97 | CMTAC_F6772F57 | CMUAC x4 |
|---|---|---|---|
| PE | PE32+ x64, base `0x140000000` | PE32 i386, base `0x400000` | 2x PE32+ x64 / 2x PE32 i386 |
| DriverEntry | `FUN_14039d000` (PE entry `0x39D0D4`) | `FUN_006fa000` (PE entry `0x2FA090`) | see section 1.2 |
| Functions recovered | 2,688 | 2,185 | 1,316-1,390 |
| `.text` | 1.29 MB | 4.94 MB | 0.28-0.30 MB |
| Imports | `portcls`, `USBD`, HAL, ntoskrnl | same | same |
| Encryption/anti-analysis | none | none | none |

Every image imports `PcInitializeAdapterDriver`, `PcAddAdapterDevice`, `PcRegisterSubdevice`, `PcDispatchIrp`, `PcNewPort`, `PcRegisterPhysicalConnection`, `USBD_*`, and the MDL trio (`IoAllocateMdl`, `MmBuildMdlForNonPagedPool`, `MmMapLockedPagesSpecifyCache`). **No image imports `IoCreateDevice`, `IoCreateDeviceSecure`, `IoCreateSymbolicLink`, `IoSetSecurityInfo`, `MmMapIoSpace`, `MmGetPhysicalAddress`, `ZwMapViewOfSection` or `MmCopyMemory`.**

### 1.2 DriverEntry / dispatch installation

| File | DriverEntry | Installed dispatch |
|---|---|---|
| CMTAC_83986D97 | `FUN_14039d000` @ `0x14039D000` | `+0x70` CREATE `FUN_140367440`; `+0x80` CLOSE `FUN_14036735c`; `+0xE0` DEVICE_CONTROL `FUN_1403676c4`; `+0x148` PNP `FUN_140367000` |
| CMTAC_F6772F57 | `FUN_006fa000` @ `0x006FA000` | `+0x38` CREATE `FUN_006ce35c`; `+0x40` CLOSE `FUN_006ce2b0`; `+0x70` DEVICE_CONTROL `FUN_006ce530`; `+0xA4` PNP `FUN_006ce000` |
| CMUAC_00D7F507 | `FUN_140097000` @ `0x140097000` | `+0x70` CREATE `FUN_140066440`; `+0x80` CLOSE `FUN_14006635c`; `+0xE0` DEVICE_CONTROL `FUN_1400666c0`; `+0x148` PNP `FUN_140066000` |
| CMUAC_2F75117C | `FUN_14009e000` @ `0x14009E000` | `+0x70` CREATE `FUN_14006d440`; `+0x80` CLOSE `FUN_14006d35c`; `+0xE0` DEVICE_CONTROL `FUN_14006d6c0`; `+0x148` PNP `FUN_14006d000` |
| CMUAC_C2A3B919 | `FUN_00473000` @ `0x00473000` | `+0x38` CREATE `FUN_0044b35a`; `+0x40` CLOSE `FUN_0044b2ae`; `+0x70` DEVICE_CONTROL `FUN_0044b52c` |
| CMUAC_D5F01449 | `FUN_0046b000` @ `0x0046B000` | `+0x38` CREATE `FUN_0044335a`; `+0x40` CLOSE `FUN_004432ae`; `+0x70` DEVICE_CONTROL `FUN_0044352c` |

All six call `PcInitializeAdapterDriver(DriverObject, RegistryPath, AddDevice)` first, so every major function is initially `PcDispatchIrp`; the driver then overwrites CREATE, CLOSE, DEVICE_CONTROL (and, on x64, PNP). DEVICE_CONTROL is therefore **not** a KS IOCTL path - it is a vendor private interface (below). KS pin/property traffic continues to arrive through `PcDispatchIrp` on the PortCls-created filter objects.

## 2. Entry / device / interface / effective DACL

**Device creation.** None of the six creates a device object. `AddDevice` (`FUN_140367264`, `FUN_006ce206`, `FUN_140066264`, ...) calls `PcAddAdapterDevice(DriverObject, PhysicalDeviceObject, ..., 0x14, 0x2b8)`, which is PortCls creating the FDO for the audio devnode. The driver's extension (`_DEVICE_OBJECT->DeviceExtension`) is then initialised and two device interfaces are registered **on the PDO** (`param_2`):

```
IoRegisterDeviceInterface(PDO, &GUID_A, &refStringA, ext+0x250/0x268)
IoRegisterDeviceInterface(PDO, &GUID_B, &refStringB, ext+0x250/0x268)
```

**Interface reference strings** (UTF-16 only; no ASCII copies): `\CMASIOPrivateInterface`, `\_CMASIOPrivateInterface`, `\CMEnumPrivateInterface`, `\_CMEnumPrivateInterface`. Two GUIDs per build in `.rdata` (`DAT_14013d600`/`DAT_14013d730` for CMTAC_x64; `DAT_14004d518`/`DAT_14004d660` for CMUAC_00D7; the other builds are equivalent).

**Effective DACL / SDDL.**

- No `IoCreateDevice`/`IoCreateDeviceSecure`/`IoSetSecurityInfo` import in any image.
- No `\Device\` or `\DosDevices\` literal in any image (ASCII or UTF-16).
- No `D:P(`, `D:(A`, `D:PAI` or `SDDL` literal in any image (ASCII or UTF-16; byte scan of all six files).
- The device objects are the PnP/PortCls FDO/PDO; the device interface is a symbolic link to the PDO. The security descriptor is the **devnode's**, supplied by the INF / media class installer (not in this corpus). The driver contributes no ACE and widens nothing.
- Consequence: the effective DACL cannot be resolved from the `.sys` alone. What can be stated is that the private interface is reachable by any principal that can open the audio devnode's PDO - i.e. whatever the INF grants - and that the driver adds **no** privilege check of its own.

**Open gate (verified).** CREATE (`FUN_140066440`, `FUN_140367440`, `FUN_006ce35c`, ...) compares the requested name against the private-interface string:

```
RtlCompareUnicodeString(&DAT_<"\_CMASIOPrivateInterface">,
                        *(FILE_OBJECT **)(stack + 0x30) + 0x58, TRUE)
```

If the name does **not** match, the IRP goes to `PcDispatchIrp` (normal KS). If it matches, the CREATE method of the CMASIO interface object is called (`vtable +0x18`) and CLOSE calls `vtable +0x28`. No `SeSinglePrivilegeCheck`, no `FILE_WRITE_ACCESS` re-check, no caller-identity check exists in the driver.

**Reach:** `R3`. The driver only starts for the matching USB audio devnode (VID/PID in the INF); without the device no FDO, no interface and nothing to open. `Setup: hardware` (plus the INF devnode).

## 3. Dispatch and IOCTL table

### 3.1 Private interface (DEVICE_CONTROL)

The handler (`FUN_1400666c0` / `FUN_14006d6c0` / `FUN_1403676c4` / `FUN_006ce530` / `FUN_0044b52c` / `FUN_0044352c`) is structurally identical in all six images:

- `CurrentStackLocation` = `Irp->Tail.Overlay.CurrentStackLocation` (x64 `+0xB8`, x86 `+0x60`).
- `OutputBufferLength` = `stack+0x08`; `InputBufferLength` = `stack+0x10`; `IoControlCode` = `stack+0x18`; buffer = `Irp->AssociatedIrp.SystemBuffer` (`irp+0x18`).
- **Every code is `METHOD_BUFFERED`** (`code & 3 == 0`). DeviceType `0x001D`, Function `0x800-0x816`. Access bits are `FILE_READ_ACCESS`, `FILE_WRITE_ACCESS` or `FILE_ANY_ACCESS` per code.
- Unknown codes -> `0xC00000BB`. `Information` is set from the output length on success.

| IOCTL | Access | Min input / output | Handler action |
|---|---|---|---|
| `0x1D6000` | READ | - / - | CMASIO `+0x30(SystemBuffer, &outLen)`; Information = outLen |
| `0x1D6004` | READ | - / - | CMASIO `+0x38(SystemBuffer, outLen)` |
| `0x1D600C` | READ | - / - | CMASIO `+0x60(SystemBuffer, &outLen)` |
| `0x1D6010` | READ | - / - | CMASIO `+0x68(SystemBuffer, &outLen)` |
| `0x1D6018` | READ | - / 4 | 0-length -> `0x80000005`; <4 -> `0xC0000023`; else `+0x58(SystemBuffer)`; Information = 4 |
| `0x1D6024` | READ | - / 8 | CMASIO `+0x80()`; Information = 4 |
| `0x1D6028` | READ | - / 4 | CMASIO `+0x88()` |
| `0x1D6034` | READ | - / 0x10 | CMASIO `+0xA0()`; filled length returned |
| `0x1D6058` | READ | - / 4 | CMASIO `+0xD8()`; Information = 4 |
| `0x1DA014` | WRITE | 8 (4 if 32-bit proc) / - | CMASIO `+0x48(ptr)`; pointer taken from SystemBuffer |
| `0x1DA01C` | WRITE | 4 / - | CMASIO `+0x70(*(u32*)SystemBuffer)` |
| `0x1DA020` | WRITE | 4 / 8 | CMASIO `+0x78(*(u32*)SystemBuffer)` then `+0x80()` |
| `0x1DA02C` | WRITE | 4 / - | CMASIO `+0x90()` |
| `0x1DA030` | WRITE | 4 / - | CMASIO `+0x98()` |
| `0x1DA03C` | WRITE | - / - | CMASIO `+0xB0()` |
| `0x1DA040` | WRITE | 8 (4 if 32-bit) / - | CMASIO `+0xB8(ptr)` |
| `0x1DA044` | WRITE | 0 / - | CMASIO `+0xC0(SystemBuffer, Irp)` - the **only** case handed the IRP. The decompiled guard calls the method when input length is 0 **or** the buffer is null (inverted-looking; unresolved) |
| `0x1DA04C` | WRITE | 0 / - | CMASIO `+0x50()`, same inverted-looking guard as `0x1DA044` |
| `0x1DA050` | WRITE | 4 / - | CMASIO `+0xC8()` |
| `0x1DA054` | WRITE | 4 / - | CMASIO `+0xD0()` |
| `0x1DE008` | ANY | - / - | CMASIO `+0x40(SystemBuffer, outLen)` |
| `0x1DE038` | ANY | >=1 / - | CMASIO `+0xA8(SystemBuffer, ...)`. For a 32-bit process only: allocate `ExAllocatePoolWithTag(NonPaged, outLen*2, 'adap')`, pass it as a second buffer, then copy back `outLen` bytes into SystemBuffer |

Method/access decoded from the codes themselves, not inferred. `0x1DE038` is the only IOCTL that reaches a pool allocation. Its size expression `outLen * 2` is evaluated in 32-bit arithmetic and the same wrapped value is passed to the callee and used as the copy-back bound, so a >2 GB output length cannot enlarge the copy beyond `SystemBuffer`; no overflow write was found on this path.

### 3.2 KS surface

Pin/property/pin-instance traffic is not handled by these drivers: it goes to `PcDispatchIrp` -> PortCls -> `ks.sys. and the format/pin handlers live in the PortCls port objects created by `PcNewPort`. The miniport's own contribution is the wave-cyclic stream path in section 5.1 plus the private interface above.

## 4. Access-control audit

| Gate | Where | Who can satisfy |
|---|---|---|
| Device/interface DACL | not set by the driver; inherited from the audio devnode (INF/class installer, not in corpus) | whatever the INF grants; **not resolvable statically** |
| Interface-name gate | CREATE: `RtlCompareUnicodeString(private-interface name, ...)` | any opener of that interface |
| Privilege check (`SeSinglePrivilegeCheck`) | **absent** in all six | - |
| `FILE_WRITE_ACCESS` re-check in driver | **absent** (I/O manager enforces the code's access bits against the handle) | any handle opened with write access |
| Pointer probe/capture | **absent, and unnecessary** - every code is `METHOD_BUFFERED`; only `SystemBuffer` is dereferenced | - |
| Hardware presence | driver only loads on the C-Media USB audio devnode | physical device required |

## 5. Memory-write trace

### 5.1 The only kernel mapping: wave-cyclic DMA buffer (all six)

| File | Function | Allocation -> MDL -> map |
|---|---|---|
| CMTAC_83986D97 | `FUN_140375820` | `ExAllocatePoolWithTag(0x200, n+0x28, 'USBD')` -> `IoAllocateMdl(buf, n+0x28, 0, 1)` -> `MmBuildMdlForNonPagedPool` -> `MmMapLockedPagesSpecifyCache(mdl, 1, 1, 0)` |
| CMTAC_F6772F57 | `FUN_006d987a` (`0x6D9C58`/`0x6D9C9C`) | same argument order (pushed 1, 1, 0, 0, `0x40000020`) |
| CMUAC_00D7F507 | `FUN_140071a70` | same |
| CMUAC_2F75117C | `FUN_14007887c`, `FUN_1400789c0` | same |
| CMUAC_C2A3B919 | `FUN_00454358` | same |
| CMUAC_D5F01449 | import present; call site not recovered in this pass | same by import set |

- `n` is computed from the **device-reported** endpoint/frame geometry and the stream's sample rate: `n = (rate x bytesPerFrame x 0x28 / 1000)` rounded down to a frame multiple (`FUN_140375820`, focus dump lines 332-343; `FUN_140071a70`, `CMUAC_00D7` dump lines 105276-105285). It is not a caller-supplied length field.
- **Allocation size and MDL length are the same expression** (`n + 0x28`), and the mapped length is exactly that. No mismatch, no OOB.
- `AccessMode = 1` (**UserMode**) and `CacheType = 1` (MmCached): the MDL pins the driver's own nonpaged-pool buffer and maps it into the calling process so the audio client can write PCM into it. The returned user VA is stored in the extension and handed back to the client.
- This is the standard wave-cyclic data path. It gives a process a writable view of a **kernel pool buffer of the driver's own, fixed size** - not a caller-chosen address and not a caller-chosen length. It is therefore **not** a kernel memory-write primitive in the MW sense.
- Residual (not rated): the mapping is process-scoped and its teardown depends on the pin-close path, which was not traced dynamically. A stale user mapping surviving pool free would be a use-after-free write. `MmUnmapLockedPages` is imported and used, but not every teardown/error path was proven to unmap, and no static evidence of a lifetime bug was found.
- Non-write defect: `n` is divided by bytes-per-frame; a zero frame size would fault (DoS only, not a write).

### 5.2 Everything else

- No `MmMapIoSpace`, `MmGetPhysicalAddress`, `MmCopyMemory`, `ZwMapViewOfSection`, `\Device\PhysicalMemory`, `MmProbeAndLockPages` in any of the six.
- No store through a pointer taken from `SystemBuffer`. The private-interface handler's only stores are `Irp->IoStatus.Status`, `Irp->IoStatus.Information`, and the callee's writes inside `SystemBuffer`.
- The CMASIO/CMEnum method implementations (vtable slots `+0x30 ... +0xD8`) were **not** traced individually; see section 8.

## 8. Verdict

| File | Reach | Setup | Write | Severity | Load |
|---|---|---|---|---|---|
| `CMTAC_83986D97.sys` | R3 | hardware + devnode | W0 | **NO-MEMORY-WRITE** | signed |
| `CMTAC_F6772F57.sys` | R3 | hardware + devnode | W0 | **NO-MEMORY-WRITE** | signed |
| `CMUAC_00D7F507.sys` | R3 | hardware + devnode | W0 | **BLOCKED** (static W0) | unsigned |
| `CMUAC_2F75117C.sys` | R3 | hardware + devnode | W0 | **BLOCKED** (static W0) | unsigned |
| `CMUAC_C2A3B919.sys` | R3 | hardware + devnode | W0 | **BLOCKED** (static W0) | unsigned |
| `CMUAC_D5F01449.sys` | R3 | hardware + devnode | W0 | **BLOCKED** (static W0) | unsigned |

**Overall: no kernel memory-write primitive was found in the six CoolerMaster builds. The CPU-Z x86/IA-64 audit notes were exported with the set and are not reproduced here.**

CoolerMaster (`NO-MEMORY-WRITE`, W0):

- No driver-created device, no driver-set DACL, no SDDL literal, no privilege check.
- The only kernel mapping is the wave-cyclic DMA buffer: nonpaged pool, MDL length equal to the allocation, mapped `UserMode`/`MmCached` for the audio client. Target and length are both driver-derived; there is no caller-chosen address or length.
- The private `CMASIO`/`CMEnum` interface is `METHOD_BUFFERED` only, so no raw user pointer is dereferenced; the handler's only stores are IRP status fields and callee writes inside `SystemBuffer`.
- The four CMUAC images are additionally **BLOCKED**: their PE security directory is `0x0/0x0` (no certificate table at all), so the as-shipped bytes cannot load under code integrity. The two CMTAC images carry valid Microsoft WHCP attestation signatures.


## 9. Limitations and unresolved paths

1. **REA not used.** Four REA audits were active; no REA cross-check or evidence IDs. All conclusions rest on Ghidra 12.1.4 headless and llvm-objdump output retained under `%TEMP%\opencode\cm_audit\`.
2. **CMASIO/CMEnum method bodies not traced.** The private interface dispatches 22 codes into interface-object vtable slots `+0x30 ... +0xD8`. The dispatcher, its length checks and the `SystemBuffer` handoff were traced exactly; the callee implementations (22 dispatch slots) were not. Any bug that writes past a length *inside a callee* would have been missed. Since every code is `METHOD_BUFFERED` and the callee receives `SystemBuffer`, such a bug would be a bounded pool overflow in the I/O-manager buffer, not an arbitrary write - but it is not excluded.
3. **CMUAC_D5F01449 MDL call site** was not recovered (import present, no direct call in the decompiled set). The other five show the identical pattern.
4. **Effective DACL is not in the image.** No INF/cat was supplied. The driver sets no SD and no SDDL; the interface inherits the audio devnode's descriptor. Whether a standard user can open `\CMASIOPrivateInterface` depends on the INF/class default and could not be resolved statically. Reach is therefore recorded as R3 (hardware/devnode), which is safe under either answer.
5. **CMTAC are 3-4 MB images** (2,688 / 2,185 functions, 1.3 MB / 4.9 MB of code). The focused pass enumerated every function's direct calls to the memory-relevant imports; it did not review all DSP/effects code. No store through a request-derived pointer was found in the dispatch path.
6. **User-mode mapping lifetime.** `MmMapLockedPagesSpecifyCache(..., UserMode, ...)` is used by design. Whether the mapping is torn down on every error path (and therefore whether a stale mapping could outlive the pool buffer) is a dynamic question and was not established.
7. **CPU-Z x86 case enumeration** is from the decompiled switch and cross-checked against the jump-table range constants (`0x9C402500`, `0x9C402604`, `0x9C402708`, `0x9C40270C`, `0x9C402740`). The constants `0x9C402501`, `0x9C402605`, `0x9C402709` are range bounds, not cases.
8. **CPU-Z x86 is i386 only.** The static MW2 rating has no path to execution on this x64 host; it would require a 32-bit Windows system (or a 32-bit VM) plus service creation.
9. Coverage-correction evidence for the prior x64 builds is in the exported report set (offline), not here.
10. Nothing was run. No dynamic confirmation of the LUID gate, the SMBus store, the physical writes, or the audio-devnode DACL was performed.

## 6. CPU-Z x86 / IA-64 - exported

The collected1 CPU-Z x86 pair (i386, both signers) and the IA-64 build were **exported
out of this repo on 2026-10-25** together with their x64 siblings. No device names, hashes,
IOCTL mappings, or audit findings for them are reproduced here. The full audit notes live
in the offline export folder.
CPU-Z x86 / IA-64 verdict: **exported with the set on 2026-10-25**; no traces here.