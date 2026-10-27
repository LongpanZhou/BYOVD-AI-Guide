# Audit: HyperX / HP Virtual Audio Cable (`vachpxkd`)

| Field | Value |
|---|---|
| Files | `drivers\HyperX\vachpxkd_F56EF5B5.sys` (x86-64 - relevant build)<br>`drivers\HyperX\vachpxkd_94A275C1.sys` (ARM64 - cannot load on x64) |
| SHA-256 | `f56ef5b54955dfcb6e3afc697bc5dde49fcee908839ebe9be2d8f413dcee811e`<br>`94a275c1b8612050ee33d97222a31ae88712a1a049656341b8e12b30c4eed3a1` |
| Architecture | x86-64 (image base `0x10000`) / ARM64 (image base `0x140000000`) |
| Method | Static-only (REA / Ghidra 12.1.4). No driver loaded, no device opened, no IOCTL issued. |
| Verdict | **NEEDS-DYNAMIC** - no physical-address primitive, but a large custom KS property/method surface with `METHOD_NEITHER` buffers that was not exhaustively reviewed |
| Setup required | **devnode** |

> Unless stated otherwise, addresses are linked VAs of the x64 build at image base `0x10000` (so `0x1b750` = RVA `0xb750`). The ARM64 build uses base `0x140000000` and the same code in the paths compared.

## 1. Device surface and creation trigger

The driver describes itself as `"HyperX Virtual Audio Device - kernel-mode WDM/KS driver"` / `"Virtual Audio Cable"`. It is a PortCls audio driver:

`FUN_0001b750` @ `0x1b750` is DriverEntry (called from `entry` @ `0x291a0`):

```
0x1b799  FUN_0001ca40(0x374b0, 0xc000)          ; create fixed 0xC000 section, map to system space
0x1b7xx  FUN_0001c810(0x374b0, 8, L"HyperX Virtual Audio Device 4.70.5.%u (full)", 0x346a)
0x1b7xx  FUN_0001aa10(DriverObject)             ; registry / config init
0x1b7xx  PcInitializeAdapterDriver(DriverObject, RegistryPath, &LAB_0001add0)
0x1b7xx  *(DriverObject + 0x70) = &LAB_0001b330  ; IRP_MJ_CREATE
0x1b7xx  *(DriverObject + 0x80) = &LAB_0001a7d0  ; IRP_MJ_CLOSE
0x1b7xx  *(DriverObject + 0xe0) = &LAB_0001b690  ; IRP_MJ_DEVICE_CONTROL
0x1b7xx  save DriverUnload (+0x68); install FUN_0001b730
```

The three hooks are position-independent thunks that load the driver-global adapter pointer (`[0x37488]`) into `RCX` and tail-jump:

| Thunk | Bytes | Target |
|---|---|---|
| `0x1b330` (CREATE) | `4c8bc2 488bd1 488b0d 4bc10100 e99efcffff` | `0x1afe0` |
| `0x1a7d0` (CLOSE) | `4c8bc2 488bd1 488b0d abcc0100 e92effffff` | `0x1a710` |
| `0x1b690` (DEVICE_CONTROL) | `4c8bc2 488bd1 488b0d ebbd0100 e9aefcffff` | `0x1b350` |

`PcInitializeAdapterDriver` supplies the PnP `AddDevice` callback; `PcAddAdapterDevice` creates the adapter FDO when the devnode starts. There is **no `IoCreateDevice` and no `IoCreateSymbolicLink` import**, and no `\Device\...` string, so there is no legacy control device.

No INF was collected for either build, so the device instance ID / DACL are not available from the package. Registration is the PortCls/KS default for a root-enumerated audio device.

## 2. Effective DACL

**Unknown / not in package.** No INF accompanies `vachpxkd_*.sys`, and the image contains no `D:P(...)` string and no `Security` value (string scan). The device therefore takes the PortCls/KS default descriptor applied to the audio devnode; the sibling SteelSeries virtual-audio INFs in this collection use `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)`, and an audio endpoint needs `WD` read/write. Treat the device as **user-openable R/W by design**; this is an inference, not an observation.

Note that `Everyone:GRGWGX` is the expected policy for an audio endpoint and is not, by itself, a vulnerability.

## 3. Handler table

`FUN_0001b350` @ `0x1b350` is the device-control dispatcher. It first offers the IRP to the normal dispatch path `FUN_000126c0` and only handles its own codes when that returns `0xC0000016` (`STATUS_INVALID_DEVICE_REQUEST`):

```
uVar8 = FUN_000126c0(DAT_00037450, Irp, Irp, ...);
if ((int)uVar8 != 0xC0000016) return uVar8;

lVar2 = Irp->Tail.Overlay.CurrentStackLocation;   // +0xb8
iVar5 = *(int *)(lVar2 + 0x18);                   // IoControlCode
uVar7 = *(uint *)(lVar2 + 0x10);                  // InputBufferLength
uVar1 = *(uint *)(lVar2 + 0x08);                  // OutputBufferLength
```

| IOCTL | Decoded | Handler | Notes |
|---|---|---|---|
| `0x2F0003` | `IOCTL_KS_PROPERTY`, `METHOD_NEITHER` | `FUN_0001b950` -> `FUN_00022160` / `FUN_00025a10` / `FUN_0002a8f0` | reads 0x18-byte `KSPROPERTY` via `ProbeForRead`; GUID-filtered |
| `0x2F001B` | `IOCTL_KS_RESET_STATE`, `METHOD_NEITHER` | `FUN_000245b0` | `KsAcquireResetValue` wrapper |
| `0x2F4017` | `IOCTL_KS_READ_STREAM`, `METHOD_NEITHER`, `FILE_READ_ACCESS` | `FUN_00024d80` | `KsProbeStreamIrp` + `MmMapLockedPagesSpecifyCache` |
| `0x2F8013` | `IOCTL_KS_WRITE_STREAM`, `METHOD_NEITHER`, `FILE_WRITE_ACCESS` | `FUN_00024d80` | same path, direction flag |
| other | - | `PcDispatchIrp` | standard PortCls |

Two property-set GUIDs are recognised in `0x2F0003` (`FUN_0001b350` @ `0x1b4xx`, `FUN_00025a10` @ `0x25a10`):

- `{45FFAAA0-6E1B-11D0-BCF2-444553540000}` - `KSPROPSETID_Audio`; ids `5` and `0x32` are special-cased (buffer-length query and a 0x28-byte timing/position reply).
- `{1D58C920-AC9B-11CF-A5D6-28DB04C10000}` - vendor/auxiliary set, id `0`.

Everything else returns `0xC0000016`.

## 4. Physical address / mapping question

**There is no user-controlled physical address.**

- `MmMapIoSpace` is **not imported** by either build. Even if a physical address leaked, there is no path to map it.
- `MmGetPhysicalAddress` is called only from `FUN_0001a180` @ `0x1a180`:

```
loop 0x100 bytes at (obj + 0x10); if any byte != 0xCC -> int3
uVar4 = MmGetPhysicalAddress(*(undefined8 *)(obj + 0x120));
*param_2 = uVar4;
```

  `obj` is a driver-owned object (`param_1`), and `obj+0x120` is a field of that object, not a user value. The `0xCC` sweep is a debug/consistency check on the object, not a user input validation.
- The only section creation found is `FUN_0001ca40` @ `0x1ca40`:

```
MmCreateSection(&sec, 6, 0, &size, 4 /*PAGE_READWRITE*/, 0x8000000 /*SEC_COMMIT*/, 0, 0);
MmMapViewInSystemSpace(sec, &view, &viewSize);
*(this + 0x18) = size;      // 0xC000
*(this + 0x20) = view;      // system VA
*(this + 0x28) = size / 0x180;
```

  The call in DriverEntry is `FUN_0001ca40(0x374b0, 0xc000)` - a **fixed 48 KB, driver-created section**, not a user-supplied size or address.
- `MmMapViewOfSection` is imported but has **no recovered direct call site** (only the import thunk at `0x2a592`), so a user-process mapping of that section could not be confirmed statically. `MmAllocatePagesForMdl` + `MmMapLockedPagesSpecifyCache` are used in the KS stream/MDL path (`FUN_00024d80`), i.e. to map the client's audio buffer MDLs - the normal KS pattern, with `KsProbeStreamIrp` run first.

Conclusion for Q4: the mapping is of a **fixed, driver-owned section**; `MmGetPhysicalAddress` is applied to a driver-owned buffer; there is no `MmMapIoSpace`; a user cannot supply a physical address.

## 5. Write sinks and copy helpers

The two buffer helpers are textbook and bounds-check the requestor mode before touching a user pointer:

`FUN_0001b950` @ `0x1b950` (copy **in**):

```
if (param_4 == 0) _Src = *(void **)(IrpSp + 0x20);   // Type3InputBuffer
else              _Src = *(void **)(Irp + 0x70);     // UserBuffer
if (Irp->RequestorMode != KernelMode && (Irp->Flags & 0x10) == 0)
    ProbeForRead(_Src, length, 1);
memcpy(dst, _Src, length);
```

`FUN_0001b9d0` @ `0x1b9d0` (copy **out**) is the mirror image with `ProbeForWrite` and `Irp->AssociatedIrp.SystemBuffer` (`Irp+0x18`) for buffered IRPs.

Observed length checks:

- `FUN_00025a10` @ `0x25a10`: `OutputBufferLength == 0` -> `0x80000005`; `< 0x10` / `< 0x28` -> `0xC0000023`; set path reads exactly 0x10 bytes and validates the requested position against `*(uint *)(stream+0x38)` before use (`0x25c4f`-`0x25c85`).
- `FUN_00024d80` @ `0x24d80`: `KsProbeStreamIrp(Irp, 0x71 | (code != 0x2f4017))` before touching stream pointers; requires `InputBufferLength >= 0x38`; maps each MDL with `MmMapLockedPagesSpecifyCache(..., 0, MmCached, ...)` and stores the returned VA into its own packet array.

No `memcpy` with a user-controlled destination or unbounded user length was found on the reviewed paths.

## 6. Validation gaps / residual unknowns

1. **Custom property handlers not exhaustively reviewed.** `FUN_0001b350` dispatches `0x2F0003` to `FUN_00022160`, `FUN_00025a10` and `FUN_0002a8f0`; only `FUN_00025a10` and `FUN_00024d80` were decompiled in full. `FUN_00022160` and `FUN_0002a8f0` remain unexamined; both receive `METHOD_NEITHER` KS property buffers.
2. **The vendor set `{1D58C920-...}` id 0** is handled by `FUN_0002a8f0` (called from `0x1b5xx` after a `FUN_0002a5f0/FUN_0002a8f0/FUN_0002a640` lock sequence). Not reviewed.
3. **User mapping of the shared section** is unresolved (see section 4). If the driver does map the 0xC000 section into the audio engine with write access, the security question becomes whether any index into that section is attacker-controlled; the indices seen so far are bounded by `0x180`-byte records within the fixed size.
4. The ARM64 build is out of scope for an x64 VM; its code matches the x64 build in the reviewed functions (`MmCreateSection`/`MmMapViewInSystemSpace`/`MmGetPhysicalAddress`/`ProbeFor*` call sites and the 0xC000 section size).

## 7. Setup required

**devnode.** PortCls adapter created on PnP start; no legacy control device. Installing the virtual audio device is Setup, so this is **disqualified under the no-setup rule** regardless of the verdict.

## 8. Next dynamic test

1. On a disposable x64 VM, install the INF (not in this package - obtain from the HP/HyperX driver package), confirm the `KSCATEGORY_AUDIO`/`KSCATEGORY_RENDER` filter appears and `\Device\...` can be opened by a standard user.
2. As a standard user, send `IOCTL 0x2F0003` with a 0x18-byte `KSPROPERTY` for `{45FFAAA0-...}` id 5/0x32 and for `{1D58C920-...}` id 0, varying `InputBufferLength` from 0 to 0x40 and `OutputBufferLength` from 0 to 0x100 - under Driver Verifier (Special Pool, Pool Tracking, I/O Verification).
3. Send `0x2F4017`/`0x2F8013` with a single valid stream pointer and a crafted `KSSTREAM_HEADER` (OptionsFlags, DataUsed, PresentationTime) to exercise `FUN_00024d80`; confirm `KsProbeStreamIrp` rejects user VAs for kernel-mode use.
4. Instrument (ETW/WPP or a debugger breakpoint at `0x1ca40`) to confirm the section base is the same fixed 0x374b0 object for every stream, and check whether `MmMapViewOfSection` is ever invoked for the client process. If it is, fuzz the per-packet offsets.

*End of report.*
