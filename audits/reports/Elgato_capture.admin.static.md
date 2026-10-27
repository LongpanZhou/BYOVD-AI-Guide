# Audit: Elgato capture family - 16 images (current scope)

| Field | Value |
|---|---|
| File(s) | 16 files (all in `drivers/`): `CamLinkPro.X64_63F81CE8.SYS`, `CamLinkPro.X64_D40EA12F.SYS`, `CY3014.X64_A73163C8.SYS`, `CY3014.X64_C56A09B3.SYS`, `e60MZ0380.X64_99118E2D.SYS`, `e60MZ0380.X64_BF9A3116.SYS`, `ElgatoGC656_042CAFD9.sys`, `ElgatoGC658_C4597A53.sys`, `elgatovirtualcamera_D216849D.sys`, `eMZ0380.X64_75F9A47D.SYS`, `kinonivad_AECF289A.sys`, `kinonivd_844635B5.Sys`, `PP.SC0710.X64_5D0EDF91.SYS`, `SC0710.X64_21A8968C.SYS`, `SC0710.X64_4CCFDEA2.SYS`, `UB3400.X64_825332A7.SYS` |
| SHA-256(s) | All 16 verified against `indexes/drivers_manifest.csv`; none is in `indexes/dedupe/known_bad_hashes.txt`. Full values in section 7.1. |
| Analysis date | 2026-10-25 |
| Method | **Static-only.** Local Ghidra 12.1.4 headless (`analyzeHeadless`, full auto-analysis, scripted property-table extraction and per-handler decompilation), Python PE/import/string parsing, `llvm-objdump` 21.1.0 for call-site confirmation. No load, no service creation, no registry write, no execution, no web. **REA was not used**: four REA audits were already active, so the cross-check was skipped (agent-prompt rule 6); no REA evidence IDs are cited. |
| Reach tier | **R3** (devnode/hardware). Effective object DACL is `ks.sys`'s default (`KsCreateFilterFactory(..., SecurityDescriptor = NULL)`); no driver-internal access check. Admin (`R2`) can open once the devnode exists; unprivileged open is the normal capture-client path but was not dynamically confirmed. |
| Setup required | **hardware** for 13 images (USB/PCI capture function drivers); **devnode** for `elgatovirtualcamera`; `kinonivad`/`kinonivd` are **BLOCKED** (i386). |
| Write quality | **W2** for `ElgatoGC656` and `ElgatoGC658`; **W0** for the other 12 x64 images; **W0** (static) for the two i386 images. |
| Verdict | **MW3 - reach=R3 setup=hardware write=W2 load=signed** overall. Two files are MW3; twelve are NO-MEMORY-WRITE (eleven `HW-ONLY`); two are BLOCKED (i386). |

> **Scope note.** The previous Elgato pass (`audits/reports/elgato_capture.static.md`) disqualified the whole family on setup cost and did not read most handlers (7 decompile timeouts). Verdicts were **not inherited**. Under the current scope a hardware/devnode gate is a severity field, so the handlers were read and the write paths re-traced.

---

## 1 Internals - three code lineages

| Lineage | Images | Build | Notes |
|---|---|---|---|
| **A. BDA "Broadcast Driver Architecture & AVStream Minidriver"** (Blackmagic-derived, Elgato-branded) | `CamLinkPro` x2, `CY3014` x2, `e60MZ0380` x2, `eMZ0380`, `PP.SC0710`, `SC0710` x2, `UB3400` | 1.1.0.189-1.1.0.202 | 3.6-5.8 MB AVStream minidrivers. Two sub-generations: 1.1.0.189/191 WDM images (image base `0x10000`, `ZwOpenSection`/`ZwMapViewOfSection` present) and 1.1.0.194-202 images (image base `0x140000000`, `WdfVersionBind` but no WDF device APIs, `MmMapIoSpace` instead of a section). |
| **B. Legacy Elgato UB658** | `ElgatoGC656`, `ElgatoGC658` | 2.1.1.5 (2015) | 43,392 bytes, WDM + USBD, `KsCreateDevice` + `KsCreateFilterFactory`. |
| **C. Kinoni/Elgato virtual camera** | `elgatovirtualcamera` (x64), `kinonivd`/`kinonivad` (i386) | 1.3.4.97 / 6.1.7600 / 10.0.10011 | AVStream virtual camera (`KsInitializeDriver`), plus a 32-bit EpocCam camera and a 32-bit PortCls virtual audio miniport. |

**Byte-identical `.text` pairs** (single analysis, same verdict):

| Pair | `.text` SHA-256 (first 16) | Size |
|---|---|---|
| `CamLinkPro.X64_D40EA12F` === `SC0710.X64_21A8968C` | `ce11210ea171cd85` | 2,709,504 |
| `e60MZ0380.X64_BF9A3116` === `eMZ0380.X64_75F9A47D` | `cf26f3449e032d45` | 2,946,048 |
| `ElgatoGC656_042CAFD9` === `ElgatoGC658_C4597A53` | `82873f5f38e28010` | 21,504 |

All other `.text` sections differ (separate compiles/configurations).

**Signing.** All 16 have a valid Authenticode signature on this host: ten by `Corsair Memory, Inc.` (Elgato's parent), two by `Elgato Systems LLC` (the 2015 UB658 pair), four by `Microsoft Windows Hardware Compatibility Publisher` (WHQL/attestation: `elgatovirtualcamera`, `kinonivad`, `kinonivd`, `SC0710 4CCFDEA2`). None is `BLOCKED` for signing.

---

## 2 Entry / device / interface / effective DACL

### 2.1 Device creation

| Image(s) | Entry | Device/interface creation |
|---|---|---|
| All eleven BDA x64 | `entry` -> `GsDriverEntry`/`FxDriverEntryWorker` -> vendor `DriverEntry` | **No `IoCreateDevice`, `IoCreateDeviceSecure`, `WdfDeviceCreate`, `WdfDeviceInitAssignSDDLString` or `IoCreateSymbolicLink` import exists.** `KsInitializeDriver` + up to 11 `KsCreateFilterFactory` call sites; KS filter devices are created by `ks.sys` from the descriptors. |
| `ElgatoGC656/658` | `entry` @ `0x1b064` -> `FUN_0001b...` | `KsCreateDevice` @ `0x11524` (caller `0x114c4`) and `KsCreateFilterFactory` @ `0x13c55` (caller `0x139c8`). No `IoCreateDevice`/symlink import. |
| `elgatovirtualcamera` | `entry` @ `0x140daf000` -> `FUN_1400012e0` | `KsInitializeDriver` @ `0x1400012f0`; `KsCreateFilterFactory` @ `0x140da9e60`. No WDF device or named device. |
| `kinonivd` | `entry` @ `0x6d8000` -> `FUN_00401262` | `KsInitializeDriver`; filter factory via `KsCreateFilterFactory`. No named device. |
| `kinonivad` | `entry` @ `0x5605e` | `PcInitializeAdapterDriver` only (PortCls adapter FDO). |

### 2.2 Effective DACL / open gate

- **No SDDL string of any kind** in the 16 images (`D:P(` scan: empty; no `Security` value string). No `IoCreateDeviceSecure`, no `WdfDeviceInitAssignSDDLString`.
- **No access check**: none of the images imports `SeAccessCheck`, `SeSinglePrivilegeCheck`, `IoValidateDeviceIoControlAccess`, or `ObReferenceObjectByHandle`-based caller tests in the I/O path.
- `KsCreateFilterFactory` is called with **`SecurityDescriptor = NULL`** in every image where the call was resolved:
  - `ElgatoGC656` `FUN_000139c8` @ `0x13c55`: `KsCreateFilterFactory(dev, descriptor, name, 0)`.
  - `CamLinkPro 63F81CE8` `0x140237624` and `0x140238408`: `xor r9d,r9d` immediately before both calls (4th argument = 0).
- Therefore the effective security descriptor is **`ks.sys`'s default filter descriptor**, not a driver-supplied SDDL. That descriptor is inside `ks.sys`, not in these images; it is the descriptor under which every DirectShow/MediaFoundation capture client opens the filter, so user-mode open is the design intent. The exact ACEs (and whether a standard user gets `FILE_READ/WRITE_ACCESS`) were **not** dynamically confirmed. An administrator can open the device once the devnode exists in any case (`R2`).
- The PnP devnode's own device-object DACL comes from the package INF, which is **not in the corpus** (`drivers/` is `.sys` only). For `ElgatoGC656/658` the baseline reports `USB\VID_0FD9&PID_005C`; for the BDA images the INF binds a PCI or USB capture function. The INF DACL was not re-read.

**Open gate for the MW3 finding:** the USB capture device must be present and started (the KS filter factory is created from the PnP start path; `KsCreateDevice` requires a physical USB device object). No root-enumerated/software-device fallback exists in the image.

---

## 3 Dispatch and IOCTL/KS surface

### 3.1 No driver-owned IOCTL device

None of the 16 images imports `IoCreateDevice`, `IoCreateDeviceSecure`, `WdfDeviceCreate`, or `WdfIoQueueCreate`. There is therefore **no vendor `IRP_MJ_DEVICE_CONTROL` dispatch and no vendor IOCTL code**. All user traffic is KS traffic handled by `ks.sys` (`KsDispatchIrp` / the KS filter dispatch), i.e.:

| Code | Name | Method | Access | Kernel action |
|---|---|---|---|---|
| `0x002B0000` | `IOCTL_KS_PROPERTY` | `METHOD_BUFFERED` | `FILE_ANY_ACCESS` | `ks.sys` resolves the property set/item and calls the driver's Get/Set handler with `Data` pointing into the non-paged system buffer. |
| `0x002B0003` | `IOCTL_KS_METHOD` | `METHOD_BUFFERED` | `FILE_ANY_ACCESS` | `ks.sys` method dispatch. **No KSMETHOD_SET is registered in the sampled automation tables** (method count = 0 in `CamLinkPro 63F81CE8`, `CY3014 A73163C8`, `D40EA12F`); no method surface to audit here. |
| `0x002B0001/2` | `IOCTL_KS_ENABLE/DISABLE_EVENT` | `METHOD_BUFFERED` | `FILE_ANY_ACCESS` | Event enable/disable; the one event set in `ElgatoGC656` is a `KSEVENT_SET` with no buffer sink. |

KMDF is only version-bound (`WdfVersionBind/Unbind`), not used for device or queue creation, in the five 1.1.0.194+ images.

### 3.2 Property sets - BDA x64 (all eleven)

Every BDA image exposes the same KS filter property surface (14-15 sets). The set tables were extracted from the automation tables and validated by GUID pointer, count and item-array stride (`0x48`); the item layout is the standard `KSPROPERTY_ITEM` (`PropertyId`, Get @ +0x08, MinProperty @ +0x10, MinData @ +0x14, Set @ +0x18).

| Set GUID | Items | Content |
|---|---|---|
| `{c6e13360-30ac-11d0-a18c-00a0c9118956}` | 5 | `PROPSETID_VIDCAP_VIDEOPROCAMP` (Brightness/Contrast/Hue/Saturation/Sharpness), Get + Set |
| `{c6e13350-30ac-11d0-a18c-00a0c9118956}` | 5 | `PROPSETID_VIDCAP_VIDEODECODER`, Get + Set |
| `{c6e13343-30ac-11d0-a18c-00a0c9118956}` | 6 | `PROPSETID_VIDCAP_VIDEOCOMPRESSION`, Get + Set |
| `{c6e13344-30ac-11d0-a18c-00a0c9118956}` | 1 | video-control related, Get |
| `{6a2e0605/640/650/670-28e4-11d0-a18c-00a0c9118956}` | 8/4/3/4 | BDA analog-video sets (crossbar / TV audio / selector family), Get + Set |
| `{45ffaaa0-6e1b-11d0-bcf2-444553540000}` | 2 (ids 4/13, 33) | BDA transport/stream set, Get + Set |
| `{0e8a0a40-6aef-11d0-9ed0-00a024ca19b3}` | 1 (id 5) | vendor/BDA device-info, Get (4 bytes) |
| `{868de3d7-1ed1-4698-af07-0a4b57662572}` | 1 (id 0) | vendor device-info, Get (4 bytes) |
| `{703f16a9-3d48-44a1-b077-018dff915d19}` | 1 | vendor, Get + Set (4 bytes) |
| `{ee5fb25c-c713-40d1-9d58-c0d7241e250f}` | 1 | vendor, Get + Set (4 bytes) |
| `{49cc4c43-ca83-4ad4-a9af-f3696af666df}` | 1 | vendor, Get + Set (4 bytes) |

Handlers decompiled in `CamLinkPro 63F81CE8` (2021) and `D40EA12F` (2020) are all fixed-offset field accessors: `MinData` is 4-104 bytes, and the Get/Set bodies store/read a fixed-size 4-, 8- or 0x28-byte structure at `Data`/`Data+N`. **No handler reads a length out of `Data` and feeds it to a copy**, and no handler writes past a fixed offset. `CY3014 A73163C8` and `C56A09B3` reproduce the same tables/handler shape. The 4-byte vendor sets (`0e8a0a40`, `868de3d7`) only branch on the PCI/USB IDs and write one dword.

### 3.3 Property sets - `ElgatoGC656` / `ElgatoGC658`

| Set GUID | Items | Handlers (VA, image base `0x10000`) |
|---|---|---|
| `{7e797f9f-b60a-4a7d-86fa-2b4f7e3d92ad}` | id 0, id 1 (Set) | `0x14378`, `0x143c0` |
| `{ab090437-b6dc-4d8d-a6b9-09dc5571b94b}` | id 9, 14, 15 (Get) | `0x145cc`, `0x14630`, `0x14678` |
| `{9b36e21a-ae37-4776-af0e-5e26803fa6e4}` | id 12 (Set) | `0x147d0` |
| `{3cbb5fab-35d3-4bc6-a27a-fb0de4a995f7}` | id 13 (Set) | `0x1487c` |
| `{18f6cec8-c837-447c-a4d1-b23f9f68bdf3}` | id 0 | none (support-only) |

The table is duplicated (items at `0x172f0...0x17450` and `0x17730...0x17860`), i.e. the same property surface is attached to two pins/filters. `MinProperty = 0x18`; `MinData = 8` for the three Get handlers, `0x21` (id 12) and `3` (id 13) for the Set handlers. The Set item id 0 has `MinData = 0x1000a` (64 KB + 10 bytes).

### 3.4 Property sets - virtual camera

`elgatovirtualcamera` exposes three sets: `KSPROPERTYSETID_PerFrameSetting` `{f1f3e261-dee6-4537-bff5-ee206db54aac}` (3 items, Get/Set), vendor `{05dc8943-b9fb-4201-808f-6e91451c4760}` (1 Get) and an empty vendor set. `kinonivd` (i386) exposes the Kinoni vendor sets (including `{05dc8943-b9fb-4201-808f-6e91451c4760}`) plus the extended camera-control and per-frame sets (see the EpocCam baseline); `kinonivad` is PortCls-only with no property handler.

---

## 4 Access-control audit

| Gate | Result |
|---|---|
| Device DACL | `ks.sys` default (no SDDL in image; `SecurityDescriptor = NULL`). Not resolvable to an SDDL from the images; the INF (absent) supplies the devnode DACL. |
| Driver access check | **None.** No `SeAccessCheck`, `SeSinglePrivilegeCheck`, `IoValidateDeviceIoControlAccess`, or `FILE_WRITE_ACCESS` test in any image. |
| METHOD_NEITHER probe | Not applicable: the KS property/method IOCTLs are `METHOD_BUFFERED`; handlers dereference `Data` as kernel memory without probes (correct for KS). |
| Handle/instance exclusivity | Some BDA images enforce a single client or a per-client context (`KsRegisterFilterWithNoKSPins`, client flags), but these are liveness gates, not security gates. |
| Effective reach | `R3` on hardware/devnode; `R2` (admin) is sufficient for the KS filter open in all cases. `R1` is plausible for a capture filter (media clients run as users) but was **not** proven. |

---

## 5 Memory-write trace

### 5.1 `ElgatoGC656_042CAFD9` / `ElgatoGC658_C4597A53` - unchecked KS property output copy (**W2**)

The UB658 filter create dispatch (`0x14098`, `KSFILTER_DISPATCH.Create` at `0x17668`; factory created by `KsCreateFilterFactory` at `0x13c55`) allocates a 0x18-byte filter context and a **0x10000-byte** data buffer:

```
plVar2 = ExAllocatePoolWithTag(0, 0x18, 0x774e434b);      // per-filter context
...
lVar3  = ExAllocatePoolWithTag(0, 0x10000, 0x63446962);  // context->buf, 64 KB
```

The vendor Set item 0 (`0x14378` -> `FUN_000141b8`) fills that buffer from the caller's data:

```
if (*(ushort *)(Data + 8) != 0 && Data + 10 != NULL)
    memcpy(ctx->buf /* *(void **)(param_1 + 8) */,
           Data + 10,
           *(ushort *)(Data + 8));            // length is a caller-controlled USHORT, <= 0xFFFF
if (Data[0] < 2 && (Data[1] & 0x80))
    ctx->len /* +0x10 */ = *(ushort *)(Data + 8);
```

The 64 KB allocation and the 16-bit length make this Set path **bounded and safe** (max 0xFFFF into 0x10000). The unsafe direction is the Get side. Three Get handlers copy the cached/frame data into the property data buffer with **no `OutputBufferLength` check**:

**(a) Get id 9 - `FUN_000145cc`** (memcpy call site `0x145fd`, memset call site `0x14609`):

```
ctx = *(filter + 0x10);
if (ctx->len != 0) {
    *Data = ctx->len;                          // 0x145f3
    memcpy(Data + 4, ctx->buf, ctx->len);      // 0x145fd - length from context, not from OutputBufferLength
} else {
    memset(Data + 4, 0, *Data);                // 0x14609 - length is the caller's first dword
}
Irp->IoStatus.Information = *Data + 7;         // 0x1461d
```

On a fresh filter (`ctx->len == 0`) the `memset` uses the caller's first dword directly: a single Get with `InputBufferLength = 0x1c` (property header + one dword) and `OutputBufferLength = 0x20` gives a caller-chosen, unbounded zero fill starting at `Data + 4` - crash-first, but a kernel write. The Set-then-Get path below gives the bounded, content-controlled copy.

**(b) Get id 14 - `FUN_00014630` -> `FUN_000143d8`**: sets `*Data = devctx->frame_size` (devctx `+0x388`) and `memcpy(Data + 4, frame_buf + i*stride, *Data)`. Also a 'G'-pattern fast path that copies `uVar7 = (*Data / 0xbc) * 0xbc` bytes.

**(c) Get id 15 - `FUN_00014678`** (memcpy call site `0x14749`):

```
if (Data + 4 && devctx->buf /* +0x2d0 */ && devctx->state /* +0x10 */ == 0) {
    *Data = devctx->frame_size;                // +0x38c, e.g. a frame stride
    memcpy(Data + 4, devctx->buf + i * devctx->stride, *Data);   // 0x14749
    Irp->IoStatus.Information = *Data + 7;
}
```

None of the three functions reads `IrpSp->Parameters.DeviceIoControl.OutputBufferLength` (`Irp+0xb8` -> `+8`). The only size gate is the item's `MinData = 8`, i.e. `OutputBufferLength >= sizeof(KSPROPERTY) + 8 = 0x20`. `ks.sys` allocates the `METHOD_BUFFERED` system buffer with `max(InputBufferLength, OutputBufferLength)`, so a Get with `OutputBufferLength = 0x20` gives `Data = SystemBuffer + 0x18` and 8 usable bytes; the handler then writes `*Data` (4 bytes) and `ctx->len` (up to 0xFFFF) bytes at `Data + 4 = SystemBuffer + 0x1c` - a **pool buffer overflow of up to 0xFFFB bytes past the system-buffer allocation**.

**Primitive shape:**

| Axis | Value |
|---|---|
| Destination | KS non-paged system buffer (`SystemBuffer + 0x1c`) and adjacent pool. Not caller-selected. |
| Value | Fully caller-controlled: the 64 KB blob written by Set id 0 (or captured frame data for ids 14/15). |
| Size | Caller-controlled USHORT via Set id 0 (`Data+8`), 0-0xFFFF; or the driver's frame size for ids 14/15. |
| Gate | USB capture device + started devnode; open KS filter; Set id 0 with `InputBufferLength >= 0x10022`; Get id 9 with `OutputBufferLength = 0x20`. No streaming required for id 9 (only the filter context). |
| Reliability | Deterministic copy; no probe/crash before the write. Pool corruption may bugcheck after the fact, but the write itself is unconditional. |

This is a **constrained kernel pool overflow (W2)** - not an arbitrary address (W1), and not physical-memory-only (W3P).

### 5.2 Why the other two 2015 handlers are not higher

- Set id 12 (`0x147d0`) and id 13 (`0x1487c`) only read 1-33 bytes of command data and call device-state helpers; no length-driven copy.
- The 0x18 context and 0x10000 buffer are allocated per filter and freed in the Close dispatch (`0x1413c`).

### 5.3 BDA x64 (2020/2021) - `MmMapIoSpace` is fixed-window device MMIO (`HW-ONLY`)

Every BDA image that maps registers does so from the **translated memory resource list**, not from caller data. Verified at `CamLinkPro 63F81CE8` `FUN_14024f07c`:

```
14024f66b  movl 0xc(%r14), %edx      ; Length from a CM resource descriptor
14024f66f  movq 0x4(%r14), %rcx      ; PhysicalAddress (Start) from the same descriptor
14024f673  callq *...                ; MmMapIoSpace
```

`r14` is an entry of the device's resource descriptor array obtained from the PnP start path; the `MmGetPhysicalAddress` calls in the same function take the VA of driver-allocated contiguous buffers (`MmAllocateContiguousMemorySpecifyCache`) for DMA descriptors, or the explicit 4 GB capability probe (`DbgPrint("> 4GB ...")`), never a caller-supplied address. No IOCTL/KS handler passes a PA, length, cache type or BAR index into `MmMapIoSpace`. **`HW-ONLY`, W0.**

### 5.4 BDA 2020 builds - QCAP shared section and MDL mapping (no caller length)

The six 1.1.0.189/191 WDM builds import `ZwOpenSection` + `ZwMapViewOfSection`. The section name is built from the UTF-16 template `\BaseNamedObjects\QCAP.VCAM.V.` (`CamLinkPro D40EA12F` string at RVA `0x294c10`), opened with `DesiredAccess = 4` and mapped with `Win32Protect = 0x204` (`PAGE_READWRITE | PAGE_NOCACHE`) into the system process:

```
14040412  callq ZwOpenSection
14040490  callq ZwMapViewOfSection(handle, -1, &base, 0, 0, ..., ViewSize=0x50, ..., 0x204)
```

The mapped 0x50-byte view is then wrapped by `FUN_0001cd50` (`IoAllocateMdl` over the section view, `MmProbeAndLockPages(UserMode, IoModifyAccess)`, `MmMapLockedPagesSpecifyCache(KernelMode, MmCached)`) and its header fields are logged. The driver copies no caller length into a kernel store from this view; the section is a user-mode-facing shared header, and the mapping is fixed at 0x50 bytes. It is a **composition** surface (a user-mode service must create the section; `\BaseNamedObjects` is the system session namespace), not an established memory write. Recorded as unresolved.

`MmMapLockedPagesSpecifyCache` in these builds is otherwise used only on driver-owned buffers (`MmBuildMdlForNonPagedPool`) or the 0x50 section MDL; `IoAllocateMdl`/`MmProbeAndLockPages` in `CY3014 C56A09B3` wrap the driver's own frame memory. No user VA/PA/length flows into an MDL.

### 5.5 `elgatovirtualcamera` - handlers are length-checked (W0)

The three handlers read the IRP stack location explicitly and compare the caller length before any copy:

- `FUN_140daa9a0` (Get id 1): `uVar1 = *(uint *)(*(Irp + 0xb8) + 8)`; `if (uVar1 == 0) ... else if (uVar1 < size) return STATUS_BUFFER_TOO_SMALL; else memcpy(Data, src, size)`.
- `FUN_140dabe20` (Set id 1, PerFrameSetting): reads `InputBufferLength` at the same offset, rejects `< 0x28`, calls parser `FUN_140daac5c(ctx, Data, InputBufferLength, &out)`; the parser rejects `Data == NULL`, `len == 0`, `len < *Data`, `*Data < 0x28`, `Data[8] != 1`, or a count outside 1..0x1ff; only then allocates `*Data` bytes via the driver's allocation wrapper and `memcpy(new, Data, *Data)`.
- `FUN_140daa8e0` (Get id 0): queries the required size via a vtable, rejects `OutLen == 0` / `OutLen < required`, then copies.

The same per-frame parser pattern and bounds logic is present in `kinonivd` (EpocCam baseline, section 4b). No `MmMapIoSpace`/`MmGetPhysicalAddress`/`MmMapLockedPages`/`ZwMapViewOfSection` import exists in this image. **W0.**

### 5.6 `kinonivad` / `kinonivd` - i386 (BLOCKED)

Both are `PE32 / i386` (`machine 0x14c`); the x64 kernel cannot load them, irrespective of DACL or signing. `kinonivad` is PortCls-only (no data handlers). `kinonivd`'s vendor Set handlers were traced in the EpocCam baseline: `0x222000` copies `InputBufferLength` into a buffer whose capacity is returned by a runtime vtable method, and the per-frame parser validates all lengths against the input buffer. Static **W0**; status **BLOCKED (i386)**.

### 5.7 Sink summary

| Image group | `MmMapIoSpace` | MDL map | Section map | Caller-length store | Write |
|---|---|---|---|---|---|
| BDA 1.1.0.194+ (63F8, A731, 9911, 5D0E, 4CCF) | device resource (HW) | - | - | none | W0 |
| BDA 1.1.0.189/191 (D40E, C56A, BF9A, 21A8, 8253) | device resource (HW) | driver-owned / 0x50 section | QCAP 0x50 (composition) | none | W0 |
| `ElgatoGC656/658` | - | - | - | **Get id 9/14/15** | **W2** |
| `elgatovirtualcamera` | - | - | - | none (checked) | W0 |
| `kinonivad`/`kinonivd` | - | - | - | none established (i386) | W0/BLOCKED |

---

## 6 Most dangerous exposed capability

**`ElgatoGC656` / `ElgatoGC658`, for an opener of the UB658 KS filter with the USB capture device present:** write a 64 KB blob with Set property `{7e797f9f-...}` id 0, then issue Get `{ab090437-...}` id 9 with an 0x20-byte output buffer. The handler copies the cached blob to `SystemBuffer + 0x1c` without consulting `OutputBufferLength`, producing a controlled pool overflow of up to 0xFFFB bytes. The two sibling Get handlers (ids 14/15) have the same defect with frame-sized copies. Target is the KS system-buffer pool block and its neighbour, not an arbitrary address; content and length are caller-controlled.

Everything else the family exposes is either the standard BDA video property surface (fixed-size structs, `ks.sys`-checked minimums), fixed-window device MMIO/DMA (`HW-ONLY`), or the 0x50-byte QCAP shared section (composition, no caller length into a kernel store).

---

## 7 Verdict

**Overall: `MW3 - reach=R3 setup=hardware write=W2 load=signed`.**

Two images carry a real, deterministic kernel pool overflow (W2) behind the USB capture devnode; the remaining twelve x64 images are `NO-MEMORY-WRITE` (eleven with `HW-ONLY` MMIO/DMA) and the two 32-bit images are `BLOCKED`.

### 7.1 Per-file table (all 16; SHA-256 verified)

| # | File | SHA-256 | Arch / version | Signer | Setup | Write | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | `CamLinkPro.X64_63F81CE8.SYS` | `63f81ce8b7850d72ad143a268a33f18b40a07a1e2f7bdfbcc0bad8f7f6abc322` | x64 / 1.1.0.194 | Corsair | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| 2 | `CamLinkPro.X64_D40EA12F.SYS` | `d40ea12f54802dd038a409aedee5eda7268d7c9abd3fc730b4244a9badca9d58` | x64 / 1.1.0.191 | Corsair | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| 3 | `CY3014.X64_A73163C8.SYS` | `a73163c84055186c00de46be90a2d3d660191b15b16f23463e7d4774f8d49451` | x64 / 1.1.0.194 | Corsair | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| 4 | `CY3014.X64_C56A09B3.SYS` | `c56a09b3a7fd8347aa9cb9b21dc33402adb672735edb6bdaedaaf2f0805a43e9` | x64 / 1.1.0.191 | Corsair | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| 5 | `e60MZ0380.X64_99118E2D.SYS` | `99118e2d4e78f5ee082e0d21cf9ffa0efbcb4382c8e97c10370bb32409701cdd` | x64 / 1.1.0.194 | Corsair | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| 6 | `e60MZ0380.X64_BF9A3116.SYS` | `bf9a311602c36ec814032538119ce5d05d614bb4d13033c4854e9c961604eef8` | x64 / 1.1.0.191 | Corsair | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| 7 | `ElgatoGC656_042CAFD9.sys` | `042cafd96162c18bd29669db5865eca8c2975a23ce19e7bea5caaf7f28a6b0de` | x64 / 2.1.1.5 | Elgato Systems | hardware | **W2** | **MW3** |
| 8 | `ElgatoGC658_C4597A53.sys` | `c4597a53985d357f72cdee1edcc785e6d9c68990cd89a25b43cc1d5701ae8dbe` | x64 / 2.1.1.5 | Elgato Systems | hardware | **W2** | **MW3** |
| 9 | `elgatovirtualcamera_D216849D.sys` | `d216849d0cac9c818622af028df4db311fb0124eb8dd96661ab1edbd2ed56451` | x64 / 1.3.4.97 | Microsoft WHCP | devnode | W0 | **NO-MEMORY-WRITE** |
| 10 | `eMZ0380.X64_75F9A47D.SYS` | `75f9a47d16f480090c6cf6740c971afe6e02f5229c6706ee4ac211850a5fa149` | x64 / 1.1.0.191 | Corsair | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| 11 | `kinonivad_AECF289A.sys` | `aecf289a83f1acb87d13831ab519b31a5317d012661524bd755d682c4f66b03c` | i386 / 6.1.7600 | Microsoft WHCP | devnode | W0 | **BLOCKED (i386)** |
| 12 | `kinonivd_844635B5.Sys` | `844635b5562cb2010285125fb216504ae1e2f03ce1874220af0d0a4630b2c291` | i386 / 10.0.10011 | Microsoft WHCP | devnode | W0 | **BLOCKED (i386)** |
| 13 | `PP.SC0710.X64_5D0EDF91.SYS` | `5d0edf91ea3e73488f3403f0209829346c6482699a25c3edf720e4c5ac10c399` | x64 / 1.1.0.202 | Corsair | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| 14 | `SC0710.X64_21A8968C.SYS` | `21a8968cebcd96c4cfd595e76c5942e530ddf151a4f608507a3078753e633092` | x64 / 1.1.0.191 | Corsair | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| 15 | `SC0710.X64_4CCFDEA2.SYS` | `4ccfdea23d22dcb8db480e6481578518448d178d173f52ba566c4d3dc3ae4049` | x64 / 1.1.0.198 | Microsoft WHCP | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| 16 | `UB3400.X64_825332A7.SYS` | `825332a70472a62a00cc4cc7a893aed033e32df25224470a753e4475f7c32fec` | x64 / 1.1.0.189 | Corsair | hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |

### 7.2 Severity lines

```
MW3 - reach=R3 setup=hardware write=W2 load=signed   ElgatoGC656_042CAFD9.sys
MW3 - reach=R3 setup=hardware write=W2 load=signed   ElgatoGC658_C4597A53.sys
NO-MEMORY-WRITE (HW-ONLY) - reach=R3 setup=hardware  CamLinkPro/CY3014/e60MZ0380/eMZ0380/PP.SC0710/SC0710/UB3400 (11)
NO-MEMORY-WRITE - reach=R3 setup=devnode             elgatovirtualcamera_D216849D.sys
BLOCKED (i386) - reach=R3 setup=devnode              kinonivad_AECF289A.sys, kinonivd_844635B5.Sys
```

### 7.3 Reclassification vs. the old baseline

| Old | New | Reason |
|---|---|---|
| All 16 `NO-WRITE` (hardware/devnode policy) | 2 x **MW3**, 12 x **NO-MEMORY-WRITE**, 2 x **BLOCKED** | Setup is now a severity field. The old pass disqualified the family on setup cost and did not review the UB658 property handlers; the unchecked output copy was not in the record. |
| `kinonivad`/`kinonivd` `NO-WRITE` | **BLOCKED (i386)** | Architecture, not a primitive downgrade; static W0 retained. |
| BDA MMIO `NO-WRITE` | **NO-MEMORY-WRITE (HW-ONLY)** | `MmMapIoSpace` maps the PnP memory resource; no caller PA/length. |

---

## 8 Limitations and unresolved paths

1. **GC656/GC658 dynamic confirmation absent.** The overflow is proven statically (C and assembly). It was not exercised; pool layout, tag, and the exact adjacent allocation are not measured. The write is deterministic, but exploitability depends on pool grooming and on the KS system-buffer allocation path. **No PoC was written.** Device presence on this host was not checked; `MW3` is the cap whether or not the dongle is attached.
2. **Default DACL not resolved.** `ks.sys`'s default filter descriptor was not read and no dynamic open was attempted. The report therefore claims `R3`/`R2`, not `R1`, even though media clients normally open capture filters as users.
3. **INF files absent.** Hardware IDs and the devnode DACL come from the package INF, which is not in `drivers/`. The `USB\VID_0FD9&PID_005C` binding for the UB658 pair is baseline-reported, not re-verified from the corpus.
4. **Per-file coverage of the BDA family.** All x64 images were covered by full handler decompilation: eleven analyses cover the fourteen x64 files, because the `.text`-identical pairs `D40EA12F`/`21A8968C`, `BF9A3116`/`75F9A47D`, and `GC656`/`GC658` share one analysis each. Every BDA build (`63F81CE8`, `D40EA12F`, `A73163C8`, `C56A09B3`, `99118E2D`, `BF9A3116`, `5D0EDF91`, `4CCFDEA2`, `825332A7`) was decompiled; each shows the same fixed-size property-handler pattern and no caller length reaching a copy.
5. **QCAP section.** The 2020 builds open `\BaseNamedObjects\QCAP.VCAM.V.*` and map a 0x50-byte RW view; the creator (a user-mode service) and the exact header semantics were not resolved. No caller length reaches a kernel store from this view in the code reviewed. This is a composition surface worth a dynamic check if the 2020 builds are ever in scope with the QCAP service installed.
6. **`kinonivd` vtable capacity.** The EpocCam baseline's one unproven link - the `0x222000` capacity returned by a runtime vtable method - remains unresolved. It is moot on this host (i386 image) and is recorded as static W0/BLOCKED.
7. **No REA cross-check** (four sessions active). All evidence is Ghidra 12.1.4 headless + `llvm-objdump` + PE parsing; addresses are linked VAs (image bases as stated).
8. **HVCI loadability not tested.** The UB658 pair is Authenticode-valid but signed by `Elgato Systems LLC` (2015), not WHQL-attested in the subject. If HVCI/secure boot rejects it, the status becomes `BLOCKED` while the static W2 primitive is retained as a reference.

*End of report.*
