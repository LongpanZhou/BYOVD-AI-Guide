# Audit: Virtual audio / Apple USB-audio group (6 images)

| Field | Value |
|---|---|
| File(s) | `drivers/VirtualAudioDriver_8F2DC680.sys` (75,120 B) · `drivers/vrtaucbl_7DA1B2AF.sys` (231,624 B) · `drivers/vrtaucbl_27DDD904.sys` (210,120 B) · `drivers/vrtaucbl_0A3D3BAB.sys` (224,968 B) · `drivers/usbaapl64_4DEC2FC2.sys` (54,784 B) · `drivers/netaapl64_D774DB02.sys` (23,040 B) |
| SHA-256(s) | `VirtualAudioDriver_8F2DC680.sys` **8F2DC680B0D218A18923F56D0B51D43729105072D4676436EB4B697FDFBB9AF3**<br>`vrtaucbl_7DA1B2AF.sys` **7DA1B2AF91198D31D37B413B1F9709377DFBFA95DD2DC0311375937645EB3E31**<br>`vrtaucbl_27DDD904.sys` **27DDD9041AECFD3EB39EB5895D3980A8EF594289DF486D029B4E653F1CADBA86**<br>`vrtaucbl_0A3D3BAB.sys` **0A3D3BAB2EAE66FC17F9DCFA7336336B2F20C1B1C79AD00224554DA672E92551**<br>`usbaapl64_4DEC2FC2.sys` **4DEC2FC20329F248135DA24CB6694FD972DCCE8B1BBEA8D872FDE41939E96AAF**<br>`netaapl64_D774DB02.sys` **D774DB020D9C46D1AA0B2DB9FA2C36C4A9C38D904CC6929695321D32ACA0D4D1**<br>(all recomputed with `Get-FileHash -Algorithm SHA256` on the exact files listed above) |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local **Ghidra 12.1.4 headless** (`C:\tools\ghidra_12.1.4_PUBLIC`, JDK 21) for PE parse, auto-analysis, decompile and dispatch-table recovery; **llvm-objdump 19** for PE headers, imports and architecture confirmation; raw-image byte search for cross-build constants. No load, install, service, registry write or execution. No web. |
| REA cross-check | **Not used — capacity.** Four REA audits were already active (`CBUL*`, `usbdaqlib*`, Brainboxes, Blackmagic). Per the scope rule this audit proceeded offline with Ghidra only and records its dump paths. No REA evidence IDs exist for this report. |
| Reach tier | **R3** at group level (devnode / hardware / composition). Per file: `VirtualAudioDriver` R3-devnode; `vrtaucbl` ×3 R3-devnode (KS filter, normally user-openable → R1 surface); `usbaapl64` **R2** (`\Device\IPOD<n>`, default device descriptor) **+ hardware**; `netaapl64` R3-hardware (no openable handle at all). |
| Setup required | **devnode** (VirtualAudioDriver, vrtaucbl ×3) · **hardware** (usbaapl64, netaapl64) |
| Write quality | **W0** (all six) |
| Verdict | **NO-MEMORY-WRITE** — `reach=R3 setup=devnode|hardware write=W0 load=signed` (static). Overall verdict for the group is **NO-MEMORY-WRITE**; no MW1–MW4, no BLOCKED primitive. |
| HW-ONLY | **No.** None of the six exposes MSR / port-I/O / PCI-config / SMBus-EC / fixed-window MMIO sinks at all. This is *not* a HW-ONLY result; it is "no write sink". |

> Static analysis only. Nothing was loaded, installed, started or executed. This report contains no exploit code and no operating steps.

**Architecture note.** Five images are x86-64 or x86. `vrtaucbl_0A3D3BAB.sys` is **AARCH64** (`coff-arm64`, PE32+, machine 0xAA64) and is **not loadable on this x64 host**; its verdict is therefore a static/structural one, not a loadable-host finding.

---

## 0. Per-file result table

| # | File | Arch | Product / build | Entry surface | Effective DACL / open gate | Write quality | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | `VirtualAudioDriver_8F2DC680.sys` | x86-64 | MS "Virtual Simple Audio Sample Driver" 10.0.10011.16384, TD 2025-07-14 | PortCls adapter + topology/wave subdevices; no control device | none in image; PortCls/INF-supplied (INF not in corpus) | W0 | **NO-MEMORY-WRITE** |
| 2 | `vrtaucbl_7DA1B2AF.sys` | x86-64 | Virtual Audio Cable 4.71.0.14195 (trial), TD 2026-06-20 | PortCls WDM/KS adapter; `IRP_MJ_CREATE` name parser; 4 IOCTL branches + `PcDispatchIrp` | none in image; PortCls KS interface `{146F1A80-4791-11D0-A5D6-28DB04C10000}` (normally user-openable) | W0 | **NO-MEMORY-WRITE** |
| 3 | `vrtaucbl_27DDD904.sys` | i386 | same product/build (x86), TD 2026-06-20 | same | same | W0 | **NO-MEMORY-WRITE** |
| 4 | `vrtaucbl_0A3D3BAB.sys` | **AARCH64** | same product/build (arm64), TD 2026-06-20 | same | same — **not loadable on x64 host** | W0 | **NO-MEMORY-WRITE** (static) |
| 5 | `usbaapl64_4DEC2FC2.sys` | x86-64 | Apple Mobile Device USB Driver 1.67.0.0, TD 2015-06-11 | WDM USB FDO + `\Device\IPOD<n>` PDO; 21 IOCTL cases, all `METHOD_BUFFERED` | `IoCreateDevice`, **no SDDL** → I/O-manager default (`SYSTEM`+`Administrators`, corpus label `DEFAULT-ADMIN`); needs Apple USB device | W0 | **NO-MEMORY-WRITE** |
| 6 | `netaapl64_D774DB02.sys` | x86-64 | Apple Mobile Device Ethernet 1.8.5.1, TD 2013-07-15 | NDIS 5.x miniport only — **no device object, no IOCTL path** | n/a (no openable object) | W0 | **NO-MEMORY-WRITE** |

**Overall verdict: NO-MEMORY-WRITE for all six files.** No caller-controlled pointer, offset, length or physical address reaches a kernel store in any of them. Details, including the exact sink list and the boundary checks that stop each one, follow.

---

## 1. Internals

**`VirtualAudioDriver_8F2DC680.sys`** — derivative of the WDK *Virtual Simple Audio Sample* driver (Microsoft-signed binary, later rebuilt with a tone generator and WAV capture logger added). KMDF 1.x class-bound (`WdfVersionBind` / `WdfVersionBindClass`) plus PortCls miniport. Imports: `ntoskrnl` (registry, pool, timers, `ZwCreateFile`/`ZwWriteFile`), `HAL`, `portcls` (`PcNewMiniport`, `PcNewPort`, `PcRegisterSubdevice`, `PcAddAdapterDevice`, `PcDispatchIrp`, `PcRegisterPhysicalConnection`), `WDFLDR`. **No `Mm*` memory API of any kind** — no `MmMapIoSpace`, no `MmMapLockedPagesSpecifyCache`, no `MmGetPhysicalAddress`, no `MmCopyMemory`, no `ZwMapViewOfSection`; and **no `ProbeForRead`/`ProbeForWrite`**. 246 functions, most of them tiny COM-style thunks.

**`vrtaucbl_*.sys`** — Virtual Audio Cable 4.71 (Eugene V. Muzychenko), a PortCls WDM/KS adapter with its own cable/format state machine. Rich kernel API set: `MmMapLockedPagesSpecifyCache`, `MmAllocatePagesForMdl`, `MmGetPhysicalAddress`, `MmCreateSection`, `MmMapViewInSystemSpace`, `MmMapViewOfSection`, `ProbeForRead`, `ProbeForWrite`, `KsProbeStreamIrp`, `KsAcquireResetValue`, `ObReferenceObjectByHandle`, `PsInitialSystemProcess`, `KeBugCheckEx`. 495 functions in the x64 build. All three builds are stamped within 15 s of each other (2026-06-20 12:50:48 / 53 / 58), carry the same `UniLib 2.71.0.9075` and the same vendor strings, and share identical import tables — **they are the same source built for three architectures.**

**`usbaapl64_4DEC2FC2.sys`** — Apple Mobile Device USB Driver 1.67.0.0 (2015). WDM function driver that attaches to the USB stack (`IoAttachDeviceToDeviceStack`) and also creates numbered control PDOs `\Device\IPOD0..n`. It registers a WMI library callback (`WmiSystemControl`) and a bugcheck callback. 134 functions.

**`netaapl64_D774DB02.sys`** — Apple Mobile Device Ethernet 1.8.5.1 (2013), a **NDIS 5.x miniport**: `NdisMRegisterMiniport` plus `NdisMRegisterUnloadHandler` are the entire registration surface. 51 functions.

---

## 2. Entry / device / interface / effective DACL

### 2.1 `VirtualAudioDriver_8F2DC680.sys`
- `entry` @ `0x140002530` → `FUN_1400111ec` (**DriverEntry**) → `PcInitializeAdapterDriver(DriverObject, RegistryPath, FUN_14000a000)`.
- `FUN_14000a000` (**AddDevice**) → `PcAddAdapterDevice(DriverObject, PDO, FUN_14000a530, 4, 0)`.
- FDO dispatch `FUN_14000a470` is a bare `PcDispatchIrp` forwarder. No `IoCreateDevice`, no `IoCreateSymbolicLink`, no `IoCreateDeviceSecure` anywhere in the image.
- Subdevices registered via `FUN_14000b37c` → `PcRegisterSubdevice`, with `IoRegisterDeviceInterface` for each; topology/wave pairs named `TopologySpeaker`, `WaveSpeaker`, `TopologyMicArray1`, `WaveMicArray1`.
- **Effective DACL:** not encoded in the image. It is whatever PortCls assigns to the adapter/subdevice objects plus whatever the (absent) INF `AddReg` sets. The INF is not in the corpus (`drivers/` is `.sys`-only, and no `*.inf` exists anywhere under `driver_candidates`).
- **Open gate:** the KS audio endpoint; by Windows audio convention openable by any authenticated user. This cannot be proven from this image.

### 2.2 `vrtaucbl_7DA1B2AF.sys` (x64; x86/arm64 identical structure)
- Adapter init `FUN_14000a200`: `IoRegisterDeviceInterface(FDO, &DAT_140022f78 /* {146F1A80-4791-11D0-A5D6-28DB04C10000} */, 0, ...)` then `PcAddAdapterDevice(DriverObject, PDO, FUN_14000b2e0, Channels*4, 0)`.
- FDO dispatch `FUN_14000a2a0` → `PcDispatchIrp`; the device-control path is overridden by `FUN_14000a690` (§3.2).
- `IRP_MJ_CREATE` = `FUN_14000a360`. It takes the **user-supplied remainder of the interface path** (`FileObject->FileName`, `+0x58` Length / `+0x60` Buffer), matches the prefix `{146F1A80-4791-11D0-A5D6-28DB04C10000}\`, and parses the trailing format text. That text is clamped: `if (0x12 < uVar7) uVar7 = 0x13;` before `FUN_14001bed0(local_2e8, uVar7, ...)` into a 24-`wchar_t` stack buffer (19 max). A second magic-triple `0x11cf62ce1a8766a0 / 0xc104db28d6a5` + version `1` records the client's requested format on the per-open context.
- **No `IoCreateDevice` / `IoCreateSymbolicLink` in the import table or in code.** There is no raw control device; the whole user surface is the PortCls KS filter plus that device interface.
- **Effective DACL:** not in the image (no SDDL string, no `RtlSetDaclSecurityDescriptor`, no `Se*` call). PortCls supplies it; audio endpoints are normally openable by any authenticated user, i.e. an **R1-grade surface** — but it is a *reach* statement, not a write.

### 2.3 `usbaapl64_4DEC2FC2.sys`
- `entry` @ `0x1f064` → `FUN_1f008` (CRT init) + `FUN_11008` (DriverEntry body).
- `FUN_11008` installs: `DriverUnload` (DriverObject+0x68) = `FUN_16708`; `DriverExtension->AddDevice` (+0x30 → +0x8) = `FUN_16738`; `MajorFunction[0x70..0x148]` CREATE, CLOSE, READ, WRITE, DEVICE_CONTROL, INTERNAL_DEVICE_CONTROL, POWER, SYSTEM_CONTROL, PNP = `FUN_111dc`.
- `FUN_16738` (AddDevice) → `IoCreateDevice(DriverObject, 0x10b8, NULL, 0x22, 0x80, 0, &devObj)` and `IoAttachDeviceToDeviceStack` — the FDO, device extension tagged `'aFDO'` (`0x4f444661`).
- The **control PDO** `\Device\IPOD<n>` is created by `FUN_14e54` via `IoCreateDevice(DriverObject, 0x1c0, "\Device\IPOD"+n, 0x22, ...)`, retrying on `STATUS_OBJECT_NAME_COLLISION` up to `IPODn`. It is reached **only** from the device-start / power / PnP path (`FUN_147f0`, `FUN_180e4`, `FUN_182b4`, `FUN_18504`) — i.e. only after an Apple USB device enumerates.
- **Effective DACL:** `IoCreateDevice` with **no security descriptor and no `IoCreateDeviceSecure`**. The object therefore receives the I/O manager's default device descriptor for a SYSTEM-created object — in practice `SYSTEM` + `BUILTIN\Administrators` (the corpus triage value `DEFAULT-ADMIN`). This is **not statically provable from the image**; treat the gate as **R2**. The `FILE_ANY_ACCESS` nature of every IOCTL (§3.3) means that *if* the default descriptor also grants `Everyone` `FILE_GENERIC_READ`, an ordinary user could issue them with a read handle — that caveat is recorded, unverified, and changes nothing about the write analysis.
- **Setup:** `hardware` — the control devices exist only while the Apple USB device is present and started.

### 2.4 `netaapl64_D774DB02.sys`
- `entry` @ `0x12920` → `FUN_1a008` → `NdisInitializeWrapper` + `NdisMRegisterMiniport(..., &MINIPORT_CHARACTERISTICS, 0xf0)` and `NdisMRegisterUnloadHandler`.
- **No device object is created and no IRP dispatch table is installed.** There is no name, no symbolic link, no interface and therefore no DACL and no open gate. User-mode reach is limited to NDIS OIDs and frame I/O mediated entirely by NDIS; the driver sees only NDIS-allocated packets and MDLs.

---

## 3. Dispatch and IOCTL table

### 3.1 `VirtualAudioDriver_8F2DC680.sys`
No IOCTL table exists in the image. `IRP_MJ_DEVICE_CONTROL` is PortCls's; the driver only answers KS property/method requests through its miniport COM vtables. Writes performed by the driver itself:

| Action | Site | Target | Caller control |
|---|---|---|---|
| Pool fills / copies | `ExAllocatePool2` sites at 0x1400013xx–0x1400015xx, e.g. `ExAllocatePool2(0x40,0x118,'uAyS')` | own pool blocks | none |
| Tone/WAV logging | `ZwCreateFile` / `ZwWriteFile` under `\DriverData\Audio_Samples\VirtualAudioDriver\*_*.wav` | file object | none |
| Registry | `ZwCreateKey` / `ZwSetValueKey` under its own driver key | registry | none |

No `memcpy`, no `RtlCopyMemory`, no `Mm*` call, and no `Probe*` in the whole binary.

### 3.2 `vrtaucbl_7DA1B2AF.sys` — `IRP_MJ_DEVICE_CONTROL` dispatcher `FUN_14000a690`

| IOCTL | Decode | Method | Access | Handler | Kernel action |
|---|---|---|---|---|---|
| `0x2F4017` | dev `0x2F` (KS), fn 5 | `METHOD_NEITHER` | `FILE_WRITE_ACCESS` | `FUN_140014a40` | KS stream create: `KsProbeStreamIrp`, walk `Irp->MdlAddress` chain, `MmMapLockedPagesSpecifyCache` each MDL, store the system VAs in a private array; also used by KS write-stream |
| `0x2F8013` | dev `0x2F`, fn 4 | `METHOD_NEITHER` | `FILE_READ_ACCESS` | `FUN_140014a40` | same, read direction |
| `0x2F0003` | `IOCTL_KS_PROPERTY` | `METHOD_NEITHER` | `FILE_ANY_ACCESS` | 3-way: private-magic → `FUN_1400145d0`; magic-registration → global list insert; otherwise `FUN_140011f80` / `PcDispatchIrp` | reads a fixed 0x18-byte request header, then fixed 0x10 or 0x28-byte reply |
| `0x2F001B` | `IOCTL_KS_RESET_STATE` | `METHOD_NEITHER` | `FILE_ANY_ACCESS` | `FUN_140014900` | `KsAcquireResetValue` + cable state reset |
| everything else | — | — | — | `PcDispatchIrp` | PortCls |

- Private handshake constants (present in **all three** builds as 16 adjacent bytes in `.rdata` — file offsets 136536/136552 x64, 131456/131472 x86, 139624/139640 arm64): `0x11d06e1b45ffaaa0` + `0x54534544f2bc`, and `0x11cf51ad8c134960` + `0xc101f8948a87`. A third pair `0x11cf62ce1a8766a0` + `0xc104db28d6a5` gates the create-time format record. These are magic values, **not** an auth boundary — any caller can replay them — but they only reach *fixed-size* copies.
- The byte in the `IRP` request header at `local_5c & 2` must be set before the registration path runs; still a constant, still fixed-size state.
- The private property handler `FUN_140011f80` additionally requires the caller to be `audiodg` (`FUN_14000c1f0(-1, name, 0x50)` + `_wcsicmp(..., L"audiodg")`), and the per-cable "format attribute" flag at `+0xa3a` must be clear. That is a **process-name check, which is spoofable** — record it as a gate of no security value, but again it only reaches an 8-byte reply.

### 3.3 `usbaapl64_4DEC2FC2.sys` — `FUN_111dc` tag dispatch → `FUN_11350` (FDO `IRP_MJ_DEVICE_CONTROL`)

`FUN_111dc` selects a 16-byte-stride `MajorFunction` table by the device-extension tag: `'aFDO'` (`0x4f444661`) → `.data 0x1d2b8`, `'aPDO'` (`0x4f445061`) → `.data 0x1d478`; `MajorFunction >= 0x1c` returns `STATUS_INVALID_DEVICE_REQUEST`. Recovered tables:

- **FDO**: CREATE `FUN_11264`, CLOSE `FUN_111d0`, READ `FUN_166c0`, WRITE `FUN_19534`, QUERY_INFORMATION `FUN_19598`, **DEVICE_CONTROL `FUN_11350`**, INTERNAL_DEVICE_CONTROL `0x16b30` (pure pass-down).
- **PDO**: CREATE `FUN_166c0`, CLOSE `FUN_111d0`, **DEVICE_CONTROL `0x17a80`**, INTERNAL_DEVICE_CONTROL `FUN_11814`.
- `0x17a80` and `0x16b30` are *not* functional handlers. Disassembly forced at those addresses shows the identical 5-instruction pass-down stub: `mov rcx,[rcx+0x40]` (device extension) · `inc byte [rdx+0x43]` (`Irp->CurrentLocation`) · `add qword [rdx+0xb8],0x48` (`IoSkipCurrentIrpStackLocation`) · `mov rcx,[rcx+0x88 / 0xf0]` (lower device object) · `jmp [0x1b068]` (`IofCallDriver`). **The PDO handles no IOCTL itself; it forwards everything to the USB stack.**

`FUN_11350` switch (all `DeviceType 0x22` = `FILE_DEVICE_UNKNOWN`, **`Access 0` = `FILE_ANY_ACCESS`**, **`Method 0` = `METHOD_BUFFERED`**):

| IOCTL | Function | Kernel action | Bound |
|---|---|---|---|
| `0x220000` | 0 | write `{1,0}` to `SystemBuffer` | `OutputBufferLength >= 4` |
| `0x220004` | 1 | copy a device-extension string (len = first byte) | `len <= OutputBufferLength` |
| `0x220008` | 2 | copy a device-extension string (len = `ushort` at +2) | `len <= OutputBufferLength` |
| `0x22000C` | 3 | conditional device-extension action | `OutputBufferLength >= 0x10`, `InputBufferLength >= 0x10` |
| `0x220010` | 4 | device-extension action | same |
| `0x220014` | 5 | device-extension action | same |
| `0x2200A0` | 0x28 | `FUN_17d20` → build URB, send down | `In/Out >= 0x10`; further checks in builder |
| `0x2200A4` | 0x29 | `FUN_17e78` → copy descriptor fields | `InputBufferLength >= 0x18`, `OutputBufferLength >= 0x18` |
| `0x2200A8` | 0x2A | `FUN_188d0` | same |
| `0x2200AC` | 0x2B | `FUN_17f50` | same |
| `0x2200B0` | 0x2C | reply `{1,0x43,1,0}` | `In/Out >= 0x10` |
| `0x2200B4` | 0x2D | `FUN_18030` | `In/Out >= 0x10` |
| `0x2200B8` | 0x2E | 4-byte read from device extension | `In/Out >= 4` |
| `0x2200BC` | 0x2F | `memcpy(SystemBuffer, ext+0x2C8, 0x4C)` | `In/Out >= 0x4C` |
| `0x2200C0` | 0x30 | 4-byte read from device extension | `In/Out >= 4` |
| `0x2200C4` | 0x31 | `FUN_18504` | `In/Out >= 0x10` |
| `0x2200CC` | 0x33 | compare 7-byte input `"USBAAPL"` then `FUN_1191c(0x22001F)` | `InputBufferLength == 7` |
| `0x2200D0` | 0x34 | `FUN_18698` | `In/Out >= 4` |
| `0x2200D4` | 0x35 | read 16 bytes from device extension `+0x710/+0x718` | `OutputBufferLength == 0x10` |
| `0x2200D8` | 0x36 | `FUN_188d0(...,2)` | — |
| `0x2200DC` | 0x37 | `FUN_17e78(...,2)` | `In/Out >= 0x18` |
| other | — | `FUN_18b2c` → USB control transfer sized from the IOCTL function field | length from `(code>>2)&0xFFF`, compared against a descriptor-table maximum |

### 3.4 `netaapl64_D774DB02.sys`
No IOCTL table. The only externally driven entry points are the NDIS miniport callbacks installed at `DAT_0001a5xx` (Initialize, Halt, Reset, Send, ReturnPacket, OID, Status…). `FUN_11fb8` is the receive-copy helper (`MmMapLockedPagesSpecifyCache` over the driver's own receive MDLs, `memcpy` into the NDIS-supplied destination, size capped at `0x5EA`).

---

## 4. Access-control audit

| Check | Where | Result |
|---|---|---|
| `SeSinglePrivilegeCheck` / `SeAccessCheck` / `SeTokenIsAdmin` / `RtlIsSandboxedToken` | **none of the six images** (import table + full decompile scan) | no privilege gate exists to bypass |
| Explicit SDDL / `IoCreateDeviceSecure` | none of the six | `usbaapl64` uses plain `IoCreateDevice`; `VirtualAudioDriver`/`vrtaucbl` devices are PortCls-created; `netaapl64` has no device |
| `FILE_ANY_ACCESS` IOCTLs | `usbaapl64` (all 21), `vrtaucbl` KS property/reset | the I/O manager performs no per-IOCTL access check; the handle's granted access is the only gate |
| Process-name "auth" | `vrtaucbl` `FUN_140011f80` requires `audiodg` | spoofable, **not** a security boundary — but reaches only an 8-byte reply |
| Magic-value handshake | `vrtaucbl` private KS property/name protocol | constants recoverable from `.rdata`; **not** a boundary — reaches only fixed-size copies |
| `PsInitialSystemProcess` comparison | `vrtaucbl` `FUN_14000a360`, `FUN_14000c450` | used only to *label* log lines ("system" vs process name), not to gate anything |
| `RequestorMode` / `IRP_BUFFERED_IO` handling | `vrtaucbl` `FUN_14000c3c0`, `FUN_14000c610` | correct: probes only when `RequestorMode != KernelMode` and the buffer is not the system buffer |

No file has a gate that, once satisfied, unlocks a memory-write path. Every gate above leads only to fixed-size or length-checked copies of that driver's own state.

---

## 5. Memory-write trace

### 5.1 `VirtualAudioDriver_8F2DC680.sys`
**No sink at all.** The binary contains no `memcpy`, no `RtlCopyMemory`, no `Mm*` memory API, no `Probe*`, no MDL handling, no caller-supplied pointer arithmetic. Its writes are limited to pool blocks it allocated itself, its own registry key, and WAV files it creates. **Trace ends at allocation size.**

### 5.2 `vrtaucbl_*.sys` — every copy sink in the x64 build, and what bounds it

| Sink | Site | Destination | Source | Length | Bound |
|---|---|---|---|---|---|
| request → kernel | `FUN_14000c3c0` (`0x14000c3c0`) | caller's kernel struct | `Irp->SystemBuffer`, or `Type3InputBuffer` for `METHOD_NEITHER`, or `Irp->UserBuffer` | `param_3 & 0xFFFFFFFF` | **both call sites pass a literal**: `0x18` (`FUN_14000a690`, `FUN_1400145d0`) and `0x10` (`FUN_1400145d0`). `ProbeForRead` is applied when `RequestorMode != KernelMode` and the buffer is not the system buffer. |
| kernel → user | `FUN_14000c610` | `SystemBuffer` or `UserBuffer` | caller's kernel struct | same fixed sizes | `ProbeForWrite` when user + not buffered; callers pass `0x28` / `0x10` only after `OutputBufferLength >= 0x10` / `>= 0x28` |
| property get | `FUN_14000f550`, `FUN_14000f670`, `FUN_140011f80`, `FUN_1400145d0` | user output buffer | device extension / static tables | fixed or string length | explicit `if (OutputBufferLength < len) return STATUS_BUFFER_TOO_SMALL` **before** every `RtlMoveMemory` (verified at each of these sites) |
| KSDATAFORMAT parse | `FUN_140019ea0` (`0x140019ea0`) | 0x28-byte stack struct | caller data | declared `FormatSize` | `FormatSize >= 0x40`, `BlockSize >= FormatSize`, `FormatSize >= 0x52/0x5A`, `cbSize` re-checked; every read offset is proven `< FormatSize` first. No overflow found. |
| cable configuration | `FUN_140005e80` (`0x140005e80`) | **fixed fields** of the per-cable extension | registry/IOCTL parameter block | field-by-field, each with a range test (`< 100`, `< 0x14`, `< 4`, `< 3`, `< 2`, `& 7`, …) | caller **value**, fixed **target** → state write, not a memory-write primitive |
| stream buffer map | `FUN_140014a40` (`0x140014a40`) | URB context array | `Irp->MdlAddress` chain | `KsProbeStreamIrp` first; per-MDL `MmMapLockedPagesSpecifyCache` | maps the *KS-allocated* stream MDLs; used for audio data movement |
| 4 KB scratch | `FUN_140005e80`, `FUN_1400167f0` | `MmAllocatePagesForMdl` + `MmMapLockedPagesSpecifyCache` | — | literal `0x1000` | fixed |
| shared section | `FUN_14000c910` / `FUN_14000ca10` | `MmCreateSection` + `MmMapViewInSystemSpace` (kernel) + `MmMapViewOfSection` **into the current process** | — | section size argument | the client view is created with `Win32Protect = 2` — **`PAGE_READONLY`**. The client cannot write the shared page. |
| clock/position reply | `FUN_1400145d0` | user output buffer | `KeQueryPerformanceCounter`, cable counters | `0x28` or `0x10` | `OutputBufferLength >= 0x28` / `>= 0x10` checked, plus a signature `0x11d06e1b45ffaaa0/0x54534544f2bc` and local-version `5`/`0x32` check |

The single `memcpy(kernel_dst, user_src, n)` in the driver (`FUN_14000c3c0`) is a **fixed-length** copy reached only with `n = 0x18` or `n = 0x10`, into stack or carefully-sized local structs. There is **no** `memcpy` whose length comes from `InputBufferLength`, from a length field inside the caller's data, or from the IOCTL code. `MmMapLockedPagesSpecifyCache` is only ever called with an MDL the driver itself built or received from KS, never with a caller-supplied physical address. `MmGetPhysicalAddress` is called once (`FUN_14000a060`) on a device-extension pointer after verifying a 0x100-byte all-`0xCC` guard pattern — a self-check, no caller input.

### 5.3 `usbaapl64_4DEC2FC2.sys`
All 23 IOCTLs are `METHOD_BUFFERED`, so both directions live in `Irp->AssociatedIrp.SystemBuffer`, which the I/O manager sized as `max(InputBufferLength, OutputBufferLength)`. Every write site re-checks the relevant length first:

| Sink | Site | Detail |
|---|---|---|
| `FUN_11350` fixed replies | `0x220000`, `0x2200B0`, `0x2200B8`, `0x2200BC`, `0x2200C0`, `0x2200D4` | 4 / 0x10 / 0x4C byte writes to `SystemBuffer`, each preceded by an exact `Input/OutputBufferLength` test |
| `FUN_193f8` | `0x220004`, `0x220008` | `if (len <= OutputBufferLength) memcpy(SystemBuffer, ext, len)`; **no write on failure** |
| `FUN_17e78`, `FUN_188d0` | `0x2200A4/8/A8/AC/D8/DC` | require `In >= 0x18` **and** `Out >= 0x18` before touching 6 fields at offsets 4..0x18 |
| `FUN_18a10` (completion) | stream replies | `memcpy(dst+8, ctx->buf, URB.Control.TransferBufferLength)` where `dst` is `SystemBuffer` (buffered) or `MmMapLockedPagesSpecifyCache(Mdl)` (direct). `TransferBufferLength` is set by `FUN_17b94` to `InputBufferLength-8` (buffered) or `Mdl->ByteCount-8` (direct), so `8 + len <= max(In,Out)` respectively `<= Mdl->ByteCount`. The URB is built by the driver, not by the caller. |
| `FUN_18b2c` fixed-size path | fall-through IOCTLs | transfer length is **derived from the IOCTL function field**, `(code>>2)&0xFFF`, then required `<` a descriptor-table maximum (`*(uint*)(descr+0x10)`), and the source buffer is a descriptor-table pointer — not the caller's buffer |
| `FUN_18edc` | pass-through | requires **both** `InputBufferLength == 0` and `OutputBufferLength == 0`; reuses the incoming IRP downward with internal code `0x220003` |

No caller-supplied pointer, offset or physical address reaches a store. `IoBuildDeviceIoControlRequest` and `IoAllocateIrp` are used only to send *its own* requests down the USB stack. The PDO's device-control handler forwards blindly and stores nothing.

### 5.4 `netaapl64_D774DB02.sys`
One variable-length copy: `FUN_11fb8` maps the receive MDLs (`MmMapLockedPagesSpecifyCache(..., 1 /*cached*/, ..., 0x10)`) and `memcpy`s into the destination packet buffer carried in the NDIS packet (`param_2+0x48`). The length is `min(0x5EA, MDL->ByteCount)` and the loop stops at `0x5EA`; the destination is an NDIS-allocated packet buffer, not an arbitrary kernel address. There is no user-mode handle to reach this function with attacker-chosen parameters.

---

## 6. Most dangerous exposed capability

| File | Most dangerous thing it can actually do |
|---|---|
| `VirtualAudioDriver` | Write audio samples and WAV files; read/write its own registry key. |
| `vrtaucbl` ×3 | Move audio data through KS stream MDLs; configure its own cable state from a magic-tagged private protocol; hand the client a **read-only** view of a shared section. |
| `usbaapl64` | Issue USB control transfers and pass-through internal IOCTLs to the USB stack; report its own descriptor bytes to the caller. Requires the Apple device. |
| `netaapl64` | Indicate and copy Ethernet frames on an NDIS miniport. No user-visible object. |

None of these is a kernel memory write. The closest thing to a "write" anywhere in the group is `usbaapl64`'s `memcpy(SystemBuffer, ext+0x2C8, 0x4C)` — a fixed 76-byte copy of the driver's own state into a buffer the I/O manager guaranteed is at least 0x4C bytes because of the check that precedes it. That is a **disclosure/state** sink, not a write primitive.

---

## 7. Verdict

**NO-MEMORY-WRITE — reach=R3 setup=devnode|hardware write=W0 load=signed (static).**

| Verdict axis | Value |
|---|---|
| Severity | `NO-MEMORY-WRITE` (all six) |
| Write quality | `W0` (all six) |
| MW scale | not applicable — no MW1, MW2, MW3 or MW4 |
| `HW-ONLY` | **no** — there are no MSR / port-I/O / PCI-config / SMBus-EC / MMIO sinks either |
| `BLOCKED` | **no** — signed images, all obtainable; the arm64 build is architecture-limited, not blocklisted |
| Reach | R3 group; `usbaapl64` R2 (default device DACL) + hardware |
| Setup | devnode (4 files), hardware (2 files) |

There is **no** caller-pointer-into-kernel-store, no caller-length kernel copy, no MDL/PortCls mapping with a caller-controlled size, and no fixed- or caller-value write to a caller-influenced kernel address in any of the six images. `vrtaucbl`'s `MmMapLockedPagesSpecifyCache` / `MmAllocatePagesForMdl` / `MmCreateSection` / `MmMapViewOfSection` use is entirely internal or maps the shared page **read-only** into the client. `usbaapl64`'s IOCTL set is a bounded USB control-transfer wrapper over the IRP system buffer. `netaapl64` is a legacy NDIS miniport with no openable object. `VirtualAudioDriver` has no memory API at all.

This group is **not** a kernel memory-write candidate on the evidence examined. It should be recorded as `NO-MEMORY-WRITE (W0)` and removed from the write-primitive queue.

---

## 8. Limitations

1. **REA cross-check not performed** — four REA sessions were already active; per scope rule 6 this audit is Ghidra-only. Independent confirmation of the PortCls and `usbaapl64` findings via a second engine is outstanding.
2. **No dynamic verification.** Nothing was loaded or opened. Every DACL statement is inferred: `usbaapl64`'s `DEFAULT-ADMIN` label is **not statically provable** (no SDDL in the image) and should be confirmed with `WinObj`/`GetSecurityInfo` if it is ever cited for impact. `VirtualAudioDriver` and `vrtaucbl` device DACLs are supplied by PortCls and are likewise not in the images.
3. **INF files are absent** from the corpus (`drivers/` is `.sys`-only; no `*.inf` under `driver_candidates`). The `AddReg` `Security` value that would settle the devnode DACLs could not be read. The "non-admin can open" question therefore cannot be answered from artifacts in scope.
4. **`vrtaucbl` depth.** The x64 build has 495 functions. All copy sinks (`memcpy`, `RtlMoveMemory`, `RtlFillMemory`, `RtlZeroMemory`, `ProbeFor*`, `MmMap*`) were enumerated and each was traced to its bound; the KSDATAFORMAT/KSATTRIBUTE parsers, the private property/method handlers and the create-path name parser were read in full. The audio **data-path** DSP/mixing routines (format conversion, mixing, clock correction) were sampled, not exhausted line by line. A length bug confined to those routines cannot be excluded by this pass, though every one of their copies is sized from the negotiated format/period rather than from caller input.
5. **`vrtaucbl_27DDD904` / `_0A3D3BAB` are structural, not independent.** They are the same source built for i386 and AARCH64 (same build stamp window, same `UniLib` version, same imports, same handshake constants at corresponding file offsets). They inherit the x64 finding by equivalence; they were not decompiled function-by-function. The ARM64 image is **not loadable on this x64 host**.
6. **`usbaapl64` is a 2015 binary.** `FUN_18a10`'s completion copy was reasoned about from the URB construction sites (`FUN_17b94`, `FUN_18c98`) rather than from a live transfer; the invariant `8 + TransferBufferLength <= system-buffer size` holds for every construction site found, but a hidden builder would invalidate it.
7. `netaapl64`'s NDIS 5 OID handlers were only skimmed: they exchange fixed-size `NDIS_REQUEST` structures via NDIS, and no OID path writes to a caller-supplied address.

### Analysis artifacts (not part of the report corpus)

| Item | Path |
|---|---|
| Ghidra project (x64 group) | `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\va_group\proj\va` |
| Ghidra project (VirtualAudioDriver) | `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\va_group\proj2\va2` |
| Full dumps (imports / functions / strings) | `…\va_group\full_<image>.txt` |
| Decompiled bodies | `…\va_group\dec_vac64.txt`, `dec_usbaapl64.txt`, `dec_netaapl64.txt`, `dec_vadrv.txt` |
| Disassembly side-dumps | `…\va_group\x86.asm`, `arm64.asm` |
| Helper scripts | `…\ghidra_scripts\VaFull.java`, `VaDec.java`, `VaTable.java`, `VaHex.java`, `VaRange.java`, `VaForce.java`, `VaRefs.java`, `VaXref.java` |
