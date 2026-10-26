# Audit: collected3 gap drivers (7 files)

| Field | Value |
|---|---|
| File(s) | `dlcdcncm660_0FFDDEF9.sys`, `dlcdcncm660_F7F3367C.sys`, `imdisk_arm64.sys`, `spacedeskDriverAndroidControl.sys`, `spacedeskDriverAndroidUsb.sys`, `spacedeskKtmInput.sys`, `spacedeskVideoCapture.sys` (all in `drivers/`) |
| SHA-256(s) | `0FFDDEF95C77424463D2758BBA730024495CF64965B2D8B11D94368E29168F39` (dlcdcncm660 ARM64)<br>`F7F3367C604588D63981E14933537C4C54A7C08D75CBB245AF8A420755E1D867` (dlcdcncm660 AMD64)<br>`48ED9FF2924071FC64DE651E272C1041BD8E04063C43603550DED7D945B2E1E8` (imdisk_arm64)<br>`61FB72840FCCACDADCD60F86441153F009786257B4479A80A562B8CECF88A0A0` (AndroidControl)<br>`D4B4037DA983411AC8F2C617833680F2EC546A8FC39339FDC51BE116B6C79B88` (AndroidUsb)<br>`3A8501F0EB0D0CC46CEB83F82775FB85AC60209F5FD8B4E54FED5AE45EEEEE01` (KtmInput)<br>`86D6AFC68CC135685217A5EA13FE64505E145FC079D0DEE922CBDBEDB3B94790` (VideoCapture) |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local Ghidra 12.1.4 headless full decompile dumps (7/7 programs), PE header/section parsing, `llvm-objdump` disassembly. **REA cross-check was not used: four REA audits were already active and the shared bridge is at capacity.** Dumps retained at `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\c3gaps\out\`; project `...\c3gaps\c3gaps.gpr`. |
| Reach tier | Mixed: `R2` for `spacedeskKtmInput` (admin-only control-device SDDL); `R3` for the remaining reachable x64 images. Two images are not loadable on x64 (`BLOCKED`). |
| Setup required | `hardware` (DisplayLink NIC, Android USB), `devnode` (KtmInput, VideoCapture), `composition` (AndroidControl interface on the spacedesk bus), `service`/none where noted. |
| Write quality | `W0` for every reachable path. `W3` is recorded only as an unreachable static reference for the ARM64 ImDisk image (BLOCKED). |
| Severity | **NO-MEMORY-WRITE** for the five x64 images; **BLOCKED** (architecture) for `dlcdcncm660_0FFDDEF9` and `imdisk_arm64`. No MW1-MW4 finding. |
| HW-only | no (no MSR/port/PCI/SMBus/EC/MMIO access was found) |

> Static analysis only. No driver was loaded, installed, started or executed; no service or registry writes were made; no exploit code or PoC was produced. All statements about runtime behaviour are static predictions.

Line references below are VAs in the dump (`ImageBase = 0x140000000`) plus the Ghidra function name in `out\<file>.txt`. Hashes were re-computed with `Get-FileHash -Algorithm SHA256` and match `indexes/drivers_manifest.csv`. All seven have a valid Authenticode signature (DisplayLink (UK) Limited for the two DisplayLink builds; Microsoft Windows Hardware Compatibility Publisher for `imdisk_arm64`; Datronicsoft Inc. for the four spacedesk builds). None of the seven hashes appears in `indexes/dedupe/known_bad_hashes.txt`.

---

## 0. Result at a glance

| File | Arch | Device / interface | Effective DACL | User IOCTL surface | Write | Verdict |
|---|---|---|---|---|---|---|
| `dlcdcncm660_F7F3367C.sys` | AMD64 | **none** - NDIS 6.60 miniport only; no control device, no symbolic link, no interface GUID | n/a | none | W0 | **NO-MEMORY-WRITE** (NO-DEVICE confirmed) |
| `dlcdcncm660_0FFDDEF9.sys` | **ARM64** (0xAA64) | same source, ARM64 build; none | n/a | none | W0 | **BLOCKED** (not loadable on x64) |
| `imdisk_arm64.sys` | **ARM64** (0xAA64) | `\Device\ImDiskCtl` + `\DosDevices\ImDiskCtl`, `\Device\ImDisk<N>`, opens `\Device\AWEAlloc` | no SDDL; default device DACL; DOS link explicitly unprotected | control-device IOCTLs exist (same as amd64 ImDisk) | W0 here; `W3` unreachable static reference | **BLOCKED** (not loadable on x64) |
| `spacedeskKtmInput.sys` | AMD64 | `\Device\spacedeskCtrlvMouse` / `\Device\spacedeskCtrlvKbd` (+ DOS links) | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` - admin/SYSTEM only (verified in code) | 2 custom IOCTLs: mouse/kbd event injection | W0 | **NO-MEMORY-WRITE** |
| `spacedeskVideoCapture.sys` | AMD64 | KS filter factory (`KsCreateFilterFactory`), virtual camera | not determinable statically (INF absent from corpus) | KS property get/set only | W0 | **NO-MEMORY-WRITE** |
| `spacedeskDriverAndroidControl.sys` | AMD64 | device interface `{01749d64-c258-45a9-830b-226b54101f9d}` on ROOT instance; USB instance gets a default queue | INF-declared admin-only (triage `D:P(A;;GA;;;BA)(A;;GA;;;SY)`); INF not in corpus | IOCTLs completed with success without touching buffers | W0 | **NO-MEMORY-WRITE** |
| `spacedeskDriverAndroidUsb.sys` | AMD64 | device interface `{09daef26-7ee9-4bfe-a046-a8a4ea91a2cc}`; USB function driver | not determinable statically (INF absent) | no device-control handler; read/write forwarded to USB target | W0 | **NO-MEMORY-WRITE** |

**Overall verdict: NO-MEMORY-WRITE for all five loadable x64 images. Two images are BLOCKED solely on architecture (ARM64 not loadable on x64). No kernel memory-write primitive (MW1-MW4) was found in any of the seven files.**

---

## 1. Internals and build identity

| File | Size | Machine | Version / build string | Engine |
|---|---:|---|---|---|
| `dlcdcncm660_F7F3367C.sys` | 135,712 | AMD64 | 3.83.0.0; `tl-usbnet.sys v3.83.0 release x64 Oct 7 2024`, KMDF 1.11, NDIS miniport 6.60 | Ghidra full decompile, 524 functions |
| `dlcdcncm660_0FFDDEF9.sys` | 129,568 | ARM64 | 3.83.0.0; same source, `ARM64 Oct 7 2024`, KMDF 1.15 | Ghidra full decompile, 339 functions |
| `imdisk_arm64.sys` | 64,192 | ARM64 | 3.0.3.66; PDB path `...\Release\sys\ARM64\imdisk.pdb` | Ghidra full decompile, 51 functions |
| `spacedeskDriverAndroidControl.sys` | 52,264 | AMD64 | 1.0.481.12 | Ghidra full decompile, 91 functions |
| `spacedeskDriverAndroidUsb.sys` | 44,656 | AMD64 | 1.0.486.13 | Ghidra full decompile, 62 functions |
| `spacedeskKtmInput.sys` | 42,552 | AMD64 | no version resource; banner "spacedesk KTM Input virtual mini driver" | Ghidra full decompile, 52 functions |
| `spacedeskVideoCapture.sys` | 89,688 | AMD64 | 1.0.484.10; KS miniport, "spacedesk virtual Camera" | Ghidra full decompile, 270 functions |

Architecture was read from the PE `IMAGE_FILE_HEADER.Machine`: `0x8664` = AMD64, `0xAA64` = ARM64. Both ARM64 files were confirmed independently by embedded build strings (`ARM64`) and PDB paths.

---

## 2. Entry / device / interface / effective DACL

### 2.1 `dlcdcncm660_F7F3367C.sys` (DisplayLink USB CDC NCM, AMD64)

- **Entry.** `DriverEntry` = `FUN_14000e188` (VA `0x14000e188`). It calls `NdisMRegisterMiniportDriver` at dump line 13344. The miniport registration block sets characteristics `0x98028a` and a full `NDIS_MINIPORT_DRIVER_CHARACTERISTICS` table (`MiniportInitializeEx`, send/receive, OID, reset, shutdown, unload).
- **Device creation.** There is **no** `IoCreateDevice`, `IoCreateDeviceSecure`, `NdisMRegisterDevice`, `NdisRegisterDeviceEx`, `WdfDeviceCreate`, `WdfControlDeviceInitAllocate`, `WdfDeviceCreateDeviceInterface`, `IoCreateSymbolicLink` or `IoCreateUnprotectedSymbolicLink` anywhere in the imports or decompiled code. No `\Device\...`, `\DosDevices\...`, `\??\...`, interface GUID or SDDL string exists in the image. A binary-wide string scan for device/interface/SDDL patterns returns only the driver name and version strings.
- **Effective DACL.** Not applicable - the driver creates no openable object. The NDIS FDO is owned and dispatched by NDIS, not by this miniport; the miniport receives no IRPs.
- **Conclusion.** The pre-existing `NO-DEVICE` triage is **confirmed**: there is no user-openable control device and no IOCTL path.

### 2.2 `dlcdcncm660_0FFDDEF9.sys` (same driver, ARM64)

Identical string set and structure (`ToriLogic ... ARM64 Oct 7 2024`, KMDF 1.15). No device, symbolic link, interface GUID or SDDL. Not loadable on this x64 host because `Machine = 0xAA64`. Recorded `BLOCKED` on architecture; static surface is the same no-device NDIS miniport.

### 2.3 `imdisk_arm64.sys` (ImDisk 3.0.3.66, ARM64)

- **Entry.** `entry` / DriverEntry at `0x14000e000` (Ghidra merged the stub and body; the control-device creation is at dump lines 8972-8983).
- **Devices.** `\Device\ImDiskCtl` created with `IoCreateDevice(..., DeviceType 0x8372, Characteristics 0x20000, Exclusive FALSE, ...)`; `\DosDevices\ImDiskCtl` created with `IoCreateUnprotectedSymbolicLink`. Per-disk `\Device\ImDisk<N>` / `\DosDevices\ImDisk<N>` devices are created on demand (creation call at dump line 7582 inside `FUN_14000b1e0`). The driver also opens (does not create) `\Device\AWEAlloc`, `\Device\NamedPipe\ImDskSvc` and `\Device\MountPointManager`, and uses `ZwMapViewOfSection` for the proxy shared-memory mode.
- **Effective DACL.** No SDDL, no `IoCreateDeviceSecure`, no `ZwSetSecurityObject`; the control-device DACL is the kernel default for a named device, and the DOS link is explicitly unprotected. Same construction as the audited amd64 `imdisk.sys`.
- **Loadability.** ARM64 image, `Machine = 0xAA64`, PDB path `...\ARM64\imdisk.pdb`. **Not loadable on x64 -> BLOCKED.** The amd64 build (`3CFC...`) was previously audited as **MW4/W3** (fixed `0xF6` fill on memory disks above 4 GiB, crash-first, no target control). This ARM64 build is the same code family; the static W3 reference is recorded, but it is not reachable on this host.

### 2.4 `spacedeskKtmInput.sys` (virtual keyboard/mouse mini driver, AMD64)

- **Entry.** KMDF stub `entry` -> `FUN_140002ddc` (WdfVersionBind). `EvtDriverDeviceAdd` = `FUN_140008000`; it matches root-enumerated hardware IDs `Root\VID_DATRONICSOFT_PID_SPACEDESK_VIRTUAL_MOUSE_0001` / `..._KEYBD_0001` (and the `{0511CEC1-0EB4-4ADE-9284-CD36606C3906}\VID_DATRONICSOFT&PID_SPACEDESK_VIRTUAL_MOUSE_0001` bus form), creates the class-mini device, then calls `FUN_1400010ec` -> `FUN_1400011c4`.
- **Control devices.** `FUN_1400011c4` (VA `0x1400011c4`) calls `WdfControlDeviceInitAllocate` with a `UNICODE_STRING` at `0x140005178` (`{Length=0x36, MaxLength=0x38, Buffer=0x140005140}`); the buffer holds **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`**. This was confirmed in the disassembly at `0x140001346` (`lea r8, [0x140005178]`) immediately before the indirect call through the WDF table `+0xc8`. `WdfDeviceInitAssignName` then assigns `\Device\spacedeskCtrlvMouse` / `\Device\spacedeskCtrlvKbd`, `WdfDeviceCreate` creates them, and `IoCreateSymbolicLink` (call at dump line 604 inside `FUN_1400011c4`) adds `\DosDevices\spacedeskCtrlvMouse` / `...Kbd`.
- **Effective DACL.** **Administrators + SYSTEM, GENERIC_ALL only.** No Everyone/Users ACE. The names and the SDDL match each other; both control devices use the same constant SDDL. File-create/cleanup handlers (`FUN_140001690`, `FUN_140001610`) only increment/decrement a handle counter and complete the request; there is no additional access check, but none is needed because the DACL excludes non-admin openers.

### 2.5 `spacedeskVideoCapture.sys` (KS virtual camera, AMD64)

- **Entry.** `FUN_14000145c` calls `KsInitializeDriver(DriverObject, RegistryPath, &KSDEVICE_DESCRIPTOR)`; `EvtDeviceAdd` = `FUN_14000d680`, which calls `KsCreateFilterFactory` once per static filter descriptor (`param_1[0x17]` count). KS.SYS owns the device object, IRP dispatch and the filter/pin handles.
- **Interface.** A KS filter (KSCATEGORY_VIDEO/CAPTURE family) with pin-centric streaming and a `CSensor` property surface (`CSensor::Get/SetZoom`, `Pan`, `Tilt`, `Exposure`, `Focus`, `Brightness`, ...). No `\Device\` name, SDDL or GUID string is present in the image.
- **Effective DACL.** **Not determined statically.** The DACL is applied by the INF `Security` value / KS default; no INF is present in `drivers/` (corpus is `.sys`-only), so this cannot be resolved from the artifact. It does not change the verdict because no memory-write sink exists (section 5).

### 2.6 `spacedeskDriverAndroidControl.sys` (AMD64)

- **Entry.** `DriverEntry` = `FUN_14000a000` (WdfDriverCreate through table `+0x3a0`); `EvtDriverDeviceAdd` = `FUN_140009240`; unload `FUN_1400091d0`.
- **Device selection.** EvtDeviceAdd queries the parent bus type. For `BusType == "USB"` it calls `FUN_140003c74`; for `"ROOT"` it calls `FUN_140009000`.
  - `FUN_140009000` (VA `0x140009000`) calls `WdfDeviceCreate` (table `+0x258`), installs file-object callbacks (`FUN_1400010f0` create, which registers the registry callback, and `FUN_140001000` cleanup, which unregisters it), then `WdfDeviceCreateDeviceInterface` (table `+0x268`) with GUID **`{01749d64-c258-45a9-830b-226b54101f9d}`** (`0x140006160`). This device gets **no I/O queue**.
  - `FUN_140003c74` (VA `0x140003c74`) calls `WdfDeviceCreate` and creates a default queue via `FUN_14000400c` (WDF_IO_QUEUE_CONFIG size `0x60`, `EvtIoDefault = FUN_1400040e0`). No interface GUID is created on this path.
- **Effective DACL.** The interface is a normal devnode interface whose SD is the device-object SD from the INF. The collected3 INF declares `D:P(A;;GA;;;BA)(A;;GA;;;SY)` (admin/SYSTEM only). **The INF is not in the corpus, so the DACL is recorded as triage-declared, not independently verified.** Either way, the device-control handler performs no data transfer (section 5).

### 2.7 `spacedeskDriverAndroidUsb.sys` (AMD64)

- **Entry.** `DriverEntry` = `FUN_140008000` (WdfDriverCreate through table `+0x3a0`); `EvtDriverDeviceAdd` = `FUN_140007000` (WdfDeviceCreate `+0x258`, `WdfDeviceCreateDeviceInterface` `+0x268` with GUID **`{09daef26-7ee9-4bfe-a046-a8a4ea91a2cc}`** at `0x140004140`).
- **Queues.** `FUN_140007a64` creates a default queue (config `0x60`, `EvtIoDefault = FUN_140001f00`) and a second, manual queue with `EvtIoCanceledOnQueue = FUN_140002260` and a ready-notify `FUN_1400022b0`; the read-completion pump is `FUN_140002398`.
- **Effective DACL.** Again INF-dependent and the INF is not in the corpus; not determined statically. The device is a USB function driver, so **setup requires the Android USB hardware**.

---

## 3. Dispatch and IOCTL table

### 3.1 Full IOCTL enumeration

Only `spacedeskKtmInput` has IOCTLs whose code is compared in driver code. Codes were recovered from the comparisons (`param_5 != -0x63bfdbbc` = `0x9C402444`, `param_5 != -0x63bfdbb8` = `0x9C402448`).

| File | Code | Method | Access | Input | Output | Handler | Kernel action |
|---|---|---|---|---|---|---|---|
| KtmInput | `0x9C402444` | METHOD_BUFFERED (0) | FILE_ANY_ACCESS (0) | >= 0x10 | 0 | `FUN_140001890` (`SKMDeviceControlEvtIoDeviceControlMouse`) | reads 16-byte mouse event, converts flags/buttons, calls `FUN_140002114` -> mouclass service callback. No destination from input. |
| KtmInput | `0x9C402448` | METHOD_BUFFERED (0) | FILE_ANY_ACCESS (0) | >= 4 | 0 | `FUN_140001720` (`SKMDeviceControlEvtIoDeviceControlKeybd`) | reads 4-byte key event (scan code + flags), calls `FUN_140002074` -> kbdclass service callback. No destination from input. |
| KtmInput (internal) | `0xB0000` | - | - | - | 0x1C | `FUN_140002344` | `IOCTL_KEYBOARD_QUERY_ATTRIBUTES`: writes a fixed 0x1C-byte `KEYBOARD_ATTRIBUTES` into the output buffer obtained with a minimum length of 0x1C. Bounded. |
| KtmInput (internal) | `0xB0004`, `0xB0008`, `0xB0020`, `0xB0040`, `0xB0080` | - | - | - | - | `FUN_140002344` | Set/query indicators, typematic, indicator translation. No memory write. |
| KtmInput (internal) | `0xB0203` | - | - | 0x10 | - | `FUN_140002344` | `IOCTL_INTERNAL_KEYBOARD_CONNECT`: copies 0x10 bytes of `KEYBOARD_ATTRIBUTES`-style connect data into fixed fields 0x00..0x10 of the device context. Bounded, fixed destination. |
| KtmInput (internal) | `0xB0403` | - | - | - | - | `FUN_140002344` | `IOCTL_INTERNAL_KEYBOARD_DISCONNECT`: returns `STATUS_INVALID_DEVICE_REQUEST` (0xC0000002). |
| KtmInput (internal) | `0xF0000` (mouse) and siblings | - | - | - | 0x1C | `FUN_140002690` -> `FUN_140002754` | `IOCTL_MOUSE_QUERY_ATTRIBUTES` and connect; same bounded behaviour. |
| AndroidControl | any | - | - | - | - | `FUN_1400040e0` on the USB instance | `IRP_MJ_DEVICE_CONTROL` and `IRP_MJ_INTERNAL_DEVICE_CONTROL` are completed with `STATUS_SUCCESS` and **no buffer access**. All other majors are formatted and forwarded to the lower target. The ROOT instance has no queue, so its IOCTLs are completed by KMDF as unsupported. |
| AndroidUsb | any | - | - | - | - | `FUN_140001f00` | No device-control branch: `IRP_MJ_READ` (3) is sent to the target; `IRP_MJ_WRITE` (4) retrieves the input buffer and forwards it to the USB target; every other major returns `STATUS_INVALID_DEVICE_REQUEST` (`0xC000000E`). |
| VideoCapture | n/a | n/a | n/a | n/a | n/a | KS property handlers | No IOCTL codes; KS.SYS translates KSPROPERTY get/set. See section 5.3. |
| DisplayLink (both) | none | - | - | - | - | none | No dispatch table; NDIS miniport callbacks only (OID, send/receive, reset, PnP). |
| ImDisk ARM64 | `0x8372E004`, `0x8372E010`, `0x8372E018`, `0x8372E024`, `0x83722000`, `0x8372200C` | buffered | varies | - | - | same as amd64 ImDisk | Not loadable here; code parallels the audited amd64 build. |

### 3.2 Access checks

| File | Gate | Admin can satisfy? | Effect |
|---|---|---|---|
| KtmInput | Device SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)`; no `SeSinglePrivilegeCheck`, no `FILE_WRITE_ACCESS` check in create | Yes (R2) | Only admin/SYSTEM handles reach the two event IOCTLs; the IOCTLs are FILE_ANY_ACCESS, so even a read-only admin handle can send them. Still input-injection only. |
| AndroidControl | INF SDDL (triage admin-only); no in-code check | Yes (R2), if the INF SDDL is applied | Queues/interface are admin-gated per INF; the queue does not move caller data. |
| AndroidUsb | INF SDDL unknown; no in-code check | Yes (R2) | Interface access is INF-dependent; no device-control handler exists. |
| VideoCapture | INF/KS default, unknown | Yes (R2/R3) | Property sets are config-only; no memory write. |
| DisplayLink | none (no device) | n/a | NDIS stack only. |
| ImDisk ARM64 | default device DACL + unprotected DOS link | Yes (R2) | Not loadable on x64. |

---

## 4. Access-control audit details

- **KtmInput** is the only driver in this set whose effective DACL is verified from code rather than inferred from an INF. The SDDL is passed to `WdfControlDeviceInitAllocate` (`0x1400011c4`, `lea r8` at `0x140001346`, SDDL at `0x140005140`, `UNICODE_STRING` at `0x140005178`). The string has no `WD`/`BU`/`AU` ACE, so an unprivileged opener cannot obtain a handle regardless of the `FILE_ANY_ACCESS` IOCTL codes. `R2` is the correct reach.
- **AndroidControl / AndroidUsb / VideoCapture** are PnP/KS devices whose SD is supplied by their INF (`Security` under the device hardware key or a class default). Those INFs were not collected (the corpus is `.sys`-only), so the effective DACL is an unresolved input, not a verified fact. This is recorded as a limitation; it does not create a memory-write primitive.
- **DisplayLink** itself creates no device object (NDIS owns the FDO), so DACL analysis is vacuous; the `NO-DEVICE` triage is confirmed by the absence of every device/interface creation API and string.
- **ImDisk ARM64** creates its control device with a NULL/unprotected security descriptor (same as the amd64 build), but cannot be loaded on this host.

---

## 5. Memory-write trace

### 5.1 Import-level sinks

| File | Sink | Present? | Site | Caller-controlled input? | Result |
|---|---|---|---|---|---|
| DisplayLink x64 | `MmMapLockedPagesSpecifyCache` | yes | `FUN_140005ec0` (`0x140005ec0`), mapping an MDL built by `MmAllocatePagesForMdlEx` | No - length/PA come from the driver's own buffer class (`FUN_140005e0c`, `FUN_140005ec0`); MDL pages are driver-allocated, mapped with cache type 1 | NO-WRITE |
| DisplayLink x64 | `MmAllocatePagesForMdlEx`, `IoAllocateMdl`, `MmBuildMdlForNonPagedPool` | yes | `FUN_140005e0c`, `FUN_140005ec0` | No - internal buffer allocation for USB transfer/queue | NO-WRITE |
| DisplayLink x64 | `RtlCopyUnicodeString`, `NdisGetDataBuffer`, `NdisAdvanceNetBufferDataStart`, `NdisRetreatNetBufferDataStart` | yes | receive/indicate path | Packet contents, but destinations are NDIS-allocated NBLs; lengths are the NBL lengths | NO-WRITE (no arbitrary target) |
| DisplayLink x64 | `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `KeStackAttachProcess`, `WRMSR`, port I/O | no | - | - | NO-WRITE |
| ImDisk ARM64 | `MmMapLockedPagesSpecifyCache`, `ZwMapViewOfSection` | yes | same roles as amd64 ImDisk (IRP read/write MDL mapping; proxy section mapping) | No - IRP buffer MDLs and a fixed-name section | NO-WRITE (and image is not loadable) |
| KtmInput | `WdfRequestRetrieveInputBuffer` / `OutputBuffer` | yes | `FUN_140001720`, `FUN_140001890`, `FUN_140002344` | Yes, but only read into stack/inline structs, or fixed 0x1C output | NO-WRITE |
| KtmInput | `IoCreateSymbolicLink`, `WdfControlDeviceInitAllocate` | yes | `FUN_1400011c4` | No | device/DACL only |
| VideoCapture | `ExAllocatePoolWithTag` | yes | `FUN_14000eee0` (`0x14000eee0`), `FUN_140009ee0`, `FUN_14000f...` | Length from descriptor fields, but allocation is exactly `0x30 + length` and the copy is exactly `length` at offset `0x30` | NO-WRITE |
| VideoCapture | `KsStreamPointerGetMdl`, `KsPinGetLeadingEdgeStreamPointer` | yes | capture path | MDLs are the user/KS streaming buffers, filled by the capture engine | NO-WRITE (DMA-style fill of caller frames) |
| VideoCapture | `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `KeStackAttachProcess` | no | - | - | NO-WRITE |
| AndroidControl | `ExAllocatePoolWithTag`, `ObQueryNameString`, `CmRegisterCallbackEx` | yes | `FUN_14000161c` (name buffer sized by `ObQueryNameString`), `FUN_1400028f0` registry callback | Registry key names/values are copied into a buffer whose size is checked (`0x3C + current`), and the callback only reads them for a VID match | NO-WRITE |
| AndroidControl | `WdfRequestRetrieveInputBuffer` / `OutputBuffer` | **no** | - | - | NO-WRITE |
| AndroidUsb | `WdfRequestRetrieveInputBuffer` (`+0x858`) / `OutputBuffer` (`+0x860`), `WdfMemoryCopyToBuffer` (`+0x620`) | yes | `FUN_140001f00` (write path), `FUN_140002398` (read completion) | Yes, but the copy destination is the caller's output buffer and the length is clamped to `min(buffer length, remaining)` | NO-WRITE |
| AndroidUsb | `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `KeStackAttachProcess` | no | - | - | NO-WRITE |
| All spacedesk | `ProbeForWrite`, `METHOD_NEITHER`, raw user pointers | no | - | - | NO-WRITE |

### 5.2 DisplayLink buffer class (the only `MmMap...` in the set)

`FUN_140005ec0` (`0x140005ec0`) is a generic "allocate pages + map" helper:

- `MmAllocatePagesForMdlEx(param_4, param_3, 0, param_2, param_5, param_6)` allocates pages for a driver-owned MDL.
- If the MDL is not already mapped (`(MDL->MdlFlags & 5) == 0`), it calls `MmMapLockedPagesSpecifyCache(Mdl, 0, 1, 0, 0, 0x40000010)` to obtain a system VA.
- `FUN_140005e0c` is the pool variant: `ExAllocatePoolWithTag(size)` + `IoAllocateMdl` + `MmBuildMdlForNonPagedPool`.

Both are internal allocators for USB transfer buffers / NBL payloads. Length and cache type are fixed or come from the driver's own descriptors, not from an IOCTL, registry value or network packet header. There is no path where a caller supplies a physical address, a kernel VA, or a cache attribute.

### 5.3 VideoCapture property surface

`spacedeskVideoCapture` has no `Mm*` imports and no WDM IOCTL dispatch; `ks.sys` calls its property handlers. The handlers follow one pattern (e.g. `FUN_14000e350` at `0x14000e350`):

1. Read `InputBufferLength` from the IRP stack location (`*(IRP + 0xb8) + 8`).
2. Reject `0` / `< 0x28` with `STATUS_INVALID_PARAMETER` / `STATUS_BUFFER_TOO_SMALL`.
3. Pass the system buffer (`param_3`) to a `CSensor` method.

The descriptor parser `FUN_14000eee0` (`0x14000eee0`, reachable through `FUN_1400081d0` -> vtable slot `+0xe0`) allocates `0x30 + descriptor_length` and copies exactly `descriptor_length` bytes to offset `0x30`, i.e. an exact fit. The alternative branches copy fixed 0x20/0x30-byte fields into a buffer of at least 0x58 bytes. The 0x28-byte property payloads are fixed-layout structures; setters such as `CSensor::SetZoom` store scalar values in the sensor object.

**Unresolved read-only path:** in the second/third branch of `FUN_14000eee0` the copy source is the internal descriptor plus `0x1c` dwords, and the declared total size (`*puVar1`) is checked only against `0x98`/`0x128`, not against `0x70 + length`. That can over-read the descriptor object; it is an out-of-bounds **read**, not a write (destination is exactly sized), and it is not counted as a memory-write primitive.

### 5.4 KtmInput input path

- Mouse: `WdfRequestRetrieveInputBuffer(Request, 0x10, &buf, &len)` -> read `buf[0]` (buttons), `buf[8]` (flags); build a `MOUSE_INPUT_DATA` on the stack in `FUN_140002114`; call the mouclass service callback under `KfRaiseIrql(2)`.
- Keyboard: `WdfRequestRetrieveInputBuffer(Request, 4, ...)` -> read scan code and flags; call `FUN_140002074` -> kbdclass callback.
- The only kernel-memory writes are the fixed fields of the callback argument structures on the stack and the `KEYBOARD_ATTRIBUTES` output struct. There is no destination or length taken from the caller beyond the validated minimums.

### 5.5 Android queue handlers

- **AndroidControl, `FUN_1400040e0`:** reads `WdfRequestGetParameters` (major function at `+4`). For major `0xE` (DEVICE_CONTROL) and `0xF` (INTERNAL_DEVICE_CONTROL) it completes with `STATUS_SUCCESS` and never calls `WdfRequestRetrieveInputBuffer`/`OutputBuffer`. For all other majors it formats the request against the file object's target and sends it. Consequence: an admin who can open the interface can make IOCTLs "succeed", but no bytes are read or written.
- **AndroidUsb, `FUN_140001f00`:** READ is sent synchronously to the USB target; WRITE retrieves the caller's input buffer and sends it to the USB target; every other major returns `STATUS_INVALID_DEVICE_REQUEST`. No IOCTL surface.
- **AndroidUsb, `FUN_140002398`:** pulls queued read requests, gets the output buffer and its length, clamps the copy to `min(remaining, output length)`, `WdfMemoryCopyToBuffer` into the caller buffer. Bounded.

### 5.6 Summary of the write question

| Question | Answer |
|---|---|
| Caller-controlled destination pointer? | No, in all seven. |
| Caller-controlled length into a kernel buffer? | No: every copy uses a size derived from the same allocation, a validated minimum, or a clamped min(). |
| Pool overflow / unchecked `memcpy`? | None found. The only descriptor-driven copy is exact-fit (VideoCapture `FUN_14000eee0`). |
| `MmMapIoSpace` / user PA / user cache type? | None. DisplayLink's mapping is a driver-owned MDL, cache type fixed at 1. |
| `ZwMapViewOfSection(\Device\PhysicalMemory)`? | None. ImDisk maps a fixed named section, as in the audited amd64 build. |
| MDL mapped writable into user mode? | None. |
| `METHOD_NEITHER` without probe/capture? | None. |
| Fixed-address write redirectable by another IOCTL? | None. |

---

## 6. Most dangerous exposed capability (per file)

| File | Capability | Why it is not a memory write |
|---|---|---|
| DisplayLink x64 | Full NDIS miniport data path for a USB CDC NCM NIC (packet send/receive, OIDs). | Destinations are NDIS NBLs/MDLs; no user-openable object and no caller-supplied address/length. |
| DisplayLink ARM64 | Same, but not loadable. | Architecture. |
| ImDisk ARM64 | Control-device IOCTL set including disk creation/removal and the fixed `0xF6` memory-disk fill on the amd64 analogue. | Not loadable on x64; the fill is fixed-value/fixed-destination and crash-first (amd64 MW4). |
| KtmInput | Admin-only virtual keyboard/mouse **input injection** through `\Device\spacedeskCtrlvMouse/Kbd`. | Writes go to class-driver input structures; no caller-chosen kernel address. Input injection is out of scope. |
| VideoCapture | KS camera property surface (zoom/pan/exposure/...) plus descriptor parsing. | Values stored in driver objects; descriptor copy exact-fit; only an OOB read noted. |
| AndroidControl | Device interface on the spacedesk bus; registry callback watching `Enum\USB`; IOCTLs acknowledged without effect. | No buffer retrieval in the device-control path; registry copies are size-checked. |
| AndroidUsb | USB function driver with an interface and read/write forwarding. | Caller buffers go to the USB target; the one kernel copy is clamped into the caller's buffer. |

---

## 7. Verdict

Per-file:

| File | Reach | Setup | Write | Load | Severity |
|---|---|---|---|---|---|
| `dlcdcncm660_F7F3367C.sys` | R3 | hardware | W0 | signed | **NO-MEMORY-WRITE** (NO-DEVICE) |
| `dlcdcncm660_0FFDDEF9.sys` | n/a | n/a | W0 | ARM64, not loadable | **BLOCKED** (architecture) |
| `imdisk_arm64.sys` | n/a | n/a | W3 static reference (unreachable) | ARM64, not loadable | **BLOCKED** (architecture) |
| `spacedeskKtmInput.sys` | R2 | devnode | W0 | signed | **NO-MEMORY-WRITE** |
| `spacedeskVideoCapture.sys` | R3 | devnode | W0 | signed | **NO-MEMORY-WRITE** |
| `spacedeskDriverAndroidControl.sys` | R3 | composition | W0 | signed | **NO-MEMORY-WRITE** |
| `spacedeskDriverAndroidUsb.sys` | R3 | hardware | W0 | signed | **NO-MEMORY-WRITE** |

**Overall verdict: NO-MEMORY-WRITE.** Across the seven files, five are loadable x64 images with no kernel memory-write primitive; the other two are ARM64 images that cannot be loaded on this host. The only write-like behaviours are (a) NDIS/KS data-path writes into NDIS/KS-owned buffers, (b) an administrator-only input-injection path in `spacedeskKtmInput`, (c) bounded property/registry state writes, and (d) the known fixed-value ImDisk fill in the unreachable ARM64 build. None is an MW1-MW4 kernel memory write. The DisplayLink `NO-DEVICE` triage is confirmed (no control device, no IOCTL). `spacedeskVideoCapture` is a KS devnode, not a no-device driver, but still has no write sink.

---

## 8. Limitations and unresolved paths

1. **REA not used.** Four REA audits were already active; per `STATIC_ANALYSIS_AGENT_PROMPT.md` the audit continued with Ghidra only. No REA evidence IDs exist for this report. A future REA or dynamic pass could re-confirm the WDF call identifications, which were inferred from the KMDF function-table offsets and call signatures (the SDDL argument in KtmInput was additionally confirmed in disassembly).
2. **INF files absent.** `spacedeskDriverAndroidControl`, `spacedeskDriverAndroidUsb` and `spacedeskVideoCapture` get their device DACLs from INFs that are not in the corpus. The AndroidControl INF SDDL is recorded as triage-declared (`D:P(A;;GA;;;BA)(A;;GA;;;SY)`); the other two are unresolved. This affects reach, not the write verdict.
3. **VideoCapture descriptor over-read.** `FUN_14000eee0` can over-read the internal descriptor because the declared total size is checked against a minimum but not against `0x70 + length`. It is a read-only OOB (the destination pool is exact-fit). Unexploited and not a memory-write primitive; recorded for completeness.
4. **ImDisk ARM64 not re-derived.** The static W3/MW4 reference is inherited from the audited amd64 `imdisk.sys` (`3CFC...`), not re-proven here. The ARM64 image cannot run on this host.
5. **DisplayLink packet path not exhaustively modelled.** The NDIS receive/send and OID handlers were reviewed at the import and function level; no user-controlled destination was found. A full packet-parser audit would need a symbolized build or dynamic tracing, but no device/IOCTL surface exists to reach it.
6. **No dynamic validation.** Per the rules, nothing was loaded or executed; all runtime statements are static predictions.
