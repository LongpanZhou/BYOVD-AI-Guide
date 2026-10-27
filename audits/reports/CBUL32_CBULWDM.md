# Audit: CBUL32.sys + CBULWDM.sys (Digilent / ComputerBoards DataAcq 6.56)

| Field | Value |
|---|---|
| File(s) | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\CBUL32_EB216763.sys`<br>`C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\CBULWDM_ADB2AAC3.sys` |
| SHA-256(s) | `EB216763FFCD57BBDA73957B44CC8C68674C3FDDFCCE696C8BD2E595E4832189` (CBUL32)<br>`ADB2AAC34318F113CB18F8F82A4C9F851C1683A43A604605C4531E9879A42A46` (CBULWDM) |
| Analysis date | 2026-10-25 |
| Method | Static-only: REA/Ghidra 12.1.4 headless decompiler + full-image `llvm-objdump` (msys64) cross-check; PE/version/Authenticode inspection. No load, service, registry write, or IOCTL execution. |
| Reach tier | **R2** - local administrator (default device DACL). The physical-memory path additionally needs a SYSTEM-token caller. |
| Setup required | CBUL32: **service**. CBULWDM: **devnode** (WDM PnP function driver). A ComputerBoards/MCC PCI board (vendor `0x1307`) is needed for the BAR-mapping path. |
| Write quality | **W3P** - physical-memory mapping into user mode (driver-chosen PA). Secondary: **W3** - fixed-value kernel pool OOB fill via IOCTL `0x86780048`. |
| Verdict | **MW3** - reach=R2 setup=service/devnode write=W3P load=signed (PE32 i386 only) |
| HW-only | No - physical-memory mapping is a memory primitive (PA-only), not merely MSR/port/MMIO |
| Loadability | Both signed (DigiCert, `CN=Digilent, Inc.`, timestamped, `Get-AuthenticodeSignature = Valid`). Both are **PE32 i386** and cannot load on x64 Windows; on a 32-bit Windows target they load as-is. |

Verification: both on-disk hashes match the file-name prefixes and the values above (`Get-FileHash -Algorithm SHA256`). All VAs below are image-base `0x10000` (RVA = VA - 0x10000; `.text` file offset = VA - 0x10000).

---

## 1. Internals

| | CBUL32 | CBULWDM |
|---|---|---|
| Type | PE32, `coff-i386`, native subsystem, image base `0x10000` | PE32, `coff-i386`, native subsystem, image base `0x10000` |
| Size / entry | 64,416 B; `DriverEntry = 0x1C4B0` (INIT) | 65,184 B; `DriverEntry = 0x1BCC0` (INIT) |
| Sections | `.text 0x10280-0x1C28E`, `.data 0x1C2A0`, `INIT 0x1C3E0`, `.rsrc`, `.reloc` | `.text 0x102A0-0x1BBFF`, `.data 0x1BC00`, `INIT 0x1BC20`, `.rsrc`, `.reloc` |
| Version resource | DataAcq 6.56; CBUL32.SYS 3.38.02; original name `CBUL32.SYS` | DataAcq 6.56; CBULWDM.SYS 1.38.02; original name `CBULWDM.SYS` |
| Banner | `" BlueWater Systems, Inc. 1996-99, version 2.62"` @ `0x104D3`; `"6.56"` @ `0x1C3A4` | `"6.60"` string copied by IOCTL `0x86780024`; `"CBUL32:CCBUL32::CCBUL32 RegisterDeviceInterface failed"` |
| Signer | DigiCert Trusted G4 CS RSA4096 SHA384 2021 CA1 -> `CN=Digilent, Inc.` (valid, timestamped) | same certificate/serial `0B77A0675F1A0F4721944282464AF742` |

**Memory-relevant imports.** Both: `ZwOpenSection`, `ZwMapViewOfSection`, `ZwUnmapViewOfSection`, `ObReferenceObjectByHandle`, `MmMapIoSpace`, `MmUnmapIoSpace`, `MmMapLockedPages`, `MmProbeAndLockPages`, `MmCreateMdl`, `MmGetPhysicalAddress`, `MmUnlockPages`, `IoFreeMdl`, `HalTranslateBusAddress`, `HalGetBusDataByOffset`, `Ke386QueryIoAccessMap`, `Ke386IoSetAccessProcess`, `Ke386SetIoAccessMap`, `READ_REGISTER_*`, `WRITE_REGISTER_*`. CBUL32 additionally imports `MmBuildMdlForNonPagedPool` and `IoAllocateMdl`.
Neither imports `MmCopyVirtualMemory`, `MmCopyMemory`, `MmMapLockedPagesSpecifyCache`, `SeAccessCheck`, `SeSinglePrivilegeCheck`, `ProbeForWrite`, `ProbeForRead`, `IoCreateDeviceSecure`, or `ZwSetSecurityObject`. There is **no user-mode MDL mapping** (`MmMapLockedPages` is always called with `AccessMode = 0`, kernel).

**Recovered strings.** CBUL32: `\Device\PhysicalMemory` @ `0x1C344`, `\Device\Pcmcia` @ `0x1C32A`, `Contiguous Memory` @ `0x1C374`, `DataAcq` @ `0x1C398`, `\Device\`/`\DosDevices\` @ `0x1A030`/`0x1A30E`. CBULWDM: `\Device\PhysicalMemory` (loaded at `0x12235` by the mapper), `DataAcq` @ `0x1655C`/`0x165FE`, `CBULWDM.SYS`, `\Device\Pcmcia`.
There is **no SDDL string** in either image.

---

## 2. Entry, device, interface, effective DACL

### 2.1 CBUL32 (legacy/WDM hybrid, NT4-style driver object)

`DriverEntry 0x1C4B0` -> helper `0x1B136` installs `DriverUnload`, `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_CLEANUP`; `DriverEntry` then overwrites:

| Major function | Offset | Handler |
|---|---|---|
| `IRP_MJ_CREATE` | `+0x38` | `0x131B0` - completes `STATUS_SUCCESS`, no checks |
| `IRP_MJ_CLOSE` | `+0x40` | `0x13180` |
| `IRP_MJ_DEVICE_CONTROL` | `+0x70` | **`0x12F40`** |
| `IRP_MJ_CLEANUP` | `+0x80` | `0x1B28E` |
| `DriverUnload` | `+0x34` | `0x131E0` |

Device creation: `0x134D0` -> `0x1A042(0x3B0, DriverObject, L"CBUL32", 0x8678, ..., 0)` -> `IoCreateDevice(DriverObject, 0x3B0, L"\\Device\\CBUL32", FILE_DEVICE_0x8678, Characteristics = 0, Exclusive = 0, ...)`. `0x1C3E0` then calls `0x1A33C`, which builds `\DosDevices\CBUL32` and calls `IoCreateSymbolicLink`. **No `IoCreateDeviceSecure`, no SDDL, no `ZwSetSecurityObject`.**

User-mode path: `\\.\CBUL32`, admin/SYSTEM only by default device SD.

In `DriverEntry`, `MmAllocateNonCachedMemory(0x2000)` is zeroed and stored at `+0xD8` (the I/O-permission bitmap), and the registry value `Contiguous Memory` (KB) is read, turned into a `HalAllocateCommonBuffer` allocation (`0x13350`, HAL DMA common buffer) and re-written to the registry at `+0x158`.

### 2.2 CBULWDM (WDM function driver)

`DriverEntry 0x1BCC0` -> `0x1B1AA` sets `IRP_MJ_CREATE = 0x1B29B`, `IRP_MJ_CLOSE = 0x1B3F7`, `IRP_MJ_CLEANUP = 0x1B495`, `IRP_MJ_PNP = 0x1B4D5`, `IRP_MJ_POWER = 0x1B6DC`, `IRP_MJ_SYSTEM_CONTROL = 0x1B7B6`, `DriverUnload = 0x1B779`; then `DriverEntry` overwrites close/device-control/unload and installs `DriverExtension->AddDevice = 0x136F0`.

- `AddDevice 0x136F0` creates an **unnamed** FDO (`IoCreateDevice`, type `0x8678`), attaches to the PDO (`IoAttachDeviceToDeviceStack`), and registers a device interface (`IoRegisterDeviceInterface`) with reference string `DataAcq`; `IoSetDeviceInterfaceState` is called on start. No SDDL, no secure device.
- `IRP_MJ_DEVICE_CONTROL = 0x13320`; `IRP_MJ_CREATE = 0x1B29B` performs C++ object/queue setup only - no identity or privilege check.

User-mode path: the `DataAcq` device interface (`\\?\GLOBALROOT\Device\...` via SetupAPI). Opening it reaches the unnamed FDO, whose DACL is the default device SD.

### 2.3 Effective DACL / open gate

Neither driver sets an SD. Both create their device with plain `IoCreateDevice`, so the object receives the I/O manager's **default device security descriptor** for a SYSTEM-created device - in practice `SYSTEM` + `BUILTIN\Administrators` (the corpus triage value `DEFAULT-ADMIN`). This is **not statically provable from the image**; it depends on the loader's token (services.exe / PnP manager, both SYSTEM). Treat the gate as **R2**.

Two caveats, both material:

1. **Zero-access open.** All IOCTLs are `FILE_ANY_ACCESS` (bits 14-15 of every code are 0). A `CreateFile(..., dwDesiredAccess = 0, ...)` requests no access, and the object-manager check with `DesiredAccess = 0` succeeds even against a restrictive DACL on legacy semantics; the I/O manager then imposes no additional access check for `FILE_ANY_ACCESS` IOCTLs. If that holds on the target build, the gate drops to **R1**. Not dynamically verified here; the IOCTL table is the only place this would matter.
2. **`\Device\PhysicalMemory`.** The mapper opens the section with `SECTION_ALL_ACCESS` (`0xF001F`) in the **caller's** context, so on Vista+ a normal administrator token gets `STATUS_ACCESS_DENIED`. The map paths therefore require a **SYSTEM-token caller** (an administrator can obtain one via a service/scheduled task), keeping the reach at R2 rather than R1.

No `SeAccessCheck`, `SeSinglePrivilegeCheck`, token inspection, or per-handle authentication exists in either driver.

---

## 3. Dispatch and IOCTL table

Both dispatchers are structurally identical: `IoControlCode - 0x86780004`, reject `> 0x6C`, index a 0x6D-byte byte table (`CBUL32 0x13110`, `CBULWDM 0x134F0`), then `jmp [4*index + jump table]` (`0x130B4` / `0x13494`). Every accepted code is `=== 0 mod 4` -> **METHOD_BUFFERED**; every code has access bits 0 -> **FILE_ANY_ACCESS**. Handlers receive `(this = DeviceExtension, Irp, CurrentStackLocation)`; `[Irp+0xC] = SystemBuffer`, `[Irp+0x1C] = IoStatus.Information`, `[Irp+0x3C] = UserBuffer`.

### 3.1 CBUL32 - 22 codes

| IOCTL | Handler | In / Out (nominal) | Kernel action | Write? |
|---|---|---|---|---|
| `0x86780004` | `0x136D0` -> `0x10A10` | >=0x20 / 0 | Install interrupt: channel `+4`, IRQ `+0x14`; `HalGetInterruptVector`, `KeInitializeDpc`, `IoConnectInterrupt` | No (over-read only) |
| `0x86780008` | `0x13700` | >=0x18 / 0 | Close channel: disconnect interrupt, `MmUnlockPages`/`IoFreeMdl`, free pool | No |
| `0x8678000C` | `0x135D0` | any / >=0x18C | Copies **OutputBufferLength** bytes from a 0x18C-byte internal object to SystemBuffer (`Information = len`) - pool **over-read** for len > 0x18C | No (read/leak) |
| `0x86780010` | `0x13930` | - | Pool alloc -> `MmCreateMdl` (driver pool) -> `MmProbeAndLockPages(KernelMode)` -> `MmMapLockedPages(KernelMode)` | Kernel DMA map, not caller-visible |
| `0x86780014` | `0x13BF0` -> `0x19BE0` | 2 / 0 | Per-channel command (`*SystemBuffer` = ushort index, `<0x20`) | No |
| `0x86780020` | `0x13C20` -> `0x11EE0` | 2 / 0 | Per-channel setup | Internal |
| `0x86780024` | `0x14630` | - | No-op, returns 0 | No |
| `0x86780028` | `0x14630` | - | No-op, returns 0 | No |
| `0x86780038` | `0x14580` | >=4 / 4 | `IoQueryDeviceDescription` enumeration; returns next index | No |
| `0x8678003C` | `0x14630` | - | No-op | No |
| `0x86780040` | `0x14630` | - | No-op | No |
| **`0x86780048`** | **`0x13C50`** | any / any | **Zero-fills 0x20 bytes of SystemBuffer with no length check**; scans PCI for vendor `0x1307`; maps BAR0-BAR4 into the caller and returns 5 user VAs at `+0x00...+0x10` | **Yes - pool OOB + user physmap** |
| `0x8678004C` | `0x13C20` -> `0x11EE0` | 2 / 0 | Per-channel setup | Internal |
| `0x86780050` | `0x14780` -> `0x11E30` | >=0xC / 0 | `Ke386QueryIoAccessMap` -> set IOPM bits -> `Ke386IoSetAccessProcess`/`Ke386SetIoAccessMap`: grants the calling process port I/O for `[base, base+len]` | HW-ONLY (IOPM) |
| `0x86780054` | `0x147B0` -> `0x127B0` | >=0xC / 0 | Allocate/free a user mapping of the driver's contiguous-DMA buffer (`SystemBuffer[8] != 0` = alloc); returns VA and kernel list pointer | **User physmap** |
| `0x86780058` | `0x14860` | >=4 / 0 | `ext+0x2A4 = SystemBuffer[0]` (chipset flags) | No (4-byte over-read) |
| `0x8678005C` | `0x14630` | - | No-op | No |
| `0x86780060` | `0x14950` | - | Returns `0xC0000001` | No |
| `0x86780064` | `0x14910` -> `0x128B0` | >=4 / 4 | Looks up a mapping entry by the VA at `+0`, writes its **kernel list pointer** to `+0` | Kernel pointer leak |
| `0x86780068` | `0x13640` | any / >=0x84 | Reads channel status (InterlockedExchange + 0x1C bytes) or echoes `OutputBufferLength` bytes from `UserBuffer` into SystemBuffer | No |
| `0x8678006C` | `0x14BB0` -> `0x12A90` | >=4 / 4 | Returns a pointer from `0x12A90` at `+0` | Kernel pointer leak |
| `0x86780070` | `0x13900` | 2 / 0 | Sets channel flag `+0xBC = 1` | Internal |

### 3.2 CBULWDM - 22 codes

| IOCTL | Handler | In / Out (nominal) | Kernel action | Write? |
|---|---|---|---|---|
| `0x86780004` | `0x1393F` -> `0x10BC0` | >=0x20 / 0 | Install interrupt | No |
| `0x86780008` | `0x13964` | >=0x18 / 0 | Close channel: disconnect interrupt, unlock/free MDL, free pool | No |
| `0x8678000C` | `0x13860` | any / >=0x18C | `memcpy(SystemBuffer, internal 0x18C object, OutputBufferLength)` - pool **over-read** for len > 0x18C; if no object, `memcpy` from `UserBuffer` | No (read/leak) |
| `0x86780010` | `0x13B35` | - | Pool -> `MmCreateMdl` -> `MmProbeAndLockPages(KernelMode)` -> `MmMapLockedPages(KernelMode)` | Kernel DMA map |
| `0x86780014` | `0x13F73` | - | No-op | No |
| `0x86780020` | `0x13D8B` -> `0x11590` | 2 / 0 | Per-channel command | Internal |
| `0x86780024` | `0x13DAB` | any / >=9 | Copies version string `"6.60"` (length-checked) | No |
| `0x86780028` | `0x14214` | >=0x600 / - | Requires `*SystemBuffer == 0x12BA0(this)`; loops `READ_REGISTER_UCHAR(ext+0x1B8+i)`, stores 2 bytes per iteration for `i < InputBufferLength` | HW read; 1-byte slack write for odd len |
| `0x86780038` | `0x13E3C` | >=4 / 4 | `IoQueryDeviceDescription` enumeration | No |
| `0x8678003C` | `0x13ECF` | >=0xC / 0 | Builds board descriptor in SystemBuffer; allocates a pool block | No |
| `0x86780040` | `0x13F73` | - | No-op | No |
| **`0x86780048`** | **`0x142CA`** | any / any | Requires board family 5; **zero-fills 0x20 bytes of SystemBuffer with no length check**; maps BAR0-BAR5 into the caller; returns VAs at `+0...+0x14` | **Yes - pool OOB + user physmap** |
| `0x8678004C` | `0x13D8B` | 2 / 0 | Per-channel command | Internal |
| `0x86780050` | `0x13F78` -> `0x114E0` | >=0xC / 0 | IOPM port-I/O grant (same as CBUL32) | HW-ONLY (IOPM) |
| `0x86780054` | `0x13F9C` -> `0x11E60` | >=0xC / 0 | Alloc/free mapping of the contiguous-DMA buffer | **User physmap** |
| `0x86780058` | `0x14017` | >=4 / 0 | `ext+0x2A4 = SystemBuffer[0]` | No (4-byte over-read) |
| `0x8678005C` | `0x14094` | any / any | Board probe: writes `0xFF,0x00,<reg>,0x00` to SystemBuffer with **no length check** (`Information = 4`) | 4-byte fixed OOB if out < 4; NULL write if out = 0 |
| `0x86780060` | `0x14281` -> `0x128C0` | >=0x10 / 0 | Requires `SystemBuffer[3] == 0x12BA0(this)`; writes caller bytes to board MMIO (`ext+0x1B8`, `+0x000`/`+0x400`) via `WRITE_REGISTER_UCHAR` | HW-ONLY (MMIO) |
| `0x86780064` | `0x13F73` | - | No-op | No |
| `0x86780068` | `0x138B4` | any / >=0x84 | Status read (0x84 struct) or `memcpy` from `UserBuffer` | No |
| `0x8678006C` | `0x14AB4` -> `0x12210` | >=4 / 4 | Returns 0 in SystemBuffer[0] | No |
| `0x86780070` | `0x13B12` | 2 / 0 | Sets channel flag `+0xBC = 1` | Internal |

Codes that map to the same handler are intentional duplicates in the dispatch table (for example `0x8678004C` -> `0x13D8B`, the same handler as `0x86780020`).

---

## 4. Access-control audit

- **No driver-level authentication.** `IRP_MJ_CREATE` is a bare completion in both drivers; there is no session state, password, challenge, or handle tagging.
- **No privilege check.** No `SeSinglePrivilegeCheck`/`SeAccessCheck`/`SeTokenIsAdmin` import; nothing prevents a non-admin with an open handle from sending any code.
- **No per-IOCTL access mask.** Every code has `FILE_ANY_ACCESS`; the device DACL is the sole gate.
- **No probe/capture.** All buffers are METHOD_BUFFERED system buffers; the drivers never touch `UserBuffer` except the `0x86780068` status path in each driver, which *reads* it in kernel mode (a crash/DoS hazard, not a write).
- **`\Device\PhysicalMemory`.** Opened with `SECTION_ALL_ACCESS` in the caller's token context - a second, stronger gate than the device DACL for the physmap paths.

Net gate for the two interesting capabilities:

| Capability | Gates |
|---|---|
| Pool OOB fill (`0x86780048`) | device open (R2, possibly R1 via zero-access open) |
| User physmap (`0x86780048` BAR path, `0x86780054` DMA path) | device open **and** SYSTEM-token caller for `ZwOpenSection(\Device\PhysicalMemory)` **and** (BAR path) an MCC PCI board |

---

## 5. Memory-write trace

### 5.1 The shared physical-memory mapper

CBUL32 `0x12CB0` (`ev_1507c678791d9466bf65daafe32e1243e4ebc920fc85c9f05d38ae57132872a4`) and CBULWDM `0x12220` (`ev_fe17b6a106837060196e040e06a872fdd0a3646746b517d6e96f742ebc15cc43`) are the same routine:

1. `RtlInitUnicodeString("\Device\PhysicalMemory")`; `OBJECT_ATTRIBUTES{Length=0x18, Attributes=0x40}`.
2. `ZwOpenSection(&h, 0xF001F /*SECTION_ALL_ACCESS*/, &oa)` - **fails for non-SYSTEM callers on Vista+**.
3. `ObReferenceObjectByHandle(h, 0xF001F, NULL, KernelMode, &section, NULL)`.
4. `HalTranslateBusAddress(...)` on the start and end addresses (twice) to convert bus-relative to system physical, then `RtlLargeIntegerAdd/Subtract` to derive the byte range; length is clamped to the requested size.
5. `*BaseAddress = NULL`; `ZwMapViewOfSection(section, (HANDLE)-1 /*NtCurrentProcess*/, BaseAddress, 0, CommitSize=len, &SectionOffset, &ViewSize, ViewShare=1, AllocationType=0x20000000, Protect=0x204 /*PAGE_READWRITE|PAGE_NOCACHE*/)`.
6. Two fallbacks (`Protect=4`, then `AllocationType=0x400000, Protect=4`); `*BaseAddress += (requested_offset - mapped_offset)`; `ZwClose(h)`.

**This is a user-mode mapping.** `ProcessHandle = (HANDLE)-1` is `NtCurrentProcess`; the routine runs at `PASSIVE_LEVEL` in the requesting thread's context (IRP dispatch), so the view lands in the **caller's** user address space. The resulting VA is written into the caller's SystemBuffer (offsets `+0x00...+0x14`) and returned as the IOCTL output. No kernel VA is returned or used for the mapping. `Protect = 0x204` makes it **writable**.

### 5.2 Path A - PCI BAR mapping (`0x86780048`)

- **CBUL32 `0x13C50`**: for each BAR index 0-4, `0x14640(bus, devfn, &descriptor, index)` reads the BAR from PCI config (`HalGetBusDataByOffset`), stores base/length at `ext+0x198+i*0x20`; if `ext+0x1A8 == 0` (not already mapped), it calls `0x12CB0` and writes the returned user VA into `SystemBuffer[i]`. It then calls `0x1A3BC(...)` (MmMapIoSpace-based kernel mapping for register access).
- **CBULWDM `0x142CA`**: same loop over `ext+0x19C/+0x1A0 ... +0x23C/+0x240`; requires `FUN_000114A0(this) == 5` (board family), maps each memory BAR with `0x12220` and stores the user VAs in the output buffer. For I/O-space BAR ranges it calls `0x114E0(this, {base,len})`, which sets the IOPM bits and `Ke386SetIoAccessMap` (user-mode port I/O for that range); kernel register access uses the common `MmMapIoSpace` helper `0x1A9F3` (`0x1AA1C`).
- **PA provenance:** the BAR values come from PCI configuration space of the enumerated MCC device (vendor `0x1307`), or from the PnP resource list in the WDM build. The caller selects only *which* enumerated MCC device/board is used (`SystemBuffer[0]`, `SystemBuffer[1]` are selectors/counts). **Not caller-controlled PA.**
- **Length:** the BAR size (driver-derived), not caller-controlled.

### 5.3 Path B - contiguous DMA buffer mapping (`0x86780054`)

- `0x147B0`/`0x13F9C` read a 12-byte request. If `SystemBuffer[8] == 0`, they look up a prior mapping (`0x128B0`/`0x11F60`) and unmap/free it. Otherwise `0x127B0`/`0x11E60` allocate a pool descriptor, take a chunk from the driver's `HalAllocateCommonBuffer` pool (`0x125E0`/`0x11C90`; base PA at `ext+0x130/+0x134`, size from the `Contiguous Memory` registry value), call the mapper, and return the VA plus the descriptor pointer.
- **PA provenance:** HAL-assigned DMA common buffer; size is a load-time registry parameter. **Not caller-controlled.** The caller controls only the chunk size and alloc/free.

### 5.4 Is PA / offset / length / value caller-controlled?

| Field | CBUL32 | CBULWDM | Verdict |
|---|---|---|---|
| Physical address | PCI BAR of an MCC `0x1307` device, or HAL common buffer | same | **No** - driver-selected |
| Offset within the PA | byte offset carried through `HalTranslateBusAddress` | same | **No** - derived from the PA |
| Length | BAR size; DMA chunk size partly caller-chosen (`SystemBuffer` size field) | same | **Partly** |
| Value | arbitrary user bytes at the returned **user** VA | same | **Yes, but into device/driver memory, not kernel VA** |

There is **no** IOCTL that accepts a physical address from the caller, and **no** IOCTL that accepts a kernel VA for a write. The only caller-influenced numbers reaching the mapper are the device selector and the DMA chunk size.

### 5.5 Kernel mappings - not caller-visible writes

`0x13930`/`0x13B35` allocate a pool buffer, `MmCreateMdl(NULL, poolPtr, size)`, `MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess)`, and `MmMapLockedPages(Mdl, KernelMode)`. The MDL is built over **driver pool**, not user pages; the mapping is kernel-only and stored in the channel object. No user-writable kernel mapping exists.

`MmMapIoSpace` (via `0x1A3BC` in CBUL32 / `0x1A9F3` in CBULWDM, call sites `0x1A408` / `0x1AA1C`) maps the same BARs into kernel VA for `READ_REGISTER_*`/`WRITE_REGISTER_*` access - a hardware path (`HW-ONLY`), with no caller-supplied address.

### 5.6 True kernel stores found

**(a) Unchecked 0x20-byte SystemBuffer fill - `0x86780048` (both files).**

CBUL32 `0x13C50` at `0x13C60-0x13C85`:
```
mov ebx,[eax+0xC]        ; SystemBuffer
mov ecx,[ebx] / mov edx,[ebx+4]   ; read 8 bytes of input
mov ecx,6 / mov edi,ebx / xor eax,eax / rep stosd   ; 0x18 bytes of zeros
mov word [ebx+0x18],0 / mov word [ebx+0x1A],0 / mov word [ebx+0x1E],0
```
No `InputBufferLength`/`OutputBufferLength` check precedes this - it is the **first** action after loading the extension. CBULWDM `0x142CA` is identical at `0x142E9-0x1430B`, gated only by the board-family check at `0x142E0`.

With METHOD_BUFFERED, `SystemBuffer` is allocated as `max(InputBufferLength, OutputBufferLength)`. A caller passing `OutputBufferLength = 1..0x1F` (input 0) gets a 1-0x1F-byte pool allocation and the driver writes **0x20 bytes**, i.e. up to 0x1F bytes past the block - into the next pool block's header/body. On success the fill is followed by up to five 4-byte **user VA** writes at `+0x00...+0x10`, so an attacker-chosen (kernel-assigned) user address can land in the adjacent block. With both lengths 0, `SystemBuffer` is `NULL` and the first `rep stosd` is a kernel NULL write (bugcheck/DoS).

This is a genuine kernel pool OOB write: **fixed size (0x20), fixed offsets, values = zeros (plus optional user VAs)**, target = adjacent pool. It is reachable with a single IOCTL and needs no hardware on CBUL32 (the zero-fill precedes the PCI scan); on CBULWDM it needs board family 5.

**(b) `0x8678005C` (CBULWDM `0x14094`).** Writes 4 bytes (`0xFF,0x00,<register>,0x00`) to SystemBuffer at `+0..+3` with **no output-length check**; `out < 4` gives a 1-3-byte fixed-value OOB, `out = 0` a NULL write. Narrow/DoS-leaning.

**(c) `0x86780028` (CBULWDM `0x14214`).** `InputBufferLength` bytes are produced two at a time (`+i`, `+i+1 = 0`). For odd `InputBufferLength` the final store at `+InputBufferLength` is one byte past the request. Because the request size is odd, it always falls inside the pool allocator's 8-byte rounding slack; **not** a cross-block overflow.

**No other kernel store takes a caller-controlled destination.** Every remaining write targets the device extension (`+0x2A4`, `+0xBC`, list heads), a driver pool object, or hardware registers.

### 5.7 What is *not* a memory write

- `Ke386SetIoAccessMap`/`Ke386IoSetAccessProcess` (`0x86780050`) - grants the calling process **port I/O**; the bitmap write is bounded (`0x10000 - port`), into the driver's own 8 KB non-cached buffer. `HW-ONLY`.
- `WRITE_REGISTER_*` - board MMIO/BAR and EEPROM strobes. `HW-ONLY`.
- `HalSetBusDataByOffset` is not imported; only `HalGetBusDataByOffset` (config reads) is present, so no PCI config write.
- `IoQueryDeviceDescription`, status/board-info copies, version string - no writes.

---

## 6. Most dangerous exposed capability

1. **Physical-memory mapping into user mode (W3P).** `0x86780048` (BARs) and `0x86780054` (DMA pool) create `PAGE_READWRITE|PAGE_NOCACHE` user views of physical memory via `\Device\PhysicalMemory`, bypassing the user-mode restriction on that section. The caller then reads/writes the pages with ordinary loads/stores. This is a **physical-address** primitive, not a kernel-VA write: the kernel never dereferences a caller pointer.
2. **Fixed-value kernel pool OOB write (W3).** The unchecked 0x20-byte SystemBuffer fill in `0x86780048` is a real kernel write (pool), with a fixed size and mostly-zero content; pool grooming can place a user VA into an adjacent block. CBUL32 is unconditional; CBULWDM requires board family 5.
3. **Information leaks (read-only).** The 0x18C-object over-read (`0x8678000C`) and the kernel list pointers returned by `0x86780064`/`0x8678006C` give KASLR/pool addresses, but no write consumes them.
4. **Port-I/O grant (`0x86780050`)** - a hardware capability (`HW-ONLY`) reachable by any device opener; useful for chipset/DMA attacks but not itself a memory write.

**Answer to the triage question:** the flagged `\Device\PhysicalMemory` + `ZwMapViewOfSection` path is a **user-mode** physical mapping (W3P), not a kernel memory write. The kernel-write finding in these binaries is the separate, unchecked SystemBuffer fill in the same IOCTL.

---

## 7. Verdict

| File | SHA-256 | Reach | Setup | Write | Severity | Note |
|---|---|---|---|---|---|---|
| `CBUL32_EB216763.sys` | `EB216763...2189` | R2 | service | W3P (+W3) | **MW3** | User-writable physmap of MCC BARs / HAL common buffer; unconditional 0x20-byte zero-fill pool OOB via `0x86780048`; 32-bit image |
| `CBULWDM_ADB2AAC3.sys` | `ADB2AAC3...2A46` | R2 | devnode | W3P (+W3) | **MW3** | Same mapper; OOB fill gated on board family 5; extra 4-byte fill in `0x8678005C`; 32-bit image |

**Overall: MW3** - `reach=R2 setup=service|devnode write=W3P load=signed` (PE32 i386).

Rationale under `SEVERITY.md`: W3P is rated MW3; the fixed-value pool OOB is W3 and would be MW4 on its own. Neither driver contains a W1/W2 kernel-VA write (no caller destination pointer, no `memcpy` to a caller address, no MDL into user mode, no write-what-where). `CBULWDM` is the example named in `SEVERITY.md` for the W3P/MW3 class, and this audit confirms that classification with the added constraint that the PA is **not** caller-chosen (the mapping is of MCC BARs and the driver's own DMA buffer).

**Loadability caveat:** both images are i386. They are signed and timestamped, but a 32-bit kernel driver cannot load on x64 Windows; on an x64 host these are reference-only (static MW3) and would need a 32-bit Windows target to be exercised. No BLOCKED status is assigned because the images are signed and obtainable; the limitation is architectural.

**Recommended treatment:** do not deploy on 32-bit targets where the DataAcq stack is unnecessary; treat the signed pair as an admin-to-physical-memory tool (BYOVD-adjacent) and alert on `0x86780048`/`0x86780054` with short buffers; the `0x86780048` handler should validate `max(InputBufferLength, OutputBufferLength) >= 0x20` before touching SystemBuffer.

---

## 8. Limitations

- Static only. No driver was loaded, no service created, no registry value written, no IOCTL sent.
- The effective device DACL is the I/O manager default for a SYSTEM-created, non-secure device object; it is **not** encoded in either image and was not dynamically inspected. The R2 rating follows the corpus triage (`DEFAULT-ADMIN`) and the SYSTEM-only `\Device\PhysicalMemory` gate; a live `WinObj`/`GetSecurityInfo` check is required to settle it, particularly for the zero-access-open caveat in section 2.3.
- Ghidra's function boundaries omit the small dispatch entry points: `0x12F40` lies immediately after `FUN_00012CB0` (which ends with `ret 0x1C` at `0x12F3D`), `0x13320` after `FUN_000131D0`, and `0x136F0` inside `FUN_000136A0`. Handlers were reconstructed from the byte/jump tables at `0x13110`/`0x130B4` and `0x134F0`/`0x13494` plus the objdump listing; addresses cited are exact VAs.
- The CBUL32 `0x13C50` and CBULWDM `0x142CA` decompilations lose the explicit argument lists of `0x12CB0`/`0x12220` (7 stack arguments); the call sites at `0x1284E-0x1285A` and the mapper prologue were read from disassembly to establish the argument order (PA low, PA high, length, bus, interface, `PVOID *outVa`, flag).
- `FUN_00012BA0` (CBULWDM board "magic") was not fully resolved; it issues an IOCTL to the parent device and returns a value the caller must echo in `0x86780028`/`0x86780060`. Its exact value is obtainable via `0x8678003C`, so it is an integrity check, not a security gate.
- The BAR-mapping path's PA provenance is inferred from the PCI scan/`HalGetBusDataByOffset` and PnP resource-list population; the exact `CM_RESOURCE_LIST` parsing in `StartDevice` was not fully decompiled.
- Pool-allocator rounding (8 bytes on x86) was assumed when judging the 1-byte `0x86780028` store; the 0x20-byte fill in `0x86780048` exceeds any rounding for short buffers and remains a cross-block overflow.
- REA was free at the start of the audit. Midway through, the shared bridge was reassigned to an unrelated target (`BbUBus51_4D52F9D9.sys`); calls made after that point were discarded, and one aggregated "MmMapIoSpace callers" result (`0x14001BE68`) was rejected as foreign. Every CBUL32/CBULWDM REA result used above was returned while the subject SHA-256 matched the file under audit and was cross-checked against the objdump listing.
- REA evidence IDs are retained only where the evidence subject matched the audited SHA-256: `ev_1507c678...72a4` (CBUL32 mapper `0x12CB0`), `ev_f98b3538...3247` (CBUL32 strings), `ev_fe17b6a1...cc43` (CBULWDM mapper `0x12220`), `ev_49cad2cf...72ab` (CBULWDM `DriverEntry`).
