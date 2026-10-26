# Audit: collected1 tail — DesktopVideoUpdate ×2, EL_Display_vhidbus ×2, usblddaqlib ×2

| Field | Value |
|---|---|
| File(s) | `drivers\DesktopVideoUpdate_81F65827.sys`; `drivers\DesktopVideoUpdate_legacy_8A6D0B83.sys`; `drivers\EL_Display_vhidbus_3242D1DC.sys`; `drivers\EL_Display_vhidbus_ECE1CE28.sys`; `drivers\usblddaqlib_9E26A72E.sys`; `drivers\usblddaqlib_CDEC967D.sys` |
| SHA-256(s) | see hash table below (all six verified with `Get-FileHash -Algorithm SHA256` against the assigned files) |
| Analysis date | 2026-10-25 |
| Method | Static-only. PE headers/imports/sections with `llvm-objdump` 20.1.5; full decompile of every function with local Ghidra 12.1.4 headless (`DumpDecomp.java`; 41 / 41 / 115 / 115 / 73 / 73 functions); targeted disassembly with `llvm-objdump -d`; Authenticode and version resources with `Get-AuthenticodeSignature` / `VersionInfo`. Nothing loaded or executed; no service, registry or devnode action. **REA was not used: four REA audits were already active (capacity limit), per `audits\STATUS.md`.** |
| Reach tier | **R3 hardware** (DesktopVideoUpdate, usblddaqlib); **R2 child PDO + R3 composition** (`EL_Display_vhidbus` x64); **n/a architecture** (`EL_Display_vhidbus` i386) |
| Setup required | `hardware` (DesktopVideoUpdate, usblddaqlib); `composition` (EL_Display_vhidbus) |
| Write quality | **W0** on all six images (no caller-controlled kernel memory write). Loadability differs: four are normally loadable; the Blackmagic legacy image is test-signed and the i386 image is architecture-blocked |
| Verdict | **NO-MEMORY-WRITE ×5; BLOCKED (i386) ×1 — no MW1–MW4** |

## Hash and file table

| # | File | SHA-256 | Arch | Signer / load | Size | Version |
|---|---|---|---|---|---|---|
| 1 | `DesktopVideoUpdate_81F65827.sys` | `81F658278AF06AE31EE6EB406F426A243D3F3A56BAABF14FFBA44644CAB5F6A4` | PE32+ x64 | Valid; CN=Microsoft Windows Hardware Compatibility Publisher (WHQL chain) | 28,592 | 4.0.2.0 |
| 2 | `DesktopVideoUpdate_legacy_8A6D0B83.sys` | `8A6D0B832DF371D96A153AAB31EAEED4090B89DC3B8E99FA723F381E834CD03C` | PE32+ x64 | `UnknownError`; CN="WDKTestCert build,131958900460134002" — **test-signed, not normally loadable** | 18,104 | 4.0.2.0 |
| 3 | `EL_Display_vhidbus_3242D1DC.sys` | `3242D1DC709DC77FF6495B566F84DEBEC503CD6DAC317060A259FDAF116BAFAA` | PE32+ x64 | Valid; Microsoft Windows Hardware Compatibility Publisher | 46,088 | 2,9,2,0 |
| 4 | `EL_Display_vhidbus_ECE1CE28.sys` | `ECE1CE28A756E2B307AD54148BB070D930FD2C8007F028B6E58318C61061015A` | PE32 i386 | Valid; Microsoft Windows Hardware Compatibility Publisher | 37,896 | 2,9,2,0 |
| 5 | `usblddaqlib_9E26A72E.sys` | `9E26A72E9C00DFE57FC5D47D467F73E13F08BD8A02D46F4BAC51C89EFFCFA4AD` | PE32+ x64 | Valid; CN=Measurement Computing Corporation | 209,072 | 5.0.0 Build 11 |
| 6 | `usblddaqlib_CDEC967D.sys` | `CDEC967DFDFC8DFC1BA96AC81449BDC84B2055F68B5436A01857BC676D07C1E6` | PE32+ x64 | Valid; CN="Digilent, Inc." | 198,784 | 5.0.0 Build 11 |

All six are x64 except `EL_Display_vhidbus_ECE1CE28.sys` (i386). All six are Authenticode-signed; the only signature failure is the Blackmagic "legacy" image, which carries a WDK test certificate.

## 1 Per-file results

| File | Device / interface | Effective DACL / open gate | User IOCTL surface | Memory-write finding | Verdict |
|---|---|---|---|---|---|
| `DesktopVideoUpdate_81F65827.sys` | Unnamed FDO, type 0x22, ext 0x80; PnP interface `{B8719EFC-9A7F-400F-B2AF-285913FBCECC}` | No SDDL; `IoCreateDevice` default; no symlink; PnP interface default. CREATE checks a started byte only | 27 codes `0x222000`–`0x2220F0`, all METHOD_BUFFERED, FILE_ANY_ACCESS | No caller destination/length; SystemBuffer writes length-checked; URB buffers bounded by in/out length and endpoint max; descriptor copy requires `len+4 <= out` | **NO-MEMORY-WRITE (W0)** |
| `DesktopVideoUpdate_legacy_8A6D0B83.sys` | Same code, same interface GUID | Same as #1 | Same 27 codes | Same; code dump is line-identical to #1 apart from the program name | **NO-MEMORY-WRITE (W0; test-signed load gate)** |
| `EL_Display_vhidbus_3242D1DC.sys` | Parent unnamed FDO, type 0x2A, chars 0x100 (SECURE_OPEN), exclusive; interface `{FE54197A-D9F9-4695-8A69-8B264A2F54F8}`. Child PDOs via `WdmlibIoCreateDeviceSecure`, interface `{A3CE5953-5303-4DF4-A8AE-FAC86ACD06C8}` | Parent: no SDDL in image, `IoCreateDevice` default + PnP interface default. Child: `D:P(A;;GA;;;SY)(A;;GA;;;BA)` → **SYSTEM + Administrators only (R2)** | 6 codes `0x2A0000`, `04`, `08`, `0C`, `10`, `14`, all METHOD_BUFFERED, FILE_ANY_ACCESS | No caller-controlled kernel target/length. Pool copies into allocations of the same length; fixed 8/14-byte report writes into a kernel-submitted URB buffer; no mapping API | **NO-MEMORY-WRITE (W0)** |
| `EL_Display_vhidbus_ECE1CE28.sys` | Same source, 115 functions, same SDDL/IOCTLs; i386 | Same intended SDDL (admin-only child) | Same 6 codes | Same logic; cannot load on x64 | **BLOCKED (i386 architecture)** |
| `usblddaqlib_9E26A72E.sys` | Unnamed FDO, type 0x22, chars 0x80, ext 0x250; interface `{C8711B66-9900-4F42-83C2-7EFEFEE0F221}` | No SDDL; `IoCreateDevice` default; no symlink. CREATE compares `FileObject->FileName` against a name allow-list; empty name accepted, `FsContext=0` | 3 codes `0x220000`, `0x220004`, `0x220008`, all METHOD_BUFFERED, FILE_ANY_ACCESS | No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmGetPhysicalAddress`, `ZwMapViewOfSection`, `IoAllocateMdl` or `MmProbeAndLockPages` in the image; the only copy is device-buffer → SystemBuffer, bounded by OutputBufferLength | **NO-MEMORY-WRITE (W0)** |
| `usblddaqlib_CDEC967D.sys` | Same code, same interface GUID | Same as #5 | Same 3 codes | Same; dump line-identical to #5 apart from program name | **NO-MEMORY-WRITE (W0)** |

## 2 DesktopVideoUpdate pair (Blackmagic Design USB driver)

### 2.1 Internals

- PE32+ x64, image base `0x140000000`, TimeDateStamp 2025-02-24, 41 functions. Original filename `BMDUsbDriver.sys`.
- Imports: `ntoskrnl.exe` (device/PnP/IRP/pool), `USBD.SYS` (`USBD_GetUSBDIVersion`, `USBD_CreateConfigurationRequestEx`, `USBD_ParseConfigurationDescriptorEx`). No WDF. **No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `MmGetSystemRoutineAddress`, `IoAllocateMdl`, `MmProbeAndLockPages`, or `ProbeForWrite` import.**
- Entry `0x140007000` calls `__security_init_cookie` then `FUN_1400013a8` (DriverEntry).

### 2.2 Entry / device / interface / effective DACL

- DriverEntry `FUN_1400013a8`:
  - `DriverObject->AddDevice` (`+0x30`/`+8`) = `FUN_140001950`.
  - Major functions: CREATE `0x70`=`FUN_140001530`, CLOSE `0x80`=`FUN_1400014b0`, DEVICE_CONTROL `0xE0`=`FUN_140001a20`, POWER `0x120`=`FUN_140001770`, PNP `0x148`=`FUN_140001620`. READ/WRITE/INTERNAL_DEVICE_CONTROL are **not set**.
- AddDevice `FUN_140001950` → `FUN_1400015bc` calls `IoCreateDevice(DriverObject, 0x80, NULL, 0x22 /*FILE_DEVICE_UNKNOWN*/, 0, FALSE, &DeviceObject)`, then attaches to the PDO and registers interface GUID `{B8719EFC-9A7F-400F-B2AF-285913FBCECC}` (`DAT_140004130`).
- **Effective DACL:** device name is NULL and no security descriptor is passed; `IoCreateDevice` (not `IoCreateDeviceSecure`) is used, characteristics = 0, and there is no `IoCreateSymbolicLink`, `ZwSetSecurityObject` or SDDL literal in the image. The device therefore has the `IoCreateDevice`/object-manager default DACL. The only user-visible name is the PnP interface symbolic link, whose ACL is set by PnP (and possibly the INF, not in the corpus). The driver itself adds no gate. Access is hardware-gated: the FDO exists only for an enumerated Blackmagic USB device (**R3**).

### 2.3 Dispatch and IOCTL table

Dispatcher `FUN_140001a20`. Entry gate: `FUN_14000246c` fails with `STATUS_DEVICE_NOT_READY` (0xC0000056) unless the device-ready byte (`ext+0x38`) is set. `lVar3 = *(IRP+0xB8)` = current stack; `FileObject->FsContext` must be non-NULL (`0xC0000008` otherwise). `SystemBuffer = IRP+0x18`; `InputBufferLength = stack+0x10`, `OutputBufferLength = stack+0x08`, `IoControlCode = stack+0x18`.

All codes are METHOD_BUFFERED (low 2 bits 0) and FILE_ANY_ACCESS (bits 14–15 = 0).

| IOCTL | Input min | Output min | Kernel action |
|---|---|---|---|
| `0x222000` | 0 | 8 | `SystemBuffer[0]=5`, `[1]=0`; Information=8 |
| `0x22205C` | 0 | ==4 | Returns `ext+0x54` (last lower-stack status) |
| `0x222080` | `0x14` and `ushort(in+8)+0x14` | same as input | `FUN_140001068`: control-transfer URB; setup from in[0..7], buffer `SystemBuffer+0x14`, length `ushort(in+8)` |
| `0x22208C` | 0 | 4 | Returns byte `ext+0x5C` |
| `0x222090` | 4 | 4 | `FUN_140002920` fetches descriptor by index; writes `len+4`; copies descriptor only if `len+4 <= out` |
| `0x222094` | 0 | 4 | Returns byte `[ext+0x68]+4` |
| `0x222098` | 0 | 4 | Returns ushort `[ext+0x68]+10` |
| `0x22209C` | 0 | 4 | Returns byte `[ext+0x68]+6` |
| `0x2220A0` | 0 | 4 | Returns ushort `[ext+0x68]+0xC` |
| `0x2220A8` | 0 | 4 | Returns byte `[ext+0x68]+5` |
| `0x2220AC` | 0 | 4 | Returns ushort `[ext+0x68]+8` |
| `0x2220B4` | 0 | 4 | Returns byte `[ext+0x68]+0x11` |
| `0x2220B8` | 4 | 0 | `FUN_140001000(index=in[0])`: fetch descriptor, rebuild config tables, set `ext+0x5C` |
| `0x2220BC` | 8 | 4 | `FUN_140001188`: match 8-byte filter against config table; writes count and matching indices only if `out >= (count+1)*4` |
| `0x2220C0` | 4 | 4 | Index check; returns byte `entry+5` |
| `0x2220C4` | 4 | 4 | Returns byte `entry+2` |
| `0x2220C8` | 4 | 4 | Returns byte `entry+7` |
| `0x2220CC` | 4 | 4 | Returns byte `entry+6` |
| `0x2220D0` | 4 | 4 | Returns byte `entry+4` |
| `0x2220D4` | 8 | 6 | Index/entry checks; writes 6 endpoint bytes |
| `0x2220D8` | `0x10`, `in[1]+0x10` | 0 | `FUN_140002a6c` URB; buffer `SystemBuffer+0x10`, length `in[1]`, max-transfer check |
| `0x2220DC` | `0x10` | `in[1]` | URB; buffer `SystemBuffer`, length `in[1]` |
| `0x2220E0` | 0 | 0 | `FUN_140002c50`: IOCTL_INTERNAL_USB_RESET_PORT (0x220007) to lower stack |
| `0x2220E4` | `0x10`, `in[1]+0x10` | 0 | Queue push (max 16); `FUN_140002b6c` URB with buffer `SystemBuffer+0x10` |
| `0x2220E8` | `0x10` | `in[1]` | Queue push; `FUN_140002b6c` URB with buffer `SystemBuffer` |
| `0x2220EC` | 8 | ==0 | `FUN_140002278(config=in[0], iface=in[1]-1)`: builds select-interface URB |
| `0x2220F0` | 0 | non-zero | `SystemBuffer[0] = [ext+0x68]+0x10`; Information=1 |
| other | — | — | `STATUS_INVALID_DEVICE_REQUEST` (0xC0000010) |

### 2.4 Access control

No `SeAccessCheck`, `SeSinglePrivilegeCheck`, ACL query, or caller-identity test. IRP_MJ_CREATE `FUN_140001530` only checks the started byte (`ext+0x11`), allocates a 0x90-byte file context, and increments an open count. Gates are: started byte, device-ready byte, table index, and the length checks above. Any principal that can open the device object/interface can issue every IOCTL, but the object exists only with the Blackmagic USB device attached.

### 2.5 Memory-write trace

Every store in the 41-function dump was reviewed.

1. **SystemBuffer fixed-offset writes** in `0x222000` (`UINT64` at `SystemBuffer`, 2 dwords), `0x2220F0` (1 byte), `0x22208C`/`094`/`098`/`09C`/`0A0`/`0A8`/`0AC`/`0B4` (4 bytes), and `0x2220C0`–`0x2220D0` (4 bytes). Each branch is entered only after `OutputBufferLength > 3` (or `> 7` for `0x222000`), so the write is inside the METHOD_BUFFERED allocation.
2. **`0x2220D4`** writes 6 bytes after `in >= 8` and `out >= 6`.
3. **`0x2220BC`** (`FUN_140001188`, `0x140001188`): `*out = count`; then `out[k] = index` for `k <= count`. Guard: if `OutputBufferLength < (count+1)*4`, only `*out = 4` (and `out >= 4` was checked). No overflow.
4. **`0x222090`** (`FUN_140002920` at `0x140002920`): the descriptor length is a device-supplied ushort. The driver writes `len+4` into `out[0]` and calls `FUN_140003080` (`memcpy`) with `len` only when `len+4 <= OutputBufferLength`. Destination is `SystemBuffer+4` inside the allocation.
5. **URB transfer buffers** (`0x222080`, `0x2220D8`, `0x2220DC`, `0x2220E4`, `0x2220E8`): the buffer is a `SystemBuffer` offset and the length is caller-supplied, but the dispatcher requires `len + 0x10 <= InputBufferLength` (IN) or `len <= OutputBufferLength` (OUT); `FUN_140002a6c`/`FUN_140002b6c` additionally clamp to the endpoint max transfer. Direction comes from the device endpoint table, not the caller. The buffer stays inside the SystemBuffer allocation.
6. **Configuration-table rebuild** (`FUN_140002ce4`, reached from `0x2220B8`): pool allocations are sized from device-supplied descriptor lengths; the `memmove` at `0x140002ce4` uses the same lengths. The source/length is the device, not the caller.
7. **Device-extension and IRP writes** (`ext+0x5C`, `ext+0x68`, `ext+0x70`, `ext+0x78`, queue at `ext+0x80..0x88`, `IoStatus` at IRP+0x30/+0x38): fixed kernel structures owned by the driver.
8. Lower-stack URB/IRP construction (`FUN_1400026d4`, `FUN_14000283c`): driver-owned structures only.

No write uses a caller-supplied destination pointer, offset or value: every caller length is first bounded by the input/output buffer length or the endpoint maximum. No mapping API exists in the image.

### 2.6 Verdict

**NO-MEMORY-WRITE — reach=R3 setup=hardware write=W0 load=signed (WHQL).** The legacy image is the same code (dump-identical apart from the program name) but is test-signed; it has no primitive either and is not normally loadable.

## 3 EL_Display_vhidbus pair (DEVGURU "DGVHID Bus")

### 3.1 Internals

- `3242D1DC` = PE32+ x64, image base `0x140000000`, TimeDateStamp 2021-06-28, 115 functions, `.text` 0x1FC1, `PAGE` 0x3D6A, `INIT` 0x9F4.
- `ECE1CE28` = PE32 i386, image base `0x400000`, same timestamp day, 115 functions; same source and same IOCTL/DACL constants, different calling convention and pointer size.
- Imports (both): `ntoskrnl.exe`, `HAL.dll` (`HalGetBusDataByOffset`, `HalGetAdapter`, `HalSetBusDataByOffset`), `WMILIB.SYS`. The x64 image also statically links a copy of Wdmlib (`WdmlibIoCreateDeviceSecure` at `0x140007e5c`) and resolves `IoCreateDeviceSecure` via `MmGetSystemRoutineAddress`.
- **No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `IoAllocateMdl` or `MmProbeAndLockPages`.** The only memory-mapping-adjacent API is `MmGetSystemRoutineAddress`, used for `IoCreateDeviceSecure` and `RtlGetProductInfo`.

### 3.2 Entry / device / interface / effective DACL

- DriverEntry `FUN_14000a000` (entry `0x14000a150`):
  - CREATE `0x70` = `FUN_140006950`; CLOSE `0x80` = `FUN_140006950`; DEVICE_CONTROL `0xE0` = `FUN_140006800`; INTERNAL_DEVICE_CONTROL `0xE8` = `FUN_140001530`; POWER `0x120` = `FUN_140001b80`; SYSTEM_CONTROL `0x128` = `FUN_140007c80`; PNP `0x148` = `FUN_1400078d0`; unload `0x68` = `FUN_1400069f0`; AddDevice = `FUN_140006a10`.
- Parent AddDevice `FUN_140006a10`: `IoCreateDevice(DriverObject, 0x110, NULL, 0x2A, 0x100 /*FILE_DEVICE_SECURE_OPEN*/, TRUE /*exclusive*/, &DeviceObject)`; sets `DO_DEVICE_INITIALIZING` handling, attaches to the PDO, and registers interface `{FE54197A-D9F9-4695-8A69-8B264A2F54F8}` (`DAT_140003330`).
  - **No SDDL, no `IoCreateDeviceSecure`, no `IoCreateSymbolicLink`, no `ZwSetSecurityObject` for the parent.** Effective parent DACL is the `IoCreateDevice` default plus the PnP interface default; the INF (not in corpus) can override.
- Child PDO creation (`IOCTL 0x2A0000`, `FUN_140007708`):
  - `WdmlibIoCreateDeviceSecure(DriverObject, 0x98, NULL, 0x2A, 0x180 /*SECURE_OPEN|AUTOGENERATED*/, FALSE, &SDDL, &GUID, &DeviceObject)`.
  - SDDL `UNICODE_STRING` at `0x140003428` points to `0x1400033f0`: **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`** (protected; GENERIC_ALL only to SYSTEM and Built-in Administrators).
  - Child interface GUID at `0x140003350`: `{A3CE5953-5303-4DF4-A8AE-FAC86ACD06C8}`.
  - **Effective child DACL: SYSTEM + Administrators only → R2.** No other principal can open a child PDO.
- PNP also creates children itself (six variants in `FUN_140006cac` at `0x140006cac`, calling `FUN_140007708` with a local 0x8DC-byte template), so the 0x2A0000 IOCTL is the user-reachable equivalent of the internal creation path.

### 3.3 Dispatch and IOCTL table

User dispatcher `FUN_140006800` (IRP_MJ_DEVICE_CONTROL). `SystemBuffer = IRP+0x18`; `IoControlCode = stack+0x18`; it checks `DeviceExtension->Started` and state, then switches on the code. All six are METHOD_BUFFERED (low 2 bits 0), FILE_ANY_ACCESS (bits 14–15 = 0). **InputBufferLength is never checked.**

| IOCTL | Method / access | Input (implicit) | Output | Kernel action |
|---|---|---|---|---|
| `0x2A0000` | BUFFERED / ANY | 0x8DC-byte structure (not checked) | 0 | `FUN_140007708`: create child PDO; three `ExAllocatePoolWithTag(len_i)` + `memmove(pool, SystemBuffer+off_i, len_i)`; lengths at in+0x408, +0x80C, +0x8D8; data at in+8, +0x40C, +0x810 |
| `0x2A0004` | BUFFERED / ANY | 4 (id) | 0 | `FUN_140007a68`: remove child by id; `FUN_140001000`, list unlink, `IoInvalidateDeviceRelations` |
| `0x2A0008` | BUFFERED / ANY | 4 (id) | 0 | `FUN_140006c08`: find child by id, `IoRequestDeviceEject` |
| `0x2A000C` | BUFFERED / ANY | 20 (id + 8 data + 4 + 4-read/2-used) | 0 | `FUN_140001348`: complete a pending bulk/interrupt read: 8-byte store + 4-byte store + 2-byte store into the URB `TransferBuffer`; sets URB status 0 and IRP status 0 |
| `0x2A0010` | BUFFERED / ANY | 20 | 0 | Same as `0x2A000C` |
| `0x2A0014` | BUFFERED / ANY | 12 (id + 8 data) | 0 | `FUN_140001258`: complete a pending read with one 8-byte store into the URB `TransferBuffer` |
| other | — | — | — | `STATUS_INVALID_DEVICE_REQUEST` (0xC0000010) |

Internal (kernel-only) path: IRP_MJ_INTERNAL_DEVICE_CONTROL `FUN_140001530` accepts only `0x220003` (`IOCTL_INTERNAL_USB_SUBMIT_URB`) and dispatches by URB function in `FUN_14000157c` → `FUN_1400016e0` (select configuration), `FUN_14000171c` (descriptors/class requests), or pends bulk/interrupt reads (`FUN_14000157c`, up to 2 pending). `0x220003` is **not** reachable from `DeviceIoControl` (it would arrive as IRP_MJ_DEVICE_CONTROL and be rejected by `FUN_140006800`).

### 3.4 Access control

- No `SeAccessCheck`, `SeSinglePrivilegeCheck`, `ProbeForWrite` or caller-identity check in the dispatcher.
- Parent: default device/interface DACL; `FILE_DEVICE_SECURE_OPEN` makes the object DACL apply; `Exclusive=TRUE` limits to one open handle. No image-level restriction.
- Child PDOs: protected SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` — **admin-only (R2)**. The child interface GUID is registered, but the SD makes it an R2 surface.
- The six IOCTLs are FILE_ANY_ACCESS, so any handle that can open the object can send them; the governing gate is the DACL above, not an IOCTL access mask.
- The PCI-config interface (`IRP_MN_QUERY_INTERFACE`, `FUN_140006770`) hands out four callbacks including `FUN_140001150` (`HalSetBusDataByOffset`). This is a **kernel-to-kernel** interface, not a user IOCTL, and is **HW-ONLY** (PCI config), not a memory write.

### 3.5 Memory-write trace

1. **`0x2A0000` pool copies** (`FUN_140007708`):
   - Three `ExAllocatePoolWithTag(0, len_i, 0x73754256 /*'VBus'*/)` followed by `memmove(pool_i, SystemBuffer+off_i, len_i)` (`FUN_140002a00` is a memmove). In every case the destination allocation size equals the copy length, so the write is in-bounds. `len_i` is a 32-bit field; a negative/huge value makes the allocation fail before the copy (checked for NULL). **No pool overflow.**
   - The handler does not validate `InputBufferLength`; with a short input it reads `len_i` and the source bytes out of bounds of the SystemBuffer pool allocation. That is a kernel **OOB read** (and the child IDs/report descriptors can expose adjacent pool bytes to the admin-only child interface). It is an info-leak path, not a write, and is out of scope here.
   - Bookkeeping bug: the third buffer is allocated with `in[0x236]` (offset 0x8D8) but its stored length is `in[0x203]` (offset 0x80C) at `ext+0x50`. `ext+0x50` is later used only as an allocation size and `_snwprintf` count in `FUN_1400066dc` (`%ws%02d` from `ext+0x48`), so a mismatch yields an OOB **read**, not an OOB write.
2. **`0x2A000C` / `0x2A0010`** (`FUN_140001348`): finds a pending IRP by id, then writes 8 + 4 + 2 bytes (14 bytes) into `URB->TransferBuffer` (`URB+0x28`), sets `URB->Status=0` and completes the IRP. The destination is the buffer of a kernel-submitted bulk/interrupt URB; the length is fixed; no caller-supplied pointer or size. The endpoint descriptor generated by `FUN_14000171c` advertises `wMaxPacketSize=0x40` (64), so the normal 14-byte report fits.
3. **`0x2A0014`** (`FUN_140001258`): one 8-byte store into the same `URB->TransferBuffer`, same constraints.
4. **URB descriptor path** (`FUN_14000171c`): for `DescriptorType 1` it requires `TransferBufferLength == 0x12` and writes exactly 0x12 bytes; for the configuration descriptor it writes a fixed 0x22-byte descriptor; for `DescriptorType 0x22` (HID report) it writes a fixed 0x82 / 0x9D / 0x3F-byte blob and updates `TransferBufferLength`, **without checking the incoming `TransferBufferLength`**. This is a fixed-size write into a URB buffer supplied by a **kernel** URB submitter (hidusb/hidclass), not by the user. It is not reachable through `DeviceIoControl`; no user-controlled target or length.
5. **Child list / device relations** (`FUN_140006cac`, `FUN_140007a68`, `FUN_140006c08`): list unlink, reference-count and `IoInvalidateDeviceRelations`/`IoRequestDeviceEject`; fixed kernel structures.
6. **WMI** (`FUN_140007b30`, `FUN_140007b90`): writes a fixed 8-byte value and fixed WMI structures after length checks; not a memory-write primitive.
7. **HAL callbacks** (`FUN_140001090`, `0x140001110`, `0x140001150`, `0x1400011d0`): PCI config read/write, DMA adapter, bus-address translation — **HW-ONLY**, no kernel memory write.

No write uses a caller-controlled destination pointer or offset; every caller-controlled length is matched to the destination allocation, and the remaining stores are fixed-size. The only non-driver-buffer stores are the fixed 8/14-byte report injections and the fixed descriptor blobs into kernel-owned URB buffers.

### 3.6 Verdict

**NO-MEMORY-WRITE — reach=R2 (child PDO) / R3 (composition) setup=composition write=W0 load=signed.** The child PDO SDDL is admin-only, and the IOCTL surface has no caller-controlled kernel target or length. The i386 sibling is **BLOCKED (architecture)**; its static logic is the same and contains no additional write.

## 4 usblddaqlib pair (Measurement Computing USB-2500 loader)

### 4.1 Internals

- PE32+ x64, image base `0x10000`, TimeDateStamp 2009-12-29, 73 functions, PDB path `...\usblddaqlib_sys\objfre_wnet_amd64\amd64\USBLDDAQLIB.pdb`; description "USB-2500 Loader Device Driver"; `.data` 0x27670 bytes (firmware/config image, not code).
- Imports: `ntoskrnl.exe` (45 imports total across all DLLs: device/PnP/IRP/pool/timer/WMI), `HAL.dll` (`KeQueryPerformanceCounter`), `WMILIB.SYS`, `USBD.SYS` (`USBD_CreateConfigurationRequestEx`, `USBD_ParseConfigurationDescriptorEx`).
- **No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmMapLockedPages`, `MmCopyMemory`, `MmGetPhysicalAddress`, `ZwMapViewOfSection`, `MmGetSystemAddressForMdlSafe`, `IoAllocateMdl`, `MmProbeAndLockPages`, `ProbeForWrite`, or `MmGetSystemRoutineAddress`.** This is a material difference from the x86 `usblddaqlib` siblings `2F015011`/`46990A05`, which import `IoAllocateMdl` + `MmProbeAndLockPages` (but still no mapping API; both are x86 and BLOCKED).
- `.data` is zero-filled firmware/parameter space; no second code image.

### 4.2 Entry / device / interface / effective DACL

- DriverEntry `FUN_00011008`: copies the `RegistryPath` (`UNICODE_STRING` at arg 2) into a pool buffer, installs the dispatch table:
  - CREATE `0x70` = `FUN_000136dc`; CLOSE `0x80` = `FUN_00013804`; DEVICE_CONTROL `0xE0` = `FUN_00013878`; CLEANUP `0x100` = `FUN_00012970`; POWER `0x120` = `FUN_00012d14`; SYSTEM_CONTROL `0x128` = `FUN_000140e0`; PNP `0x148` = `FUN_00011464`; unload `0x68` = `FUN_0001111c`; AddDevice = `FUN_00011148`.
  - No READ/WRITE/INTERNAL_DEVICE_CONTROL.
- AddDevice `FUN_00011148`: `IoCreateDevice(DriverObject, 0x250, NULL, 0x22, 0x80 /*FILE_AUTOGENERATED_DEVICE_NAME*/, FALSE, &DeviceObject)`; initializes the extension, `IoWMIRegistrationControl`, `PoSetPowerState`, `IoAttachDeviceToDeviceStack`, then `IoRegisterDeviceInterface(PDO, &{C8711B66-9900-4F42-83C2-7EFEFEE0F221}, NULL, ...)` at `0x000161b0`.
- **Effective DACL:** unnamed FDO, no SDDL, no `IoCreateSymbolicLink`, no `IoCreateDeviceSecure`, no `ZwSetSecurityObject`. Access is through the PnP interface (default DACL) and the driver's own name check.
- CREATE `FUN_000136dc` is an **open gate**: it reads `FileObject->FileName` (`FILE_OBJECT+0x58`) and, when the name is non-empty, compares it against an allow-list at `ext+0x80` (`ext+0x78` = count) via `FUN_0001438c`. A name match sets `FileObject->FsContext` to the matching 0x18-byte entry; an empty name is accepted with `FsContext=0`. No privilege check; the check is a name handshake, not a DACL.
- Access is hardware-gated: the FDO is a function driver for the USB-2500/PDaq3K loader device (**R3 hardware**).

### 4.3 Dispatch and IOCTL table

Dispatcher `FUN_00013878`. Gate: `ext+0x88` must be 2 (started), else `STATUS_INVALID_DEVICE_STATE` (0xC0000184). `SystemBuffer = IRP+0x18`; `IoControlCode = stack+0x18`; `OutputBufferLength = stack+0x08`; `InputBufferLength = stack+0x10`.

| IOCTL | Method / access | Sizes | Kernel action |
|---|---|---|---|
| `0x220000` | BUFFERED / ANY | out >= `ushort(*(ext+0x70)+2)` | Copies `ushort(ext+0x70+2)` bytes from the driver's device-config buffer at `ext+0x70` to `SystemBuffer`; returns `STATUS_BUFFER_TOO_SMALL` (0xC0000023) if out is smaller; Information = copied length |
| `0x220004` | BUFFERED / ANY | none | `FUN_00013a4c`: builds and sends `IOCTL 0x220013` and, if bit 2 of the result is set, `IOCTL 0x220007` to the lower device with no user buffer; returns the lower status |
| `0x220008` | BUFFERED / ANY | none | `FUN_000139c0`: requires `FileObject->FsContext != 0` (name-matched open); builds a 0x28-byte vendor URB with `*(FsContext+8)` as the pipe handle and sends it to the lower device; no user buffer |
| other | — | — | `STATUS_INVALID_DEVICE_REQUEST` (0xC0000010) |

All three are METHOD_BUFFERED (low 2 bits 0) and FILE_ANY_ACCESS (bits 14–15 = 0).

### 4.4 Access control

No `SeAccessCheck`, privilege check, or security-descriptor work. The only gate is the CREATE name allow-list (empty name accepted) plus the started state. Because there is no symbolic link, user access is via the PnP interface registered on the PDO; effective access is the PnP/device default DACL. The device exists only with the USB-2500/PDaq3K hardware (**R3**).

### 4.5 Memory-write trace

1. **`0x220000`** (`FUN_00013878`): `puVar6 = ext+0x70` (device config buffer); `len = *(ushort*)(puVar6+2)`; if `len <= OutputBufferLength`, `FUN_00014ba0(SystemBuffer, puVar6, len)` (memcpy). Destination is the SystemBuffer, which is at least `OutputBufferLength`; source is driver/device data. **No caller-controlled destination or length.**
2. **`0x220004`** (`FUN_00013a4c`): `IoBuildDeviceIoControlRequest(0x220013, ...)` / `0x220007`; writes only IRP stack fields and a stack local; no user pointer.
3. **`0x220008`** (`FUN_000139c0`): allocates a 0x28-byte URB, sets `Length=0x28`, `Function=0x1E`, copies `*(FsContext+8)` into the URB pipe field, sends it; frees it. `FsContext` is a driver list entry selected by the create-time name match, not a user pointer.
4. **URB/config paths** (`FUN_00011684`, `FUN_0001453c`, `FUN_00013bc0`, `FUN_00013df8`): driver-owned IRP/URB/extension structures and a device-supplied configuration descriptor (`FUN_00014b40`/`0x14ba0` copies sized to the descriptor). No mapping API and no physical-address use.
5. **Pool copies** in `FUN_00012aa4`, `FUN_00013bc0`, `FUN_00013df8`, `FUN_000140e0`: fixed 0x10/0x28-byte allocations and fixed-size stores; no caller offset.

**No kernel-VA write, no MDL mapping, and no physical-memory (W3P) path exists in either x64 build.** The x86 siblings' `IoAllocateMdl`/`MmProbeAndLockPages` imports are absent here and, in any case, those siblings have no mapping call.

### 4.6 Verdict

**NO-MEMORY-WRITE — reach=R3 setup=hardware write=W0 load=signed.** `CDEC967D` is code-identical to `9E26A72E` (dump line-identical apart from the program name); the only material difference is the signature block/signer (MCC vs Digilent).

## 5 Most dangerous exposed capability (overall)

- **DesktopVideoUpdate:** raw URB transfers and configuration re-selection (`0x2220B8`, `0x2220D8`–`0x2220E8`), all bounded by SystemBuffer/endpoint lengths. The device is a USB peripheral; no kernel memory write.
- **EL_Display_vhidbus:** admin-only child PDO creation with caller-supplied report/ID blobs (`0x2A0000`) and fixed 8/14-byte report injection into a kernel URB buffer (`0x2A000C`/`10`/`14`). The injection target and size are kernel-owned, not caller-controlled; the creation path has a kernel OOB **read** (leak) but no write overflow. The PCI-config interface is HW-ONLY and kernel-to-kernel.
- **usblddaqlib:** a device-config read-back IOCTL and two device-control IOCTLs. No MDL, no physical mapping, no kernel memory write.

## 6 Overall verdict

| Field | Value |
|---|---|
| Files | six audits above |
| Reach | R2 (EL child) / R3 (all loadable devices) / n/a (i386) |
| Setup | hardware (4), composition (1), n/a (1) |
| Write quality | **W0** |
| Verdict | **NO-MEMORY-WRITE** for `DesktopVideoUpdate_81F65827`, `DesktopVideoUpdate_legacy_8A6D0B83`, `EL_Display_vhidbus_3242D1DC`, `usblddaqlib_9E26A72E`, `usblddaqlib_CDEC967D`; **BLOCKED (i386)** for `EL_Display_vhidbus_ECE1CE28` |
| MW level | **none (no MW1–MW4)** |

No driver in this tail exposes a caller-controlled kernel memory write. The closest surfaces are the EL_Display child-creation pool copies (destination sized to the copy; OOB read only) and the fixed report injection into a kernel-submitted URB buffer (target/size not caller-controlled).

## 7 Limitations

- **REA was not used.** Four REA audits were already active on the shared bridge (the task/`audits\STATUS.md` cap is four concurrent sessions). All findings are from local Ghidra 12.1.4 headless, `llvm-objdump`, and PE/AuthentiCode inspection. No REA evidence IDs exist for this report.
- **Static only.** No driver was loaded, executed, installed, or written to the registry; no devnode or hardware was staged.
- **EL_Display `0x2A0000` OOB read:** the handler does not check `InputBufferLength`; short inputs cause out-of-bounds reads of the SystemBuffer pool into the new child's ID/report buffers. This is a kernel **info leak**, not a write, and is out of scope for this memory-write audit. It is recorded because the same lengths are the only caller-controlled values near a kernel store.
- **EL_Display fixed report injection:** `0x2A000C`/`10`/`14` write 8/14 bytes into `URB->TransferBuffer` without comparing to `TransferBufferLength`. An overflow past the URB buffer would require a kernel URB submitter to supply a buffer smaller than 14 bytes; the endpoint descriptor generated by the driver advertises `wMaxPacketSize=0x40`, and the URB path is IRP_MJ_INTERNAL_DEVICE_CONTROL (not `DeviceIoControl`). No static proof of an undersized kernel buffer, so this is not rated W3. It remains the top unresolved path if a dynamic harness can observe hidusb's read buffer size.
- **EL_Display `ext+0x50` length mismatch** (`in[0x203]` stored for a buffer allocated with `in[0x236]`) is an OOB-read risk in `FUN_1400066dc` (`%ws`), not a write; `_snwprintf` bounds the output allocation.
- **EL_Display URB descriptor path** writes fixed 0x22/0x82/0x9D/0x3F-byte blobs without checking `TransferBufferLength`; reachable only from a kernel URB submitter.
- **DesktopVideoUpdate legacy** is test-signed (`WDKTestCert`), so it is not loadable on a normally signed/HVCI system; its code is dump-identical to the WHQL image, so the W0 finding is code-based, not load-based.
- **usblddaqlib interface DACL** is not expressed in the image (no SDDL, no symlink); the INF/PnP default was not available. The reported gate is therefore "PnP interface default + CREATE name handshake + hardware presence", not a resolved SDDL.
- **Signatures** were checked at analysis time on the host; certificate revocation/trust-chain state can change.
- No exploit code, PoC, or BYOVD steps are included. The pre-existing per-driver reports `DesktopVideoUpdate_81F65827.admin.static.md`, `DesktopVideoUpdate_legacy_8A6D0B83.admin.static.md`, `EL_Display_vhidbus_ECE1CE28.admin.static.md`, `usblddaqlib_2F015011.admin.static.md`, and `usblddaqlib_46990A05.admin.static.md` were used only as cross-checks; this report covers the six assigned tail files and does not modify those reports or `audits\STATUS.md`.
