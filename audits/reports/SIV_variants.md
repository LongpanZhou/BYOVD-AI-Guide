# Audit: SIV driver variants - SIVA32, SIVNT3, SIVNT4, SIVP32, SIVX32, SIVX64

| Field | Value |
|---|---|
| File(s) | `drivers/SIVA32_ACF0A05D.sys`, `drivers/SIVNT3_4D5D6150.sys`, `drivers/SIVNT4_D2480941.sys`, `drivers/SIVP32_8186ADD9.sys`, `drivers/SIVX32_BB7B2C60.sys`, `drivers/SIVX64_956D5440.sys` |
| SHA-256(s) | `ACF0A05DECB12D805636192FE8D9D463F39E902B325E301974F8E2EA14255E3C` (SIVA32)<br>`4D5D615096A71541E1C9AE471114D171F87F3EA603071ED3598F85F83CB44CF4` (SIVNT3)<br>`D248094147F7CA440143BF7600806ACFCA4873F62D7A12D5A4C864887708F654` (SIVNT4)<br>`8186ADD91E912BDFD3582C4EC0ACCBFD87D87799A7CEDB227F747005216E60EB` (SIVP32)<br>`BB7B2C60EBD3AB8C9CB62DEB06E19E7B6115BE7E8F4837A8E4E1744BF7E01661` (SIVX32)<br>`956D5440E857BDFD6EC5221AC4CBEF6C710B8F3AC08350641A7556644B6F2BB6` (SIVX64) |
| Analysis date | 2026-10-25 |
| Method | Static-only. PE/import/string triage with `objdump`; local Ghidra 12.1.4 headless decompilation of the x86/x64 images. No load, execution, service creation, registry write, or installer run. No web access. REA was not used because the shared bridge is at capacity (three other REA audits active); this is the disclosed engine gap. Nothing was run against a live device. |
| Reach tier | **R2 - local administrator** for SIVX64 (default device DACL; relative opens additionally require `SeLoadDriverPrivilege`, which an administrator holds). Not applicable to the five non-loadable images. |
| Setup required | **service** for SIVX64 (create/start a legacy kernel service; no devnode, hardware, or composition step). Not applicable to the five BLOCKED images. |
| Write quality | **W3P** - physical-memory mapping/write only. No W1/W2 kernel-VA write and no reachable W3 fixed-value kernel-VA store was found in the traced paths of the loadable image. |
| Verdict | **MW3 - SIVX64 only; the other five images are BLOCKED (architecture mismatch on this x64 host).** |
| HW-only | **yes** - the family exposes MSR (`wrmsr`), port I/O (`in`/`out`), PCI config (`HalGet/SetBusDataByOffset`), SMBus/EC, and MMIO paths. They are recorded as HW-ONLY and are not rated MW1-MW4. |

**Overall verdict:** `MW3 - reach=R2 setup=service write=W3P load=signed` for `SIVX64`. `SIVX32`, `SIVNT3`, `SIVNT4`, `SIVA32`, and `SIVP32` are **BLOCKED** on this Windows 10 x64 host: they are i386, Alpha AXP, or PowerPC images and cannot be loaded by the x64 kernel. Their static physical-memory path is the same family primitive, but it is not actionable on this machine.

---

## 1. Bottom line

The SIV family is a hardware-diagnostics driver with a very large raw-function IOCTL surface. The only primitive that reaches a **kernel memory write** is the physical-memory path:

- `IOCTL 0x10` (`IOCTL_SIV_PHY_MEMORY`) maps a caller-supplied physical address and copies the mapping to the output buffer - **arbitrary physical read / info leak**, not a write.
- `IOCTL 0x13` (`IOCTL_SIV_BIG_MEMORY`, `METHOD_NEITHER`) does the same with an explicit `ProbeForRead`/`ProbeForWrite` pair - **arbitrary physical read**, not a write.
- `IOCTL 0x14` (`IOCTL_SIV_BAR_MEMORY`) maps a caller-supplied physical address and performs a read-modify-write of a 32-bit value at a caller-supplied offset. With mask `0`, the value is fully caller-controlled. This is an **arbitrary physical dword write**, i.e. `W3P`, `MW3`.

The write target is physical memory, not a caller-chosen kernel virtual address. `MmMapIoSpace` returns a kernel VA, but the caller only selects the physical address. There is no `MmMapLockedPagesSpecifyCache`, `ZwMapViewOfSection`, `MmCopyMemory`, or `MmGetPhysicalAddress` path that turns this into an arbitrary kernel-VA write.

The driver also exposes MSR, port I/O, PCI config, SMBus/EC, and MMIO operations. Those are HW-ONLY. The `0x24` MSR write of `IA32_SYSENTER_ESP` (MSR `0x150`) is the most interesting hardware residual, but no static chain from it to a kernel memory write was established, so it is not rated as a memory write.

## 2. File identity, architecture, and loadability

Hashes were computed with `Get-FileHash -Algorithm SHA256` and match the filenames' embedded hash suffixes. Signatures were checked with `Get-AuthenticodeSignature`; all six report `Status: Valid`.

| File | Machine | PE | Size | Signature | Loadable on this host? |
|---|---|---|---:|---|---|
| `SIVA32_ACF0A05D.sys` | `0x0184` - **Alpha AXP** | PE32 | 207,632 | RH Software Limited, valid | **No** - not an x86/x64 image |
| `SIVNT3_4D5D6150.sys` | `0x014C` - **i386** | PE32 | 149,496 | RH Software Limited, valid | **No** - 32-bit kernel driver on x64 |
| `SIVNT4_D2480941.sys` | `0x014C` - **i386** | PE32 | 149,496 | RH Software Limited, valid | **No** - 32-bit kernel driver on x64 |
| `SIVP32_8186ADD9.sys` | `0x01F0` - **PowerPC** | PE32 | 260,048 | RH Software Limited, valid | **No** - not an x86/x64 image |
| `SIVX32_BB7B2C60.sys` | `0x014C` - **i386** | PE32 | 169,160 | Microsoft WHCP, valid | **No** - 32-bit kernel driver on x64 |
| `SIVX64_956D5440.sys` | `0x8664` - **AMD64** | PE32+ | 211,144 | Microsoft WHCP, valid | **Yes** - x64, WHCP-signed, not in `known_bad_hashes.txt` |

Host: Windows 10 Pro 19045, `OSArchitecture = 64-bit`, `PROCESSOR_ARCHITECTURE = AMD64`. A 32-bit kernel driver cannot be loaded by the x64 kernel; Alpha and PowerPC images cannot be loaded at all on this machine. This is the same class of block as the already-audited `SIVI64` IA-64 image, but the five blocked files here are *not* assumed to be identical to `SIVI64` or to each other; each was identified by its own PE machine field and hash.

All six are version 5.88 builds dated 2026-10-14. `SIVX64` is built `11:53:21`, `SIVNT3` `11:53:04`, `SIVNT4` `11:53:07`, `SIVX32` `11:53:18`; the PDB paths are `D:\SIV\SIVNT3.pdb`, `D:\SIV\SIVNT4.pdb`, `D:\SIV\SIVP32.pdb`, `E:\SIV\obj\alpha\SIVA32.pdb`.

## 3. Device, interface, and effective DACL (shared design)

The SIVX64 image was decompiled end-to-end for the entry and dispatch. The 32-bit NT3/NT4 images and the x86 SIVX32 image use the same device name and the same `IoCreateDevice` pattern; their entry points and dispatches were also decompiled (SIVNT3/NT4 in full, SIVX32 at the entry and dispatch level).

| Item | SIVX64 evidence |
|---|---|
| `DriverEntry` | `0x42cdc` (`entry`), calls the device/initialisation function at `0x42008`. |
| Device creation | `0x42008`; `IoCreateDevice` call at `0x4206a` with `DeviceType = 0x22` (`FILE_DEVICE_UNKNOWN`), `DeviceCharacteristics = 0` (no `FILE_DEVICE_SECURE_OPEN`), `Exclusive = 0`, and a **NULL security descriptor**. Device name `\Device\SIVDRIVER` at `0x42d40`. |
| Symlinks | `\DosDevices\SIVDRIVER` (`0x3ea10`) and, on Vista+, `\DosDevices\Global\SIVDRIVER` (`0x3ea40`). |
| Driver object dispatch | `DriverUnload = 0x21008` at `0x42b45`; `IRP_MJ_CREATE = 0x211c8` at `0x42b51`; `IRP_MJ_CLOSE = 0x21890` at `0x42b5d`; `IRP_MJ_DEVICE_CONTROL = 0x21984` at `0x42b6c`. |
| Effective SDDL/DACL | No SDDL string, no `IoCreateDeviceSecure`, no `SeAssignSecurity`/`RtlSetDaclSecurityDescriptor`, and no security-descriptor bytes are present. The object receives the I/O manager's default device DACL: `D:P(A;;GA;;;SY)(A;;GA;;;BA)` - SYSTEM and BUILTIN\Administrators full control, no `WD`/`AU`/`BU`/`IU` ACE. This is the documented `IoCreateDevice` default; it was **not** read from a live device object (static-only limitation). |
| Open gate | `IRP_MJ_CREATE` at `0x211c8`. A normal open by symlink has an empty `FileObject->FileName`, so only the device DACL is checked. A **relative open by name** (the driver also recognises `\GPIO-EXT` and `\GPIO-INT`) hits `SeSinglePrivilegeCheck` at `0x21250` with the LUID at `0x1b960`; the bytes there are `0A 00 00 00 00 00 00 00` = **SeLoadDriverPrivilege (10)**, `PreviousMode = UserMode`. An administrator holds that privilege by default. |
| Per-IOCTL access checks | None. The image has no `IoValidateDeviceIoControlAccess` and no per-code `SeAccessCheck`. The low raw codes have `FILE_ANY_ACCESS` (access bits 0), so the device DACL is the only gate. Some high `CTL_CODE` values request `FILE_READ|FILE_WRITE` (e.g. `0x7C084`, `0x4D004`) or `FILE_WRITE_ACCESS` (e.g. `0x294080`); an administrator's full-access handle satisfies them. |

The 32-bit builds use the same `\Device\SIVDRIVER` / `\DosDevices[\Global]\SIVDRIVER` names and the same `IoCreateDevice` call with a NULL SD:

- `SIVNT3`: entry `0x31000`; `IoCreateDevice` at `0x31036`; create dispatch `0x1f0c6`; IOCTL dispatch `0x1f47b`; MajorFunction setup at `0x3182c`/`0x3183a`; LUID at `0x165c8` is also `10` (`SeLoadDriverPrivilege`).
- `SIVNT4`: entry `0x31000`; create dispatch `0x1f0c6`; IOCTL dispatch `0x1f44b`; same default device DACL.
- `SIVX32`: entry `0x37a75`, device create `0x37006`; create dispatch `0x2ac10`; IOCTL dispatch start `0x2cc3a`; same device name and default DACL.
- `SIVA32` / `SIVP32`: strings contain `\Device\SIVDRIVER`, `\DosDevices\SIVDRIVER`, `\DosDevices\Global\SIVDRIVER`, and `IoCreateDevice` is imported. They are the same family design; the architecture block makes the DACL moot.

**Reach conclusion:** `R2` for SIVX64. The default DACL excludes unprivileged openers; the relative-open privilege is also administrator-held. No unprivileged open path was found. If a deployment rewrites the device SD to grant `Everyone` read/write, the low `FILE_ANY_ACCESS` codes would become R1; this was not observed statically and is not assumed.

## 4. Dispatch and IOCTL surface

SIVX64's `IRP_MJ_DEVICE_CONTROL` handler is `FUN_00021984` at `0x21984`. The driver does **not** use `CTL_CODE` for most of its interface: it compares the raw `IoControlCode` field against small function values (`0x10`, `0x13`, `0x14`, `0x74`, `0x100`, ...). Because the raw value's low two bits still select the I/O-manager transfer method, the effective methods are:

- `0x07` and `0x13` are `METHOD_NEITHER` (low bits `3`).
- Nearly every other low code is `METHOD_BUFFERED` (low bits `0`).
- `0x04` is `METHOD_BUFFERED` and reaches the version store at `0x22753`/`0x22774` through the `SystemBuffer` pointer (`r14` set at `0x21a29`); `0x07` is `METHOD_NEITHER` and is gated on `FileObject == 0x66666666` at `0x22723`, so it is dead for a normal user handle.
- No low code is `METHOD_IN_DIRECT`/`OUT_DIRECT` except incidental `0x19`/`0x75`-style values, which are not top-level cases in this build.

The table below lists every top-level code identified in the dispatch, grouped where the action is identical. "m/a" is `method/access` from the raw value; "0/0" means `METHOD_BUFFERED`, `FILE_ANY_ACCESS`. Input/output sizes are the branch minimums observed in the decompiled handler; "var" means the handler has several sub-shapes.

| Code(s) | m/a | In/out | Kernel action | Memory write? |
|---|---|---|---|---|
| `0x04` | 0/0 | var / var | Version query. Enters at `0x22753`; stores the fixed version string at `0x22774` through the `SystemBuffer` pointer (`r14` set at `0x21a29`). No caller-chosen pointer. | No |
| `0x07` | 3/0 | 8 / 12 | Same version path, but gated on `FileObject == 0x66666666` at `0x22723`; a normal user handle never satisfies it. Dead. | No |
| `0x08` | 0/0 | 4 / 8 | `rdmsr` of a caller-selected MSR, subject to a whitelist (`FUN_00018fbd`); returns 8 bytes. | No (HW) |
| `0x0C` | 0/0 | 12 / 12 | `wrmsr` of MSR `0x38D/0x38F/0x19C/0x110A/0x1147/0xC0000086`; caller value. | No (HW) |
| `0x10` | 0/0 | >=8 / 4..0x40000 | **`IOCTL_SIV_PHY_MEMORY`**: maps caller PA at `0x2228d` via `0x29a40`; copies mapping to output. Optional 0x30-byte descriptor selects a stride. | Read only |
| `0x13` | **3/0** | 8 / 0x400..0x1000000 | **`IOCTL_SIV_BIG_MEMORY`**: `ProbeForRead` input 8, `ProbeForWrite` output, maps caller PA at `0x21faf`, copies mapping to user output. | Read only |
| `0x14` | 0/0 | equal, >=0x48 | **`IOCTL_SIV_BAR_MEMORY`**: maps caller PA at `0x21c06` (size 0x100..0x400000); descriptor array at input+0x30; RMW write at `0x21d99`. | **Yes - arbitrary physical dword write (W3P)** |
| `0x18` | 0/0 | any | Returns `STATUS_INVALID_PARAMETER`; no action. | No |
| `0x1C` | 0/0 | any | Returns `STATUS_INVALID_PARAMETER`; no action. | No |
| `0x20` | 0/0 | >=4 / >=4 | Writes PCI config offset 0xD0 for bus 0/dev 0 (`FUN_00011ae4`/`FUN_000119c8`). | No (PCI config) |
| `0x24` | 0/0 | >=4 / >=0x18 | IPI/TSC calibration; writes **MSR 0x150 (`IA32_SYSENTER_ESP`)** with a caller-derived value. | No (MSR; HW-ONLY) |
| `0x28` | 0/0 | >=0x80 / >=0x80 | CPU/topology query. | No |
| `0x2C` | 0/0 | >=0x40 / >=0x40 | CPU/IPI worker enumeration. | No |
| `0x30` | 0/0 | any / >=0x64 | Disk/device information. | No |
| `0x34` | 0/0 | any / any | Resets internal counters/flags. | No |
| `0x3C`, `0x4010C` | 0/0 | any / any | Resets internal counters/flags. | No |
| `0x40` | 0/0 | >=8 / >=0x40 | PCI bus/ECAM read; maps a computed physical window and copies to output. | Read only |
| `0x44` | 0/0 | >=12 / >=4 | PCIe config/BAR access; maps a BAR via `FUN_00029934`; bounded RMW within 0x1000 at decompiled line 3973. | No (BAR/MMIO) |
| `0x48` | 0/0 | >=16 / >=16 | PCI config write of a caller-supplied block. | No (PCI config) |
| `0x4C` | 0/0 | >=12 / >=0x40 | PCI config/SPD read. | No |
| `0x50` | 0/0 | >=4 / >=8 | Scans I/O ports 0..0xFFF via `in`; returns first/last. | No (port I/O) |
| `0x54`, `0x58`, `0x5C` | 0/0 | >=8 / var | `HalGetBusDataByOffset` PCI config reads (types 7, 1, 0); `0x5C` also reads ports 0x70/0x71. | No (HW) |
| `0x60` | 0/0 | var / >=var | SMBus/device-list query; copies internal tables to output. | No |
| `0x68`, `0x70` | 0/0 | >=0x20 / var | SMBus put/block operations via the SMBus stack. | No (HW) |
| `0x74` | 0/0 | >=0x48 / >=0x48 | **`IOCTL_SIV_PCIBUS`**: maps a PCI bus window and copies to output. | Read only |
| `0x78`, `0x7C` | 0/0 | >=0x38 / >=0x38 | PCI config/device queries. | No |
| `0x80` | 0/0 | >=0x28 / >=0xF58 | ACPI/device table query. | No |
| `0x84` | 0/0 | var / >=0x24 | `IOCTL_SIV_OXSEMI` device query. | No |
| `0x88` | 0/0 | >=0x10 / >=0x10 | Device/PCIe information. | No |
| `0x8C` | 0/0 | 4 or 0 / var | PCIe map/unmap helper (`FUN_00029934`/`0x29c1c`); no data write. | No |
| `0x90` | 0/0 | 4 / 0 or >=0x46 | Device configuration query. | No |
| `0x94` | 0/0 | any | Invalid/no action. | No |
| `0x98`, `0x9C` | 0/0 | >=0x10 / >=0x110 | Device/firmware information read/compare. | No |
| `0xA0`, `0xA4`, `0xA8` | 0/0 | >=2 / var | Port `in` byte/word/dword loops (`in`). | No (port I/O) |
| `0xB0`, `0xB4`, `0xB8` | 0/0 | >=3/4/8 / 0 | Port `out` byte/word/dword. | No (port I/O) |
| `0xC0` | 0/0 | >=8 / var | `ZwOpenSymbolicLinkObject` + query link target. | No |
| `0xC4` | 0/0 | >=8 / var | Enumerates `\Device\Harddisk%u\Partition0` and queries links. | No |
| `0xD0` | 0/0 | >=0x38 / >=0x38 | Maps caller PA for 0x400 bytes via `0x24998`; copies selected fields to output. | Read only |
| `0xD8` | 0/0 | var / var | `IOCTL_SIV_MUTANT_OWNER`: `ObReferenceObjectByHandle` + object field read; writes to output. | No |
| `0xE0` | 0/0 | any / >=0x6C | Copies 0x6C bytes of driver state to output. | No |
| `0xE4` | 0/0 | any / var | Copies a variable driver-state range to output. | No |
| `0xE8` | 0/0 | >=0x20 / >=0x20 | `HalTranslateBusAddress` query. | No (HW) |
| `0xF0`, `0xF8`, `0xFC` | 0/0 | >=10/12 / var | Port I/O sequences (including indexing through ports 0xCF8/0xCFC-style pairs). | No (port I/O) |
| `0x100`, `0x104` | 0/0 | var / var | ACPI namespace/table read via `FUN_0002fddc`; writes only to output. | No |
| `0x130`, `0x134`, `0x138`, `0x13C` | 0/0 | >=8 / var | ACPI/DSDT/table head and firmware queries. | No |
| `0x144` | 0/0 | >=0x10 / >=0x210 | `IOCTL_SIV_DISK_CSMI` ATA/CSMI pass-through to the disk stack. | No |
| `0x160` | 0/0 | var / >=8 | CPU/firmware information. | No |
| `0x170` | 0/0 | any / >=4 | `IOCTL_SIV_GET_CPU_CR0`: returns current CR0 (read). | No |
| `0x184`, `0x188`, `0x18C`, `0x194`, `0x198`, `0x19C` | 0/0 | var / >=0x80 | `IoGetDeviceProperty` / `IoOpenDeviceRegistryKey` + `ZwQueryKey` queries. | No |
| `0x1B8` | 0/0 | var / var | CPU/IPI timing table. | No |
| `0x1BC` | 0/0 | var / >=0x80 | Device registry key query. | No |
| `0x1C0`, `0x1C4`, `0x1C8` | 0/0 | >=1 / <=0x100 | Port `in` loops (0x3C4/0x3C5, 0xCD6/0xCD7, 0xCD0/0xCD1). | No (port I/O) |
| `0x1D0`, `0x1D4`, `0x1D8`, `0x1DC`, `0x1E0`, `0x1E4` | 0/0 | >=0x28/0x40/0x70 / same | ACPI/PCIe/firmware table queries. | No |
| `0x1EC` | 0/0 | >=0x90 / >=0x80 | ACPI/firmware query (`FUN_0002c454`). | No |
| `0x1F0` | 0/0 | >=8 / >=12 | PCIe config read. | No |
| `0x1F8` | 0/0 | >=4 / equal | AMD PCIe/SMN access; maps a BAR and performs vendor-specific MMIO. | No (MMIO) |
| `0x40108`, `0x40120`, `0x40124`, `0x40128`, `0x40140`, `0x40150`, `0x40160` | 0/0 | var / var | Storage/SCSI helper codes; fill caller output, send pass-through to the disk stack. | No |
| `0x4100C`, `0x41018` | 0/0 | var / var | SCSI inquiry / get-address pass-through. | No |
| `0x4D004`, `0x4D008`, `0x4D02C` | 3/3 | var / var | SCSI pass-through, SCSI miniport, ATA pass-through. | No |
| `0x70000`, `0x700A0`, `0x74080` | 0/0, 0/0, 0/1 | var / var | Drive geometry / SMART version. | No |
| `0x7C084`, `0x7C088` | 3/3 | var / var | SMART send/receive drive data. | No |
| `0x294080`, `0x294180` | 1/1 | var / var | Processor object information. | No |
| `0x2D1400` | 0/0 | >=12 / >=8 | Storage query property. | No |
| `0x32C004`, `0x32C020` | 3/3 | var / var | Storage/device property queries; one copies internal state to output. | No |

**Method/access caveat.** The raw codes are not `CTL_CODE` values. The I/O manager still derives the transfer method and access mask from the low bits, so `0x13` is `METHOD_NEITHER` and almost everything else is `METHOD_BUFFERED`/`FILE_ANY_ACCESS`. The driver itself never validates the handle's access rights. This is why the device DACL is the decisive gate.

## 5. Memory-write trace (SIVX64)

### 5.1 `IOCTL 0x14` - arbitrary physical dword write (`W3P`)

This is the only path that writes memory.

1. Dispatch enters the `0x14` branch at `0x21984` / case value `0x14` (top-level tree; the handler starts at `0x21b91`).
2. It requires `InputBufferLength == OutputBufferLength` and `InputBufferLength >= 0x48`.
3. From the buffered input:
   - `PA = *(uint64*)input` (`0x21ba3`/`0x21bf8` region),
   - `size = *(uint32*)(input+8)`; accepted only when `0x100 < size <= 0x400000`,
   - `count = *(uint16*)(input+0x14)`; the descriptor array starts at `input+0x30`, each entry 0x18 bytes; `0x30 + count*0x18 <= InputBufferLength`,
   - the 16-bit flags field at `input+0xe` must have bit 15 clear to take the RMW branch; bit 1 enables the store, bit 2 requests readback, and bit 14 enforces 4-byte offset alignment.
4. `FUN_00029a40` is called at **`0x21c06`** with `(driver, PA, size, wait_flag)`. That wrapper:
   - rounds `PA` down to a page and `size` up to a page (`0x29a40`),
   - checks its mapping cache, otherwise calls `MmMapIoSpace`/`MmMapIoSpaceEx` through the function pointer at `0x29b5d` with protect `0x204` (`PAGE_READWRITE | PAGE_NOCACHE`),
   - returns `mapped_VA + (PA & 0xFFF)`.
5. For each descriptor with `offset < size` and, if flag bit 14 is set, `offset & 3 == 0`:
   - `old = *(uint32*)(mapped_VA + offset)` at `0x21d67`,
   - `new = (mask & old) | or_value` at `0x21d74`-`0x21d81`, where `mask = *(uint32*)(desc+4)` and `or_value = *(uint32*)(desc+8)`,
   - the handler rejects the entry if `(mask & or_value) != 0` at `0x21d54`,
   - if `input_flags & 2` (bit 1 of the 16-bit field at `input+0xe`), it stores `new` to `*(uint32*)(mapped_VA + offset)` at **`0x21d99`**,
   - if `input_flags & 4`, it reads the value back into the output descriptor.
6. `FUN_00029c1c` at `0x29c1c` releases the mapping.

With `mask = 0`, `or_value = desired`, `offset = 0`, `size >= 0x100`, and flag bit 1 set, the store at `0x21d99` writes an arbitrary 32-bit value to an arbitrary physical address (a 4-byte store; the offset is only forced to be 4-aligned when input flag bit 14 is set). The physical address is a full 64-bit value on x64. The mapping is explicitly writable and non-cached. **This is arbitrary physical memory write, not arbitrary kernel virtual address write.**

Why this is `W3P`, not `W1`/`W2`: the caller selects a physical address, and the driver writes through the `MmMapIoSpace` alias. There is no caller-controlled kernel VA destination. The `MmMapIoSpace` VA itself is not returned to the caller, and no other IOCTL accepts a kernel VA as a destination. Per `SEVERITY.md`, a PA-based mapping/write is `W3P` -> `MW3`.

### 5.2 `IOCTL 0x10` - arbitrary physical read (info leak, not a write)

`IOCTL_SIV_PHY_MEMORY` at case `0x10`:

- Requires `InputBufferLength >= 8`, `4 <= OutputBufferLength <= 0x40000`.
- `PA = *(uint64*)input`; optional 0x30-byte descriptor supplies a stride (`*(uint32*)(input+0x10)`); `size = stride ? stride * OutputBufferLength : OutputBufferLength`.
- `FUN_00029a40` is called at **`0x2228d`**; the driver copies from the mapping to the output SystemBuffer (`0x222d7` and `0x22336` loops).
- No store to the mapping. This leaks arbitrary physical memory to the caller, but it is a read primitive. It is an important modifier (it can locate physical targets for `0x14`) but does not itself write kernel memory.

Note: if `stride * OutputBufferLength` overflows 32 bits, the mapping may be smaller than the copy length, producing an out-of-bounds **read** of the mapping. It remains a read.

### 5.3 `IOCTL 0x13` - arbitrary physical read via `METHOD_NEITHER` (not a write)

`IOCTL_SIV_BIG_MEMORY` at case `0x13`:

- `InputBufferLength == 8`, `0x400 <= OutputBufferLength <= 0x1000000`.
- `ProbeForRead(input_ptr, 8, 4)` and `ProbeForWrite(output_ptr, OutputBufferLength, 8)` at `0x21faf` region.
- `PA = *(uint64*)input_ptr`; `FUN_00029a40` maps it at **`0x21faf`**; the driver copies the mapping to the probed user output (`memmove`-style `FUN_00012e10`).
- No store to the mapping. This is a physical read / info leak. The probes prevent a kernel pointer from being used as the destination.

### 5.4 `IOCTL 0x44` - bounded BAR RMW (HW-ONLY)

Case `0x44` resolves a PCIe device/BAR through `FUN_00029934` (which searches the driver's enumerated PCI device table and calls `0x29a40` on the BAR physical address), then parses a descriptor array. At decompiled line 3973 it writes a caller-supplied 32-bit value to `BAR_mapping + offset`, but:

- the BAR is one the driver enumerated, not an arbitrary PA;
- `offset` must be `< 0x1000` and 4-aligned;
- the value is written through an `MmMapIoSpace` BAR mapping, i.e. device MMIO.

This is a bounded device-MMIO RMW, not a kernel memory write. It is HW-ONLY.

### 5.5 `IOCTL 0x24` - `wrmsr(0x150)` (HW-ONLY, potential chain not proven)

Case `0x24` writes `IA32_SYSENTER_ESP` (MSR `0x150`) through the `wrmsr` intrinsic at decompiled lines 3762-3763. The value is derived from the caller's first DWORD OR `0x80000000`, plus a per-iteration offset. This is a CPU MSR write, not a memory write. On a 32-bit Windows kernel it could pivot the SYSENTER stack and potentially chain into kernel memory corruption; on x64 the SYSENTER path is not the normal syscall entry, and no static chain to a kernel memory write was traced. It is recorded as HW-ONLY and does not change the MW3 verdict.

### 5.6 Fixed-value stores checked and rejected

- **Version path (`0x04`/`0x07`)**: the store at `0x22774` writes the fixed `"V5.88 ..."` string to `r14`. For `0x04`, `r14` is `Irp->AssociatedIrp.SystemBuffer` (set at `0x21a29`) and the write is to the buffered kernel buffer. For `0x07`, `r14` would be `Irp->UserBuffer` (loaded at `0x2273c`), but that branch is guarded by `FileObject == 0x66666666` at `0x22723` and is dead for a normal user handle. No reachable fixed-value kernel-VA store.
- **Guard-area store**: `*local_488 = 0xBADCAFFEDEADBEEF`-style stores in the dispatch/cleanup write only to the driver's own per-file context allocated in `IRP_MJ_CREATE`; the target is not caller-controlled.
- **Descriptor output fields**: the `0x14` handler writes old/new values back into the buffered SystemBuffer at `desc+0xc`/`desc+0x10`; this is the caller's own buffer, not a kernel target.

No W3 fixed-value store to an attacker-chosen kernel VA was found.

## 6. Why the other five are BLOCKED

| File | Architecture | Evidence | Why blocked on this host |
|---|---|---|---|
| `SIVA32_ACF0A05D.sys` | Alpha AXP (`0x0184`) | PE machine `0x0184`, PE32, entry `0x3e000`; imports `MmMapIoSpace`, `ProbeForWrite`, `IoCreateDevice`; strings `\Device\SIVDRIVER`, `IOCTL_SIV_PHY_MEMORY`, `IOCTL_SIV_BIG_MEMORY`, `IOCTL_SIV_BAR_MEMORY` | Alpha code cannot execute on AMD64. Static family design indicates the same `0x14` physical RMW, but it is not loadable and was not decompiled (Ghidra has no Alpha processor module). |
| `SIVP32_8186ADD9.sys` | PowerPC (`0x01F0`) | PE machine `0x01F0`, PE32, entry `0x1c1c8`; imports `MmMapIoSpace`, `ProbeForWrite`, `IoCreateDevice`; same device/IOCTL strings | PowerPC code cannot execute on AMD64. Static family indication only; not decompiled. |
| `SIVNT3_4D5D6150.sys` | i386 (`0x014C`) | Entry `0x31000`; `IoCreateDevice` `0x31036`; IOCTL dispatch `0x1f47b`; case `0x14` at decompiled lines 2655-2733; map wrapper `0x233b2`, unmap `0x235a3`; MSR `0x150` write at decompiled line 2617 | A 32-bit kernel driver cannot load on the x64 kernel. Static path is `W3P` (`0x14` arbitrary PA RMW) but is not actionable here. |
| `SIVNT4_D2480941.sys` | i386 (`0x014C`) | Entry `0x31000`; create dispatch `0x1f0c6`; IOCTL dispatch `0x1f44b`; same `0x10`/`0x13`/`0x14`/`0x24` cases; device extension `0x1f22` vs NT3's `0x21c2` | 32-bit kernel driver; not loadable on x64. Same static `W3P` path. |
| `SIVX32_BB7B2C60.sys` | i386 (`0x014C`) | Entry `0x37a75`; device create `0x37006`; create dispatch `0x2ac10`; IOCTL dispatch `0x2cc3a`; resolves `MmMapIoSpace`/`MmMapIoSpaceEx` dynamically; strings `IOCTL_SIV_PHY_MEMORY`/`BIG_MEMORY`/`BAR_MEMORY` | 32-bit kernel driver; not loadable on x64. Static family path is `W3P`. |

`SIVA32` and `SIVP32` are not "x86 variants" with a different bitness; they are different instruction sets. `SIVNT3`/`SIVNT4`/`SIVX32` are genuine i386 builds. None can be loaded by the AMD64 kernel on this host.

## 7. 32-bit vs 64-bit and SIVNT differences

The material differences are architectural, not primitive-level:

1. **Bitness and calling convention.** `SIVX64` is AMD64 and uses the x64 `IO_STACK_LOCATION`/`IRP` layouts (`0x18` SystemBuffer, `0x70` UserBuffer, `0xB8` CurrentStackLocation). `SIVNT3`/`SIVNT4`/`SIVX32` are i386 and use the 32-bit layouts (CurrentStackLocation at `0x60`, IoControlCode at `+0xC`, FileObject at `+0x18`, UserBuffer at `+0x3C`). The physical-memory cases are otherwise the same design.
2. **`MmMapIoSpace` resolution.** `SIVNT3`/`SIVNT4` import `MmMapIoSpace` directly and also resolve `MmMapIoSpace`/`MmMapIoSpaceEx` by name (`RtlInitUnicodeString` + `MmGetSystemRoutineAddress`). `SIVX64` has no static `MmMapIoSpace` import; it resolves `MmMapIoSpace` and `MmMapIoSpaceEx` dynamically (`0x3e850`/`0x3e870` strings, pointers stored at `+0x138`/`+0x140`). `SIVX32` also resolves both dynamically. The wrapper behavior is the same: writable non-cached mapping.
3. **Device extension / feature set.** NT3 uses `0x21c2` bytes of extension, NT4 `0x1f22`, X64 `0x2f8a`. The extra space carries different hardware tables (SMBus/EC/PCIe/ACPI), not a different memory primitive. The `0x10`/`0x13`/`0x14` cases exist in all three x86/x64 builds.
4. **MSR `0x150`.** All x86/x64 builds have the `0x24` `wrmsr(0x150)` path. It is HW-ONLY and not a memory write by itself. On 32-bit Windows it is a more plausible chain than on x64; this is noted as a residual, not rated.
5. **SIVNT3 vs SIVNT4.** Same entry, create dispatch, and IOCTL dispatch; different extension size and internal table layout. The physical-memory code is the same. Both are i386 and blocked on x64; no material memory-write difference.
6. **SIVX32 vs SIVX64.** Same raw-code family and same `0x14` physical RMW. The x64 build has more IOCTL cases (ACPI/PCIe/SCSI/SMART) and a larger dispatch, but the memory-write primitive is identical. SIVX32 is i386 and blocked on x64.
7. **SIVA32 / SIVP32.** Same source family (device name, IOCTL names, `MmMapIoSpace` import) compiled for Alpha and PowerPC. They are not analyzed to the same depth because they cannot load; no claim is made that their internal code is byte-identical.

## 8. Per-file table

| File | SHA-256 (prefix) | Reach / setup | Effective gate | Static memory-write finding | Verdict |
|---|---|---|---|---|---|
| `SIVX64_956D5440.sys` | `956D5440...` | R2 / service | `\Device\SIVDRIVER` default `D:P(A;;GA;;;SY)(A;;GA;;;BA)`; relative open needs `SeLoadDriverPrivilege` (LUID 10); admin holds it | `0x14` arbitrary physical dword RMW at `0x21d99` (`W3P`); `0x10`/`0x13` arbitrary physical read; `0x44` bounded BAR RMW; `0x24` MSR `0x150` HW-ONLY | **MW3** (`W3P`, signed) |
| `SIVX32_BB7B2C60.sys` | `BB7B2C60...` | n/a / n/a | Same family device and default admin DACL | Same `0x14` physical RMW family path (static); not loadable on this host | **BLOCKED** (i386 on x64) |
| `SIVNT3_4D5D6150.sys` | `4D5D6150...` | n/a / n/a | Same family device and default admin DACL | `0x14` physical RMW at decompiled lines 2655-2733; `0x24` MSR `0x150`; not loadable | **BLOCKED** (i386 on x64) |
| `SIVNT4_D2480941.sys` | `D2480941...` | n/a / n/a | Same family device and default admin DACL | Same `0x14` physical RMW family path; `0x24` MSR `0x150`; not loadable | **BLOCKED** (i386 on x64) |
| `SIVA32_ACF0A05D.sys` | `ACF0A05D...` | n/a / n/a | Same family strings/imports; default admin by design | Family indication of the same physical path (`MmMapIoSpace` + `IOCTL_SIV_BAR_MEMORY` strings); not decompiled, not loadable | **BLOCKED** (Alpha AXP) |
| `SIVP32_8186ADD9.sys` | `8186ADD9...` | n/a / n/a | Same family strings/imports; default admin by design | Family indication of the same physical path; not decompiled, not loadable | **BLOCKED** (PowerPC) |

**One overall verdict:** **MW3** - `SIVX64` at `reach=R2 setup=service write=W3P load=signed`; the remaining five are `BLOCKED` on this x64 host. No `MW1`/`MW2` kernel-VA write was found, no reachable `MW4` fixed-value kernel-VA store was found in the traced paths, and `NO-MEMORY-WRITE` is not supported for the loadable image because the `0x14` physical write exists.

## 9. Limitations and unresolved paths

1. **Static only / no live DACL read.** The effective `D:P(A;;GA;;;SY)(A;;GA;;;BA)` is the documented `IoCreateDevice` default. The image contains no SDDL and no security-descriptor code. The live device object's SD was not queried (no load/service/registry). If a deployment or filter attaches a different SD, the reach could change; an `Everyone`-writable SD would make the low `FILE_ANY_ACCESS` codes unprivileged, but the primitive remains `W3P`/`MW3`.
2. **No dynamic `MmMapIoSpace` confirmation.** `0x14` depends on `MmMapIoSpace`/`MmMapIoSpaceEx` accepting the caller's physical range and returning a writable mapping. The static call and protect value (`0x204`) are clear; actual success on this Windows 10 19045 host was not tested. Windows physical-memory mapping restrictions or HVCI could cause `STATUS_INSUFFICIENT_RESOURCES` (`0xC00000E6`) instead of a mapping. This is the main residual uncertainty for the MW3 rating.
3. **REA gap.** REA was not used; the shared bridge is at capacity and the task allowed offline Ghidra/objdump with disclosure. All SIVX64 and SIVNT3/NT4 claims are from local Ghidra 12.1.4 headless decompilation plus `objdump`; SIVX32 was decompiled only at the entry/dispatch level. SIVA32/SIVP32 were triaged by PE machine, imports, and strings only; no Ghidra decompilation (Alpha is unsupported by the installed Ghidra processors; PowerPC is non-loadable and was not worth the extra pass).
4. **Raw IOCTL numbering.** The driver compares raw function numbers, not `CTL_CODE` values. The table lists the top-level values observed in the dispatch; a few values are shared sub-commands inside a parent case and are not listed as independent IOCTLs. The memory-relevant codes (`0x10`, `0x13`, `0x14`) are independently confirmed by their string names and code paths.
5. **MSR chain not proven.** The `0x24` `wrmsr(0x150)` path is an arbitrary `IA32_SYSENTER_ESP` write. It is HW-ONLY under the project scale. A chain to kernel memory corruption via a 32-bit SYSENTER stack pivot is plausible on 32-bit Windows but was not traced statically; it is not counted in the MW3 rating and is not a claim of exploitability.
6. **No exploit code / no PoC.** This report describes the primitive and the gate only. No IOCTL sequence, structure layout for a working write, or BYOVD instructions are included.
