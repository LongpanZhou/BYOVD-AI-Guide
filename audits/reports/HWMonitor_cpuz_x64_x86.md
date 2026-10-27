# Audit: HWMonitor-shipped CPUID `cpuz166` driver (x64 + x86)

| Field | Value |
|---|---|
| File(s) | `drivers/HWMonitor_cpuz_x64_72DA2127.sys` (PE32+ x86-64, 47,616 bytes)<br>`drivers/HWMonitor_cpuz_x86_BBEF6D8E.sys` (PE32 i386, 43,776 bytes) |
| SHA-256(s) | x64 `72DA21270B5295423104B971277334973033C39E4D85F574AC9E9740768049F6`<br>x86 `BBEF6D8E19B4E4BDC74C0469778CD4D3922128EAA88799712EC5731420CD72A6` |
| Analysis date | 2026-10-24 |
| Method | Static only. Local Ghidra 12.1.4 headless decompile plus `objdump` disassembly; read-only PE parsing for the SDDL, LUID and certificate table. Nothing loaded, installed, executed, or written to the registry. No web. |
| Reach tier | **R2** local administrator (effective DACL = Builtin Administrators + SYSTEM; open also calls `SeSinglePrivilegeCheck` for LUID 10, `SeLoadDriverPrivilege`) |
| Setup required | **service** (legacy driver; no devnode/INF; the memory primitives need no specific hardware) |
| Write quality | **W2** for the kernel pool OOB; **W3P** for the arbitrary physical write (conditional physical read); **W0** for the MSR/port/PCI/SMBus/MMIO-only paths |
| Verdict | **BLOCKED (static MW2)** - `reach=R2 setup=service write=W2 load=unsigned-as-stored`. Both corpus copies have no embedded Authenticode blob: the certificate table begins exactly at EOF. If a signed or catalog-trusted vendor copy of the same code is loaded, the static primitive is **MW2**. The x86 image is additionally not loadable on this x64 host. |
| HW-only | yes for MSR, port I/O, PCI config, SMBus/EC and fixed-window MMIO paths |

> Static-only audit. This report records gates and primitives. It contains no test code and no operating steps. Nothing was loaded or run.

**Provenance note.** These are the CPUID driver shipped inside HWMonitor, not the CPU-Z `cpuz_x64` builds already reported. Internal device name `\Device\cpuz166`; PDB paths `c:\cpuid2\cpuidsdk\driver\sys_cpuz_166\objfre_win7_amd64\amd64\cpuz166_x64.pdb` and `...\objfre_wxp_x86\i386\cpuz166_x32.pdb`; version resource CompanyName `CPUID`, OriginalFilename `cpuz.sys`, FileVersion `6.1.7600.16385`.

## 1. Internals

- **x64**: image base `0x10000`, entry `0x1e064` (`entry` -> `FUN_0001e008` CRT init -> `FUN_00011cf0`). Mapped blocks: `Headers`, `.text` `0x11000-0x185ff`, `.rdata`, `.data`, `.pdata`, `PAGE` (statically linked Wdmlib SDDL/device-create code), `INIT`, `.rsrc`, `.reloc`. 114 functions recovered; dispatcher `FUN_00011f30` at `0x11f30` is 21,368 bytes.
- **x86**: image base `0x10000`, entry `0x19b3e` -> `FUN_00016f90`. Dispatcher `FUN_000110a0` at `0x110a0` is 19,773 bytes. The same 55 IOCTL codes are present.
- Imports (both): `MmMapIoSpace`, `MmUnmapIoSpace`, `MmGetPhysicalAddress`, `MmAllocateContiguousMemorySpecifyCache`, `MmFreeContiguousMemory`, `IoCreateDevice`, `IoCreateSymbolicLink`, `SeSinglePrivilegeCheck`, `ZwSetSecurityObject`, `ObOpenObjectByPointer`, HAL bus-data and port-I/O routines. The x64 build inlines `in`/`out`; the x86 build imports `READ_PORT_*`/`WRITE_PORT_*`.
- `DriverUnload` (`FUN_00017a70` x64 / `FUN_00016ec0` x86) unmaps the 32-entry physical-map cache and deletes the symbolic link and device.
- Dispatch majors installed: `IRP_MJ_CREATE` (0), `IRP_MJ_CLOSE` (2), `IRP_MJ_DEVICE_CONTROL` (14). No `IRP_MJ_READ`/`IRP_MJ_WRITE`.

## 2. Entry / device / interface / effective DACL

- **Device creation (x64)** at `0x11e3d`:
  `WdmlibIoCreateDeviceSecure(DriverObject, 4, &"\Device\cpuz166", 0x9C40, 0x100 /*FILE_DEVICE_SECURE_OPEN*/, 1 /*Exclusive*/, &sddl, &classGuid, &devobj)`.
- **Device creation (x86)** at `0x1701d`: identical arguments, SDDL `UNICODE_STRING` at `0x18200`, class GUID at `0x17bb4`.
- **Effective SDDL** (read from the image, not inferred): `D:P(A;;GA;;;BA)(A;;GA;;;SY)` (27 wide chars, length 0x36).
  - `D:P` = protected DACL, no inherited ACEs.
  - `GA` = GENERIC_ALL to `BUILTIN\Administrators` (`BA`) and `NT AUTHORITY\SYSTEM` (`SY`).
  - No `Everyone`, `Authenticated Users`, `INTERACTIVE` or owner ACE.
- **Symbolic link**: `\DosDevices\CPUZ166`; on Vista+ (`PsGetVersion >= 5`) the code uses `\DosDevices\Global\CPUZ166` (`IoCreateSymbolicLink` at x64 `0x11e8d`, x86 `0x1706a`).
- **Open gate (verified)**: `IRP_MJ_CREATE` path at x64 `0x1747b` / x86 `0x16634` does
  `SeSinglePrivilegeCheck(&luid, TRUE)` with LUID `{LowPart=0xA, HighPart=0}` (x64 data at `0x19478`, x86 at `0x17bc4`). LUID 10 is `SeLoadDriverPrivilege`. Failure sets `STATUS_ACCESS_DENIED` (`0xC0000022`).
- **Effective reach**: the DACL admits only Administrators and SYSTEM; the create path additionally requires `SeLoadDriverPrivilege` to be enabled. An elevated administrator can satisfy both. Standard users cannot open the device. Reach is **R2**.
- **Exclusive** = 1: only one handle may be open at a time. This is a functional gate (HWMonitor's own service may hold the handle), not a security boundary.

## 3. Dispatch and IOCTL table

All 55 codes are `0x9C40xxxx` with:

- Device type `0x9C40`
- Access bits `(code >> 14) & 3 = 0` -> `FILE_ANY_ACCESS`
- Method bits `code & 3 = 0` -> `METHOD_BUFFERED`

Because all I/O is buffered, `Irp->AssociatedIrp.SystemBuffer` (x64 IRP+`0x18`, x86 IRP+`0x0C`) is the input and output buffer; the driver never uses `Type3InputBuffer`, `Irp->UserBuffer` or an MDL, and never calls `ProbeForRead`/`ProbeForWrite`.

`In min` / `Out min` below are the driver's own checks against `IO_STACK_LOCATION` `InputBufferLength` (x64 +`0x10`, x86 +`8`) and `OutputBufferLength` (x64 +`8`, x86 +`4`). `n` is a count read from the request.

| IOCTL | Out min | In min | Kernel action | Memory effect |
|---|---:|---:|---|---|
| `0x9C402400` | 4 | - | returns `0x166` | none |
| `0x9C402404` | 0xC | - | `PsGetVersion` -> 3 dwords | none |
| `0x9C402408` | 4 | - | returns open reference count | none |
| `0x9C402440` | 8 | 4 | `rdmsr(index)`, index whitelist | HW-only |
| `0x9C402444` | 8 | 0xC | `wrmsr(index,value)`, index whitelist (no LSTAR/GS base) | HW-only |
| `0x9C402448` | 8 | 8 | `wrmsr(0x150,value)` + read-back | HW-only |
| `0x9C40244C` | 0xC | 0x14 | config dword at caller offset & caller mask, `+0x5DA0`, map 0x10, write 2 dwords | physical write, config-anchored window |
| `0x9C402480/484/488` | 8 | 4 | port `in` byte / word / dword | HW-only |
| `0x9C4024C0/C4/C8` | 8 | 8 | port `out` byte / word / dword (blocks 0xCF8/CFC/CFF) | HW-only |
| `0x9C402540` | `n+4` | 0xC | physical read into `SystemBuffer+4`; PA whitelist (0xFEC70, 0xFED80E40, 0xFED80000+0x1000, 0xC0000/0xE0000/0xF0000 windows, 0xFFC00000 window, 0xFE000000) | read |
| `0x9C402544` | 8 | 0x10 | physical read at `config[0xF0] & 0xFFFFC000` + offset < 0x90000 | read |
| `0x9C402548` | 4 | 8 | physical read at `config[0xF0] & 0xFFFFC000` + offset < 0x8000 | read |
| `0x9C40254C` | 4 | 0xC | physical **write** 4 bytes at `config[0xF0] & 0xFFFFC000` + offset < 0x8000; value from input | physical write, BAR window |
| `0x9C402550` | 8 | 0xC | `MmMapIoSpace` of caller 64-bit PA, caller 32-bit length; 32-slot cache | arbitrary PA mapping |
| `0x9C402554` | 8 | 0xC | unmap exact PA/length from cache | unmap |
| `0x9C402560` | 4 | 0x14 | physical **write** 4 bytes at `config[caller offset] & caller mask` + offset < 0x90000 | physical write, config-anchored |
| `0x9C402564` | 8 | 8 | physical read 8 bytes at `config[0xD0/0xD4]` BAR + offset < 0x2FF000 | read |
| `0x9C402568` | 4 | 0xC | physical **write** 4 bytes at `config[0xD0/0xD4]` BAR + offset < 0x2FF000 | physical write, BAR window |
| `0x9C40256C` | 8 | 8 | physical read at `config[0x10]` BAR + offset < 0x8000 | read |
| `0x9C402584` | 4 | 0xC | PCI config RMW at 0x60/0xB8/0xC4 | HW-only |
| `0x9C402588` | 4 | 0x10 | PCI config write of two dwords | HW-only |
| `0x9C40258C` | 0x1C | 0x44 | CPUID-synchronised PCI config sequence (`FUN_00011470`) | HW-only |
| `0x9C402594` | 8 | 0x20 | `(config[caller offset] & ~0xF) + 4*input[2]`, map 0x40, write 3 dwords at unbounded indices | **arbitrary physical write (32-bit PA)** + OOB kernel-VA write |
| `0x9C402598` | 0x20 | 4 | SMBus/PMIC via `config[0x10]` BAR + 0x3000, write 0x1E520 | HW-only |
| `0x9C40259C` | `n+4` | 0x4C | physical read into `SystemBuffer+4` via config 0xD0/0xD4 base | read |
| `0x9C4025A0` | `n+4` | 0x28 | physical read into `SystemBuffer+4` + device register writes | read + physical write |
| `0x9C4025A4` | 8 | 0x14 | `FUN_00011750` device MMIO write (`base+0xA58`, `base+0xA18`) | HW-only |
| `0x9C4025A8` | **unchecked** | 0xC | contiguous alloc of `input[2]`, `MmGetPhysicalAddress`, program device, `memcpy(input[2])` to `SystemBuffer+4` | **kernel pool overflow** |
| `0x9C4025D4` | 8 | 0x10 | physical read via `FUN_00011B30` | read |
| `0x9C402600` | 8 | 8 | `rdmsr` + port timing | HW-only |
| `0x9C402604` | 8 | 8 | `MmMapIoSpace(caller PA, 0x200)`, read +0xF0/+0xF4 | read |
| `0x9C402608` | 8 | 4 | `rdmsr` timing | HW-only |
| `0x9C402640` | 0x10 | 8 | `MmMapIoSpace(input[1]+0x300, 0x100)`, write 3 dwords, restore | physical write, arbitrary PA base |
| `0x9C402644` | 0x10 | 4 | same as 0x9C402640 with `input[0]` | physical write, arbitrary PA base |
| `0x9C402648` | 0x10 | 4 | MSR 0x832/0x83E/0x838 timing | HW-only |
| `0x9C40264C` | 0x10 | - | MSR timing | HW-only |
| `0x9C402680` | 0x10 | 0x10 | SMBus via port I/O | HW-only |
| `0x9C402684` | 0x10 | 0x14 | SMBus via PCI config | HW-only |
| `0x9C402688` | 0x10 | 0xC | SMBus via port I/O | HW-only |
| `0x9C40268C` | 0x10 | 0x1C | SMBus via PCI config | HW-only |
| `0x9C402690` | 8 | 0x14 | SMBus via port I/O | HW-only |
| `0x9C402694` | 0x10 | 0xC | SMBus via fixed MMIO 0xFED80A00 | HW-only |
| `0x9C402698` | 8 | 0x10 | SMBus via fixed MMIO 0xFED80A00 | HW-only |
| `0x9C40269C` | 0x10 | 0x18 | SMBus via port I/O | HW-only |
| `0x9C4026A8` | 8 | 0x20 | PMIC via fixed MMIO 0xFEDC2000 + offset < 0x9000 | HW-only |
| `0x9C4026C0` | 0x10 | 0x10 | port writes to 0xB2/0x84 | HW-only |
| `0x9C402700` | `n+4` | 0x14 | `HalGetBusDataByOffset` into `SystemBuffer+4` | read |
| `0x9C402720` | 8 | 0x10 | PCI config dword read | read |
| `0x9C402728` | 8 | 0x14 | PCI config write after vendor/device whitelist | HW-only |
| `0x9C40272C` | 8 | 0x10 | PCI config read then write same value | HW-only (no-op) |
| `0x9C402740` | 0x10 | 4 | Super-I/O port writes | HW-only |

## 4. Access-control audit

- **Open**: DACL (BA+SY, GA) **and** `SeLoadDriverPrivilege` enabled. Both x64 and x86 use the same SDDL and LUID 10.
- **Per-IOCTL**: `SeSinglePrivilegeCheck` is repeated on `0x9C402540`, `0x9C4024C0/C4/C8`, `0x9C40259C`, `0x9C4025A0`, `0x9C4025A8` and `0x9C402728`. It adds no constraint because the open already required it.
- No `FILE_WRITE_ACCESS` check and no caller-identity check. Once an administrator has a handle, every IOCTL is callable.
- No `ProbeForWrite`/`ProbeForRead` and no MDL path; all buffer validation is the explicit `InputBufferLength`/`OutputBufferLength` checks in the table. The one missing output check is section 5.1.
- `Exclusive=1` means one handle at a time. If HWMonitor's service holds the device, an attacker must wait for release or use a separately loaded instance.

## 5. Memory-write trace

### 5.1 Kernel pool overflow - IOCTL `0x9C4025A8` (primary kernel-VA write)

x64 (`FUN_00011f30`):

- `0x13C0B` privilege check; `0x13C1C` `cmp dword ptr [rdi+0x10], 0xC` - **only `InputBufferLength >= 12` is checked**; `[rdi+8]` (`OutputBufferLength`) is never read.
- `0x13C33` `r12d = [r15+8]` = `input[2]` (`n`, the copy length and allocation size).
- `0x13C3E` `FUN_000116C0(input[0], input[1])` - AMD SMN-style config index/data gate. If it returns 0, status 1 and no allocation.
- `0x13C62` `MmAllocateContiguousMemorySpecifyCache(n, 0, 0xFFFFFFFF, 0, 0)` - 64-bit contiguous allocation; n is caller-controlled with no upper bound other than the allocation succeeding.
- `0x13C7C` `memset(buf, 0, n)` (`FUN_00017db0`, verified zero fill).
- `0x13CFD` `lea rcx, [r15+4]` and `0x13D01` `memcpy(SystemBuffer+4, buf, n)`.
- `0x13D30` `IoStatus.Information = n + 4`.

The SystemBuffer is allocated by the I/O manager with size `max(InputBufferLength, OutputBufferLength)` for `METHOD_BUFFERED`. A caller passing `InputBufferLength = 12`, `OutputBufferLength = 0` and `n` > 8 gets a 12-byte pool allocation and a write of `n` bytes starting at offset 4. The destination is the adjacent kernel pool, not the caller's buffer.

- **Target control**: constrained (adjacent pool; grooming-dependent).
- **Value control**: none - zero (the buffer is zeroed before the copy; a device DMA into the buffer between the PA programming and the copy could make it non-zero).
- **Size control**: arbitrary 32-bit, limited only by contiguous-allocation success.
- **Gate**: `FUN_000116C0` must return non-zero. It writes 0x13B102EC to PCI config 0x60/0xB8/0xC4 and requires the 0x64/0xBC/0xC8 read-back to be non-zero. On the AMD host this is the standard SMN index/data path and should succeed; on other platforms it is a soft gate.
- **x86**: same primitive at `0x12E57` (`cmp [edi+8], 0xC`; `edi` = `IRP+0x60` stack location), `0x12E6E` size, `0x12E73` `FUN_00010B50` gate, `0x12EA1` allocation, `0x12EB8` `_memset`, `0x12F4A` `FUN_00017240` memcpy to `[esi+4]` (`esi` = `IRP+0x0C` SystemBuffer), `0x12F52` `output[0] = n`, `0x12F61` `Information = n+4`.

This is a real kernel pool buffer overflow with a controlled length and a fixed zero value. It is **W2** and **MW2** as a static primitive.

Secondary arithmetic issue: `0x9C40259C` and `0x9C4025A0` compare `OutputBufferLength == n + 4` in 32-bit arithmetic. `n = 0xFFFFFFFC` wraps the check to 0 and passes with a small buffer; the subsequent `MmMapIoSpace(addr, n)` would have to map 4 GB before the copy loop runs. This is recorded but not rated (the mapping normally fails).

### 5.2 Arbitrary physical write (conditional read) - IOCTL `0x9C402594` (W3P)

The dispatcher (x64 `0x13E18`, x86 `0x130B3`) calls the helper `FUN_000118A0` (x64) / `FUN_00010CD0` (x86):

- `input[0]` = encoded bus/device/function.
- `input[1]` = PCI config offset. `HalGetBusDataByOffset(4, bus, devfn, &dword, input[1], 4)` reads **any** config dword; it must be non-zero.
- `input[2]` = base adjustment in dwords. The mapping base is
  `(config_dword & 0xFFFFFFF0) + 4 * input[2]` (32-bit arithmetic; x64 `0x1190E`, x86 helper).
  Because `input[2]` is a full 32-bit dword, the base can be any 4-byte-aligned 32-bit physical address; the config dword only has to be non-zero to pass the check.
- `0x1192B` `MmMapIoSpace(base, 0x40, MmNonCached)` (x64); the x86 helper is the same.
- `input[5]` (x64 `r10`) = status/zero index: `0x1199F` writes **0** at `map + 4*input[5]`.
- `input[4]` = optional value index: `0x119B5` writes `input[6]` at `map + 4*input[4]` when `input[6] != 0`.
- `input[3]` = value index: `0x119C0` writes `input[7]` at `map + 4*input[3]` unconditionally.
- No mask or bound is applied to the three indices (`4*input[3..5]`). For indices 0..15 these stay inside the 0x40 mapping and give an arbitrary physical write with a caller value. For larger indices the write is beyond the mapping in kernel VA space and usually faults (crash-first), so the reliable primitive is the physical write.
- After the writes the helper polls the status index and, if it reads 1, returns the dword at `input[4]` in `output[1]` (x64 `0x11A22`). With `input[6] = 0`, that is a conditional arbitrary physical read.

**Primitive**: write up to three 32-bit dwords (one zero, two caller values) to any 4-byte-aligned physical address below 4 GB, plus a conditional physical dword read. Target and value are caller-controlled; this is **W3P**, not a fixed/narrow mapping.

### 5.3 Fixed-value physical writes at an arbitrary PA - IOCTLs `0x9C402640` / `0x9C402644`

- x64 `0x9C402644`: `0x14AC7` `base = input[0] + 0x300`; `0x14AE3` `MmMapIoSpace(base, 0x100)`; writes `+0x20 = old & 0xFFFDFFFF`, `+0xE0 = 2`, `+0x80 = 0xFFFFFFFF`; measures; restores all three at the end.
- x64 `0x9C402640`: `0x14448` `base = input[1] + 0x300`; same map and writes (`0x144AC`, `0x144B0`, `0x144C0`), same restore.
- x86 `0x9C402644` at dump lines 2753-2790 and `0x9C402640` at 3822 use the same pattern.

**Primitive**: three 32-bit writes at `PA + 0x320`, `PA + 0x380`, `PA + 0x3E0`, with fixed/read-modify-write values, then restored. The base is a caller dword with no validation, so the target is an arbitrary 32-bit physical page. **W3P**, transient.

### 5.4 Narrow / BAR-relative physical writes

- `0x9C40254C` (x64 map `0x1312F`, write `0x13151`; x86 same case): base `config[0xF0] & 0xFFFFC000`, offset < 0x8000, 4-byte value. Device BAR window.
- `0x9C402560`: base `config[caller-selected offset] & caller mask`, offset < 0x90000, 4-byte value. Config-anchored; the config dword is not attacker-controlled.
- `0x9C402568`: base `config[0xD0/0xD4]` BAR, offset < 0x2FF000, 4-byte value.
- `0x9C40244C`: base `config[caller offset] & mask + 0x5DA0`, two dwords.
- `0x9C4025A0`: `FUN_000118A0` with a fixed config offset 0x24, base `(config[0x24] & ~0xF) + 0x90`; caller indices/values, same unbounded-index caveat as section 5.2 but a device-anchored base.
- `0x9C4025A4`: `FUN_00011750` maps `FUN_000116C0(...) + 0xA00` (0x80 bytes) and writes `+0x58`/`+0x18`.
- `0x9C402598`, `0x9C402694/698`, `0x9C4026A8`: fixed MMIO windows (0xFED80A00, 0xFEDC2000+offset) and SMBus/PMIC transactions.

These are hardware/MMIO windows, not arbitrary system-memory writes. They are listed so the table is complete; they do not raise the rating above the section 5.2 primitive.

### 5.5 Arbitrary physical mapping - IOCTLs `0x9C402550` / `0x9C402554`

- x64 `0x9C402550` at `0x135B5`: `MmMapIoSpace(PA, length, MmNonCached)` with a 64-bit PA (`input[0..1]`) and a 32-bit length (`input[2]`); no validation other than a free slot in the 32-entry table. Stores `{PA, VA, length}` at `0x135C0/0x135C3/0x135C7`.
- `0x9C402554` unmaps the exact `{PA, length}` entry when the caller repeats it.
- The mapping is **not** returned to the caller and there is no direct read/write-by-handle IOCTL. It becomes usable only if another IOCTL computes an address inside the cached range (`FUN_000110C0` lookup). That does not add a capability beyond section 5.2/section 5.3.
- `0x9C402604` maps a caller 32-bit PA for 0x200 bytes and reads `+0xF0`/`+0xF4` (read-only).

### 5.6 `MmGetPhysicalAddress`

Used only in `0x9C4025A8` (`0x13C84`) to obtain the PA of the freshly allocated contiguous buffer. The PA is written to device registers 0x15 (low) and 0x14 (high), with command 0x16, not returned to the caller. No physical-address leak to user mode.

### 5.7 Hardware-only paths

- `wrmsr` / `rdmsr`: `0x9C402440`, `444`, `448`, `600`, `608`, `648`, `64C`. The write whitelist covers 0x150, 0x186-0x188, 0x19A, 0x19C, 0x1B1, 0x38D, 0x38F and the 0xC00102xx/0xC001000x blocks. It does **not** include LSTAR (0xC0000082) or GS base, so no direct SMEP/SMAP or syscall-hook chain from this path.
- Port I/O: `0x9C402480/484/488`, `4C0/C4/C8`, `680/688/690/69C/6C0`, `740`. Arbitrary ports except 0xCF8/0xCFC/0xCFF.
- PCI config: `0x9C402584`, `588`, `58C`, `728`. Writes are limited to selected offsets and, for `0x9C402728`, a vendor/device whitelist.
- SMBus/EC/PMIC: `0x9C402598`, `680-69C`, `6A8`.
- Fixed-window MMIO: `0xFED80A00`, `0xFEDC2000+<0x9000`.
All of the above are **HW-ONLY** and are not counted as kernel memory writes.

### 5.8 Negative findings (important for the CPU-Z comparison)

- No IOCTL writes to a **caller-supplied kernel virtual address**. `0x9C402540`, `59C`, `5A0` write physical data into `SystemBuffer+4`, not into a pointer from the request. The CPU-Z MW1 "physical data copied to a caller-chosen kernel destination" primitive is **not present** in these HWMonitor builds.
- No `METHOD_NEITHER`, no raw user pointer, no `ProbeForWrite`, no MDL mapping, no `ZwMapViewOfSection`, no `MmMapLockedPagesSpecifyCache`.
- No kernel pointer or KASLR leak returned to the caller. The physical read at `0x9C402594` returns physical data, not a kernel VA; `0x9C4025A8` does not return its PA.
- The only kernel-VA write with a controllable copy length and a reachable destination is the section 5.1 pool overflow. The section 5.2 unbounded index is also a kernel-VA OOB write, but it is beyond the MmMapIoSpace mapping and crash-first.

## 6. Most dangerous exposed capability

**Arbitrary physical write (W3P) plus a controlled-length kernel pool overflow (W2).**

- `0x9C402594` gives a 32-bit physical write with caller value at any 4-byte-aligned address below 4 GB, plus a conditional physical read. This is a full physical-memory primitive, not a fixed or narrow mapping.
- `0x9C402640/644` give three fixed/read-modify-write dwords at an arbitrary 32-bit physical page (then restore).
- `0x9C4025A8` is the only direct kernel-VA corruption: a zero-fill pool overflow whose length is the caller's `input[2]`, with the destination `SystemBuffer+4` sized only by `max(InputBufferLength, OutputBufferLength)`.
- There is no arbitrary kernel-VA write, no caller-VA copy, and no kernel-address leak. That is why the static rating is **MW2**, not MW1.

## 7. Verdict

### Per-file table

| File | Arch | SHA-256 | Effective DACL / open gate | Static primitive | Write | Load status | Verdict |
|---|---|---|---|---|---|---|---|
| `HWMonitor_cpuz_x64_72DA2127.sys` | PE32+ x64 | `72DA21270B5295423104B971277334973033C39E4D85F574AC9E9740768049F6` | `D:P(A;;GA;;;BA)(A;;GA;;;SY)` + `SeLoadDriverPrivilege` | pool overflow at `0x9C4025A8`; arbitrary 32-bit physical write at `0x9C402594` (conditional read); fixed-value PA writes at `0x9C402640/644`; arbitrary PA map at `0x9C402550` | W2 kernel pool OOB; W3P physical | No embedded signature (cert table starts at EOF 0xBA00, 0x28B0 bytes absent); vendor catalog not in corpus | **BLOCKED as stored (static MW2)** |
| `HWMonitor_cpuz_x86_BBEF6D8E.sys` | PE32 i386 | `BBEF6D8E19B4E4BDC74C0469778CD4D3922128EAA88799712EC5731420CD72A6` | same SDDL and LUID 10 | same 55 IOCTLs and same primitives (overflow at `0x12E57`/`0x12F4A`; physical write at `0x130B3`) | W2 kernel pool OOB; W3P physical | No embedded signature (cert table starts at EOF 0xAB00, 0x28B0 bytes absent); **also not loadable on the x64 host** (32-bit kernel driver) | **BLOCKED as stored (static MW2)** |

### Overall verdict

**BLOCKED (static MW2)** - `reach=R2 setup=service write=W2 load=unsigned-as-stored`.

The block is a loadability/evidence problem, not a capability problem:

- The code is a genuine **MW2** static primitive (constrained kernel pool write) with an additional **W3P** arbitrary physical write path (and a conditional physical read).
- Both corpus files are signature-stripped: the certificate directory points at the first byte past EOF, so `Get-AuthenticodeSignature` reports `NotSigned` and the vendor signature cannot be verified from this corpus. If the original CPUID-signed or HWMonitor-cataloged copy of the same code is loaded, the static rating is **MW2** on x64. The x86 image cannot load on this x64 host regardless of signature.
- The driver is not in `known_bad_hashes.txt`.

## 8. Limitations

- Static only. No dynamic confirmation of the pool overflow, the `FUN_000116C0` gate, or the physical mapping; no driver was loaded.
- The corpus copies end exactly at the last section (`0xBA00`/`0xAB00`); the 0x28B0-byte certificate table is absent. The vendor's original signed/cataloged state could not be checked because the `.cat`/installer is not in the corpus.
- The `0x9C4025A8` overflow depends on `FUN_000116C0` returning a non-zero base. The host is AMD (Ryzen 5 3600X), where the SMN index/data path is expected to work, but this was not executed. On non-AMD platforms the config read-back may be zero and the overflow would not be reached.
- The arbitrary physical write at `0x9C402594` depends on `MmMapIoSpace` accepting the selected 32-bit PA. Non-RAM/MMIO holes fail and return a status; the report does not claim every address succeeds.
- Indices beyond the 0x40 mapping at `0x9C402594` are a kernel-VA OOB write but are crash-first; they are not rated as a reliable kernel write.
- Ghidra decompiler artifacts (x86 `stdcall` argument rendering, `_DAT_00000008`) were resolved against the disassembly for the key sites. The IOCTL table was enumerated from the recovered switch in both builds; function/line references are to the local dumps.
- No REA session was used (Ghidra headless only), so no REA evidence IDs are retained.
