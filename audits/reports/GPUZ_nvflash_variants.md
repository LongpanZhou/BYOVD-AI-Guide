# Audit: GPU-Z nvflash — x64 variant 2 and x86

| Field | Value |
|---|---|
| File(s) | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\GPUZ_nvflash_x64_variant2_8C2D9847.sys`<br>`C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\GPUZ_nvflash_x86_01BBA8E8.sys` |
| SHA-256(s) | `8C2D9847B70C3DC1AAC5D9E5330C67DEB86F369DCD3CA85845ADF2A001088DDE` (x64 variant 2, 48,848 bytes)<br>`01BBA8E8D0859F605D72DE7E0C015A2E96DAFCF856B37AD3EA7F8E187BE1B8FB` (x86, 39,104 bytes) |
| Analysis date | 2026-10-24 |
| Method | Static-only. Local **Ghidra 12.1.4 headless** decompiler (per-file projects, full-function dump), **llvm-objdump** linear disassembly, and a hand-written PE/import/resource parser. **REA was not used** — the shared REA bridge is at capacity (four concurrent audits); there are no REA evidence IDs in this report and no claim depends on REA. |
| Reach tier | **R3** — device DACL is R2 (local administrator); the write needs a physical NVIDIA/PLX/LSI PCI function with a mapped BAR0 |
| Setup required | **hardware** (service load + present PCI device) |
| Write quality | **W2** — constrained OOB kernel-VA write relative to an undisclosed mapping base |
| Verdict | **MW3** — reach=R3 setup=hardware write=W2 load=signed |

| File | Bits | Build (UTC) | CFG | Device / SDDL | IOCTLs | Primitive | Reach | Setup | Write | Verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| `GPUZ_nvflash_x64_variant2_8C2D9847.sys` | PE32+ AMD64 | 2024-10-15 06:25:11 (`0x670E0AC7`) | yes (`DllChar 0x4160`) | `\Device\NVFLASH`, `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | 9 + 2 unsupported | OOB write past `MmMapIoSpace` BAR, caller 32-bit offset | R2 DACL / R3 hardware | hardware | W2 | **MW3** |
| `GPUZ_nvflash_x86_01BBA8E8.sys` | PE32 i386 | 2024-10-15 06:25:53 (`0x670E0AF1`) | no (`DllChar 0x540`) | `\Device\NVFLASH`, `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | 9 + 2 unsupported | Same, 32-bit address arithmetic (wraps mod 2³²) | R2 DACL / R3 hardware | hardware | W2 | **MW3** |

Both files: NVIDIA Flash Driver 1.21.0, linker 14.37, Authenticode **Valid** (`CN=Microsoft Windows Hardware Compatibility Publisher`, Microsoft Third Party Component CA 2014, timestamped, leaf notAfter 2025-01-10), neither hash in `indexes\dedupe\known_bad_hashes.txt`. Static only; neither file was loaded, installed, or executed.

---

## 1 Internals

### 1.1 Binary shape

| | x64 variant 2 | x86 |
|---|---|---|
| Machine / magic | `0x8664` / PE32+ | `0x14C` / PE32 |
| Size | 48,848 | 39,104 |
| Image base | `0x140000000` | `0x400000` |
| `AddressOfEntryPoint` | `0x2C80` | `0x29F0` |
| Sections | `.text` `0x1000`–`0x3640`, `.rdata` `0x4000`–`0x4E40`, `.data` `0x5000`–`0x52B4`, `.pdata` `0x6000`, `PAGE` `0x7000`–`0x8C4F`, `INIT` `0x9000`–`0x9698`, `.rsrc` `0xA000`, `.reloc` `0xB000` | `.text` `0x1000`–`0x2D00`, `.rdata` `0x3000`–`0x337C`, `.data` `0x4000`–`0x41D0`, `PAGE` `0x5000`–`0x65D8`, `INIT` `0x7000`–`0x75AC`, `.rsrc` `0x8000`, `.reloc` `0x9000` |
| Subsystem / DllCharacteristics | `NATIVE` / `0x4160` (HIGH_ENTROPY_VA, DYNAMIC_BASE, NX, **GUARD_CF**) | `NATIVE` / `0x540` (DYNAMIC_BASE, NX, TERMINAL_SERVER_AWARE) |
| Version resource | `nvflash.sys` 1.21.0, "NVIDIA Flash Driver, Version 1.21.0", © 2017-2024 | same |

The x64 image is compiled with Control Flow Guard (guard thunks at `0x1400030A0`/`0x1400030E0`; every indirect call to a driver-supplied pointer goes through `__guard_dispatch_icall`). The x86 image has no CFG. CFG is the main code-generation difference between the x64 variant and the baseline (which is not CFG-enabled).

### 1.2 Imports (ntoskrnl.exe only)

Memory/IO: `MmMapIoSpace`, `MmUnmapIoSpace`, `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `IoBuildSynchronousFsdRequest`, `IofCallDriver`, `IofCompleteRequest`, `KeInitializeEvent`, `KeWaitForSingleObject`, `KeDelayExecutionThread`, `KeBugCheckEx`, `MmGetSystemRoutineAddress`.

Device/security: `IoCreateDevice`, `IoDeleteDevice`, `IoCreateSymbolicLink`, `IoDeleteSymbolicLink`, `ObOpenObjectByPointer`, `ZwSetSecurityObject`, `ZwClose`, `RtlCreateSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlAddAccessAllowedAce`, `RtlAbsoluteToSelfRelativeSD`, `RtlLengthSecurityDescriptor`, `RtlLengthSid`, `SeCaptureSecurityDescriptor`, `SeExports`, `IoDeviceObjectType`, plus the registry helpers used only by the statically linked Wdmlib shim (x64) / Wdmsec library (x86).

**Not imported in either file:** `ProbeForWrite`, `ProbeForRead`, `SeAccessCheck`, `SeSinglePrivilegeCheck`, `MmCopyMemory`, `MmGetPhysicalAddress`, `MmMapLockedPagesSpecifyCache`, `MmProbeAndLockPages`, `ZwMapViewOfSection`, `HalGetBusDataByOffset`, any `WRITE_PORT_*`/`READ_PORT_*`, `ZwWriteFile`. x86 adds only `memcpy`/`memset`.

Each file contains exactly **one** `MmMapIoSpace` call and **one** `MmUnmapIoSpace` call (x64 `0x140001FA4` / `0x140001B97`; x86 `0x401E15` / `0x4019A4`).

### 1.3 Runtime state (x64 variant 2; x86 equivalents in parentheses)

| Address | Meaning |
|---|---|
| `0x140005000` (`0x404004`) | `__security_cookie` |
| `0x140005288` (`0x4041B8`) | resolved `IoCreateDeviceSecure` (fallback `0x140007130` / `0x405076`) |
| `0x140005280` (`0x4041B0`) | resolved `IoValidateDeviceIoControlAccess` — stored, **never referenced** |
| `0x140005298` (`0x4041C0`) | `LIST_ENTRY` head of mapped-BAR contexts |
| `0x1400052A8` (`0x4041C8`) | one-byte `'LTVN'` pool sentinel = "driver active" |
| `0x1400052B0` (`0x4041CC`) | live context count |

Pool tag `0x4E76544C` = `'LTVN'`.

---

## 2 Baseline comparison (delta against `GPUZ_nvflash_x64.md`)

Baseline `drivers\GPUZ_nvflash_x64_79050454.sys` was verified on disk: SHA-256 `79050454D06AB7B6607BCA09386F704DF021C3C367CC0743DE6845301BB192AC`, 45,776 bytes, same linker, COFF `0x670E0B06` = 2024-10-15 06:26:14 UTC. It was imported into Ghidra only to compare code; the baseline verdict was **not** re-adjudicated.

| Property | Baseline | x64 variant 2 | x86 |
|---|---|---|---|
| Product / version | 1.21.0 | 1.21.0 | 1.21.0 |
| Build time (UTC) | 06:26:14 | 06:25:11 | 06:25:53 |
| CFG | no | **yes** | no |
| Device / SDDL | `\Device\NVFLASH`, same SDDL | identical | identical |
| IOCTL set | 9 implemented, 2 unsupported | identical | identical |
| Enumeration target | `\Device\NTPNP_PCI%04u` | identical | identical |
| `MmMapIoSpace` site | BAR0, size from vendor/class | identical | identical |
| OOB BAR write | unchecked 32-bit offset | identical | identical (32-bit add) |
| Record-copy loop | no entry-count bound | identical | identical |

**Two descriptive errors in the baseline report, confirmed against the baseline binary:**

1. §2.3 states the driver enumerates `\Device\Video%u`. The baseline does **not** contain that string or code path; it formats `\Device\NTPNP_PCI%04u` at `0x140001816` and opens PCI PDOs. Both variants do the same.
2. §3.2 describes `IOCTL 0x81DE002C` as a "GPU locate/match helper (reads config space, compares BDF/vendor, no output write)". In the baseline the case calls `FUN_140002470` (1,862 bytes) — a flash program/erase sequence (config-space capability walk, flash-controller register pokes, status polling up to 3,000 iterations). It writes nothing to the caller buffer, but it is not a locate/match helper. Variant 2's `FUN_1400024F0` (1,929 bytes) is the same routine.

Neither correction changes the baseline's core finding or its MW3 verdict; they are recorded so later work does not inherit the wrong model of the device surface.

**What actually differs in the variants:** CFG, +3,072 bytes total (+0x280 `.text`, +0x45C `.rdata`), a changed context pool flag (x64 baseline `0x200`, variant 2 `0x600`), and shifted addresses. No new IOCTL, no new device, no changed SDDL, no new memory primitive.

---

## 3 Entry / device / interface / effective DACL

### 3.1 DriverEntry

x64 `0x140002C80`, x86 `0x4029F0`:

1. `__security_init_cookie` (`0x140009000` / `0x407000`).
2. Single-load sentinel: if `[0x1400052A8]` is non-NULL, return `0xC0000001`; else `ExAllocatePoolWithTag(0x401, 1, 'LTVN')` (x64 `0x140002CB1`; x86 `0x402A24`).
3. Device name is assembled on the stack from split string literals (`\DosDevices\NVFL` + `ASH`, `\Device\NVFLASH`; x64 literals at `0x1400035C0`/`0x140003620`, same construction on x86) — `RtlInitUnicodeString` produces `\Device\NVFLASH`.
4. Device creation at x64 `0x140002D9A` → `FUN_14000708C` → `[0x140005288]`; x86 `0x402AD2` → `_WdmlibIoCreateDeviceSecure@36`. Arguments: `DeviceExtensionSize=0`, `DeviceType=0x81DE`, `DeviceCharacteristics=0`, **`Exclusive=1`**, `DefaultSDDLString` = x64 `0x140004298` / x86 `0x4030D8`, `DeviceClassGuid=NULL`.
5. Handlers: unload + `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_DEVICE_CONTROL` only (x64 `+0x68/0x70/0x80/0xE0`; x86 `+0x34/0x38/0x40/0x70`). No READ, WRITE, INTERNAL_DEVICE_CONTROL, PNP, POWER, or SYSTEM_CONTROL handler.
6. `\DosDevices\NVFLASH` symlink created; then the BAR-mapping routine runs.

### 3.2 Effective DACL — admin-only, protected

The SDDL is a real `UNICODE_STRING`, verified byte-for-byte in both files:

* x64: `UNICODE_STRING{Length=0x36, MaximumLength=0x38, Buffer=0x140004260}` at `0x140004298`; string at `0x140004260`.
* x86: `UNICODE_STRING{Length=0x36, MaximumLength=0x38, Buffer=0x4030E0}` at `0x4030D8`; string at `0x4030E0`.

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)
```

Protected DACL (`P`), exactly two `GENERIC_ALL` ACEs: `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`. No `Everyone`, `Authenticated Users`, `Users`, `INTERACTIVE`, or `RESTRICTED` ACE, and no inherited ACEs.

The descriptor is applied by the kernel's own `IoCreateDeviceSecure`, resolved at run time by `MmGetSystemRoutineAddress` (x64 `0x140007000`, x86 `0x405000`). If that export were missing, the statically linked Wdmlib/Wdmsec fallback parses the same SDDL (`SeSddlSecurityDescriptorFromSDDL`) and applies it with `ObOpenObjectByPointer` + `ZwSetSecurityObject`; both paths use the identical descriptor. `Exclusive=1` means one open handle at a time.

**Therefore: any process that can open `\\.\NVFLASH` reaches every IOCTL. With this DACL that is an elevated administrator or SYSTEM; a standard/filtered token is denied by the object manager. No further gate exists** (no `SeAccessCheck`, no `SeSinglePrivilegeCheck`, no `RequestorMode` test; `IoValidateDeviceIoControlAccess` is resolved at `0x140005280`/`0x4041B0` and never called).

### 3.3 PCI access interface (not a vendor-private miniport interface)

`FUN_140001940` (x86 `FUN_00401820`) allocates an 8-pointer interface block (0x40 bytes x64 / 0x20 bytes x86) and sends `IRP_MJ_PNP` / `IRP_MN_QUERY_INTERFACE` (`major 0x1B`, `minor 0x08`, `Parameters=0x10040`, x86 `0x10020`) for GUID `496B8280-6F25-11D0-BEAF-08002BE2092F` (`0x140004520` / `0x403158`) = **`GUID_PCI_BUS_INTERFACE_STANDARD`**.

So the callbacks at interface `+0x38` (read) and `+0x30` (write) are `pci.sys`'s `GetBusData`/`SetBusData` for PCI configuration space, not an NVIDIA display-miniport interface. Consequences:

* the driver works on any PCI function, independent of `nvlddmkm`;
* the "vendor-private IRP" wording in the baseline report is inaccurate;
* all writes through these callbacks are **PCI configuration space** (hardware), not kernel memory.

The query is sent to `IoGetAttachedDeviceReference(PDO)` after enumerating the PCI driver's device list, and the loop only considers device objects with `Flags & 0x1000` (`DO_BUS_ENUMERATED_DEVICE`).

### 3.4 BAR mapping

`FUN_140001BE0` (x86 `FUN_004019F0`):

1. Enumerate `\Device\NTPNP_PCI0000`…`\Device\NTPNP_PCIFFFE` (`0x140001826`, x86 `0x401731`), take the base PDO, enumerate that driver's device objects into a `'LTVN'` array.
2. Query `GUID_PCI_BUS_INTERFACE_STANDARD` on each attached device; read 0x100 bytes of config space (`fn38(ctx, 0, buf, 0, 0x100)`).
3. Vendor filter: accept `0x10DE` (NVIDIA, any class), `0x10B5` (PLX with subsystem vendor `0x10DE`, class `0x06/0x04`), `0x1000` (LSI with subsystem vendor `0x10DE`, class `0x06/0x04` or `0x01/0x07`).
4. Allocate a 0x48-byte context (`0x140001DF9`, x86 `0x401BF8`) with fields `+0x08` bus, `+0x0C` device, `+0x10` function, `+0x14` vendor, `+0x18` device ID, `+0x1C` physical BAR0 (qword), `+0x24` map size, `+0x28` mapped VA, `+0x30` interface, `+0x38` `LIST_ENTRY`.
5. Map size is selected by vendor/class only (`0x140001EBF`–`0x140001F0C`): NVIDIA `0x1000000` (16 MiB), or `0x2000000` if class `0x06`/subclass `0x80`; PLX `0x100000`; LSI `0x4000`. The actual BAR size is **not** read.
6. Enable PCI command bits 1/2 (memory space + bus master) via `SetBusData` (`0x140001F65`).
7. `MmMapIoSpace(BAR0_phys, map_size, MmNonCached)` at `0x140001FA4` (x86 `0x401E0D`–`0x401E15`), then store VA/size in the context.

**The physical address never comes from an IOCTL.** It is BAR0 from PCI config space of an enumerated NVIDIA/PLX/LSI device. Only devices with header type 0 or 1 (`(byte&0x7F)`, `0x140001F10`) and a non-zero BAR0 are mapped.

Note that the fixed 16/32 MiB size is not derived from the BAR: for an NVIDIA HDA function (also vendor `0x10DE`) whose BAR is far smaller than 16 MiB, the driver still maps 16 MiB starting at that BAR, i.e. beyond the real BAR range into adjacent physical MMIO/RAM.

---

## 4 Dispatch, IOCTL surface

`0x1400010B0` (x86 `0x401090`) is the only IOCTL handler:

```
ioStack      = Irp->Tail.Overlay.CurrentStackLocation   ; x64 Irp+0xB8, x86 Irp+0x60
InLength     = ioStack->Parameters.DeviceIoControl.InputBufferLength
OutLength    = ioStack->Parameters.DeviceIoControl.OutputBufferLength
code         = ioStack->Parameters.DeviceIoControl.IoControlCode
if ((code - 0x81DE0004) > 0x28) -> 0xC00000BB
```

Two-level jump table: byte selector at RVA `0x1688` (x86 `0x4015D0`), target RVAs at `0x1660` (x86 `0x4015A8`). All implemented codes are `CTL_CODE(DeviceType=0x81DE, Function=F, Access=0, Method=0)` → **`FILE_ANY_ACCESS` + `METHOD_BUFFERED`**. Every case checks `InputBufferLength == OutputBufferLength == exact size` before touching `Irp->AssociatedIrp.SystemBuffer` (`Irp+0x18` x64, `Irp+0x0C` x86); a size mismatch returns `0xC000000D`.

| IOCTL | F | In/Out | x64 handler | x86 handler | Kernel action |
|---|---|---|---|---|---|
| `0x81DE0004` | 1 | `0x218`/`0x218` | `0x140001117` | `0x4010D3` | BDF match; copy `count` dwords (`buf+0x14`, 1–128) from `mapped_VA + buf[0x10]` into `buf+0x18`. Block BAR read (x86 additionally rejects count 0 and guards `offset+4*count` overflow). |
| `0x81DE0008` | 2 | `0x1C`/`0x1C` | `0x1400011EE` | `0x40119F` | BDF match; read 1/2/4 bytes at `mapped_VA + buf[0x10]` into `buf+0x18`. Scalar BAR read. |
| `0x81DE000C` | 3 | `0x1C`/`0x1C` | `0x1400012C6` | `0x401258` | BDF match; **write 1/2/4 bytes of `buf+0x18` to `mapped_VA + buf[0x10]`**. Scalar BAR write — the primitive. |
| `0x81DE0010` | 4 | `0x1C`/`0x1C` | `0x140001398` | `0x401321` | `SetBusData(ctx, 0, buf+0x18, buf[0x10], buf[0x14])`; success iff return == `buf[0x14]`. Length unchecked. |
| `0x81DE0014` | 5 | `0x1C`/`0x1C` | `0x140001445` | `0x4013B9` | `GetBusData(ctx, 0, buf+0x14, buf[0x10], buf[0x18])`; success iff return == `buf[0x18]`. Length unchecked. |
| `0x81DE0018` | 6 | any | default `0x140001623` | default `0x40157E` | `STATUS_NOT_SUPPORTED` (`0xC00000BB`). |
| `0x81DE001C` | 7 | any | default | default | `STATUS_NOT_SUPPORTED`. |
| `0x81DE0020` | 8 | `4`/`4` | `0x1400014F3` | `0x401454` | Returns 4-byte version `{00,15,00,01}`. |
| `0x81DE0024` | 9 | `0x7E0`/`0x7E0` | `0x140001527` | `0x401487` | One 0x24-byte record per context: index, BDF, vendor/device ID, physical BAR, map size. **No entry-count bound.** |
| `0x81DE0028` | 10 | `4`/`4` | `0x1400015D7` | `0x401529` | Returns live context count. |
| `0x81DE002C` | 11 | `0x14`/`0x14` | `0x14000160C` → `FUN_1400024F0` | `0x401561` → `FUN_00402250` | Flash routine: config-space reads, flash-controller register writes via `SetBusData`/BAR, status polling. No output write. |

Input layout for BDF-selected codes (`0x1C` bytes): `+0x04` bus, `+0x08` device, `+0x0C` function, `+0x10` offset (u32, zero-extended), `+0x14` width `{1,2,4}` or block count `{1..128}`, `+0x18` value/result.

There is **no alignment check** on `offset` and **no check that `offset + width <= ctx+0x24` (map size)** anywhere in either binary.

---

## 5 Access-control audit

| Gate | Present | Detail |
|---|---|---|
| Device DACL | yes | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` applied via `IoCreateDeviceSecure`; admin/SYSTEM only |
| Exclusive open | yes | one handle at a time |
| Per-IOCTL access mask | no | every code is `FILE_ANY_ACCESS` |
| `IoValidateDeviceIoControlAccess` | resolved, **unused** | stored at `0x140005280` / `0x4041B0`, no xref |
| `SeAccessCheck` / `SeSinglePrivilegeCheck` | absent | not imported |
| `RequestorMode` test | absent | METHOD_BUFFERED system buffers only |
| Symbolic-link DACL | n/a | link has no SD; access resolves to the device object |

An administrator can satisfy every gate; a standard user cannot open the device. There is no additional handshake.

---

## 6 Memory-write trace

### 6.1 Primary: unchecked-offset write past the mapped BAR (`0x81DE000C`)

x64 path: case `0x1400012C6` → BDF match `0x14000130D`–`0x14000133C` → width dispatch `0x140001349` → store.

* `0x14000133C` `mov r8, [rdx-0x10]` — `r8` = `ctx+0x28` = **MmMapIoSpace kernel VA** (not caller-controlled, not disclosed).
* `0x14000135F`/`0x1371`/`0x1385` `mov ecx, [rsi+0x10]` — `ecx` = caller **offset**, a 32-bit load (upper 32 bits zeroed).
* `0x140001368` `mov [rcx+r8], eax` (dword), `0x14000137B` `mov [rcx+r8], ax` (word), `0x14000138F` `mov [rcx+r8], al` (byte).
* The context's map size at `ctx+0x24` (`[rdx-0x14]`) is **never loaded in this path**. No `cmp`, no `sub`, no bound.

x86 path: case `0x401258` → `0x4012CB` loads the VA into `edi` (with a two-dword null check), width dispatch `0x4012D9`, stores `0x4012F7` (dword), `0x401308` (word), `0x401317` (byte) as `mov [edi+ecx], …` with `ecx = [esi+0x10]`. No size comparison against `[edx-0x10]` (map size).

Caller control:

| Input | Control | Bound |
|---|---|---|
| Destination base | none (kernel-chosen `MmMapIoSpace` VA) | — |
| Offset | full 32-bit (`0`–`0xFFFFFFFC`) | **none** |
| Value | full 8/16/32-bit | — |
| Width | `{1,2,4}` | enforced |
| Device | BDF of any accepted PCI function | enumerated list |

Impact: offsets `< map_size` are ordinary GPU/device MMIO writes (the product's purpose). Offsets above the mapping produce a **kernel virtual-address write past the `MmMapIoSpace` region** — up to 4 GiB forward on x64; on x86 the 32-bit sum wraps modulo 2³², so the reachable set is the whole 32-bit address space. The base VA is not returned by any IOCTL (§4: the enumeration record returns physical BAR and size only), so the target cannot be aimed at a known object without a separate kernel-VA leak; a wrong guess raises `0x50`/`0x0A`. This is a genuine relative/OOB kernel memory-corruption primitive, not a write-what-where.

The same missing check applies to the reads (`0x81DE0004`, `0x81DE0008`): arbitrary-offset MMIO reads, and OOB reads past the mapping.

### 6.2 Secondary: pool overflow in the context dump (`0x81DE0024`)

`0x140001580`–`0x1400015D0` (x86 `0x4014D0`–`0x401523`) walks the context list and writes 9 dwords (0x24 bytes) per entry, advancing the destination by 0x24 **with no counter and no comparison against the 0x7E0-byte output buffer** (56 records fit exactly). With 57 or more live contexts the loop writes 36 bytes past the `METHOD_BUFFERED` system buffer into non-paged pool.

Reachability: contexts are one per accepted PCI function; the list is rebuilt from hardware each time it is empty. Exploiting this needs ≥57 NVIDIA/PLX/LSI PCI functions on one machine (the audit host has 2: RTX 3080 `10DE:2206` and NVIDIA HDA `10DE:1AEF`). Real defect, not a practical primitive here.

### 6.3 Secondary: caller-controlled length forwarded to `SetBusData`/`GetBusData`

`0x81DE0010` passes `buf[0x14]` as the length and `buf[0x10]` as the offset to `SetBusData`, with the data buffer at `SystemBuffer+0x18` — only 4 bytes remain in the 0x1C input buffer. `0x81DE0014` does the same with `buf[0x18]` into `SystemBuffer+0x14`. Neither length is validated by this driver. Whether `pci.sys` validates `Offset + Length` before touching the caller buffer is **outside this image and was not verified**; PCI configuration space is normally limited to 256 bytes (4 KiB extended), which would make the oversized calls fail before any copy. Treated as an unproven secondary path, not as the verdict driver.

### 6.4 Secondary: unsynchronised teardown/rebuild

Every case calls `FUN_140001BE0` when the list head is empty; that routine first calls `FUN_140001B10` (`0x140001B97` `MmUnmapIoSpace`), which frees every context and unmaps every BAR, then rebuilds. There is no lock, mutex, or critical section anywhere. Two threads issuing IOCTLs on the single handle while the list is empty can run the rebuild concurrently → double free / list corruption (the list-integrity checks bugcheck via `int 0x29` at `0x140001BDB` and `0x140002050`; x86 `0x4019DF`, `0x401EA6`). Requires an empty list (machine with no accepted device) plus a race; DoS/UAF, not a controlled write.

### 6.5 Not present

* No caller-supplied physical address reaches `MmMapIoSpace` (single call site, BAR0 from config space).
* No caller-supplied kernel pointer is dereferenced; all buffers are `METHOD_BUFFERED` system buffers with exact-length checks.
* No `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, MDL mapping, or user-pointer write.
* No port I/O, no MSR access, no DMA programming by this driver.
* No arbitrary call target: all indirect calls go through the PCI bus interface block (`+0x30`/`+0x38`) or CFG-guarded driver pointers.
* No kernel-VA disclosure (the record dump returns physical BAR + size, not `ctx+0x28`).

### 6.6 Flash routine (`0x81DE002C`)

`FUN_1400024F0` (x86 `FUN_00402250`) re-enumerates PCI devices, matches bus `buf+4`, reads 0x100 bytes of config space, walks capabilities, and programs flash-controller registers through `SetBusData` and the mapped BAR (`fn30`), polling a status bit up to 3,000 times. All buffers are fixed-size and all callback lengths are constants (0x100, 4, 2, 0x40); the count of accepted devices is bounded at 0x100 before indexing the three 256-entry stack arrays. It writes **nothing** to the caller buffer and performs no kernel memory write — it is a hardware flash-programming capability (HW-ONLY).

---

## 7 Most dangerous exposed capability

**Unchecked 32-bit offset write past a `MmMapIoSpace` BAR mapping, reachable by any holder of an admin-opened `\\.\NVFLASH` handle** (IOCTL `0x81DE000C`). Target base and value: base fixed by the kernel mapping, value fully caller-controlled, offset fully caller-controlled but relative to an undisclosed VA, width limited to 1/2/4 bytes. In-range access is intended device MMIO; out-of-range access is a kernel memory-corruption primitive that bugchecks on a bad guess.

Supporting facts that make it more than a paper defect: the device DACL is the only gate; the interface is plain PCI config space, so no NVIDIA display driver is needed; the driver maps every NVIDIA-vendor PCI function (including non-GPU functions) with a fixed 16/32 MiB size that can exceed the real BAR; and the OOB check is absent in both builds.

The secondary defects (unbounded record dump, unsynchronised rebuild, unchecked lengths to `pci.sys`) are real but need >56 devices, an empty-list race, or callee behaviour that could not be verified.

---

## 8 Verdict

| File | Reach | Setup | Write | Load | Verdict |
|---|---|---|---|---|---|
| `GPUZ_nvflash_x64_variant2_8C2D9847.sys` | R3 (admin-only DACL; NVIDIA/PLX/LSI PCI function required) | hardware | W2 | signed, CFG | **MW3** |
| `GPUZ_nvflash_x86_01BBA8E8.sys` | R3 (same) | hardware | W2 | signed; x86 image — only loadable on 32-bit Windows, not on this x64 host | **MW3** |

**Overall: MW3 — reach=R3 setup=hardware write=W2 load=signed.**

This matches the baseline verdict and for the same reason: the strongest admin-reachable primitive is a kernel-VA write whose base is chosen by `MmMapIoSpace` and never disclosed, with an unvalidated 32-bit offset — a real OOB kernel write, but relative and crash-first, not an arbitrary write. Neither variant is `BLOCKED` (both are validly WHQL-signed and not blocklisted), and neither is `NO-MEMORY-WRITE` (the write path exists and is reachable). The x86 image carries an additional platform constraint but is rated on the same static merits.

---

## 9 Limitations

* Static analysis only. Neither file was loaded, installed, executed, or used to create a service; no registry writes. No dynamic confirmation of mapping addresses, pool layout, or crash behaviour.
* **REA was not used** because the shared bridge already had four active audits. All evidence is from local Ghidra 12.1.4 headless, `llvm-objdump`, and the PE parser; function names are analyst-assigned (`FUN_*`), no PDB was available.
* Authenticode was checked statically with `Get-AuthenticodeSignature` (Valid, WHCP); revocation and catalog membership were not evaluated.
* The PCI bus interface callbacks (`GetBusData`/`SetBusData`) are Microsoft `pci.sys` code outside this image. Their internal bounds checking (and therefore the real impact of §6.3) was not analysed.
* BAR addresses and map sizes come from PCI configuration space; behaviour with a malicious or emulated PCI device (arbitrary BAR, arbitrary config space) was not modelled.
* The OOB write's practical exploitability depends on the system VA layout and on whether the mapping VA can be inferred or groomed; no VA leak exists in either binary, so the write was rated W2 rather than W1.
* The audit host has an NVIDIA RTX 3080 (`10DE:2206`) plus its HDA function (`10DE:1AEF`), so the hardware gate is satisfiable here; the two contexts are far below the 57 needed for §6.2.
