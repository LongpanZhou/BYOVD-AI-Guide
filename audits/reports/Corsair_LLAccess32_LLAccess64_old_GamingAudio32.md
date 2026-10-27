# Audit: Corsair LL Access x86 1.0.82, LL Access x64 1.0.74, Corsair Gaming Audio x86 2.4.2.0

| Field | Value |
|---|---|
| File(s) | `drivers\CorsairLLAccess32_1C0A82EC.sys` (x86, 1.0.82.0)<br>`drivers\CorsairLLAccess64_020ACBF0.sys` (x64, 1.0.74.0 - older build, not the audited 1.0.82 `E8BE57F7`)<br>`drivers\CorsairGamingAudio32_8F9E3B02.sys` (x86, 2.4.2.0) |
| SHA-256(s) | `1C0A82ECF65868720604DEF09843752A76DBFF9F49665CEAFE216E717C7FC7FF` (LLAccess32)<br>`020ACBF028C67C0936798AD7BA8436D0D58603912F5019A5E56898C2211CF056` (LLAccess64 1.0.74)<br>`8F9E3B022DCA93960E718473DA78F85053F0EFB279B9C54CCED7C2F16EDDE082` (GamingAudio32) |
| Analysis date | 2026-10-24 |
| Method | **Static-only.** PE/import parsing with a local parser + **llvm-objdump** disassembly + **Ghidra 12.1.4 headless** decompilation. No load, execution, service creation, registry write, or install. **REA was not used**: the shared REA bridge already had four active audits, so no REA cross-check or evidence IDs exist for this report. No web access. |
| Reach tier | **R3 overall** - R2 for both LL Access builds (default admin DACL + elevated-token create gate); R3 for GamingAudio32 (hardware-gated, effective interface DACL unresolved statically) |
| Setup required | **hardware overall** - `none` for both LL Access builds; `hardware` for GamingAudio32 |
| Write quality | **W2 overall** - W0 for both LL Access builds; W2 for GamingAudio32 (plus a W3 fixed-copy overflow) |
| Verdict | **MW3 overall** (worst case: GamingAudio32).<br>**CorsairLLAccess32: NO-MEMORY-WRITE (HW-ONLY)** - reach=R2 setup=none write=W0 load=signed.<br>**CorsairLLAccess64 1.0.74: NO-MEMORY-WRITE (HW-ONLY)** - reach=R2 setup=none write=W0 load=signed.<br>**CorsairGamingAudio32: MW3** - reach=R3 setup=hardware write=W2 load=signed (x86-only). |
| HW-only | Yes for both LL Access builds (SMBus/LPC/TCO port I/O, PCI config, fixed MMIO, firmware/PCI-derived physical mapping). No for GamingAudio32, which has genuine pool-overflow writes. |

> **x86 loadability caveat.** The two x86 images cannot be loaded on 64-bit Windows (there is no WOW64 kernel-driver path); they are valid WHCP-signed x86 images loadable only on 32-bit Windows or an x86 VM. All x86 conclusions below were derived from 32-bit instruction semantics and 32-bit structure layouts, not inferred from the x64 baselines. On the current x64 host, strict loadability would make both x86 files `BLOCKED`; the static MW/Write ratings describe a 32-bit Windows target.
>
> **Static only.** No driver was loaded, no IOCTL was issued, and no device was created. The effective DACLs marked NEEDS-DYNAMIC are inferred from the absence of a driver-supplied security descriptor, not measured.

---

## 0. Per-file result table

| File | Arch / version | Entry / device | Gate | Memory-write primitive | Write | Verdict |
|---|---|---|---|---|---|---|
| `CorsairLLAccess32_1C0A82EC.sys` | x86 / 1.0.82.0, valid WHCP signature | `\Device\<DriverName>` + `\DosDevices\<DriverName>`; `FILE_DEVICE_UNKNOWN`, `FILE_DEVICE_SECURE_OPEN`, no SD | I/O-manager default device DACL (SYSTEM/Administrators) + `TokenElevation` create gate | **None.** `MmMapIoSpace` + MDL + `MmMapLockedPagesSpecifyCache(UserMode)` yields a user R/W alias, but every PA is fixed or firmware/PCI-derived; no caller PA, no WRMSR, no waitable write | W0 | **NO-MEMORY-WRITE (HW-ONLY)** - R2/none, signed |
| `CorsairLLAccess64_020ACBF0.sys` | x64 / 1.0.74.0, valid WHCP signature | Same construction | Same | **None.** Same mapping core. **Material difference:** `0x229380` PCI config write has **no BDF allow-list** (1.0.82 restricts it to the enumerated SMBus controller) | W0 | **NO-MEMORY-WRITE (HW-ONLY)** - R2/none, signed |
| `CorsairGamingAudio32_8F9E3B02.sys` | x86 / 2.4.2.0, valid WHCP signature | Unnamed device + interface `{5403DC98-1385-48F3-B57F-BA46C39A5377}`; `IoCreateDevice` with no SD, Characteristics 0 | Default device DACL expected (admin); interface symlink DACL PnP/INF-derived, **unresolved**; **no privilege check** in `IRP_MJ_CREATE` | Double-fetch pool overflow at `0x2f4017`/`0x2f8013` (W2); fixed `0x24`-byte pool overflow at `0x226ee8` (W3) | W2 | **MW3** - R3/hardware, signed (x86-only) |

**Overall: MW3.** No MW1/MW2 primitive exists in these three files. The two LL Access builds are hardware-access drivers and do not write caller-chosen kernel memory. GamingAudio32 carries the same W2 double-fetch already reported for GamingAudio64, plus an additional fixed-size pool overflow that the GamingAudio64 baseline did not record.

---

## 1. Corsair LL Access - shared architecture (both LL Access files)

### 1.1 Internals and imports

Both LL Access binaries are compact WDM drivers that expose chipset hardware to a user-mode component. The import sets establish the capability boundary:

- **Memory mapping:** `MmMapIoSpace`, `MmUnmapIoSpace`, `IoAllocateMdl`, `IoFreeMdl`, `MmBuildMdlForNonPagedPool`, `MmMapLockedPagesSpecifyCache`, `MmUnmapLockedPages`.
- **Port I/O:** x86 build uses HAL `READ_PORT_UCHAR/USHORT/ULONG` and `WRITE_PORT_*` (`IAT 0x403000`-`0x403014`); x64 build uses inline `IN`/`OUT` intrinsics.
- **Fixed register access:** x86 `READ_REGISTER_*`/`WRITE_REGISTER_*`; x64 direct pointer reads/writes.
- **PCI config:** `HAL.dll!HalGetBusDataByOffset` and `HalSetBusDataByOffset`.
- **Access control:** `SeQueryInformationToken`, `IoGetRequestorProcessId`.
- **No memory-write helpers:** no `MmGetPhysicalAddress`, `MmCopyMemory`, `ZwMapViewOfSection`, `KeStackAttachProcess`, `MmCopyVirtualMemory`, or `MmProbeAndWrite`-style export.

A full `.text` disassembly contains exactly **one `rdmsr`** and **zero `wrmsr`** in each LL Access file:

| File | `rdmsr` | `wrmsr` |
|---|---:|---:|
| `CorsairLLAccess32_1C0A82EC.sys` | 1 at `0x401CEF` (fixed index `0xC0010058`) | 0 |
| `CorsairLLAccess64_020ACBF0.sys` | 1 at `0x140001DBD` (fixed index `0xC0010058`) | 0 |

(The raw byte scan that reports three `0F 30` hits is a false positive from multi-byte instruction encodings; the disassembly is authoritative.)

### 1.2 Device, effective DACL, and create gate

Both builds create the device with `IoCreateDevice` and **no security descriptor**:

- x86: `0x4022DF`, `IoCreateDevice(DriverObject, 0, &name, 0x22, 0x100, FALSE, &dev)`. `0x100` is `FILE_DEVICE_SECURE_OPEN`.
- x64: `0x140002319`, same arguments in the x64 calling convention (`r9d = 0x22`, `[rsp+0x20] = 0x100`, no SD).

There is no `IoCreateDeviceSecure`, no SDDL string, and no `RtlSetDaclSecurityDescriptor`/`ZwSetSecurityObject` in either import set. The effective object DACL is therefore the I/O manager's default device-object DACL: full control for `SYSTEM` and `BUILTIN\Administrators`, no `Everyone`/`Users` ACE. Because `FILE_DEVICE_SECURE_OPEN` is set, the DACL is also enforced on opens through the `\DosDevices\` symlink.

The device name is derived at runtime from `DriverObject->DriverName` (strip `\Driver\`, prefix `\Device\`/`\DosDevices\`), so the exact name depends on the service name used to load it; it is not a fixed attacker-known literal.

`IRP_MJ_CREATE` adds a token gate:

| Build | Address | Checks |
|---|---|---|
| x86 | `0x401220`-`0x4012F6` | `RequestorMode == UserMode` (`0x40122F`); `FileObject->FileName.Length == 0` (`0x401243`); `SecurityContext` and `AccessState` non-null (`0x401253`-`0x40125D`); `SeQueryInformationToken(TokenElevation=0x14)` at `0x401281`; elevation DWORD must be non-zero (`0x4012B5`); `SeQueryInformationToken(TokenIntegrityLevel=0x19)` at `0x4012A9` compared against `0x3000` (`0x4012BB`) |
| x64 1.0.74 | `0x1400010D0` | `RequestorMode == UserMode` (`0x1400010F3`); `FileName.Length == 0` at `+0x58` (`0x140001106`); `SecurityContext`/`AccessState`/client-or-primary token; `TokenElevation` (`0x14000114F`) must be non-zero; integrity value compared to `0x3000` (`0x14000118E`) |

The integrity comparison is the same defect as the audited 1.0.82 x64 baseline: it compares the first DWORD of the returned `TOKEN_MANDATORY_LABEL` (the low half of `Label.Sid`) to `0x3000`, not the integrity RID. That check therefore almost always passes; the effective gate is `TokenElevation != 0`, i.e. an **elevated administrator token**. Kernel-mode creates skip the block (`RequestorMode != UserMode`), but a user cannot issue one.

**Reach = R2 (elevated local administrator).** A standard user or a UAC-filtered administrator token is denied by the elevation check even if the DACL admits it.

### 1.3 Dispatch and IOCTL table

`IRP_MJ_DEVICE_CONTROL` dispatcher: x86 `0x401410`, x64 `0x1400012E0`. All codes are `METHOD_BUFFERED` and use `SystemBuffer` (`IRP+0x0C` on x86, `IRP+0x18` on x64). Unknown codes return `0xC0000002` (x86 `0x4014D7`) / `0xC0000002` (x64 `0x14000140D`).

| IOCTL | Access | Method | x86 handler | x64 1.0.74 handler | Kernel action |
|---|---|---|---|---|---|
| `0x225348` | READ | BUFFERED | `0x401D76` | `0x140001E30` | PCI config **read** - `{bus, dev, fn, offset, length}`; x64 1.0.74 does not validate `dev<0x20`, `fn<8`, `lengthin{1,2,4}`, or `offset+len<=0x100` (masks dev/fn instead) |
| `0x225358` | READ | BUFFERED | `0x401F26` | `0x140001FFC` | Port I/O **read**; `(port,size)` must lie inside a load-time allow-list entry |
| `0x22537C` | READ | BUFFERED | `0x401608` | inline (`0x100004A`) | Version query |
| `0x22538C` | READ | BUFFERED | `0x401CC0` | `0x140001DA4` | `RDMSR 0xC0010058` only; index is hard-coded |
| `0x225390` | READ | BUFFERED | `0x401E2E` (flag 0) | `0x140001F04` (flag 0) | Fixed MMIO read at PA `0xFED80300`, 4 bytes |
| `0x225394` | READ | BUFFERED | `0x40166A` | `0x140001600` | Scan `0xF0000`-`0xFFFFF`, parse SMBIOS 2.1/3, map the firmware-declared table address/length into the caller |
| `0x225398` | READ | BUFFERED | `0x40176E` + `0x4018B0` | `0x140001748` + `0x140001850` | Enumerate up to 64 PCI-derived physical pages, map each 0x1000, return user VAs |
| `0x22539C` | READ | BUFFERED | `0x40176E` + `0x4019A0` | `0x140001748` + `0x140001990` | Alternate enumeration, map each 0x1000 |
| `0x229354` | WRITE | BUFFERED | `0x401F26` (flag 1) | `0x140001FFC` (flag 1) | Port I/O **write**, same load-time allow-list |
| `0x229378` | WRITE | BUFFERED | `0x402018`/`0x40204C` | `0x140002080` | Release a mapping by user VA; unmaps MDL/IoSpace |
| `0x229380` | WRITE | BUFFERED | `0x4020B6` | `0x140002120` | PCI config **write**. x86/1.0.82 requires `(bus,dev,fn)` match a load-time SMBus-controller entry; **x64 1.0.74 has no such allow-list** |

The access bits are router-enforced: `0x229xxx` codes are `FILE_WRITE_ACCESS`; the rest are `FILE_READ_ACCESS`. There is no per-IOCTL privilege check beyond the create gate.

### 1.4 The `MmMapIoSpace` / MDL mapping trace

The shared mapping core is:

- x86 `FUN_00401A78` (`0x401A78`)
- x64 `FUN_140001AC0` (`0x140001AC0`)

Sequence (x86 addresses; x64 addresses in section 3):

1. `IoGetRequestorProcessId(IRP)` - x86 `0x401A97`; PID is the cache key.
2. List lookup under `KeWaitForSingleObject` (call to `FUN_00401594` at `0x401AC0`); a cache hit increments the refcount at `0x401AC9` and returns the cached **user VA** at `0x401ACC` (`0x401AC5`-`0x401ADA`).
3. `MmMapIoSpace(physLow, physHigh, size, MmNonCached)` - x86 `0x401AE8`; the cache-type zero is pushed at `0x401ADF`, size at `0x401AE0`, PA high at `0x401AE4`, PA low at `0x401AE7`. The physical address is a full 64-bit value on x86 (low/high dwords), so SMBIOS 3 addresses above 4 GB are representable.
4. `IoAllocateMdl(va, size, 0, 0, 0)` - x86 `0x401B00`.
5. `MmBuildMdlForNonPagedPool(mdl)` - x86 `0x401B25`.
6. `MmMapLockedPagesSpecifyCache(mdl, UserMode (1), MmNonCached (0), NULL, FALSE, DAT_0040401C | 0x20)` - x86 `0x401B45`; the push sequence is `0x401B36`-`0x401B44` (`push 1` at `0x401B42`). `DAT_0040401C` is `0x40000000` on Windows >= 6.2, so the priority carries `MdlMappingNoExecute`.
7. Return `(mapped & 0xFFFFF000) + MDL->ByteOffset` - x86 `0x401B4B`-`0x401B50`; x64 `0x140001BDB`-`0x140001BE4`.
8. Store the entry: x86 `+0x08` FileObject, `+0x0C` phys low, `+0x10` kernel VA, `+0x14` size, `+0x18` PID, `+0x1C` user VA, `+0x20` MDL, `+0x24` refcount (`0x401BF6`-`0x401C23`).

**What the caller receives is a user-mode read/write alias of a physical page, created by the kernel in the caller's process.** After the IOCTL returns, the caller reads/writes the physical page directly with no further kernel mediation.

**What the caller does *not* control is the physical address.** The three mapping paths are:

| IOCTL | PA source | Size source | Caller control |
|---|---|---|---|
| `0x225390` | hard-coded `0xFED80300` | 4 | none; read-only branch; the helper's write branch is unreachable |
| `0x225394` | SMBIOS entry point inside `0xF0000`-`0xFFFFF` (firmware) | firmware-declared, <= `0xFFFF` | none; requires firmware control to redirect |
| `0x225398`/`0x22539C` | PCI config reads + hard-coded offsets (`+0xF5000+n*0x100000` / `+0x98000+n*0x100000`) | 0x1000 per page, <= 64 pages | none; derived from the chipset/GPU configuration |

There is **no IOCTL that accepts a caller-supplied physical address** in either LL Access build. The mapping is a hardware/firmware access primitive, not a kernel-memory write-what-where.

### 1.5 Write analysis

- **`WRITE_REGISTER_UCHAR/USHORT/ULONG` (x86) / direct MMIO store (x64):** only in the fixed-MMIO helper (`0x401E2E` / `0x140001F04`). The dispatcher always passes the read flag `0` (`0x401477` / `0x14000137C`), and there is no other call site. The write branch (`0x401E9F`/`0x401EAD`/`0x401EBB` in the x86 helper) is dead code.
- **`WRITE_PORT_*` / `OUT`:** gated by the load-time allow-list (`DAT_00404318`, 16 entries max). The list is seeded only in `DriverEntry` (`0xCD6`, `0xCD7`, the SMBus BAR0 0x10-byte range, the TCO `0x17`-byte range). No IOCTL appends to it. Writes are hardware-only.
- **`HalSetBusDataByOffset`:** x86/1.0.82 allow-lists the SMBus BDF; x64/1.0.74 allows any BDF but remains PCI config space. Hardware-only.
- **No kernel virtual-address write sink:** no handler dereferences a user-supplied kernel pointer; all buffers are `METHOD_BUFFERED` `SystemBuffer`; every write is length-checked against `InputBufferLength`/`OutputBufferLength` (or is a fixed <= 0x12-byte output).

**LL Access verdict: NO-MEMORY-WRITE (HW-ONLY), W0.** The drivers give an elevated administrator SMBus/LPC/TCO port access, PCI config access, selected MMIO, and writable aliases of firmware/chipset physical pages. None of that is a kernel memory write.

**Residual latent path (not rated):** on a platform where the SMBIOS entry point is attacker-controlled (malicious or virtualized firmware), `0x225394` would map an arbitrary physical address/length into the admin process - a genuine physical-memory read/write. It requires firmware control, not merely a driver handle, and is recorded as `W3P`-conditional only.

---

## 2. `CorsairLLAccess32_1C0A82EC.sys` - x86 1.0.82 specifics

- **FILE / SHA-256:** 23,248 bytes; `1C0A82ECF65868720604DEF09843752A76DBFF9F49665CEAFE216E717C7FC7FF`; PE32 `i386`, image base `0x400000`, entry `0x405000` -> `DriverEntry 0x402190`; version 1.0.82.0, "Corsair LL Access", Corsair Memory, Inc.; WHCP-signed, `Get-AuthenticodeSignature = Valid`.
- **No SDDL/security-descriptor code:** import set contains no `IoCreateDeviceSecure`, `RtlCreateSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, or `ZwSetSecurityObject`; the only device creation is `IoCreateDevice` at `0x4022DF`.
- **x86-specific implementation details:** the 32-bit build uses HAL port intrinsics and `WRITE_REGISTER_*` rather than inline `IN`/`OUT`; the mapping core passes the physical address as low/high dwords; the cache key compares only the **low 32 bits** of the physical address (`FUN_00401CA0` at `0x401CA0` compares `+0x0C` and `+0x18`), so a >4 GB PA with the same low dword would alias an existing entry. All mapping PAs are firmware/PCI-derived, so this is a correctness/aliasing edge case, not a caller-controlled primitive.
- **IOCTL surface:** the same 11 codes as the x64 baseline, all `METHOD_BUFFERED`; dispatcher comparisons at `0x401437`-`0x4014D5`.
  - Port allow-list check `0x401F26`; PCI read `0x401D76`; PCI write with BDF allow-list `0x4020B6` (checks `bus/dev/fn` against `DAT_0040431C`, max 16 entries, and `lengthin{1,2,4}`, `offset+len<=0x100`).
  - SMBIOS `0x40166A` maps the firmware table via `0x401A78`; page-map `0x40176E` with enumerators `0x4018B0`/`0x4019A0` (64-iteration loops, output length checked as `count*8 <= OutputBufferLength`).
  - Fixed MMIO `0x401E2E` is only called with the read flag at `0x401477`; the write branch (`WRITE_REGISTER_ULONG/USHORT/UCHAR` at `0x401E9F`/`0x401EAD`/`0x401EBB`) is unreachable.
  - `RDMSR 0xC0010058` at `0x401CEF`.
- **Gate:** `0x401220`-`0x4012F6`, as in section 1.2. Effective: elevated administrator.
- **Difference from the audited 1.0.82 x64 baseline:** **none material.** The x86 build is the same 11-IOCTL design, same default-DACL/elevation gate, same fixed/firmware/PCI-derived PA set, same dead MMIO write branch, and no MSR write. It is not evidence that the x64 build has an x86-equivalent bug; it is the same hardware-access surface compiled for x86.
- **Verdict:** **NO-MEMORY-WRITE (HW-ONLY)** - reach=R2 setup=none write=W0 load=signed. On this x64 host: x86-only, not loadable.

---

## 3. `CorsairLLAccess64_020ACBF0.sys` - x64 1.0.74 specifics

- **FILE / SHA-256:** 23,616 bytes; `020ACBF028C67C0936798AD7BA8436D0D58603912F5019A5E56898C2211CF056`; PE32+ `x86-64`, image base `0x140000000`, entry `0x140006000` -> `DriverEntry 0x14000219C`; version **1.0.74.0**, "Corsair LL Access", Corsair Memory, Inc.; WHCP-signed, `Valid`.
- **Device/DACL/gate:** identical construction; `IoCreateDevice` at `0x140002319` with Characteristics `0x100`, no SD; create gate at `0x1400010D0` with the same `TokenElevation` requirement (`0x14000114F`) and the same defective integrity comparison (`0x14000118E`).
- **IOCTL surface:** the same 11 codes; dispatcher `0x1400012E0`. Version returns `0x100004A`.
- **Mapping core:** `FUN_140001AC0` (`0x140001AC0`):
  - `MmMapIoSpace` `0x140001B5A`
  - `IoAllocateMdl` `0x140001B82`
  - `MmBuildMdlForNonPagedPool` `0x140001BAE`
  - `MmMapLockedPagesSpecifyCache` `0x140001BD5`; `mov dl,1` at `0x140001BD0` = **UserMode**; `r8d=0` = `MmNonCached`; `r9d=0` = no requested address; `[rsp+0x20]=0` (BugCheckOnFailure); `[rsp+0x28]=DAT_140004044|0x20` = `MdlMappingNoExecute|NormalPagePriority`.
  - User VA = `MDL->ByteOffset (+0x2C) + (mapped & ~0xFFF)` at `0x140001BDB`-`0x140001BE4`.
  - Entry layout: `+0x10` FileObject, `+0x18` phys, `+0x20` kernel VA, `+0x28` size, `+0x2C` PID, `+0x30` user VA, `+0x38` MDL, `+0x40` refcount. Cache key `(phys, PID)` in `FUN_140001D90`.
- **Material difference from 1.0.82 - unrestricted PCI config write.** `0x229380` -> `FUN_140002120` (`0x140002120`):
  - Input: `{u32 bus, u32 dev, u32 fn, u32 offset, u32 length, u8 data[]}`; only checks `InputBufferLength >= 0x14` and `>= length + 0x14` (`0x140002130`-`0x140002141`).
  - Masks `dev & 0x1F`, `fn & 7` (`0x140002143`-`0x140002154`) instead of validating, and does **not** check `length in {1,2,4}` or `offset + length <= 0x100`.
  - Calls `HalSetBusDataByOffset(4, bus, (fn<<5)|dev, data, offset, length)` at `0x14000216E`.
  - This is an **arbitrary PCI configuration-space write** to any BDF the HAL can address, whereas 1.0.82 restricts the BDF to the enumerated SMBus controller. It is still **hardware-only** (`HW-ONLY`) and is not a kernel memory write.
  - The paired PCI read `FUN_140001E30` likewise has no `dev/fn/length` validation (masks only), so 1.0.74 is a broader PCI config read/write surface than 1.0.82.
- **Potential (unverified) PA-influence chain:** with arbitrary PCI config writes, an attacker could in principle reprogram a chipset/host-bridge register that the runtime enumerators (`0x140001850`/`0x140001990`) read when computing the MMIO base (`local_10 + 0xF5000 + n*0x100000` / `+0x98000 + ...`). If such a register is writable and controls the base, the enumerated physical addresses become attacker-influenced, and `0x225398`/`0x22539C` would map that PA read/write into user mode. This is a **physical-memory** effect (W3P at most), requires specific chipset semantics, and was **not** established statically; it is recorded as a residual path, not a verdict change.
- **No caller PA in any IOCTL:** confirmed across all 11 handlers; the mapping targets are the same fixed/firmware/PCI-derived set.
- **Verdict:** **NO-MEMORY-WRITE (HW-ONLY)** - reach=R2 setup=none write=W0 load=signed. The older build is **materially weaker as a hardware-access primitive** (unrestricted PCI config write/read), but it does not add a kernel memory-write primitive.

---

## 4. `CorsairGamingAudio32_8F9E3B02.sys` - x86 2.4.2.0

### 4.1 Internals

- **FILE / SHA-256:** 54,472 bytes; `8F9E3B022DCA93960E718473DA78F85053F0EFB279B9C54CCED7C2F16EDDE082`; PE32 `i386`, image base `0x400000`, entry `0x40C000` -> `DriverEntry 0x405C62`; version 2.4.2.0, "Corsair Gaming Headset drivers package", internal name `CorsairGamingAudio.sys`; WHCP-signed, `Valid`. PDB path in the image: `c:\jenkins\workspace\udio_Driver_unification-hotfixes\Output\Release\Win32\FilterDriver.pdb`.
- **Purpose:** a KS filter/function driver for a Corsair USB headset; it attaches to a lower device stack, registers a device interface, runs audio streaming/queueing, and exposes a set of private IOCTLs.
- **Memory imports:** `MmProbeAndLockPages`, `MmUnlockPages`, `MmMapLockedPagesSpecifyCache`, `IoAllocateMdl`, `IoFreeMdl`, `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `memcpy`, `memset`. **No** `MmMapIoSpace`, `MmGetPhysicalAddress`, `MmCopyMemory`, `ZwMapViewOfSection`, or `KeStackAttachProcess`.
- **Security imports:** `RtlCreateSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlCreateAcl`, `RtlAddAccessAllowedAce`, `RtlLengthSid`, `SecLookupWellKnownSid`, `ObSetSecurityObjectByPointer`.

### 4.2 Device, effective DACL, create handling

- `AddDevice` = `0x405710`; `IoCreateDevice(DriverObject, 0x6C0, NULL, 0x22, 0, FALSE, &dev)` at `0x405727`. The device is **unnamed**, has **no security descriptor**, and **does not set `FILE_DEVICE_SECURE_OPEN`**. It then calls `IoAttachDeviceToDeviceStack` (`0x40573E`) and `FUN_0040469A` at `0x405763`, which registers interface `{5403DC98-1385-48F3-B57F-BA46C39A5377}` and creates the named notification event.
- **The only DACL code is on the event, not the device.** `FUN_00404E64` (`0x404E64`) builds an ACL with `ALLOW CREATOR OWNER 0x101F0000` and `ALLOW Everyone SYNCHRONIZE 0x100000` and applies it via `ObSetSecurityObjectByPointer` (`0x404E64`). Its only caller is the named-event creation path `FUN_00401F5E` (`0x401F5E`) (`\BaseNamedObjects\...`). It never touches the device object or the interface symlink.
- **Effective DACL:** the device object receives the I/O manager default device-object DACL (SYSTEM/Administrators full, no `Everyone`). The **interface symlink DACL is created by PnP and is not derivable from the `.sys`**; the INF for this binary is not in the corpus (the only INF described in the Audio64 baseline is an APO extension package that does not bind that binary). Static reach is therefore **R2 (admin)**, with **R1 possible** if the deployed interface DACL is permissive - NEEDS-DYNAMIC. This is the same unresolved-DACL position as the GamingAudio64 baseline.
- **No privilege check.** `IRP_MJ_CREATE` (`FUN_00403638`, `0x403638`) allocates a per-open context (0x3F30 bytes, tag `'CRCF'` / `0x46435243`) and validates the requested file name against the KS category GUID `{146F1A80-4791-11D0-A5D6-28DB04C10000}` or the device interface GUID `{5403DC98-...}`. It does not call `SeAccessCheck`, `SeSinglePrivilegeCheck`, or `SeTokenIsAdmin`. Any opener that satisfies the DACL and uses the right name gets a context.

### 4.3 Dispatch and IOCTL table

`DriverEntry 0x405C62` fills the major table (all default to `0x405A10` pass-through) and overrides:

| Major | Offset | Handler |
|---|---|---|
| `IRP_MJ_CREATE` | `+0x38` | `0x405900` -> `0x405920` -> `FUN_00403638` |
| `IRP_MJ_CLOSE` | `+0x40` | `0x4058C0` -> `FUN_004034A6` |
| `IRP_MJ_READ` | `+0x44` | `0x405C30` -> `FUN_00403ECC` |
| `IRP_MJ_CLEANUP` | `+0x80` | `0x405850` |
| `IRP_MJ_POWER` | `+0x90` | `0x405B60` |
| `IRP_MJ_PNP` | `+0xA4` | `0x405A30` |
| `IRP_MJ_DEVICE_CONTROL` | `+0x70` | `0x405940` -> `0x405960` (switch) |

`IRP_MJ_DEVICE_CONTROL` switch `0x405960`:

| Code | Access / method | Handler | Action |
|---|---|---|---|
| `0x226ee0`-`0x22be80` (specific subcodes below) | ANY / BUFFERED (`(code>>14)&3 = 3`, `code&3 = 0`) | `FUN_00403C78` (`0x403C78`) | Control/version/name/channel-block queries |
| `0x2f0003` | READ / NEITHER | `FUN_00403C12` (`0x403C12`) | `KsPropertyHandler(IRP, 3, &PTR_DAT_0040A3F8)` |
| `0x2f001b` | READ / NEITHER | `FUN_00404182` (`0x404182`) | Caller-VA lock + 1/2/4/8-byte read + one-bit flag |
| `0x2f001f` | READ / NEITHER | inline | Returns `0xC0000010` |
| `0x2f4017` | READ / NEITHER | `FUN_004042F6` (`0x4042F6`) | `FUN_00402772(dir=0, lockOp=0)`; forward to lower device |
| `0x2f8013` | WRITE / NEITHER | `FUN_004043FA` (`0x4043FA`) | `FUN_00402772(dir=1, lockOp=2)`; forward to lower device |
| other | - | default | Increment `CurrentLocation`, `IofCallDriver` |

`0x226ee0`-range subcodes handled by `FUN_00403C78`:

| Subcode | Action | Bounds |
|---|---|---|
| `0x226ee0` | Copy fixed version string `L"2.4.2.0"` | length checked against `OutputBufferLength` |
| `0x226ee4` | Copy a device/KS name string obtained via `FUN_00402C9C` | string length checked against `OutputBufferLength` |
| `0x226ee8` | **Copy the 0x24-byte channel block from `device+0x190`** | **only `OutputBufferLength >= 4`; no comparison to the copy length - see section 4.5** |
| `0x226eec` | Write 8 bytes from `device+0xD4/+0xD8` | `OutputBufferLength > 7` |
| `0x226f0c` / `0x226f10` | Copy fixed driver strings via `FUN_0040545C` | `_wcsnlen`/length checked against `OutputBufferLength` |
| `0x226f3c` | `FUN_004030E6` | output length passed in |
| `0x226fa8` | Write 8 bytes from `device+0xF8/+0xFC` | `OutputBufferLength > 7` |

### 4.4 Primary finding - double-fetch pool overflow at `0x2f4017` / `0x2f8013`

This is the same primitive class as the GamingAudio64 baseline (which rated it W2/MW3), re-verified in x86 form.

**Path:** `IRP_MJ_DEVICE_CONTROL` -> `0x405960` -> `0x2f4017` (`0x4042F6`) or `0x2f8013` (`0x4043FA`) -> `FUN_00402772` (`0x402772`).

**Preconditions:** a successful `IRP_MJ_CREATE` with the right file name (per-open context at `device+0x130`, looked up by `FUN_00402EAC`); `0x2f4017` needs `FILE_READ_ACCESS`, `0x2f8013` needs `FILE_WRITE_ACCESS`; both are `METHOD_NEITHER`, so the buffer pointer is the caller's user VA (`IRP->UserBuffer` for direction 0, `Type3InputBuffer` for direction 1) and the length is `OutputBufferLength` (direction 0) or `InputBufferLength` (direction 1).

**`FUN_00402772` (`0x402772`) behavior:**

1. `FUN_0040113A` (`0x40113A`) locks the IRP buffer. For `METHOD_NEITHER`, `IRP->Flags` does not have `IRP_BUFFERED_IO`; the code uses `IRP->UserBuffer` (`IRP+0x3C`) or `Type3InputBuffer` (`stack+0x10`). `FUN_0040113A` saves `IRP->RequestorMode` (`IRP+0x20`) and `FUN_00401054` calls `MmProbeAndLockPages(mdl, RequestorMode, Operation)` at `0x4010A4`, then `MmMapLockedPagesSpecifyCache(mdl, KernelMode (0), MmCached (1), NULL, FALSE, 0x40000020)` at `0x4010F4` (AccessMode pushed at `0x4010F2`, cache type at `0x4010F0`, priority at `0x4010ED`). The user pages are mapped into kernel VA; the user's own mapping remains writable.
2. **Pass 1** (`0x4027DC`-`0x402804`): walks the buffer as variable-size entries. Each entry size is `*piVar3` (`0x4027F4`), the cursor advances by that size (`0x4027F6`), and the cumulative size (`[ebp-8]`) is compared to the cached buffer length (`[ebp-4]`). The entry count is stored in `param_1[0]` at `0x4027FF`. A zero-size entry does not advance the sum -> infinite loop (DoS, no race needed).
3. If `count <= 1`, the single-entry path at `0x4028D4` locks one entry into the in-structure holder at `param_1+0x34`; no arrays, no overflow.
4. If `count >= 2` (`0x402814`):
   - `ExAllocatePoolWithTag(poolType, count << 2, 'CASH')` at `0x402822`/`0x40282C` -> `param_1[2]`.
   - `ExAllocatePoolWithTag(poolType, count * 0x28, 'CASM')` at `0x40283D`/`0x40284C` -> `param_1[0x17]` (via `FUN_0040453A` at `0x402859`).
   - `FUN_0040453A` (`0x40453A`) zeroes `count` holders at 0x28 stride.
5. **Pass 2** (`0x40286A`-`0x4028C4`): walks the **same user buffer again**. It re-reads each entry size at `0x4028AE` and advances the cursor (`0x4028B5`). For each iteration:
   - writes a 4-byte DWORD to `arr1 + runningOffset` at `0x402883` (`mov [edx+eax], ecx`) - the value is the entry's `+0x20` (direction 0) or `+0x24` (direction 1) field, caller-chosen;
   - calls `FUN_004011D0` at `0x4028A5` with `arr2 + runningOffset` (0x28 stride), the entry's `+0x28` VA, the entry length, `RequestorMode`, and the lock operation; this fills a 0x28-byte holder with the caller VA, length, MDL, mapped VA, and flags;
   - `runningOffset += 0x28` (`0x4028B7`), `runningOffset1 += 4` (`0x4028BB`), and the loop condition is only `cumulativeSize < bufferLength` (`0x4028C1`).
   **Nothing compares the pass-2 index to `param_1[0]` (the pass-1 count).**

If the user changes the entry sizes between pass 1 and pass 2 (a second thread rewriting the same user buffer), pass 2 can run more iterations than pass 1 counted. The code then writes:
- a caller-chosen DWORD at `arr1 + 4*k`, and
- a 0x28-byte holder at `arr2 + 0x28*k` containing caller-chosen VA/length plus kernel-generated MDL/mapped-VA pointers,

past the end of both `NonPagedPoolNx` allocations (`DAT_0040b118 = 0x200` on Windows >= 6.2, set in `DriverEntry` at `0x405CA9`).

**Classification:** pool buffer overflow in `NonPagedPoolNx`, with a sequential index, caller-chosen DWORD and VA/length values, kernel pointer disclosure in the holder, and race-gated trigger. Under `SEVERITY.md` this is **W2**; with the hardware-gated device it is **MW3** (same as the GamingAudio64 baseline).

**32-bit-specific notes:**

- The holder is 0x28 bytes (vs 0x40 on x64), the first array is `count*4`, and the second is `count*0x28`. The overflow geometry differs but the primitive is the same.
- The allocation arithmetic is 32-bit: `count << 2` and `count * 0x28` can wrap for counts above ~1.07e9 / ~1.07e8 respectively. `FUN_0040453A` then zeroes `count` holders regardless of the (wrapped) allocation size, which would be a non-race overflow. Reaching the threshold requires a buffer with >10^8 one-byte entries and makes the zeroing loop write gigabytes - crash-first, not a usable primitive. Recorded as a 32-bit arithmetic caveat, not the primary path.
- `FUN_0040113A` correctly reads the x86 `IRP->RequestorMode` at `+0x20` and `IRP->Flags` at `+0x08`; this is not a mode-confusion bug. The x86 IRP layout was verified from the code (`IoStatus` at `+0x18`, `CurrentStackLocation` at `+0x60`, `UserBuffer` at `+0x3C`) and matches the 32-bit ABI.

### 4.5 Additional finding - fixed 0x24-byte pool overflow at `0x226ee8`

`FUN_00403C78` (`0x403C78`) handles the `0x226ee0` range as `METHOD_BUFFERED`, using `IRP->AssociatedIrp.SystemBuffer` (`IRP+0x0C`).

`0x226ee8` path (`0x403D2B`-`0x403D58`):

1. `eax = *(device + 0x190)` - the channel block allocated at AddDevice. If null -> `0xC000009A`.
2. `ebx = *(u32*)eax` - the block's first DWORD, which is its own size.
3. The only length check is `OutputBufferLength >= 4` (`cmp [ebp-4], 4` at `0x403D3E`; earlier the range-wide check at `0x403CB5` also only requires `>= 4`).
4. `memcpy(SystemBuffer, block, ebx)` at `0x403D50`.

The block is allocated in `FUN_0040456A` (`0x40456A`): `FUN_004062CA` returns a fixed channel count of **2** (`0x4062CA`: `*param_1 = 2`), and `0x404628` computes `lea eax, [4*ecx + 0x1C]` = **0x24**; `ExAllocatePoolWithTag(0x40B118, 0x24, 'CAMS' / 0x534D4143)` at `0x404639`, stored at `device+0x190` at `0x404641`; `memset(..., 0x1C)` at `0x404667`; the two channel values are written at `+0x1C/+0x20`. The overflow bytes past a 4-byte SystemBuffer are the seven zero DWORDs and the two channel descriptors (from `DAT_0040B004`, values `3` and `0x63F`).

**Consequence:** a caller who opens the device and sends `0x226ee8` with `InputBufferLength = OutputBufferLength = 4` gets a 4-byte system buffer and a **0x24-byte write** - a 0x20-byte fixed-content pool overflow. The content is driver-controlled (mostly zeros and two small channel IDs), the length is fixed at 0x24, and the target is adjacent pool. This is **W3** (narrow/fixed), **MW4-class** on its own; it does not change the overall MW3 driven by the W2 double fetch.

**Baseline gap:** the GamingAudio64 baseline (`corsair_audio64.admin.static.md`) recorded the `0x226ee0` range as "no lock or copy" and did not list this copy. A cross-check decompile of the x64 baseline binary at `FUN_1400046C8` (not a re-audit) shows the same pattern: `puVar5 = param_1[0x58]; uVar11 = *puVar5; if (3 < OutputBufferLength) FUN_140009500(SystemBuffer, puVar5, *puVar5);` - the same missing length comparison. The x64 report therefore appears to have missed this path; the 32-bit finding is not a 32-bit-only regression.

### 4.6 `0x2f001b` - kernel-VA lock and one-bit read (no write)

`FUN_00404182` (`0x404182`):

- Looks up the per-open context (`FUN_00402EAC(device+0x130, FileObject, 1)`).
- Calls `FUN_004011D0(local_34, Type3InputBuffer, InputBufferLength, 0, 0)` at `0x4041F2`-`0x4041FF`. `AccessMode = 0` = **KernelMode**, so `MmProbeAndLockPages` does not probe a user range; a caller-chosen **kernel VA** is accepted if the pages are valid.
- If the locked length is 1/2/4/8, reads that many bytes (`0x404225`-`0x40426A`) and calls `FUN_004066E4(context, value)` at `0x404277`, which stores `context+0x3F0C = (value == 0)` (`0x4066E4`).
- No write to the locked VA; the only sink is the one-bit flag.

**Classification:** a one-bit kernel-VA read oracle (zero/non-zero) with no write. The x64 baseline reported a KS-property getter for the flag (`FUN_140001270`); in this 32-bit build no reader of `context+0x3F0C` was found in the decompiled image, so the exfiltration path is **unconfirmed** (NEEDS-DYNAMIC). Either way it is `NO-MEMORY-WRITE` for this branch and only DoS-relevant if the probe raises.

### 4.7 Other paths checked

- `IRP_MJ_READ` `FUN_00403ECC` (`0x403ECC`): requires `OutputBufferLength >= 0x80`; the queue-to-user copy is `FUN_00404C7E` (`0x404C7E`), whose `memcpy` calls at `0x404D0D` and `0x404D85` are bounded by the `OutputBufferLength` comparisons at `0x404CE7`/`0x404CEB`/`0x404D00` and `0x404D5A`/`0x404D68`. No caller-chosen kernel destination.
- `FUN_00406858` (`0x406858`, registry value read): allocates `valueNameLen + *param_4 + 0x18`, queries, then checks `*param_4 >= returnedLength` before the `memcpy` in that function. Bounded.
- `FUN_0040545C` (`0x40545C`) copies a driver-owned string into `SystemBuffer` after `_wcsnlen(...,0x100) <= OutputBufferLength`; the string length is the bound, not 0x100. Safe.
- `0x226ee0` / `0x226ee4` / `0x226eec` / `0x226f0c` / `0x226f10` / `0x226f3c` / `0x226fa8`: fixed or length-checked copies; no unbounded caller-controlled write found.
- `KsPropertyHandler` (`0x403C12`) and the KS property sets were not exhaustively re-traced; the visible sinks are bounded copies and a registry write (`ZwSetValueKey` via the x64 baseline's `FUN_140007F04` analogue), not a caller-chosen kernel destination.
- No `MmMapIoSpace`, no physical-address mapping, no `ZwMapViewOfSection`, no MSR access.

**Verdict:** **MW3** - reach=R3 setup=hardware write=W2 load=signed (x86-only; R2 if the device DACL is the default admin DACL, R1 if the PnP interface DACL is permissive). The W2 double-fetch is the strongest primitive; the W3 fixed copy is an additional MW4-class overflow.

---

## 5. Baseline comparison - what differs materially

| Pair | Difference | Material? |
|---|---|---|
| LLAccess32 1.0.82 vs LLAccess64 1.0.82 (`E8BE57F7`) | Same 11 IOCTLs, same default-DACL + `TokenElevation` gate, same fixed/firmware/PCI-derived PA set, same dead MMIO write branch, no WRMSR. x86 uses HAL port intrinsics and 32-bit PA low/high pairs; cache key compares only the PA low dword. | **No.** Same `NO-MEMORY-WRITE (HW-ONLY)` verdict. x86-only load is the only practical difference. |
| LLAccess64 1.0.74 vs LLAccess64 1.0.82 | **`0x229380` PCI config write loses the BDF allow-list** and the `dev/fn/length/offset` validation; PCI read likewise lacks validation. Mapping core is otherwise the same (UserMode alias, `MdlMappingNoExecute`). | **Yes, for hardware access** (arbitrary PCI config R/W vs SMBus-only). **No** for kernel memory write: still `HW-ONLY`, W0. A speculative PCI-config -> enumeration-base -> PA chain is recorded but unverified. |
| GamingAudio32 2.4.2.0 vs GamingAudio64 2.4.2.0 (`64D31B6E`) | Same double-fetch (`0x2f4017`/`0x2f8013`) with 0x28-byte holders instead of 0x40; same `0x226ee8` unchecked 0x24-byte copy; same `0x2f001b` KernelMode lock/read oracle; same unnamed device with no SD/`SECURE_OPEN`; 32-bit allocation arithmetic can wrap at high counts. | **No** for the double-fetch tier (both MW3/W2). **Yes, a baseline gap:** the GamingAudio64 report did not record the `0x226ee8` fixed overflow; the 32-bit file has it and the x64 binary shows the same code pattern. The x86-only load constraint is new. |

**Baseline gap note:** the GamingAudio64 report's IOCTL-table row for `0x226ee0`-`0x22be80` says "No lock or copy" and its memory-write table describes the `0x226ee0`-range copies as fixed version strings. The `0x226ee8` channel-block copy is a real, length-unchecked `memcpy` in both builds; it is reported here for the 32-bit file and flagged for the x64 baseline owner. No other baseline contradiction was found.

---

## 6. Verdicts

### 6.1 Per file

| File | Reach | Setup | Write | Severity | Rationale |
|---|---|---|---|---|---|
| `CorsairLLAccess32_1C0A82EC.sys` | R2 | none | W0 | **NO-MEMORY-WRITE (HW-ONLY)** | Hardware-access driver: SMBus/LPC/TCO port I/O (allow-listed), PCI config R/W, fixed MMIO read, fixed `RDMSR`, firmware/PCI-derived physical pages mapped read/write into the caller. No caller PA, no WRMSR, no kernel-VA write. |
| `CorsairLLAccess64_020ACBF0.sys` | R2 | none | W0 | **NO-MEMORY-WRITE (HW-ONLY)** | Same, plus **unrestricted PCI config write/read** (1.0.74 regression vs 1.0.82). Still hardware-only. |
| `CorsairGamingAudio32_8F9E3B02.sys` | R3 (R2 default DACL; R1 if interface DACL permissive) | hardware | W2 | **MW3** | W2 double-fetch pool overflow at `0x2f4017`/`0x2f8013` (caller-chosen DWORD/VA/length into `NonPagedPoolNx`, race-gated, hardware-gated); plus W3 fixed 0x24-byte overflow at `0x226ee8`. |

### 6.2 Overall

**MW3 - reach=R3 setup=hardware write=W2 load=signed.**

- **No MW1 or MW2** exists in these three files. The LL Access pair is `NO-MEMORY-WRITE (HW-ONLY)`; its strongest capability is an elevated administrator's hardware/firmware access, not a kernel memory write.
- **GamingAudio32** carries the same W2 double-fetch already accepted for GamingAudio64 (MW3) and an additional W3 fixed-copy overflow. The statically unresolved DACL and the hardware dependency keep it at MW3, not MW2.
- **Applied to the current x64 host:** both x86 images are not loadable (32-bit kernel only). Strictly applying the loadability rule would mark them `BLOCKED` on this host; the static verdicts above describe a 32-bit Windows target. The x64 1.0.74 image is loadable and remains `NO-MEMORY-WRITE (HW-ONLY)`.

---

## 7. Limitations

1. **Static only.** No driver was loaded, no device was created, no IOCTL was issued, no service/registry change was made, and no code was executed. DACLs, pool layout, and race timing are inferred, not measured.
2. **REA not used.** The shared REA bridge was at its four-audit capacity; this audit used only local Ghidra 12.1.4 headless, llvm-objdump, and a local PE/import parser. No REA evidence IDs exist for these three files, so there is no independent cross-check of the decompiler output.
3. **Effective DACLs.** The LL Access default admin DACL is proven only by the absence of a driver-supplied SD; the exact ACEs are the documented I/O-manager default. GamingAudio32's interface-symlink DACL is set by PnP/INF and was **not** determined; the INF is not in the corpus. The x64 baseline's `NEEDS-DYNAMIC` for the same point still applies.
4. **GamingAudio32 setup.** The Audio64 baseline's supplied INF is an APO extension package that does not bind that `.sys`; no INF for the Audio32 binary is in the corpus, and the binding INF/hardware IDs are not available. `Setup: hardware` is inferred from `AddDevice`/`IoAttachDeviceToDeviceStack`, not from a verified binding.
5. **Double-fetch race.** The pass-2 overflow is established from the code (`0x40286A`-`0x4028C4` has no count comparison), but the race, pool adjacency, and exploitability were not executed. Pool layout and the adjacent object type are not controlled statically.
6. **32-bit arithmetic.** The `count<<2`/`count*0x28` wrap at high counts is a theoretical non-race overflow; reaching it requires >10^8 entries and produces a crash-first multi-gigabyte zeroing loop. It was not tested and is not counted in the verdict.
7. **`0x2f001b` exfiltration.** The one-bit flag write at `context+0x3F0C` is confirmed; no reader of that offset was found in the 32-bit image, so the oracle's observability is unconfirmed (the x64 baseline reported a KS getter).
8. **KS surface.** `KsPropertyHandler` and the three KS property sets were not exhaustively re-traced; only the visible sinks (bounded copies, registry write) were checked. KS.SYS's own descriptor/buffer validation was not analyzed.
9. **PCI-config chain.** The 1.0.74 unrestricted PCI config write could, in principle, influence the PCI-derived MMIO bases used by `0x225398`/`0x22539C`. This requires specific chipset register semantics and was not established; it is recorded as a residual hardware->PA path, not a confirmed primitive.
10. **Decompiler artifacts.** Ghidra's `FUN_*` names and a few uninitialized-return paths (e.g. `FUN_00401E2E`'s short-output return) are artifacts; all cited behavior was checked against the disassembly at the stated addresses. The x86 `_IRP` offsets (`RequestorMode +0x20`, `Flags +0x08`, `SystemBuffer +0x0C`, `UserBuffer +0x3C`, `CurrentStackLocation +0x60`) were verified against the instruction stream.
11. **No exploit code or PoC.** This report describes primitives and constraints only; it contains no operating steps, payloads, or BYOVD instructions.
