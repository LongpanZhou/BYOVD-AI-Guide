# Audit: CorsairLLAccess64.sys

| Field | Value |
|---|---|
| File | `drivers\CorsairLLAccess64_E8BE57F7.sys` |
| SHA-256 | `E8BE57F7EBDAA6A1DCA95F90BA2E39BE689EB080D0C30979219D286C1E6607C8` |
| Analysis date | 2026-10-24 |
| Method | **Static-only audit via REA/Ghidra** (Ghidra 12.1.4 headless; no execution, no load, no service creation) |
| Reach tier | **R2** - local administrator (default admin DACL + elevation check) |
| Setup required | none (driver load) |
| Write quality | W0 - no kernel memory write; hardware-access only |
| Verdict | **NO-MEMORY-WRITE (HW-ONLY)** - reach=R2 setup=none write=W0 load=signed |
| Binary | PE32+ x86-64, 24,784 bytes, image base `0x140000000`, 30 internal functions |
| Version | 1.0.82.0 - "Corsair LL Access", Corsair Memory, Inc. (`0x1400071A0`, `0x140007238`, `0x1400073D0`) |

> Note: the file at the requested path was relocated by the collection process during the audit to
> `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\CorsairLLAccess64_E8BE57F7.sys`. The replacement was
> hash-verified to be identical (`E8BE57F7...07C8`) before analysis continued. All addresses below are
> image-relative (preferred base `0x140000000`).

---

## 1. Internals

**Purpose.** A vendor "low-level access" driver that exposes chipset hardware to a user-mode component:
SMBus / LPC / TCO port I/O, PCI configuration space access, a fixed MSR read, SMBIOS table retrieval, and
mapping of a small set of firmware/chipset physical pages into the calling process.

**Size / shape.** 30 internal functions, one driver object, one device, one mutex, one 0x48-byte
non-paged lookaside list (tag `'CLMM'` = `0x4D4D4C43`, `0x1400026C8`). No worker threads, no
callbacks, no WMI, no file-system filter, no network. No PDB path is present in this binary; symbols are
Ghidra `FUN_*`.

**Complete external import set (30).** `RtlInitUnicodeString`, `RtlGetVersion`, `KeInitializeMutex`,
`KeReleaseMutex`, `KeWaitForSingleObject`, `ExFreePoolWithTag`, `ExQueryDepthSList`,
`ExpInterlockedPopEntrySList`, `ExInitializeNPagedLookasideList`, `ExDeleteNPagedLookasideList`,
`MmBuildMdlForNonPagedPool`, `MmMapLockedPagesSpecifyCache`, `MmUnmapLockedPages`, `MmMapIoSpace`,
`MmUnmapIoSpace`, `IoAllocateMdl`, `IoFreeMdl`, `IofCompleteRequest`, `IoCreateDevice`,
`IoCreateSymbolicLink`, `IoDeleteDevice`, `IoDeleteSymbolicLink`, `SeQueryInformationToken`,
`IoGetRequestorProcessId`, `KeBugCheckEx`, `wcscpy_s`, `wcsncat_s`, `wcsncmp`,
`HAL.dll!HalGetBusDataByOffset`, `HAL.dll!HalSetBusDataByOffset` (evidence `ev_7d9e87cb...842e`).

Two negative findings matter:

* **No security-descriptor machinery at all.** No `IoCreateDeviceSecure`, no `RtlSetDaclSecurityDescriptor`,
  no `ZwSetSecurityObject`, no SDDL string (`ev_2fe2b502...da0d` lists only the `\Driver\`, `\Device\`,
  `\DosDevices\` literals and the version resource).
* **No MSR write.** A masked byte scan of `.text` (`0x140001000`-`0x140002730`) finds exactly one
  `0F 32` (`RDMSR`) at `0x140001E0D` and **zero** `0F 30` (`WRMSR`) (`ev_1e0b1b7d...4585`).
  There is no `MmGetPhysicalAddress`, no `ZwMapViewOfSection`, no `MmCopyVirtualMemory`,
  no `KeStackAttachProcess`, and no virtual-address write helper.

**Core object.** `FUN_140001B10` (`0x140001B10`) creates the driver's only persistent object: a
0x48-byte list entry holding

| Offset | Content | Set at |
|---|---|---|
| +0x10 | owning `FILE_OBJECT` | `0x140001C6E` |
| +0x18 | physical address | `0x140001C72` |
| +0x20 | kernel VA from `MmMapIoSpace` | `0x140001C76` |
| +0x28 | size | `0x140001C7A` |
| +0x30 | **user-mode VA** returned to caller | `0x140001C82` |
| +0x38 | MDL | `0x140001C86` |
| +0x2C | requestor PID (cache key) | `0x140001C8E` |
| +0x40 | reference count | `0x140001C0A`/`0x140001C8E` |

Entries live on a doubly-linked list (`DAT_1400042B8`) guarded by mutex `DAT_140004280`
(`0x140001B6D`, `0x140001DA0`). They are keyed by *(PID, physical address)* for reuse
(`FUN_140001DE0`, `0x140001DE0`) and released either by refcount (`FUN_14000215C`) or by
`IRP_MJ_CLOSE` (`FUN_140001050`).

**Mapping primitive.** `FUN_140001B10`:

1. `MmMapIoSpace(phys, size, MmNonCached)` - `0x140001BAA` (RCX=phys, RDX=size, R8=0).
2. `IoAllocateMdl(va, size, 0, 0, irp)` - `0x140001BD2`.
3. `MmBuildMdlForNonPagedPool(mdl)` - `0x140001BFE`.
4. `MmMapLockedPagesSpecifyCache(mdl, UserMode, MmNonCached, NULL, FALSE, ...)` - `0x140001C25`
   (`MOV DL,1` at `0x140001C20`; R8D=0; R9D=0).
5. Returns `MDL->ByteOffset + (mapped & ~0xFFF)` - `0x140001C2B`-`0x140001C37` - to the caller.

The result is a **user-mode, non-cached read/write alias of a physical page**, created by the kernel on
behalf of the requesting process.

---

## 2. Entry / device / dispatch

**Entry.** `entry` at `0x140006000` performs `__security_init_cookie` and calls `FUN_14000231C`
(`0x14000231C`), the real `DriverEntry`.

**Step 1 - OS gate and pool flags.** `RtlGetVersion`; on >= 6.2 it sets `DAT_140004040 = 0x200` and
`DAT_140004044 = 0x40000000` (`0x14000237E`, `0x140002388`) - pool flags used for the lookaside list.

**Step 2 - static port allow-list.** `FUN_140001000(0xCD6,1)` at `0x1400023A0` and
`FUN_140001000(0xCD7,1)` at `0x1400023AA`. `FUN_140001000` (`0x140001000`) appends `(base,length)`
pairs to `DAT_140004380/DAT_140004384`, capped at 16 entries (`DAT_140004400`, `0x140001000`-`0x140001050`).
`0xCD6/0xCD7` are the classic chipset LPC index/data pair.

**Step 3 - PCI enumeration, SMBus discovery.** Nested loop `0x1400023C3`-`0x1400024CB`
(bus `0x00..0xFF`, device `0x00..0x1F`, function `0..7`). For each function it reads config dword 0
(`0x140002464` -> `FUN_140001E2C` -> `HalGetBusDataByOffset`, `0x140001E67`), skips `0xFFFF` IDs, and
tests class/subclass:

* class base `0x0C` / subclass `0x05` (**SMBus controller**) - `0x14000243E`/`0x140002441`;
* reads BAR0 at config `0x20` (`0x140002464`, R9D=0x20), clears bit 0 (`0x140002471`), and registers a
  **0x10-byte I/O port range** for it: `FUN_140001000(bar,0x10)` at `0x14000247F`;
* records `(bus, device, function)` in the PCI-write allow-list `DAT_140004410`
  (`0x140002496`-`0x1400024A4`), also capped at 16 entries (`0x14000248A`).

**Step 4 - TCO base.** `MmMapIoSpace(0xFED80300, 4, MmNonCached)` at `0x1400024DC`, reads the dword,
and if `(value & 0xFF00) != 0` registers a **0x17-byte** port range at `value & 0xFF00`
(`0x140002502`-`0x140002511`).

**Step 5 - device and symlink.** The device name is derived at runtime from the driver object's own
`DriverName` (`0x140002516`-`0x1400025F6`), stripping a leading `\Driver\`, then:

* `\Device\<DriverName>` (built at `0x14000257B`/`0x1400025A7`);
* `\DosDevices\<DriverName>` (built at `0x1400025D8`/`0x1400025E9`).

`IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN (0x22), FILE_DEVICE_SECURE_OPEN (0x100), FALSE)`
at `0x140002625` (`R9D=0x22` at `0x140002615`, `[RSP+0x20]=0x100` at `0x14000261D`, `[RSP+0x28]=0`).
**No explicit security descriptor is passed** - see section 4. `IoCreateSymbolicLink` at `0x14000263D`.

**Step 6 - dispatch table** (`DriverObject` in R14):

| Offset | IRP major | Handler | Address written |
|---|---|---|---|
| `+0x68` | `IRP_MJ_UNLOAD` | `FUN_140001510` | `0x140002692` |
| `+0x70` | `IRP_MJ_CREATE` | `FUN_140001120` | `0x140002664` |
| `+0x80` | `IRP_MJ_CLOSE` | `FUN_140001050` | `0x140002676` |
| `+0xE0` | `IRP_MJ_DEVICE_CONTROL` | `FUN_140001330` | `0x140002684` |

All other majors are left NULL. There is no `IRP_MJ_INTERNAL_DEVICE_CONTROL` path.

**Step 7 - runtime state.** `KeInitializeMutex(&DAT_140004280)` (`0x1400026AB`) and
`ExInitializeNPagedLookasideList(&DAT_140004300, ..., 0x48, 'CLMM', 0)` (`0x1400026DB`).

**Unload** (`FUN_140001510`, `0x140001510`) deletes the symlink (`IoDeleteSymbolicLink`) and the device
(`IoDeleteDevice`), and deletes the lookaside list - but **does not walk and unmap the mapping list**;
outstanding entries are only released by `IRP_MJ_CLOSE`.

---

## 3. IOCTL table

Dispatch: `FUN_140001330` (`0x140001330`). It reads the current stack location from `Irp+0xB8`
(`0x140001349`), `IoControlCode` from `+0x18` (`0x14000135E`), `InputBufferLength` from `+0x10`
(`0x140001365`), `OutputBufferLength` from `+0x8` (`0x140001369`), and the buffer from
`Irp+0x18` (`0x140001353`) - i.e. **`AssociatedIrp.SystemBuffer`**, consistent with every code below
being `METHOD_BUFFERED`. Unknown codes complete with `0xC0000002` (`0x14000145D`).

All codes use `DeviceType = 0x22` (`FILE_DEVICE_UNKNOWN`).

| IOCTL | Access | Function | Method | Handler | Action |
|---|---|---|---|---|---|
| `0x225348` | READ | `0x4D2` | BUFFERED | `FUN_140001E80` | PCI config **read** (any bus/dev/fn) |
| `0x225358` | READ | `0x4D6` | BUFFERED | `FUN_140002078` (p2=0) | Port I/O **read** (allow-listed ports) |
| `0x22537C` | READ | `0x4DF` | BUFFERED | inline `0x1400013EE` | Version query -> `0x01000052` (1.0.82) |
| `0x22538C` | READ | `0x4E3` | BUFFERED | `FUN_140001DF4` | `RDMSR 0xC0010058` |
| `0x225390` | READ | `0x4E4` | BUFFERED | `FUN_140001F80` | Fixed MMIO read @ `0xFED80300`, 4 bytes |
| `0x225394` | READ | `0x4E5` | BUFFERED | `FUN_140001650` | SMBIOS table -> mapped into caller |
| `0x225398` | READ | `0x4E6` | BUFFERED | `FUN_140001798`+`FUN_1400018A0` | Enumerate + map chipset MMIO pages |
| `0x22539C` | READ | `0x4E7` | BUFFERED | `FUN_140001798`+`FUN_1400019E0` | Alternate enumerate + map |
| `0x229354` | WRITE | `0x4D5` | BUFFERED | `FUN_140002078` (p2=1) | Port I/O **write** (allow-listed ports) |
| `0x229378` | WRITE | `0x4DE` | BUFFERED | `FUN_14000215C` | Release a mapping by user VA |
| `0x229380` | WRITE | `0x4E0` | BUFFERED | `FUN_1400021FC` | PCI config **write** (allow-listed BDF only) |

Access bits (`(code>>14)&3`) are router-enforced: `0x229xxx` codes are `FILE_WRITE_ACCESS`, all others
`FILE_READ_ACCESS`. There is no additional per-IOCTL privilege check.

### 3.1 Input / output contracts

**`0x225348` - PCI config read.** `FUN_140001E80` (`0x140001E80`). Input >= 20 bytes:
`{u32 bus, u32 dev, u32 fn, u32 offset, u32 length}`. Validation (`0x140001E80`-`0x140001EC0`):
`inlen >= 0x14`, `outlen >= length`, `dev < 0x20`, `fn < 8`, `length in {1,2,4}`
(`(len-1)&0xFFFFFFFC == 0 && len != 3`), `offset+len <= 0x100`. `bus` is **not** range-checked.
Data is read into the same SystemBuffer: `HalGetBusDataByOffset(4, bus, dev<<5|fn, buf, offset, len)`
at `0x140001E67`. Read-only; no capability beyond config-space reads.

**`0x225358` / `0x229354` - port I/O.** `FUN_140002078` (`0x140002078`). Input >= 10 bytes:
`{u32 port, u32 value, u16 size}`. `size in {1,2,4}`. The `(port, size)` window must be fully inside one
of the registered ranges (`base <= port && port+size <= base+len`, `0x140002078`-`0x140002146`).
Data path: `IN AL/AX/EAX, DX` at `0x140002131`/`0x140002129`/`0x140002123`; `OUT DX, AL/AX/EAX` at
`0x140002106`/`0x1400020FE`/`0x1400020F6`. Registered ranges are only the four seeded at load time:
`0xCD6` (1), `0xCD7` (1), SMBus BAR0 (0x10), TCO base (0x17). Writes are gated behind the
`FILE_WRITE_ACCESS` code `0x229354` (`SETZ DL` at `0x1400014A8`).

**`0x22537C` - version.** `outlen >= 4`, writes `0x01000052`, `Information = 4` (`0x1400013EE`-`0x140001409`).

**`0x22538C` - MSR read.** `FUN_140001DF4(0xC0010058, outlen, buf, &info)` (`0x1400013DF`).
Requires `outlen >= 8` (`0x140001DF4`). `RDMSR` at `0x140001E0D`; result stored as 8 bytes.
The MSR index is a hard-coded constant - the caller cannot select it. No write path exists.

**`0x225390` - fixed MMIO read.** `FUN_140001F80(&{0xFED80300,0,4}, read, outlen, buf, &info)`
(`0x1400013B6`-`0x1400013CC`). `MmMapIoSpace(0xFED80300,4,0)`, copies 4 bytes, `MmUnmapIoSpace`.
The write branch of `FUN_140001F80` exists in code but is unreachable - the dispatcher always passes
`EDX = 0` (`0x1400013C5`).

**`0x225394` - SMBIOS.** `FUN_140001650` (`0x140001650`). Requires `outlen >= 0x12`
(`0x140001650`). It maps `MmMapIoSpace(0xF0000, 0x10000, 0)` (`0x140001699`/`0x1400016A2`), scans the
64 KB ROM window for a SMBIOS 3 (`"_SM3_"`, `FUN_1400012C8`) or SMBIOS 2.1 (`"_SM_"` + `"_DMI_"`,
`FUN_140001228`) entry point, validates the entry-point checksums, extracts the structure-table
**physical address and length** from the entry point, unmaps the ROM, then calls `FUN_140001B10` with
that firmware-supplied address/length (`0x14000174C`). Output: `{u64 userVA, u64 length, u16 0}`,
`Information = 0x12`.

**`0x225398` / `0x22539C` - MMIO page mapping.** `FUN_140001798` (`0x140001798`) calls a fixed
enumerator (`FUN_1400018A0` / `FUN_1400019E0`) to fill up to 64 physical addresses, requires
`outlen >= count*8`, then calls `FUN_140001B10` once per address with size `0x1000` and writes the
resulting **user-mode VAs** into the output buffer (`0x140001798`-`0x140001855`). On partial failure it
unwinds with `FUN_14000215C`. The addresses are derived from PCI config reads plus hard-coded offsets
(`... + 0xF5000 + n*0x100000` at `0x1400018A0`; `... + 0x98000 + n*0x100000` at `0x1400019E0`).
**The caller cannot choose the page or the size.**

**`0x229378` - release.** `inlen >= 8`, reads a `u64` user VA from the SystemBuffer and calls
`FUN_14000215C(FileObject, va)` (`0x140001481`). Decrements the entry refcount; at zero it does
`MmUnmapLockedPages`, `IoFreeMdl`, `MmUnmapIoSpace` (`FUN_1400015D4`, `0x1400015D4`).

**`0x229380` - PCI config write.** `FUN_1400021FC` (`0x1400021FC`). Input:
`{u32 bus, u32 dev, u32 fn, u32 offset, u32 length, u8 data[]}`; requires
`inlen >= 0x14 + length`, `dev < 0x20`, `fn < 8`, `length in {1,2,4}`, `offset+length <= 0x100`.
The `(bus,dev,fn)` triple must match an entry recorded at load time (`DAT_140004410`,
`0x1400021FC`), otherwise `0xC0000022`. Write via
`HalSetBusDataByOffset(4, bus, fn<<5|dev, &data, offset, len)` at `0x1400022D6`.

**Buffer safety.** Every handler reads/writes only `SystemBuffer`; every write is bounded by a length
check against `OutputBufferLength`/`InputBufferLength` (or is a fixed <= 0x12-byte write). Because all
codes are `METHOD_BUFFERED`, `ProbeForWrite`/`ProbeForRead` are neither present nor required. No
user-mode pointer is dereferenced in any handler, so there is no classic `METHOD_NEITHER` capture bug.

---

## 4. Access-control audit

**Gate 1 - device DACL (default, admin-only).** `DriverEntry` calls `IoCreateDevice`
(`0x140002625`). The binary contains **no SDDL string and no locally-constructed security descriptor**;
none of `IoCreateDeviceSecure`, `RtlSetDaclSecurityDescriptor`, `RtlCreateSecurityDescriptor`,
`ZwSetSecurityObject` is imported (full import list in section 1). The object therefore receives the I/O
manager's default device-object security descriptor, whose DACL grants full access to `SYSTEM` and
`BUILTIN\Administrators` - the "default admin DACL" reported in triage. `Characteristics` is
`0x100` = `FILE_DEVICE_SECURE_OPEN` (`0x14000261D`), so the DACL is enforced on opens **through the
`\DosDevices\...` symlink as well**, not just on `\Device\...`. There is no `Everyone`/`Users` ACE.

**Gate 2 - create-path token check.** `FUN_140001120` (`0x140001120`) is `IRP_MJ_CREATE`:

* The check runs only when `Irp->RequestorMode == UserMode` (`0x140001143`); kernel-mode creates skip it
  (`BPL` initialised to 1 at `0x14000113A`).
* `0x140001156`: rejects creates whose `FILE_OBJECT->FileName.Length != 0` (`0x1400011FB`), i.e. opens
  that carry a remaining sub-name after the device.
* `0x140001161`-`0x140001188`: derives the requestor token from
  `Parameters.Create.SecurityContext`.
* `0x14000119F`: `SeQueryInformationToken(token, TokenElevation (0x14), &out)`.
* `0x1400011D9`: if the elevation DWORD is **0** -> `STATUS_ACCESS_DENIED (0xC0000022)`.
* `0x1400011CD`: `SeQueryInformationToken(token, TokenIntegrityLevel (0x19), &out2)`.
* `0x1400011DE`: `CMP dword ptr [RSP+0x58], 0x3000` - this compares the **first DWORD of the returned
  `TOKEN_MANDATORY_LABEL`**, i.e. the low 32 bits of `Label.Sid`, not the integrity RID
  (`*(PULONG)((PSID)Label.Sid + 8)`). The test is therefore not a meaningful IL check; the effective
  gate is the `TokenElevation` test above.

**Result.** Reach is **local administrator with an elevated, high-integrity token**. A standard user
with a handle inherited from an elevated process would pass the DACL but still needs the elevated token
to satisfy Gate 2. There is no `SeSinglePrivilegeCheck`, `SeAccessCheck`, or privilege-name check
anywhere in the dispatch path.

**Lifetime / cleanup.** `IRP_MJ_CLOSE` (`FUN_140001050`, `0x140001050`) walks the mapping list and
frees every entry whose `+0x10` equals the closing `FILE_OBJECT`. It **ignores the refcount at +0x40**,
so an entry that was shared with a second handle of the same process (cache hit path `FUN_140001B10`
returns the cached user VA to any handle with the same PID, `0x140001B8A`) is destroyed when the
*creating* handle closes, invalidating the other handle's user VA. This is a user-mode availability
bug, not a kernel memory-safety issue: entries are unlinked before being returned to the lookaside
list, and a later `0x229378` on the stale VA fails the list lookup (`0xC0000225`).

---

## 5. Most dangerous exposed capability

**Primitive: kernel-created user-mode read/write mappings of firmware/chipset physical pages
(`FUN_140001B10` -> `0x225394`, `0x225398`, `0x22539C`).**

`FUN_140001B10` calls `MmMapIoSpace(phys, size, MmNonCached)` (`0x140001BAA`), builds an MDL over the
result (`0x140001BD2`, `0x140001BFE`), and maps it with
`MmMapLockedPagesSpecifyCache(mdl, UserMode, MmNonCached, NULL, FALSE, ...)` (`0x140001C25`). The
resulting address is a **user-mode VA inside the calling process**; after the IOCTL returns the
caller reads and writes the physical page directly, with no further kernel mediation.

Reachable page sets:

| IOCTL | Physical target | Address source | Size |
|---|---|---|---|
| `0x225394` | SMBIOS structure table | firmware entry point inside `0xF0000`-`0xFFFFF` (`0x14000174C`) | firmware-declared, <= 0xFFFF |
| `0x225398` | chipset/GPU MMIO | PCI config + hard-coded base (`0x1400018A0`) | 0x1000 per page, <= 64 pages |
| `0x22539C` | chipset/GPU MMIO | PCI config + hard-coded base (`0x1400019E0`) | 0x1000 per page, <= 64 pages |

Secondary hardware primitives in the same trust domain:

* **Port I/O write** to `0xCD6`/`0xCD7` (LPC index/data), the SMBus controller BAR (0x10 bytes), and the
  TCO base (0x17 bytes) - `0x229354` / `FUN_140002078` (`OUT` at `0x1400020F6`-`0x140002106`).
* **PCI configuration write** to the SMBus controller BDF only - `0x229380` (`HalSetBusDataByOffset`,
  `0x1400022D6`).
* **PCI configuration read** from any bus/device/function - `0x225348` (`HalGetBusDataByOffset`,
  `0x140001E67`).
* **Fixed MSR read** `0xC0010058` (AMD MMIO configuration base) - `0x22538C` (`RDMSR`, `0x140001E0D`).

**Is it a true kernel memory write? No.** Nothing in the driver writes to a caller-supplied virtual
address, and no IOCTL accepts a caller-supplied **physical** address. The mapping targets are
(a) fixed offsets relative to PCI-derived chipset bases and (b) the firmware's own SMBIOS table
pointer. There is no `WRMSR`, no arbitrary port range, no arbitrary PCI BDF, and no MDL built over a
user-supplied VA. An administrator using this driver gains **hardware-level access** (SMBus/LPC/TCO,
PCI config, selected MMIO), which is a strong firmware/chipset attack surface but is *not* a kernel
read/write primitive and does not by itself defeat KASLR, DSE, or SMEP.

One latent escalation path is worth flagging: the `0x225394` target address and length come from the
SMBIOS entry point in the ROM window. On a platform where that data is attacker-controlled (malicious
or virtualized firmware), pointing the table address at RAM would cause the driver to map that RAM page
into the admin's process - a genuine, if indirect, physical-memory read/write. It requires firmware
control, not merely the driver handle.

---

## 6. VERDICT

**Classification: hardware-access driver (SMBus/LPC/TCO + PCI config + fixed MMIO + SMBIOS). Not a
kernel memory-write primitive.**

* **Admin-reachable:** yes - default admin-only device DACL (`FILE_DEVICE_SECURE_OPEN`, no custom SD)
  plus an `SeQueryInformationToken(TokenElevation)` check in `IRP_MJ_CREATE` (`0x14000119F`/`0x1400011D9`).
* **Arbitrary kernel virtual write:** **none**.
* **Arbitrary physical-address mapping:** **none** - all mapping targets are firmware- or
  PCI-enumeration-derived; there is no caller-controlled physical address in any of the 11 IOCTLs.
* **Arbitrary port I/O:** **no** - strictly allow-listed to `0xCD6`, `0xCD7`, the SMBus BAR (0x10 bytes)
  and the TCO base (0x17 bytes), seeded only in `DriverEntry`.
* **Arbitrary PCI config write:** **no** - restricted to the enumerated SMBus controller BDF.
* **MSR write:** none. One fixed `RDMSR 0xC0010058`.
* **Memory-safety defects exploitable from user mode:** none identified. All 11 handlers use
  `METHOD_BUFFERED` with explicit input/output length checks; no user pointer is dereferenced.
* **Residual risk:** **Medium-High as a hardware/firmware access primitive** for an administrator
  (MMIO pages are mapped read/write into user mode; LPC/SMBus/TCO port writes are available), **Low as
  a BYOVD kernel-memory primitive** (the property such tooling needs is absent). The driver is a
  legitimate Corsair component and is signed, but it is a textbook "ring-0 hardware access" surface:
  any code running as an elevated administrator - including malware that has already elevated - can
  use it to reach chipset registers without writing a driver of its own.

---

## 7. Limitations

1. **Static only.** No driver was loaded, no IOCTL was issued, no hardware behaviour was observed.
   Statements about which chipset registers the enumerated addresses reach are inferred from the code
   and standard PCI/Intel/AMD register layouts, not measured.
2. **Artifact relocation.** The requested path disappeared mid-analysis (collection re-organisation);
   the file was re-opened from `...\driver_candidates\drivers\` after `Get-FileHash` confirmed the same
   SHA-256. Evidence IDs below were produced against that identical byte stream.
3. **Default DACL inference.** The absence of a driver-supplied SD is proven; the exact default
   device-object ACEs (`SYSTEM`/`Administrators` full control) are the documented I/O-manager default
   and were not verified at runtime.
4. **Integrity-level check.** `0x1400011DE` compares a `TOKEN_MANDATORY_LABEL` pointer field against
   `0x3000` rather than the SID's RID. This is reported as observed assembly; whether the compiler
   intended a different offset could not be confirmed without symbols. It does not weaken the separate
   `TokenElevation` gate.
5. **Decompiler artefacts.** `FUN_140001F80`'s early-return paths surface as `unaff_EBX`
   (uninitialised status); the exact NTSTATUS returned when `OutputBufferLength < 4` on `0x225390` was
   not resolved. `FUN_1400018A0`/`FUN_1400019E0` contain loop/offset arithmetic whose hardware meaning
   (which chipset block `0xF5000`/`0x98000` offsets refer to) is inferred, not verified.
6. **SMBIOS parsing.** Entry-point offsets are reported at the level needed to establish provenance of
   the physical address/length; per-field SMBIOS semantics were not exhaustively validated.
7. **Concurrency of the analysis backend.** REA/Ghidra served multiple concurrent analyses during this
   audit; every cited observation was re-verified against the correct SHA-256 before use, but a small
   number of earlier tool responses belonged to other targets and were discarded.

### Evidence IDs (REA)

| Evidence | Operation | Subject |
|---|---|---|
| `ev_7d9e87cb504ceaa6cee7afa15c7490f0f5d8914ae0d8a01f1f6e3bded33b842e` | `list_procedures` | function/import inventory |
| `ev_1d8b3909886f41e838736bd90a9e14d7d8026109d7bcae571ce29bf62b41e488` | `batch_decompile` | `0x140001330` dispatcher |
| `ev_0df73a941b8b7e9fd874656176cfd7a7332d86c3cdc1f01560f4e61459c72734` | `batch_decompile` | `0x140001B10` mapping core |
| `ev_d3d5f68cc556c5c1511ab802f5f4964477fe72132e59536bca3cbc1ba40266dd` | `batch_decompile` | `0x14000231C` DriverEntry |
| `ev_fc03eb3739c6c72d0d9d6a478966965f679f40c1371e101edcffcec04879aa56` | `procedure_assembly` | `0x140001120` create gate |
| `ev_2fe2b502ea362334c1f576344b1be6d66ea971610f9111221a33f8dedb8cda0d` | `list_strings` | no SDDL; names/version |
| `ev_a5322b82dda485897f988605fd7c9c1231e65a782c739ae807bb2ea8508b5546` | `batch_decompile` | `0x140001DF4`, `0x140001E2C`, `0x140001E80`, `0x1400021FC` |
| `ev_e2d65bce15d388a3b4727f750d61d089ae272aaa37c1170f8bddfcc905365d91` | `batch_decompile` | `0x140001650`, `0x140001798`, `0x1400018A0`, `0x1400019E0` |
| `ev_ed19ba49633deca98e425e176a513b907eca6b63dd9f0f309a93395f7f081035` | `batch_decompile` | `0x140002078`, `0x140001F80` |
| `ev_1dc94106f0611bdafcb5423e66bbd7ed5908e2f94e7aabfc17c9cb3f5d47f60a` | `batch_decompile` | `0x140001050`, `0x1400015D4`, `0x14000215C` |
| `ev_1e0b1b7daa03b85398ce5df972003892dd149ae28205690c5ad2255da6f84585` | `search_bytes` | `0F 30` (WRMSR) scan - no hits |
