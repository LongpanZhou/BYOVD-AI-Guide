# Netac `SMI_IO` (Silicon Motion) - static audit

| file | arch | size | verdict |
|---|---|---|---|
| `Netac\SMI_IO_64_89A4F4DC.sys` | x64 | 16056 | **WRITE-HIGH primitive - blocked by DACL** (default admin-only) |
| `Netac\SMI_IO_32_B198D7E1.sys` | x86 | 16056 | **WRITE-HIGH primitive - blocked by DACL** (default admin-only) |

Device: `\Device\SMI_IO` + `\DosDevices\SMI_IO`, `DeviceType = 0x8033`, extension 0.
Neither binary imports or references `SeTokenIsAdmin`, `SeSinglePrivilegeCheck`, `IoValidateDeviceIoControlAccess` or any `RequestorMode` test. There is **no access check of any kind** in the dispatch - the DACL is the only gate.

---

## 1. Device creation / effective DACL

`DriverEntry` is `FUN_00011150` @ `0x11150` (x64) and `FUN_00011010` @ `0x11010` (x86). Both are byte-for-byte the same logic:

```c
RtlInitUnicodeString(local_38, L"\\Device\\SMI_IO");
local_20 = IoCreateDevice(param_1, 0, local_38, 0x8033, 0, 0, &local_28);
if (-1 < local_20) {
    *(code **)(param_1 + 0xe0) = FUN_00011270;   // IRP_MJ_DEVICE_CONTROL
    *(code **)(param_1 + 0x80) = FUN_00011270;   // IRP_MJ_CLOSE
    *(code **)(param_1 + 0x70) = FUN_00011270;   // IRP_MJ_CREATE
    *(code **)(param_1 + 0x68) = FUN_000115b0;   // unload
    RtlInitUnicodeString(local_18, L"\\DosDevices\\SMI_IO");
    local_20 = IoCreateSymbolicLink(local_18, local_38);
}
```

* **Plain `IoCreateDevice`, no SDDL, no `IoCreateDeviceSecure`** (not imported, not resolved dynamically).
* Effective DACL = the I/O manager's default device security descriptor: owner SYSTEM, full control to SYSTEM and BUILTIN\Administrators; **no ACE for Everyone / Users / Interactive / Restricted**.
* `IRP_MJ_CREATE` (`local_30 == 0`) falls through to `IofCompleteRequest` with `STATUS_SUCCESS` after setting `IoStatus` to 0 - no `FILE_WRITE_ACCESS` check.

**=> Every IOCTL below is blocked by DACL for an unprivileged local user.** Mark the primitive *"blocked by DACL"*, not "no write".

---

## 2. IOCTL tables

All `METHOD_BUFFERED`, device type `0x8033`, `RequiredAccess = FILE_ANY_ACCESS` (bits 14-15 = 0). The "length" the driver checks is the buffer-length field of the I/O stack location (`[stack+0x10]` on x64 / `[stack+0x8]` on x86, as compiled); it only tests `!= 0`, never a maximum.

### SMI_IO_64 - dispatch `FUN_00011270` @ `0x11270`

| IOCTL | handler | gate | action |
|---|---|---|---|
| `0x803320CC` | `FUN_00011600` @ `0x11600` | `len != 0` | **map arbitrary physical range -> user VA** |
| `0x803320D0` | `FUN_00011830` @ `0x11830` | `len != 0` | unmap (by VA) |
| `0x803320DC` | inline (`FUN_00011010/30/60`) | `len != 0` | **port read** byte/word/dword |
| `0x803320E0` | inline (`FUN_00011080/a0/c0`) | `len != 0` | **port write** byte/word/dword |

### SMI_IO_32 - dispatch `FUN_000110c0` @ `0x110c0`

| IOCTL | handler | gate | action |
|---|---|---|---|
| `0x803320CC` | `FUN_000114d0` | `len != 0` | map arbitrary physical range |
| `0x803320D0` | `FUN_00011720` | `len != 0` | unmap |
| **`0x803320D4`** | inline | none | **IOPM enable** (`MmAllocateNonCachedMemory(0x2000)` -> `Ke386IoSetAccessProcess` -> `Ke386SetIoAccessMap`) |
| **`0x803320D8`** | inline | none | IOPM disable |
| `0x803320DC` | inline | `len != 0` | port read |
| `0x803320E0` | inline | `len != 0` | port write |

The IOPM IOCTLs (`0x803320D4/D8`) have **no token check** - same primitive as MICSYS `0x80102048`, and here the DACL is the only barrier.

---

## 3. Write sinks (decompiled)

### a) Arbitrary physical memory mapped into the caller - `FUN_00011600` @ `0x11600` (x64)

```c
lVar1 = MmMapIoSpace(param_1 /*phys addr*/, param_2 /*size*/, 0);
lVar3 = IoAllocateMdl(lVar1, param_2, 0, 0, 0);
MmBuildMdlForNonPagedPool(lVar3);
uVar4 = MmMapLockedPages(lVar3, 1);              // 1 = user-mode mapping
lVar5 = (uVar4 & 0xfffffffffffff000) + *(uint *)(lVar3 + 0x2c);
...
*param_3 = lVar5;                                // VA returned to the caller
```

* The physical address (`local_78`) and the size (`local_80[0]`, a dword) come **straight from the user input buffer**, with **no validation whatsoever** - no `MmGetPhysicalMemoryRanges`, no MCFG window, no size cap.
* `MmMapLockedPages(Mdl, TRUE)` creates a **user-accessible** mapping, and the IOCTL copies the resulting VA back in the output buffer (`memcpy(_Src, local_20, len)`), so a user-mode process can `memcpy()` over any physical page it maps.
* Consequence: arbitrary kernel/physical memory **read and write**, any length, one IOCTL per region.

### b) Arbitrary port write - `0x803320E0` (x64)

```c
FUN_000117e0(&local_res10, SystemBuffer, len);   // memcpy 7-byte {port,value,width}
if (local_res16 == '\x01') FUN_00011080(local_res10, (undefined1)local_res12);  // out
else if (local_res16 == '\x02') FUN_000110a0(local_res10, (undefined2)local_res12);
else if (local_res16 == '\x04') FUN_000110c0(local_res10, local_res12);
```

and the leaf functions:

```c
void FUN_00011080(undefined2 port, undefined1 val) { out(port, val); }
void FUN_000110a0(undefined2 port, undefined2 val) { out(port, val); }
void FUN_000110c0(undefined2 port, undefined4 val) { out(port, val); }
```

**No port range check, no blocklist** (`0xCF9`, `0xCF8/0xCFC`, DMA ports all reachable).

### c) IOPM grant - `0x803320D4` (x86 only)

```c
local_24 = MmAllocateNonCachedMemory(0x2000);
memset(local_24, 0, 0x2000);
Ke386IoSetAccessProcess(IoGetCurrentProcess());
Ke386SetIoAccessMap(1, local_24);
```

Zeroed bitmap => all 65 536 ports allowed for the calling process at CPL 3.

### d) Kernel stack overflow (x64) - `0x803320CC`

```c
puVar7 = local_80;                       // 8-byte local
for (uVar5 = (ulonglong)uVar1 /*user length*/; uVar5 != 0; uVar5--) {
    *puVar7 = (char)*puVar6;             // unbounded copy into locals
    puVar7 = puVar7 + 1;
}
```

The destination is the 12-byte `{qword phys; dword size}` struct on the stack, but the copy length is the raw user-supplied buffer length (only checked `!= 0`). Any length > ~40 bytes overwrites the saved return address / SEH state => **kernel stack buffer overflow** reachable from the same IOCTL. The x86 build has the equivalent `memcpy(local_20, _Src, len)` into a small stack struct.

---

## 4. Validation gaps

1. **No privilege check** anywhere (no `SeSinglePrivilegeCheck`, no `SeTokenIsAdmin`, no `RequestorMode`).
2. **No `IoValidateDeviceIoControlAccess`** - read-only handle suffices if the DACL ever permits it.
3. **No physical-address validation** - any 32/64-bit physical address, any length, mapped into user space.
4. **No port filter** - any 16-bit port.
5. **No upper bound on the buffer length** - the length field is only tested for zero, and drives an unbounded stack copy (see section 3d).
6. `IRP_MJ_CREATE` returns success without any access check.

---

## 5. Setup required

**none** beyond installing/starting the driver: the device and symlink are created unconditionally in `DriverEntry`; no PnP, no hardware probe, no firmware dependency. (Netac ships this with its SSD tooling; the IOCTLs are generic.)

---

## 6. Next dynamic test

1. Standard user: `CreateFileW(L"\\\\.\\SMI_IO", GENERIC_READ|GENERIC_WRITE, 0, ...)` -> expect `ERROR_ACCESS_DENIED`; confirms the default admin-only DACL.
2. If openable on some image: `DeviceIoControl(h, 0x803320CC, {phys=<known RAM page>, size=0x1000}, 12, out, 0x1000, ...)` -> the returned qword is a user VA; `VirtualQuery` it and read/write to prove the mapping. This is the least invasive proof (no port I/O, no MSR).
3. On x86: `DeviceIoControl(h, 0x803320D4, NULL, 0, NULL, 0, ...)` then `IN`/`OUT` from ring 3.
4. Fuzz the length field of `0x803320CC` (e.g. 0x100) only in a disposable VM - it is a kernel stack overflow.

---

## 7. Verdict / ranking

**WRITE-HIGH primitive, blocked by DACL.**

* The per-IOCTL primitive is the strongest in the collection alongside EVGA: a single `0x803320CC` call maps an **arbitrary-length arbitrary-physical-address** region directly into the caller's address space, and `0x803320E0` writes any I/O port.
* It is not reachable by a standard user because `IoCreateDevice` produced the default admin-only device DACL, and the driver does not check `FILE_WRITE_ACCESS` (so a hypothetical permissive DACL - even read-only - would immediately yield the full primitive).
* Rank within group: `SMI_IO_64` (arbitrary-length phys map + port I/O) ~ `SMI_IO_32` (same plus unauthenticated IOPM) - both blocked by DACL.
