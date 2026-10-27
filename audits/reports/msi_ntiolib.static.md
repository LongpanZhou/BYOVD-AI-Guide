# MSI group - NTIOLib / amifldrv / MSIO - static audit

| file | arch | size | identity | verdict |
|---|---|---|---|---|
| `MSI\NTIOLib_X64_DA3C1360.sys` | x64 | 43856 | MSI NTIOLib 2.0.0.7x (Mystic Light) | **WRITE-MEDIUM primitive - blocked by DACL** (SDDL admin-only) |
| `MSI\NTIOLib_05A202D5.sys` | x86 | 39248 | MSI NTIOLib 2.0.0.7x | **WRITE-MEDIUM primitive - blocked by DACL** (SDDL admin-only) |
| `MSI\amifldrv64_5F487829.sys` | x64 | 15984 | AMI flash driver | **WRITE-HIGH primitive - blocked by DACL** (default admin-only) |
| `MSI\amifldrv32_6AC4DE8D.sys` | x86 | 12528 | AMI flash driver | **WRITE-HIGH primitive - blocked by DACL** (default admin-only) |
| `MSI\MSIO64_525D9B51.SYS` | x64 | 25616 | MICSYS MsIo v1.2 clone (MSI brand) | **WRITE-HIGH primitive - blocked by DACL** (default admin-only) |
| `MSI\MSIO32_C7D4943D.SYS` | x86 | 6144 | MICSYS MsIo v1.2 clone (MSI brand) | **WRITE-HIGH primitive - blocked by DACL** (default admin-only) |

Image base `0x140000000` (x64) / `0x400000` (x86) for NTIOLib; `0x10000` for MSIO/amifldrv.

None of the six contains any `SeTokenIsAdmin`, `SeSinglePrivilegeCheck`, `RequestorMode` test or `IoValidateDeviceIoControlAccess` call. In every case access control is the object DACL alone.

---

## 1. Device creation and effective DACL

### NTIOLib_X64 (`NTIOLib_X64_DA3C1360.sys`)

`FUN_140001000` @ `0x140001000`:

```
14000100d  LEA RDX,[0x1400020f0]        ; "\Device\NTIOLib_MysticLight"
140001039  LEA RAX,[0x140003220]        ; &DeviceClassGuid (non-NULL)
14000104a  LEA RAX,[0x140003210]        ; &DefaultSDDLString
140001063  CALL 0x140006090             ; WdmlibIoCreateDeviceSecure
...
140001087  LEA RDX,[0x140002130]        ; "\DosDevices\NTIOLib_MysticLight"
```

`DeviceType = 0xC350`, `Characteristics = 0x100`, class GUID `{f430d5ee-7fc2-4b14-a48a-5565e44b9c83}` (`0x140003220`).

SDDL descriptor at `0x140003210`:

```
36 00 38 00 00 00 00 00 30 32 00 40 01 00 00 00
len = 0x36 (27 chars), Buffer = 0x140003230
0x140003230: "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
```

-> **admin-only** (SYSTEM + Administrators).

### NTIOLib_05A202D5 (x86)

`FUN_00401000` @ `0x401000` calls `_WdmlibIoCreateDeviceSecure_36` with `\Device\NTIOLib_MysticLight`, type `0xC350`, SDDL pointer `&DAT_00403108`; the SDDL text is at `0x403120`:

```
0x403120: "D:P(A;;GA;;;SY)(A;;GA;;;BA)"     (27 chars, len 0x36)
0x403110: {f430d5ee-7fc2-4b14-a48a-5565e44b9c83}   (class GUID)
```

-> **admin-only**.

### amifldrv64 / amifldrv32

```c
// amifldrv64 FUN_00011e70 (DriverEntry helper)   / amifldrv32 FUN_00010e1a @ 0x10e1a
RtlInitUnicodeString(local_10, L"\\Device\\genericdrv");
iVar2 = IoCreateDevice(param_1, 0x10, local_10, 64000 /*0xFA00*/, 0, 0, &local_8);
RtlInitUnicodeString(local_18, L"\\??\\genericdrv");
IoCreateSymbolicLink(local_18, local_10);
```

**Plain `IoCreateDevice`, no SDDL** -> default device DACL (Administrators + SYSTEM only).

### MSIO64 (`MSIO64_525D9B51.SYS`)

`FUN_000116c0` @ `0x116c0`:

```c
RtlInitUnicodeString(local_30, L"\\Device\\MsIo");
iVar1 = IoCreateDevice(param_1, 0, local_30, 0x8010, 0, 0, &local_38);
IoCreateSymbolicLink(L"\\DosDevices\\MsIo", local_30);
```

**Plain `IoCreateDevice`** -> default admin-only DACL. (Same code as ASRock MsIo v1.2, rebranded.)

### MSIO32 (`MSIO32_C7D4943D.SYS`)

`FUN_00011916` @ `0x11916`: identical plain `IoCreateDevice(..., 0x8010, 0, 0, ...)` + `\DosDevices\MsIo`. Default admin-only DACL.

---

## 2. IOCTL tables

### NTIOLib (x64 dispatch `FUN_1400010e0` @ `0x1400010e0`; x86 `FUN_004010d0` @ `0x4010d0`)

Device type `0xC350`, all `METHOD_BUFFERED`, `RequiredAccess = FILE_ANY_ACCESS`.

| IOCTL | handler | action |
|---|---|---|
| `0xC3502004` | inline | return device refcount (out 4) |
| `0xC3502084` | `FUN_140001518` | **`rdmsr`** with curated allowlist (0x35, 0xCE, 0x10A, 0x150, 0x194-0x199, 0x19C, 0x1A0, 0x1A2, 0x1AD-0x1B1, 0x30A/0x30B, 0x38D/0x38F, 0x601, 0x606-0x608, 0x610/0x611, 0x614, 0x620/0x621, 0x650/0x651, 0xC0010293 ...) |
| `0xC3502088` | `FUN_14000192c` | **`wrmsr`** with a *narrower* allowlist (0x150, 0x194, 0x199, 0x1A0, 0x1AD-0x1AF, 0x38D/0x38F, 0x601, 0x610, 0x620, 0x650/0x651, 0xC0010293-range) |
| `0xC350214C` | inline | magic-token unlock (`DAT_140004220 = 0` if input dword == `DAT_140004000`); all handlers below require `DAT_140004220 == DAT_140004000` |
| `0xC35060C4/60CC/60D0` | `FUN_140001370` | **port read** byte/word/dword (in-len must be 2) |
| `0xC350A0C8/A0D8/A0DC/A0E0` | `FUN_1400017ac` | **port write** byte/word/dword (bitmap `0x1110001` on `ioctl+0x3caf5f38`) |
| `0xC3506104` | `FUN_1400013dc` | `MmMapIoSpace` **read**, phys-address high bits in {0x0C, 0x0F, 0xFDAE, 0xFED1, 0xFED8, 0xFF98, 0xFF99, 0xFFFF} |
| `0xC350A108` | `FUN_140001810` | `MmMapIoSpace` **write**, high bits in {0xFDAE, 0xFED1, 0xFED8} |
| `0xC3506144` | `FUN_140001688` | PCI config **read** (`HalGetBusDataByOffset`), device allowlist (0x0, 0x8-0xA, 0x42, 0xC1-0xC5, 0xF8, 0xFB, 0xFC, 0xFF02, 0xFF50, 0xFF98, 0xFFA0/1/8/9, 0xFFF0/1 ...) |
| `0xC350A148` | `FUN_1400019dc` -> `FUN_140001ad4` | PCI config **write** (`HalSetBusDataByOffset`), same kind of allowlist |

**Port write filter (`FUN_1400017ac`):** only `0xCF9`, `0x64`, `0x61` are refused.

```c
iVar1 = *param_2;
if (((iVar1 != 0xcf9) && (iVar1 != 100)) && (iVar1 != 0x61)) {
  if (param_1 == -0x3caf5f28) out(uVar2, (char)param_2[1]);        // 0xC350A0D8
  else if (param_1 == -0x3caf5f24) out(uVar2, (short)param_2[1]);  // 0xC350A0DC
  else if (param_1 == -0x3caf5f20) out(uVar2, param_2[1]);         // 0xC350A0E0
  return 0;
}
return 0xc0000008;
```

### amifldrv (x64 dispatch `FUN_00011a60` @ `0x11a60`)

Device type `0xFA00`, `METHOD_BUFFERED`.

| IOCTL | handler | action |
|---|---|---|
| `0xFA002EE0` | `FUN_000118b0` | flash/region read (0x14-byte struct) |
| `0xFA002EE4` | `FUN_000119c0` | region erase/lock helper |
| `0xFA002EE8` | `FUN_00011670` | region read |
| `0xFA002EEC` | **`FUN_00011070`** | **arbitrary physical/port READ** |
| `0xFA002EF0` | **`FUN_00011280`** | **arbitrary physical/port WRITE** |
| `0xFA002EF8` | `FUN_00011870` | region info |
| `0xFA002EFC` | `FUN_00011490` | 0x16-byte flash command |
| `0xFA002F08` | inline | capability query (writes `{2,2}`) |

### MSIO64 (`FUN_000113f0` @ `0x113f0`) / MSIO32 (`FUN_00011558` @ `0x11558`)

Device type `0x8010`, `METHOD_BUFFERED`, `FILE_ANY_ACCESS`.

| IOCTL | MSIO64 | MSIO32 | action |
|---|---|---|---|
| `0x80102040` | [x] | [x] | map physical -> user VA (`FUN_00011090` / `FUN_000111d8`) |
| `0x80102044` | [x] | [x] | unmap (`FUN_00011360` / `FUN_000113d4`) |
| `0x80102048` | - | [x] | **IOPM enable, no token check** (`MmAllocateNonCachedMemory(0x2000)` + `Ke386SetIoAccessMap`) |
| `0x8010204c` | - | [x] | IOPM disable |
| `0x80102050` | [x] | [x] | port read |
| `0x80102054` | [x] | [x] | **port write, no port filter at all** |

---

## 3. Write sinks (decompiled)

### amifldrv64 `FUN_00011280` @ `0x11280` - arbitrary physical **and** port write

```c
cVar2 = HalTranslateBusAddress(1,0,local_18,&local_res8,&local_10);
if (local_res8[0] == 0) {
    local_28 = (uint *)MmMapIoSpace(..., 1, 0);
    *(char *)local_28 = (char)param_1[3];          // <-- phys byte write
} else {
    out(local_28._0_2_, (char)param_1[3]);         // <-- port byte write
}
```

Width from `param_1[2]` in {0,1,2} -> 1/2/4 bytes; the 16-bit port and the 32/64-bit address come **directly from the input buffer**. No range check, no allowlist, no token check.

### MSIO64 `FUN_000113f0` @ `0x113f0` - port write, no filter

```c
if (iVar7 == -0x7fefdfac) {                     // 0x80102054
  FUN_000117e0(&local_res10, puVar3, uVar9);    // memcpy 7-byte {port,value,width}
  if (local_res16 == '\x01') out(local_res10, (undefined1)local_res12);
  else if (local_res16 == '\x02') out(local_res10, (undefined2)local_res12);
  else if (local_res16 == '\x04') out(local_res10, local_res12);
}
```

Unlike ASRock/MSI-NTIOLib, **there is no `0x66/0x92/0xCF9` blocklist** - literally any port.

### MSIO64 `FUN_00011090` @ `0x11090` - physical mapping with **no validation**

```c
local_88 = param_1 & 0xffffffff;                  // physical address, user supplied
local_90 = local_88 + local_res10[0];             // + length, user supplied
HalTranslateBusAddress(1,0,local_88,...);
ZwMapViewOfSection(*param_4 /*\Device\PhysicalMemory*/, -1, &local_98, 0,
                   local_res10[0], &local_80, local_res10, 1, 0, 0x204);
```

No `MmGetPhysicalMemoryRanges` check, no MCFG window, no size clamp -> arbitrary physical range (any length) mapped **into the calling process**, read/write.

### MSIO32 `0x80102048` - IOPM, no token check

```c
puVar3 = MmAllocateNonCachedMemory(0x2000);
memset(puVar3, 0, 0x2000);
Ke386IoSetAccessProcess(IoGetCurrentProcess());
Ke386SetIoAccessMap(1, puVar3);
```

### NTIOLib port write `FUN_1400017ac` - see snippet in section 2 (blocks only 0x61/0x64/0xCF9).

### NTIOLib `wrmsr` `FUN_14000192c` @ `0x14000192c`

```c
uVar1 = *param_1;
if ((uVar1 == 0x150) || (uVar1 == 0x194) || (uVar1 == 0x199) || (uVar1 == 0x1a0) ||
    (uVar1 == 0x1ad) || (uVar1 == 0x1ae) || (uVar1 == 0x1af) || (uVar1 == 0x38d) ||
    (uVar1 == 0x38f) || (uVar1 == 0x610) || (uVar1 == 0x620) || (uVar1 - 0x650 < 2) ||
    (uVar1 + 0x3ffeff9e < 5)) {
      wrmsr(uVar1, *(undefined8 *)(param_1 + 1));
      ...
```

Allowlist only - **LSTAR (0xC0000082) is not reachable**. This is a materially weaker MSR primitive than EVGA's.

---

## 4. Validation gaps

| gap | NTIOLib | amifldrv | MSIO64 | MSIO32 |
|---|---|---|---|---|
| token / privilege check | none | none | none | none |
| `IoValidateDeviceIoControlAccess` | not called | not called | not called | not called |
| port allowlist | 3 ports blocked (0x61/0x64/0xCF9) | **none** | **none** | **none** |
| physical address validation | high-bit allowlist (MMIO windows) | **none** | **none** | MCFG window (v1.2 style) |
| buffer-length validation | per-IOCTL | per-IOCTL (0x10 min) | `len != 0` only | `len != 0` only |
| extra bug | - | - | - | `memcpy(local_20, SystemBuffer, len)` into a 12-byte stack slot -> kernel stack overflow for `0x803320CC`-style calls with `len > 12` |

`IRP_MJ_CREATE` in all four families only `DbgPrint`s / returns success - no `FILE_WRITE_ACCESS` check.

---

## 5. Setup required

* **none** beyond driver installation/service start. All devices are created unconditionally in `DriverEntry`; no PnP, no hardware probe.
* amifldrv's flash-path IOCTLs may fail without an AMI flash region, but `0xFA002EF0` (arbitrary write) is independent of that.
* MSIO/NTIOLib are plain WDM drivers with no firmware dependency.

---

## 6. Next dynamic test

1. Standard user on a scratch VM: `CreateFileW(L"\\\\.\\NTIOLib_MysticLight", ...)` and `CreateFileW(L"\\\\.\\genericdrv", ...)` and `CreateFileW(L"\\\\.\\MsIo", ...)` -> all should return `ERROR_ACCESS_DENIED` with the DACLs above (confirms "blocked by DACL", not "no write").
2. Read the binary DACL at runtime with `GetSecurityInfo` (or `WinObj`) if the device can be opened at all, to catch OEM images that ship a different SDDL.
3. If `\\.\MsIo` is openable: `DeviceIoControl(0x80102054, {port=0x80,value=0,width=1}, 7, ...)` is a harmless port-write probe; `0x80102040` with `{len=8, phys=<a known RAM page>}` returns a user VA - verify with `VirtualQuery` that it is user-accessible, then read a known signature (e.g. the `_KUSER_SHARED_DATA` physical page is not fixed, so pick a page discovered via `0x80102050`/PCI instead).
4. If `\\.\genericdrv` is openable: `DeviceIoControl(0xFA002EF0, {addr, width, value}, 0x10, ...)` writes 1/2/4 bytes to any physical address or I/O port.

---

## 7. Ranking within this group

1. **`MSIO64_525D9B51.SYS`** - cleanest arbitrary-write primitive: no port filter, no physical-address validation, arbitrary-length user mapping of physical memory. Blocked only by the default admin-only DACL.
2. **`amifldrv64_5F487829.sys`** - arbitrary phys/port write with zero validation; slightly less convenient (4 bytes max per call, and `HalTranslateBusAddress` decides port vs memory).
3. **`MSIO32_C7D4943D.SYS`** - adds the unauthenticated IOPM IOCTL (`0x80102048`), but the DACL is admin-only, so it adds nothing for a standard user.
4. **`NTIOLib_X64` / `NTIOLib` (x86)** - good port/PCI primitive but with real filters (port blocklist, MSR allowlist, phys high-bit allowlist) and an admin-only SDDL.

> **Bottom line for MSI:** all six are "blocked by DACL". The DACL is admin-only in every case (SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` for NTIOLib, default device SD for amifldrv/MSIO). No unprivileged path exists here.
