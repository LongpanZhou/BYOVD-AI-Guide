# Audit: CorsairVBusDriver64.sys

| Field | Value |
|---|---|
| File | `CorsairVBusDriver64_651FB6AF.sys` |
| SHA-256 | `651FB6AFD1FE4B8CE03F48EDF6930FF0470929AA979AEE8AB039A9300A871A08` |
| Analysis date | 2026-10-24 |
| Method | Static-only audit via REA/Ghidra (plus read-only objdump/PE parsing of the same bytes; no load, no execution, no service creation, no web access) |
| Reach tier | R2 - local administrator (write IOCTLs require `FILE_WRITE_ACCESS`; default DACL) |
| Setup required | none (driver load) |
| Write quality | W0 - no established kernel memory write; admin-gated double-free/UAF residual |
| Verdict | **NO-MEMORY-WRITE** (admin-gated UAF residual) - reach=R2 setup=none write=W0 load=signed |
| Image base | `0x10000` (all addresses below are image-base virtual addresses) |
| Claimed version / vendor | 3.0.88.0 / Corsair |

---

## 1. Internals

**Binary shape.** PE32+ (AMD64), 47,032 bytes, 8 sections plus a Ghidra "tdb" pseudo-segment. `.text` 0x11000-0x15A00 (~18.9 KB), `.rdata` 0x16000-0x16E00, `.data` 0x17000-0x17671, `PAGE` 0x19000-0x1AC00, `INIT` 0x1B000-0x1BA00. 155 procedures and 171 defined strings (`ev_1d17f5...`, `ev_809560...`, `ev_bb348a...`).

**Provenance.** File version 3.0.88.0, CompanyName "Corsair", OriginalFilename `CorsairVBusDriver.sys`, PDB `CorsairVBusDriver.pdb` (RSDS GUID `b6f21ec3-cd91-4842-9c35-b23c021ed3cf`). PE TimeDateStamp `0x5EFB6DFA` = 2020-06-30 16:53:14 UTC; the companion INF declares `DriverVer=07/27/2022,3.0.88.0`. The INF installs the driver as a root-enumerated device `root\CorsairBus`, class `System` (`{4d36e97d-e325-11ce-bfc1-08002be10318}`), service type 1, demand start.

**Function.** Corsair virtual bus driver. It creates an FDO for the root-enumerated device, registers one device interface, and on `IRP_MN_QUERY_DEVICE_RELATIONS(BusRelations)` creates one child PDO described as "Corsair virtual input device" with instance ID `CorsairBus\virtualdevice&10`, hardware ID `CorsairBus\virtualdevice`, and two GUID-style compatible IDs (`{e7fd4ace-ee13-11e2-afda-000c29100502}`, `{e7fd4ace-ee13-11e2-afda-000c291bbc07}`). The child is a HID-style virtual device; the FDO additionally accepts a small Corsair-private control protocol (Section 3).

**Imports.** 66 imports, all from `ntoskrnl.exe`. Notably present: `ProbeForRead`, `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `IoCreateDevice`, `IoRegisterDeviceInterface`, `MmGetSystemRoutineAddress`. Notably **absent**: `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmProbeAndLockPages`, `__writemsr64`, `WRMSR`, `READ_PORT_*`/`WRITE_PORT_*`, `Hal*`, `SeAccessCheck`, `SeSinglePrivilegeCheck`, `IoValidateDeviceIoControlAccess` call sites. There are no MDL, physical-memory, MSR or port-I/O primitives in the image.

**Statically linked support code.** `PAGE` contains a local implementation of `WdmlibIoCreateDeviceSecure` (0x19074), the OS-like secure-device path `IoDevObjCreateDeviceSecure` (0x191B8), an SDDL parser (`SepSddlSecurityDescriptorFromSDDLString` 0x1A22C, `SepSddlDaclFromSDDLString` 0x1A064, `SepSddlGetAclForString` 0x19CA4, etc.), and registry helpers (`CmRegUtil*`, `PiRegState*`). `WdmlibInit` (0x19008) resolves the real `IoCreateDeviceSecure` through `MmGetSystemRoutineAddress` (string at 0x16530) and stores it at 0x17498; the local implementation is only a fallback. The same init resolves `IoValidateDeviceIoControlAccess` (string 0x16560) and stores it at 0x174A0 - **that pointer is never read anywhere in the image** (only write is at 0x19062).

---

## 2. Entry / device / interface / SDDL

### 2.1 DriverEntry - 0x11150 (`ev_06e907...`, `ev_774dd1...`)

`DriverEntry` (called from `entry` at 0x1B064) resolves the WDM secure-device helpers, optionally initialises logging from `HKLM\...\CorsairVHID\DoLog`, and fills the dispatch table (`DRIVER_OBJECT+0x70`, index x 8):

| Offset | IRP major | Handler |
|---|---|---|
| `+0x70` | `IRP_MJ_CREATE` (0) | 0x11358 |
| `+0x80` | `IRP_MJ_CLOSE` (2) | 0x113A4 |
| `+0x90` | `IRP_MJ_WRITE` (4) | 0x12128 |
| `+0xE0` | `IRP_MJ_DEVICE_CONTROL` (14) | 0x12BE0 |
| `+0xE8` | `IRP_MJ_INTERNAL_DEVICE_CONTROL` (15) | 0x12FBC |
| `+0x120` | `IRP_MJ_POWER` (22) | 0x11644 |
| `+0x148` | `IRP_MJ_PNP` (27) | 0x11750 |
| `+0x68` | `DriverUnload` | 0x11310 |
| `DriverExtension+0x08` | `AddDevice` | 0x11444 |

All 28 major slots are first filled with the pass-through/completion stub 0x113F0 (0x11248-0x11252); unlisted majors therefore forward to the lower device or complete with the current status. `IRP_MJ_READ` (index 3, `+0x88`) is **not** overridden.

### 2.2 AddDevice and the user-facing FDO - 0x11444 (`ev_01d145...`)

```
0x114A0  IoCreateDevice(DriverObject, 0x550, NULL, 0x2A, 0x100, 0, &Fdo)
0x114FE  IoAttachDeviceToDeviceStack(Fdo, PhysicalDeviceObject)
0x1151E  Fdo->Flags &= 0xFFFFDF6B      ; clears 0x4 DO_BUFFERED_IO, 0x10 DO_DIRECT_IO,
                                        ;          0x80 DO_DEVICE_INITIALIZING, 0x2000 DO_POWER_PAGABLE
0x11528  IoRegisterDeviceInterface(PhysicalDeviceObject, &GUID_0x167D0, NULL, &DevExt->SymbolicLinkName)
```

* Device type `0x2A` = `FILE_DEVICE_BUS_EXTENDER`; extension 0x550 bytes; device name **NULL**; characteristics `0x100` = `FILE_DEVICE_SECURE_OPEN`; not exclusive.
* Clearing `DO_BUFFERED_IO` and `DO_DIRECT_IO` means `IRP_MJ_READ`/`IRP_MJ_WRITE` use **neither** buffering: the handlers receive raw user addresses in `Irp->UserBuffer` and must probe them. The write handler does so (Section 3.2).
* `IoRegRegisterDeviceInterface` is called with the **PDO** (correct WDM usage); opens through the resulting symbolic link resolve to the top of the attachment chain (this FDO), so the FDO's dispatch and security descriptor govern user access.
* `FILE_DEVICE_SECURE_OPEN` is set, so the device's DACL is enforced even for opens that arrive through the interface symlink rather than `\Device`.
* The interface is enabled on `IRP_MN_START_DEVICE` (`IoSetDeviceInterfaceState(DevExt+0x538, TRUE)` at 0x1181E).

**Registered interface GUID.** `IoRegisterDeviceInterface` receives `&DAT_000167D0`. The 16 bytes at 0x167D0 are `DE D0 BA 2A DC 4D 65 49 8D 7A 7F AF 3B 7F 1D 59` (`ev_c46142...`), i.e.:

```
{2ABAD0DE-4DDC-4965-8D7A-7FAF3B7F1D59}
```

There is no device name string and no `IoCreateSymbolicLink` import; the only user-mode name for the FDO is this interface symlink. The other 16-byte value at 0x167C0 (`{8D87BEAF-AA9D-4163-8B02-FEE021B77E75}`) is the bus-type GUID returned for `IRP_MN_QUERY_BUS_INFORMATION` (0x13712), not an interface.

**Security descriptor of the FDO: none.** `IoCreateDevice` takes no SDDL and the driver never calls `ZwSetSecurityObject`, `RtlSetDaclSecurityDescriptor` or `ObOpenObjectByPointer` in its own code (those imports exist only inside the linked secure-device fallback, 0x1910C-0x1919C, which is not reached for the FDO). The companion INF has no `[Security]` section and no `AddReg` of a `Security` value. The FDO therefore receives the I/O manager's **default device DACL**: full access for `SYSTEM` and `BUILTIN\Administrators`, read-only (`FILE_GENERIC_READ`) for `Everyone`. That default is an OS property rather than bytes in this SYS, but it is exactly the "...(A;;GR;;;WD)" shape that appears in this binary's own SDDL table at 0x16320, and no package component overrides it.

### 2.3 Child PDO and the only `IoCreateDeviceSecure` call - 0x11D74 (`ev_be06f6...`)

`BusCreateChildDevice` (called from the BusRelations path at 0x12004) executes:

```
0x11DBB  lea rax, [0x162C0]                 ; PUNICODE_STRING DefaultSDDLString
0x11DC2  edx = 0x48                         ; DeviceExtensionSize
0x11DC6  r8  = 0                            ; DeviceName = NULL
0x11DCE  rcx = DriverObject
0x11DD6  [rsp+0x20] = 0x180                 ; FILE_AUTOGENERATED_DEVICE_NAME | FILE_DEVICE_SECURE_OPEN
0x11DD1  [rsp+0x28] = 0                     ; Exclusive = FALSE
0x11DC9  [rsp+0x30] = &UNICODE_STRING_0x162C0
0x11DDE  call WdmlibIoCreateDeviceSecure
```

`WdmlibIoCreateDeviceSecure` (0x19074, `ev_1104ed...`) trampolines to the real `IoCreateDeviceSecure` resolved at run time (fallback 0x191B8 if absent), forwarding the same SDDL pointer. Device type is `0x22` (`FILE_DEVICE_UNKNOWN`).

**The SDDL actually passed is the admin-only literal.** The `UNICODE_STRING` at 0x162C0 is `{Length=0x36, MaximumLength=0x38, Buffer=0x16288}`; 0x16288 contains 27 UTF-16 characters (`ev_b0e165...`):

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)
```

Decoded: protected DACL (`P`), `GENERIC_ALL` to `NT AUTHORITY\SYSTEM` (`SY`) and `BUILTIN\Administrators` (`BA`). **No `WD` (Everyone) ACE, no `RC` (Restricted Code) ACE, no write ACE for any unprivileged principal.**

After creation the PDO extension (0x48 bytes) is initialised at 0x11E37-0x11E78 with the instance ID, hardware ID, compatible-ID GUIDs and description listed in Section 1; the PDO is a named-but-auto-generated `\Device\...` object with no DOS symlink and no device interface, so it is not user-openable by name.

### 2.4 The seven-SDDL family: only one is live

The image contains seven SDDL strings and six wrapping `UNICODE_STRING`s:

| # | String VA | `UNICODE_STRING` | SDDL | Referenced in code? |
|---|---|---|---|---|
| 1 | 0x16258 | 0x16278 | `D:P(A;;GA;;;SY)` | no |
| 2 | **0x16288** | **0x162C0** | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | **yes - 0x11DBB, the child PDO** |
| 3 | 0x162D0 | 0x16310 | `D:P(A;;GA;;;SY)(A;;GRGX;;;BA)` | no |
| 4 | 0x16320 | 0x16378 | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR;;;WD)` | no |
| 5 | 0x16390 | 0x16400 | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR;;;WD)(A;;GR;;;RC)` | no |
| 6 | 0x16410 | 0x16488 | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)` | no |
| 7 | 0x164A0 | (none found) | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)` | no |

Only entry #2 has a code reference (the RIP-relative `lea` at 0x11DBB). A whole-image scan for 4- and 8-byte pointers to the six `UNICODE_STRING` addresses and to the string buffers found none, and the complete `lea ...# 0x16xxx` inventory contains no other SDDL address. The permissive `WD` variants - the ones that would make the driver world-writable - are **dead data** in this build, not an alternate runtime policy.

### 2.5 Effective DACL, resolved as far as the package allows

* **Child PDO:** explicit, protected, admin-only SDDL (#2). Effective and restrictive.
* **FDO (the only user-reachable object):** no explicit SDDL; OS default device DACL (SYSTEM/Administrators full, Everyone read), enforced because `FILE_DEVICE_SECURE_OPEN` is set. The INF adds no security override.
* **Net effect:** an unprivileged user may open the interface `{2ABAD0DE-...}` for read and can issue only IOCTLs whose `CTL_CODE` access field is `FILE_READ_ACCESS`; anything requiring `FILE_WRITE_DATA` is denied by the I/O manager before dispatch. Section 3 shows that every state-changing IOCTL is `FILE_WRITE_ACCESS` and that `IRP_MJ_WRITE` is likewise gated.

---

## 3. IOCTL table

### 3.1 Dispatch - `IRP_MJ_DEVICE_CONTROL` at 0x12BE0 (`ev_ff897b...`)

The handler compares `IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode` (`[IoStack+0x18]`) against six codes; everything else returns `STATUS_INVALID_DEVICE_REQUEST` (0xC00000BB) via the common exit at 0x12D94. All codes use device type `0x2A`.

| IOCTL | Function | Method | Access | Handler | Kernel action | Bounds / checks |
|---|---|---|---|---|---|---|
| `0x2A6004` | 0x801 | 0 BUFFERED | `FILE_READ_ACCESS` (0x4000) | 0x12D44 | `memcpy(SystemBuffer, "3.0.88", 7)`; `Information=7` | `OutputBufferLength >= 7` (0x12D72) |
| `0x2A6008` | 0x802 | 0 BUFFERED | `FILE_READ_ACCESS` | 0x12D44 | `memcpy(SystemBuffer, ".0.88", 14)` incl. NUL; `Information=14` | `OutputBufferLength >= 14` |
| `0x2AA010` | 0x804 | 0 BUFFERED | `FILE_WRITE_ACCESS` (0x8000) | 0x126DC, then 0x12908 | "SetReportDescriptor": compare against stored descriptor, allocate `InputBufferLength`, copy from `SystemBuffer`, free/replace `DevExt+0x28`/`+0x38`; on change restart child devices | length == stored (`+0x38`) or full alloc; no upper cap beyond pool; **no lock** |
| `0x2AA014` | 0x805 | 0 BUFFERED | `FILE_WRITE_ACCESS` | 0x12CA9 | allocate `InputBufferLength`, `memcpy` from `SystemBuffer`, free/replace `DevExt+0x30` | zero length rejected (0xC000000D); alloc failure 0xC000009A; **no lock** |
| `0x2AA018` | 0x806 | 0 BUFFERED | `FILE_WRITE_ACCESS` | 0x12C76 | `*(u32 *)(DevExt+0x40) = *(u32 *)SystemBuffer`; `Information=4` | `InputBufferLength == 4` else 0xC0000206 |
| `0x2AA01F` | 0x807 | 3 **METHOD_NEITHER** | `FILE_WRITE_ACCESS` | 0x12C6E -> 0x12908 | restart child devices / invalidate relations | **does not read `Type3InputBuffer` or `UserBuffer` at all** |

Notes:

* The two version IOCTLs copy constant strings. `0x2A6004` checks `OutputBufferLength` (offset +8) against 7; `0x2A6008` computes the length with a `wcslen`-style loop over 0x15320 (`.0.88`) and copies 14 bytes including the NUL. Both are `METHOD_BUFFERED`, so the destination is the I/O manager's system buffer sized `max(Input,Output)`; the check cannot be bypassed to overflow it.
* `0x2AA010`/`0x2AA014` are the only calls that accept variable-length caller data. `SystemBuffer` is a kernel copy made by the I/O manager; the `memcpy` length is exactly `InputBufferLength`, which cannot exceed the allocation. The resulting pointer is a pool block owned by the device extension.
* `0x2AA018` is a **fixed-field** 4-byte write at `DevExt+0x40`; the address is not caller-influenced.
* `0x2AA01F` uses neither I/O precisely because it ignores the buffers; it only sets `DevExt+0x549..0x54B` and calls `IoInvalidateDeviceRelations(DevExt+0x18, 0)` in 0x12908.

### 3.2 `IRP_MJ_WRITE` at 0x12128 (`ev_61ed5c...`)

This is the HID-input-report path. Because `DO_BUFFERED_IO`/`DO_DIRECT_IO` are cleared (0x1151E), the IRP carries a raw user pointer in `Irp->UserBuffer` (`Irp+0x70`):

```
0x1213F-0x12181  stack cookie / KeInitializeEvent
0x12239          if (Write.Length < 2)              -> 0xC0000206
0x12244-0x12256  if (Write.Length - 1 < 5)          -> 0xC0000206   ; requires length >= 6
0x1225C-0x12266  ProbeForRead(Irp->UserBuffer, Write.Length, 1)
0x12275          p = UserBuffer + 1
0x122DA-0x12300  loop: len32 = *(u32 *)p; if (len32 + 4 + consumed > Write.Length - 1) -> 0xC0000206
0x12300          if (len32 > 0x41)                  -> 0xC000000D
0x12311-0x12357  zero a 0x45-byte ring entry, copy 0x45 bytes from the 16-entry ring
0x123AB-0x123BB  entry->length = len32; memcpy(entry+4, p+4, len32)
0x123D2-0x123EC  advance p by len32+4; stop when consumed == Write.Length-1
```

The `ProbeForRead` covers the full declared `Write.Length`, and every subsequent read (`*(u32 *)p`, `memcpy(p+4, len32)`) lies inside that probed range: the loop refuses to start a record whose 4-byte header plus payload would exceed `Write.Length-1`. The destination entry is 0x45 bytes and `len32 <= 0x41`, so `4 + 0x41 = 0x45` is an exact fit. The ring head is masked to 0..15 (`0x12384`, `0x12394`). This path is memory-safe.

The 16-entry ring is at `DevExt+0x4E0` (buffer pointer `+0x4D0`, head `+0x4D8`, tail `+0x4DC`); access is serialised by the fast mutex acquired through 0x11084 at 0x121C8 and released by 0x110F4. No user-controlled pointer or size reaches a write destination here.

### 3.3 `IRP_MJ_INTERNAL_DEVICE_CONTROL` at 0x12FBC (`ev_a90a8b...`)

Kernel-only path (`IRP_MJ_INTERNAL_DEVICE_CONTROL` cannot be issued by `NtDeviceIoControlFile`). It accepts only IOCTL `0xB000B` (`IOCTL_HID_READ_REPORT`) and only when the device extension type dword is 0 (FDO); anything else returns `0xC00000BB`. It acquires the mutex, queues the IRP on the `DevExt+0x4E0` pending list, marks it pending and installs a cancel routine (0x12ECC). When a report arrives, `FUN_00012DE0` (0x12DE0, `ev_96e3f6...`) completes it:

```
0x12E25  outLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength
0x12E29  if (storedReportLength > outLen) -> 0xC0000023 (BUFFER_TOO_SMALL)
0x12E5C  copyLen = min(storedReportLength, outLen)
0x12E73  memcpy(Irp->UserBuffer, storedReport+4, copyLen)
```

Both sides are length-checked; the destination is the buffer supplied by the kernel HID client.

### 3.4 `IRP_MJ_CREATE` / `IRP_MJ_CLOSE`

`0x11358` (`ev_6d1b1a...`) logs and completes `IRP_MJ_CREATE` with `STATUS_SUCCESS`, `Information=0`, for every request. `0x113A4` does the same for close. **No desired-access mask, impersonation, `RequestorMode`, or caller-identity inspection occurs in either handler** - the DACL check performed by the object manager is the only gate.

---

## 4. Access-control audit

| Control | Present? | Evidence |
|---|---|---|
| Explicit SDDL on user-facing FDO | **No** | 0x114A0 `IoCreateDevice(..., NULL, 0x2A, 0x100, 0, ...)`; no `ZwSetSecurityObject` call anywhere |
| Explicit SDDL on child PDO | **Yes**, admin-only | 0x11DBB/0x11DDE, string at 0x16288 |
| `FILE_DEVICE_SECURE_OPEN` | Yes, both objects | characteristics 0x100 (FDO), 0x180 (PDO) |
| Device interface enabled | Yes | 0x1181E `IoSetDeviceInterfaceState(..., TRUE)` |
| DOS device link / named symlink | No | no `IoCreateSymbolicLink` import; only the interface GUID |
| `SeAccessCheck` / `SeSinglePrivilegeCheck` | No | not imported; no call sites |
| `RequestorMode` check in dispatch | No | 0x11358, 0x12BE0, 0x12128, 0x12FBC contain no `Irp+0x40` test |
| `IoValidateDeviceIoControlAccess` | Resolved but **never called** | pointer stored at 0x174A0 (0x19062), zero readers |
| Reliance on `CTL_CODE` access bits | Yes | four of six IOCTLs are `FILE_WRITE_ACCESS`; two are `FILE_READ_ACCESS` |
| `ProbeForRead` on raw user buffer | Yes, full length | 0x1225C-0x12266 (`Write.Length`, alignment 1) |
| Output-length validation before copy | Yes | 0x12D72 (version), 0x12E29 (HID read completion) |
| Locking on descriptor mutation | **No** | 0x126DC and 0x12CA9 mutate `DevExt+0x28/+0x30` without the 0x11084 mutex used by `IRP_MJ_WRITE` |

**Reachability.** The FDO is unnamed and only reachable through the interface symlink `{2ABAD0DE-4DDC-4965-8D7A-7FAF3B7F1D59}`. With `FILE_DEVICE_SECURE_OPEN` set, the object manager evaluates the FDO's default DACL on that path. Under the default DACL a standard user obtains `FILE_GENERIC_READ` only, so:

* `0x2A6004` / `0x2A6008` (`FILE_READ_ACCESS`) are callable and return constant version strings.
* `0x2AA010`, `0x2AA014`, `0x2AA018`, `0x2AA01F` (`FILE_WRITE_ACCESS`) are rejected by the I/O manager with `STATUS_ACCESS_DENIED` before reaching 0x12BE0.
* `WriteFile` (`IRP_MJ_WRITE`) requires `FILE_WRITE_DATA` on the handle and is likewise rejected.

The child PDO is auto-named in `\Device` and has no symlink or interface; it is reachable only by kernel components holding its `PDEVICE_OBJECT` (its own SDDL is admin-only in any case).

If the default DACL were relaxed to `Everyone: FILE_GENERIC_WRITE` by an out-of-package registry/class-installer `Security` value (not present in the supplied INF), the four write IOCTLs and `IRP_MJ_WRITE` would become reachable by any local user. The audit therefore evaluates them for memory safety independently of the DACL (Section 5).

---

## 5. Most dangerous exposed capability

### 5.1 The strongest primitive: unsynchronised descriptor replacement (pool double-free / UAF)

`0x2AA010` -> `FUN_000126DC`:

```
0x1272A  old = DevExt->ReportDescriptor      (+0x28)
0x12733  oldLen = DevExt->ReportDescriptorLength (+0x38)
0x1275F  memcmp(SystemBuffer, old, ...)
0x127AB  new = ExAllocatePoolWithTag(NonPagedPool, InputBufferLength, 'BSF4')
0x1284C  ExFreePoolWithTag(old, 0)           ; old pointer not cleared before free
0x12854  DevExt->ReportDescriptor = NULL
0x1286C  DevExt->ReportDescriptor = new
```

`0x2AA014` performs the same free/replace on `DevExt+0x30` at 0x12D12-0x12D23. Neither path acquires the device fast mutex (0x11084) that `IRP_MJ_WRITE` takes at 0x121C8, and I/O manager dispatch does not serialise IOCTLs. Two threads issuing the same IOCTL concurrently can both observe the same `old` pointer and both free it (double free), or one can free a buffer the other has just published (use-after-free). The resulting pool corruption is the most serious defect in the driver.

However:

* It requires a handle with `FILE_WRITE_DATA`; under the shipped package that means an administrator/SYSTEM context.
* It is a **heap lifetime** bug, not an address-controlled write: the freed/replaced pointers come from `ExAllocatePoolWithTag`, never from the request.

### 5.2 Report-descriptor injection

`0x2AA010`/`0x2AA014` let a write-capable caller install an arbitrary-length HID report descriptor into the device extension. The buffer is later consumed to describe the virtual HID child. A malformed descriptor is parsed by the HID class stack (and/or `CorsairVHidDriver`), outside this image; any resulting memory-safety impact would live in those components. This is a supply-chain/attack-surface concern for a privileged caller, not a kernel write primitive in this driver.

### 5.3 What is *not* present

* No write to a caller-supplied kernel address anywhere: the only direct user-data write is `DevExt+0x40 = *(u32 *)SystemBuffer` (0x12C93), a fixed offset in the device extension.
* No `METHOD_NEITHER` buffer dereference: the single neither-method IOCTL (`0x2AA01F`) ignores both buffers (0x12C6E -> 0x12908).
* No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, MDL mapping, MSR access or port I/O imports (Section 1).
* No user-controlled allocation size reaches a copy destination unbounded: `0x2AA010/0x2AA014` copy exactly `InputBufferLength` from the I/O manager's system buffer; the ring path bounds each record by `0x41` and by the probed `Write.Length`.
* No uninitialised-memory return to user mode: the version strings are constants; the HID read completion copies from a ring entry that was zeroed before filling (0x12311).
* No arbitrary kernel **read** exposed to user mode either: the two read IOCTLs return compile-time strings.

### 5.4 Direct answer to the central question

**No unprivileged user can reach a kernel memory write through this driver.** The only user-openable object (the FDO behind interface `{2ABAD0DE-...}`) has no explicit SDDL and therefore the default read-only-for-Everyone DACL; every state-changing operation is `FILE_WRITE_ACCESS`/`FILE_WRITE_DATA`-gated, and even with write access the code contains no attacker-address write. The explicit SDDL in the binary is admin-only and applies to the non-user-reachable child PDO. The seven-SDDL table is a red herring: six of seven literals, including every `Everyone` (WD) variant, are unreferenced.

---

## 6. VERDICT

**NOT A KERNEL MEMORY-WRITE PRIMITIVE. No unprivileged kernel write.**

| Question | Finding | Confidence |
|---|---|---|
| Which SDDL reaches `IoCreateDeviceSecure`? | Exactly one call site (0x11DDE) with `UNICODE_STRING` 0x162C0 -> `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (admin-only), for the child PDO | High (string + struct + call site) |
| Are the Everyone/WD SDDL variants used? | No; six of seven, including all `WD` variants, are dead data | High (no xrefs/pointers) |
| Which interface GUID is registered? | `{2ABAD0DE-4DDC-4965-8D7A-7FAF3B7F1D59}` at 0x167D0, registered at 0x11528, enabled at 0x1181E | High |
| Does the interface lead to the FDO? | Yes - interface registered on the PDO, opens resolve to the attached FDO, which owns the dispatch table | High (WDM semantics + FDO handlers) |
| Is the FDO protected by an explicit DACL? | No; OS default device DACL, `FILE_DEVICE_SECURE_OPEN` set, no INF override | Medium-high (OS default is not bytes in the SYS) |
| Can an unprivileged user issue write IOCTLs? | No (default DACL denies `FILE_WRITE_DATA`; all four write IOCTLs are `FILE_WRITE_ACCESS`) | Medium-high |
| Even with write access, is there an arbitrary kernel write? | No. Fixed-offset 4-byte write, bounded pool copies, bounded ring copies | High |
| Most serious residual issue | Unsynchronised free/replace of the report descriptor (`0x126DC` / `0x12CA9`) -> double-free/UAF pool corruption, write-handle (admin) only | High on the race; exploitation not demonstrated |

**Residual risk.** If a future package/INF grants `Everyone` write access to the interface (or the device is opened by a SYSTEM service and the handle is shared), the descriptor IOCTLs become reachable and the double-free race is a credible local pool-corruption primitive - but it is a lifetime bug, not an address-controlled write, and it still does not by itself constitute an unprivileged arbitrary kernel write.

---

## 7. Limitations

1. **Static only.** No driver load, IOCTL replay, DACL inspection or pool debugging was performed. All conclusions are from bytes and control flow.
2. **Effective DACL of the FDO is inferred.** `IoCreateDevice` does not embed the SD; the "SYSTEM/Administrators full, Everyone read" default is OS behaviour, corroborated by the absence of any SDDL/`ZwSetSecurityObject` path in the driver and by the INF having no `[Security]`/`AddReg` override. A pre-existing class-key `Security` value or a modified INF could change it.
3. **Shared REA/Ghidra backend.** During the audit the single Ghidra session was repeatedly switched by concurrent analyses; every REA result cited here was accepted only when `subject.digest.sha256` matched the target. Several results (notably the `0x11444`, `0x11D74`, `0x12BE0`, `0x12128` pseudocode and the 0x16280/0x167D0 byte reads) carry evidence IDs; for the remaining instruction-level claims the same bytes were disassembled locally with `objdump` and cross-checked against the REA listing. Evidence IDs are listed below.
4. **Sample removed mid-audit.** The `_collected5\agentR1\new` tree was deleted by the environment after the analysis and byte extraction completed. All cited addresses and bytes were captured before removal; the SHA-256 is the pinned identity.
5. **Companion INF not signature-verified.** The INF was read for security-relevant directives only; the `.cat` was not validated. The audit target remains the SYS.
6. **Child HID stack out of scope.** `CorsairVHidDriver64` (present in the same collection) and `hidclass.sys` parse the descriptor installed by `0x2AA010`; report-descriptor parsing bugs there were not assessed.
7. **Function boundaries.** Ghidra/objdump boundaries can merge tail code; addresses are exact, but a function label may cover more than one logical routine (e.g., 0x12BE0 contains the inline 0x2AA014 path).
8. **No fuzzing or symbolic execution.** The absence of a write primitive is established by enumerating all writes with user-influenced sources, not by exhaustive proof.

---

## Appendix A - Key evidence

| Evidence ID | Operation | Content |
|---|---|---|
| `ev_1d17f5cad2ea80c8433b996ac83ae1751d78bc076c541310de3b1e2323a599` | `binary_overview` | PE64, image base 0x10000, section map, 155 procedures / 171 strings |
| `ev_80956076d0da75217a7bc3c797910ca745ecb8686e85f443e591fa63fb2c2f1b` | `list_procedures` | import/export inventory; no MmMap/MSR/port I/O imports |
| `ev_bb348a222163a8e950475d5fbf8a2b87c1eb736418bc8415a53d86a47ffa249f` | `list_strings` | version 3.0.88, `CorsairVHID`, `IoCreateDeviceSecure`, GUID strings |
| `ev_774dd182fe73b42a6e232eed059a8f667e5261f6621685dead1ff0b103250f0d` | `procedure_pseudo_code` | `entry` -> `FUN_0001b008`, `FUN_00011150` |
| `ev_06e90744a5eb88a0e50f8d2d3a04ac682702a233a3522a135c6e6e4b820e8cbf` | `procedure_pseudo_code` | DriverEntry 0x11150 dispatch-table construction |
| `ev_6d1b1adb2c05363e4079747e0590f489eeb1640c6fe282125abbb9d2f88ed14d` | `procedure_pseudo_code` | IRP_MJ_CREATE 0x11358, unconditional success |
| `ev_01d145131fe7535f8f988e65b6cda405f047e1a2676c2e7d6ba0cec8f1e3a04d` | `procedure_pseudo_code` | AddDevice 0x11444: `IoCreateDevice(...,0x550,NULL,0x2A,0x100,0,...)`, `IoRegisterDeviceInterface(...,&DAT_000167d0,...)` |
| `ev_be06f6dcccae42030b3fea957cd495f260419535a355bcd517197ceaebe03c5b` | `procedure_pseudo_code` | Child create 0x11D74 -> `WdmlibIoCreateDeviceSecure(...,&DAT_000162c0,...)` |
| `ev_1104ed2f763610a2b57cfac15047d3dab0da7f3e2297f814f0ae3649d8ea09d4` | `procedure_pseudo_code` | `WdmlibIoCreateDeviceSecure` trampoline to the resolved OS API |
| `ev_b0e1653c72c7f3c0e985a0728f7ca74b82f196f0f64d7a549636751843564e2b` | `read_bytes` 0x16280 | `UNICODE_STRING` at 0x162C0 and UTF-16 `D:P(A;;GA;;;SY)(A;;GA;;;BA)` at 0x16288 |
| `ev_c4614270f54e4d829153a125b0e9b87aa2e5c3a55183b4936cd0212dee4fee4a` | `read_bytes` 0x167D0 | Interface GUID `{2ABAD0DE-4DDC-4965-8D7A-7FAF3B7F1D59}` |
| `ev_ff897bd5c30508e81f17ca961db85b6f90a66be01da4604531bfece9de3ef279` | `procedure_pseudo_code` | DeviceControl 0x12BE0: six-IOCTL switch, version copies, fixed-field write, descriptor replace |
| `ev_61ed5ceb3919ea41b8f7168ba45ed28ee92d528a9288249606a4bc042b5116d4` | `procedure_pseudo_code` | IRP_MJ_WRITE 0x12128: `ProbeForRead(UserBuffer, Write.Length, 1)`, bounded record parse |
| `ev_a90a8bfdbc74d564d7e33ed82821098cc1960f61b4572c2b5b618a53b69e8d83` | `procedure_pseudo_code` | InternalDeviceControl 0x12FBC: only 0xB000B, pending-queue |
| `ev_96e3f63977063a530e13f0ad8ce6f3473e2f6e68a438b043f2a96343fdd7ee71` | `procedure_pseudo_code` | Completion 0x12DE0: output-length check then `memcpy(Irp->UserBuffer, ...)` |

## Appendix B - Address index

| Address | Item |
|---|---|
| 0x11150 | DriverEntry |
| 0x11444 | AddDevice |
| 0x114A0 | `IoCreateDevice` (FDO, type 0x2A, char 0x100) |
| 0x1151E | FDO flag clear (removes BUFFERED/DIRECT IO) |
| 0x11528 | `IoRegisterDeviceInterface` |
| 0x1181E | `IoSetDeviceInterfaceState(TRUE)` |
| 0x11D74 | `BusCreateChildDevice` |
| 0x11DBB / 0x11DDE | SDDL argument / `WdmlibIoCreateDeviceSecure` |
| 0x16288 | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` |
| 0x162C0 | `UNICODE_STRING` for the above |
| 0x167D0 | Interface GUID |
| 0x11358 / 0x113A4 | CREATE / CLOSE |
| 0x12128 | WRITE |
| 0x126DC | SetReportDescriptor core |
| 0x12908 | Restart child devices |
| 0x12BE0 | DEVICE_CONTROL |
| 0x12FBC | INTERNAL_DEVICE_CONTROL |
| 0x19008 / 0x19074 / 0x191B8 | WdmlibInit / WdmlibIoCreateDeviceSecure / local secure-create fallback |
