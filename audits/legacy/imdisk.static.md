# imdisk.sys static audit (x64, full depth) and ARM64 structural diff

Static only. Nothing was loaded, installed, started or executed. Ghidra 12.1.4 (`DumpAllDecomp.java`, `DumpAsm.java`, read-only) on the canonical files under `drivers\ImDisk\`. x64: 59 functions decompiled, 0 failures, 0 timeouts. Corpus hashes were re-checked at the end: unchanged. Only two ImDisk builds exist in the corpus (x64, ARM64); no byte-identical duplicates.

Analysis dumps are in `C:\Users\<scrubbed>\AppData\Local\Temp\claude\C--Users-<scrubbed>\f675ee28-909f-4610-bb22-f57f1b1e06ab\scratchpad\c3\imdisk\` (`dump_x64.txt`, `asm_x64.txt`, `asm_x64_tail.txt`, `dump_arm64.txt`, `iat\x64_iat.txt`).

## 1. Verdict

| Binary | SHA256 (prefix) | PE timestamp (UTC) | Verdict | Setup required |
|---|---|---|---|---|
| `imdisk.sys` (x64, PE32+, machine 0x8664) | 3CFC11F2 | 2026-06-15 09:17:34 | **NO-WRITE** | none (driver load only) |
| `imdisk_arm64.sys` (ARM64, machine 0xAA64) | 48ED9FF2 | 2026-06-15 09:17:49 | not audited (structural diff only) | none (driver load only) |

**NO-WRITE reason (x64):** no traced path reaches an attacker-chosen kernel virtual address, physical address or I/O port. The one out-of-range write (section 5, item 1) is a fixed-value fill at a driver-allocated base with an attacker-chosen 32-bit offset, which is Corruption, not write.

**Reachability is NOT resolved.** The driver sets no DACL on any device, and the Microsoft documentation I fetched does not state the kernel default for a named `IoCreateDevice` object created outside PnP. "DEFAULT-ADMIN" is therefore an assumption here, not a verified result. The verdict does not depend on it, because no primitive was found.

**Setup cost:** the INF (`imdisk.inf`) contains only `AddService` for kernel service `ImDskDrv` (`ServiceType=1`, `StartType=2`) and helper service `ImDskSvc`. It has no hardware IDs, no devnode and no `AddReg Security` line. Driver load is the corpus baseline, so setup is `none`. The helper service is not needed for the device CREATE path.

**Q-answers in brief:**
- Q1 (devices): two device objects are created by the driver: `\Device\ImDiskCtl` (DriverEntry) and `\Device\ImDisk<N>` (on demand). The other four names in the master table are opened, not created. The only explicit DACL in the driver is a NULL DACL on the named event `\BaseNamedObjects\Global\ImDiskRefresh`, which is not a device.
- Q2 (collision): none. The driver never creates `\Device\MountPointManager` or `\Device\NamedPipe\ImDskSvc`.
- Q3 (dispatch): section 4.
- Q4 (sinks): no PHYS, no PORT, no traced KVA. One Corruption lead (section 5).
- Q5 (standard user): UNKNOWN for both devices. Not assumed.

**ARM64 structural diff (not audited):**
- Same device creation shape: `IoCreateDevice(DriverObject, 0x130, "\Device\ImDiskCtl", 0x8372, 0x20000, Exclusive 0)` (dump line 8973), same symlink call (line 8984), per-disk `IoCreateDevice` present (line 7582), NULL-DACL event (line 9156-9158), same DRIVER_OBJECT offsets (+0x68, +0x70, +0x80, +0x88, +0x90, +0xA0, +0xB8, +0xE0, +0xE8, +0x148).
- Differences: 51 functions (x64: 59). Imports differ: ARM64 adds `ExInterlockedInsertTailList`, `ExInterlockedRemoveHeadList`, `KeAcquireSpinLockRaiseToDpc`, `KeReleaseSpinLock`, `KeGetCurrentThread`, `RtlIsZeroMemory`. x64 has `KeAcquireInStackQueuedSpinLock`, `KeReleaseInStackQueuedSpinLock`, `RtlCompareMemoryUlong`, `strlen`, `wcslen`. The IOCTL constant sets differ: x64-only `0x8372E005`, `0x83722009`; ARM64-only `0x8372E011`, `0x8372E01C`, `0x8372E01D`, `0x8372E020`. The ARM64 build is a different revision of the IOCTL switch and is not audited.
- ARM64 registrations: +0x70 `FUN_1400028A0`, +0xE0/+0xE8 `FUN_140002D20`, +0x148 `FUN_1400045D0`, +0x68 `FUN_14000CBC0`.
- The x64 memset site (section 5, item 1) was not located in the ARM64 decompile (no 0xF6 fill call seen).

## 2. Evidence block

None. No finding meets the four-part standard (entry point, sink, control, class) for x64. The Corruption lead in section 5 is recorded there, not here.

## 3. Precondition table

DriverEntry is `entry` at `0x14000E5F0`. All DACL and device-creation addresses below are instruction addresses from `asm_x64.txt` / `asm_x64_tail.txt`.

| Device | Created in | Symbolic link | DACL and source | Setup | Standard user can open? |
|---|---|---|---|---|---|
| `\Device\ImDiskCtl` | DriverEntry. `IoCreateDevice` at `0x14000E8C9`: DriverObject=RSI, ext=0x130, DeviceType=0x8372, Characteristics=0x20000, Exclusive=FALSE per decompile. | `\DosDevices\ImDiskCtl` via `IoCreateUnprotectedSymbolicLink` at `0x14000E916` (return value not checked). | **None set in code.** No `IoCreateDeviceSecure`, no `ZwSetSecurityObject`, no SDDL string in the dump. Default is the kernel default for a named `IoCreateDevice` object. Not verified; the fetched MS pages do not state it for this case. The PnP default ("administrators full, everyone else read/write/execute") applies to PnP-stack objects, which this driver does not create. | none | **UNKNOWN.** Needs the dynamic test in section 7. |
| `\Device\ImDisk<N>` (N from IOCTL config or max+1 via `FUN_140001410`) | `FUN_14000B000` (core create). `IoCreateDevice` at `0x14000C437`: ext=0x130, DeviceType=R12D (0x7 default; 0x2 for flag 0x30; 0x22 for flag 0x40), Characteristics=0x20000 plus removable/read-only bits from Flags (R8D/ECX/EBX logic at `0x14000C249`-`0x14000C293`), Exclusive=0 (`MOV byte [RSP+0x28],0` at `0x14000C42E`). Callers: IOCTL 0x8372E004 via `FUN_14000C900`, and boot registry (`FUN_14000E000`, `Parameters\FileName<N>` etc.). | `\DosDevices\ImDisk<N>` via `IoCreateUnprotectedSymbolicLink` at `0x14000C4A1` (failure path deletes the device). Drive-letter link `\DosDevices\Global\<X>:` at `0x14000CC02` (in `FUN_14000C900`). | Same as above: **none set in code**, kernel default not verified. No FILE_DEVICE_SECURE_OPEN (0x100) in Characteristics. | none (IOCTL on ctl device, or boot registry as admin) | **UNKNOWN.** Same test. |
| `\Device\AWEAlloc` | **Not created.** Opened only: `ZwCreateFile("\Device\AWEAlloc"+suffix)` in `FUN_14000B000` (LEA at `0x14000B370`). | none | n/a | n/a | n/a. Collision: none (not created). |
| `\Device\NamedPipe\ImDskSvc` | **Not created.** Client open in `FUN_14000B000` (LEA at `0x14000B3B9`, `ZwCreateFile` path). The master table's "`\Device\NamedPipe`" is a truncated name. | none | n/a | n/a | n/a. Collision: none (not created). |
| `\Device\MountPointManager` | **Not created.** Opened by `IoGetDeviceObjectPointer` at `0x14000CDAC` (`FUN_14000CD70`, access 0x80). IOCTLs sent via `IoBuildDeviceIoControlRequest` `0x14000CE0E` and `IofCallDriver` `0x14000CE38`. Codes passed from `FUN_14000C900`: 0x006D402C, 0x006DC000 (names not verified). | none | n/a | n/a | n/a. Collision: none (not created). |
| `\BaseNamedObjects\Global\ImDiskRefresh` (event, not a device) | DriverEntry: `ZwCreateEvent` at `0x14000EA6F`; fallback name `\BaseNamedObjects\ImDiskRefresh` at `0x14000EAA5` when status is 0xC000003A. | none | **NULL DACL.** `RtlCreateSecurityDescriptor` at `0x14000EA0E`, `RtlSetDaclSecurityDescriptor` at `0x14000EA27` with DaclPresent=1 (DL=1), Dacl=0 (R8D=0), Defaulted=0. Any user gets full access to the event. | none | **Yes** (NULL DACL). This is the only explicit permissive DACL in the driver. It is not a device, and by itself it is not a finding. |

**Q2 (collision):** no driver-created name collides with an OS device. `\Device\ImDiskCtl` and `\Device\ImDisk<N>` are created by `IoCreateDevice`. Failure returns the NTSTATUS. In `FUN_14000B000` the failure path calls `IoDeleteDevice` at `0x14000C4B5` when the symlink fails. In DriverEntry the `IoCreateDevice` failure returns the status. `IoCreateUnprotectedSymbolicLink` for `\DosDevices\ImDiskCtl` (`0x14000E916`) has no status check. MountPointManager and NamedPipe are never created, so no collision branch exists for them.

**Q5 detail:** FILE_DEVICE_SECURE_OPEN is absent from both Characteristics values. The IoCreateDevice documentation I fetched says "most drivers specify FILE_DEVICE_SECURE_OPEN". This driver's CREATE/CLOSE handler `FUN_1400027A0` rejects any open with a remaining path (`FILE_OBJECT.FileName.Length != 0` returns 0xC0000034), so the missing flag does not create a suffix-open bypass in this code.

**Control-gate summary:** the only user-mode gate beyond the DACL is `SeSinglePrivilegeCheck(LUID 7 = SE_TCB)` on IOCTL 0x8372E010 (`0x140003979`). CREATE (0x8372E004), REMOVE (0x8372E018) and the disk query/format IOCTLs have no privilege check in the driver. Their only gate is the DACL, which is unverified.

## 4. Callback or IOCTL table

**Dispatch routines (x64 DRIVER_OBJECT offsets, set in DriverEntry):**

| Offset | Major function | Routine |
|---|---|---|
| +0x68 | DriverUnload | `FUN_14000D260` (only its IoDeleteSymbolicLink/IoDeleteDevice call sites seen; body not traced) |
| +0x70 | IRP_MJ_CREATE | `FUN_1400027A0` |
| +0x80 | IRP_MJ_CLOSE | `FUN_1400027A0` |
| +0x88 | IRP_MJ_READ | `FUN_140003D90` |
| +0x90 | IRP_MJ_WRITE | `FUN_140003D90` |
| +0x98 | IRP_MJ_QUERY_INFORMATION | `FUN_140003C70` |
| +0xA0 | IRP_MJ_SET_INFORMATION | `FUN_140004110` (not traced) |
| +0xB8 | IRP_MJ_FLUSH_BUFFERS | `FUN_140003A80` |
| +0xE0 | IRP_MJ_DEVICE_CONTROL | `FUN_140002840` (both ctl and disk devices) |
| +0xE8 | IRP_MJ_INTERNAL_DEVICE_CONTROL | `FUN_140002840` |
| +0x148 | IRP_MJ_PNP | `FUN_140003B90` |

Routing inside `FUN_140002840`: `CMP R13, [0x140009080]` at `0x1400028AE` selects the control device. Other majors are unset.

**IRP_MJ_DEVICE_CONTROL, control device (`\Device\ImDiskCtl`): all codes that the control gate admits.** IRP offsets: InputBufferLength `+0x10`, OutputBufferLength `+0x08`, IoControlCode `+0x18`. All codes have `code & 3 = 0`, so **every code below is METHOD_BUFFERED** (no METHOD_NEITHER path in the traced dispatch). Gate for this device: only the six codes {0x8372E004, 0x8372E010, 0x8372E018, 0x8372E024, 0x83722000, 0x8372200C} pass; all other codes return 0xC0000010.

| Code | Method | Func | In min | Out min | Handler | Gate / notes |
|---|---|---|---|---|---|---|
| 0x8372E004 | BUFFERED | 0x801 | 0x36 + NameLen (USHORT at SB+0x2E) | none | entry `0x140003711`; `CALL FUN_14000C900` at `0x14000374C` | IRQL must be 0 (`KeGetCurrentIrql` `0x1400071D0`). No privilege check. Creates a disk from a user config (image path, size, flags, drive letter). Image opened in caller context (impersonation, see section 6). |
| 0x8372E010 | BUFFERED | 0x804 | 8 | 8 | entry `0x140003947` | `SeSinglePrivilegeCheck(7)` at `0x140003979` for user-mode callers only (internal IRPs skip it). `ObReferenceObjectByHandle(user handle, 0x83, IoFileObjectType)` at `0x1400039E5`, with the Object out-param stored in a list entry. The **kernel FILE_OBJECT pointer is returned** in the 8-byte output (information disclosure, non-goal). |
| 0x8372E018 | BUFFERED | 0x806 | 4 | none | entry `0x14000389C`; `CALL FUN_140002750` at `0x14000393D` | Removes disk by DeviceNumber (dword SB, not -1) if its open count (ext+0xFC) < 1; otherwise 0xC0000022. No privilege check. |
| 0x8372E024 | BUFFERED | 0x809 | 8 | none | fallthrough after `CMP` at `0x14000379B` (entry address not confirmed) | **Internal only.** Accepted only when MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL (0x0F). User DEVICE_CONTROL returns 0xC0000022. Matches a user-supplied pointer against the reference list by equality. Never dereferenced. |
| 0x83722000 | BUFFERED | 0x800 | none | 4 | inline; compare `0x1400032AD` | Returns constant 0x103 (4 bytes). |
| 0x8372200C | BUFFERED | 0x803 | none | 4 (bitmap if out < 9; list otherwise) | entry `0x1400035BF` (JZ from `0x14000344D`) | Lists ImDisk device numbers under spinlock `DAT_140009090`. |

**IRP_MJ_DEVICE_CONTROL, disk devices (`\Device\ImDisk<N>`): partial.** For disk devices, 0x8372E004 and the subset 0x83722010/0x83722018/0x83722024 are rejected. All other codes are routed to the common table. Codes checked or traced:

| Code | Method | Func | In min | Out min | Handler / compare | Notes |
|---|---|---|---|---|---|---|
| 0x83722008 | BUFFERED | 0x802 | none | 0x3A + ext[0xB8] | compare `0x14000328B` | Returns per-disk parameters (DiskLen at ext+0xD0, geometry, flags, image name). |
| 0x83722014 | BUFFERED | 0x805 | 8 | none | compare `0x140003459` | IRQL ≤ 1 required. Sets per-disk flags; may call `ZwFsControlFile(0x900C4)` on the image handle. |
| 0x7405C | BUFFERED | 0x17 | none | 8 | compare `0x14000296E` | Returns DiskLen (ext+0xD0). |
| 0x70000 | BUFFERED | 0x0 | none | 0x18 | `LAB_1400029C0` | Returns CHS geometry from ext fields. |
| 0x7C018 | BUFFERED | 0x6 | 0x14 | none | `LAB_140002C08` (shared with 0x7C02C) | Queued to worker `FUN_140001B30` then `FUN_14000C720` (**sink, section 5.1**). Write-protect check ext+0xF4. Cylinder/head/end checks in 64-bit against DiskLen. |
| 0x7C02C | BUFFERED | 0xB | 0x14 (0x1C+ when the EX entry list is parsed) | none | `LAB_140002C08` | Same as 0x7C018 (EX form). |
| 0x2D9404 | BUFFERED | 0x501 | 0x1C | none | compare `0x140002E4E` | Range list (offset,len pairs) bounded by InLen; applies `ZwFsControlFile(0x980C8 / 0x98208)` on image handle (zero/trim). |
| 0x2D0C14 | BUFFERED | 0x305 | none | 8 | entry `0x140002EA1` (JZ from `0x140002E62`) | Returns a flags byte. |
| 0x2D0800 | BUFFERED | 0x200 | none | 4 | `LAB_140002D91` | Returns ext+0xF0 when `ext+0xF5 != 0`; otherwise queued (`FUN_1400041F0`). |
| 0x4D0000 | BUFFERED | 0x0 | none | 4 | JZ `0x1400031F9` (from `0x1400030D9`) | Returns "ImDisk<N>" (ANSI). |
| 0x4D0008 | BUFFERED | 0x2 | none | 4 | JZ `0x140003190` (from `0x1400030E2`) | Returns "\Device\ImDisk<N>" (UTF-16) via `_snwprintf`. |
| 0x4D000C | BUFFERED | 0x3 | none | 6 | JZ `0x140003102` (from `0x1400030EB`) | Calls `FUN_14000CE90` (`0x14000312F`). |
| 0x56C008 | BUFFERED | 0x2 | none | none | inline (`0x1400032D3`) | Success, Information 0. |
| 0x560038, 0x560048, 0x4DC010 | BUFFERED | 0xE, 0x12, 0x4 | none | none | `LAB_1400030F9` | Rejected with 0xC0000010. |
| 0x70048 | BUFFERED | 0x12 | none | 0x90 | inline; no entry address mapped | Fixed-size geometry reply. |
| 0x74004 | BUFFERED | 0x1 | none | 0x20 | inline; no entry address mapped | Fixed-size reply. |
| 0x2D0C00 | BUFFERED | 0x300 | none | 0x18 | `LAB_1400029C0` | Fixed-size reply. |

**Disk-device codes present in the dispatch but not individually traced:** 0x24000, 0x2404C, 0x24038, 0x24800, 0x254730, 0x4B800, 0x70014, 0x70024, 0x70140, 0x70C00, 0x74800, 0x74804, 0x74808, 0x7C008, 0x7C04C, 0x7C0C8, 0x7C0D0, 0x2D0800-family (0x2D4800, 0x2D4804, 0x2D4808), 0x2D9405. All are METHOD_BUFFERED (`code & 3 = 0`).

**Names:** the names in the table (for example "create disk", "format tracks") are descriptive labels from the code paths. The WDK names for the standard disk codes (0x7405C, 0x70000, 0x7C018, 0x7C02C) are from memory and were not checked against a header in this session.

**Sink inventory (Q4), with addresses:**

| Sink | Address (function) | Class | Control |
|---|---|---|---|
| `MmMapLockedPagesSpecifyCache` (IRP MDL, user buffer mapped to kernel view) | `0x1400020DB` (`FUN_140002090`), `0x14000238D` (`FUN_140002330`), `0x140003F15` and `0x14000402D` (`FUN_140003D90`), `0x1400044C8` (`FUN_140004380`) | none (user buffer mapping, not a write to a chosen address) | IRP length; user buffer contents. ByteOffset bounded in `FUN_140003D90` (`DiskLen < offset+len` returns success with no transfer); fast-path copy bounded to mapped window (ext+0x120, ext+0x128). |
| `ZwMapViewOfSection` (`FUN_14000B000`) | `0x14000B68B` | none | Handle from user-path `ZwCreateFile`; BaseAddress chosen by MM. |
| `ZwAllocateVirtualMemory` | `0x140001C2C`, `0x14000B1C4`, `0x14000B8B0` | allocation only | Size from config (DiskSize). |
| `NtWriteFile` (image file write) | `0x14000C89A` (`FUN_14000C720`), `0x1400026C3` (`FUN_140002330`) | file write, not kernel memory | Offset from request, handle in caller context. |
| Memory-disk fill `memset(0xF6)` | `0x14000C79F` (`FUN_14000C720`) | KVA candidate, see section 5.1 | Offset (low 32 bits of start) from 0x7C018/0x7C02C request. |
| `IoCreateDevice` | `0x14000C437` (per-disk), `0x14000E8C9` (ctl) | device creation | n/a |
| `PsCreateSystemThread` | `0x14000C9B8` (`FUN_14000C900`), `0x14000E537` (`FUN_14000E000`) | thread creation | Start routine at `0x14000C9B8` not identified (section 6). |

No `MmMapIoSpace`, no HAL bus/port/MSR imports, no `MmProbeAndLockPages`, no `IoAllocateMdl`, no `IoCreateDeviceSecure`, no `ZwSetSecurityObject`, no `ObSetSecurityObjectByPointer`, no `PsRevertToSelf`. Full IAT was checked (76 entries, `iat\x64_iat.txt`).

## 5. Corruption, not write

1. **`FUN_14000C720` (memory-backed disk fill, reached from IOCTL 0x7C018 / 0x7C02C via worker `FUN_140001B30` at `0x140001B30`):** start = (cyl·tpc + head)·bpt and end likewise, computed in 64 bits. The dispatch checks both against DiskLen in 64 bits (`0x140002C08` block). The memory branch (ext+0xF5 != 0) then truncates: `MOV ECX,EDX` (`0x14000C78B`) takes low 32 bits of start; `MOV R8D,R10D` (`0x14000C792`) takes low 32 bits of end; count is `SUB R8,RCX` (64-bit) plus bytes-per-track (`0x14000C795`-`0x14000C79C`); `CALL memset(base+low32(start), 0xF6, count)` at `0x14000C79F`. When the range crosses a 4 GiB boundary, low32(end) < low32(start), the count wraps to about 2^64, and the fill runs from `base+low32(start)` until a fault. The fill value is fixed (0xF6) and the base is a driver allocation, so this is **Corruption, not write**. Gates: device DACL (unresolved), a memory-backed disk with DiskLen > 4 GiB, and a request crossing a 4 GiB boundary. Would be reconsidered if the overrun could be steered to a known object.
2. **IOCTL 0x8372E010 returns a kernel FILE_OBJECT pointer** to the caller (`**SB = list[2]`). Information disclosure (non-goal). Gated by SE_TCB for user-mode callers.
3. **Memory-disk write copy (`FUN_140002330` at `0x14000238D` region):** destination base+ByteOffset, length = IRP length. Safe only if the VM allocation size equals ext+0xD0 (DiskLen). The allocation size (`ZwAllocateVirtualMemory` in `FUN_14000B000`, size from `param_2+2`) and the ext+0xD0 assignment were not compared. Not traced.

## 6. Not traced

- The full disk-device IOCTL list (section 4 lists codes not individually traced).
- `FUN_140004110` (SET_INFORMATION), `FUN_140004380` (IRP forwarder: `IoAllocateIrp` / `IofCallDriver`), `FUN_140004850`, `FUN_14000D400` and `FUN_14000D780` (section and proxy paths), `FUN_14000CD70`, `FUN_14000CC60`, `FUN_14000CF10`, `FUN_14000D0B0`, `FUN_14000D180`, `FUN_14000CE90` (MountMgr and symlink helpers), `FUN_140005100`, `FUN_140005450`, `FUN_140005E40`, `FUN_140005EC0`, `FUN_140001000`, `FUN_140001230`.
- `FUN_140005A40` and `FUN_140005D00` were assumed to be memcpy and memset from their call pattern. Their bodies were not read. Section 5.1 depends on `FUN_140005D00` being memset.
- `FUN_14000D260` (DriverUnload) body: only the teardown calls were seen.
- The worker thread start routine for `PsCreateSystemThread` at `0x14000C9B8` was not identified.
- Impersonation: `SeImpersonateClient` at `0x14000B2E7` is not paired with a revert import (no `PsRevertToSelf` or `SeDeleteClientSecurity` in the IAT). Whether the worker thread stays impersonated was not traced.
- Proxy mode (type 0x300): `FUN_140004D80` bounds the peer reply length by the requested length (pipe and shared-memory modes). Pipe squatting on `\Device\NamedPipe\ImDskSvc` when the helper is absent, and reachability of proxy disks, were not traced.
- Device DACL: the kernel default SD for a named `IoCreateDevice` object was not verified from any source. The fetched MS pages (`nf-wdm-iocreatedevice`, `security-descriptors`, `controlling-device-access`) do not state it for non-PnP devices.
- VM allocation size vs ext+0xD0 (section 5.3).
- 0x83722014 flag path and 0x8372200C list path: reviewed at summary level only.
- Instruction addresses for `FUN_140002840` case entries are the compare or JZ target addresses. Some case entries are fallthrough blocks without a confirmed entry address (flagged in section 4).
- ARM64: structural diff only. Not audited.

## 7. Next dynamic test (described, not run)

1. **DACL and reachability (resolves Q5 and the DEFAULT-ADMIN label):** in a disposable VM, as admin, install the service from the INF (driver load). From a standard-user session, attempt `CreateFile("\\.\ImDiskCtl")` with read/write and an `NtOpenFile` on `\Device\ImDiskCtl`. After an admin creates one disk, repeat the open on `\Device\ImDisk<N>`. In the kernel debugger read the actual DACL with `!object \Device\ImDiskCtl` and `!sd` on the object's security descriptor.
2. **Section 5.1 lead:** create a memory-backed disk with DiskLen > 4 GiB (requires large commit). Send a format request whose start and end straddle 0x1_0000_0000. Break at `0x14000C79F` and inspect RCX (destination) and R8 (count). Observe whether the fill faults or bugchecks. This decides whether it is Corruption-only or can be steered.
3. Static follow-up: read `FUN_140005D00` and `FUN_140005A40` bodies to confirm memset and memcpy semantics (section 6).

## 8. NO-WRITE reason

The missing link is the CONTROL on any write sink: no traced sink writes to an attacker-chosen kernel virtual address, physical address or port. The only out-of-range write (section 5.1) writes a fixed byte at a driver-allocated base with a bounded-by-32-bit attacker offset, which is Corruption, not write. Device reachability (DACL) is unresolved and does not change this verdict.
