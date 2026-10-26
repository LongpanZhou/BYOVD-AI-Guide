# imdisk.sys: admin-scope static audit (kernel memory write)

| Field | Value |
|---|---|
| File | `drivers/imdisk.sys` (manifest batch: collected3; previously `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected3\drivers\ImDisk\imdisk.sys` (58048 bytes)) |
| SHA-256 | `3CFC11F2FCAD16785FFA3B134100C20111B2D51051B931993C13AEDEEC116D95` |
| Company and version | Olof Lagerkvist; FileVersion and ProductVersion 3.0.3.66 (ProductName "imdisk", FileDescription "ImDisk Virtual Disk Driver") |
| Signature status and signer | Valid (`Get-AuthenticodeSignature`). Signer `CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation`; issuer `CN=Microsoft Windows Third Party Component CA 2014` |
| Method | static, Ghidra 12.1.4 headless decompile dump (59/59 functions; dump `ghidra_dump\out\imdisk.txt`, `=== DONE functions=59`). Analysis date 2026-10-24 |
| Reach tier | local administrator (assumed). The device DACL is not determined statically, and no memory-write primitive was found, so the tier is informational only. |
| Setup required | none (driver load). No hardware or devnode dependency appears in the driver code. |
| Verdict | **MW4 — LOW** (reach=R2 setup=none write=W3 load=signed). One kernel-mode fixed-value write (0xF6 memory-disk fill) into a driver-allocated user-range base on memory disks above 4 GiB. Fixed value, crash-first, cannot reach kernel VA; MW4 per SEVERITY.md. |
| Write quality | W3 |
| Severity | MW4 |

> Static analysis only. Nothing was loaded, installed, started or executed. The Ghidra dump and the binary were read, not run. Statements about runtime behaviour are predictions for section 5, not results.

Line numbers below refer to `ghidra_dump\out\imdisk.txt`.

---

## 1. Entry surface

### 1.1 Devices, symbolic links, DACL

| Item | Finding | Source |
|---|---|---|
| Control device | `\Device\ImDiskCtl`, created in DriverEntry: `IoCreateDevice(DriverObject, 0x130, name, 0x8372, 0x20000, Exclusive FALSE, &DAT_140009080)`. Characteristics 0x20000 is FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSE. FILE_DEVICE_SECURE_OPEN is not set. | line 6140 (`entry` at 6019) |
| Symbolic link (control) | `\DosDevices\ImDiskCtl` via `IoCreateUnprotectedSymbolicLink`. Return value not checked. | line 6151 |
| Disk devices | `\Device\ImDisk<N>`, created on demand in FUN_14000B000 (`IoCreateDevice`, line 5018). Symbolic link `\DosDevices\ImDisk<N>` at 5033. Drive-letter link `\DosDevices\Global\<X>:` at 5327 (FUN_14000C900) and 5384 (FUN_14000CC60). | lines 5018, 5033, 5327, 5384 |
| Creation path | IOCTL 0x8372E004 reaches FUN_14000C900 at line 1694. Boot-time disks are created from registry values (FUN_14000E000). | lines 1688-1694, 5855 |
| Names opened, not created | `\Device\MountPointManager` (IoGetDeviceObjectPointer in FUN_14000CD70), `\Device\AWEAlloc` (ZwCreateFile in FUN_14000B000), `\Device\NamedPipe\ImDskSvc` (proxy mode). No name collision branch exists. | FUN_14000CD70; FUN_14000B000 |
| DACL on any device object | none. No `IoCreateDeviceSecure`, `ZwSetSecurityObject`, `ObSetSecurityObjectByPointer`, or SDDL string appears in the dump. | EXT list; grep |
| Only DACL in the driver | a NULL DACL on the named event `\BaseNamedObjects\Global\ImDiskRefresh`. This is an event, not a device. | lines 6177-6178 |
| Effective device DACL | **not determined statically.** It is the kernel default for a named `IoCreateDevice` object with no SD. The earlier "DEFAULT-ADMIN" label stays unconfirmed. | |
| Effect on verdict | None. The verdict does not depend on who can open the device, because no memory-write primitive was found. | |

### 1.2 IRP dispatch (set in DriverEntry)

| DRIVER_OBJECT slot | Major function | Routine | Line |
|---|---|---|---|
| +0x68 | DriverUnload | FUN_14000D260 | 6171 |
| +0x70 | IRP_MJ_CREATE | FUN_1400027A0 | 6161 |
| +0x80 | IRP_MJ_CLOSE | FUN_1400027A0 | 6162 |
| +0x88 | IRP_MJ_READ | FUN_140003D90 | 6163 |
| +0x90 | IRP_MJ_WRITE | FUN_140003D90 | 6164 |
| +0x98 | IRP_MJ_QUERY_INFORMATION | FUN_140003C70 | 6168 |
| +0xA0 | IRP_MJ_SET_INFORMATION | FUN_140004110 | 6169 |
| +0xB8 | IRP_MJ_FLUSH_BUFFERS | FUN_140003A80 | 6170 |
| +0xE0 | IRP_MJ_DEVICE_CONTROL | FUN_140002840 | 6165 |
| +0xE8 | IRP_MJ_INTERNAL_DEVICE_CONTROL | FUN_140002840 | 6166 |
| +0x148 | IRP_MJ_PNP | FUN_140003B90 | 6167 |

FUN_140002840 routes control-device and disk-device requests by comparing the device object with DAT_140009080 (the control device).

### 1.3 Control-device codes (the only ones it admits)

Lines 1191, 1196-1199 and 1234-1235 admit six codes and reject everything else with 0xC0000010.

| Code | Routine (line) | Notes |
|---|---|---|
| 0x8372E004 | CREATE disk, FUN_14000C900 (1694) | No privilege check on this path. The only SeSinglePrivilegeCheck in the dispatch is at line 1965. |
| 0x8372E010 | line 1954 | `SeSinglePrivilegeCheck(7)` (SE_TCB) for user-mode callers (line 1965). Returns a kernel FILE_OBJECT pointer. |
| 0x8372E018 | REMOVE disk, FUN_140002750 | Removes a disk whose open count is below 1. |
| 0x8372E024 | internal only | Accepted only for IRP_MJ_INTERNAL_DEVICE_CONTROL (per the earlier pass; not re-verified here). |
| 0x83722000 | version constant | No memory access. |
| 0x8372200C | list device numbers | Output only. |

---

## 2. Memory-write analysis (every dangerous call site)

### 2.1 Import-level sinks

| # | Sink | Site (line, function) | Reached from | Gate | Destination and value | Finding |
|---|---|---|---|---|---|---|
| 1 | `MmMapLockedPagesSpecifyCache` | 902, FUN_140002330 | IRP read and write path, called from the thread routine FUN_140001490 (line 458) | DiskLen and offset check in FUN_140003D90 (2282) on the IRP path | MDL of the caller's IRP buffer (user VA). Copy length is the IRP length. | NO-WRITE |
| 2 | `MmMapLockedPagesSpecifyCache` | 2302, 2350, FUN_140003D90 | IRP_MJ_READ and IRP_MJ_WRITE (+0x88, +0x90) | `offset + len > DiskLen` or `len == 0` returns success without transfer (2282-2285) | MDL of the IRP buffer. Copy length is at most DiskLen minus offset. | NO-WRITE |
| 3 | `MmMapLockedPagesSpecifyCache` | 2587, FUN_140004380 | forwarder for memory-type IRPs (IofCallDriver at 2663) | type 3 or 4 check (2584) | MDL. For type 4 (write) the copy at 2627 fills a pool buffer sized by the IRP length (2614). | NO-WRITE |
| 4 | `ZwMapViewOfSection` | 4739, FUN_14000B000 | proxy shared-memory mode (type 0x300) | section opened by fixed name (4427, 4444) | mapping into the current process; BaseAddress chosen by MM | NO-WRITE |
| 5 | `ZwOpenSection` | 4444, FUN_14000B000 | proxy mode, flag 0x3000 | fixed name `\Device\NamedPipe\ImDskSvc` (line 4427). Not `\Device\PhysicalMemory`. | section handle only | NO-WRITE |
| 6 | `ZwAllocateVirtualMemory` | 651, FUN_140001B30 (resize); 4619, 4772, FUN_14000B000 (create); base stored at 663 and 5081 | IOCTL 0x7C0D0 (resize) and memory-disk create | size from request (64-bit). Size below 1 is rejected (617). | base is a user-range address. Resize copies `min(old DiskLen, new size)` (661). | NO-WRITE |
| 7 | memory-disk fill, `memset(…, 0xF6, count)` | 5205-5206, FUN_14000C720 → FUN_140005D00 (memset at 3947) | IOCTL 0x7C018 and 0x7C02C, queued to the worker FUN_140001B30 (598-599) | 64-bit start and end checked against DiskLen in the dispatch (1369-1377) | destination `base + low32(start)`; count `bpt + low32(end) − low32(start)` (5205-5206). See the overrun note below. | **NO-WRITE for kernel VA.** CPL0 fixed-value overrun into user-range VA, crash-first. |
| 8 | `memmove` | 213, FUN_140001230 (ImDiskSafeReadFile) | image load into a memory disk (FUN_140001490 at 343) | read chunk at most 0x800000 bytes. Copy length is the IoStatus.Information value (at most the chunk). | destination `ext+0x70`, the user-range base | NO-WRITE |
| 9 | `memmove` | 829, 850, FUN_140002090 | read path, file and proxy | pool block allocated before the read call at 809, sized from the request | NO-WRITE |
| 10 | `memmove` | 923, 951, FUN_140002330 | memory-disk read copy (923) and IRP buffer copy (951) | DiskLen check before the call (2282 path) | base + ByteOffset to MDL VA; length is the IRP length | NO-WRITE |
| 11 | `memmove` | 1608, 1675, 1779, FUN_140002840 | IOCTL output strings (0x4D0000, 0x4D0008, 0x4D000C) and per-disk parameters (0x83722008) | output length compared first (1600-1606 and 1668-1673, and the 0x83722008 minimum) | METHOD_BUFFERED SystemBuffer | NO-WRITE |
| 12 | `memset` | 1294, FUN_140002840 | pool object | constant 0x324 | NO-WRITE |
| 13 | `memset` | 2196, FUN_140003C70 | QUERY_INFORMATION output | length is the IRP length (lVar2+8) | NO-WRITE |
| 14 | `memmove` | 2493, FUN_140004270 | IRP forward for codes 0x8372E01C and 0x8372E020 on disks with flag +0x68 (call at 2048) | guard `3 < InputBufferLength` (2046) makes `length − 4` non-negative; source and destination both inside SystemBuffer | NO-WRITE |
| 15 | `memmove` | 2784, 2785, 2863, 2866, 2888, 2895, FUN_140004850 | proxy request builder and reply | pool sized `param_5 + param_7`. `param_7` comes from a ushort (FUN_14000D400 at 5661) and `param_5` is 0x18 or 8, so the sum cannot wrap. | NO-WRITE. Reply-side bounds partly checked (section 6). |
| 16 | `memmove` | 3028, FUN_140004D80 | proxy reply into the caller buffer | reply length must be at most the requested length (3026-3027); pipe mode 3048-3051 | NO-WRITE. The peer supplies content only, not an address or length beyond the request. |
| 17 | `memmove` | 3130, 3204, FUN_140005100 | proxy request builder | pool `param_5*0x10 + 0x10`; copy `param_5*0x10` (same value) | NO-WRITE |
| 18 | `memmove` | 3306, 3345, FUN_140005450 | proxy request builder and reply | pool `iVar3 + 0x18`; copy `uVar6`, at most `uVar7` | NO-WRITE (3345 not fully re-verified) |
| 19 | `memmove` | 4367, FUN_14000B000 | copy of request name | pool sized `local_168`, the same length (4362) | NO-WRITE |
| 20 | `memmove` | 5979, FUN_14000E000 | boot-time configuration | value from registry | NO-WRITE |
| 21 | `memset` | 5045, 5278, 5479, 5517 | constant sizes (0x130, 0xc8, 0xc8, 0x100) | NO-WRITE |
| 22 | `NtWriteFile`, `NtReadFile` | 576, 809, 1010, 5189 | file I/O | not memory writes | n/a |

Not present anywhere in the dump: `MmMapIoSpace`, `MmUnmapIoSpace`, `MmCopyMemory`, `MmGetPhysicalAddress`, `ZwOpenSection(\Device\PhysicalMemory)`, MSR or port intrinsics (`__readmsr`, `__writemsr`, `__inbyte`, `__outbyte`), HAL bus-data calls, and dynamic name resolution (`MmGetSystemRoutineAddress` is not imported). Checked against the EXT list and by case-insensitive search.

### 2.2 The memory-disk fill overrun (row 7)

- Destination base: `ext+0x70` is assigned from `ZwAllocateVirtualMemory` at 663 and 5081 (lines 651-663 and 4772-5081). The base is a user-range address. It is not `ExAllocatePool` memory. The only `ExAllocatePool` assignment to `+0x70` (2616) writes to the IRP's own field, not the device extension.
- Trigger: the 64-bit start and end are checked against DiskLen in the dispatch (1369-1377). The fill itself (5172-5176) computes the 64-bit values and then truncates them to 32 bits (5205-5206).
- Overrun: when the range crosses a 4 GiB boundary, `low32(end) < low32(start)`, and the count wraps to nearly 2^64. The fill then writes 0xF6 forward from `base + low32(start)` until it faults.
- Reach into kernel space: none. The run starts in user range and moves upward. The canonical-address gap between user and kernel space stops it before any kernel address, so a kernel VA write cannot be reached this way.
- Gate: a memory disk with DiskLen above 4 GiB, and a request whose range crosses the 4 GiB boundary.
- Classification: CPL0 fixed-value write into user-range VA, crash-first. Not a kernel memory write under the scope. Consistent with the earlier "Corruption, not write" label.

### 2.3 Proxy path (pipe squatting)

The proxy reply is bounded by the requested length (row 16). The peer chooses content only. The pipe name `\Device\NamedPipe\ImDskSvc` is opened by the driver (line 4427). Whether an unprivileged process can create that name is not verified here, but it would not change the verdict, because the reply copy is bounded.

---

## 3. Memory-touching IOCTL table

Every code below is METHOD_BUFFERED (`code & 3 == 0`). The device checks are the ones in section 1.3 and the dispatch.

| Code | Routine (line) | Input checks | Memory primitive | Reach (gate) | Verdict |
|---|---|---|---|---|---|
| 0x8372E004 | CREATE (1688, 1694; core FUN_14000B000 at 4205) | size and name from request | memory-backed disk allocates a user-range base (4619, 4772). File-backed disk opens the image file in caller context. No kernel-VA write. | device open (DACL not determined) | NO-WRITE |
| 0x8372E010 | 1954-1965 | SE_TCB for user callers (1965) | returns a kernel FILE_OBJECT pointer (8 bytes) | SE_TCB (1965) | NO-WRITE (information only) |
| 0x8372E018 | REMOVE (FUN_140002750) | open count below 1 | none | device open | NO-WRITE |
| 0x7C018 / 0x7C02C | dispatch 1345-1411; worker FUN_140001B30 (598-599) → FUN_14000C720 | write-protect check (ext+0xF4), 64-bit start and end against DiskLen (1369-1377) | memory-disk fill (memset 0xF6, section 2.2); file or pool write (NtWriteFile at 5189) | device open | NO-WRITE for kernel VA (2.2) |
| 0x7C0D0 | worker 607-617 and 651-663; dispatch 1455-1456 | size from request; below 1 rejected | new user-range base; copy `min(old DiskLen, new size)` | device open | NO-WRITE |
| 0x2D9404 | worker 676; dispatch 1480 | InputBufferLength at least 0x1C (per the earlier pass) | pool block sized `count << 4` from the request; copy from request offset `*(uint*)(req+0x14)`. Whether that source range is within InputBufferLength was not verified. | device open | NO-WRITE (possible read beyond input, information only) |
| 0x4D0000 / 0x4D0008 / 0x4D000C | dispatch 1588 and following | output length checked | user output strings | device open | NO-WRITE |
| 0x8372200C | 1801 | output at least 4 bytes | device-number list under spinlock | device open | NO-WRITE |
| 0x83722008 | dispatch 1779 | minimum output length (earlier pass) | per-disk parameters with image name | device open | NO-WRITE |

---

## 4. Verdict

- **MW4 — LOW** (reach=R2 setup=none write=W3 load=signed). Kernel-mode memory write that is fixed-value and narrow, so W3. The SEVERITY.md matrix gives R2/W3 = MW4, and a crash-first primitive is capped at MW4.
- Basis: no traced path writes to a kernel address chosen by input, whether through IRP, IOCTL, proxy reply or file data. Every copy destination is a driver pool block sized from the same bounded length, a user-range base, or an MDL mapping of a caller buffer.
- The one memory write is the memory-disk fill (row 7, section 2.2): a CPL0 write of 0xF6 into a driver-allocated user-range base on memory disks above 4 GiB. It cannot reach kernel VA and is crash-first.
- The device DACL is not determined. The reach tier is local administrator as assumed; it does not change the MW4 rating, because the write is fixed and narrow.
- The earlier NO-WRITE label was wrong under SEVERITY.md: a kernel-mode memory write exists, so NO-MEMORY-WRITE does not apply.

---

## 5. Dynamic confirmation plan (described only, not run)

All steps are for an isolated Windows 10 build 19045 VM. Nothing below was executed in this pass.

1. **Device DACL.** Read the security descriptor of `\Device\ImDiskCtl` and of a created `\Device\ImDisk<N>` (`!object`, then `!sd`). Record which token classes can open each. This resolves the device-step reach tier.
2. **Memory-disk base.** Confirm that the base returned by `ZwAllocateVirtualMemory` lies in the user range, and record which process owns it (`!address` on the base, and the process context of the worker thread).
3. **Fill arguments.** Observe the base and count arguments at 5205-5206 for a memory disk larger than 4 GiB. Confirm that the write stops at the first user-range fault. This is observation only.
4. **Length sources.** Confirm for 0x2D9404 that the request source range is inside InputBufferLength (the one item not verified statically).
5. **Proxy reply.** Confirm the reply bounds in FUN_140004D80 by observation only. Do not build a crafted reply.

---

## 6. Limitations

- All 59 functions were searched for the sinks and every function on a sink path was read; not every function body was read line by line. The disassembly was not re-read in this pass.
- FUN_140005A40 (memmove) and FUN_140005D00 (memset) were confirmed from their opening branches (lines 3652-3700 and 3947-4000). Their tail paths were not read.
- Not traced in full: the reply copies at 2863-2895 in FUN_140004850 (partly checked); the copy at 3345 in FUN_140005450; the proxy callers FUN_14000D400 and FUN_14000D780 (only the 16-bit length argument was checked); FUN_14000CD70, FUN_14000CC60, FUN_14000CF10, FUN_14000D0B0, FUN_14000D180, FUN_14000CE90; the body of DriverUnload (FUN_14000D260); the worker start routine FUN_140001490 (it has no direct caller in the dump, so it is presumably the thread routine; not verified); whether memory-disk allocation size equals DiskLen (not compared).
- Impersonation: `SeImpersonateClient` (14000B2E7) is not paired with a revert import in this dump. Whether the worker keeps the client token was not traced.
- 0x2D9404 source-range bound (section 3) not verified.
- The earlier INF read is not repeated here. The ARM64 build was not audited.
- The effective device DACL is not determined.
- No dynamic testing. Every runtime statement is a prediction for section 5.
