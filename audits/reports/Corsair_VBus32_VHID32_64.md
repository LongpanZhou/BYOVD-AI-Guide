# Audit: Corsair VBusDriver32, VHidDriver32, VHidDriver64

| Field | Value |
|---|---|
| File(s) | `CorsairVBusDriver32_293FF38B.sys` (PE32 i386, 38,840 B) ; `CorsairVHidDriver32_96A45A28.sys` (PE32 i386, 19,392 B) ; `CorsairVHidDriver64_81C6E568.sys` (PE32+ AMD64, 22,968 B) |
| SHA-256(s) | `293FF38BEDC1DBB7B1D00AEC6CC135F97C34565A9936298AF2C48C64EC9E37DE` ; `96A45A2872FE334F1A9D5DC09FB7B79045E31BAD82E5AF81CFDC6E65466CE81A` ; `81C6E5681F16194C93FB3C3FB3C2D574DF864E27ECA91CB7AFB8BACAF00FD838` |
| Analysis date | 2026-10-24 |
| Method | Static-only: local Ghidra 12.1.4 headless decompiler/disassembler on the SHA-256-verified bytes, plus read-only PE/byte parsing of the same files. No REA session was opened (shared bridge at capacity - `STATUS.md` in-flight items 1-4; three concurrent REA audits). No load, execution, service creation, registry write, or network access. |
| Reach tier | **R2** local administrator for the VBus32 write paths; **R1** read-only open via the same interface; **R3** (composition) for VHid32/64 |
| Setup required | `devnode` (VBus32 root-enumerated bus) / `composition` (VHid32/64 require the Corsair virtual-bus + HID stack) |
| Write quality | **W0** |
| Verdict | **NO-MEMORY-WRITE** - no kernel memory write in any of the three images. VBus32 carries the same admin-gated, non-address-controlled double-free/UAF residual as the VBus64 baseline. |

Image base is `0x10000` for all three; every address below is a loaded VA (image base + RVA).

## Per-file summary

| File | Arch | Role | Device / interface and effective DACL | Open gate | IOCTL surface | Strongest caller-controlled kernel store | Write | Verdict |
|---|---|---|---|---|---|---|---|---|
| `CorsairVBusDriver32_293FF38B.sys` | i386 | Corsair virtual bus FDO + one child PDO | FDO: no SD -> I/O-manager default device DACL (SYSTEM/Administrators full, `Everyone` read), `FILE_DEVICE_SECURE_OPEN`; interface `{2ABAD0DE-4DDC-4965-8D7A-7FAF3B7F1D59}`. Child PDO: explicit `D:P(A;;GA;;;SY)(A;;GA;;;BA)`, not user-named | FDO openable by any user for read; `FILE_WRITE_DATA`/write IOCTLs require admin | 6 codes: `0x2A6004`, `0x2A6008` (READ), `0x2AA010/14/18/1F` (WRITE) | Fixed 4-byte store at `DevExt+0x20`; pool copies of exactly `InputBufferLength`; bounded ring writes (`<=0x41`) | **W0** | **NO-MEMORY-WRITE** (admin-gated UAF residual) - reach=R2 setup=devnode write=W0 load=signed |
| `CorsairVHidDriver32_96A45A28.sys` | i386 | HID minidriver (`HidRegisterMinidriver`) | **No device object, no interface, no SDDL.** Only reachable via `IRP_MJ_INTERNAL_DEVICE_CONTROL` from HIDCLASS | None of its own; HID stack owns the user-facing DACL | 10 internal `IOCTL_HID_*` codes, kernel-originated only | None. Every store targets the IRP output buffer after an `OutputBufferLength` check | **W0** | **NO-MEMORY-WRITE** - reach=R3 setup=composition write=W0 load=signed |
| `CorsairVHidDriver64_81C6E568.sys` | AMD64 | HID minidriver (`HidRegisterMinidriver`) | **No device object, no interface, no SDDL.** Only reachable via `IRP_MJ_INTERNAL_DEVICE_CONTROL` from HIDCLASS | None of its own; HID stack owns the user-facing DACL | 10 internal `IOCTL_HID_*` codes, kernel-originated only | None. Every store targets the IRP output buffer after an `OutputBufferLength` check | **W0** | **NO-MEMORY-WRITE** - reach=R3 setup=composition write=W0 load=signed |

**Overall verdict: NO-MEMORY-WRITE.** No file exposes a caller-controlled destination address, a caller-controlled copy length that exceeds its allocation, an unchecked `METHOD_NEITHER` dereference, a physical-memory mapping, or an MSR/port/PCI/SMBus/EC/MMIO path that chains into a memory write.

---

## 1. Internals

### 1.1 `CorsairVBusDriver32_293FF38B.sys`

PE32 (I386), 7 sections, entry `0x1903E`, `SizeOfImage 0xC000`, `TimeDateStamp 0x5EFB6DF9` (2020-06-30 16:53:13 UTC). Sections: `.text` `0x1000-0x4B5E`, `.rdata` `0x5000-0x5790`, `.data` `0x6000-0x64B9`, `PAGE` `0x7000-0x83E2`, `INIT` `0x9000-0x97AE`, `.rsrc` `0xA000`, `.reloc` `0xB000`. 72 imports: 70 from `ntoskrnl.exe`, 2 from `HAL.dll`.

Version resource 3.0.88, CompanyName "Corsair", OriginalFilename `CorsairVBusDriver.sys`. Authenticode: **Valid**, `CN=Microsoft Windows Hardware Compatibility Publisher` (WHQL).

Imports confirm the surface: `IoCreateDevice`, `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`, `IoAttachDeviceToDeviceStack`, `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `ProbeForRead`, `memcpy`, `IoInvalidateDeviceRelations`, plus the WDMLIB support set (`ZwSetSecurityObject`, `ObOpenObjectByPointer`, `SeCaptureSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlAddAccessAllowedAce`, `RtlCreateSecurityDescriptor`, `RtlAbsoluteToSelfRelativeSD`, `SeExports`). Notably **absent**: `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmProbeAndLockPages`, `MmGetPhysicalAddress`, `WRMSR`/`RDMSR`, `READ_PORT_*`/`WRITE_PORT_*`, `Hal*`. The SDDL/registry imports belong to the statically linked WDMLIB fallback (`0x17005-0x183A6`), not to bus-driver logic.

Statically linked WDMLIB: `WdmlibInit` `0x17005`, `WdmlibIoCreateDeviceSecure` `0x17064`, `IoDevObjCreateDeviceSecure` `0x17144`, `SeUtilSecurityInfoFromSecurityDescriptor` `0x17266`, SDDL parser `0x177B3-0x17EA5`, class-key/registry state `0x17352-0x176C6`.

### 1.2 `CorsairVHidDriver32_96A45A28.sys`

PE32 (I386), 6 sections, entry `0x1503E`, `SizeOfImage 0x8000`, `TimeDateStamp 0x5EFB6DFC`. 23 imports from two modules: 22 `ntoskrnl.exe` (`DbgPrintEx`, `IoInitializeRemoveLockEx`, `IofCallDriver`, `IofCompleteRequest`, `KeBugCheckEx`, `KeCancelTimer`, `KeInitializeDpc/Event/Timer`, `KeQuerySystemTime`, `KeSetEvent`, `KeSetTimerEx`, `KeTickCount`, `KeWaitForSingleObject`, `PoCallDriver`, `PoSetPowerState`, `PoStartNextPowerIrp`, `RtlQueryRegistryValues`, `_alldiv`, `memcpy`, `memset`) and one from `HIDCLASS.SYS` - `HidRegisterMinidriver`. Version 3.0.88, OriginalFilename `CorsairVHidDriver.sys`, WHQL-signed (Valid).

There is no `IoCreateDevice`, no `IoCreateSymbolicLink`, no `IoRegisterDeviceInterface`, no `ExAllocatePool*`, no `Mm*`, no port/MSR import. The image is a HID minidriver, not an independently openable device.

### 1.3 `CorsairVHidDriver64_81C6E568.sys`

PE32+ (AMD64), 7 sections (`.pdata` present), entry `0x16064`, `SizeOfImage 0x9000`, `TimeDateStamp 0x5EFB6DFE`. 18 imports: 17 `ntoskrnl.exe` plus `HidRegisterMinidriver`. Version 3.0.88, WHQL-signed (Valid). Same structural absence of device-creation, pool and memory-mapping APIs as the 32-bit twin. `memcpy`/`memset` are statically linked CRT routines (`0x11EE0`, `0x11DE0`), not imports.

---

## 2. Entry / device / interface / effective DACL

### 2.1 VBus32 - DriverEntry `0x12A8A`

All 28 `MajorFunction` slots are first set to the pass-through `FUN_000111B0` (loop writing `DriverObject+0x38 ... +0xA4`), then:

| Offset | Major | Handler |
|---|---|---|
| `+0x38` | `IRP_MJ_CREATE` (0) | `0x11134` |
| `+0x40` | `IRP_MJ_CLOSE` (2) | `0x11172` |
| `+0x48` | `IRP_MJ_WRITE` (4) | `0x11FBE` |
| `+0x70` | `IRP_MJ_DEVICE_CONTROL` (14) | `0x11B3C` |
| `+0x74` | `IRP_MJ_INTERNAL_DEVICE_CONTROL` (15) | `0x128C4` |
| `+0x90` | `IRP_MJ_POWER` (22) | `0x1137A` |
| `+0xA4` | `IRP_MJ_PNP` (27) | `0x12A22` |
| `+0x34` | `DriverUnload` | `0x11102` |
| `DriverExtension+0x04` | `AddDevice` | `0x111FA` |

`IRP_MJ_READ` (`+0x44`, index 3) is **not** overridden; it forwards down the stack.

`DriverEntry` also captures the OS version via `RtlGetVersion` (`FUN_00011006`, result stored at `DAT_00016328`) and reads `DoLog` from the driver's `Services\CorsairVHID` key (`RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"CorsairVHID", ...)` in `FUN_00013B44`) to enable logging only.

### 2.2 VBus32 - AddDevice `0x111FA`

```
0x11238  IoCreateDevice(DriverObject, 0x4DC, NULL, 0x2A, 0x100, FALSE, &DevObj)
0x11259  DevExt = DevObj->DeviceExtension
0x1125F  memset(DevExt, 0, 0x4DC)
0x1126A  DevExt[0] = 0                       ; object kind = FDO
0x1126F  DevExt[2] = DevObj
0x11273  DevExt[3] = PhysicalDeviceObject
0x11279  IoAttachDeviceToDeviceStack(DevObj, PDO) -> DevExt[1]
0x11285  DevObj->Flags &= 0xFFFFDF6B         ; clears 0x4 DO_BUFFERED_IO, 0x10 DO_DIRECT_IO,
                                             ;        0x80 DO_DEVICE_INITIALIZING, 0x2000 DO_POWER_PAGABLE
0x1129A  IoRegisterDeviceInterface(PDO, &GUID_0x1515C, NULL, DevExt+0x4D0)
```

Device type `0x2A` = `FILE_DEVICE_BUS_EXTENDER`; characteristics `0x100` = `FILE_DEVICE_SECURE_OPEN`; extension `0x4DC` bytes; not exclusive; **no security descriptor argument**.

Because `DO_BUFFERED_IO`/`DO_DIRECT_IO` are cleared, `IRP_MJ_WRITE` receives a raw user pointer in `Irp->UserBuffer` (`Irp+0x3C` on x86) and must probe it - it does (Section 5.1).

**Interface.** `IoRegisterDeviceInterface` is called with the **PDO** (correct WDM usage) and the symlink buffer is stored in the FDO extension at `+0x4D0`. The GUID at `0x1515C` is bytes `DE D0 BA 2A DC 4D 65 49 8D 7A 7F AF 3B 7F 1D 59`:

```
{2ABAD0DE-4DDC-4965-8D7A-7FAF3B7F1D59}
```

- identical to the VBus64 baseline. The interface is enabled when the FDO successfully starts: `FUN_00011D84` (the `IRP_MN_START_DEVICE` path) calls `IoSetDeviceInterfaceState(DevExt+0x4D0, TRUE)` after the forwarded start IRP succeeds.

**FDO security descriptor: none.** No `IoCreateDeviceSecure`, no `ZwSetSecurityObject`, no `RtlSetDaclSecurityDescriptor` is called on the FDO anywhere in bus-driver code (the only `ZwSetSecurityObject` site is inside WDMLIB's `IopDevObjApplyPostCreationSettings`, `0x170C5`, reachable only through `WdmlibIoCreateDeviceSecure`). The FDO therefore receives the I/O manager's default device DACL - full access for `SYSTEM` and `BUILTIN\Administrators`, `FILE_GENERIC_READ` for `Everyone` - enforced through the interface symlink because `FILE_DEVICE_SECURE_OPEN` is set.

### 2.3 VBus32 - child PDO, `0x114B4`

The only secure-creation call in the image (verified in disassembly at `0x114DA-0x114F2`, args pushed right-to-left):

```
push  DeviceObjectOut
push  0                          ; DeviceClassGuid = NULL
push  0x15260                    ; DefaultSDDLString (UNICODE_STRING)
push  0                          ; Exclusive = FALSE
push  0x180                      ; FILE_AUTOGENERATED_DEVICE_NAME | FILE_DEVICE_SECURE_OPEN
push  0x22                       ; FILE_DEVICE_UNKNOWN
push  0                          ; DeviceName = NULL
push  0x24                       ; DeviceExtensionSize
push  DriverObject
call  WdmlibIoCreateDeviceSecure (0x17064)
```

The `UNICODE_STRING` at `0x15260` is `{Length=0x36, MaximumLength=0x38, Buffer=0x15228}`; `0x15228` holds 27 UTF-16 characters:

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)
```

Protected DACL, `GENERIC_ALL` to `SYSTEM` and `BUILTIN\Administrators`, no `WD`/`RC` ACE. **This is byte-identical to the SDDL used by VBus64.** A full-image scan finds the familiar seven-literal SDDL family at `0x15200`, `0x15228`, `0x15268`, `0x152B0`, `0x15310`, `0x15388`, `0x15408`; only `0x15228` is referenced (through `0x15260`), so the permissive `Everyone` variants remain dead data.

The child PDO is auto-named in `\Device` with no DOS symlink and no interface, so it is not user-openable by name; its explicit DACL is a second, redundant barrier.

### 2.4 VHid32 `0x11962` / VHid64 `0x11008` - HID minidrivers

Neither image creates a device. `DriverEntry` fills all 28 `MajorFunction` slots with a pass-through and overrides only:

| Major | VHid32 | VHid64 |
|---|---|---|
| `IRP_MJ_INTERNAL_DEVICE_CONTROL` | `0x11748` | `0x11990` |
| `IRP_MJ_POWER` | `0x11112` | `0x1136C` |
| `IRP_MJ_PNP` | `0x11300` | `0x115C0` |
| `DriverUnload` | `0x11006` | `0x11218` |
| `AddDevice` | `0x11060` | `0x11280` |

`HidRegisterMinidriver` is called with `Version=1`, `DriverObject`, `RegistryPath`, `DeviceExtensionSize=0x58` (32-bit) / `0x78` (64-bit). `AddDevice` only zeroes the extension, initialises a remove-lock and a timer, and clears `0x80|0x2000` in the device-object flags. There is **no device name, no interface GUID, and no SDDL** - the user-facing objects and their DACL belong to `hidclass.sys`, and every request that reaches these images is an `IRP_MJ_INTERNAL_DEVICE_CONTROL` issued by HIDCLASS, which user mode cannot send (`NtDeviceIoControlFile` produces `IRP_MJ_DEVICE_CONTROL`, and the minidriver's DEVICE_CONTROL slot is the pass-through).

**Effective DACL for the VHid pair: not owned by these files.** Whatever DACL the HID collection carries is created and secured by HIDCLASS/`hidusb`-class code; these minidrivers add no open gate and expose no named object.

---

## 3. Dispatch and IOCTL table

### 3.1 VBus32 - `IRP_MJ_DEVICE_CONTROL` `0x11B3C`

Reads `IoControlCode` from `IoStack+0x0C`; all other codes return `STATUS_INVALID_DEVICE_REQUEST` (`0xC00000BB`). All six codes use device type `0x2A`. Codes and access bits are **identical to the VBus64 baseline**.

| IOCTL | Function | Method | Access | Handler | Kernel action | Bounds / checks |
|---|---|---|---|---|---|---|
| `0x2A6004` | `0x801` | 0 BUFFERED | `FILE_READ_ACCESS` | `0x117BC` | `memcpy(SystemBuffer, "3.0.88" (ASCII, 0x14156), 7)` at `0x1180A`; `Information=7` | `OutputBufferLength >= 7` (`0x117F8`) |
| `0x2A6008` | `0x802` | 0 BUFFERED | `FILE_READ_ACCESS` | `0x117BC` | `memcpy(SystemBuffer, L"3.0.88" (0x14148), 14)` at `0x1180A`; `Information=14` | `OutputBufferLength >= 14` (`0x117F8`) |
| `0x2AA010` | `0x804` | 0 BUFFERED | `FILE_WRITE_ACCESS` | `0x11826` | **SetReportDescriptor**: compare vs stored descriptor; allocate `InputBufferLength`; free/replace `DevExt+0x14`/`+0x1C`; restart children | length 0 rejected; allocation-exact copy; **no lock** |
| `0x2AA014` | `0x805` | 0 BUFFERED | `FILE_WRITE_ACCESS` | `0x11A06` | allocate `InputBufferLength`, `memcpy` from `SystemBuffer`, free/replace `DevExt+0x18` | zero length -> `0xC000000D`; alloc failure -> `0xC000009A`; **no lock** |
| `0x2AA018` | `0x806` | 0 BUFFERED | `FILE_WRITE_ACCESS` | `0x11A8A` | `*(u32 *)(DevExt+0x20) = *(u32 *)SystemBuffer`; `Information=4` | `InputBufferLength == 4` else `0xC0000206` |
| `0x2AA01F` | `0x807` | 3 **METHOD_NEITHER** | `FILE_WRITE_ACCESS` | `0x11AC6` | restart children / `IoInvalidateDeviceRelations(DevExt+0xC, 0)` | **never reads `Type3InputBuffer` or `UserBuffer`** |

`IRP_MJ_CREATE` (`0x11134`) and `IRP_MJ_CLOSE` (`0x11172`) log and complete `STATUS_SUCCESS`; neither inspects the desired-access mask, `RequestorMode`, or caller identity.

### 3.2 VBus32 - `IRP_MJ_WRITE` `0x11FBE` (HID input-report feed)

Because neither buffering mode is set, the IRP carries a raw user pointer (`Irp+0x3C`):

```
0x1206C  FUN_00011794(IoStack): require Write.Length >= 6, else 0xC0000206
0x120C7  ProbeForRead(Irp->UserBuffer, Write.Length, 1)
0x120E7  p = UserBuffer + 1;  remaining = Write.Length - 1
0x12128  bound check: p + remaining <= cursor
0x12133  len32 = *(u32 *)p
0x12138  require len32 + 4 + consumed <= remaining
0x1214D  require len32 <= 0x41
0x12181  push a zeroed 0x45-byte ring entry (DevExt+0x44, 16 slots)
0x121C2  entry = ring slot (head-1); *entry = len32; memcpy(entry+4, p+4, len32)
```

The probe covers the full declared length; every record is rejected before the copy if its 4-byte header plus payload would exceed the probed range, and the 0x45-byte ring slot exactly fits `4 + 0x41`. The ring head is masked to 0..15, and both producer and consumer hold the fast mutex at `DevExt+0x24`. One `int`-overflow corner (`len32 + 4 + consumed`) exists, but the `len32 > 0x41` test runs **before** any copy and rejects the wrapped case, so it is not a write.

### 3.3 VBus32 - `IRP_MJ_INTERNAL_DEVICE_CONTROL` `0x128C4`

Kernel-only. Accepts only `IOCTL 0xB000B` (`IOCTL_HID_READ_REPORT`) when the extension kind is 0 (FDO). It either queues the IRP pending (cancel routine `0x12820`) or, if a report is already buffered, completes it through `FUN_00011C04`:

```
0x11C04  outLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength
         entryLen = ringEntry[0]
         if (outLen < entryLen) -> 0xC0000023
         else memcpy(Irp->UserBuffer, ringEntry+4, min(outLen, entryLen))
```

Length-checked on both sides; destination is the kernel HID client's buffer.

### 3.4 VHid32 / VHid64 - `IRP_MJ_INTERNAL_DEVICE_CONTROL`

Both dispatch on `IoControlCode` (`IoStack+0x0C` on x86, `+0x18` on x64) with the same handler set:

| IOCTL | Meaning | Handler | Action | Bound |
|---|---|---|---|---|
| `0xB0027` | `HID_GET_DEVICE_ATTRIBUTES` | 32: `0x114C4`, 64: inline in `0x11990` | writes a 0x20-byte `HID_DEVICE_ATTRIBUTES` into `Irp->UserBuffer` | requires `OutputBufferLength >= 0x20`, else `0xC0000023` |
| `0xB0003` | `HID_GET_DEVICE_DESCRIPTOR` | 32: `0x1152E`, 64: `0x117C4` | writes 9-byte `HID_DESCRIPTOR` | requires `>= 9`, else `0x80000005` with `Information = 9 - outLen` |
| `0xB0007` | `HID_GET_REPORT_DESCRIPTOR` | 32: `0x1160E`, 64: `0x118A8` | `memcpy(UserBuffer, descriptor, len)` - default static descriptor `0x14000`/`0x14118`, 0x17 bytes | requires `OutputBufferLength >= len`, else `0xC0000023`; an absent/zero-length descriptor falls back to the 0x17-byte built-in |
| `0xB000B` | `HID_READ_REPORT` | 32: `0x116D0`, 64: inline in `0x11990` | forwards to the lower device (pending queue) | none needed - no buffer touched |
| `0xB001F` / `0xB0023` | ACTIVATE / DEACTIVATE | inline | complete success, `Information = 0` | - |
| `0xB0191` `0xB0192` `0xB01A2` `0xB01E2` | SET_FEATURE / GET_FEATURE / GET_INPUT_REPORT / GET_INDEXED_STRING | 32: `0x115E8`; 64: inline | `STATUS_INVALID_DEVICE_REQUEST` (`0xC00000BB`) | - |
| default | - | - | log + complete with the current status | - |

No handler reads an input buffer, a `Type3InputBuffer`, or a caller-supplied length. The only variable-length copy is the report descriptor, whose length comes from the minidriver's own extension (never written in either image, so the static 0x17-byte default is used) and whose destination is the IRP's output buffer.

### 3.5 VHid - device creation summary

`HidRegisterMinidriver` is the entire registration surface. There is no `IRP_MJ_CREATE`/`IRP_MJ_DEVICE_CONTROL`/`IRP_MJ_WRITE` handler to exploit, and no user-mode handle ever names these drivers.

---

## 4. Access-control audit

| Control | VBus32 | VHid32 | VHid64 |
|---|---|---|---|
| Explicit SDDL on user-facing object | **No** - `IoCreateDevice(..., NULL, 0x2A, 0x100, 0, ...)` at `0x11238` | n/a (no object) | n/a (no object) |
| Explicit SDDL on child PDO | **Yes**, admin-only, `0x15260 -> 0x15228` | n/a | n/a |
| `FILE_DEVICE_SECURE_OPEN` | Yes, FDO `0x100` and PDO `0x180` | n/a | n/a |
| Device interface enabled | Yes, `IoSetDeviceInterfaceState(DevExt+0x4D0, TRUE)` in `0x11D84` | n/a | n/a |
| DOS symlink | No (interface GUID only) | n/a | n/a |
| `SeAccessCheck` / `SeSinglePrivilegeCheck` | Not imported, no call sites | no | no |
| `RequestorMode` check in dispatch | No | no | no |
| `IoValidateDeviceIoControlAccess` | Resolved at `0x17005`, stored `0x16334`, **never read** | n/a | n/a |
| Reliance on `CTL_CODE` access bits | Yes - 2 read, 4 write | n/a | n/a |
| `ProbeForRead` on raw user buffer | Yes, full `Write.Length`, alignment 1 (`0x120C7`) | n/a | n/a |
| Output-length validation before copy | Yes (`0x117F8`, `0x11C04`) | Yes (three handlers) | Yes (three handlers) |
| Locking on descriptor mutation | **No** (`0x11826`, `0x11A06`) | n/a | n/a |

**Reachability.** The VBus32 FDO is unnamed and reachable only through interface `{2ABAD0DE-...}`. With `FILE_DEVICE_SECURE_OPEN` set, the object manager evaluates the FDO's default DACL on that path:

* an unprivileged user obtains `FILE_GENERIC_READ`, so `0x2A6004`/`0x2A6008` are callable (constant version strings only);
* `0x2AA010`, `0x2AA014`, `0x2AA018`, `0x2AA01F` and `WriteFile` are rejected with `STATUS_ACCESS_DENIED` before dispatch;
* an administrator can satisfy every gate, which is why the write handlers were audited for memory safety independently of the DACL.

The child PDO is auto-named and has no symlink or interface; its admin-only SDDL is unreachable from user mode anyway (as in the baseline).

---

## 5. Memory-write trace

### 5.1 VBus32

Every `memcpy`/store in bus-driver code, with its source and bound:

| Address | Destination | Source | Length | Verdict |
|---|---|---|---|---|
| `0x117BC` (0x2A6004/8) | `Irp->SystemBuffer` (`Irp+0x0C`) | compile-time ASCII/UTF-16 version string | 7 / 14 | destination is the I/O manager's buffered copy sized `max(In,Out)`; `OutputBufferLength` checked at `0x117F8` before the `0x1180A` copy - safe |
| `0x11826` (0x2AA010) | `ExAllocatePoolWithTag(NonPagedPool, InputBufferLength, 'BSF5')` at `0x118D2` | `Irp->SystemBuffer` | exactly `InputBufferLength` (`0x1198A`) | allocation-exact; no overflow; no caller address |
| `0x11A06` (0x2AA014) | `ExAllocatePoolWithTag(NonPagedPool, InputBufferLength, 'BSF7')` | `Irp->SystemBuffer` | exactly `InputBufferLength` | allocation-exact |
| `0x11A8A` (0x2AA018) | `*(u32 *)(DevExt+0x20)` | `*(u32 *)SystemBuffer` | fixed 4 bytes | fixed offset, not caller-influenced |
| `0x11FBE` (WRITE) | ring slot `DevExt+0x44 + n*0x45` | probed user buffer | `len32 <= 0x41`, exact 0x45-byte slot | bounded after `ProbeForRead`; integer-wrap case rejected before copy |
| `0x11C04` (IDC complete) | `Irp->UserBuffer` | ring entry | `min(OutputBufferLength, entryLen)` | output-length checked |
| `0x12C40` / `0x12D4A` (PnP strings) | fresh pool allocations | static ID strings | fixed 0x4E / `wcslen+2` | PnP-only, static sources |

There is **no** write to a caller-supplied kernel address, no `MmMapIoSpace`/`MmMapLockedPagesSpecifyCache`/`MmCopyMemory`/`ZwMapViewOfSection`/MDL mapping, and no MSR/port/PCI/SMBus/EC/MMIO primitive anywhere in the image. `IRP_MJ_READ` is unhandled (pass-through), so there is no kernel-read primitive either.

### 5.2 VHid32 / VHid64

Both images contain exactly one variable-length store: the report-descriptor `memcpy` (`0x1160E` / `0x118A8`), destination `Irp->UserBuffer`, source the driver's own static descriptor (`0x14000` / `0x14118`, 0x17 bytes; the extension fields that could override it - `+0x14`/`+0x1C` in the 32-bit build, `+0x28`/`+0x38` in the 64-bit build - are never written by these images), length checked against `OutputBufferLength` first. The fixed struct writes (`0x20`/`9` bytes) are likewise output-length gated. `IRP_MJ_WRITE`, `IRP_MJ_READ` and `IRP_MJ_DEVICE_CONTROL` are pass-throughs. The only other `memcpy` is the fixed 0x1C/0x38-byte stack-location copy used to forward IRPs to the next device (`0x112F8` / `0x11518`), a kernel structure of fixed size.

No pool allocation, no mapping API, no port/MSR access, and no caller-controlled pointer or length reaches any store.

### 5.3 VBus32 vs VBus64 baseline - delta

| Aspect | VBus64 (`651FB6AF`, baseline) | VBus32 (`293FF38B`, this audit) |
|---|---|---|
| Image / entry | PE32+ AMD64, 47,032 B; DriverEntry `0x11150` | PE32 i386, 38,840 B; DriverEntry `0x12A8A` |
| FDO create | `IoCreateDevice`, ext `0x550`, type `0x2A`, char `0x100` | same call/args, ext `0x4DC` at `0x11238` |
| FDO SDDL | none -> default device DACL | **none -> default device DACL** (identical) |
| Interface GUID | `{2ABAD0DE-4DDC-4965-8D7A-7FAF3B7F1D59}` | **same** (`0x1515C`) |
| Child PDO SDDL | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | **same** (`0x15228`, struct `0x15260`) |
| IOCTL set | `0x2A6004/8/2AA010/14/18/1F` | **same codes, methods, access bits** |
| SetReportDescriptor | `0x126DC`, unsynchronised free/replace of `DevExt+0x28` | `0x11826`, unsynchronised free/replace of `DevExt+0x14` - **same defect** |
| Second descriptor path | `0x12CA9` on `DevExt+0x30` | `0x11A06` on `DevExt+0x18` - **same defect** |
| Fixed 4-byte store | `DevExt+0x40` | `DevExt+0x20` |
| WRITE ring | 16 x 0x45 at `DevExt+0x4E0` | 16 x 0x45 at `DevExt+0x44` |
| Memory-mapping / MSR / port APIs | none | none |

*Setup classification note.* The sibling baseline recorded `Setup: none (driver load)`. The same package's INF installs a root-enumerated `root\CorsairBus` device (per that report), so the object does not exist at bare driver load; this report records `devnode`. The difference is documentary only - both are R2-reachable and neither changes the memory-write finding.

**The admin-gated double-free/UAF in SetReportDescriptor is present and is not materially different.** Both builds allocate a fresh pool block of exactly `InputBufferLength`, copy exactly that many bytes from the I/O manager's system buffer, free the previous descriptor, and publish the new pointer - with **no acquisition of the device fast mutex** that the WRITE path takes (`0x12014` in this build; `0x121C8` in the VBus64 baseline). Two concurrent `0x2AA010` (or `0x2AA014`) callers can therefore both observe and free the same pointer, or free a buffer another thread has just published. The 32-bit version zeroes the pointer/length before the `memcpy` and publishes afterwards; the 64-bit version clears then publishes. That is an ordering difference inside the same un-synchronised window, not a change in reachability or primitive class: the corrupted object is a pool block whose address comes from `ExAllocatePoolWithTag`, never from the request, so this remains a lifetime bug rather than an address-controlled write. Reach is the same (`FILE_WRITE_ACCESS` -> administrator/SYSTEM under the shipped default DACL).

One additional 32-bit-only observation, not a write primitive: the descriptor-free path in `FUN_00012528` (device removal) uses a loop bound that Ghidra renders as an unassigned stack slot; the underlying ring state is initialised by `FUN_00011CD6`, so this is most likely a decompiler aliasing artifact. Even taken literally it would be at worst a bounded/looping DoS in a PnP removal path, not a memory write.

---

## 6. Most dangerous exposed capability

### 6.1 VBus32 - unsynchronised report-descriptor replacement (admin only)

`0x2AA010` -> `0x11826`:

```
0x11855  old = DevExt+0x14 (descriptor), oldLen = DevExt+0x1C
0x11877  compare oldLen vs InputBufferLength; 0x11889 byte-compare (CMPSB.REPE)
0x118D2  new = ExAllocatePoolWithTag(NonPagedPool, InputBufferLength, 'BSF5')
0x1196F  ExFreePoolWithTag(old, 0)          ; +0x14 and +0x1C zeroed at 0x11975/0x11979
0x1198A  memcpy(new, SystemBuffer, InputBufferLength)
0x11992  DevExt+0x14 = new; DevExt+0x1C = InputBufferLength (0x11998)
```

`0x2AA014` -> `0x11A06` performs the same free/replace on `DevExt+0x18` (allocate -> copy -> free old -> publish), also without the mutex.

This is the strongest defect in the trio: a local administrator holding a write handle can race two descriptor IOCTLs into a kernel pool double-free/use-after-free. It is **not** a memory-write primitive: no caller-supplied address or length reaches a store beyond its own allocation, and the freed pointer is always a driver-owned pool block.

### 6.2 Report-descriptor injection (admin only)

`0x2AA010`/`0x2AA014` install an arbitrary-length HID report descriptor into the bus extension. It is consumed by the HID child stack (`CorsairVHidDriver*`/`hidclass.sys`), outside this image. That is supply-chain attack surface for a privileged caller, not a write in this driver.

### 6.3 What is not present

* No write to a caller-supplied kernel address in any of the three images.
* No `METHOD_NEITHER` buffer dereference: `0x2AA01F` ignores both buffers.
* No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, MDL mapping, MSR, port I/O, PCI config, SMBus/EC or MMIO access.
* No unbounded copy: every pool copy is allocation-exact; every ring copy is `<= 0x41` inside a 0x45-byte slot; every output copy is `OutputBufferLength`-checked.
* No kernel read exposed to user mode (VBus32's read IOCTLs return compile-time strings; VHid exposes none).
* No device, interface or SDDL created by either VHid image, and no user-reachable IOCTL handler in them at all.

### 6.4 Direct answer

**None of the three drivers can be made to write kernel memory from the requester's access.** VBus32 duplicates the VBus64 posture exactly: the only user-openable object is the FDO behind `{2ABAD0DE-...}` with the default read-for-Everyone DACL, every state-changing operation is `FILE_WRITE_ACCESS`, and even with write access the code contains no attacker-address write. The explicit SDDL in the binary is admin-only and applies to the non-user-reachable child PDO; six of the seven SDDL literals, including every `Everyone` variant, are unreferenced. The VHid pair is a HID minidriver with no device, no DACL, no pool and no caller-controlled store.

---

## 7. Verdict

| Question | Finding | Confidence |
|---|---|---|
| Effective DACL on the only user-openable VBus32 object | No explicit SD on the FDO (`0x11238`); OS default device DACL (SYSTEM/Administrators full, Everyone read), enforced by `FILE_DEVICE_SECURE_OPEN`; interface `{2ABAD0DE-...}` | Medium-high (default is OS behaviour, corroborated by the absence of any SDDL/`ZwSetSecurityObject` path and the unreferenced `WD` literals) |
| Which SDDL reaches `IoCreateDeviceSecure` | Exactly one call site (`0x114F2`) with `UNICODE_STRING 0x15260` -> `D:P(A;;GA;;;SY)(A;;GA;;;BA)`, for the child PDO; identical to VBus64 | High (string + struct + push order) |
| Are the `Everyone` SDDL variants used | No; six of seven are dead data | High (single call site, no other references) |
| Open gate | R1 read via the interface; R2 for the four write IOCTLs and `WriteFile` | High |
| VBus32 SetReportDescriptor double-free/UAF present | **Yes** (`0x11826`, `0x11A06`), unsynchronised | High (code) |
| Is it materially different from VBus64 | **No** - same allocation-exact copy, same unsynchronised free/replace, same admin gate, same non-address-controlled class | High |
| Any caller-controlled kernel address/length store in VBus32 | No | High |
| Any kernel memory write in VHid32/64 | No - no device, no user IOCTL, output-length-gated fixed/static copies only | High |
| Overall | **NO-MEMORY-WRITE** - reach=R2/R3 setup=devnode/composition write=W0 load=signed | High |

**Residual risk (all three).** If a future package or registry class-installer relaxed the VBus32 FDO DACL to grant `Everyone` write - not present in the shipped package, and the permissive SDDL literals in the binary are unused - the two descriptor IOCTLs would become reachable by any local user and the double-free race would be a credible local pool-corruption primitive. It would still be a lifetime bug, not an address-controlled write, and the two VHid images remain write-free regardless of DACL.

---

## 8. Limitations

1. **Static only.** No driver load, IOCTL replay, DACL inspection, pool debugging or fuzzing was performed. All conclusions come from bytes and control flow.
2. **No REA.** The shared REA bridge was reported at capacity (`STATUS.md` in-flight items 1-4, three concurrent REA audits). A read-only `binary_session` probe was made only to confirm the bridge state; the shared session was deliberately left untouched so as not to displace a concurrent audit, and the entire analysis used local Ghidra 12.1.4 headless (`analyzeHeadless`, PE loader, decompiler) on the SHA-256-verified files. No REA evidence IDs are cited and no cross-provider result was accepted; there is therefore no foreign-binary contamination risk, but also no second-engine confirmation.
3. **VBus32 FDO DACL is inferred.** `IoCreateDevice` does not embed a security descriptor; the "SYSTEM/Administrators full, Everyone read" default is OS behaviour, corroborated by the absence of any `ZwSetSecurityObject`/SDDL path on the FDO and by the fact that the only `IoCreateDeviceSecure` call targets the child PDO. A pre-existing class-key `Security` value or an INF `[Security]` section could change it.
4. **INF/package unavailable.** The corpus contains only `.sys` files; the companion INF described in the VBus64 baseline could not be re-read to confirm the root-enumerated device, service type, or any security override. The baseline's package description is the only source for those install details.
5. **Architecture.** VBus32 and VHid32 are i386 images and cannot load on the x64 analysis host; they would require a 32-bit Windows target. This does not affect the memory-write finding (none exists in the code), but it does affect live reachability.
6. **VBus64 was not re-audited.** The sibling report was used only as a comparison baseline; its addresses and conclusions are cited as given.
7. **Shared code.** The `PAGE`/WDMLIB block (`0x17005-0x183A6`) is a statically linked library; its `ZwSetSecurityObject`/`RtlSetDaclSecurityDescriptor` paths are reachable only through `WdmlibIoCreateDeviceSecure`, which the driver calls exactly once (child PDO). The audit did not attempt to prove the WDMLIB fallback bug-free, only that it is not on the FDO path.
8. **Decompiler boundaries.** Ghidra did not create a function at `0x11FBE` (the `IRP_MJ_WRITE` handler is referenced only as a data pointer from the dispatch table); it was recovered explicitly and decompiled/disassembled for this report. Other tail-merged functions may similarly span more than one logical routine, though the cited addresses are exact.
9. **Child HID stack out of scope.** `hidclass.sys` and the descriptor parser that consumes the buffer installed by `0x2AA010` were not assessed, and `CorsairVHidDriver*`'s own descriptor is static in these builds.

---

## Appendix A - Address index

### VBus32 (`293FF38B`, base `0x10000`)

| Address | Item |
|---|---|
| `0x11134` / `0x11172` | CREATE / CLOSE (log + success) |
| `0x111FA` | AddDevice |
| `0x11238` | `IoCreateDevice(FDO, 0x4DC, NULL, 0x2A, 0x100, 0, ...)` |
| `0x11285` | FDO flags `&= 0xFFFFDF6B` |
| `0x1129A` | `IoRegisterDeviceInterface(PDO, &0x1515C, ...)` |
| `0x114B4` | `BusCreateChildDevice` |
| `0x114F2` | `WdmlibIoCreateDeviceSecure` call (SDDL `0x15260`) |
| `0x117BC` | version-string IOCTL body |
| `0x11826` | SetReportDescriptor (`0x2AA010`) |
| `0x11A06` | descriptor-2 replace (`0x2AA014`) |
| `0x11A8A` | fixed 4-byte store (`0x2AA018`) |
| `0x11AC6` | restart children (`0x2AA01F`) |
| `0x11B3C` | `IRP_MJ_DEVICE_CONTROL` |
| `0x11C04` | pending-report completion |
| `0x11D84` | FDO start / interface enable |
| `0x11FBE` | `IRP_MJ_WRITE` |
| `0x128C4` | `IRP_MJ_INTERNAL_DEVICE_CONTROL` |
| `0x12A22` | PnP dispatch |
| `0x12A8A` | DriverEntry |
| `0x1515C` | Interface GUID `{2ABAD0DE-4DDC-4965-8D7A-7FAF3B7F1D59}` |
| `0x15228` / `0x15260` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` / its `UNICODE_STRING` |
| `0x17005` / `0x17064` / `0x17144` | `WdmlibInit` / `WdmlibIoCreateDeviceSecure` / local secure-create |

### VHid32 (`96A45A28`, base `0x10000`)

| Address | Item |
|---|---|
| `0x11006` | DriverUnload |
| `0x11060` | AddDevice |
| `0x11300` | PnP |
| `0x114C4` | GET_DEVICE_ATTRIBUTES |
| `0x1152E` | GET_DEVICE_DESCRIPTOR |
| `0x1160E` | GET_REPORT_DESCRIPTOR |
| `0x116D0` | READ_REPORT |
| `0x11748` | `IRP_MJ_INTERNAL_DEVICE_CONTROL` |
| `0x11962` | DriverEntry / `HidRegisterMinidriver` |
| `0x14000` | default 0x17-byte report descriptor |

### VHid64 (`81C6E568`, base `0x10000`)

| Address | Item |
|---|---|
| `0x11008` | DriverEntry / `HidRegisterMinidriver` |
| `0x11218` | DriverUnload |
| `0x11280` | AddDevice |
| `0x115C0` | PnP |
| `0x117C4` | GET_DEVICE_DESCRIPTOR |
| `0x118A8` | GET_REPORT_DESCRIPTOR |
| `0x11990` | `IRP_MJ_INTERNAL_DEVICE_CONTROL` |
| `0x14118` | default 0x17-byte report descriptor |
