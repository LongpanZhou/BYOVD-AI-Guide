# Audit: collected2 gaps - FTDI `ftser2k` (6AD3DC79) and Turtle Beach `VirtualHID` (43774DE0)

| Field | Value |
|---|---|
| File(s) | `drivers\ftser2k_6AD3DC79.sys` ; `drivers\VirtualHID_43774DE0.sys` |
| SHA-256(s) | `6AD3DC79E76E67A269F13ADC32257D95350028C1E9987476EDA8DA3D69B3450A` ; `43774DE0970B914DC3154568721AABB32AA6C3E9134BB5670339C2D6DA4BEEFC` |
| Analysis date | 2026-10-25 |
| Method | Static-only: local Ghidra 12.1.4 headless + LLVM objdump 20.1.5 / raw PE parsing. **REA not used** - four REA sessions already active; no REA cross-check was performed. |
| Reach | R2 (ftser2k, default device DACL) ; none (VirtualHID - no openable object) |
| Setup required | hardware (ftser2k: FTDI USB device + INF) ; devnode/composition (VirtualHID: Turtle Beach devnode + HIDCLASS) |
| Write quality | W0 / W0 |
| HW-only | no (neither driver reaches MSR / port / PCI / SMBus / EC / fixed MMIO) |
| Verdict | **NO-MEMORY-WRITE** (both) ; **BLOCKED (architecture)** - both images are i386 and cannot load on the AMD64 host |

## 0 Scope, hashes, method, loadability

Hashes were recomputed on the exact files with `Get-FileHash -Algorithm SHA256` and match the manifest rows in
`indexes\drivers_manifest.csv` (`collected2`). Neither hash appears in `indexes\dedupe\known_bad_hashes.txt`.

Both files are **32-bit PE32 images**, Machine `0x014C` (`IMAGE_FILE_MACHINE_I386`), OptionalHeader magic `0x010B`,
Subsystem `IMAGE_SUBSYSTEM_NATIVE`:

| File | Size | Machine | OptMagic | LINK time | Version | Signature |
|---|---:|---|---|---|---|---|
| `ftser2k_6AD3DC79.sys` | 75,896 | `0x014C` i386 | `0x010B` PE32 | 2017-08-21 | 2.12.28 (FTDI CDM, "D2XX Serial Device Driver") | Valid (FTDI, timestamped) |
| `VirtualHID_43774DE0.sys` | 24,848 | `0x014C` i386 | `0x010B` PE32 | 2019-12-24 | 1.0.0.2 (TurtleBeach Virtual HID) | Valid (Voyetra Turtle Beach, timestamped) |

A 32-bit kernel driver has no load path on x64 Windows (there is no kernel WOW64). On this AMD64 host both images are
therefore **BLOCKED** before any IOCTL is reachable. The audit below still records what the code would expose if it
could be loaded, because the static surface is the deliverable and the architecture block is a status, not a finding.

Related reports were read only to choose checkpoints, not to inherit conclusions:

* `audits\reports\ftdi.static.md` covers `ftdibus_8C494A63` and **`ftser2k_2D07F148` (x64, 2.12.28, 89,792 bytes)** -
  a different build with a different device/DACL and a different IOCTL surface from this 75,896-byte i386 image.
* `audits\reports\roccat_scpvbus.static.md` covers **`VirtualHID_6BD8F1E1` (x64, 26,768 bytes)** and concluded it
  creates no device at all. This i386 build is materially different: it creates a WDF device and registers an
  internal-device-control queue (section 3), so the prior "no device" verdict does not carry over.

No load, execution, install, service creation, registry write, or web lookup was performed. No exploit code or PoC
is included.

### Method / evidence paths

* Ghidra 12.1.4 headless (`C:\tools\ghidra_12.1.4_PUBLIC`, JDK 21), temp project
  `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\ghp_c2gaps` (`-deleteProject`), dump script `DumpDecomp.java`.
* Decompiled dumps: `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\ftser2k_dump.txt` (231 functions) and
  `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\vhid_dump.txt` (27 functions).
* PE headers, imports, sections and selected disassembly via `C:\msys64\clang64\bin\llvm-objdump.exe`.
* Structural layouts cross-checked against the local WDK headers (`wdfio.h` 1.9, `wdfdevice.h` 1.9,
  `ntddser.h` 10.0.22621.0, `hidport.h`).

## 1 Per-file table

| File | Arch | Device / interface | Effective DACL | Open gate | IOCTL surface | Memory-write primitive | Write | Verdict |
|---|---|---|---|---|---|---|---|---|
| `ftser2k_6AD3DC79.sys` | i386 | `\Device\VCP<n>` (type `0x1B` FILE_DEVICE_SERIAL_PORT, char `0x100` FILE_DEVICE_SECURE_OPEN, exclusive), `\DosDevices\<name>` symlink, `GUID_DEVINTERFACE_COMPORT` `{86e0d1e0-8089-11d0-9ce4-08003e301f73}` | No SDDL in image -> default device DACL (`SYSTEM` + `Administrators` GA). INF may relax it; not auditable from the `.sys`. | R2 admin (device present). Standard-serial IOCTLs are `FILE_ANY_ACCESS`, so the DACL is the only gate. | `IRP_MJ_DEVICE_CONTROL` -> `FUN_0040D760` (serial `0x1B00xx`, all `METHOD_BUFFERED`); `IRP_MJ_INTERNAL_DEVICE_CONTROL` -> `FUN_0040D476`; READ/WRITE are `DO_BUFFERED_IO`. | None. All copies land in `Irp->AssociatedIrp.SystemBuffer`, the device context, or fixed-size pool rings; every length is checked against `InputBufferLength`/`OutputBufferLength`. | **W0** | **NO-MEMORY-WRITE** (BLOCKED: i386) |
| `VirtualHID_43774DE0.sys` | i386 | Unnamed KMDF FDO; hardware ID `TurtleBeach\VirtualHID`; no `\Device\` name, no symlink, no device interface, no SDDL | None - object cannot be opened by name/interface; KMDF default device SD would be `SYSTEM`/`Administrators` if it were reachable | None. Only `IRP_MJ_INTERNAL_DEVICE_CONTROL` is dispatched (`EvtIoInternalDeviceControl`, queue config `+0x20`). | `0xB0003/7/B/F/13/27/191/192/195/1A2` HID miniport IOCTLs, `METHOD_NEITHER`, dispatched only for kernel callers (HIDCLASS). | Latent only: `SET_FEATURE` stores 1 byte through `HID_XFER_PACKET.reportBuffer` taken from `IRP->UserBuffer`; no probe, but the IRP major is internal-only and the packet is supplied by HIDCLASS (kernel). | **W0** (reachable surface) | **NO-MEMORY-WRITE** (BLOCKED: i386) |

## 2 `ftser2k_6AD3DC79.sys` - FTDI CDM serial function driver (2.12.28, i386)

### 2.1 Internals

WDM function driver. Imports are `ntoskrnl` (I/O, `ExAllocatePoolWithTag`, `ExAllocatePoolWithQuotaTag`, `memcpy`,
`memmove`, `memset`, `Ke*`, `Io*`, `Rtl*`, `ZwQueryValueKey`, `PsCreateSystemThread`, `Po*`, `WmiSystemControl`,
`MmLockPagableDataSection`), `HAL` (fast mutex/spinlock only) and `WMILIB`. There is **no** `MmMapIoSpace`,
`MmMapLockedPagesSpecifyCache`, `MmGetPhysicalAddress`, `MmProbeAndLockPages`, `MmCopyMemory`,
`ZwMapViewOfSection`, `KeStackAttachProcess`, `IoAllocateMdl`, `ProbeForRead`/`ProbeForWrite`, or
`IoCreateDeviceSecure` import, and no dynamically resolved `MmGetSystemRoutineAddress`. The only `Mm*` calls are
`MmLockPagableDataSection` / `MmUnlockPagableImageSection` / `MmQuerySystemSize` - code paging and ring sizing, not
memory mapping.

The driver is split into `PAGESRP0` / `PAGESER` pageable sections; driver entry is `FUN_00411000` at `0x411000`
(`INIT`).

### 2.2 Entry, device, interface, effective DACL

`DriverEntry` (`0x411000`) installs:

| DriverObject offset | IRP major | Handler |
|---|---|---|
| `+0x38` | `IRP_MJ_CREATE` | `FUN_00409778` |
| `+0x40` | `IRP_MJ_CLOSE` | `FUN_00404E30` |
| `+0x44` | `IRP_MJ_READ` | `FUN_0040EE04` |
| `+0x48` | `IRP_MJ_WRITE` | `FUN_00410092` |
| `+0x4C` | `IRP_MJ_QUERY_INFORMATION` | `FUN_0040BC46` |
| `+0x50` | `IRP_MJ_SET_INFORMATION` | `FUN_0040BD12` |
| `+0x5C` | `IRP_MJ_FLUSH_BUFFERS` | `FUN_00409000` |
| **`+0x70`** | **`IRP_MJ_DEVICE_CONTROL`** | **`FUN_0040D760`** |
| **`+0x74`** | **`IRP_MJ_INTERNAL_DEVICE_CONTROL`** | **`FUN_0040D476`** |
| `+0x80` | `IRP_MJ_CLEANUP` | `FUN_0040E8AC` |
| `+0x90` | `IRP_MJ_POWER` | `FUN_0040B792` |
| `+0x94` | `IRP_MJ_SYSTEM_CONTROL` | `FUN_0040C094` (WMILIB) |
| `+0xA4` | `IRP_MJ_PNP` | `FUN_0040AC08` |

The stores are visible at `0x411123`-`0x411179`; in particular `0x411138` writes `FUN_0040D760` to `[esi+0x70]` and
`0x41113F` writes `FUN_0040D476` to `[esi+0x74]`.

`AddDevice` is `FUN_00409C62` (`0x409C62`). It calls `FUN_00409CE6` to create the port device and then attaches it:

* `0x409DEA`: `IoCreateDevice(DriverObject, 0x8D8, &name, 0x1B, 0x100, TRUE, &DeviceObject)`, where `name` is built
  from `L"\\Device\\VCP"` + decimal index (`RtlAppendUnicodeToString` at `0x409D8C`, `RtlIntegerToUnicodeString` at
  `0x409DBF`). Type `0x1B` = `FILE_DEVICE_SERIAL_PORT`; characteristics `0x100` = `FILE_DEVICE_SECURE_OPEN`;
  `Exclusive = TRUE`.
* `0x409C9B`: `IoAttachDeviceToDeviceStack` (lower FTDI USB PDO).
* `0x409CCA`-`0x409CD9`: `DeviceObject->Flags = (Flags & ~0x80) | 0x2004`, i.e. clears `DO_DEVICE_INITIALIZING`
  and sets **`DO_BUFFERED_IO` (0x04)** + `DO_POWER_PAGABLE` (0x2000). This is the decisive property for the data
  paths: READ/WRITE/IOCTL buffers are kernel system buffers, not raw user pointers.
* `0x40A3C4`: `IoCreateSymbolicLink(&\DosDevices\<name>, &\Device\VCP<n>)`.
* `0x40A46C`: `IoRegisterDeviceInterface(PDO, &GUID_DEVINTERFACE_COMPORT, NULL, &ifname)` and `0x40A485`
  `IoSetDeviceInterfaceState(..., TRUE)`. The GUID at `0x407160` is
  `{86e0d1e0-8089-11d0-9ce4-08003e301f73}` (`GUID_DEVINTERFACE_COMPORT`).

**Effective DACL.** There is no `IoCreateDeviceSecure`, no `Se.*SecurityDescriptor`, no `"D:P("` string, and no
`"Security"` value in the image. The device is created with plain `IoCreateDevice`, so the object manager's default
device descriptor applies: `SYSTEM` and `Administrators` full control. With `FILE_DEVICE_SECURE_OPEN` that DACL is
enforced on every open, including through the `\DosDevices\` symlink and the COM-port interface. **Gate: R2 local
administrator.** The class/INF can install a different device security descriptor (COM-port INFs often grant
`Everyone` read/write); the `.inf` is not in the corpus and was not audited, so an R1 rating cannot be proven or
excluded from the `.sys` alone. Either way the IOCTL handlers below are non-writing.

**Setup.** The device only exists after the FTDI USB device enumerates and the driver is installed as its function
driver (`AddDevice` is PnP-driven). `Setup required = hardware`.

### 2.3 Dispatch and IOCTL table - `IRP_MJ_DEVICE_CONTROL` (`FUN_0040D760`, `0x40D760`)

`FUN_0040D760` reads the current stack location from `Irp->Tail.Overlay.CurrentStackLocation` (`[irp+0x60]`), takes
`IoControlCode` from `[sl+0xC]`, `InputBufferLength` from `[sl+8]`, `OutputBufferLength` from `[sl+4]`, and the
buffer from `Irp->AssociatedIrp.SystemBuffer` (`[irp+0xC]`). Every case in the switch is `METHOD_BUFFERED`
(low two bits of every code are `00`) and `FILE_ANY_ACCESS` (bits 14-15 zero), so there is **no METHOD_NEITHER
branch and no raw user pointer anywhere in the handler**. If the port is not in the ready state
(`ctx+0x19D != 1`), the handler completes the request with `STATUS_SUCCESS` and returns before the switch.

`B` = `0x1B0000`; all codes are `CTL_CODE(FILE_DEVICE_SERIAL_PORT, n, METHOD_BUFFERED, FILE_ANY_ACCESS)`.

| Code | Serial function | Length gate (SL+8 in / SL+4 out) | Kernel action |
|---|---|---|---|
| `0x1B0004` | SET_BAUD_RATE | in >= 4 | reads dword baud, `FUN_0040D22E`; no buffer write |
| `0x1B0008` | SET_QUEUE_SIZE | in >= 8 | `ExAllocatePoolWithQuotaTag(*(u32*)SystemBuffer)` for the RX queue; pointer stored in `SL+0x10`; free on cancel at `0x40F628+` |
| `0x1B000C` | SET_LINE_CONTROL | in >= 3 | parses stop/parity/word bytes into context |
| `0x1B0010` | SET_BREAK_ON | none | `FUN_00404C30` |
| `0x1B0014` | SET_BREAK_OFF | none | `FUN_00404BD8` |
| `0x1B0018` | IMMEDIATE_CHAR | in != 0 | queues the IRP as a pending immediate-char request |
| `0x1B001C` | SET_TIMEOUTS | in > 0x13 | copies 5 dwords from `SystemBuffer` into context |
| `0x1B0020` | GET_TIMEOUTS | out >= 0x14 | copies 5 dwords from context to `SystemBuffer` |
| `0x1B0024` | SET_DTR | none | handshake state |
| `0x1B0028` | CLR_DTR | none | handshake state |
| `0x1B002C` | serial control (fn 11) | none | `FUN_004017D6(..., 0xB, ...)` |
| `0x1B0030` | SET_RTS | none | handshake state |
| `0x1B0034` | CLR_RTS | none | handshake state |
| `0x1B0038` | SET_XOFF | none | XOFF callback |
| `0x1B003C` | SET_XON | none | XON callback |
| `0x1B0040` | GET_WAIT_MASK | out >= 4 | writes 4 bytes to `SystemBuffer` |
| `0x1B0044` | SET_WAIT_MASK | in >= 4 | reads mask, arms wait |
| `0x1B0048` | WAIT_ON_MASK | in >= 4 | queues async wait |
| `0x1B004C` | PURGE | in >= 4 | purge queues |
| `0x1B0050` | GET_BAUD_RATE | out >= 4 | writes 4 bytes to `SystemBuffer` |
| `0x1B0054` | GET_LINE_CONTROL | out >= 3 | `memset(SystemBuffer, 0, outLen)` then 3 bytes |
| `0x1B0058` | GET_CHARS | out >= 6 | writes 6 bytes |
| `0x1B005C` | SET_CHARS | in >= 6 | reads 6 bytes |
| `0x1B0060` | GET_HANDFLOW | out >= 0x10 | writes 0x10 bytes |
| `0x1B0064` | SET_HANDFLOW | in >= 0x10 | validates and applies 0x10 bytes |
| `0x1B0068` | GET_MODEMSTATUS | out >= 4 | writes 4 bytes |
| `0x1B006C` | GET_COMMSTATUS | out >= 0x14 | writes 0x14 bytes |
| `0x1B0070` | serial extension (fn 28) | in > 0xB | validates a dword field >= 1; completes |
| `0x1B0074` | GET_PROPERTIES | out >= 0x40 | fills 0x40-byte `SERIAL_COMMPROP` |
| `0x1B0078` | GET_DTRRTS | out >= 4 | writes 4 bytes |
| `0x1B007C` | serial extension (fn 31) | in != 0 | reads 1 modem-control byte |
| `0x1B0080` | CONFIG_SIZE | out >= 4 | writes 0 |
| `0x1B008C` | GET_STATS | out > 0x17 | fills 0x18-byte `SERIAL_STATS` |
| `0x1B0090` | CLEAR_STATS | none | clears counters |
| `0x1B0094` | GET_MODEM_CONTROL | out >= 4 | writes 4 bytes |
| `0x1B0098` | SET_MODEM_CONTROL | in >= 4 | reads 4 bytes |
| `0x1B009C` | SET_FIFO_CONTROL | in >= 4 | reads 4 bytes |

All output writes go to `SystemBuffer`; the I/O manager allocated it with `max(InputBufferLength, OutputBufferLength)`
for a buffered IRP, and each case checks the relevant length first (e.g. `0x1B0060` checks `outLen >= 0x10` before
the 16-byte copy, `0x1B0074` checks `outLen >= 0x40`; failures branch to `LAB_0040D83B`, which returns
`STATUS_BUFFER_TOO_SMALL`). No case derives a destination from input data, and `SystemBuffer` is never replaced.

### 2.4 Dispatch and IOCTL table - `IRP_MJ_INTERNAL_DEVICE_CONTROL` (`FUN_0040D476`, `0x40D476`)

Reachable only from a kernel caller (serial class/port stack), not from `DeviceIoControl`:

| Code | Length gate | Action |
|---|---|---|
| `0x1B0004` | none | ready/divisor validation |
| `0x1B0008` | none | clears ready, cancels pending IRP (`IoCancelIrp`) |
| `0x1B000C` / `0x1B0010` | out >= 0x2C | 0x2C-byte line-control block copied from context to `SystemBuffer`; 0x2C bytes copied back from `SystemBuffer` to context |
| `0x1B0400` | in >= 8 | FTDI descriptor/EEPROM helper (`FUN_00401E2A`, guarded by the device-type dword at `ctx+0x824`) |
| `0x1B0404` | in >= 4 | `FUN_00401508` state helper |
| `0x22021C` | none | re-issues the IRP to the lower FTDIBUS device (`IofCallDriver`) with `MajorFunction=0x0F`, `IoControlCode=0x22021C` |

The 0x2C-byte writes are guarded by `outLen >= 0x2C` (`0x40D638`, `0x40D6A3`). No user-mode path reaches this
handler (an application cannot issue `IRP_MJ_INTERNAL_DEVICE_CONTROL`).

### 2.5 Access-control audit

* No `SeSinglePrivilegeCheck`, no `SeAccessCheck`, no caller-identity check in the IOCTL paths. The only gate is the
  device DACL (section 2.2).
* All serial IOCTLs are `FILE_ANY_ACCESS`; an opener with any access can issue them. `IRP_MJ_CREATE` (`FUN_00409778`)
  rejects a second open (`ctx+0x4E0 != 1` -> `STATUS_INSUFFICIENT_RESOURCES`) but does not check the requested access
  beyond what the I/O manager already enforced with the DACL.
* Read/Write/IOCTL buffers are system buffers (`DO_BUFFERED_IO`), so missing `ProbeForWrite` is not a gap here: the
  driver never dereferences a user VA.

### 2.6 Memory-write trace

Every write sink in the image was traced:

1. **Read completion** - `FUN_0040EBEC` (`0x40EBEC`): `_Size_00 = min(ctx+0xF0, ctx+0x10C)`;
   `dst = Irp->SystemBuffer + OutputBufferLength - ctx+0x10C`; `memmove(dst, ring, _Size_00)`.
   `ctx+0x10C` is initialised from the read length at `0x40EFAE` and is only decremented by the copied amount, so
   `dst` stays inside the system buffer. This is the standard "fill the pending read" path.
2. **Ring-to-buffer copy** - `FUN_0040ED6E` (`0x40ED6E`): copies from the fixed ring (`ctx+0xE8`, size 0x80/0x400/0x1000
   chosen from `MmQuerySystemSize` at `0x409864`) to a buffer with `_Size` clamped to the ring's available bytes and
   the caller's remaining length.
3. **RX byte insert** - `FUN_0040E700` (`0x40E700`): writes one received byte at `ctx+0xF4`, bounded by
   `ctx+0x104`; wraps at the fixed ring end `ctx+0xF8`.
4. **USB staging** - `FUN_00402F28` (`0x402F28`): `local_e8` is clamped to `local_e4-1` (or `local_e4`) before
   `memcpy(local_d4+1, ctx+0x39, local_e8)`; `local_d4` is a pool block of `local_e4`. No overflow.
5. **Device/context fields** - fixed offsets only (`ctx+0x158`, `+0x174`, `+0x1DF`, `+0x150`, `+0x5C0`, ...).
6. **WMI output** - `FUN_0040BF48` (`0x40BF48`): `if (nameLen+2 <= BufferAvail) { *Buffer = nameLen;
   memcpy(Buffer+1, name, nameLen); }`; bounds are checked.
7. **Registry value read** - `FUN_0040BD82` (`0x40BD82`): `ZwQueryValueKey` into a pool block sized
   `0x18 + callerLen`, then `if (valueLen <= callerLen) memcpy(dst, value, valueLen)`; checked.
8. **Error log** - `FUN_0040BE08` (`0x40BE08`) allocates `IoAllocateErrorLogEntry` with a `UCHAR` size built from
   driver strings and copies `param_13`/`param_15` bytes. The `UCHAR` truncation is a latent robustness issue for
   long strings, but the strings are driver/device names, not IOCTL input, and the lengths are small at every call
   site. Not a caller-controlled write.
9. **No physical/MDL/MMIO path**: no `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmGetPhysicalAddress`,
   `MmProbeAndLockPages`, `MmCopyMemory`, `ZwMapViewOfSection`, or DMA import. The only `Mm*` imports are paging
   helpers.

There is no caller-chosen destination, no caller-chosen value, and no caller-length copy that is not checked against
a kernel allocation or a system-buffer length.

**Write quality: W0.**

### 2.7 Most dangerous exposed capability

The most dangerous capability is a *DoS/robustness* one, not a write: `0x1B0008` (SET_QUEUE_SIZE) lets any opener
request an `ExAllocatePoolWithQuotaTag` of a user-chosen size (quota-limited, failure handled with
`STATUS_INSUFFICIENT_RESOURCES`), and `0x1B0054` zeroes `OutputBufferLength` bytes in the system buffer (bounded by
the allocation the I/O manager made). Neither produces a kernel memory write at an attacker-chosen address.

## 3 `VirtualHID_43774DE0.sys` - Turtle Beach virtual HID miniport (1.0.0.2, i386)

### 3.1 Internals

KMDF driver, 27 functions, imports only `ntoskrnl` (`ExAllocatePoolWithTag`, `IofCompleteRequest`, `Ke*`,
`RtlCopyUnicodeString`, `memcpy`, `memset`, `KeTickCount`) and `WDFLDR` (`WdfVersionBind*`). WDF service functions
are reached through the driver's WDF function table (all entries are zero in the file and are filled by
`WdfVersionBind`). No `IoCreateDevice`, no `WdfDeviceCreateDeviceInterface`, no `WdfDeviceInitAssignName`, no
`WdfDeviceInitAssignSDDLString`, no `WdfDeviceCreateSymbolicLink`, no `WdfControlDeviceInitAllocate`, no `Mm*` /
physical / MDL API, and no `ProbeForRead`/`ProbeForWrite`.

### 3.2 Entry, device, interface, effective DACL

`DriverEntry` `0x10DD2` -> `_FxDriverEntryWorker@8` `0x10CFC` -> `FUN_00010C2A` (`0x10C2A`), which calls the WDF
`WdfDriverCreate`-equivalent table entry with a `WDF_DRIVER_CONFIG` of size `0x14` whose `EvtDriverDeviceAdd` is
`FUN_00010B02` (`0x10B02`). `FUN_00010B02` is `EvtDriverDeviceAdd`:

* `0x10B6C`/`0x10B79`: `WdfDeviceCreate(&DeviceInit, &attributes, &Device)` with a `0x20`-byte
  `WDF_OBJECT_ATTRIBUTES` whose context type is `VHID_CONTEXT` (`0x1105C`), `ExecutionLevel=Passive`,
  `SynchronizationScope=Device`.
* No name, no symbolic link, no SDDL, no device interface is assigned anywhere in the image. There is no
  `\Device\` or `\DosDevices\` literal and no SDDL `"D:P("` string; the only device/identity strings are
  `VHID_CONTEXT`, `KmdfLibrary`, `TurtleBeach\VirtualHID`, `TurtleBeach`, `Virtual HID Device`, `TB1000001`.
* The device is an unnamed PnP FDO; users cannot obtain a handle to it (`CreateFile` needs a name or a device
  interface). The driver builds the `TurtleBeach\VirtualHID` string in `FUN_0001087A` (`0x1087A`) and returns it as
  `Irp->IoStatus.Information`, which is how the HID class stack binds to the devnode; the user-facing HID collection
  then belongs to HIDCLASS, not to this FDO.
* `Effective DACL: none` - there is no open path to apply a DACL to. If it were named, the KMDF default device
  descriptor (`SYSTEM`/`Administrators`) would apply.

**Setup required: devnode/composition** (Turtle Beach virtual-HID devnode + HIDCLASS). On x64 it is additionally
**BLOCKED** by architecture.

### 3.3 Dispatch and IOCTL table

Only one dispatcher is registered:

* `0x10B9C`-`0x10BBE`: a `0x34`-byte `WDF_IO_QUEUE_CONFIG` with `DispatchType = 2` (`WdfIoQueueDispatchParallel`),
  `PowerManaged = 2`, `DefaultQueue = TRUE`, and the callback stored at **config `+0x20`**. In the KMDF 1.9 layout
  (size `0x34`, no `Driver` field) `+0x20` is **`EvtIoInternalDeviceControl`**, not `EvtIoDeviceControl`.
* `0x10BC5`: `WdfIoQueueCreate(Device, &config, NULL, &Queue)`.
* `0x10C10`: a second `WdfIoQueueCreate` with `DispatchType = 3` (`Manual`) and no callbacks - a holding queue.

Because there is no `EvtIoDeviceControl`/`EvtIoRead`/`EvtIoWrite` and no default callback, a user-mode
`DeviceIoControl`/`ReadFile`/`WriteFile` on the (unopenable) FDO would go no further than the framework's
`STATUS_INVALID_DEVICE_REQUEST`.

`FUN_00010A18` (`0x10A18`), the internal-control callback, switches on `IoControlCode`:

| Code | HID miniport operation | Method | Handler / action |
|---|---|---|---|
| `0xB0003` | GET_DEVICE_DESCRIPTOR | NEITHER | `FUN_000104A6`: `WdfRequestRetrieveOutputMemory` + `WdfMemoryCopyFromBuffer(0, fixed 9-byte descriptor)` |
| `0xB0007` | GET_REPORT_DESCRIPTOR | NEITHER | `FUN_00010500`: fixed 0x11E-byte report descriptor to output memory |
| `0xB000B` | READ_REPORT | NEITHER | `FUN_0001072A`: completes with no data |
| `0xB000F` | WRITE_REPORT | NEITHER | `FUN_0001096A`: `IRP->UserBuffer` -> `HID_XFER_PACKET`; copies report into a WDF memory |
| `0xB0013` | GET_STRING | NEITHER | `FUN_000105CC`: string index 0xE/0xF/0x10 -> `TurtleBeach` / `Virtual HID Device` / `TB1000001`; length computed, output memory checked |
| `0xB0027` | GET_DEVICE_ATTRIBUTES | NEITHER | `FUN_0001055E`: writes 0x20-byte attributes block (VID `0x1E7D`, PID 6, version 1) |
| `0xB0191` | GET_FEATURE | NEITHER | `FUN_00010756`: reads `reportBuffer[1]` into `ctx+4` |
| `0xB0192` | SET_FEATURE | NEITHER | `FUN_000107DE`: **writes 1-2 bytes through `reportBuffer`** (see section 3.4) |
| `0xB0195` | input/output report | NEITHER | `FUN_0001096A` (same as WRITE_REPORT) |
| `0xB01A2` | input/output report | NEITHER | `FUN_0001072A` (completes with no data) |

All are `METHOD_NEITHER` by construction (`HID_CTL_CODE`), so the buffers are not copied by the I/O manager. The
driver is written to the HID miniport contract: `HIDCLASS` builds the IRP with a **kernel** `HID_XFER_PACKET`
(`{reportBuffer, reportBufferLen, reportId}`) in `IRP->UserBuffer`.

### 3.4 Memory-write trace

`FUN_000107DE` (`0x107DE`, SET_FEATURE) is the only writer:

```c
Params = query request parameters (0x18-byte WDF_REQUEST_PARAMETERS);  // 0x10808
if (params.DeviceIoControl.InputBufferLength < 0xC)        // 0x1080E
    return STATUS_BUFFER_TOO_SMALL;
Irp = WdfRequestWdmGetIrp(Request);                        // 0x10824
packet = *(HID_XFER_PACKET **)(Irp + 0x3C);                // 0x1082A  IRP->UserBuffer
if (packet == NULL) return STATUS_INVALID_PARAMETER;
if (packet->reportId == 1 && packet->reportBufferLen == 2)
    packet->reportBuffer[1] = 0x14;                        // 0x10861  fixed 1-byte write
else if (packet->reportId == 2 && packet->reportBufferLen == 3) {
    packet->reportBuffer[1] = *(BYTE *)(ctx + 4);          // 0x10850  1-byte write from context
    packet->reportBuffer[2] = 0;                           // 0x10853
}
```

`packet->reportBuffer` is read out of the caller-supplied packet and used as the destination with no
`ProbeForWrite`. If a **kernel** caller passed a `HID_XFER_PACKET` whose `reportBuffer` pointed at an arbitrary
kernel address, the driver would write one byte there (value `0x14`, or the device-context byte) plus a zero. That
is a 1-byte, constrained-value, caller-chosen-destination write (W2-shaped). It is **not reachable from user mode**:

* the queue callback is `EvtIoInternalDeviceControl` (`IRP_MJ_INTERNAL_DEVICE_CONTROL`), which the I/O manager does
  not accept from `DeviceIoControl`;
* the device has no name, symlink, or interface, so there is no handle to send anything to;
* the packet pointer comes from `IRP->UserBuffer`, which for this path is filled by HIDCLASS with a kernel buffer.

`FUN_00010756` (`0x10756`, GET_FEATURE) performs the mirror 1-byte **read** (`ctx+4 = reportBuffer[1]`) with the same
trusted-caller assumption; it is a kernel-read/information-flow issue, not a write.

`FUN_0001096A` (`0x1096A`, WRITE_REPORT path) copies from `reportBuffer+2` into a WDF memory using
`len = reportBuffer[1]` (`0x109D1`) and checks `len <= reportBufferLen - 2` (`0x109D5`-`0x109D9`), so it is bounded.

**Write quality on the requester-reachable surface: W0.** Latent internal-only write: 1 byte, W2-shaped, kernel
caller only.

### 3.5 Most dangerous exposed capability

No requester-reachable capability. The only memory-corrupting code is the SET_FEATURE byte store, and it requires a
kernel caller able to supply a forged `HID_XFER_PACKET` in `IRP->UserBuffer` - i.e. a malicious kernel driver, not
the local administrator. The missing `ProbeForWrite` is a hardening defect in the miniport contract, not an
R1/R2 primitive.

## 4 Overall verdict

**NO-MEMORY-WRITE** for both files; **BLOCKED (architecture)** as the loadability status.

* `ftser2k_6AD3DC79.sys`: standard buffered serial function driver. The COM device is `FILE_DEVICE_SECURE_OPEN`
  with the default `SYSTEM`/`Administrators` DACL; the IOCTL surface is the complete `0x1B00xx` serial set, all
  `METHOD_BUFFERED`, all length-checked, all writing only to `Irp->AssociatedIrp.SystemBuffer` or fixed context
  fields. No MDL, MMIO, physical-memory, or caller-chosen-destination path exists. **W0.**
* `VirtualHID_43774DE0.sys`: unnamed KMDF HID miniport with an internal-device-control-only queue. No device name,
  symlink, interface, or SDDL - nothing user mode can open. The SET_FEATURE handler has a 1-byte constrained write
  through a caller-supplied `HID_XFER_PACKET`, but only a kernel caller can reach it. **W0** on the reachable
  surface.
* Both are i386 PE32 and cannot load on the AMD64 host. Even the absent primitives are unreachable; the correct
  status flag is **BLOCKED**, and no MW1-MW4 rating applies.

## 5 Limitations and unresolved paths

1. **REA not used.** The shared REA bridge was at its four-session limit; this audit is Ghidra/objdump only. No REA
   evidence IDs are available, and no independent decompiler cross-check was performed.
2. **Architecture.** Both images are i386; the analysis describes what the code would do if loaded on a 32-bit
   Windows kernel, not an executable path on this host. No runtime confirmation is possible (and none was
   attempted).
3. **INF/DACL.** The `.inf`/`.cat` are not in the corpus. `ftser2k`'s `.sys` leaves the device DACL at the default
   (admin); a COM-port INF could install an `Everyone` descriptor. That would change Reach from R2 to R1 but does
   not create a write primitive. `VirtualHID`'s devnode security was not assessed for the same reason; it has no
   name/interface regardless.
4. **WDF function-table names.** Most KMDF service calls are indirect through the bind table (entries are zero in
   the file). The queue callback offset (`+0x20` = `EvtIoInternalDeviceControl`) and the device/queue creation
   calls were resolved from the KMDF 1.9 header layout and the call shapes; the five-argument `DeviceInit` call at
   `0x10B37` (table entry `0x113AC`) could not be named offline. It precedes `WdfDeviceCreate` and is not a
   name/SDDL registration (those have 2/3 arguments and no SDDL string exists in the image).
5. **ftser2k error-log helper.** `FUN_0040BE08` truncates its allocation size through `UCHAR` casts while copying
   full-width lengths. All call sites pass driver-generated device/registry strings of small fixed size; this is
   recorded as a latent robustness issue, not a requester-reachable write. A future dynamic test with an oversized
   device name would settle it.
6. **Latent VirtualHID write.** If a kernel component (or a future build that adds `EvtIoDeviceControl`) ever
   exposes `IRP_MJ_DEVICE_CONTROL` with the same handler, the SET_FEATURE path becomes an R1/R2 1-byte
   write-what-where with a constrained value. This build does not expose it.
7. **No dynamic test performed.** Per project rules, loading/execution is reserved for the snapshotted VM and was
   out of scope for this static task.

---

**Report status:** complete for both exact hashes. `audits\STATUS.md` was not modified.
