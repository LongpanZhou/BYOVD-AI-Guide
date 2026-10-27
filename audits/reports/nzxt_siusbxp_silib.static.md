# NZXT `SiUSBXp` + `SiLib` - static audit

| Binary | SHA256 (prefix) | PE TS | Product | Verdict |
|---|---|---|---|---|
| `SiUSBXp_A8BE9E3F.sys` | `A8BE9E3F...` | 2010-07-15 | USBXpress 3.3 | **NO-WRITE** (hardware-bound; no KVA/PHYS/PORT sink) |
| `SiLib_DD2C9A1D.sys` | `DD2C9A1D...` | 2010-07-15 | Silicon Laboratories 1.3.0.0 | **NO-WRITE** (PnP device-interface only; no sink) |

Method: static only. Ghidra 12.1.4 headless, `DumpAllDecomp.java` (full dump) for both. Nothing loaded or installed.

## 1. The question from the brief: does SiUSBXp create a device, and under what name?

Yes, one device, created **unnamed** in its AddDevice routine. Details:

- `entry` @ `0x19064`. AddDevice is `FUN_000137e8` @ `0x137e8`.
- Device creation at line 1862 of the dump: `IoCreateDevice(DriverObject, size, NULL, 0x22, 0x80, 0, &devobj)`. The third argument (device name) is `NULL`.
- The string `\DosDevices\USBINT` (literal `0x14a70`, referenced at `0x1380a` in `FUN_000137e8`) is copied into the device extension with `RtlCopyUnicodeString`. It is **not** published as a symbolic link: `IoCreateSymbolicLink` is not in the import table.
- Exposure is a device interface, not a named device. `GenericRegisterInterface` is **imported from `SILIB.SYS`** (`ns=SILIB.SYS` in the import table), so the registration lives in SiLib (section 2). The interface GUID is referenced at `0x16160` in SiUSBXp.

So the only user-reachable path is a PnP device interface on the attached USB device. There is no `\DosDevices\USBINT` name that a standard user can open without that device.

## 2. SiLib - the interface registration

- `GenericRegisterInterface` @ `0x148d0` (SiLib). Takes a resource lock on the extension, inserts a record into a list keyed by the GUID pair, and calls `IoRegisterDeviceInterface(PDO = extension+0x10, GUID, ...)` at line 3172 of the dump.
- SiLib creates no device object of its own (no `IoCreateDevice` import). Its entry `entry` @ `0x1b064` calls `FUN_0001b008` and `FUN_00016008`. Neither creates a named device.
- Imports include `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`, `IoOpenDeviceRegistryKey`, `IoInvalidateDeviceState`, `PoRegisterDeviceForIdleDetection`. These are PnP-only: they run when the USB device enumerates.

## 3. Sink check (both binaries)

| Class | Sink found? | Evidence |
|---|---|---|
| KVA (write to kernel VA from user input) | No API-level sink | No `MmCopyMemory`, `ZwMapViewOfSection`, `MmMapLockedPages*` import in either binary. Inline stores through pointers were **not** reviewed (see section 5). |
| PHYS (physical map / write) | No | No `MmMapIoSpace` or `HalGet/SetBusData*` import in either binary. |
| PORT (I/O, MSR, PCI config) | No | No `HalGet/SetBusData*`, `wrmsr`, or port intrinsic (`in`/`out`) in either decompiled dump. |

The only data the drivers take from the device side is USB descriptors (`USBD_ParseDescriptors` in `FUN_00014264` @ `0x14264`). Those come from the hardware, not from a user, so they are not a user-reachable input.

## 4. Precondition table

| Item | SiUSBXp | SiLib |
|---|---|---|
| Device object | Yes, unnamed, in AddDevice (`0x137e8`) | None (no `IoCreateDevice`) |
| Named symlink | Name stored, **not published** | None |
| User-reachable entry | Device interface, only after USB device enumerates | Device interface (registration only) |
| Setup cost | **hardware** (USB device, VID/PID) + **devnode** (PnP enumeration) | **hardware** + **devnode** |
| DACL | Not applicable (no named device to open) | Not applicable |
| Master-table label | `DEFAULT-ADMIN` in `master_drivers.csv`; **incorrect** - the device has no name to open at all | `NO-DEVICE`; correct |

Both are disqualified by policy: the surface requires a USB device attached and a devnode. The DACL question does not arise.

## 5. Callback / IOCTL table

Not applicable as an IOCTL table. The Generic framework callbacks registered by SiUSBXp: `FUN_0001477c` @ `0x1477c`, `FUN_00013c60` @ `0x13c60`, `FUN_00011530` @ `0x11530`, `FUN_000114b4` @ `0x114b4` (set in `FUN_000137e8` near line 1940 of the dump). These handle USB transfers to the attached device. **Not decompiled or reviewed one by one.** The section 3 check covers API-level sinks only. An inline store through an attacker-chosen pointer would not show up as an import, so the verdict does not rest on section 3 alone. It rests on the hardware disqualifier in section 4: none of these callbacks is reachable without the attached USB device.

## 6. Corruption, not write

- SiUSBXp: none found. The descriptor parser handles device-supplied data (hardware, not user), so it is outside the user-reachable surface.
- SiLib: none reviewed beyond the interface registration path.

## 7. Next dynamic test

None planned. Both are disqualified by policy (hardware and devnode). If the policy changes, the first test would be a standard-user open of the interface GUID on an attached device, which needs hardware and is out of scope.

## 8. NO-WRITE reasons (one line each)

- **SiUSBXp:** no API-level KVA, PHYS, or PORT sink in the binary, and the only user-reachable path is a PnP device interface that exists only with the USB hardware attached. The hardware requirement is what disqualifies it.
- **SiLib:** no device object of its own and no sink. Its only function is PnP interface registration.

## 9. Notes

- The master table's `DEFAULT-ADMIN` label for SiUSBXp should be corrected. The driver publishes no openable name, so "admin-only" is not the right description; "hardware-only" is.
- SiUSBXp depends on SiLib.sys. Both ship in the same NZXT package, so both must be present to be used.
