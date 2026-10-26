# Audit: idisplayfilter,2_1993A861.sys

| Field | Value |
|---|---|
| File | drivers\idisplayfilter,2_1993A861.sys |
| SHA-256 | 1993A86196AC2F9E5C58F3E4324A9D0BBC84F18F446887739E33B36389985187 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\idisplayfilter_2_1993A861.txt`, complete; scratch stem `idisplayfilter_2_1993A861` because the comma in the file name broke the cmd launcher). DriverEntry, device creation (FUN_14000255C), default dispatch (FUN_14000241C), PnP (FUN_140001664) and AddDevice (FUN_1400012D0) read; SDDL resolved from the image. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | None in version resources (no VersionInfo) |
| Signature | Authenticode Valid; signer CN=SHAPE GmbH |
| Reach | R1 for opening the named device: the effective DACL grants Everyone (WD) GR and GW (see §2). Setup: devnode (the filter attaches to a display device). |
| Setup required | devnode |
| Write quality | W0 on the IOCTL path in this image (provisional, see §8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 WDM display filter (iDisplay / SHAPE). Imports: `IoCreateDevice`, `WdmlibIoCreateDeviceSecure` (via `IoCreateDeviceSecure` lookup, dump 1820-1835), `ZwSetSecurityObject`, `IoConnectInterruptEx`, `IoAttachDeviceToDeviceStack`, `IoGetDeviceProperty`, `ObOpenObjectByPointer`, `SeCaptureSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlAddAccessAllowedAce`, `IoValidateDeviceIoControlAccess` (import name at dump 1825), `MmGetSystemRoutineAddress`, `KeBugCheckEx`.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress or ProbeForWrite import.
- Entry: DriverEntry (dump ~3270-3310): all 28 MajorFunction slots set to `FUN_14000241C` (3296-3300); PnP (+0x148) = `FUN_140001664` (3301); power (+0x120) = `FUN_140002324` (3302); AddDevice (DriverExtension+8) = `FUN_1400012D0` (3303); DriverUnload slot (+0x68) = `LAB_140002410` (3304).

## 2 Entry / device / interface / effective DACL

- The named device is created in `FUN_14000255C` (dump 919-972): `RtlInitUnicodeString(L"\\Device\\idisplaywddm")` (934) then `WdmlibIoCreateDeviceSecure(DriverObject, ext 0x48, &name, DeviceType 0x23, Characteristics 0x100 (FILE_DEVICE_SECURE_OPEN), Exclusive 0, &DAT_140004460, 0, &device)` (936-938).
- The default SDDL argument `DAT_140004460` is a UNICODE_STRING (Length 0x6E bytes, MaximumLength 0x70, dump-image VA 0x140004460, file offset 0x3060). Its text: **`D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)`** (read from the image bytes; `WdmlibIoCreateDeviceSecure` applies it with `ZwSetSecurityObject` at dump 1882).
- Effective DACL decoded: SYSTEM GA (generic all); Administrators GR|GW|GX; **Everyone (WD) GR|GW**; RESTRICTED CODE (RC) GR. The FILE_DEVICE_SECURE_OPEN flag applies this descriptor on every open.
- Consequence: any unprivileged user can open the named device for read and write under this descriptor. Reach is R1 for the open. The IOCTL surface is controlled by what the device does on IRP (§3).

## 3 Dispatch and IOCTL table

- IRP_MJ_DEVICE_CONTROL slot (+0xE0) = `FUN_14000241C` (default for all slots; DriverEntry dump 3296-3300). `FUN_14000241C` (dump 881-916) takes the device-extension remove lock (`IoAcquireRemoveLockEx`, 895), increments the stack location, and forwards with `IofCallDriver(ext+0x10, Irp)` (908). **It does no IOCTL decoding.**
- For the named device, the extension's lower-device pointer (+0x10) is not set in `FUN_14000255C` (dump 940-943 set only the first qword and the remove lock). The behavior of an IOCTL sent to `\Device\idisplaywddm` therefore depends on a value that this pass did not resolve. This is an open point (§8).
- IOCTL switch: none found. The grep for `== 0x22xxxx` and `== 0x2xxxxx` case labels returns none, and `IoValidateDeviceIoControlAccess` is imported only by name (dump 1825). No IOCTL code is handled in this image's dispatch.

| Code | Method | Access | Input | Output | Kernel action |
|---|---|---|---|---|---|
| none decoded | - | - | - | - | IOCTLs are forwarded by the default pass-through (§3 above). |

## 4 Access-control audit

- The effective DACL grants WD GR|GW (§2). No `SeAccessCheck` or privilege check in the driver's IOCTL path (none present in the dispatch). The ACL, not the driver, is the gate: any unprivileged user has read and write access to the named device.

## 5 Memory-write trace

- memcpy call sites: dump 725, 771 (inside the PnP handler `FUN_140001664`, copying resource/device strings), 992 (`FUN_14000255C` ... `memcpy(_Dst, param_1, _Size)`), 1780 (in `FUN_140001664`), 2381 (`RtlAddAccessAllowedAce` ACL build), 2816 (`SepSddl...`/library), 2939 (library). None are on the IOCTL path (the dispatch is the pass-through `FUN_14000241C`).
- Writes in `FUN_14000255C` (dump 939-943) are to the device object and its extension (fixed offsets, after creation).
- No write uses a caller-supplied destination or length, because the caller's IOCTL buffers are not handled by this image.

## 6 Most dangerous exposed capability

- Unprivileged read/write open of `\Device\idisplaywddm` (R1, from the SDDL) combined with the pass-through: whatever the lower device accepts is reachable. The lower device (the display stack) is outside this image. No kernel memory write is found in this image.

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** No memory write on any IOCTL path in this image: the dispatch is a pass-through, and the copies are in the PnP and ACL-building code. The named device is openable by Everyone for read and write (R1), which is a severe access finding even though this image holds no write primitive. Setup: devnode; HW-only: no.

## 8 Limitations

- The lower-device pointer of the named device is not resolved (§3). If IOCTLs to the named device are forwarded to a lower stack, the write surface is in that lower stack, which is outside this image.
- The PnP handler `FUN_140001664` (3,257 bytes) and power handler `FUN_140002324` were read only at their memcpy sites.
- The DriverUnload slot target `LAB_140002410` was not read.
- No REA session used. No execution, no driver load, no registry writes.
