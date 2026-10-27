# Audit: libusbK_1DF66FF2.sys

| Field | Value |
|---|---|
| File | drivers\libusbK_1DF66FF2.sys |
| SHA-256 | 1DF66FF22E2EAEC27180756D90926CA5B07E8BCF6B0E4E3C56471E63A3A05FA6 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\libusbK_1DF66FF2.txt`, complete). IOCTL dispatcher `FUN_00015570` (5,246 bytes, dump 3123-~3700) read in part (first case and case-label map); second dispatcher `FUN_00011050` (1,255 bytes) and `FUN_00014128` / `FUN_00014968` / `FUN_00014dc4` located by grep. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | "http://libusb-win32.sourceforge.net"; file version 3.0.7.0 (WinDDK build); "libusbK(lusbk) WDF USB Driver" |
| Signature | Authenticode Valid; signer CN=Travis Lee Robinson |
| Reach | R3 (devnode / hardware: a USB device bound to libusbK must be present); the device-interface and DosDevices name `\DosDevices\libusb0-` are created through the driver's own device objects |
| Setup required | devnode (INF binding to a USB device) |
| Write quality | W0 (provisional: no kernel write to a caller-chosen address found in the traced cases; see section 8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 KMDF USB driver (WDFLDR imports; WDF calls through indirect pointers `DAT_0001aeb8` / `DAT_0001a718` / `DAT_0001a880` / `DAT_0001aaa0`). Imports: `RtlGUIDFromString`, `RtlCopyUnicodeString`, `_snwprintf`, `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `USBD_GetUSBDIVersion`, `KeBugCheckEx`, `DbgPrint`.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, ProbeForWrite, memcpy or memmove import. The image contains a `\DosDevices\libusb0-` name string.
- Entry: DriverEntry and WDF callbacks are located through the WDF function table; the IOCTL dispatcher is `FUN_00015570`.

## 2 Entry / device / interface / effective DACL

- Device names: `\DosDevices\libusb0-` (the only device-name string). No SDDL string and no `ZwSetSecurityObject` in the image. Effective DACL: WDF default for the device created through the driver's device-init.
- The libusbK IOCTL surface is reached through the WDF queue callback (`FUN_00015570` takes the request, the queue and the IRP-stack values, dump 3125).

## 3 Dispatch and IOCTL table

`FUN_00015570` is the device-control dispatcher: it reads the IOCTL code (`param_5`, dump 3125) and branches on it. For each case the first step retrieves the request buffers with WDF (for example `(*DAT_0001aaa0)(DAT_0001aeb8, request, 1, &buf, &len)`, dump 3183) and returns STATUS_INVALID_PARAMETER (0xC0000010) when the device or pipe handles are missing (3169-3174).

Case labels found in the dispatcher (dump line of the first label):

| IOCTL | Dump line | Case behavior (as read) |
|---|---|---|
| 0x222408 | 3181 | Retrieves a 1-byte buffer, writes one byte from the device state (3183-3196). Fixed size. |
| 0x222410 | 3198 | Not read. |
| 0x222418 | 3219 | Not read. |
| 0x22241C | 3236 | Not read. |
| 0x222420 | 3245 | Not read. |
| 0x222424 | 3276 | Not read. |
| 0x222429 | 3277 | Stores 0x222429 in an internal request field (3291). Not read further. |
| 0x22242E | 3295 | Stores 0x22242E (3309). Not read further. |
| 0x222430 | 3314 | Not read. |
| 0x222434 | 3180 | Not read. |
| 0x222438 | 3390 | Not read. |
| 0x22243C | 3398 | Not read. |
| 0x222440 | 3411 | Not read. |
| 0x222444 | 3420 | Not read. |
| 0x222448 | 3421 | Not read. |
| 0x22244D | 3432 | Stores 0x22244D (3452). Also referenced at `FUN_00011050` dump 1382. |
| 0x222452 | 3458 | Stores 0x222452 (3478). Also referenced at `FUN_00011050` dump 1382. |
| 0x222455 | 3482 | Stores 0x222455 (3502). Not read further. |
| 0x22245A | 3507 | Stores 0x22245A (3527). Not read further. |
| 0x222058 | 3553 | Not read. |
| 0x22202E | 3560 | Not read. |
| 0x222018 | 3607 | Stores 0x222018 (3632). Not read further. |
| other | - | STATUS_INVALID_PARAMETER path (`LAB_000158ca`, dump 3170-3173). |

Method and access bits were not decoded for each code; all codes are in the 0x22xxxx range (DeviceType 0x22), so METHOD and ACCESS bits follow the low two and bits 14-15 of each code (not stated per row here).

## 4 Access-control audit

- No `SeAccessCheck` or privilege check in the dispatcher. The gates are the presence of the WDF device handles and the pipe handles (dump 3169-3174) and the request buffer minimum sizes.

## 5 Memory-write trace

- The traced case (0x222408, dump 3183-3196) writes one byte to the retrieved request buffer (`*(char*)local_70`, 3187/3190) after the minimum-size retrieval. Bounded.
- The stored-code cases (0x222018, 0x222429, 0x22242E, 0x22244D, 0x222452, 0x222455, 0x22245A; dump 3291, 3309, 3452, 3478, 3502, 3527, 3632) store the code into an internal request field (`piVar13[3]`) and then queue the request. The writes are to driver-owned request context, not to a caller-chosen address.
- Transfer cases (control/bulk/interrupt I/O with caller-supplied lengths) were not traced; their buffer handling decides the verdict (section 8).

## 6 Most dangerous exposed capability

- Not established for the traced cases. The transfer cases carry caller-supplied lengths into WDF USB requests (device-facing), and their buffer validation was not read.

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** No kernel write to a caller-chosen address found in the traced cases. The device-facing transfer cases are open. Reach R3 (devnode / hardware); Setup: devnode; W0 for the traced cases. The image is signed (Valid). HW-only: no.

## 8 Limitations

- Most case bodies of `FUN_00015570` (dump 3123-~3700) were not read; the transfer cases are the open candidates, since they accept caller-supplied lengths.
- `FUN_00011050` (1,255 bytes), `FUN_00014128`, `FUN_00014968`, `FUN_00014dc4` were not read.
- The WDF function-table indices are not named in the dump (WDF symbols absent), so WDF calls are identified by position and argument count only.
- No REA session used. No execution, no driver load, no registry writes.
