# Audit: deckser_65A92D8F.sys

| Field | Value |
|---|---|
| File | drivers\deckser_65A92D8F.sys |
| SHA-256 | 65A92D8FBC11CA1AB54A39ADD0FEBEA8222CF7EEE2D598DF46AB878D7E0B248D |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\deckser_65A92D8F.txt`, 90 functions, complete). IOCTL switch read in full (dump 440-800); device creation and dispatch sites located by grep. Import triage, Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Blackmagic Design; file version 15.3.1; "DeckLink Serial Driver" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher |
| Reach | R3 (devnode / hardware: a DeckLink card must be present) |
| Setup required | hardware |
| Write quality | W0 for caller-controlled writes in the traced switch (provisional, see section 8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 WDM serial port driver (port IRP queue with cancel-safe queue `IoCsqInitialize` / `IoCsqInsertIrp`, timers, registry `RtlWriteRegistryValue` / `RtlDeleteRegistryValue` / `ZwQueryValueKey`, worker thread `PsCreateSystemThread`, `IoGetDeviceObjectPointer`, `IoGetDeviceInterfaces`, `KeBugCheckEx`).
- No mapping API (MmMapIoSpace, MmMapLockedPagesSpecifyCache, ZwMapViewOfSection, MmCopyMemory), no memcpy/memmove import, no ZwSetSecurityObject, no SDDL string.
- Entry: DriverEntry sets DRIVER_OBJECT slots at dump 3546-3550: DEVICE_CONTROL (+0xE0) = `FUN_140001470`, CREATE (+0x70) = `FUN_140002160`, CLOSE (+0x80) = `FUN_140002030`.

## 2 Entry / device / interface / effective DACL

- `IoCreateDevice(DriverObject, 0x468, &name, 0x1B)` at dump 1288: DeviceType 0x1B (FILE_DEVICE_SERIAL_PORT), extension 0x468, name built at runtime (device name string in the image: `\Device\DeckLinkSerial`).
- `IoCreateSymbolicLink(..., DriverObject+0x30)` at dump 1489 (`\DosDevices\` link).
- No SDDL string and no `ZwSetSecurityObject` in the image. Effective DACL: IoCreateDevice default, not fixed by the driver.

## 3 Dispatch and IOCTL table

Dispatch: `FUN_140001470` (IRP_MJ_DEVICE_CONTROL slot). The serial IOCTL switch is on `IoControlCode` (`uVar18 = *(uint*)(stack+0x18)`, dump 445). Input length at stack+0x10, output length at stack+0x08. SystemBuffer at IRP+0x18. All codes are 0x1B00xx (DeviceType 0x1B; METHOD and access per the low two bits and bits 14-15).

| IOCTL | Input min | Output min | Kernel action (dump lines) |
|---|---|---|---|
| 0x1B0004 | 4 (469) | - | Writes input DWORD to device field +0x1D0 under the spin lock (470-471). |
| 0x1B0008 | - | - | No case; falls through to the default path (477). |
| 0x1B000C | 3 (479) | - | Validates input bytes (482-485), writes device fields +0x1D8 / +0x1DA (486-488). |
| 0x1B0010 | - | - | Sets flag +0x210 |= 0x10 (491-493). |
| 0x1B0014 | - | - | Clears flag +0x210 &= ~0x10 (496-552). |
| 0x1B0018 | input == 0 (498) | - | Error 0xC000000D or 0xC0000120 when the state check fails (498-501). |
| 0x1B001C | 0x14 (506) | - | Validates input DWORDs (507-512); writes five DWORDs to device fields +0x2EC..+0x2FC (513-521). |
| 0x1B0020 | output >= 0x14 (531) | 0x14 | Copies device fields +0x2EC..+0x2FC (20 bytes) to the output (533-544). Info 0x14. |
| 0x1B0024 | - | - | Default path (528). |
| 0x1B0028 | - | - | Reads state +0x1DC & 3 == 2 check; returns 0xC000000D or 0 (459-466). |
| 0x1B002C, 0x1B0030 | - | - | Completed with the default path (565). |
| 0x1B0034 | - | - | Flag check at +0x1E0 (567-571). |
| 0x1B0038, 0x1B003C | - | - | Completed with the default path (573). |
| 0x1B0040 | output >= 4 (575) | 4 | Writes device field +0x298 (DWORD) to output (576). Info 4. |
| 0x1B0044 | input >= 4 (581) | - | If input DWORD & 0xFFFFE000 == 0: `FUN_1400045D8` (583; dump 2672-2689): AND-mask into device field +0x29C and sets +0x298 from the input DWORD; completes the IRP. No buffer write. |
| 0x1B0048 | output >= 4 (595) | - | `FUN_140004678` (596; dump 2692-2720): queues the IRP on the cancel-safe queue (`IoCsqInsertIrp`, 2701) and may send a lower-stack request. No buffer write. |
| 0x1B004C | input >= 4 (448) | - | If input DWORD != 0 and (DWORD & 0xFFFFFFF0) == 0: `FUN_140003A70` (451; dump 2063-2078): sub-IOCTL 0x222030 whose 256-byte output goes to a local stack buffer `local_118` (2072); completes with no SystemBuffer write. |
| 0x1B0050 | output >= 4 (622) | 4 | Writes device field +0x1D0 to output (624-626). Info 4. |
| 0x1B0054 | output >= 3 (633) | 3 | `memset(output, 0, OutputBufferLength)` (634), then writes 3 bytes of state (637-638). Info 3. |
| 0x1B0058 | output >= 6 (645) | 6 | Writes device field +0x1EC (DWORD) and +0x1F0 (WORD) to output (648-650). Info 6. |
| 0x1B005C | input >= 6 (658) | - | If the device-state check passes, writes input DWORD and WORD to device fields +0x1EC and +0x1F0 (659-665); otherwise 0xC000000D (667). |
| 0x1B0060 | output >= 0x10 (673) | 0x10 | Copies device fields +0x1DC..+0x1E8 (16 bytes) to output (675-685). Info 0x10. |
| 0x1B0064 | input >= 0x10 (690) | - | Validates input fields (691-693), writes four DWORDs to device fields +0x1DC..+0x1E8 under the lock (694-703); otherwise 0xC000000D (705). |
| 0x1B0068, 0x1B0080 | output >= 4 (753) | 4 | Writes zero DWORD to output (754). Info 4. |
| 0x1B006C | output >= 0x14 (719) | 0x14 | `FUN_1400012B8` (721; dump 294-333): writes DWORD `SystemBuffer[0]` from device field +0x20C, byte at +0x10, DWORD at +0x0C, and a sub-IOCTL 0x222038 with a 4-byte output into SystemBuffer+8 (309). All writes are within the 0x14-byte output. Info 0x14. |
| 0x1B0070 | input >= 0xC (714) | - | If input DWORD[1] > 0 completes (715); otherwise error (717). |
| 0x1B0074 | output >= 0x40 (604) | 0x40 | Writes a fixed 0x40-byte status structure (606-618). Info 0x40. |
| 0x1B0078 | output >= 4 (727) | 4 | Writes zero DWORD to output (728). Info 4. |
| 0x1B007C | input != 0 (736) | - | Reads input byte; sets flag +0x1DB if the state check passes (737-748). |
| 0x1B008C | output >= 0x18 (760) | 0x18 | Copies device fields +0x1F8..+0x204 (24 bytes) to output (761-772). Info 0x18. |
| 0x1B0090 | - | - | Clears device fields +0x1F4..+0x204 (777-782). |
| 0x1B0094 | output >= 4 (785) | 4 | Writes device field +0x1D4 to output via the same path as 0x1B0050 (786-788). Info 4. |
| 0x1B0098 | input >= 4 (799) | - | Not traced in detail (dump 799-800). |
| 0x1B009C | input >= 4 (794) | - | Completes with no action when the input is at least 4 bytes (dump 794, 561); otherwise the default error path. |
| other | - | - | STATUS_INVALID_DEVICE_REQUEST (0xC000000D) (797). |

## 4 Access-control audit

- No privilege or caller-identity check in the driver. The gates are device-state flags and the length checks in section 3. Any principal that can open the device object (IoCreateDevice default security) can issue these codes.

## 5 Memory-write trace

1. **Output writes at fixed offsets:** 0x1B0020, 0x1B0040, 0x1B0050, 0x1B0058, 0x1B0060, 0x1B0068/0x1B0080, 0x1B0074, 0x1B0078, 0x1B008C, 0x1B0094 write fixed-size data (4 to 0x40 bytes) into the SystemBuffer after the output-length check. Destinations fixed; values device state. Bounded.
2. **0x1B0054 memset:** `memset(SystemBuffer, 0, OutputBufferLength)` at dump 634, executed only when OutputBufferLength > 2 (633). Length is the caller's output length, which is also the SystemBuffer's size (METHOD buffered). Bounded.
3. **Device-field writes from input:** 0x1B0004, 0x1B000C, 0x1B001C, 0x1B0064, 0x1B005C write fixed device fields from input DWORDs or bytes at fixed offsets (dump 471, 486-488, 513-521, 694-703, 659-665). No caller-chosen index.
4. **Handlers 0x1B0044, 0x1B0048, 0x1B004C, 0x1B006C (dump 2672-2720, 2063-2078, 294-333):** traced in full (section 3). Each writes only device fields, a local stack buffer, or within the output-length check.

Conclusion: no write in the IOCTL surface uses a caller-supplied destination, unbounded length, or caller-chosen index.

## 6 Most dangerous exposed capability

- The sub-IOCTLs 0x222030, 0x222038 sent to the lower device by 0x1B004C and 0x1B006C; their outputs are bounded (256-byte stack buffer, 4-byte SystemBuffer region). No kernel write primitive.

## 7 Verdict

**NO-MEMORY-WRITE.** No caller-controlled kernel write in the IOCTL surface; all IOCTL cases in the switch (0x1B0004-0x1B009C) were traced. Reach R3 (devnode / hardware); Setup: hardware; W0. HW-only: no.

## 8 Limitations

- The create and close routines (`FUN_140002160`, `FUN_140002030`) and the cancel-safe queue helpers were not read; they are not buffer-copy paths on the IOCTL surface.
- The lower device's behavior for sub-IOCTLs 0x222030 and 0x222038 is outside this image.
- No REA session used. No execution, no driver load, no registry writes.
