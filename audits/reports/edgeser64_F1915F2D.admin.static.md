# Audit: edgeser64_F1915F2D.sys

| Field | Value |
|---|---|
| File | drivers\edgeser64_F1915F2D.sys |
| SHA-256 | F1915F2D5DD1EB85A851AB7E56FEAEEF8C21DEDBF03AEA5DB72E78314892E9AF |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\edgeser64_F1915F2D.txt`, complete, about 1.2 MB). Device creation and IOCTL dispatch located by grep; the 0x22205C-0x222078 and 0x1B0xxx handler blocks sampled (dump 6544-7810, 9150-9800); other blocks not read. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Digi International; file version 6.04.001; "Edgeport Serial Driver 64 bit" |
| Signature | Authenticode status UnknownError; signer CN="WDKTestCert davidi,132294677773414589" (test-signing certificate, not a WHQL chain) |
| Reach | R3 (devnode / hardware: an Edgeport USB adapter must be present) |
| Setup required | hardware, and a test-signed load path |
| Write quality | W0 (provisional, see section 8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 WDM serial / USB port driver (port IRP queue, USBD imports `USBD_ParseDescriptors`, `USBD_CreateConfigurationRequest(Ex)`, timers, WMI, `ObReferenceObjectByName`, `IoCreateUnprotectedSymbolicLink`, `RtlWriteRegistryValue`, `ZwCreateFile`, `PsCreateSystemThread`, `KeBugCheckEx`, `sprintf` / `swprintf`).
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress or memcpy import. The copy helper `FUN_14003A1C0` is internal (called at dump 7513, 7554).

## 2 Entry / device / interface / effective DACL

- `IoCreateDevice(DriverObject, 0x4E0, 0, 0x22, 0, 1, &device)` at dump 1229: DeviceType 0x22, extension 0x4E0, **unnamed**, Exclusive = 1.
- Symbolic links and names in the image: `\Device\EdgeSer%u`, `\Device\USBSERIAL%03u`, `\DosDevices\COM%u`, `\DosDevices\USBSERIAL%03u`, `\DosDevices\HCD%d`. Links are created with `IoCreateSymbolicLink` and `IoCreateUnprotectedSymbolicLink`.
- No SDDL string and no `ZwSetSecurityObject` in the image. Effective DACL: default; the exclusive flag does not change the DACL.

## 3 Dispatch and IOCTL table

Sampled blocks (dump line numbers):

| IOCTL | Method | Access | Input min | Output min | Kernel action (dump lines) |
|---|---|---|---|---|---|
| 0x22205C | - | - | - | - | `FUN_14000D534` call with trace hooks (7379-7390). Returns a device value; no buffer write. |
| 0x222004 | - | - | - | output buffer non-null | Calls `FUN_140001F84` to get a device buffer; if the output is shorter than the returned length (`uVar4 < local_78`) the request fails 0xC0000023, else copies with `FUN_14003A1C0` (7497-7519). Copy length is bounded by the output length. |
| 0x222008 | - | - | - | output buffer non-null | Same pattern as 0x222004 with the direction flag set (7520-7531). Bounded. |
| 0x222020 | input/output > 3 (7533) | - | - | - | Writes one byte from the input to the device buffer request (7534-7542). |
| 0x222024 | - | - | - | - | `FUN_140009B50` returns a buffer of length `local_68`; copied only if `local_68 <= output length` (7546-7559). Bounded. |
| 0x222028 | - | - | - | - | Not read. |
| 0x222084, 0x222068, 0x22206C, 0x222074, 0x222078, 0x22207C, 0x222088 | - | - | - | - | Not read (dump 7604-7803). |
| 0x223000, 0x223004, 0x223008, 0x22300C | - | - | - | - | Not read (dump 7612-7667). |
| 0x1B0070 | input >= 0xC (7405) | - | - | - | Forwards to `FUN_1400250D4` when input DWORD[1] > 0 (7406-7409). |
| 0x1B0074 | - | output >= 0x40 (7422) | - | 0x40 | `FUN_140014C6C` fills the 0x40-byte output (7423-7425). Info 0x40. |
| 0x1B0078 | - | output >= 4 (7434) | - | 4 | Writes a 2-bit status DWORD (7435-7446). Info 4. |
| 0x1B007C | input != 0 (7450) | - | - | - | Reads input byte and sets device flag +0xC9 if the state check passes (7451-7463). |
| 0x1B0080 | - | output >= 4 (7472) | - | 4 | Zeroes the output DWORD (7474-7475). Info 4. |
| 0x1B008C | - | output >= 0x18 (7485) | - | 0x18 | Zeroes six DWORDs of the output (7486-7493). Info 0x18. |
| 0x1B0090 | - | - | - | - | Sets a 0x80-byte internal state (7393-7397). |
| 0x1B0058, 0x1B005C, 0x1B0060, 0x1B0064 | - | - | - | - | Dispatch branches at 7162-7304; handlers not read. |
| 0x1B0004 / 0x1B0008 / 0x1B0010 / 0x1B0024 / 0x1B0028 / 0x1B0030 / 0x1B0034 / 0x1B0038 / 0x1B003C / 0x1B0040 / 0x1B0044 / 0x1B0048 / 0x1B004C / 0x1B0054 / 0x1B006C / 0x1B001C | - | - | - | - | Dispatch branches at dump 6544-7100 and 9150-9800; handlers not read. |

Full coverage was not achieved. The table lists every code that appears as a case label in the sampled blocks; the codes marked "not read" are open.

## 4 Access-control audit

- No privilege or caller-identity check in the driver found in the sampled blocks. Gates are device state and length checks.

## 5 Memory-write trace

- Sampled copies (0x222004, 0x222008, 0x222024) are bounded by the output length (dump 7509-7514, 7553-7554). The copy helper `FUN_14003A1C0` is internal; its destination is the SystemBuffer.
- Fixed-offset writes (0x1B0078, 0x1B0080, 0x1B008C, 0x222020) write fixed-size data.
- The unread blocks (section 3) are where any user-length copy would sit; they are the open candidates.

## 6 Most dangerous exposed capability

- Not established for the sampled blocks. The 0x223000-0x22300C family and 0x222084-0x22207C are the largest unread set.

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** No caller-controlled kernel write found in the sampled IOCTL blocks. The image is test-signed (UnknownError) and is not loadable on a normally configured system. Reach R3; Setup: hardware. HW-only: no.

## 8 Limitations

- The IOCTL switch is large (two dispatch families, dump 6544-9800). Only the blocks listed in section 3 were read. The codes marked "not read" (including 0x223000-0x22300C and 0x222028-0x22207C) must be read before the verdict is final.
- Digi-specific device-object logic (`FUN_140001408`, `FUN_140001430`, `FUN_140001D7C`: debug/trace hooks gated by a flag at DAT_14003F000) was not read.
- No REA session used. No execution, no driver load, no registry writes.
