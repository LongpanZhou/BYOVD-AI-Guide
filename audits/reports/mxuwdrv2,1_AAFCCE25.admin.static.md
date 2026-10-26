# Audit: mxuwdrv2,1_AAFCCE25.sys

| Field | Value |
|---|---|
| File | drivers\mxuwdrv2,1_AAFCCE25.sys |
| SHA-256 | AAFCCE2545DB9419E881E5800C50A92D1720EC81B80524BCC7226DB5874610C5 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\mxuwdrv2_1_AAFCCE25.txt`, complete; scratch stem `mxuwdrv2_1_AAFCCE25`). Device creation (dump 347, 4527, 11712, 12348), IOCTL switch at dump 6355-6533 (case labels located; handlers not read), 0x222080 case (dump 6520-6523) read. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Moxa Inc.; file version 4.3 Build 26010215; "MOXA UPort 1110/1130/1150 Driver" |
| Signature | Authenticode Valid; signer CN=MOXA INC. |
| Reach | R3 (devnode / hardware: a Moxa UPort 1110/1130/1150 USB adapter must be attached) |
| Setup required | hardware |
| Write quality | W0 (provisional, see §8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 WDM serial / USB driver (Moxa UPort 1110/1130/1150 family, 2026 build). Imports include `IoCreateDevice`, `IoCreateSymbolicLink` and `IoCreateUnprotectedSymbolicLink`, `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`, `ZwCreateFile`, `ZwReadFile`, `IoBuildDeviceIoControlRequest`, `PsCreateSystemThread`, `IoQueueWorkItemEx`, `IoCreateSystemThread`, `RtlWriteRegistryValue`, `MmGetSystemRoutineAddress`, `RtlIsNtDdiVersionAvailable`.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, ProbeForWrite, memcpy or memmove import. No `ZwSetSecurityObject`, no SDDL string.
- Dynamic resolution: `MmGetSystemRoutineAddress` is imported (dump imports). It is used for version-dependent calls (not traced in this pass); it can resolve an API by name at runtime, so the resolved set is not visible from the imports.

## 2 Entry / device / interface / effective DACL

- `IoCreateDevice(param_2, param_7+8, name, param_4)` at dump 347 (device name built at runtime; strings include `\Device\SerBus%0d`, `\Device\UMP%%d`, `\Device\UMPLDR%%d`, `\Device\mxuport%d`, `\DosDevices\`).
- `IoRegisterDeviceInterface(…, &DAT_1400150E0, …)` at dump 4527; `IoCreateUnprotectedSymbolicLink` at dump 11712; `IoRegisterDeviceInterface` at dump 12348 (second interface).
- No SDDL string or `ZwSetSecurityObject`. Effective DACL: IoCreateDevice default and PnP interface default; not fixed by the driver.

## 3 Dispatch and IOCTL table

The IOCTL switch (dump 6355-6533) covers the serial family and one vendor code:

| Code (first dump line) | Gate / handling (as read) |
|---|---|
| 0x1B0004 - 0x1B009C (6355-6516) | Serial family: case labels present (0x1B0004, 0x1B0008, 0x1B000C, 0x1B0010, 0x1B0014, 0x1B0018, 0x1B001C, 0x1B0020, 0x1B0024, 0x1B0028, 0x1B002C, 0x1B0030, 0x1B0034, 0x1B0038, 0x1B003C, 0x1B0040, 0x1B0044, 0x1B0048, 0x1B004C, 0x1B0050, 0x1B0054, 0x1B0058, 0x1B005C, 0x1B0060, 0x1B0064, 0x1B0068, 0x1B006C, 0x1B0070, 0x1B0074, 0x1B007C, 0x1B0080, 0x1B008C, 0x1B0090, 0x1B0094, 0x1B0098, 0x1B009C). Handlers not read in this pass. |
| 0x222080 (6520-6523) | Forwards the request through the guarded dispatch pointer `PTR__guard_dispatch_icall_1400142E0` (6521). No buffer handling in this function. |
| other | Invalid parameter (0xC000000D) (6525-6526); STATUS_INVALID_DEVICE_STATE (0xC0000056) at 6529 when the device-state gate fails. |

Method and access: serial codes are METHOD_BUFFERED with FILE_ANY_ACCESS (low bits 0, bits 14-15 zero).

## 4 Access-control audit

- No privilege or caller-identity check in the dispatcher; the gates are device state (6529) and the code match.

## 5 Memory-write trace

- No memcpy, mapping or copy primitive is imported. The only user-buffer handler read (0x222080) forwards the request without writing to the caller's buffer.
- The handlers of the serial family were not read. They follow the same family as `deckser_65A92D8F` and `mxuport,1_5B845038`, where all output writes were gated by the output length (not re-verified in this build).

## 6 Most dangerous exposed capability

- Not established. The serial handlers and the forwarded request path (0x222080) were not read in full.

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** No caller-controlled kernel write found in the traced code. The serial handlers are open. Reach R3 (devnode / hardware); Setup: hardware; W0 in the traced code. The image is signed (Valid). HW-only: no.

## 8 Limitations

- The serial handlers (dump 6355-6516 targets) were not read; the verdict is provisional until they are checked for output-length gating.
- `MmGetSystemRoutineAddress` is imported; the set of runtime-resolved APIs was not enumerated.
- No REA session used. No execution, no driver load, no registry writes.
