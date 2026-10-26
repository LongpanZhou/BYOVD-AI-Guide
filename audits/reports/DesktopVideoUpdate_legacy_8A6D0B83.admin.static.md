# Audit: DesktopVideoUpdate_legacy_8A6D0B83.sys

| Field | Value |
|---|---|
| File | drivers\DesktopVideoUpdate_legacy_8A6D0B83.sys |
| SHA-256 | 8A6D0B832DF371D96A153AAB31EAEED4090B89DC3B8E99FA723F381E834CD03C |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\DesktopVideoUpdate_legacy_8A6D0B83.txt`, 41 functions, decompile complete). Dump compared line-by-line with `DesktopVideoUpdate_81F65827` (see Limitations): identical except the program name on line 1. PE import/string triage; Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Blackmagic Design; file version 4.0.2.0; "Blackmagic Design USB Driver" |
| Signature | Authenticode status UnknownError; signer CN="WDKTestCert build,131958900460134002" (test-signing certificate, not a WHQL chain). Image is 18,104 bytes against 28,592 for the signed sibling, consistent with the signature block being removed. |
| Reach | R3 (devnode / hardware) |
| Setup required | hardware, and a test-signed load path (test-signing or a loader that accepts this signature) |
| Write quality | W0 (no caller-controlled kernel memory write; bounded SystemBuffer and URB transfers only) |
| Severity | NO-MEMORY-WRITE |
| HW-only | no |

## 1 Internals

- Same code as `DesktopVideoUpdate_81F65827` (dump-identical functions). Entry, DriverEntry `FUN_1400013A8`, AddDevice `FUN_140001950`, IoCreateDevice `FUN_1400015BC`, dispatch table at dump 264-277, IOCTL dispatcher `FUN_140001A20` (dump 618-956) all as in that report.
- Imports identical (ntoskrnl device/PnP/IRP/pool APIs; USBD parse/create/version). No mapping or copy primitive in the imports.

## 2 Entry / device / interface / effective DACL

- IoCreateDevice with DeviceName = NULL, DeviceType 0x22, extension 0x80 (dump 394). No SDDL or symbolic link. Interface GUID at `DAT_140004130` (IoRegisterDeviceInterface, dump 604) is the same as the sibling build. Effective DACL: IoCreateDevice default; not set in the image.

## 3 Dispatch and IOCTL table

- Same table as `DesktopVideoUpdate_81F65827` §3 (IOCTLs 0x222000 through 0x2220F0, all METHOD_BUFFERED, FILE_ANY_ACCESS, identical length checks and actions). Refer to that report for the per-code rows and dump line numbers, which are identical in this build.

## 4 Access-control audit

- No privilege or ACL check in the dispatcher. Gate: device-ready byte (dump 646-653). Same as the sibling build.

## 5 Memory-write trace

- Same trace as the sibling build (§5 of `DesktopVideoUpdate_81F65827`): SystemBuffer writes at fixed offsets and bounded by IOCTL lengths; URB transfer buffers bounded by in/out lengths; config-table copies sized from device-supplied descriptor lengths (`FUN_140002CE4`, memmove at dump 1663-1668); fixed-offset device-extension and IRP writes. No caller-controlled destination, offset or value reaches kernel memory.

## 6 Most dangerous exposed capability

- Configuration re-selection (0x2220B8) and raw URB transfers (0x2220D8-0x2220E8), bounded as above.

## 7 Verdict

**NO-MEMORY-WRITE.** Reach R3 (hardware); Setup: hardware; Write quality W0; load: test-signed signature (UnknownError), so this image is not loadable on a normally signed system. HW-only: no.

## 8 Limitations

- The dump matches the sibling dump in all 2,016 lines except the program name, so the sibling analysis is reused for code paths. The binary differs in layout (18,104 vs 28,592 bytes) because of the signature block; the code is the same.
- Same unresolved items as the sibling build: DriverUnload slot labelled `_guard_check_icall`, and the off-by-one read in 0x2220EC.
- No REA session used. No execution, no driver load, no registry writes.
