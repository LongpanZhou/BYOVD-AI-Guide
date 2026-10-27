# Audit: usblddaqlib_CDEC967D.sys

| Field | Value |
|---|---|
| File | drivers\usblddaqlib_CDEC967D.sys |
| SHA-256 | CDEC967DFDFC8DFC1BA96AC81449BDC84B2055F68B5436A01857BC676D07C1E6 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\usblddaqlib_CDEC967D.txt`, complete). Dump compared with `usblddaqlib_9E26A72E`: identical except the program name on line 1 (4 diff lines), so the sibling's IOCTL dispatcher analysis (dump 1915-1977, bounded 0x220000 copy) is reused. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Measurement Computing Corp.; file version 5.0.0 Build 11; "USB-2500 Loader Device Driver" |
| Signature | Authenticode Valid; signer CN="Digilent, Inc." (Digilent-signed build of the same MCC loader) |
| Reach | R3 (devnode / hardware: a USB-2500 device must be attached) |
| Setup required | hardware |
| Write quality | W0 (no caller-controlled kernel write found) |
| Severity | NO-MEMORY-WRITE |
| HW-only | no |

## 1 Internals

- Same code as `usblddaqlib_9E26A72E` (PE32+ x64 WDM USB loader). Imports identical. No mapping API, no MDL probe, no `ZwSetSecurityObject`, no SDDL string.

## 2 Entry / device / interface / effective DACL

- As in the sibling: `IoCreateDevice(..., 0x250, 0, 0x22, 0x80, 0, ...)` at dump 108 (no FILE_DEVICE_SECURE_OPEN flag), `IoRegisterDeviceInterface` at dump 156. Effective DACL: IoCreateDevice default.

## 3 Dispatch and IOCTL table

- As in the sibling section 3: dispatcher at dump 1915-1977 with IOCTLs 0x220000 (bounded copy of the loader buffer into SystemBuffer, gated by OutputBufferLength and started state), 0x220004 (no buffer), 0x220008 (no caller buffer write); other codes return STATUS_INVALID_DEVICE_REQUEST (0xC0000010).

## 4 Access-control audit

- As in the sibling: the started-state gate (dump 1930); no privilege or caller-identity check.

## 5 Memory-write trace

- As in the sibling section 5: the only IOCTL-path buffer write is `FUN_00014BA0(SystemBuffer, loaderBuffer, len)` with `len <= OutputBufferLength` (dump 1947-1948). Bounded.

## 6 Most dangerous exposed capability

- None beyond the bounded copy.

## 7 Verdict

**NO-MEMORY-WRITE.** Same code as the sibling; no caller-controlled kernel write. Reach R3 (devnode / hardware); Setup: hardware; W0. The image is signed (Valid). HW-only: no.

## 8 Limitations

- As in `usblddaqlib_9E26A72E` section 8: the helper functions were read at their call sites only.
- No REA session used. No execution, no driver load, no registry writes.
