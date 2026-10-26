# Audit: mccfwld_5279671E.sys

| Field | Value |
|---|---|
| File | drivers\mccfwld_5279671E.sys |
| SHA-256 | 5279671EE760069A9DBB9C3054177C3781AF60E7ACC009F52DAFDEEB93C30317 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\mccfwld_5279671E.txt`, complete, 783 lines, 24 functions). Dump compared with `mccfwld_2824AC5B`: identical except the program name and header (4 diff lines), so the sibling's analysis of the firmware-select path (`FUN_0003C74C`) and the absence of an IOCTL dispatch are reused. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Measurement Computing Corporation.; file version 1.0.6.0; product version 6.74.0.0; "MCC Firmware Loader" |
| Signature | Authenticode Valid; signer CN="Digilent, Inc." (the image is a Digilent-signed MCC build) |
| Reach | R3 (devnode / hardware: an MCC USB device must be present) |
| Setup required | hardware |
| Write quality | W0 |
| Severity | NO-MEMORY-WRITE |
| HW-only | no |

## 1 Internals

- Same code as `mccfwld_2824AC5B` (PE32+ x64 KMDF firmware loader, WDFLDR imports, static firmware blobs selected by device identity). Imports: `RtlCopyUnicodeString`, `RtlCompareMemory`, `KeBugCheckEx`, `KeTickCount`, `memset`; no mapping API, no `memcpy`/`memmove`, no IOCTL import pattern.

## 2 Entry / device / interface / effective DACL

- No `IoCreateDevice`, `IoCreateSymbolicLink`, `ZwSetSecurityObject` or SDDL string in the image. Device created by WDF with default security; bound by PnP to the MCC device.

## 3 Dispatch and IOCTL table

- No IOCTL case labels in the dump (grep for `0x22xxxx` returns none). The firmware select and download path `FUN_0003C74C` (dump 585-734) is the same as the sibling.

| Code | Method | Access | Input | Output | Kernel action |
|---|---|---|---|---|---|
| none defined | - | - | - | - | No user IOCTL dispatch in the decompile. |

## 4 Access-control audit

- No privilege or caller-identity check (no user request path).

## 5 Memory-write trace

- As in the sibling: writes go to driver-owned locals and to the USB device; sizes are constants or come from the static blob table. No caller-supplied destination or length.

## 6 Most dangerous exposed capability

- None on the user side.

## 7 Verdict

**NO-MEMORY-WRITE.** Same code as the sibling; no user-reachable write. Reach R3; Setup: hardware; W0. HW-only: no (USB firmware download is not a memory write). The image is signed (Valid).

## 8 Limitations

- As in `mccfwld_2824AC5B` §8.
- No REA session used. No execution, no driver load, no registry writes.
