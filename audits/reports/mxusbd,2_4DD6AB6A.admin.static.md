# Audit: mxusbd,2_4DD6AB6A.sys

| Field | Value |
|---|---|
| File | drivers\mxusbd,2_4DD6AB6A.sys |
| SHA-256 | 4DD6AB6A9474BFE2E647D4DF3BC7A24FD37E8148104D1887F9A7F5FC07ED9CA2 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\mxusbd_2_4DD6AB6A.txt`, complete; scratch stem `mxusbd_2_4DD6AB6A`). Dump compared with `mxusbd_1_477EA31C`: 46 diff lines (lock and pool-allocation call forms, program name); the IOCTL 0x1B2040 case (dump 3076-3117) is the same code in both builds (shifted by one line), read in full. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Moxa Inc.; file version 4.1 build 23090720; "MOXA UPort Series Windows Driver" |
| Signature | Authenticode Valid; signer CN=MOXA INC. |
| Reach | R3 (devnode / hardware: a Moxa UPort USB-serial adapter must be attached) |
| Setup required | hardware |
| Write quality | W2 (same primitive as the sibling; see `mxusbd,1_477EA31C` section 5) |
| Severity | MW3 (`reach=R3 setup=hardware write=W2 load=signed`) |
| HW-only | no |

## 1 Internals

- Same family and imports as `mxusbd,1_477EA31C` (PE32+ x64 WDM serial port driver with a vendor IOCTL family 0x1B2000-0x1B2054). No mapping API, no memcpy/memmove import, no SDDL string, no `ZwSetSecurityObject`.

## 2 Entry / device / interface / effective DACL

- Dispatch and device creation as in the sibling (`IoCreateDevice(..., 0x508, ..., 0x2A, ..., exclusive)`, `IoRegisterDeviceInterface`). Effective DACL: PnP device-interface default, not fixed by the driver.

## 3 Dispatch and IOCTL table

- IOCTL 0x1B2040 (dump 3076-3117): input gate `3 < InputBufferLength` (3077); **no OutputBufferLength check**; start and end indices from the input (3079-3081); records written to SystemBuffer at 16x(k-start) for each attached port index k (3092-3113); Information = 16x(end-start+1) (3116). The same as the sibling (section 3 and section 5 of `mxusbd,1_477EA31C`).
- Other vendor and serial cases: as in the sibling; not re-traced for this build beyond the 0x1B2040 block.

## 4 Access-control audit

- No privilege or caller-identity check in the IOCTL path. Reach depends on who can open the device object through its PnP interface.

## 5 Memory-write trace

- The pool out-of-bounds write described in `mxusbd,1_477EA31C` section 5 is present in this build at dump 3092-3113: the SystemBuffer (size `max(InputBufferLength, OutputBufferLength)`, METHOD_BUFFERED) receives 16-byte port-state records at offsets 16x(k-start), with no OutputBufferLength check. The overrun length depends on the caller's index range and on the attached port indices; the values are device-state fields.

## 6 Most dangerous exposed capability

- IOCTL 0x1B2040 (as for the sibling).

## 7 Verdict

**MW3 - reach=R3 setup=hardware write=W2 load=signed.** The image is Authenticode-signed (Valid). HW-only: no.

## 8 Limitations

- Same as `mxusbd,1_477EA31C` section 8 (the rest of the switch and the port-array population were not resolved).
- No REA session used. No execution, no driver load, no registry writes, no exploit developed.
