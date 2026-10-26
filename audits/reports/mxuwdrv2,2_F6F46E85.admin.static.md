# Audit: mxuwdrv2,2_F6F46E85.sys

| Field | Value |
|---|---|
| File | drivers\mxuwdrv2,2_F6F46E85.sys |
| SHA-256 | F6F46E859336A75EF3D32C0B86B54DF47913DB34EAF71D3B06D7892568305BA4 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\mxuwdrv2_2_F6F46E85.txt`, complete; scratch stem `mxuwdrv2_2_F6F46E85`). Dump compared with `mxuwdrv2_1_AAFCCE25`: identical except the program name on line 1, so the sibling analysis (IOCTL switch case labels, device creation, 0x222080 forwarding) is reused. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Moxa Inc.; file version 4.3 Build 26010215; "MOXA UPort 1110/1130/1150 Driver" |
| Signature | Authenticode Valid; signer CN=MOXA INC. |
| Reach | R3 (devnode / hardware: a Moxa UPort 1110/1130/1150 USB adapter must be attached) |
| Setup required | hardware |
| Write quality | W0 (provisional, as for the sibling) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

## 1 Internals

- Same code as `mxuwdrv2,1_AAFCCE25` (PE32+ x64 WDM serial / USB driver). Imports identical. No mapping API, no memcpy/memmove import, no SDDL string, no `ZwSetSecurityObject`. `MmGetSystemRoutineAddress` is imported (runtime-resolved API set not enumerated).

## 2 Entry / device / interface / effective DACL

- As in the sibling §2: `IoCreateDevice` at dump 347, interface registration at dump 4527 and 12348, `IoCreateUnprotectedSymbolicLink` at dump 11712. Effective DACL: IoCreateDevice and PnP interface defaults.

## 3 Dispatch and IOCTL table

- As in the sibling §3: serial family 0x1B0004-0x1B009C (dump 6355-6516 in this build) and 0x222080 (dump 6520-6523, forwarded through the guarded dispatch pointer). Serial handlers not read (see the sibling §8).

## 4 Access-control audit

- As in the sibling: no privilege or caller-identity check in the dispatcher.

## 5 Memory-write trace

- As in the sibling §5: no copy or mapping primitive imported; the read cases do not write to caller buffers; serial handlers not read.

## 6 Most dangerous exposed capability

- Not established (as for the sibling).

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** Same code as the sibling; no caller-controlled kernel write in the traced cases. The serial handlers are open. Reach R3 (devnode / hardware); Setup: hardware; W0 in the traced code. The image is signed (Valid). HW-only: no.

## 8 Limitations

- As in `mxuwdrv2,1_AAFCCE25` §8: the serial handlers and the runtime-resolved APIs were not read.
- No REA session used. No execution, no driver load, no registry writes.
