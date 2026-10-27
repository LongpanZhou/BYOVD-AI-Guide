# Audit: mxuport,2_5A9003D4.sys

| Field | Value |
|---|---|
| File | drivers\mxuport,2_5A9003D4.sys |
| SHA-256 | 5A9003D405A5575FAAE41D564F68B71692A9AE885920BF361903EB16EAF42F94 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\mxuport_2_5A9003D4.txt`, complete; scratch stem `mxuport_2_5A9003D4`). Dump compared with `mxuport_1_5B845038`: identical except the program name (4 diff lines), so the mxuport,1 analysis (IOCTL switch `FUN_140001CB0`, device creation at dump 219/268) is reused. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Moxa Inc.; file version 4.1 build 23090720; "MOXA UPort Driver" |
| Signature | Authenticode Valid; signer CN=MOXA INC. |
| Reach | R3 (devnode / hardware: a Moxa UPort USB-serial adapter must be present) |
| Setup required | hardware |
| Write quality | W0 (provisional, as for the sibling) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

## 1 Internals

- Same code as `mxuport,1_5B845038` (dump-identical functions, PE32+ x64 WDM serial port driver). Imports identical.
- No mapping API, no memcpy/memmove import, no SDDL string, no `ZwSetSecurityObject`.

## 2 Entry / device / interface / effective DACL

- As in the sibling: `IoCreateDevice(..., 0x968, name, 0x1B)` (dump 219), `IoCreateSymbolicLink` (dump 268); effective DACL default.

## 3 Dispatch and IOCTL table

- As in the sibling section 3: serial IOCTL switch `FUN_140001CB0` (dump 579-1720). Output-handling cases read at dump 776-860: 0x1B0078, 0x1B0050, 0x1B0054, 0x1B0058, 0x1B005C, 0x1B0060, 0x1B0064, 0x1B0068, 0x1B006C, each with the same gates and fixed offsets (see the sibling table). Queue cases (0x1B0008-0x1B0044, 0x1B0080-0x1B009C) not read.

## 4 Access-control audit

- As in the sibling: no privilege or caller-identity check in the switch.

## 5 Memory-write trace

- As in the sibling section 5: fixed-offset SystemBuffer writes gated by the output length; fixed-size input-to-state copies; no caller-chosen destination or index in the read cases.

## 6 Most dangerous exposed capability

- Not established for the read cases; the unread queue cases are open (as for the sibling).

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** Same code as the sibling; no caller-controlled kernel write in the read cases. The image is signed (Valid). Reach R3; Setup: hardware; W0 in the read cases. HW-only: no.

## 8 Limitations

- As in `mxuport,1_5B845038` section 8: the queue cases and helper routines were not read.
- No REA session used. No execution, no driver load, no registry writes.
