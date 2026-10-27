# Audit: deckser_legacy_16F3AD97.sys

| Field | Value |
|---|---|
| File | drivers\deckser_legacy_16F3AD97.sys |
| SHA-256 | 16F3AD97F77591A9DC58E8E77146618A6A481296FA231FAB1BAD8DF8D0877002 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\deckser_legacy_16F3AD97.txt`, complete). Dump compared with `deckser_65A92D8F`: identical except the program name (line 1) and one decompiler rendering of a KeWaitForSingleObject call (line 1835, same call); the sibling analysis is reused. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Blackmagic Design; file version 15.3.1; "DeckLink Serial Driver" |
| Signature | NotSigned (no Authenticode signature). The image is 27,648 bytes against 38,104 for the signed sibling. |
| Reach | R3 (devnode / hardware: a DeckLink card must be present) |
| Setup required | hardware |
| Write quality | W0 |
| Severity | NO-MEMORY-WRITE |
| HW-only | no |

## 1 Internals

- Same code as `deckser_65A92D8F` (dump-identical functions). WDM serial port driver; device `\Device\DeckLinkSerial`; `IoCreateDevice(..., 0x468, ..., 0x1B)` and `IoCreateSymbolicLink` as in the sibling.
- No mapping API, no memcpy/memmove import, no SDDL string, no `ZwSetSecurityObject`.

## 2 Entry / device / interface / effective DACL

- As in `deckser_65A92D8F` section 2. Effective DACL: IoCreateDevice default.

## 3 Dispatch and IOCTL table

- As in `deckser_65A92D8F` section 3: the full serial IOCTL switch 0x1B0004-0x1B009C (dump line numbers identical in this build). Sub-IOCTLs to the lower device are 0x222030 (256-byte local output, dump 2072) and 0x222038 (4-byte output into SystemBuffer+8, dump 309).

## 4 Access-control audit

- As in the sibling: no privilege or caller-identity check in the driver.

## 5 Memory-write trace

- As in `deckser_65A92D8F` section 5: all output writes are fixed-size and within the output-length checks; the 0x1B0054 memset is bounded by the output length; no caller-chosen destination or index.

## 6 Most dangerous exposed capability

- None (see the sibling section 6).

## 7 Verdict

**NO-MEMORY-WRITE.** Same code as the signed sibling; no caller-controlled kernel write in the IOCTL surface. The image is unsigned, so it is not loadable on a normally configured system. Reach R3; Setup: hardware. HW-only: no.

## 8 Limitations

- As in `deckser_65A92D8F` section 8: the create and close routines and the cancel-safe queue helpers were not read; the lower device's sub-IOCTL behavior is outside the image.
- No REA session used. No execution, no driver load, no registry writes.
