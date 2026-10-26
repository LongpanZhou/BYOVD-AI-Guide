# Audit: deckavs_legacy_51CBC2F8.sys

| Field | Value |
|---|---|
| File | drivers\deckavs_legacy_51CBC2F8.sys |
| SHA-256 | 51CBC2F8E6A4F1BBCE7FBBFC831E2B30BB0AF71C03CF4A635826D2A9597B7ABC |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\deckavs_legacy_51CBC2F8.txt`, complete). Dump compared with `deckavs_B89FCDA2`: identical except the program name on line 1, so the B89 analysis is reused for the code paths. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Blackmagic Design; file version 15.3.1; "DeckLink WDM Capture Driver" |
| Signature | NotSigned (no Authenticode signature). The image is 67,072 bytes against 77,528 for the signed sibling. |
| Reach | R3 (devnode / hardware: a DeckLink card must be present) |
| Setup required | hardware |
| Write quality | W0 (provisional, as for the sibling; see §8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL). Unsigned image: not loadable on a normally configured system. |
| HW-only | no |

## 1 Internals

- Same code as `deckavs_B89FCDA2` (dump-identical functions). KS WDM capture filter; imports identical to the sibling.
- No mapping API, no memcpy/memmove import, no SDDL string, no `ZwSetSecurityObject`, no `IoCreateDevice` call in the dump.

## 2 Entry / device / interface / effective DACL

- As in `deckavs_B89FCDA2` §2: KS filter factories; interface enumeration via `IoGetDeviceInterfaces`; effective DACL default.

## 3 Dispatch and IOCTL table

- As in `deckavs_B89FCDA2` §3: no custom IOCTL dispatch. Private outbound lower-device codes through `FUN_140001e3c` / `FUN_140001f40` with constant codes and fixed sizes (see the sibling table; dump line numbers are identical).

## 4 Access-control audit

- As in the sibling: no privilege or caller-identity check in the driver.

## 5 Memory-write trace

- As in `deckavs_B89FCDA2` §5: `FUN_140001f40` copies bounded by its pool allocation; `FUN_14000211c`'s 0x9A0-byte output targets a stack buffer (dump 7904); other private calls use constant sizes.

## 6 Most dangerous exposed capability

- Not established (KS user surface not traced; see §8).

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** No caller-controlled kernel write found in the traced code (the same code as the signed sibling). The image is unsigned, so it is not loadable on a normally configured system. Reach R3; Setup: hardware. HW-only: no.

## 8 Limitations

- Same as `deckavs_B89FCDA2` §8: callers of `FUN_140001f40` that pass a non-stack output buffer were not enumerated, and the KS property, method and stream handlers were not traced.
- No REA session used. No execution, no driver load, no registry writes.
