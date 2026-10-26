# Audit: deckaud_legacy_64B2CFAE.sys

| Field | Value |
|---|---|
| File | drivers\deckaud_legacy_64B2CFAE.sys |
| SHA-256 | 64B2CFAEE6D3C09447BBF1E652ABB2154ACA4EA6FF895D9C5EB053ADDE7B779E |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\deckaud_legacy_64B2CFAE.txt`, complete). Dump compared with `deckaud_D525B6F1`: identical except the program name on line 1 (4 diff lines), so the D525 analysis is reused for the code paths. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Blackmagic Design; file version 15.3.1; "DeckLink Audio Driver" |
| Signature | NotSigned (no Authenticode signature). The image is 26,112 bytes against 36,568 for the signed sibling. |
| Reach | R3 (devnode / hardware: a DeckLink card must be present) |
| Setup required | hardware |
| Write quality | W0 (provisional, as for the sibling; see §8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL). Unsigned image: not loadable on a normally configured system. |
| HW-only | no |

## 1 Internals

- Same code as `deckaud_D525B6F1` (dump-identical functions). PortCls audio adapter; imports identical to the sibling.
- No mapping API, no memcpy/memmove import, no SDDL string, no `ZwSetSecurityObject`, no `IoCreateDevice` call in the dump.

## 2 Entry / device / interface / effective DACL

- As in `deckaud_D525B6F1` §2: adapter FDO through `PcAddAdapterDevice`; interfaces via `IoGetDeviceInterfaces`; effective DACL default (not fixed in the image).

## 3 Dispatch and IOCTL table

- As in `deckaud_D525B6F1` §3: no custom IOCTL dispatch. Outbound lower-device requests at dump lines 1773 (0x222018, 0x10-byte input, 8-byte output) and 1848 (0x222043, 8-byte output), both with constant sizes.

## 4 Access-control audit

- As in the sibling: no privilege or caller-identity check in the driver.

## 5 Memory-write trace

- As in the sibling §5: no mapping and no bulk copy import; outbound buffer sizes constant; `_vsnwprintf` destination is driver-internal.

## 6 Most dangerous exposed capability

- Not established (KS / PortCls user surface not traced; see §8).

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** No caller-controlled kernel write found in the traced code (the same code as the signed sibling). The image is unsigned, so it is not loadable on a normally configured system. Reach R3; Setup: hardware. HW-only: no.

## 8 Limitations

- Same as `deckaud_D525B6F1` §8: the PortCls KS property and stream handlers are not traced.
- No REA session used. No execution, no driver load, no registry writes.
