# Audit: deckavs_B89FCDA2.sys

| Field | Value |
|---|---|
| File | drivers\deckavs_B89FCDA2.sys |
| SHA-256 | B89FCDA2F8F705A5CADBE5FE01B5CAFBF96D11289083E6ECE48095867D596D98 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\deckavs_B89FCDA2.txt`, 10,006 lines, 336 functions, complete). Import triage; grep of the dump for IOCTL comparisons, IRP builders, copy helpers, mapping and security calls; read of the private IOCTL helper chain (FUN_140001f40, FUN_140001e3c, FUN_14000211c, FUN_140001f4x callers). Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Blackmagic Design; file version 15.3.1; "DeckLink WDM Capture Driver" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher |
| Reach | R3 (devnode / hardware: a DeckLink card must be present) |
| Setup required | hardware |
| Write quality | W0 (provisional: no caller-controlled kernel write found in the traced code; see §5 and §8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 KS WDM capture filter driver (KS: `KsCreateFilterFactory`, `KsFilterCreatePinFactory`, `KsAddItemToObjectBag`, `KsGenerateEvents`, `KsDefaultAddEventHandler`, `KsStreamPointerDelete`, `KsReleaseDevice`, `KsAcquireDevice`).
- Imports: `PsCreateSystemThread`, `KeWaitForMultipleObjects`, `ObReferenceObjectByHandle`, `IoBuildDeviceIoControlRequest`, `IoAllocateIrp`, `IoFreeIrp`, `IoCancelIrp`, `IoGetDeviceInterfaces`, `IoGetDeviceObjectPointer`, `IoGetDeviceAttachmentBaseRef`, `IoSetDevicePropertyData`, `RtlWriteRegistryValue`, `RtlQueryRegistryValues`, `ZwCreateKey`, `KeBugCheckEx`, `_vsnwprintf`.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, MmProbeAndLockPages, ZwSetSecurityObject, memcpy or memmove import. The CRT copy helper is internal (`FUN_140006100`, called at dump 1084, 1098).

## 2 Entry / device / interface / effective DACL

- The driver does not call `IoCreateDevice` or `IoCreateSymbolicLink`. The KS filter factories are created under the KS device; the interface is enumerated with `IoGetDeviceInterfaces`. No SDDL string and no `ZwSetSecurityObject` in the image. Effective DACL: default (KS / PnP), not fixed in the image.

## 3 Dispatch and IOCTL table

- No custom IOCTL dispatch: a grep for `== 0x22xxxx` and `== 0x2xxxxx` case labels in the dump returns none. The user surface is KS (property, method, event and stream IRPs routed by KS).
- The driver issues private IOCTLs to the lower DeckLink device through `FUN_140001e3c` (dump 1010-1040, `IoBuildDeviceIoControlRequest` at 1025) and the IRP helper `FUN_140001f40` (dump 1048-1117). All call sites are listed below. Codes are constants; sizes are constants except where noted.

| Code (dump line) | Method | Access | Input | Output | Notes |
|---|---|---|---|---|---|
| 0x222880 (1002) | - | - | 0x20 | 0 | Fixed. |
| 0x222884 (749) | - | - | 0x18 | 0 | Fixed. |
| 0x222888 (1510, 1515) | - | - | 0x18 | 0x48 into stack `local_98` | Output is a stack buffer. |
| 0x222890 (946) | - | - | 8 | 4 into `local_res10` | Local buffer. |
| 0x222894 (721) | - | - | 8 | 0 | Fixed. |
| 0x222898 (7123) | - | - | 0x20 | 8 into `local_38` | Local buffer. |
| 0x22288C (923) | - | - | 0x10 | 0 | Fixed. |
| 0x222818 (7083) | - | - | 0x20 | 8 into `local_38` | Local buffer. |
| 0x222458 (1159) | - | - | 8 | 0x9A0 into caller `param_3` | Called from 7904 with a stack buffer `local_9f8`; not a user buffer (§5). |
| 0x222453, 0x222443, 0x22244B, 0x22244F, 0x22242B, 0x22241C, 0x22240F, 0x222403, 0x222413, 0x222418, 0x222424, 0x222447, 0x222467, 0x222480, 0x222484, 0x22246C, 0x2224C0-0x2224E8, 0x222643, 0x222648, 0x222664, 0x222668, 0x222678, 0x22208C, 0x22264C, 0x222084, 0x222088 | - | - | fixed (4 to 0x20) | fixed (0 to 0x10) or caller `param_2` / `param_4` with fixed size 4 or 8 | Fixed-size private calls; outputs go to driver or stack buffers, sizes fixed (see §5). |
| 0x222018 (7312) | - | - | 0x10 | 8 into `local_60` | Local buffer. |

| Code | Method | Access | Input | Output | Kernel action |
|---|---|---|---|---|---|
| none defined by the driver | - | - | - | - | KS-managed; outbound private codes above only. |

Method and access are not stated by the driver for the private codes: they are lower-device control codes sent with `IoBuildDeviceIoControlRequest`.

## 4 Access-control audit

- No privilege or caller-identity check in the driver. Access is governed by KS and the default device security (§2).

## 5 Memory-write trace

1. **FUN_140001f40 (dump 1048-1117):** allocates `ExAllocatePoolWithTag(max(param_6, param_4))` (1083), copies `param_4` bytes from `param_3` into it (1084), sends the IRP and, on success, copies `param_6` bytes out to `param_5` (1098). The pool size is at least `param_6` and at least `param_4`, so both copies are bounded by the allocation. The destination `param_5` is a caller-supplied pointer; its size is the caller's `param_6`.
2. **FUN_140001e3c (dump 1010-1040):** passes its buffers to `IoBuildDeviceIoControlRequest` and copies back into `param_5` only through the IOCTL output path of the lower stack (`local_38` is the completion information, dump 1034).
3. **FUN_14000211c (dump 1148-1163):** the 0x9A0-byte output (0x222458) targets `param_3`. The only caller (dump 7904) passes the stack buffer `local_9f8`, so the write stays in the frame.
4. **Fixed-size private calls** (§3) write into local stack buffers or to fixed-size driver output; the output lengths are constants.
5. **Other memcpy-like sites:** none by name (`memcpy`/`memmove` are not imported; `FUN_140006100` is the internal CRT copy called at dump 1084 and 1098 with the sizes in item 1).

Conclusion of this pass: no site writes to a caller-chosen kernel address. Copy sizes are bounded by the allocation or are constants. The caller-supplied destination `param_5` in item 1 is bounded by the caller's own `param_6`; the callers that pass a non-stack buffer were not enumerated (§8).

## 6 Most dangerous exposed capability

- Not established. The KS property, method and stream handlers (the user surface) were not traced. The private IOCTL chain (§3) is driver-initiated and not user-selected.

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** No caller-controlled kernel write found in the traced code. Reach R3 (devnode / hardware); Setup: hardware; W0 in the traced code. HW-only: no.

## 8 Limitations

- Callers of `FUN_140001f40` and `FUN_140001e3c` that pass a non-stack output buffer (the `param_5` destination in §5 item 1) were not enumerated. The verdict is provisional until those callers are checked.
- The KS property, method and stream handlers (the user surface) were not traced.
- No REA session used. No execution, no driver load, no registry writes.
