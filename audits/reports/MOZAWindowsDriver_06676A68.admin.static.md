# Audit: MOZAWindowsDriver_06676A68.sys

> **SUPERSEDED (2026-10-25):** `S1_S2_remaining.md` is the consolidated batch audit and rates this
> build **MW4/W3** (8-byte over-write of a declared buffered output buffer, cross-allocation
> corruption unproven). Use MW4; this per-file MW3 is retained for history only.

| Field | Value |
|---|---|
| File | drivers\MOZAWindowsDriver_06676A68.sys |
| SHA-256 | 06676A680A5A6D0DB83A0A6EBEDB75AD55701879D74022CCB42FB8E566BE7AC9 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\MOZAWindowsDriver_06676A68.txt`, complete, 2,700+ lines); PE import/string triage; Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | MOZA Racing Team; "v1.0.2.6 Commit: (x64)"; description "MOZA Windows Driver" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher |
| Reach | R3 (devnode / hardware: loaded by PnP for a MOZA device; device-interface notification in dump 1064) |
| Setup required | hardware |
| Write quality | W2 (in-object constrained write, 256 fixed slots in the device context, arbitrary byte value); secondary W3 8-byte pool overflow (see section 5) |
| Severity | MW3 (`reach=R3 setup=hardware write=W2 load=signed`) |
| HW-only | no (the rated primitive is a kernel-pool write into the device context; no HW-ONLY writes) |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64, KMDF driver (WDFLDR imports). WDF calls go through `DAT_1400066f0` and the dispatch thunk `PTR__guard_dispatch_icall_140005098`; WDF function indices are not named in the dump.
- ntoskrnl imports include `IoRegisterPlugPlayNotification` and `IoUnregisterPlugPlayNotification`, `DbgPrint`, `RtlCopyUnicodeString`, `wcsstr`. No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, MmGetSystemRoutineAddress, RtlCopyMemory or ProbeForWrite in the imports.
- Entry: `entry @ 140003A90` (dump 1796) -> DriverEntry `FUN_140003ABC` (dump 1807-1845); DriverUnload slot (+0x68) = `FUN_140003C20` (dump 1845).

## 2 Entry / device / interface / effective DACL

- Device-add path: `FUN_140002634` (dump 1050-1069) registers a device-interface PnP notification (`IoRegisterPlugPlayNotification`, GUID at `DAT_140005120`, callback `FUN_1400025F0`) and stores the notification handle at device-context+0x5651 (dump 1064). WDF device creation is in the same add path; the image contains no SDDL string or device name (string triage: only the PDB path and "MOZA Windows Driver" text).
- Queue setup `FUN_140002718` (dump 1070-1101): EvtIoDeviceControl = `FUN_140002800` (dump 1095, the IOCTL handler, 1102-1381); EvtIoInternalDeviceControl = `FUN_140003160` (dump 1096, forwards); other callbacks `FUN_140003260` (1092), `FUN_1400016C0` (1094).
- Effective DACL: the device uses the WDF default security (no descriptor is set anywhere in the image). Access is therefore determined by the device interface and default device object, not by the driver; the device exists only when MOZA hardware is present (R3).

## 3 Dispatch and IOCTL table

Dispatch: `FUN_140002800` (dump 1102-1381) is EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL (queue, request, OutputBufferLength, InputBufferLength, IoControlCode). Device context `lVar7 = WdfObjectGetTypedContext(device)` (dump 1135-1136). Codes: all 0x22xxxx codes are METHOD_BUFFERED with FILE_ANY_ACCESS (low bits 0, bits 14-15 zero). 0xB0191 and 0xB0192 are METHOD_IN_DIRECT and METHOD_OUT_DIRECT, access bits 3 (READ|WRITE).

| IOCTL | Method | Access | Input | Output | Kernel action (dump lines) |
|---|---|---|---|---|---|
| 0x22200C | BUFFERED | ANY | InputBufferLength != 0 (1143) | OutputBufferLength exactly 0x22 or 0x2A (1140-1143) | Selector = input[0] (1155). `FUN_1400017FC(selector, ctx, output)` (dump 393-436): selector 0/1/2 copies a 0x2A-byte record from device-context regions to the output (402-434); other selectors return 0xC000000D (423). Completed with Information = OutputBufferLength (1158-1160, 1378). **See section 5: 8-byte overflow when OutputBufferLength = 0x22.** |
| 0xB0191 | IN_DIRECT | READ\|WRITE | input >= 0x12 (1169) | none | If input[0] == 0x11: `FUN_1400015DC` (309-331) writes input[1] into the first free slot flag (see section 5 item 4). Otherwise the request is forwarded (1179-1188). |
| 0xB0192 | OUT_DIRECT | READ\|WRITE | none | OutputBufferLength (1193-1194) | `*ctx_request = output[0]` (1196-1198), then the request is forwarded with completion `FUN_140003630` (1270). |
| 0x222000 | BUFFERED | ANY | input >= 1 (1203) | none | Sets ctx+0x48 = (input[0] == 1) (1205-1209). Information 1 (1299-1300). |
| 0x222004 | BUFFERED | ANY | input >= 1 (1240) | none | Sets ctx+0x47 = (input[0] == 1); if ctx+0x10 != 0, calls `FUN_1400024D0` and a WDF call on ctx+0x5649 (1244-1257). Information 1. |
| 0x222008 | BUFFERED | ANY | OutputBufferLength >= 4 (1215, buffer retrieved with size 4, 1221-1222) | 4 | Writes version bytes {01 00 02 06} (1224-1228), Information 4 (1372-1374). |
| 0x222010 | BUFFERED | ANY | input == 0x10 exactly (1278) | none | Expands the 16-byte input into 128 bit-flags at ctx+0x565A+2k (1283-1298). Information 1. |
| 0x222014 | BUFFERED | ANY | input != 0 (1304), length = InputBufferLength (1307-1308) | none | For each pair i: ctx[0x5657 + 2*input[2i]] = input[2i+1] (1310-1322). Information 1. **section 5 item 1: caller-controlled slot and value.** |
| 0x222018 | BUFFERED | ANY | none | none | ctx+0x5A9F = 0; ctx+0x5A9E = 1 (1333-1334). Status 0. |
| 0x22201C | BUFFERED | ANY | none | OutputBufferLength == 4 (1350) | Requires ctx+0x5A9E (1347); requires ctx+0x5A9F != 0 (1354); writes ctx[0x5A9F..0x5AA2] to the output (1359-1368); clears ctx+0x5A9F (1369). Information 4. |
| 0x222020 | BUFFERED | ANY | none | none | ctx+0x5A9E = 0; ctx+0x5AA2 = 0 (1343-1345). Status 0. |
| any other | forwarded | as received | as received | as received | Forwarded to the lower WDF I/O target with completion `FUN_140003630` (1266-1274). |

## 4 Access-control audit

- No `SeAccessCheck`, `SeSinglePrivilegeCheck` or caller identity check in the driver. Every IOCTL above is reachable by any principal that can open the device.
- Gates: input/output length checks in the table; flag gates in ctx for 0x22201C (1347, 1354); WDF request validation (`WdfRequestRetrieveInputBuffer` / `OutputBuffer` minimum sizes).
- Device exists only when MOZA hardware is present (R3).

## 5 Memory-write trace

1. **0x222014: in-object write with caller-controlled slot and value (W2).** Slot = `ctx + 0x5657 + 2*k`, k = input[2i] (0..255), value = input[2i+1] (dump 1319-1320). Targets are the 256 odd offsets 0x5657..0x5855, all inside the device context (the context is accessed up to offset 0x5AA2, so the 0x5855 maximum is inside it). No pointer target is reachable except one case: k = 0 writes ctx+0x5657, which is byte 6 of the 8-byte PnP notification handle at ctx+0x5651 (stored at dump 1064, read back at 899-901). A canonical kernel pointer has 0xFF in that byte, so any other value makes the pointer non-canonical and causes a fault when it is used at unregistration. That is a denial of service, not a controlled write. Other k values touch only data slots (the bit-flag area at 0x565A-0x5758 is even-offset; 0x5659..0x5855 odd-offset slots are data).
2. **0x222010: fixed-target bit writes.** 128 bytes at ctx+0x565A+2k, each a bit of the 16-byte input (1283-1298). Targets fixed; values constrained to 0/1.
3. **0x222000 / 0x222004 / 0x222018 / 0x22201C / 0x222020: fixed-offset flag writes** (ctx+0x47, 0x48, 0x5A9E, 0x5A9F, 0x5AA2), values 0/1 or from input byte 0.
4. **0xB0191 (FUN_1400015DC, dump 309-331):** `FUN_1400015A0` (dump 275-294) returns the 1-based index of the first empty slot (flag byte at ctx+0x57D8+0x45*k) or 0 if none in 10. The write is `ctx + 0x5793 + 0x45*u`, which equals `ctx + 0x57D8 + 0x45*(u-1)`, so it is always within the 10-slot table and within the context. Value = input[1] (arbitrary byte); target = first free slot (not caller-chosen). Counters updated at ctx+0x5A8E, 0x5A91, 0x5A92, 0x5A93, 0x5A98.
5. **0x22200C: 8-byte pool overflow (secondary finding).** `FUN_1400017FC` writes a 0x2A-byte record for selectors 0, 1 and 2 (dump 402-434): five 8-byte stores at output+0x00..0x27 and a 2-byte store at output+0x28. The IOCTL accepts OutputBufferLength = 0x22 (34 bytes) (1143), and the function still writes 42 bytes, so offsets 0x22..0x29 (8 bytes) fall past the end of the buffer. Method is BUFFERED, so the output is the SystemBuffer (allocation max(input, output)); the input may be 1 byte, so the overflow is past a 34-byte pool allocation. Destination: adjacent pool memory (not caller-chosen). Value: device-context bytes, of which slot flags written by 0xB0191 (item 4) are part of the source region (0x5783..0x57D5). Rated W3 (narrow, fixed 8-byte size, adjacent-chunk target); by the matrix this is MW4 under R3/hardware. The verdict below is taken from item 1.
6. **Request-context and completion writes:** 0xB0192 writes one byte to the WDF request context (1196-1198); the completion `FUN_140003630` writes 0x12 to the first byte of the input buffer, bounded by a 0x12-byte retrieval (1555, 1582). Both are bounded.
7. **Internal helpers:** `FUN_140004080` (memcpy-like, dump 2135-2429) and `FUN_140004340` (memset, dump 2430-2475) are called with fixed sizes (0x2B00, 0x2C7, 0x88, 0x90, 0x60) on device-context or stack objects (dump 362, 452, 701, 818, 852-853, 929, 982-983, 1087). `FUN_140004080` calls at 609, 622 and 1469 copy between device-context fields with fixed sizes or counter-bounded indices. None use a caller-supplied destination.

Conclusion: the one caller-controlled kernel write is the in-object write in item 1 (0x222014): constrained to 256 fixed slots in the device context, arbitrary value. It cannot leave the context and has no pointer target, so it is rated W2 and not W1. The 8-byte overflow in item 5 is a separate narrow pool write (MW4 class). No write uses a caller-supplied address, offset outside the context, or copy length into arbitrary memory.

## 6 Most dangerous exposed capability

0x222014 (SetKeysMap): an admin-capable (any device opener) caller on a host with the MOZA device attached can write 256 possible bytes in the device context, with arbitrary values. Within this image it corrupts only driver state; the pointer-slot case (k = 0) yields a non-canonical pointer and a fault, not a controlled write.

## 7 Verdict

**MW3 - reach=R3 setup=hardware write=W2 load=signed.** The in-object constrained write (0x222014, section 5 item 1) is the rated primitive. The 8-byte pool overflow in 0x22200C (section 5 item 5) is noted as a separate MW4-class defect. Hardware-gated (MOZA device present); not HW-only.

## 8 Limitations

- The device-context size is not recovered from the dump. The code accesses the context up to offset 0x5AA2, so the 0x5855 maximum of the 0x222014 write is inside it; the allocation size from the WDF context type is not verified.
- WDF function-table indices are not named. Callback assignments were taken from the struct field stores (dump 1070-1101).
- Adjacent pool layout for the 8-byte overflow is not analysed; exploitability is not assessed.
- Robustness note (not a write): 0x22201C calls `WdfRequestComplete(0xC0000002)` when ctx+0x5A9E is 0 (1347-1348) and does not return, so the request may be completed twice.
- Forwarded requests are passed to the lower target. Its IOCTL surface is outside this image.
- No REA session used. No execution, no driver load, no registry writes.
