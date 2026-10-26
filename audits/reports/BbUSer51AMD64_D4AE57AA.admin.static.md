# Audit: BbUSer51AMD64_D4AE57AA.sys (PARTIAL: IOCTL switch behind vtable not resolved)

| Field | Value |
|---|---|
| File | drivers\BbUSer51AMD64_D4AE57AA.sys |
| SHA-256 | D4AE57AADD1D238B84F938E63DAE578E3A2557E456533EA57376F78FFDFDB759 (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\BbUSer51AMD64_D4AE57AA.txt`, 495 functions, `=== DONE` at last line). REA not used. |
| Reach | R3 (Brainboxes serial/USB function driver; named device exists only on the hardware) |
| Setup required | hardware |
| Write quality | W0 |
| Severity | NO-MEMORY-WRITE (provisional: device-control path not fully resolved, section 8) |
| HW-only | yes (BAR MMIO via fixed PnP resource; no kernel memory write found) |

Identity: Company Brainboxes Limited; FileVersion 5.1.132.0; signature Valid (Brainboxes Ltd).

## 1 Internals

- WDM function driver (Brainboxes serial/USB function), same codebase family as `BbUBus51AMD64_06AD927A`. Its string table (`strings_c1\BbUSer51AMD64_D4AE57AA.strings.txt`) contains no `CFTDI1Port` / `SendDataToDevice` text (those are in the BbUBus strings).
- Dangerous imports: `MmMapIoSpace`, `MmUnmapIoSpace`, `IoCreateDevice`, `IoCreateSymbolicLink`, `IoRegisterDeviceInterface`, `IoBuildDeviceIoControlRequest`, `ExAllocatePoolWithTag` (EXT lines 5, 26, 56, 59, 63, 74, 80).

## 2 Entry / device / interface / effective DACL

- Device creation: `IoCreateDevice(param_2, 0x40, puVar6, param_4, 0, param_6, param_8)` at line 22688, inside `FUN_00031488 @ 00031488` (header 22632). No SDDL argument; effective DACL is the IoCreateDevice default for a named device.
- Symbolic links: `IoCreateSymbolicLink(puVar3, puVar4)` at line 19765 in `FUN_0002d9e4 @ 0002d9e4` (header 19713), and `IoCreateSymbolicLink(puVar5, puVar6)` at line 22739 in `FUN_00031488` (same function as the device creation above).
- MajorFunction setup: IRP_MJ_CREATE (0x70) `*(code **)(*param_2 + 0x70) = FUN_00025ef4;` at line 14656 and IRP_MJ_DEVICE_CONTROL (0xE0) `*(code **)(*param_2 + 0xe0) = FUN_00025fe4;` at line 14661, both in `FUN_00026460 @ 00026460` (header 14630).

## 3 Dispatch and IOCTL table

- IRP_MJ_DEVICE_CONTROL = `FUN_00025fe4 @ 00025fe4` (header 14345): null check (`0xC0000001`), then `FUN_00026dd8 @ 00026dd8` (header 14941) with the object at `*(param_1+8)+0x60`.
- `FUN_00026dd8` makes two vtable calls (indirect `(**(code **)(...))`) and performs no `IoControlCode` comparison. The IOCTL switch is in the object it dispatches to, not resolved.
- No `switch` / `case 0x...` in the image. No user-facing IOCTL constant found. (`0x220003` and `0x220007` appear in the sibling BbUBus driver as internal USB codes; not re-counted here.)
- IOCTL table: not resolved (section 8).

## 4 Access-control audit

- No privilege or caller-identity checks in the image. Named device uses the IoCreateDevice default DACL. Reach gated by the hardware.

## 5 Memory-write trace

1. **BAR mapping (fixed):** `MmMapIoSpace(CONCAT44(uStack_8c, CONCAT22(uStack_8e, local_90)), local_88, 0)` at line 17374 in `FUN_0002a088 @ 0002a088` (header 17157). Address and length from PnP `AllocatedResourcesTranslated`. Caller does not supply them. Fixed-window MMIO, HW-only.
2. **Buffer copies:** the `memcpy` family in this image copies to and from driver and IRP buffers with driver-field lengths (not traced line by line in this pass). No caller-controlled kernel destination identified in the analysed code.

Write classification: target none, value none, size driver-bounded, kernel write from caller input none found.

## 6 Most dangerous exposed capability

Not determined. Serial IOCTL handlers are behind the vtable hop in `FUN_00026dd8` and were not resolved.

## 7 Verdict

- Provisional: **NO-MEMORY-WRITE** (HW-only BAR mapping). Reach R3, setup hardware, write quality W0, signed.
- Status: partial.

## 8 Limitations

- The vtable targets called from `FUN_00026dd8` (line 14941 region) were not resolved, so the serial IOCTL set is not enumerated.
- Static only; not loaded.
