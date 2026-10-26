# Audit: BbUSerV251AMD64_475E1B75.sys (PARTIAL: IOCTL switch behind vtable not resolved)

| Field | Value |
|---|---|
| File | drivers\BbUSerV251AMD64_475E1B75.sys |
| SHA-256 | 475E1B7596945F2C953B110C222A9CD5C8DCE4EA1F14C1829C87E2528481EC52 (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\BbUSerV251AMD64_475E1B75.txt`, 710 functions, `=== DONE` at last line). REA not used. |
| Reach | R3 (Brainboxes serial function driver; named device exists only on the hardware) |
| Setup required | hardware |
| Write quality | W0 |
| Severity | NO-MEMORY-WRITE (provisional: device-control path not fully resolved, section 8) |
| HW-only | yes (BAR MMIO via fixed PnP resource; no kernel memory write found) |

Identity: Company Brainboxes Limited; FileVersion 5.1.132.0; signature Valid (Brainboxes Ltd).

## 1 Internals

- WDM function driver, same codebase family as `BbUSer51AMD64_D4AE57AA` (see that report).
- Dangerous imports: `MmMapIoSpace`, `MmUnmapIoSpace`, `IoCreateDevice`, `IoCreateSymbolicLink`, `IoRegisterDeviceInterface`, `IoBuildDeviceIoControlRequest`, `ExAllocatePoolWithTag`. No `MmMapLockedPagesSpecifyCache`, `ZwMapViewOfSection`, `MmCopyMemory`, `MmGetPhysicalAddress`, `ProbeForWrite`.

## 2 Entry / device / interface / effective DACL

- Device creation: `IoCreateDevice(param_2, 0x40, puVar5, param_4, 0, param_6, param_8)` at line 18118, inside `FUN_140018658 @ 140018658` (header 18084). No SDDL argument; effective DACL is the IoCreateDevice default for a named device.
- MajorFunction setup: IRP_MJ_CREATE (0x70) `*(code **)(*param_2 + 0x70) = FUN_1400162e0;` at line 15799 and IRP_MJ_DEVICE_CONTROL (0xE0) `*(code **)(*param_2 + 0xe0) = FUN_140016300;` at line 15804, both in `FUN_140015f48 @ 140015f48` (header 15772).

## 3 Dispatch and IOCTL table

- IRP_MJ_DEVICE_CONTROL = `FUN_140016300 @ 140016300` (header 15953): null check (`0xC0000001`), then `FUN_140015724 @ 140015724` (header 15508) with the object at `*(param_1+8)+0x60`.
- `FUN_140015724` contains no vtable call and no `IoControlCode` comparison; the handler set is in the forwarded-to object, not resolved.
- No `switch` / `case 0x...` in the image. No user-facing IOCTL constant found.
- IOCTL table: not resolved (section 8).

## 4 Access-control audit

- No privilege or caller-identity checks. Named device uses the IoCreateDevice default DACL. Reach gated by the hardware.

## 5 Memory-write trace

1. **BAR mapping (fixed):** `MmMapIoSpace(CONCAT44(uStack_84, CONCAT22(uStack_86, local_88)), local_80, 0)` at line 20489 in `FUN_14001be68 @ 14001be68` (header 20428). Address and length from PnP `AllocatedResourcesTranslated`. Fixed-window MMIO, HW-only.
2. **memcpy family:** driver structure and IRP-buffer copies bounded by driver fields. No caller-controlled kernel destination identified in the analysed code.

Write classification: target none, value none, size driver-bounded, kernel write from caller input none found.

## 6 Most dangerous exposed capability

Not determined. Handler set behind the forwarder in `FUN_140015724` (line 15508) not resolved.

## 7 Verdict

- Provisional: **NO-MEMORY-WRITE** (HW-only BAR mapping). Reach R3, setup hardware, write quality W0, signed.
- Status: partial.

## 8 Limitations

- Forwarded-to object from `FUN_140015724` (line 15508) not resolved; IOCTL set not enumerated.
- memcpy family not traced to IRP input buffers.
- Static only; not loaded.
