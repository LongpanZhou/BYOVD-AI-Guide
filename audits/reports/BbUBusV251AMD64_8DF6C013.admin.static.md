# Audit: BbUBusV251AMD64_8DF6C013.sys (PARTIAL: IOCTL switch behind vtable not resolved)

| Field | Value |
|---|---|
| File | drivers\BbUBusV251AMD64_8DF6C013.sys |
| SHA-256 | 8DF6C01336F9E4B9CEF8C5723CE8FD3A40DD56CADB0AA6499D417993709671D3 (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\BbUBusV251AMD64_8DF6C013.txt`, 782 functions, `=== DONE` at last line). REA not used. |
| Reach | R3 (Brainboxes bus function; named device exists only after AddDevice on the hardware) |
| Setup required | hardware |
| Write quality | W0 |
| Severity | NO-MEMORY-WRITE (provisional: device-control path not fully resolved, section 8) |
| HW-only | yes (BAR MMIO via fixed PnP resource; no kernel memory write found) |

Identity: Company Brainboxes Limited; FileVersion 5.1.132.0; signature Valid (Brainboxes Ltd).

## 1 Internals

- WDM bus/function driver, same codebase family as `BbUBus51AMD64_06AD927A` (see that report).
- Dangerous imports: `MmMapIoSpace`, `IoCreateDevice`, `IoCreateSymbolicLink`, `IoRegisterDeviceInterface`, `IoBuildDeviceIoControlRequest`, `ExAllocatePoolWithTag`. No `MmMapLockedPagesSpecifyCache`, `ZwMapViewOfSection`, `MmCopyMemory`, `MmGetPhysicalAddress`, `ProbeForWrite` in the image.

## 2 Entry / device / interface / effective DACL

- Device creation: `IoCreateDevice(param_2, 0x40, puVar5, param_4, 0, param_6, param_8)` at line 21330, inside `FUN_14001b898 @ 14001b898` (header 21296). No SDDL argument; the effective DACL is the IoCreateDevice default for a named device object.
- MajorFunction setup: IRP_MJ_CREATE (offset 0x70) `*(code **)(*param_2 + 0x70) = FUN_140012800;` at line 14011 and IRP_MJ_DEVICE_CONTROL (offset 0xE0) `*(code **)(*param_2 + 0xe0) = FUN_140012820;` at line 14016, both in `FUN_140012468 @ 140012468` (header 13984).
- Symbolic link and device interface: `IoCreateSymbolicLink` and `IoRegisterDeviceInterface` in the same AddDevice path (EXT list).

## 3 Dispatch and IOCTL table

- IRP_MJ_DEVICE_CONTROL = `FUN_140012820 @ 140012820` (header 14165): if the device object is null returns `0xC0000001`, otherwise calls `FUN_140011c44 @ 140011c44` (header 13720) with the object at `*(param_1+8)+0x60`.
- `FUN_140011c44` makes no vtable call and contains no `IoControlCode` comparison; its IOCTL-to-handler routing lives in the object it forwards to (not resolved).
- No `switch` / `case 0x...` in the image (grep). IOCTL-shaped constants: none user-facing. Internal values (`0x220003`, `0x8000e000`) are lower-driver requests.
- IOCTL table: not resolved (section 8).

## 4 Access-control audit

- No `SeSinglePrivilegeCheck` / `SeAccessCheck` / caller identity checks. Named device uses the IoCreateDevice default DACL. Reach gated by the hardware (section 1).

## 5 Memory-write trace

1. **BAR mapping (fixed):** `MmMapIoSpace(CONCAT44(uStack_84, CONCAT22(uStack_86, local_88)), local_80, 0)` at line 16629 inside `FUN_140015e98 @ 140015e98` (header 16568). Address and length come from the PnP `AllocatedResourcesTranslated` list (`FUN_00026b90`-equivalent reads). Caller does not supply them. Fixed-window MMIO, HW-only.
2. **memcpy family:** driver structure and IRP-buffer copies (bounded by driver fields). No caller-controlled kernel destination identified in the analysed code.
3. **Unmapping:** `MmUnmapIoSpace` on the mapped BAR on failure/removal; not a write.

Write classification: target none, value none, size driver-bounded, kernel write from caller input none found.

## 6 Most dangerous exposed capability

Not determined. The IOCTL handler set is in the forwarded-to object; not resolved.

## 7 Verdict

- Provisional: **NO-MEMORY-WRITE** (HW-only BAR mapping). Reach R3, setup hardware, write quality W0, signed.
- Status: partial (see section 8).

## 8 Limitations

- Object forwarded to from `FUN_140011c44` (line 13720) was not resolved, so the IOCTL switch is not enumerated.
- The memcpy family was not traced to IRP input buffers.
- Static only; not loaded.
