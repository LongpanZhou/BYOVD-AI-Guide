# Audit: BbUBus51AMD64_06AD927A.sys (PARTIAL: IOCTL switch behind vtable not resolved)

| Field | Value |
|---|---|
| File | drivers\BbUBus51AMD64_06AD927A.sys |
| SHA-256 | 06AD927AC9E69E8AC7F86E1E322FDE2AEEB3848D09714D34758AA803423EC660 (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\BbUBus51AMD64_06AD927A.txt`, 510 functions, `=== DONE` at last line). REA not used. |
| Reach | R3 (Brainboxes ExpressCard/USB bus function; the named device exists only after AddDevice on the hardware) |
| Setup required | hardware |
| Write quality | W0 |
| Severity | NO-MEMORY-WRITE (provisional: device-control path not fully resolved, section 8) |
| HW-only | yes (BAR MMIO via fixed PnP resource; no kernel memory write found) |

Identity (Get-AuthenticodeSignature / VersionInfo): Company Brainboxes Limited; FileVersion 5.1.132.0; signature Valid (Brainboxes Ltd, Liverpool).

## 1 Internals

- Driver type: WDM bus/function driver (PnP AddDevice, `BbUBus m_AddDevice`, `m_PnpStartDevice` strings).
- Imports: NTOSKRNL.EXE only in the dangerous set: `MmMapIoSpace`, `MmUnmapIoSpace`, `IoCreateDevice`, `IoCreateSymbolicLink`, `IoRegisterDeviceInterface`, `IoBuildDeviceIoControlRequest`, `ExAllocatePoolWithTag` (EXT lines 5, 44, 57, 60, 63, 67, 71).
- No `MmMapLockedPagesSpecifyCache`, `ZwMapViewOfSection`, `MmCopyMemory`, `MmGetPhysicalAddress`, or `ProbeForWrite` import.

## 2 Entry / device / interface / effective DACL

- Device creation: `IoCreateDevice(param_2, 0x40, puVar6, param_4, 0, param_6, param_8)` at line 23470, inside `FUN_000319c0 @ 000319c0` (header 23415). Device name is the `puVar6` argument. No SDDL argument (`IoCreateDeviceSecure` not imported), so the effective DACL is the IoCreateDevice default for a named device object. The driver does not set a custom DACL.
- Symbolic link: `IoCreateSymbolicLink(puVar5, puVar6)` at line 23519, same function.
- Interface: `IoRegisterDeviceInterface` at dump line 57 (EXT); call site in the AddDevice path.
- MajorFunction setup: IRP_MJ_CREATE (offset 0x70) at line 13036 `*(code **)(*param_2 + 0x70) = FUN_00022b54;` and IRP_MJ_DEVICE_CONTROL (offset 0xE0) at line 13041 `*(code **)(*param_2 + 0xe0) = FUN_00022c44;`.

## 3 Dispatch and IOCTL table

- IRP_MJ_DEVICE_CONTROL = `FUN_00022c44 @ 00022c44` (header line 12725) forwards to `FUN_00023a38 @ 00023a38` (header line 13321).
- `FUN_00023a38` calls `FUN_00023dd0 @ 00023dd0` (header line 13436; object resolution) and then the object's vtable slot `+0x40` (`(**(code **)(*local_res20 + 0x40))(local_res20, param_3)`) and `+0x68`. The IOCTL switch is inside that per-object vtable method, which is not resolved in the dump.
- No `switch`, `case 0x...`, or comparison against the IO_STACK IoControlCode field (+0x18) was found in the bus driver body (grep of the dump).
- IOCTL-shaped constants present: `0x220003` (lines 25195, 25272, 25387, 25651; `IOCTL_INTERNAL_USB_SUBMIT_URB`) and `0x220007` (lines 24932, 25313; `IOCTL_INTERNAL_USB_RESET_PORT`). Both are issued to the USB PDO, not received from user mode. `0x8000e000` is built at line 12071 (`FUN_00021fe8 @ 00021fe8`, header 12059) and forwarded to a lower driver (internal).
- IOCTL table: none user-facing resolved. The per-child vtable handlers are not enumerated (section 8).

## 4 Access-control audit

- No `SeSinglePrivilegeCheck` / `SeAccessCheck` / caller identity check in the image. The device object uses the IoCreateDevice default DACL (section 2).
- Reach is gated by the hardware (ExpressCard/USB Brainboxes device must enumerate). Administrator reach is not a separate gate here.

## 5 Memory-write trace

1. **BAR mapping (fixed):** `MmMapIoSpace(CONCAT44(uStack_8c, CONCAT22(uStack_8e, local_90)), local_88, 0)` at line 15765 inside `FUN_00026d38 @ 00026d38` (header 15548). The base and length come from `FUN_00026b90` reads of `AllocatedResourcesTranslated` (log string "call MmMapIoSpace with parameter", lines ~15760) and the PnP resource list. The caller does not supply them. Fixed-window MMIO, HW-only.
2. **memcpy calls:** `memcpy` at lines 634, 636, 1765, 6286, 6699, 6707, 6950, 6992, 7062, 7405-7990, 8064, 8600, 10898-10966, 13827 and others. The sources and destinations are driver structures and I/O-manager buffers (`*(param_2+0x10)`, `param_1+0x120`). Lengths come from driver fields (`*(ushort *)(param_1+0x1a)`, etc.). No caller-controlled kernel destination was identified; the kernel-side length and destination are not shown to be attacker-controlled through a user IOCTL because the IOCTL switch was not resolved (section 8).
3. **Internal URB / lower-driver requests:** lines 12071, 24932, 25195, 25272, 25313, 25387, 25651 (internal IOCTL codes, not user-facing).

Write classification:

- Target control: none found (fixed BAR and driver structures).
- Value control: none found.
- Size control: driver-field bounded.
- Kernel write from caller input: none found in the analysed paths. This is the open item.

## 6 Most dangerous exposed capability

Not determined. The bus-level device-control path forwards to child objects, and the child IOCTL handlers were not resolved. The known risk surface is the memcpy family at lines 7405-8064, which copies driver/IRP buffers. Their caller-supplied length fields were not traced to an IRP input buffer.

## 7 Verdict

- Provisional: **NO-MEMORY-WRITE** (HW-only BAR mapping). Reach R3, setup hardware, write quality W0, signed (Brainboxes).
- Status: partial. The user-reachable IOCTL switch is behind an unresolved vtable hop (`FUN_00023a38` line 13321, vtable `+0x40`). A full verdict requires the child-object handlers, which are in the sibling BbUSer driver (`BbUSer51AMD64_D4AE57AA`, section 8).

## 8 Limitations

- The per-object vtable at `+0x40` (called from `FUN_00023a38`, line 13321) was not resolved to a concrete function, so the IOCTL switch and its input validation are not enumerated.
- The memcpy family (lines 7405-8064, 10898-10966) was not traced to IRP input buffers.
- Device-side behaviour and BAR register semantics are not modelled.
- Not loaded or executed (static only).
