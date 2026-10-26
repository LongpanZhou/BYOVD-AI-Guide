# Audit: TruePort_47710BD8.sys

| Field | Value |
|---|---|
| File | drivers\TruePort_47710BD8.sys |
| SHA-256 | 47710BD892EFB49085CB01B79063496F964F494571645B666C407A0B8646698F |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\TruePort_47710BD8.txt`, 15,159 lines, 289 functions, complete). IOCTL switch `FUN_1400016F0` read in full; device-creation and dispatch sites located by grep. PE import/string triage; Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Perle Systems Limited; file version 6.11.0.0001; "TruePort" / "TruePort Serial Device Driver" |
| Signature | Authenticode Valid; signer CN=Perle Systems Limited |
| Reach | R3 (devnode / hardware: a Perle port device must be enumerated; the control device is created in the AddDevice path) |
| Setup required | hardware |
| Write quality | W0 for caller-controlled writes in the traced IOCTL switch; provisional (see Limitations) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL: the untraced paths in §8 may change this) |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 WDM serial driver (serial port function-driver model: port IRP queue, cancel-safe queue, ring buffers, WMI). Imports: ntoskrnl (IRP, queue, registry, WMI), WMILIB, WDFLDR (imported but not the device model). Imports include `IoCreateDevice`, `IoCreateSymbolicLink`, `IoRegisterDeviceInterface`, `IoAcquireRemoveLockEx`, `RtlWriteRegistryValue`, `ZwSetValueKey`, `IoWMIRegistrationControl`.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, ProbeForWrite, MmGetSystemRoutineAddress or ZwSetSecurityObject in the imports.
- Entry: `entry @ 14000F970` (dump 11749). Dispatch slots set in the device-create paths: MajorFunction CREATE (+0x70) = `FUN_1400064C0` (dump 4597), CLOSE (+0x80) = `FUN_140006310` (dump 4509), DEVICE_CONTROL (+0xE0) = `FUN_140005E40` (dump 4206-4232, calls `FUN_14000604C` and `FUN_140002A30`). A second device set uses +0x70 = `FUN_140007770` and +0xE0 = `FUN_140007090` (dump 10063-10069).

## 2 Entry / device / interface / effective DACL

- Control device: `IoCreateDevice(DriverObject, 0x325D8, 0, 0x22)` at dump 13012 (DeviceType FILE_DEVICE_UNKNOWN, extension 0x325D8, no name, no security descriptor). Failure logged at dump 13052.
- Per-port device: `IoCreateDevice(DeviceObject, 0xBF8, &local_70, 0x1B)` at dump 13480 (DeviceType 0x1B = FILE_DEVICE_SERIAL_PORT, named via a UNICODE_STRING built at runtime; the name strings in the image are `\Device\TPPort` and `\DosDevices\`).
- Symbolic link: `IoCreateSymbolicLink` at dump 13367. Device interface: `IoRegisterDeviceInterface(DriverObject, &DAT_1400114F8, 0, ...)` at dump 13372 (GUID bytes at VA 0x1400114F8, not decoded in this pass).
- Effective DACL: the image has no `IoCreateDeviceSecure`, no `ZwSetSecurityObject`, and no SDDL string (triage: the only SDDL-like strings are source paths). Devices therefore carry the IoCreateDevice default security, and the interface ACL is set by PnP. The image does not fix it.

## 3 Dispatch and IOCTL table

Dispatch: `FUN_1400016F0` (dump 442-1945) is the serial IOCTL switch on `IoControlCode` (`uVar11 = *(uint*)(stack+0x18)`, dump 494-495). Input length at stack+0x10 and output length at stack+0x08 (`lVar3+0x10` and `lVar3+8`). SystemBuffer = IRP+0x18. All codes below are 0x1B00xx: DeviceType 0x1B, function 0x0001..0x0026. Method and access bits are per the low 2 bits and bits 14-15 of each code.

Common helper names: `FUN_140007B20` queues the IRP behind a wait routine (cancel-safe), `FUN_140006970` is the wait/queue helper, `FUN_14000E680` is the cancel-safe IRP queue insert (dump 10732-10797, reads no buffer size). Fixed-size checks are the minimum lengths in the table.

| IOCTL | Input min | Output min | Kernel action (dump lines) |
|---|---|---|---|
| 0x1B0004 | 4 (501) | - | Writes input DWORD to device fields +0x4E0 and +0x2B8 (511-512) after `FUN_140007B20(FUN_140002600)` (506). |
| 0x1B0008 | - | - | No case in this switch (falls through the 0x1B0004-0x1B000C chain, dump 527-528). Not traced further. |
| 0x1B000C | 3 (532) | - | Sets line-control state (+0x4F8, +0x514, +0x2C4, +0x2C8) from input bytes via a fixed mapping (534-609). Info 0. |
| 0x1B0010 | - | - | If dev+0xD58 >= 2 and `FUN_14000539C` false: `FUN_140006970(...)`, sets flag +0xB90 |= 0x4000 (620-625). |
| 0x1B0014 | - | - | Same gate as 0x1B0010; flag 0x8000 (685-691). |
| 0x1B0018 | input != 0 (630) | - | Wait-mask IRP queue: sets +0x470 and +0x530, calls `FUN_14000131C` (631-638). |
| 0x1B001C | 0x14 (653) | - | Copies 5 DWORDs from input into device fields +0x500..+0x510 (656-660). Info 0. |
| 0x1B0020 | output >= 0x14 (671) | 0x14 | Copies device fields +0x500..+0x510 (20 bytes) to output (675-678). Info 0x14. |
| 0x1B0024 | - | - | `FUN_140007B20(FUN_140002840 or FUN_140002760)`, then `FUN_140006970` when dev+0xD58 > 1 (715-744). |
| 0x1B0028 | input >= 8 (699) | - | If input DWORD[0] > dev+0x4C0: `FUN_1400054CC` allocates input DWORD[0] bytes (701) and attaches the buffer at IO stack +0x20 (702); queued with callback `FUN_140004AB0` via `FUN_14000E680` (704-707, 800-801). **Not fully traced: see §8.** Otherwise error (710). |
| 0x1B002C | - | - | Completes with the default path (753). |
| 0x1B0030 / 0x1B0034 | - | - | Checks flags +0x4EC and queues via `FUN_140007B20(FUN_140002880 or FUN_140002780)` (754-762). |
| 0x1B0038 | dev+0xD58 >= 2 (765) | - | `FUN_140006970` with flag +0xB90 |= 0x2000 (767-770). |
| 0x1B003C | dev+0xD58 >= 2 (807) | - | `FUN_140006970` with flag +0xB90 |= 0x1000 (809-812). |
| 0x1B0040 | output >= 4 (775) | 4 | Writes dev+0x4CC (DWORD) to output (776-779). Info 4. |
| 0x1B0044 | input >= 4 (784) | - | If input DWORD & 0xFFFFE000 == 0: queue via `FUN_14000E680(FUN_14000EAF0)` (785, 797-801). Otherwise error (786). |
| 0x1B0048 | output >= 4 (795) | - | Queue via `FUN_14000E680(FUN_14000EAF0)` (796-801). |
| 0x1B004C | input >= 4 (825) | - | If input DWORD != 0 and (DWORD & 0xFFFFFFF0) == 0: queue via `FUN_140004070` (826-830). Otherwise error (832). |
| 0x1B0050 | output >= 4 (849) | 4 | Writes dev+0x4E0 (DWORD) to output (851). Info 4. |
| 0x1B0054 | output >= 3 (859) | 3 | Writes 3 bytes of line/flow state to output (862-895). Info 3. |
| 0x1B0058 | output >= 6 (903) | 6 | Writes dev+0x4F9 (DWORD) and dev+0x4FD (WORD) to output (906-908). Info 6. |
| 0x1B005C | input >= 6 (914) | - | Conditional queue `FUN_140007B20(FUN_1400026F0)` and sets dev+0x2CC/+0x2D4 from device bytes (918-924). Error if the state check fails (927). |
| 0x1B0060 | output >= 0x10 (933) | 0x10 | Copies 16 bytes (dev+0x4E8, +0x4F0) to output (936-939). Info 0x10. |
| 0x1B0064 | input >= 0x10 (945) | - | Validates four fields ≤ dev+0x4C0 and flags (946-949); queues `FUN_140007B20(FUN_140002860)` and sets dev+0x2D0 / +0x2D8 (953-961). |
| 0x1B0068 | output >= 4 (968) | 4 | `FUN_1400053DC` query; writes DWORD from dev+0xBC8 or dev+0xBC8 & 0xF0 to output (970-979). Info 4. |
| 0x1B006C | output >= 0x14 (983) | 0x14 | Queues `FUN_140007B20(FUN_140001530)` under the cancel lock (985-989). Info 0x14. |
| 0x1B0070 | input >= 0xC (837), input DWORD[1] > 0 (838) | - | Queues `FUN_14000F2F0` via `FUN_14000E680` (839-842). |
| 0x1B0074 | output >= 0x40 (994) | 0x40 | `FUN_140001624` fills the 0x40-byte output from device state (995-996). Info 0x40. |
| 0x1B0078 | output >= 4 (1001) | 4 | Writes a status DWORD (bits from dev+0xA88 / +0xA8A) to output (1003-1009). Info 4. |
| 0x1B007C | input >= 1 (1015) | - | Reads input byte; queues `FUN_140007B20(FUN_140002710)` (1016-1022). |
| 0x1B0080 | output >= 4 (1026) | 4 | Zeroes the output DWORD (1028). Info 4. |
| 0x1B008C | output >= 0x18 (1033) | 0x18 | Queues `FUN_1400016C0` via `FUN_140007B20` (1035-1046). Info 0x18. |
| 0x1B0090 | - | - | Queues `FUN_140001510` (1042-1046). |
| 0x1B0094 | output >= 4 (1049) | 4 | Writes a 2-bit status DWORD to output (1051-1053). Info 4. |
| 0x1B0098 | input >= 4 (1058) | 4 | Reads input DWORD (1061), queues `FUN_140002840` (1059). Info 4. |
| 0x222000 | - | - | Handled in the second device path (`FUN_140007770`, dump 5771). Not traced (§8). |
| other | - | - | Invalid request (0xC000000D). |

## 4 Access-control audit

- No `SeAccessCheck`, `SeSinglePrivilegeCheck` or caller-identity check. The gates are device state (dev+0xD58 port count, dev+0x4C0 queue size, flag bytes) and the length checks in §3.
- Any principal that can open the device object (IoCreateDevice default security, or the interface) can issue the 0x1B00xx codes.

## 5 Memory-write trace

1. **IOCTL-written output buffers:** 0x1B0020, 0x1B0040, 0x1B0050, 0x1B0054, 0x1B0058, 0x1B0060, 0x1B0068, 0x1B0074, 0x1B0078, 0x1B0080, 0x1B0094 write fixed-size fields (3 to 0x40 bytes) into the SystemBuffer after the output-length check in §3. Destinations are fixed; values are device state. Bounded.
2. **Device-field writes from input:** 0x1B0004, 0x1B000C, 0x1B0018, 0x1B001C, 0x1B0064, 0x1B005C write fixed device fields from input DWORDs or bytes at fixed offsets (dump 511-512, 534-609, 631, 656-660, 946-961, 918-924). No index comes from the caller.
3. **Pool allocation with caller size (0x1B0028):** `FUN_1400054CC` allocates `SystemBuffer[0]` bytes when it exceeds dev+0x4C0 (dump 699-702). The allocation is attached to the IO stack location. Its later use is in `FUN_140004AB0` (queue callback) and the queue machinery, which were not traced for copy lengths (§8).
4. **Ring-buffer writes on the write IRP:** `FUN_1400086E0` copies user data into the device ring (`FUN_140010100` at dump 6826, 6874, 6896) with length limited to the free space `(dev+0x4B0 - dev+0x4A8) + 1` and the request length (6810-6833). Bounded by the ring; not an IOCTL.
5. **Serial receive state machine:** `FUN_140003614` (dump 1946-3585) writes received characters into the ring from hardware interrupts (dump 1979-1984). Not caller-controlled.
6. **0x222000 (second device path):** not traced (§8). The second device uses `FUN_140007B84` (dump 5906-6268) whose writes are bounded by the output-length check (5941, 5984) and the 0x31 table cap (5937-5939, 5959-5961); this is the 0x222000 candidate path and is bounded for the paths read.

No write in the traced IOCTL switch uses a caller-supplied destination or unbounded length. No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection or MmGetPhysicalAddress import exists.

## 6 Most dangerous exposed capability

The caller-sized allocation in 0x1B0028 (up to the pool limit, §5 item 3) is the only input-controlled allocation found. It is a denial-of-service or resource-pressure path until its use is traced. No write primitive is identified in the traced code.

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** Reach R3 (devnode/hardware); Setup: hardware; Write quality W0 in the traced code. The verdict is provisional because the paths in §8 are not traced. HW-only: no.

## 8 Limitations (paths not traced; reason: scale)

- **0x1B0028 allocation (dump 699-711, 800-801):** the allocation buffer and its later use in `FUN_140004AB0` (dump 2947-3931), `FUN_14000E680`, `FUN_14000E300` (dump 10517) and the queue callbacks are not fully traced. A copy length taken from the buffer's own size, or a store past it, is not ruled out.
- **Queue and wait helpers not individually read:** `FUN_140007B20`, `FUN_140006970`, `FUN_14000539C`, `FUN_14000131C`, `FUN_140002600/…/2880`, `FUN_1400026F0`, `FUN_140002860`, `FUN_14000F2F0`, `FUN_140001510`, `FUN_1400016C0`, `FUN_140001624`, `FUN_140004070`, `FUN_14000EAF0`.
- **Second device dispatch (FUN_140007090 → FUN_140007500 → FUN_140007B84/FUN_14000798C):** the 0x222000 handler's routing was located but the caller of FUN_140007500 (IOCTL code) and FUN_14000798C (dump 5797-5902) were not traced.
- **IRP_MJ_READ / WRITE copy helpers** (`FUN_140003560`, `FUN_140003F58`, `FUN_140003614` tail) were read only at call sites.
- **Device-interface GUID** `DAT_1400114F8` not decoded.
- No REA session used. No execution, no driver load, no registry writes.
