# Audit: usbdaqlib_58D0669F.sys (kernel-VA write via caller-supplied buffer address; device must be started)

| Field | Value |
|---|---|
| File | drivers\usbdaqlib_58D0669F.sys |
| SHA-256 | 58D0669F2756350998A9826216EDFD62D2D921D4AC534C56DFCCD629130FC443 (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\usbdaqlib_58D0669F.txt`, 238 functions, 0 decompile failures, `=== DONE` at last line). REA not used. |
| Reach | R3 (Measurement Computing USB DAQ function driver; the IOCTL is accepted only when the device is in the started state, dispatcher line 1973) |
| Setup required | hardware |
| Write quality | W2 (target = caller-supplied address, validated only by KernelMode MDL lock, so arbitrary; value = fixed driver pattern, so constrained) |
| Severity | MW3 (provisional: R3 hardware with W2, per SEVERITY matrix) |
| HW-only | no |

Identity (Get-AuthenticodeSignature / VersionInfo): Company Measurement Computing Corp.; FileVersion 5.0.3 Build 1; signature Valid (signer `CN="Digilent, Inc."`).

## 1 Internals

- DriverEntry / MajorFunction table: `FUN_00011008 @ 00011008` (header 67). IRP_MJ_CREATE (0x70) = `FUN_000136dc` (line 89); IRP_MJ_PNP (0x148) = `FUN_00011464` (line 88); IRP_MJ_DEVICE_CONTROL (0xE0) = `FUN_000138f8` (line 86).
- Dangerous imports (EXT list): `IoAllocateMdl`, `IoFreeMdl`, `MmProbeAndLockPages`, `MmUnlockPages`, `MmMapLockedPagesSpecifyCache`, `IoCreateDevice`, `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`, `IoBuildDeviceIoControlRequest`, `PsCreateSystemThread`, `PoSetPowerState`, `USBD_ParseConfigurationDescriptorEx`. No `ProbeForWrite`, `ProbeForRead`, `MmHighestUserAddress`, or `MmIsAddressValid` import (grep of the dump: 0 hits).

## 2 Entry / device / interface / effective DACL

- AddDevice: `FUN_00011148 @ 00011148` (header 113). `IoCreateDevice(param_1, 0x250, 0, 0x22, 0x80, 0, &dev)` at line 127: **unnamed** device (DeviceName = 0), FILE_DEVICE_UNKNOWN, Exclusive = 0. No SDDL argument.
- Device interface: `IoRegisterDeviceInterface(plVar2[2], &DAT_000295f0, 0, plVar2+3)` at line 175 (GUID at `DAT_000295f0`). The interface DACL is the IoRegisterDeviceInterface default (no SDDL in the call or in the image). This interface is the user-mode route to the device.
- Effective DACL: default (not resolved to a specific SDDL). No `SeSinglePrivilegeCheck` / `SeAccessCheck` in the IOCTL path.

## 3 Dispatch and IOCTL table

Dispatcher `FUN_000138f8 @ 000138f8` (header 1949, size 360):

- Line 1969: IoControlCode = `*(uint *)(IO_STACK + 0x18)`.
- Line 1973: `if (*(int *)(dev+0x88) != 2)` -> completes with STATUS `0xC0000184` (device not started). This gate means the handler needs a started device, i.e. attached hardware.
- Line 1983: `0x220000` copies a driver-owned block (`memcpy(local_res10, _Src, uVar1)`, line 1983 area).
- Line 2001: `0x220004` -> `FUN_00013b80`. Line 2006: `0x220008` -> separate handler.
- Line 2008: all other codes -> `FUN_00022944(dev, IOCTL, SystemBuffer, ...)` (`FUN_00022944 @ 00022944`, header 13084), which calls `FUN_0001f8a0(...)` at line 13146.

IOCTL handler `FUN_0001f8a0 @ 0001f8a0` (header 10801, size 2339). Custom codes in the 0x5000xxxx range (decoded as device 0x5000, METHOD_BUFFERED, FILE_ANY_ACCESS unless noted):

| IOCTL | Decode | Line | Action (as traced) |
|---|---|---|---|
| 0x500024a4 | function 0x929, METHOD_BUFFERED, FILE_ANY_ACCESS | 10856 -> 10857 | `FUN_00022c38((int*)param_3, ...)`: buffer lock + pattern copy (section 5, item 1). **Traced.** |
| 0x50002408 | function 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS | 10850 | `FUN_0001f38c(param_3, ...)` (not traced) |
| 0x500024a8, 0x500024a0, 0x50002490, 0x5000249c, 0x50002484, 0x50002400, 0x50002404, 0x50002478, 0x50002410, 0x5000240c, 0x50002434, 0x50002494, 0x50002414, 0x50002428, 0x50002420, 0x50002424, 0x50002418, 0x5000241c, 0x5000242c, 0x50002480, 0x50002498, 0x50002448, 0x50002454, 0x50002458, 0x5000246c, 0x5000247c, 0xffffffff | various | 10834-10870+ | cases in the same dispatcher; not traced |

The other buffer-lock callers are `FUN_000176a4 @ 000176a4` (line 4780, header 4743, `FUN_000232c0(*(puVar3+3), ...)`) and `FUN_0001d190 @ 0001d190` (line 9099, header 9026, `FUN_000232c0(*(piVar4+5), ...)`). They use the same helper with a caller-provided address; they were not traced further.

## 4 Access-control audit

- No privilege or caller-identity check in the IOCTL path. The only gates are (a) the device must be started (line 1973) and (b) the device-interface DACL (default, not resolved).
- The IOCTLs are METHOD_BUFFERED with FILE_ANY_ACCESS, so the I/O manager performs no per-code access check. Whoever can open the interface can issue 0x500024a4.

## 5 Memory-write trace

1. **Caller address into a kernel mapping (IOCTL 0x500024a4):**
   - `FUN_00022c38 @ 00022c38` (header 13225): `piVar4 = param_1` (the METHOD_BUFFERED SystemBuffer). The caller-controlled fields are the address `*(longlong *)(piVar4 + 4)` (SystemBuffer+0x10) and the length `uVar1 = piVar4[3]` (SystemBuffer+0x0C, line 13262). The operation flag is `piVar4[1] & 2` (line 13263 branch).
   - Line 13263: `_Dst = FUN_000232c0(*(longlong*)(piVar4+4), (ulonglong)uVar1, &local_res18, param_4)`.
   - `FUN_000232c0 @ 000232c0` (header 13557): rejects a zero address or zero length (line 13559-13563). `IoAllocateMdl(param_1, param_2, 0, 0, 0)` at line 13574 (param_1 = caller address, param_2 = caller length). `MmProbeAndLockPages(mdl, 0, 2)` (KernelMode, IoWriteAccess) follows. `MmMapLockedPagesSpecifyCache(mdl, 0, 1, 0, ...)` at line 13586 (AccessMode 0 = **KernelMode**, returns a system VA for the locked range). No user-range check is performed on the address before the lock.
   - Because the probe runs at KernelMode and no `ProbeForWrite` is called, a kernel-mode address is accepted as well as a user-mode address. Whether that is accepted in practice is an API-behaviour inference, not verified dynamically (section 8).
2. **Copy into the mapped range:** lines 13282 and 13286 `memcpy(_Dst, _Src, uVar5)` / `memcpy(_Dst, _Src, uVar2)`, with a second `memcpy(_Dst, s_abcdefghij_0002b110, uVar5-uVar2)` on the wrap branch (dump around line 13286-13290). `_Src` is `PTR_s_abcdefghij_000437b8`, a pointer into a **driver-resident fixed pattern** (strings `abcdefghij`). The value is therefore not device-supplied and not caller-supplied.
3. **Size:** `uVar5 = min(caller length uVar1, ring distance)` where the ring distance is computed from the pointer pair at `0x000437b0` / `0x000437b8` (line 13269-13278 region), with a 99999-byte wrap term. The write is bounded by the caller's length uVar1 (the MDL length), so it cannot exceed the mapped range. The bound is the caller's length, which the caller controls.
4. **Other mappings:** no `MmMapIoSpace`, `ZwMapViewOfSection` or `MmCopyMemory` in the image. The only mapping helper is `FUN_000232c0`.

Write classification:

- Target control: **arbitrary** (caller supplies the VA, no range validation before the KernelMode lock; the target can be a kernel address if the MDL path accepts it).
- Value control: **constrained** (a fixed driver pattern `abcdefghij`, not caller-chosen).
- Size control: **caller-bounded** (uVar1, clamped by ring distance; the write does not exceed the MDL).
- Overall: **W2**.

## 6 Most dangerous exposed capability

IOCTL 0x500024a4 (METHOD_BUFFERED, FILE_ANY_ACCESS, `FUN_0001f8a0` line 10856 -> `FUN_00022c38` line 13263 -> `FUN_000232c0` line 13586): a copy of a fixed pattern to a caller-chosen address, for a caller-chosen length, on a started device.

## 7 Verdict

- Provisional: **MW3** (R3 hardware, W2 constrained value with arbitrary target, setup hardware, signed). The primitive is a caller-addressed write of a fixed pattern into kernel or user memory. It needs the device started, so hardware presence is required.
- If the kernel path accepts kernel addresses (as the API inference above suggests), the target is arbitrary, and the value is a fixed driver pattern. A reviewer may argue for W1 with MW2. This report keeps W2/MW3 because the value is fixed.
- Status: partial (see section 8).

## 8 Limitations

- Behaviour of `MmProbeAndLockPages` / `IoAllocateMdl` with a kernel-mode address was inferred from API semantics, not verified. Dynamic verification was not performed (the driver was not loaded).
- Other IOCTL cases in `FUN_0001f8a0` (0x50002408 -> `FUN_0001f38c`, and the other 0x5000xxxx codes) were not traced. The lock callers at lines 4780 and 9099 were not traced.
- Device-interface DACL not resolved (IoRegisterDeviceInterface default; no SDDL in the image).
- The `0x220000` / `0x220004` / `0x220008` handlers (lines 1983-2006) were not traced.
- Static only.
