# Audit: usbdaqlib_E4056475.sys (kernel-VA write via caller-supplied buffer address; device must be started)

| Field | Value |
|---|---|
| File | drivers\usbdaqlib_E4056475.sys |
| SHA-256 | E4056475AF02B1399A5F90844511E9EAAC4118677F74747928F9762258DF7D2B (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\usbdaqlib_E4056475.txt`, 238 functions, 0 decompile failures, `=== DONE` at last line). REA not used. |
| Reach | R3 (Measurement Computing USB DAQ function driver; IOCTL accepted only when the device is started, dispatcher line 1973) |
| Setup required | hardware |
| Write quality | W2 (target = caller-supplied address, validated only by KernelMode MDL lock, so arbitrary; value = fixed driver pattern, so constrained) |
| Severity | MW3 (provisional: R3 hardware with W2, per SEVERITY matrix) |
| HW-only | no |

Identity (Get-AuthenticodeSignature / VersionInfo): Company Measurement Computing Corp.; FileVersion 5.0.3 Build 1; signature Valid (signer `CN=Measurement Computing Corporation`).

## 1 Internals

Same code as `usbdaqlib_58D0669F` (see that report). Function headers and call-site line numbers are identical in both dumps: DriverEntry `FUN_00011008` (67), AddDevice `FUN_00011148` (113), dispatcher `FUN_000138f8` (1949), `FUN_00022944` (13084), `FUN_0001f8a0` (10801), `FUN_00022c38` (13225), `FUN_000232c0` (13557). The IRP_MJ_DEVICE_CONTROL assignment is at line 86; PnP at line 88; CREATE at line 89.

## 2 Entry / device / interface / effective DACL

- `IoCreateDevice(param_1, 0x250, 0, 0x22, 0x80, 0, &dev)` at line 127 (`FUN_00011148`): **unnamed** device, Exclusive 0, no SDDL argument.
- `IoRegisterDeviceInterface(plVar2[2], &DAT_000295f0, 0, plVar2+3)` at line 175. Interface DACL is the default (no SDDL in the call or image).
- No `SeSinglePrivilegeCheck` / `SeAccessCheck` in the IOCTL path.

## 3 Dispatch and IOCTL table

Dispatcher `FUN_000138f8 @ 000138f8` (header 1949): IoControlCode at line 1969; started-state gate at line 1973 (`!= 2` -> `0xC0000184`); `0x220000` (line 1983), `0x220004` (line 2001), `0x220008` (line 2006), all other codes -> `FUN_00022944` (line 2008) -> `FUN_0001f8a0` (line 13146).

`FUN_0001f8a0 @ 0001f8a0` (header 10801). **Traced code:** `0x500024a4` (function 0x929, METHOD_BUFFERED, FILE_ANY_ACCESS): guard at line 10856, call `FUN_00022c38` at line 10857. Other codes (`0x50002408` -> `FUN_0001f38c` at line 10850, and the 0x5000xxxx cases from line 10834 onward) were not traced.

## 4 Access-control audit

- The only gates are the started-device check (line 1973) and the default device-interface DACL. METHOD_BUFFERED with FILE_ANY_ACCESS means no per-code check.

## 5 Memory-write trace

1. `FUN_00022c38 @ 00022c38` (header 13225): caller-controlled address `*(longlong*)(SystemBuffer+0x10)` and length `piVar4[3]` (SystemBuffer+0x0C, line 13262). Line 13263 calls `FUN_000232c0(address, length, &mdl, ...)`.
2. `FUN_000232c0 @ 000232c0` (header 13557): `IoAllocateMdl(address, length)` at line 13574; `MmProbeAndLockPages(mdl, 0, 2)` (KernelMode); `MmMapLockedPagesSpecifyCache(mdl, 0, 1, 0, ...)` at line 13586 (AccessMode 0 = KernelMode). No user-range check; no `ProbeForWrite` import.
3. Copy: `memcpy(_Dst, _Src, uVar5)` at line 13282 and `memcpy(_Dst, _Src, uVar2)` at line 13286 (plus the wrap-branch copy from `s_abcdefghij_0002b110`). `_Src` is `PTR_s_abcdefghij_000437b8`, a driver-resident fixed pattern (`abcdefghij`), so the value is driver-chosen.
4. Size: `uVar5 = min(uVar1, ring distance)`; the write is bounded by the caller-supplied length uVar1, which is also the MDL length.

Write classification: target arbitrary (caller VA, no range check); value constrained (fixed pattern); size caller-bounded. Overall **W2**.

## 6 Most dangerous exposed capability

IOCTL 0x500024a4 (METHOD_BUFFERED, FILE_ANY_ACCESS): copy of a fixed pattern to a caller-chosen address and length on a started device.

## 7 Verdict

- Provisional: **MW3** (R3 hardware, W2, setup hardware, signed). Same reasoning as `usbdaqlib_58D0669F`.
- Status: partial.

## 8 Limitations

- KernelMode `MmProbeAndLockPages` / `IoAllocateMdl` behaviour with kernel addresses inferred from API semantics; not dynamically verified (not loaded).
- Other IOCTL cases (`0x50002408`, and the 0x5000xxxx codes from line 10834) and the lock callers at lines 4780 and 9099 not traced.
- Device-interface DACL not resolved.
- Static only.
