# Audit: ionenum64_F6C87E28.sys

| Field | Value |
|---|---|
| File | drivers\ionenum64_F6C87E28.sys |
| SHA-256 | F6C87E28A8C69B6F1E6B4F61231B79536E82D2B2160669933549E201A65E0549 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\ionenum64_F6C87E28.txt`, complete). IRP_MJ_DEVICE_CONTROL routine `FUN_140001DA0` (dump 841-886) and its registry-copy helper `FUN_140001350` (dump 215-254) read in full; device creation at dump 1931 and 1988. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Digi International; file version 6.04.001; "Serial Port Enumerator 64 bit" |
| Signature | NotSigned (no Authenticode signature) |
| Reach | R3 (devnode: the enumerator is loaded by PnP for a Digi serial enumeration device) |
| Setup required | devnode |
| Write quality | W0 |
| Severity | NO-MEMORY-WRITE |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 WDM serial port enumerator (Digi). Imports: `IoCreateDevice`, `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`, `IoOpenDeviceRegistryKey`, `ZwQueryValueKey`, `ZwSetValueKey`, `ExAllocatePoolWithTag`, `RtlInitUnicodeString`, `IoBuildDeviceIoControlRequest`, `PsCreateSystemThread`, `KeBugCheckEx`.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, ProbeForWrite, memcpy or memmove import.
- Dispatch: `FUN_140001DA0` is installed at IRP_MJ_DEVICE_CONTROL (`*(param_1+0xE0)`, dump 3091).

## 2 Entry / device / interface / effective DACL

- Device objects: `IoCreateDevice(..., ext 0x88, ...)` at dump 1931 (child PDO) and `IoCreateDevice(param_1, 0x108, 0, DeviceType 0x2A, 0, Exclusive 1, &device)` at dump 1988 (FDO, exclusive, unnamed).
- Interface: `IoRegisterDeviceInterface` (import). No symbolic link to a named device and no SDDL string in the image. No `ZwSetSecurityObject`. Effective DACL: default; the device is reached through the PnP interface.

## 3 Dispatch and IOCTL table

`FUN_140001DA0` (dump 841-886) decodes one IOCTL: `*(int*)(stack+0x18) == 0x37020C` (dump 864). Every other code goes to `FUN_140001B20` (dump 703-738) after the gate `FUN_140001BF0` (dump 739-794). If the device is not in the started state (`*(lVar1+8) == 0`, dump 855), the request is forwarded with `IofCallDriver` (858).

| IOCTL | Method | Access | Input | Output | Kernel action (dump lines) |
|---|---|---|---|---|---|
| 0x37020C | BUFFERED | ANY | none used | OutputBufferLength (`*(lVar2+8)`, 871) | Reads registry value `PortName`, or `Identifier` if the first query returns STATUS_OBJECT_NAME_NOT_FOUND or STATUS_BUFFER_TOO_SMALL (871-876). The value is copied into SystemBuffer by `FUN_140001350`, and Information is the value's length (877). |
| any other | - | - | as received | as received | Forwarded to the lower stack by `FUN_140001B20` after `FUN_140001BF0` (dump 884-885, 703-794). Forwarding path not read in full (section 8). |

Decoded code 0x37020C: DeviceType 0x37, function 0x083, METHOD_BUFFERED (low bits 0), FILE_ANY_ACCESS (bits 14-15 = 0).

## 4 Access-control audit

- No privilege or caller-identity check in the driver's IOCTL path. The gate is the started state (dump 855). Access is the device's default security and the PnP interface.

## 5 Memory-write trace

- **0x37020C copy (dump 871-877):** `FUN_140001350` queries the registry value into a pool buffer of `param_5 + 0x18 + param_3` bytes (229-230). It copies the value into the caller buffer only when the returned length `*(lVar2+0xC) <= param_5`, where `param_5` is the caller's OutputBufferLength (236-238). The copy destination is the SystemBuffer, and its length is bounded by the output length. Bounded.
- The registry data comes from the device's registry key (admin-writable, but not caller-controlled per request). The copy length is taken from the registry data and checked against the output length before the copy.
- No other kernel write is on the IOCTL path: `FUN_140001DA0` writes only the request's status and information (882, 877).

## 6 Most dangerous exposed capability

- None on the IOCTL path. The forwarded codes depend on the lower stack, which is outside this image.

## 7 Verdict

**NO-MEMORY-WRITE.** The only IOCTL handled in this image (0x37020C) copies a registry value bounded by the caller's output length. All other codes are forwarded. Reach R3 (devnode); Setup: devnode; W0. The image is unsigned, so it is not loadable on a normally configured system. HW-only: no.

## 8 Limitations

- The forwarding path `FUN_140001B20` and gate `FUN_140001BF0` were read only in outline; the lower stack's behavior is outside this image.
- The registry helper's copy routine `FUN_140002040` was not read; the bound is checked at the call site (dump 236-238).
- No REA session used. No execution, no driver load, no registry writes.
