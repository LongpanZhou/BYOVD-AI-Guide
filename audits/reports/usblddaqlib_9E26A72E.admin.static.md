# Audit: usblddaqlib_9E26A72E.sys

| Field | Value |
|---|---|
| File | drivers\usblddaqlib_9E26A72E.sys |
| SHA-256 | 9E26A72E9C00DFE57FC5D47D467F73E13F08BD8A02D46F4BAC51C89EFFCFA4AD |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\usblddaqlib_9E26A72E.txt`, complete). IOCTL dispatcher read in full (dump 1915-1977); device creation at dump 108 and interface at dump 156; the copy helper `FUN_00014BA0` located at its call site (1948). Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Measurement Computing Corp.; file version 5.0.0 Build 11; "USB-2500 Loader Device Driver" |
| Signature | Authenticode Valid; signer CN=Measurement Computing Corporation |
| Reach | R3 (devnode / hardware: a USB-2500 device must be attached) |
| Setup required | hardware |
| Write quality | W0 (no caller-controlled kernel write found) |
| Severity | NO-MEMORY-WRITE |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 WDM USB loader (MCC USB-2500 firmware loader). Imports include `IoCreateDevice`, `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`, `IoBuildDeviceIoControlRequest`, `IofCallDriver`, `IoQueueWorkItem`, `KeWaitForSingleObject`, `RtlQueryRegistryValues`, `USBD_CreateConfigurationRequestEx`, `USBD_ParseConfigurationDescriptorEx`, `IoWMIRegistrationControl`, `WmiSystemControl`, `WmiCompleteRequest`.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, ProbeForWrite, IoAllocateMdl or MmProbeAndLockPages import. No `ZwSetSecurityObject`, no SDDL string.
- Dispatch: `*(param_1+0xE0) = FUN_00013878` (IRP_MJ_DEVICE_CONTROL, dump 67).

## 2 Entry / device / interface / effective DACL

- `IoCreateDevice(DriverObject, 0x250, 0, DeviceType 0x22, DeviceCharacteristics 0x80, Exclusive 0, &device)` at dump 108. The characteristics value 0x80 does not include FILE_DEVICE_SECURE_OPEN (0x100), so no per-open security check is applied to this device.
- `IoRegisterDeviceInterface(…, &DAT_000161B0, 0, …)` at dump 156. The GUID at DAT_000161B0 is not decoded in this pass.
- No SDDL or `ZwSetSecurityObject`. Effective DACL: IoCreateDevice default.

## 3 Dispatch and IOCTL table

`FUN_00013878` routes IRP_MJ_DEVICE_CONTROL to the handler at dump 1915-1977 (IOCTL in `iVar1 = *(int*)(stack+0x18)`, output length `uVar2 = *(uint*)(stack+8)`, SystemBuffer `puVar5 = *(IRP+0x18)`).

| IOCTL | Method | Access | Input | Output | Kernel action (dump lines) |
|---|---|---|---|---|---|
| 0x220000 | BUFFERED | ANY | none used | `OutputBufferLength` (uVar2) | Gate: device state must be 2 (1930-1935). Copies the driver's own loader buffer (`*(ext+0x70)`, length `*(ushort*)(buf+2)`) into the SystemBuffer via `FUN_00014BA0` only if that length is <= OutputBufferLength (1946-1949). Otherwise STATUS_BUFFER_TOO_SMALL (0xC0000023, constant -0x3FFFFFDD at 1951). |
| 0x220004 | BUFFERED | ANY | none | none | `FUN_00013A4C` (1955-1956). No caller buffer write. |
| 0x220008 | BUFFERED | ANY | none | none | Calls `FUN_000139C0` with the IRP parameter from the stack (1959-1964); returns the status. No caller buffer write in this function. |
| other | - | - | - | - | STATUS_INVALID_DEVICE_REQUEST (0xC0000010, constant -0x3FFFFFF0 at 1968). |

Codes are 0x22xxxx: METHOD_BUFFERED (low bits 0), FILE_ANY_ACCESS (bits 14-15 zero).

## 4 Access-control audit

- No privilege or caller-identity check in the handler. The gate is the started state (1930). Access is the device default (no FILE_DEVICE_SECURE_OPEN).

## 5 Memory-write trace

- The only buffer write on the IOCTL path is 0x220000: `FUN_00014BA0(SystemBuffer, loaderBuffer, len)` with `len <= OutputBufferLength` (1947-1948). The destination is the SystemBuffer (kernel pool, size `max(in, out)`), the source is the driver's own loader buffer; its length is from its own header, and the copy is bounded by the output length. Bounded.
- Other writes: the information field (`param_2+0x38`, 1972) and the status (1973).

## 6 Most dangerous exposed capability

- The 0x220000 copy of the loader buffer, bounded by the caller's output length. No kernel write primitive.

## 7 Verdict

**NO-MEMORY-WRITE.** The IOCTL surface is three codes, one bounded copy into the SystemBuffer, and no caller-chosen destination or length. Reach R3 (devnode / hardware); Setup: hardware; W0. The image is signed (Valid). HW-only: no.

## 8 Limitations

- `FUN_000139C0`, `FUN_00013A4C` and `FUN_00014BA0` were read at their call sites only. `FUN_00014BA0` takes its length from the caller-checked value at 1947.
- The GUID at DAT_000161B0 was not decoded.
- No REA session used. No execution, no driver load, no registry writes.
