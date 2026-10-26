# Audit: mccfwld_2824AC5B.sys

| Field | Value |
|---|---|
| File | drivers\mccfwld_2824AC5B.sys |
| SHA-256 | 2824AC5B44CD526A718D4C54909C52F706B91A2940F7804FAD5BB05AACC55E21 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\mccfwld_2824AC5B.txt`, complete, 12 functions of substance). Import triage (no mapping, no copy primitive imported), grep for IOCTL case labels (none), read of the device-init and firmware-select path `FUN_0003C74C` (dump 585-734). Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Measurement Computing Corporation.; file version 1.0.6.0; product version 6.74.0.0; "MCC Firmware Loader" |
| Signature | Authenticode Valid; signer CN=Measurement Computing Corporation |
| Reach | R3 (devnode / hardware: an MCC USB device must be present; the driver is bound to it by PnP) |
| Setup required | hardware |
| Write quality | W0 (no caller-controlled kernel write; no user IOCTL path found) |
| Severity | NO-MEMORY-WRITE |
| HW-only | no (the writes it performs are USB firmware writes to the attached device, which are not HW-ONLY memory writes; no MSR, port, PCI, SMBus, EC or MMIO) |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 KMDF firmware loader (WDFLDR imports: `WdfVersionBind`, `WdfVersionUnbind`). Imports: `RtlCopyUnicodeString`, `RtlCompareMemory`, `KeBugCheckEx`, `KeTickCount`, `memset`. No IoControl path imports, no `IoCreateDevice`, no mapping API, no `memcpy`/`memmove`.
- The dump has about a dozen real functions (`FUN_00011014` ... `FUN_0003d008`); the firmware images are static data (`DAT_00013170`, `DAT_00016FF0`, `DAT_00019C30`, `DAT_0001D5A0`, `DAT_00021230`, `DAT_00035470` and others) selected by device identity.

## 2 Entry / device / interface / effective DACL

- No `IoCreateDevice`, no `IoCreateSymbolicLink`, no `ZwSetSecurityObject` and no SDDL string in the image. The device is created by WDF (default security); the firmware loader binds to the MCC device through PnP.

## 3 Dispatch and IOCTL table

- No IOCTL case labels: grep for `== 0x22xxxx` and `== 0x2xxxxx` in the dump returns none. No `EvtIoDeviceControl`-style switch is present in the decompile. The request surface for user-mode is therefore absent in this image.
- Work is done in the device-init path. `FUN_0003C74C` (dump 587-734) reads the device's vendor and product identifiers (`*(short*)(lVar1+0x10) == 0x1809`, 623; comparisons with `0x70A4`, `0x70A7`, `0x71C3`, `0x730C`, `0x741E`, `0x7441`, 624-653), selects one of the static firmware blobs, and downloads it to the device through vendor requests (`FUN_0003C5A4` / `FUN_0003C678` helpers, 618, 621).

| Code | Method | Access | Input | Output | Kernel action |
|---|---|---|---|---|---|
| none defined | - | - | - | - | No user IOCTL dispatch in the decompile. |

## 4 Access-control audit

- No privilege or caller-identity check in the driver (none needed: there is no user request path). Firmware is written only from PnP-driven device-init.

## 5 Memory-write trace

- Kernel writes in `FUN_0003C74C` and its helpers go to driver-owned local buffers (`local_238[64]`, `local_258`, `local_254`) and to the USB device (vendor requests). The source firmware blob is static driver data; its length is a constant per blob.
- The helpers `FUN_0003C014`, `FUN_0003C1E0` (729 bytes), `FUN_0003C4C0`, `FUN_0003C5A4`, `FUN_0003C678`, `FUN_0003C74C` and `FUN_0003D008` write only to driver-owned memory and to the device (USB), with constant sizes or sizes taken from the static blob table.
- No write uses a caller-supplied destination or length, because no caller-supplied buffer reaches the driver.

## 6 Most dangerous exposed capability

- None: no user-reachable request path. The device-side firmware write is driven by the device identity read from the attached MCC hardware.

## 7 Verdict

**NO-MEMORY-WRITE.** No IOCTL dispatch and no caller-controlled write in the image. Reach R3 (devnode / hardware); Setup: hardware; W0. The image is signed (Valid). HW-only: no (USB firmware download is not a memory write).

## 8 Limitations

- The helper functions with constant sizes were read at their call sites; the USB vendor-request helpers were not read in full, but they receive no caller-supplied buffers.
- No REA session used. No execution, no driver load, no registry writes.
