# Audit: MOZAUSBDriver_8AAC3D7C.sys

| Field | Value |
|---|---|
| File | drivers\MOZAUSBDriver_8AAC3D7C.sys |
| SHA-256 | 8AAC3D7CB51B42D101B7A32D0DC903E4C580B4440466ADC4081E502B497C9D6C |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\MOZAUSBDriver_8AAC3D7C.txt`, decompile complete, 41+ functions); PE import/string triage; Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | MOZA Racing Team; "v1.0.0.0 Commit: (x64)"; description "MOZA USB Driver" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher. The image also carries "#WDKTestCert moza" strings (earlier test-signature attributes). |
| Reach | R3 (devnode / hardware: the driver is loaded by PnP for a MOZA USB device) |
| Setup required | hardware |
| Write quality | W0 (no kernel memory write reachable from IOCTLs; the only local handler writes a fixed 4 bytes to a WDF-validated buffer) |
| Severity | NO-MEMORY-WRITE |
| HW-only | no (no MSR, port I/O, PCI config, SMBus/EC or MMIO) |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64, KMDF driver (WDFLDR imports: WdfVersionBind/Unbind/BindClass/UnbindClass, WdfLdrQueryInterface). WDF calls go through the WdfFunctions table (`DAT_140004318`) and a dispatch thunk (`PTR__guard_dispatch_icall_140003058`, `DAT_140004320` = WDF driver globals). No WDM IoCreateDevice import.
- ntoskrnl imports: RtlCopyUnicodeString, KeDelayExecutionThread, DbgPrintEx. No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, MmGetSystemRoutineAddress, RtlCopyMemory or ProbeForWrite.
- Entry: `FUN_140007000` (dump 1102-1120) and `FUN_14000187C` (dump 380-428) register the WDF driver object. EvtDriverDeviceAdd = `FUN_1400062A0` (dump 1067-1072), which calls `FUN_140006000`.

## 2 Entry / device / interface / effective DACL

- `FUN_140006000` (EvtDriverDeviceAdd body, dump 964-1062):
  - PnP/power callbacks struct (0x90 bytes, zeroed by `FUN_140001E40`, dump 1005) registered at 1006-1008; one callback is `FUN_140001000` (dump 1006).
  - WdfDeviceCreate (dump 1016-1017) with a 0x38-byte attributes block (1012). The device is created with no WdfDeviceInitAssignSDDLString and no named device. No SDDL and no `\Device\` or `\DosDevices\` string appears in the image (triage: only "MOZA USB Driver" and related text).
  - Device interface: call at dump 1024 with GUID at VA 0x1400030D0 = `{B040EED8-6579-4B34-8376-ABF03CAAA913}` (file offset 0x16D0). Device interface registration is performed by WDF; the symlink ACL is set by PnP / WDF default and is not expressed in the image.
  - Default I/O queue created via `FUN_1400062B4` (dump 1077-1098): a 0x60-byte WDF_IO_QUEUE_CONFIG with DispatchType=2 (parallel, dump 1091), default queue set (1093), **EvtIoDeviceControl = `FUN_1400014A0`** (dump 1096), **EvtIoInternalDeviceControl = `FUN_140001180`** (dump 1094), queue created via dump 1097.
  - A second queue is created at dump 1040-1041 and 1053-1054 with callbacks `FUN_140001090` (dump 42-54) and `FUN_140001100` (dump 59-71). Both only use WDF object handles (`WdfObjectGet...` / close paths).
- `FUN_140001000` (dump 13-35): opens the WDF I/O target that the device forwards to (stores it at context+8). This target is the lower device object of the stack.
- Effective DACL: WDF default device security. The image sets no descriptor. Any principal that can open the interface symlink can reach the IOCTL queue; access is therefore hardware-gated (R3), not admin-gated by the driver.

## 3 Dispatch and IOCTL table

Dispatch: `FUN_1400014A0` (dump 154-205) is EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL (Queue, Request, OutputBufferLength, InputBufferLength, IoControlCode). Codes are BUFFERED (low two bits 0) with FILE_ANY_ACCESS (bits 14-15 = 0) for 0x222008.

| IOCTL | Method | Access | Input min | Output min | Kernel action |
|---|---|---|---|---|---|
| 0x222008 | BUFFERED | ANY | not used | 4 (WdfRequestRetrieveOutputBuffer min size 4, dump 182) | If OutputBufferLength == 0: STATUS_INVALID_PARAMETER (177-180). Otherwise writes {01 00 00 00} to the 4-byte output buffer (184-187) and WdfRequestSetInformation(4) (188). If retrieval fails the request falls through to the forward path below. |
| all other codes | forwarded | as received | as received | as received | No local handling. Requests are forwarded unchanged to the WDF I/O target via WdfRequestSend (dump 193-197, options block 194-195). |

Internal device control (`FUN_140001180`, dump 74-152) is for IRP_MJ_INTERNAL_DEVICE_CONTROL only, which user-mode cannot issue. It checks URB function 0x1E (dump 97) and writes only to driver URB-tracking context (100-101).

## 4 Access-control audit

- No `SeAccessCheck`, `SeSinglePrivilegeCheck` or caller-identity check in the driver.
- Gates: device creation through PnP only; WDF request validation (`WdfRequestRetrieveOutputBuffer` min size 4).
- Non-0x222008 requests are passed to the lower target, so their effect is governed by the lower driver, which is outside this image. See §8.

## 5 Memory-write trace

Every dereference write in the dump was checked (grep `*(...) =` and array writes across the file). Results:

1. IOCTL 0x222008 (dump 184-188): four byte writes to `local_28`, the WDF-validated output buffer (min size 4). Bounded and fixed-value.
2. Lines 100-101 and 138-139 are in the internal control path (`FUN_140001180` and `FUN_140001370`). They write URB-tracking context fields (context+0x18/+0x20). User-mode cannot reach them.
3. Lines 478, 1027 are in driver initialisation (`FUN_140001A0C`, `FUN_140006000`) and write WDF context fields.
4. Lines 728-736 and 795 are inside `FUN_140001E40`, a memset helper (`value` argument = 0). Its only callers pass stack structures with fixed sizes (0x90 at dump 1005, 0x60 at dump 1089).
5. Forwarded requests carry caller buffers unchanged to the lower target; this driver performs no copy into them.

Conclusion: no write in this driver uses a caller-supplied destination pointer, offset, length or value. No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection` or `MmGetPhysicalAddress` exists in the imports, and no computed-VA write was found.

## 6 Most dangerous exposed capability

The forward-all behaviour: arbitrary IOCTL codes sent to this device are passed to the lower WDF I/O target. Any kernel write from that path would belong to the lower driver, not to this image. Within this image the only handled code writes a fixed 4-byte value.

## 7 Verdict

**NO-MEMORY-WRITE.** Reach R3 (devnode/hardware); Setup required: hardware; Write quality W0; load: Authenticode Valid (WHQL-chain signer). HW-only: no.

## 8 Limitations

- The lower target (the device stack below this FDO, opened in `FUN_140001000`) is not analysed. Forwarded IOCTLs reach it unchanged, so its IOCTL surface is outside this audit.
- WDF function-table indices are not named in the dump (no WDF symbols). Callback assignments are taken from the struct fields written before each WdfIoQueueCreate / WdfDeviceCreate call (dump 1005-1098).
- Dump line 191 calls the failure path with a single argument (a decompiler artefact); it does not change the write analysis.
- No REA session used. No execution, no driver load, no registry writes.
