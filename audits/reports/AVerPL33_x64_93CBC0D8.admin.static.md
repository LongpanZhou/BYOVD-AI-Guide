# Audit: AVerPL33_x64_93CBC0D8.sys

| Field | Value |
|---|---|
| File | drivers\AVerPL33_x64_93CBC0D8.sys |
| SHA-256 | 93CBC0D80BBB1742EBC94BCF20122C0CC4745ABC7A9DDDC9A5F0ABEDD1F6D433 (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\AVerPL33_x64_93CBC0D8.txt`, 2068 functions, `=== DONE` at last line). REA not used. |
| Reach | R3 (PnP-enumerated AVerMedia PCIe capture hardware; the KS device is created only when the device is present) |
| Setup required | hardware |
| Write quality | W0 (no kernel memory write reachable from caller input) |
| Severity | NO-MEMORY-WRITE |
| HW-only | yes (device BAR MMIO and I2C/GPIO register access only; no kernel write found) |

Identity (Get-AuthenticodeSignature / VersionInfo): Company AVerMedia TECHNOLOGIES, Inc.; FileVersion 3.3.64.52; signature status NotSigned. Load status: unsigned, so it is not loadable under HVCI as shipped. This is recorded as `load=unsigned`; it does not change the verdict because no memory write was found.

## 1 Internals

- PE entry is `DriverEntry` = `FUN_00010f20 @ 00010f20` (dump line 605). It logs `DriverEntry()` and calls `KsInitializeDriver(param_1, param_2, &PTR_PTR_00113a00)` at line 611. The driver is a KS (kernel streaming) capture driver. Its imports include `KS.SYS::KsInitializeDriver`, `KsRegisterFilterWithNoKSPins`, `KsGetDevice`, `KsAcquireDevice` (EXT list, dump lines 3-107).
- Imports relevant to memory: `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `IoAllocateMdl`, `MmProbeAndLockPages`, `MmUnmapIoSpace`, `MmUnlockPages`, `IoFreeMdl` (EXT list, dump lines 3-107). No `MmCopyMemory`, `RtlCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, or `ProbeForWrite` import.
- Class names from strings (`strings_c1\AVerPL33_x64_93CBC0D8.strings.txt`): `CDevice`, `CDecoderFilter`, `CEncoderFilter`, `CCaptureFilter`, `CMpegInPin`, `CYUVInPin`, `CVirtualPin`, `CPCIeCntl`, `CUsbInterface`, plus per-chip video/audio decoder classes.

## 2 Entry / device / interface / effective DACL

- No `IoCreateDevice`, `IoCreateDeviceSecure` or `WdfDeviceCreate` import. The device object is created by KS.SYS on the driver's behalf after `KsInitializeDriver`.
- Device interface: `IoRegisterDeviceInterface(param_2, param_3, local_30, local_40)` at dump line 3104, inside `FUN_000164e0 @ 000164e0` (header line 3080). Its callers are `FUN_00038500` (lines 20030-20050) and `FUN_0004a8e0` / `FUN_0004e920` (lines 28209-30010). `IoRegisterDeviceInterface` takes no security-descriptor argument.
- Effective DACL: no SDDL string is present in the image. The only SDDL-shaped string is `D:P(A;;GA;;;SY)(A;;GA;;;BA)` in `EL_Display_vhidbus`, not here. The DACL of the KS device object is therefore the KS.SYS/PnP default and is not set in this driver. The DACL was not resolved from driver code, so this is recorded as a limitation (section 8).
- Symbolic link and device name: not created in this driver; KS assigns the interface.

## 3 Dispatch and IOCTL table

- Driver-owned `IRP_MJ_DEVICE_CONTROL` dispatcher: not located in the dump. The `CDevice::dispatch*` strings (`dispatchCreate`, `dispatchPnpStart`, `dispatchPnpStop`, `dispatchRemove`, `dispatchSurpriseRemoval`, `dispatchQueryPower`, `dispatchSetPower`) and `CCaptureFilter::dispatchCreate` etc. are the PnP and KS filter entry points. User-mode requests reach driver code through KS pin/filter/property callbacks, which KS.SYS routes.
- Only IOCTL-shaped constant in the dump: `0x220003` at lines 71484 (`FUN_000b4860 @ 000b4860`, header 71426) and 71719 (`FUN_000b5010 @ 000b5010`, header 71645). Both are `IOCTL_INTERNAL_USB_SUBMIT_URB` built on the USB PDO (`IofCallDriver(*puVar1, lVar7)`). This is internal to the driver and not user-reachable.
- IOCTL table: not enumerated. The KS property/method sets (descriptor `PTR_PTR_00113a00`, referenced at line 611) were not decoded. Every KS-routed request is therefore unenumerated (section 8).

## 4 Access-control audit

- No `SeSinglePrivilegeCheck`, `SeAccessCheck` or caller-identity check was found in the import list. Access is governed by KS and the device interface DACL (section 2).
- Reach is gated by hardware: `PciValidateConfig` rejects unknown VendorID/DeviceID (string at dump 0x001169c0; code in `PciStartDevice` path). Without the card there is no BAR mapping and no device object.

## 5 Memory-write trace

Each mapping and copy site was traced to its source of address and length.

1. **BAR mapping (fixed/PnP):** `MmMapIoSpace(*(undefined8 *)(puVar3 + 6))` at line 74901 in `FUN_000bc0d0 @ 000bc0d0` (header 74832, `PciStartDevice`). The address comes from the PnP `CmResourceTypeMemory` list (line 74895 message). The caller does not supply it. This is a fixed-window MMIO mapping, so it is HW-only.
2. **Caller buffer mapping (user pages):** `FUN_00010390 @ 00010390` (lines 108-150) calls `IoAllocateMdl` (126), `MmProbeAndLockPages` (133) and `MmMapLockedPagesSpecifyCache` (136, `KernelMode`, `MmCached`). Its inputs are the caller's buffer VA and length. It is called from `FUN_00026a20` (line 10831, header 10810), `FUN_00026bc0` (10879, header 10852), `FUN_00026d70` (10921, header 10900) and `FUN_00026f10` (10969, header 10942). The kernel VA refers to pages the caller already owns (locked user pages). The driver does not write to an address the caller chooses; the device DMAs into the buffer.
3. **PED DMA buffer allocation:** `FUN_000b9dd0 @ 000b9dd0` (header 73901, `PedDmaBufferAlloc`). `IoAllocateMdl(*param_2, *(param_2+1), 0, 1, 0)` at 73958 and `MmProbeAndLockPages(lVar2, 0)` at 73968. The MDL is on a caller buffer. Callers: `FUN_000b62b0` (line 72325, header 72292) and `FUN_000b6520` (line 72424, header 72391).
4. **DMA control block:** `FUN_000ba4a0 @ 000ba4a0` (header 74104) calls `IoAllocateMdl(param_4, 0x10, 0, 1, 0)` at 74157 and `MmProbeAndLockPages` at 74165. The buffer is 16 bytes. Caller: `FUN_000b8c60` (line 73799, header 73579).
5. **DMA completion record:** `FUN_000ba7f0 @ 000ba7f0` (header 74220, `PedDmaComplete`). `MmMapLockedPagesSpecifyCache` at 74297 maps the caller's locked buffer. The loop at 74313-74318 writes 16 bytes of driver-generated status (`local_50`, dump 74290 log string) into it. Size is fixed (0x10). The value is driver/device state, not caller input. The destination is caller-owned locked memory, not a kernel address. Caller: `FUN_000bad00 @ 000bad00` (header 74355, line 74368).

Write classification:

- Target control: none. Kernel VA targets are fixed or driver-owned. The only caller-supplied buffers are the caller's own locked pages (items 2, 3, 4, 5).
- Value control: driver/device-generated (item 5). No caller-chosen value reaches a kernel write.
- Size control: fixed (16 bytes) or device-determined (items 2, 3).
- Kernel write: none found. Writes into caller-locked pages (item 5) are user-buffer writes, not kernel memory writes.

## 6 Most dangerous exposed capability

The largest exposure is hardware-level register access through the BAR mapping (`FUN_000bc0d0`, line 74901) and I2C/GPIO helpers (`CDevice::SetGPIO`, `ReadI2C`, `WriteI2C` strings), which only touch device registers. These are HW-only. No kernel memory write from caller input was found.

## 7 Verdict

- Severity: **NO-MEMORY-WRITE** (HW-only). Reach R3 (AVerMedia PCIe capture hardware), setup `hardware`, write quality W0, load unsigned.
- Rationale: the only `MmMapIoSpace` target is PnP-assigned BAR memory (line 74901), and the `MmMapLockedPagesSpecifyCache` / `IoAllocateMdl` uses map caller-owned locked pages or driver-owned DMA buffers (items 2-5). No caller-controlled kernel address, length or value reaches a kernel write.
- Caveat: the KS property and IOCTL tables were not decoded, so a KS property handler that writes a caller-chosen register in the BAR is not excluded. That would still be HW-only (register write in fixed-window MMIO). A caller-controlled kernel pointer write is not indicated by the analysed sites.

## 8 Limitations

- KS property/method/event descriptors (`PTR_PTR_00113a00`, dump line 611) were not decoded, so the IOCTL table and per-property input validation are unenumerated.
- Driver-owned `MajorFunction` assignments were not traced; KS.SYS owns the IRP routing.
- Effective device DACL is not set by this driver (KS.SYS default). Not resolved beyond that.
- Device-side DMA semantics (what the hardware writes into locked pages) are not modelled.
- No dynamic analysis; the driver is unsigned and was not loaded.
- Decompilation is from Ghidra 12.1.4 headless with analysis timeout 900 s; the dump includes 2068 functions.
