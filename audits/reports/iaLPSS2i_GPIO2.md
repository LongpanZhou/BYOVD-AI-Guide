# Audit: iaLPSS2i_GPIO2.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaLPSS2i_GPIO2.sys` |
| Recorded SHA-256 | `6FF5D13EF69E8FBCB4772C7B5C4D5770C78E0B29F9164FA1611EFDE91CE876BE` (verified vs triage_index.csv, REA `open_binary` + local Get-FileHash) |
| Company/Version | Intel Corporation 30.100.1816.3 - "Intel(R) Serial IO GPIO Driver v2" |
| Method | Static-only. Full decompile of all 129 functions via **local Ghidra 12.1.4 headless** (REA shared bridge unusable this round: repeated binding theft by parallel agents A/B, fresh-import starvation; every identity cross-checked by SHA-256). String/import recon cross-checked against REA `open_binary` identity + local string dumps. |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (segments: `.text` 0x140001000-0x14000B7FF, `.rdata` 0x14000C000-0x14000D7FF, `.data` 0x14000E000-0x14000E48F, `.pdata`, `PAGE` 0x140010000, `INIT` 0x140011000, `.rsrc`, `.reloc`, `tdb` 0xFF00000000).

## Entry surface

- KMDF class-extension client minidriver (GpioClx): `FxDriverEntryWorker` (`FUN_140001000`) -> real DriverEntry through the KMDF bind pointer `DAT_14000e470` (populated by `WdfVersionBind`, class bind `WdfVersionBindClass` with extension name `GPIOClx`).
- Per driver's own ETW log strings: DriverEntry = `WdfDriverCreate` + `GPIO_CLX_RegisterClient`; DeviceAdd = `GPIO_CLX_ProcessAddDevicePreDeviceCreate` -> `WdfDeviceCreate` -> `GPIO_CLX_ProcessAddDevicePostDeviceCreate`. **No control device, no device interface.**
- **No SDDL string anywhere in the image** (no `D:P`, no `A;;` text), **no device-name string** (`\Device\...` absent), **no `\DosDevices\`, no symbolic-link string, no `{...}` interface-GUID string** - the FDO is created unnamed via `WdfDeviceCreate` and the minidriver registers no interface. Its only "names" are ACPI HWIDs used for hardware-profile detection: `ACPI\INT345D`, `ACPI\INT34BB`, `ACPI\INT3451`, `ACPI\INT34D1`, `ACPI\INT3452`, `ACPI\INT3453` (BXT-P-family GPIO controllers, `FUN_140001cd0`).
- **Imports (complete):** `EtwRegister/Unregister/ActivityIdControl/EtwWrite`, `wcsnlen`, `wcsncmp`, `_purecall`, `ExAllocatePoolWithTag`, `IoWMIRegistrationControl`, `memcpy_s`, `DbgPrintEx`, `KeLowerIrql/KfRaiseIrql/KeAcquireSpinLockAtDpcLevel/KeReleaseSpinLockFromDpcLevel`, `MmUnmapIoSpace`, `MmMapIoSpaceEx`, `KeInitializeSpinLock`, `RtlCopyUnicodeString`, `RtlCompareMemory`, `MmGetSystemRoutineAddress`, `ExFreePoolWithTag`, `RtlInitUnicodeString`, `WdfVersionBind/Unbind/BindClass/UnbindClass`. Dynamic-resolution targets (via `MmGetSystemRoutineAddress`): only `PsGetVersion`, `WmiTraceMessage`, `WmiQueryTraceInformation`, `EtwRegisterClassicProvider`, `EtwUnregister` - all benign WMI/ETW.
- Absent: any `Zw*`, `Se*`, `Ob*`, `IoCreateDevice*`, `MmProbeAndLockPages`, `MmMapLockedPages*`, `ZwOpenSection`, `MmCopyMemory`, `Hal*`, DMA/MDL kit, `Cm*`.

## Memory-write analysis

All I/O flows through GpioClx client callbacks (kernel-internal, invoked by the Microsoft GPIO class extension on PnP/IOCTL events; GpioClx validates connection/pin descriptors before the client sees them):

- `FUN_140005cd0` (PrepareController): single `MmMapIoSpaceEx(*(pcVar8+4), *(pcVar8+0xc), 0x204)` - physical address and length are read straight out of the translated PnP resource descriptor (`CmPartialResource`), protection `PAGE_READWRITE|MmNonCached`. The physical addresses are firmware/PnP-supplied MBARs (`PrepareController MBAR%1 mapped: PA:%2 LEN:%3 VA:%4`), not caller-influenced. Unmapping in ReleaseHardware uses the stored context length.
- `FUN_140002cf0` (GpioPrepareController client callback): allocates per-generation controller objects from a fixed switch on the detected profile - `ExAllocatePoolWithTag(0x200 /*NonPagedPoolNx*/, 0x170/0x1b0/0xc0/0xa0/0x80, 'IGPI')` each immediately `memset` to **exactly** the allocated size; vtable-driven C++ controller classes (`_GPIO_CONTROLLER_CHASSIS3`).
- `FUN_1400040e0` (`CHASSIS3::GpioConnectIoPins`): per-pin loop bounded by GpioClx-supplied `PinCount`; every pin number is validated each iteration via `FUN_140007b30` (GpioValidatePinNumber) before the indexed write into the pin-context array (`+0x18`-stride) and the MMIO pad-config RMW (`*puVar13`/`puVar13[1]`). Writes are register RMWs and bounded context stores only.
- `FUN_14000511c`: the only `memcpy_s` in-file - fixed `0x10`-byte copy from a constant (`&DAT_14000c698`), destination inside a freshly allocated/fixed context. Bounded.
- Registry: the parameter names seen in the binary (`iaLPSS2_GPIO2_HwInstance/HwMode/HwRevision/HwVersion/InterruptMode/InterruptPolarity/IoMode/PinMode/PinOwnership/PullMode`) are **not referenced by any decompiled code** (no `RtlQuery*`, no registry-DDI call site found); hardware profile comes from ACPI HWID matching into fixed fields (`FUN_140001a80`/`FUN_140001cd0`). HKLM-device Parameters would be admin-writable anyway.
- Privileged instructions: byte-scan of the whole file for `0F 30` (WRMSR), `0F 20/22` (MOV CR) = **0 executable hits**; all `0F 01` hits are in `.rsrc` (WEVT_TEMPLATE) - none in code. No GDT/IDT/MSR touch.

## Memory-touching IOCTL table

None. The minidriver creates no dispatch surface: no named device, no interface, no queue with `EvtIo*` control codes is registered in-file; all IOCTL handling for GPIO belongs to the Microsoft GpioClx class extension (out of this file's scope, kernel-side).

## Verdict + VM confirmation plan

**NO-WRITE.** A GpioClx client minidriver with no user-openable device object: unnamed FDO (hardware-enumerated only), no device interface, no SDDL string, no IOCTL dispatcher in-file, no MDL/mapping/physmem primitives beyond `MmMapIoSpaceEx` on PnP-supplied BARs, no privileged instructions. There is no unprivileged-reachable kernel write path.

VM plan (orchestrator-owned, describe-only): none warranted - the driver only binds to real LPSS GPIO hardware (ACPI INT345D/34BB/3451/34D1/3452/3453); a stand-in devnode cannot exercise GpioClx callbacks, and no control surface exists to open.

*End of report.*
