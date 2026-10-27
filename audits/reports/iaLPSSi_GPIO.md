# Audit: iaLPSSi_GPIO.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaLPSSi_GPIO.sys` |
| Recorded SHA-256 | `F77696AE55B992154A3B35F7660BD73E0AB35A6ECEEC1931C0D35748CFA605C0` (verified vs triage_index.csv, local Get-FileHash) |
| Company/Version | Intel Corporation 1.1.250.0 - "Intel(R) Serial IO GPIO Controller Driver" (Gen1/LPT-LP+WPT-LP, Win8.1-era build; source path string `D:\qba2\workspace\1371\lpss\Drivers\iaLPSS_GPIO\1.1.250.0\Win81Release\x64\inbox\iaLPSSi_GPIO.pdb`) |
| Method | Static-only. Full decompile of all 57 functions (local Ghidra 12.1.4 headless; REA shared bridge contended by parallel agents A/B - see archived agent-D ledger in audits/_archive/agent_ledgers_2026-10-24.zip) + local string/import recon; every identity cross-checked by SHA-256 |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (`.text` 0x140001000-0x140003459, `.rdata`, `.data`, `PAGE` 0x140008000, `INIT` 0x140009000, `.rsrc` incl. authenticode blob).

## Entry surface

- KMDF class-extension client minidriver (GpioClx): `FxDriverEntryWorker` (0x140002c24) -> real DriverEntry; DeviceAdd = `FUN_140008000` (PAGE): `GPIO_CLX_ProcessAddDevicePreDeviceCreate` -> `WdfDeviceCreate` -> `GPIO_CLX_ProcessAddDevicePostDeviceCreate` -> ACPI HWID match (`FUN_140001000`: `ACPI\INT33C7` / `ACPI\INT3437`, two capped iterations, length-min'd `wcsncmp`) -> fixed characteristics/init calls.
- **No SDDL string, no `\Device\...` name, no `\DosDevices\`, no interface-GUID string** - unnamed FDO, no interface. GpioClx class binds via `WdfVersionBindClass` (extension `GPIOClx`).
- **Imports (complete, 14):** `IoWMIRegistrationControl`, `EtwRegister/Unregister/Write`, `RtlCompareMemory`, `RtlCopyUnicodeString`, `RtlVerifyVersionInfo`, `MmGetSystemRoutineAddress`, `RtlInitUnicodeString`, `WdfVersionBind/Unbind/BindClass/UnbindClass`. Dynamic-resolution targets: `PsGetVersion`, `WmiTraceMessage`, `WmiQueryTraceInformation`, `EtwRegisterClassicProvider`, `EtwUnregister` (all benign).
- Absent: any `Zw*`, `Se*`, `Ob*`, `ExAllocatePool*`, `Mm*` (no mapping API at all), MDL kit, DMA DDIs, `Hal*` port routines.

## Memory-write analysis

- **Register access = inline x86 IN/OUT port instructions** (Ghidra `in`/`out` pseudocode), e.g. `out(sVar6 + 0x100 + (short)*param_1, uVar8)`, `in(uVar2 * 4 + (short)*param_1)` - the port base `*param_1` is the PnP-assigned CM_RESOURCE_PORT base, validated by the "Incorrect IO Base address" / "Incorrect IO resources count" checks in PrepareHardware before any access. These are device-IO operations on the controller's IO window, not kernel-memory writes; the base/offsets come from PnP resources, not callers.
- Pin/bank-indexed accesses (`bank * 0x200 + ctx`, `pin * 0x10`/`pin * 8` strides) are driven by GpioClx-supplied parameters after per-pin validation (`FUN_1400018fc` compares stored per-pin mode before acting); context is the fixed 0x610-byte `GPIO_DRIVER_CONTEXT` (`memset(param_2,0,0x610)` on the object's own allocation in `FUN_140001aa0`).
- **No pool allocations, no copies from request buffers, no MDLs, no mapping APIs, no registry reads** in-file (the driver's registry parameter names seen in the INF-era strings are not referenced by decompiled code).
- **Privileged instructions:** byte-scan - `0F 30` (WRMSR) hits are all inside the embedded authenticode certificate blob (past `.reloc`, non-executable); `0F 01`/`0F 20`/`0F 22` = 0 executable hits.

## Memory-touching IOCTL table

None. Unnamed hardware FDO, no interface, no IOCTL dispatch in-file; GPIO IOCTLs are served by the Microsoft GpioClx class extension (out of file scope).

## Verdict + VM confirmation plan

**NO-WRITE.** Gen1 GpioClx client with inline port I/O on PnP-checked resources and bounded fixed-size context writes; no user-openable device object and no kernel-copy surface of any kind.

VM plan (orchestrator-owned, describe-only): none warranted - binds only to real PCH GPIO (ACPI INT33C7/INT3437); no control surface exists to open.

*End of report.*
