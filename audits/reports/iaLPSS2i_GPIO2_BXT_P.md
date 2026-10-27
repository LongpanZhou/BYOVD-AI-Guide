# Audit: iaLPSS2i_GPIO2_BXT_P.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaLPSS2i_GPIO2_BXT_P.sys` |
| Recorded SHA-256 | `2141DE558461B592D4111A0388D1AAC8062FA72CD1E2A2D2D68279A9633288E9` (verified vs triage_index.csv, local Get-FileHash) |
| Company/Version | Intel Corporation 30.100.1816.1 - "Intel(R) Serial IO GPIO Driver v2" (BXT-P platform variant) |
| Method | Static-only. Abbreviated diff audit vs root `iaLPSS2i_GPIO2.sys` (audits/iaLPSS2i_GPIO2.md): full decompile of all 150 functions (local Ghidra 12.1.4 headless; REA bridge contended - see root report method note) + full string-set diff vs root (local dumps) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`.

## Diff vs root (iaLPSS2i_GPIO2.sys)

- **Identical:** all 28 external imports except one benign addition `_vsnwprintf` (log formatting); no SDDL string, no `\Device\...`/`\DosDevices\` name, no `{...}` interface-GUID string; single `MmMapIoSpaceEx` call fed from the translated PnP resource descriptor; zero MDL/`MmProbeAndLock*`/`Zw*`/`Se*`/`Ob*` APIs; pool allocations `ExAllocatePoolWithTag('IGPI')` memset to exactly the allocated size; no `EvtIo*`/IOCTL dispatch in-file.
- **Differences (platform content only):** +21 functions (129->150) implementing the additional `_GPIO_CONTROLLER_CNL_LP::...` controller class methods the BXT-P profile reuses; extra GPIO community/bank name strings (`GPP_V`, `SOUTHWEST32`, `AUDIO0`, `SCC0`, `SCC32`), `ReadRegistryKeyForController`/`SetDefaultParameter` helper names, `PinMux` trace label, ACPI HWID set adds `ACPI\INT344B` to the root set (INT345D/34BB/3451/34D1/3452/3453); version 30.100.1816.1; own `.pdb` name.
- **Privileged instructions:** none - `0F 30`/`0F 20/22` 0 executable hits (same scan method as root).

## Verdict + VM confirmation plan

**NO-WRITE** - same reasoning as the root report: unnamed, interface-less GpioClx client FDO, no IOCTL dispatcher in-file, `MmMapIoSpaceEx` only on PnP BARs, all client callbacks GpioClx-validated. BXT-P adds only controller-class/bank-table content.

VM plan: none warranted (see root report).

*End of report.*
