# Audit: iaLPSS2i_GPIO2_GLK.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaLPSS2i_GPIO2_GLK.sys` |
| Recorded SHA-256 | `71FDC25244298D62A335769D6ED43394C33FBD8DB05AA54CA924A2977F37858F` (verified vs triage_index.csv, local Get-FileHash) |
| Company/Version | Intel Corporation 30.100.1820.1 - "Intel(R) Serial IO GPIO Driver v2" (GLK platform variant) |
| Method | Static-only. Abbreviated diff audit vs root `iaLPSS2i_GPIO2.sys` (audits/iaLPSS2i_GPIO2.md): full decompile of all 153 functions (local Ghidra 12.1.4 headless; REA bridge contended - see root report method note) + full string-set diff vs root (local dumps) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`.

## Diff vs root (iaLPSS2i_GPIO2.sys)

- **Identical:** all 28 external imports (no additions); no SDDL string, no device/DOS name, no interface-GUID string; single `MmMapIoSpaceEx` call from the translated PnP resource descriptor; zero MDL/probe/`Zw*`/`Se*`/`Ob*` APIs; pool allocs memset to exact size; no IOCTL dispatch in-file.
- **Differences (platform content only):** +24 functions (129->153) implementing `_GPIO_CONTROLLER_CNL_H::...`/`CNL_LP::...` classes reused for GLK; bank/community names (`GPP_U/V/K/J/R/S`, `NORTHWEST96`, `SOUTHWEST32`, `AUDIO0`, `SCC0`, `SCC32`); ACPI HWID set adds **`ACPI\INT3455` and `ACPI\INT3450`** (the GLK GPIO controller IDs); version 30.100.1820.1; own `.pdb` name.
- **Privileged instructions:** none - `0F 30`/`0F 20/22` 0 executable hits.

## Verdict + VM confirmation plan

**NO-WRITE** - same reasoning as the root report; the GLK delta is controller-class/bank-table/HWID content only.

VM plan: none warranted (see root report).

*End of report.*
