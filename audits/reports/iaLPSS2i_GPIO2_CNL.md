# Audit: iaLPSS2i_GPIO2_CNL.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaLPSS2i_GPIO2_CNL.sys` |
| Recorded SHA-256 | `E353D90D0B79A70F976FD5EA1CB7E25A97835E25116962EA035424715B2F43FE` (verified vs triage_index.csv, local Get-FileHash) |
| Company/Version | Intel Corporation 30.100.1816.3 — "Intel(R) Serial IO GPIO Driver v2" (CNL platform variant) |
| Method | Static-only. Abbreviated diff audit vs root `iaLPSS2i_GPIO2.sys` (audits/iaLPSS2i_GPIO2.md): full decompile of all 177 functions (local Ghidra 12.1.4 headless; REA bridge contended — see root report method note) + full string-set diff vs root (local dumps) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`.

## Diff vs root (iaLPSS2i_GPIO2.sys)

- **Identical:** all 28 external imports except benign addition `_vsnwprintf` (log formatting); no SDDL string, no device/DOS name, no interface-GUID string; single `MmMapIoSpaceEx` call from the translated PnP resource descriptor; zero MDL/probe/`Zw*`/`Se*`/`Ob*` APIs; pool allocs memset to exact size; no IOCTL dispatch in-file.
- **Differences (platform content only):** +48 functions (129→177) implementing the **CNL-H and CNL-LP controller classes**; large bank-name tables (`GPP_U`, `GPP_V`, `GPP_K`, `GPP_J`, `GPP_R`, `GPP_S`, `GPP_V0–V4`, `SOUTHWEST32`, …) reflecting the CNL PCH GPIO communities; ACPI HWID set extends the root set (adds `ACPI\INT3455` + further CNL IDs — 13 HWID strings total); same version 30.100.1816.3 as root; own `.pdb` name.
- **Privileged instructions:** none — `0F 30`/`0F 20/22` 0 executable hits.

## Verdict + VM confirmation plan

**NO-WRITE** — same reasoning as the root report; the CNL delta is controller-class/bank-table content only.

VM plan: none warranted (see root report).

*End of report.*
