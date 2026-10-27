# Audit: iaLPSS2i_I2C_GLK.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaLPSS2i_I2C_GLK.sys` |
| Recorded SHA-256 | `A92487129B81376471C842B9932FF3A7B3ABBBB89797978E3FDEAF71A6FD5E3F` (verified vs triage_index.csv, local Get-FileHash) |
| Company/Version | Intel Corporation 30.100.1820.1 - "Intel(R) Serial IO I2C Driver v2" (GLK platform variant) |
| Method | Static-only. Abbreviated diff audit vs root `iaLPSS2i_I2C.sys` (audits/iaLPSS2i_I2C.md): full decompile of all 173 functions (local Ghidra 12.1.4 headless; REA bridge contended - see root report method note) + full string-set diff vs root (local dumps) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`.

## Diff vs root (iaLPSS2i_I2C.sys)

- **Identical:** all 23 external imports (no additions/removals); same SDDL literal `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GRGW;;;LS)(A;;GRGW;;;RC)` (unnamed, interface-less FDO - unreachable boilerplate, same as root); same DMA/MDL structure (3 `MmMapLockedPagesSpecifyCache` sites on WDF-locked DMA-chain MDLs); 1 `MmMapIoSpaceEx` site from the PnP resource list; 64 KB/entry check and reject-all `EvtIoDeviceControl`/`EvtSpbOther` structure present.
- **Differences (platform content only):** +1 function (172->173); GLK HWID tables (ACPI `INT3442-INT3447`, PCI `VEN_8086&DEV_9D60/9D61` ... 72 HWID strings); version 30.100.1820.1; own `.pdb` name.
- **Privileged instructions:** none (same byte-scan method as root).

## Verdict + VM confirmation plan

**NO-WRITE** - same reasoning as the root report; the GLK delta is platform HWID/registry content only.

VM plan: none warranted (see root report).

*End of report.*
