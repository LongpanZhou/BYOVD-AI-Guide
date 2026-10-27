# Audit: iaLPSS2i_I2C_CNL.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaLPSS2i_I2C_CNL.sys` |
| Recorded SHA-256 | `F105EDD16E38F5C0044CC7139E4084A04B0AE3212171A1C7F6FE759F3F5F77FC` (verified vs triage_index.csv, local Get-FileHash) |
| Company/Version | Intel Corporation 30.100.1929.1 - "Intel(R) Serial IO I2C Driver v2" (CNL platform variant; NEWEST build in the family) |
| Method | Static-only. Abbreviated diff audit vs root `iaLPSS2i_I2C.sys` (audits/iaLPSS2i_I2C.md): full decompile of all 173 functions (local Ghidra 12.1.4 headless; REA bridge contended - see root report method note) + full string-set diff vs root (local dumps); reject/validate structure re-verified directly in this build's decompile |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`.

## Diff vs root (iaLPSS2i_I2C.sys)

- **Identical structure (verified in THIS build's decompile):** same SDDL literal `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GRGW;;;LS)(A;;GRGW;;;RC)` (unnamed FDO, no interface - unreachable boilerplate); 3 x `STATUS_NOT_SUPPORTED` reject completions (EvtIoDeviceControl/EvtSpbOther plane); 1 x 64 KB transfer-length check (`0xffff <`); 3 x `MmMapLockedPagesSpecifyCache` (WDF-locked DMA-chain MDLs, KernelMode); 1 x `MmMapIoSpaceEx` (PnP BAR); "OnSequence" handler present.
- **Differences:** external-set swap `EtwWrite`+`RtlCompareMemory` (root) -> `EtwWriteTransfer` (CNL) - ETW variant only, no new capability; largest HWID table of the family (102 strings: ACPI `INT3442-INT3447`, PCI `VEN_8086&DEV_9D60/9D61` + further CNL-LP/CNP controllers); version 30.100.1929.1; own `.pdb` name; minor codegen junk differences.
- **Privileged instructions:** none (same byte-scan method as root).

## Verdict + VM confirmation plan

**NO-WRITE** - same reasoning as the root report; the CNL delta (30.100.1929.1) is platform HWID/ETW content only; the reject/validate/DMA structure is byte-for-byte the same shape.

VM plan: none warranted (see root report).

*End of report.*
