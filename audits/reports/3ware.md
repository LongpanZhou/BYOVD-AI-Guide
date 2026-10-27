# Audit: 3ware.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\3ware.sys` |
| Recorded SHA-256 | `5A29D80AF47D08998125CB81BC1D4E84093291A74DE422B63F7BBDA7BDE95311` (verified against triage_index.csv; recomputed with Get-FileHash) |
| Recorded SHA-256 | `5A29D80AF47D08998125CB81BC1D4E84093291A74DE422B63F7BBDA7BDE95311` (verified against triage_index.csv) |
| Company/Version | LSI 5.01.00.051 (LSI 3ware 97xx SCSI Storport driver) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless, private project; REA shared bridge contended by parallel agents) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x1C0000000`.

## Entry surface

- Storport miniport: initialization solely via `StorPortInitialize`/`StorPortNotification` (DDI list: `StorPortBusy`, `StorPortGetDeviceBase`, `StorPortGetPhysicalAddress`, `StorPortGetScatterGatherList`, `StorPortGetUncachedExtension`, `StorPortRegistryRead`, `StorPortLogError`, ...).
- **No user-openable control device:** no `\Device\<name>` construction and no `StorPortDeviceControl`-style management device is created by this file. Its only external interface is the storport SRB path (`HwBuildIo`/`HwStartIo` registered with `StorPortInitialize`).
- Reaching the SRB ioctl path (`SRB_FUNCTION_IO_CONTROL`) requires an adapter device handle; storport adapter device objects use the OS default security descriptor - administrator-gated.

## Memory-write analysis

- All buffer handling flows through storport-supplied SG lists and adapter-owned uncached-extension buffers; `StorPortGetVirtualAddress` maps adapter DMA contexts, not caller pointers.
- No `MmProbeAndLockPages`/`MmMapLockedPagesSpecifyAccess`/`MmMapIoSpace`/`ZwOpenSection`/`MmCopyMemory` imports (storport miniports cannot call these directly here).
- No METHOD_NEITHER, no MSR/GDT/IDT byte patterns, no user-trusted length fields driving kernel writes.

## Memory-touching IOCTL table

None - no dedicated control device; the SRB path is admin-gated by the adapter device object ACL.

## Verdict + VM confirmation plan

**NO-WRITE.** No unprivileged local user can reach any memory-write path: there is no control device, and the SRB plane requires an administrator-gated adapter handle.

VM plan (orchestrator-owned, non-destructive): with the 3ware adapter present, attempt a restricted-token `CreateFile` on the adapter's SCSI device - expected ACCESS_DENIED; no IOCTL execution needed beyond reachability confirmation; no corruption test warranted.

*End of report.*
