# Audit: bcmfn2.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\bcmfn2.sys` |
| Recorded SHA-256 | `9AD12E18A042C5B8EFB19297BC2E7BD1FEF75A138FEFB64C6BF0261FD3E53AB1` (verified against triage_index.csv) |
| Company/Version | Windows (R) Win 7 DDK provider 6.3.9600.17336 (Broadcom "BCM Function 2 Device Driver" for Baytrail SDIO GPIO) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless, private project; REA shared bridge contended by parallel agents) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (document `target-9ad12e18a042.sys`).

## Entry surface

KMDF function driver that binds to the **SdBus** interface of its parent stack: `SdBusOpenInterface` (`0x140001280`), `SdBusSubmitRequest`/`Async` (`0x14000138C`/`0x140001478`), internal IRP completion `SdbusIoctlCompletion` (`0x140001504`). All bus traffic goes downward via `IoBuildSynchronousFsdRequest` + `IofCallDriver`.

- **No `IoCreateDevice`/`IoCreateSymbolicLink`/device-name strings** — the driver creates no device object and no interface of its own; it services only the PDO provided by its parent (SDIO) stack.
- No IOCTL dispatch of its own: with no device object there is no MJ_DEVICE_CONTROL surface reachable from user mode.

## Memory-write analysis

- Procedure set is tiny (28 procedures; all memset sites are fixed-size zero-fills of stack/object locals: `0x68`, `0x90`, `0x38`, `0x30`, `0x26`, `0x24`, `0x20` — constants, no caller-dependent sizes).
- No `MmProbeAndLockPages` / `MmMapLockedPagesSpecifyAccess` / `MmMapIoSpace` / `MmGetPhysicalAddress` / `ZwOpenSection` / `MmCopyMemory` imports.
- No METHOD_NEITHER, no MSR/GDT/IDT patterns, no user-trusted length fields.

## Memory-touching IOCTL table

None — the driver registers no device object; no control codes exist.

## Verdict + VM confirmation plan

**NO-WRITE.** No user-openable surface and no user-controlled kernel write path exists.

VM plan (orchestrator-owned, non-destructive): none required for write-primitive confirmation; the driver can only be exercised with the matching Baytrail SDIO GPIO hardware present in the parent stack.

*End of report.*
