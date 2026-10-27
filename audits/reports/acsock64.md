# Audit: acsock64.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\acsock64.sys` |
| Recorded SHA-256 | `C38B29FB50B7EC4627132ED05CB2FF3CB12899D4D610EAD745E92ECE5864A9A1` (verified against triage_index.csv) |
| Company/Version | Cisco Systems, Inc. 5, 1, 7, 27 (AnyConnect NVM "ngcsock" WFP callout) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless + byte-level PE parsing; REA shared bridge contended by parallel agents) |
| Verdict | **NO-WRITE** (both device objects are SDDL-gated away from unprivileged users; the serialized IOCTL input path is itself bounds-checked) |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (document `target-c38b29fb50b7.sys`).

## Entry surface

WFP callout driver (`Fwps*`/`Fwpm*` + WSK) that creates **two devices**, both via the standard `wdmsec` library (`WdmlibIoCreateDeviceSecure` = runtime-resolved `nt!IoCreateDeviceSecure`, `WdmlibInit` at `0x140070000`):

| Device | Type | Characteristics | Exclusive | DefaultSDDLString | Class GUID |
|---|---|---|---|---|---|
| `\Device\ngcsock` (`STR 1400479c0`, site `0x140004b06` -> `FUN_140004a60`) | `0x12` FILE_DEVICE_NETWORK | 0 | **TRUE** | `US@0x14005CCF8` = **`"D:P"`** - protected DACL with **zero ACEs** (open denied to everyone) | `0x14005CAE0` |
| `\Device\csskfltr` (site `0x140007c30`) + symlink `\DosDevices\csskfltr` (`0x140049690`) | `0x22` FILE_DEVICE_UNKNOWN | 0 | FALSE | `US@0x14005CD08` = **`"D:P(A;;GA;;;SY)(A;;GA;;;BA)"`** - **SYSTEM + Administrators only** | `0x14005CAE0` |

SDDL strings decoded from file bytes (RVA `0x5CCC0` = 27 chars `"D:P(A;;GA;;;SY)(A;;GA;;;BA)"`; RVA `0x5CD18` = `"D:P"`). DriverObject MajorFunction stores at `0x140007cb4+`: MJ_CREATE/CLOSE/CLEANUP = `FUN_140007570` (stub), **MJ_DEVICE_CONTROL = `FUN_140007480`**. No device interfaces registered. No `Se*`-style caller checks needed in-driver because the object manager gates MJ_CREATE by SDDL.

## Memory-write analysis

- **IOCTL forwarder** (`FUN_140007480`): resolves file/device context, passes `Irp->SystemBuffer` as both input and output plus lengths to the plugin dispatcher `FUN_1400072e4(DAT_1400620E0, IoControlCode, SystemBuffer, inLen, SystemBuffer, outLen, &info)`. A 4-byte output (`IoControlCode` requiring 4-byte reply) is written back into SystemBuffer - buffered, allowed.
- **Plugin dispatcher** (`FUN_1400072e4`): requires plugin-ready flag; unserializes SystemBuffer (`FUN_140011CC0` - allocates a scratch buffer of `len+0x100` (capped `< 0xFFFFFEFF`), copies `len` bytes, then validates header `"SRLZ"`, version <= 3, and **`hdrLen <= len`**); deserializes 4 fields with a strict bounds predicate `FUN_140011C00 = (offset + needed <= length)`; routes to one of 6 plugin objects (`param_1+0x6070`, stride `0x30`) via `vtbl+0x70(plugin, code, SystemBuffer)`.
- The plugin handlers receive the **system buffer** (not raw user VA), so buffered-method OOB against the caller is not possible; no probe-less user-pointer flow exists on this path.
- **Not found in-file:** no `MmProbeAndLockPages`, `MmMapLockedPagesSpecifyCache` callers that take a caller MDL into kernel VA (the MDL APIs - `IoAllocateMdl`, `MmBuildMdlForNonPagedPool`, `MmMapLockedPagesSpecifyCache` - are used only for driver-owned non-paged buffers on the WFP injection path `FUN_1400120CC`/`FUN_1400124D8`); no `MmMapIoSpace`/`MmGetPhysicalAddress`/`ZwOpenSection`/`MmCopyMemory`; no METHOD_NEITHER; no MSR/GDT/IDT code.

**Reachability conclusion:** an unprivileged local user cannot open either device object (`D:P` empty DACL, or SY/BA-only SDDL), so no IOCTL handler - and therefore no copy/fill/index path in this file - is reachable unprivileged. The one reachable-by-identity mode (SYSTEM) has no defective copy found in the dispatcher.

## Memory-touching IOCTL table

Only one dispatch path exists (all codes forwarded to the plugin table after bounded serialization); no per-code in-file copy table. Codes are validated by plugin ID (max 6 plugins) before any buffer use.

## Verdict + VM confirmation plan

**NO-WRITE.** No unprivileged-reachable kernel memory-write primitive. The control surface is explicitly admin-gated by its own SDDL, and even that path serializes input with correct bounds checks.

VM plan (orchestrator-owned, non-destructive): open `\\.\csskfltr` and `\\.\ngcsock` under a restricted token to record ACCESS_DENIED (SDDL confirmation); no IOCTL execution warranted; no corruption test.

*End of report.*
