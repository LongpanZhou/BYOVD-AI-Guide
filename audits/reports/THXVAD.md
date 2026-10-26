# Audit: THXVAD.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\THXVAD.sys` |
| Recorded SHA-256 | `F8AF9D897C95EBD256FC66E9A292CFF65FEEA75A8C45DC48547F3B826E7BC280` (verified against triage_index.csv) |
| Company/Version | Windows (R) Win 7 DDK provider 10.0.10011.16384 (THX Spatial Audio virtual adapter, portcls; copyright THX 2017) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless, private project; REA shared bridge contended by parallel agents) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (document `target-f8af9d897c95.sys`).

## Entry surface

Portcls (Port Class) virtual-audio minidriver: registers the adapter through `PcAddAdapterDevice` (import strings at `0x140026A16`); the KS device object and symbolic links are created by **portcls**, not by this file. The driver registers the standard audio device interface `IoRegisterDeviceInterface(Pdo, {6994AD04-93EF-11D0-A3CC-00A0C9223196}, …)` (`FUN_14001B948`, GUID bytes at `0x140006F98` — KSCATEGORY_AUDIO) and sets interface property data.

- IOCTL/property requests therefore arrive through the **KS/portcls property system**, which validates property-request buffer sizes against the property-item tables before the miniport handler runs.
- No `IoCreateDevice` in this file; no custom device names; interfaces are the standard audio stack surface (opened through MMDevAPI/wave services for rendering).

## Memory-write analysis

- **No memory-mapping APIs imported:** no `MmProbeAndLockPages`, `MmMapLockedPagesSpecifyAccess`, `MmMapIoSpace`, `MmGetPhysicalAddress`, `ZwOpenSection`, `MmCopyMemory`. The only MDL-adjacent import is `MmGetSystemRoutineAddress` (WPP/ETW library bootstrap, same family as winmad.sys).
- `ZwWriteFile` sites (`FUN_140003560`/`FUN_140004FBA` chain and `0x14001EDC8`/`0x14001EE34`): file/config persistence to a storage device — not kernel memory.
- `RtlRaiseException` (`0x140003560`): error-path assertion only.
- Fill sites: fixed-size `memset` constants (`0x38`, `0x230`, `0x50`, `0x20`) plus a handful of dynamic sizes on buffers just allocated in the same function (allocation-then-zero shapes) — no fixed-destination/user-length mismatch found in the analyzed set.
- No METHOD_NEITHER codes of its own (no device object), no MSR/GDT/IDT patterns.

**Residual unknown (accepted scope):** custom KSDAI/KSPROPERTY handlers — if THX added any — are routed through binary GUID/property-item tables not fully enumerated in this static pass. Their request buffers are portcls/Ks-validated before the handler runs, so the residual exposure would require a handler that writes past its validated request buffer using a user-embedded count; no such shape was found in the recovered procedures.

## Memory-touching IOCTL table

No in-file dispatch table exists (portcls owns MJ_DEVICE_CONTROL). All property handling is KS-mediated.

## Verdict + VM confirmation plan

**NO-WRITE.** Sample-derived portcls virtual-audio driver with no direct kernel-memory APIs; property surface is object-manager/KS-validated.

VM plan (orchestrator-owned, non-destructive): with the audio stack bound (endpoint activation), enumerate the KS interfaces registered by the driver and record which are openable under a restricted token; no IOCTL execution beyond standard endpoint activation; no corruption test warranted.

*End of report.*
