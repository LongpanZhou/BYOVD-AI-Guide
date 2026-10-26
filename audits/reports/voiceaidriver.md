# Audit: voiceaidriver.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\voiceaidriver.sys` |
| Recorded SHA-256 | `74C4C2F122D48548019314FE15A331B81BFC10408B0D6F471DEE94E37FE3C1BC` (verified against triage_index.csv) |
| Company/Version | Windows (R) Win 7 DDK provider 10.0.10011.16384 (VoiceAIDriver — portcls audio adapter, same build family as THXVAD.sys) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless, private project; REA shared bridge contended by parallel agents) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (document `target-74c4c2f122d4.sys`).

## Entry surface

Portcls adapter driver (222 procedures): `PcInitializeAdapterDriver` + `PcDispatchIrp`/`PcAddAdapterDevice`/`PcNewPort`/`PcNewMiniport`/`PcRegisterSubdevice`/`PcRegisterPhysicalConnection`. KS device objects and symbolic links are created by **portcls**. Interfaces registered with the standard `KSCATEGORY_AUDIO` GUID `{6994AD04-93EF-11D0-A3CC-00A0C9223196}` (bytes at `0x140004510`; sites `FUN_140039340`, `FUN_140039E54`).

- Property/IOCTL requests are KS/portcls-validated before miniport handlers run.
- Registry access via `IoOpenDeviceInterfaceRegistryKey` + `Zw*Key` — allocation-then-reallocate on `STATUS_BUFFER_OVERFLOW` (bounded shapes).

## Memory-write analysis

- **No memory-mapping APIs:** no `MmProbeAndLockPages`, `MmMapLockedPagesSpecifyAccess`, `MmMapIoSpace`, `MmGetPhysicalAddress`, `ZwOpenSection`, `MmCopyMemory`; only `MmGetSystemRoutineAddress` (library bootstrap).
- Timers/work-items (`ExAllocateTimer`, `IoQueueWorkItem`) are used for internal state, not for deferred writes through stashed user pointers.
- Fill/copy sites are fixed-size or allocation-matched; no fixed-destination/user-length mismatch found in the recovered set.
- No METHOD_NEITHER (no own device object), no MSR/GDT/IDT patterns.

**Residual unknown (accepted scope):** same as THXVAD.sys — driver-defined KSDAI/KSPROPERTY handlers behind binary GUID tables were not exhaustively enumerated; their request buffers are KS-validated beforehand.

## Memory-touching IOCTL table

No in-file dispatch table (portcls owns MJ_DEVICE_CONTROL).

## Verdict + VM confirmation plan

**NO-WRITE.** Portcls audio adapter with no direct kernel-memory APIs and KS-validated property surface.

VM plan (orchestrator-owned, non-destructive): same as THXVAD — enumerate registered KS interfaces under a restricted token; no corruption test warranted.

*End of report.*
