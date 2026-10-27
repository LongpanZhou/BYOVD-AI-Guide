# Audit: iaLPSSi_I2C.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaLPSSi_I2C.sys` |
| Recorded SHA-256 | `8445E41BAB21964C7F014742795E462BDDC6C37A261990B3D6BF4E637A719547` (verified vs triage_index.csv, local Get-FileHash) |
| Company/Version | Intel Corporation 1.1.253.0 - "Intel(R) Serial IO I2C Controller Driver" (Gen1/LPT-LP+WPT-LP, Win8.1-era build; HWIDs `ACPI\INT33C2/INT33C3/INT3432/INT3433`) |
| Method | Static-only. Full decompile of all 162 functions (local Ghidra 12.1.4 headless; REA shared bridge contended by parallel agents A/B - see archived agent-D ledger in audits/_archive/agent_ledgers_2026-10-24.zip) + local string/import recon; MDL/allocation call sites audited directly; every identity cross-checked by SHA-256 |
| Verdict | **NO-WRITE** (permissive-DACL noted; no user-openable device object and no unbounded kernel write on any surface) |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (`.text` 0x140001000-0x140016869, `.rdata` 0x140017000-0x1400180BB, `.data` 0x140019000, `PAGE` 0x14001C000, `INIT` 0x14001D000, `.rsrc` incl. authenticode blob).

## Entry surface

- KMDF class-extension client minidriver (SpbCx): DeviceAdd = `SpbDeviceInitConfig` + `WdfDeviceCreate` + `SpbDeviceInitialize` (+ interrupt/spinlock/timer/work-item creation per log strings "Error creating interrupt object"/"Failed to create delay timer"/"Error creating Work Item"), then hardware-profile ACPI HWID match.
- **SDDL assigned on the FDO** (log line "Error setting the device security descriptor"; literal in `.rdata` at `0x14017400`):
  ```
  D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GRGW;;;LS)(A;;GRGW;;;RC)
  ```
  -> Everyone (WD) = GENERIC_READ|GENERIC_WRITE - **same boilerplate as the Gen2 family**. The FDO is unnamed (no `\Device\...` string; the `%ws_%u` literal at 0x140016090 is unreferenced trace-label material) and **no device interface is registered** (no `{...}` GUID string anywhere). No user-mode open path exists for the controller; SPB targets are kernel-client-only (connection IDs).
- **Imports (complete, 33):** ETW trio; `KeClearEvent/KeSetEvent/KeWaitForSingleObject/KeWaitForMultipleObjects/KeInitializeEvent/KeDelayExecutionThread/KeStallExecutionProcessor/KeLowerIrql/KfRaiseIrql`; `MmMapIoSpace/MmUnmapIoSpace/MmGetPhysicalAddress/MmMapLockedPagesSpecifyCache/MmBuildMdlForNonPagedPool/MmAllocateContiguousMemorySpecifyCache/MmFreeContiguousMemory`; `IoAllocateMdl/IoFreeMdl`; `PoRegister/UnregisterPowerSettingCallback`; `IoWMIRegistrationControl`; `RtlAnsiCharToUnicodeChar/RtlCompareMemory/RtlCopyUnicodeString/RtlVerifyVersionInfo/VerSetConditionMask/MmGetSystemRoutineAddress/RtlInitUnicodeString`; `WdfVersionBind/Unbind/BindClass/UnbindClass`.
- Absent: `MmProbeAndLockPages` (**cannot lock user pages**), any `Zw*`, `Se*`, `Ob*`, `IoCreateDevice*`, `MmCopyMemory`, `ZwOpenSection`, `Hal*`.

## Memory-write analysis

- **MMIO mapping:** `FUN_140004270` (PrepareHardware): `MmMapIoSpace(*(pcVar6+4), *(pcVar6+0xc))` - PA/length from the translated PnP resource descriptor, guarded by the "MBAR address is not below 4GB" / "Error Mapping controller MBAR" / resource-count checks. Not caller-influenced.
- **DMA buffers are driver-owned:** `FUN_14000e924`, `FUN_14000ebf4`, `FUN_14000f17c` build MDLs with `IoAllocateMdl(poolVA, size, 0,0,0)` + `MmBuildMdlForNonPagedPool` over the driver's own non-paged/contiguous allocations (via `MmAllocateContiguousMemorySpecifyCache` through its runtime thunk), then `MmMapLockedPagesSpecifyCache(mdl, KernelMode /*0*/, ...)` - all KernelMode mappings of **self-built MDLs over driver-owned memory** (no caller MDL anywhere; the import set cannot probe user pages).
- **Request data path:** single-transfer and sequence flows (trace labels "Sequence"/"LockConnection"/"UnlockConnection"/"Write"/"Other"/"Cancel") move data between the SpbCx/WDF request memory and the driver's staging buffers / hardware FIFOs; reject completions present (3 x `STATUS_NOT_SUPPORTED`, 10 x `STATUS_NOT_IMPLEMENTED` stub callbacks). No inline copy of request data was found in-file (movement is DMA-engine-driven from driver-owned staging buffers).
- **Registry config:** named DWORD values (`StandardSpeed_*/FastSpeed*/HighSpeed_* SCL/SDA counters`, `DmaError`, `DmaInit`, `MonitorOn/OffIdleTimeout`, `MonitorOffD0EntryDelay`, `EnableMbar1Control`, `ForceDma[0]`, `CancelTimeoutUs[0]`, `ByteTimeUs[0]`, `CombinedWriteRead[0]`-family) - admin-writable device-Parameters values feeding hardware timing/DMA configuration and idle-timeout settings (bounded fixed-field stores).
- **Privileged instructions:** byte-scan - all `0F 01` pairs are rip-relative displacements (`mov rcx,[rip+0x10F8D]`, `lea rax,[rip+0x10F86]`, `jz +0x10F`) or `.rsrc`/cert-blob coincidences; the single `0F 20` is `44 0F 20 C5` = `MOV EBP, CR8` (the standard inline IRQL read - read-only, not a CR write). **No WRMSR/SGDT/SIDT/LGDT/INVD/CR-write anywhere.**

## Memory-touching IOCTL table

| Surface | Result |
|---|---|
| Direct controller-device IOCTLs / "Other" SPB IOCTLs | rejected (`STATUS_NOT_SUPPORTED` completions / `STATUS_NOT_IMPLEMENTED` stubs) |
| `EvtSpbIoRead/Write/Sequence` (SpbCx targets, kernel clients) | DMA via driver-owned staging buffers; request data never memcpy'd in-file |

## Verdict + VM confirmation plan

**NO-WRITE.** Gen1 SpbCx controller minidriver: unnamed FDO with no interface (Everyone-GRGW ACE unreachable boilerplate), MDL kit strictly over driver-owned non-paged/contiguous memory (no user-page locking capability), MMIO mapped only from PnP resources, registry values stored into fixed fields. No unprivileged kernel memory-write primitive.

VM plan (orchestrator-owned, describe-only): none warranted - binds only to real LPSS I2C PCI hardware (ACPI INT33C2/33C3/3432/3433); without the device SpbCx never creates the controller. Non-destructive reachability test (restricted-token open attempt) applies only when the hardware is present.

*End of report.*
