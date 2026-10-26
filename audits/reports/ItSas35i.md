# Audit: ItSas35i.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\ItSas35i.sys` |
| Recorded SHA-256 | `A66C90009C7B20736A8B291889C518CBAF9D0C32A5EC720330EF25F30C056F1B` (verified vs triage_index.csv) |
| Company/Version | Avago Technologies 2.60.94.80 (SAS35xx family Storport miniport, CN=Microsoft Windows signing) |
| Method | Static-only audit via local Ghidra 12.1.4 headless (complete import inventory + complete string inventory (302) + function inventory (227) + executable-section privileged-instruction byte scan) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are Ghidra-linked VAs at image base `0x140000000`.

## Entry surface

- Pure StorPort miniport. **Complete import surface = 21 functions**: 18 `STORPORT.SYS::StorPort*` DDIs (Initialize, GetDeviceBase, GetUncachedExtension, GetPhysicalAddress, GetScatterGatherList, GetLogicalUnit, GetBusData, SetDeviceQueueDepth, Pause/Resume/PauseDevice/ResumeDevice/Ready, Busy, Notification, StallExecution, QuerySystemTime, ExtendedFunction) + `ScsiPortNotification` (legacy-compat notification helper) + 2 `NTOSKRNL.EXE::RtlFind{Most,Least}SignificantBit` helpers.
- **No `Mm*`/`Zw*`/`Probe*`/`Se*`/`Io*`/`Ob*`/`Ps*`/`Ex*` imports** — the binary cannot create a device object (`IoCreateDevice*` not imported), cannot map memory (`MmMapIoSpace`/`MmMapLockedPages*`/`MmCopyMemory` not imported), and has no runtime-import escape hatch (no `MmGetSystemRoutineAddress`).
- **No export table** (export RVA/size = 0) — no exported callable surface beyond the PE entry point.
- String inventory (302 strings, complete): **no `\Device\` or `\DosDevices\` name, no SDDL string, no "PhysicalMemory"**. All "Device"/"IOCTL" strings are hardware diagnostics of the SRB/firmware plane (e.g. `IOCTL on Non-Nvme Device is failed`, `Invalid function for Read slot IOCTL`, `Diag Reset(miniport)... IOCTL timed Out` — enclosure/firmware message IO, not user-facing control codes). WMI helpers `ScsiPortWmiPostProcess`/`ScsiWmipFindGuid` appear as name strings (SRB_FUNCTION_WMI plane via the storport scsiport-compat layer).

## Memory-write analysis

- Kernel writes can only originate from StorPort-mediated planes (SRB_FUNCTION_IO_CONTROL / WMI / SCSI request execution) — buffers marshalled by storport; the driver never touches a user buffer, MDL, or system VA.
- No caller-influenced mapping: `StorPortGetDeviceBase`/`GetUncachedExtension` map PCI BARs / comm area during HwFindAdapter/HwInitialize only (kernel-initiated, hardware-address-driven).
- Privileged-instruction scan over executable sections: every candidate byte pattern (`0F 30` WRMSR, `0F 01` SGDT/LGDT group, `0F 20/22` MOV-CR, WBINVD) was verified against the analyzed listing — **all hits are non-instruction byte coincidences in immediates/data** (`no-instruction` at each reported address, e.g. WRMSR bytes at `0x14001c843` sit in a data region). No real `wrmsr`/`lgdt`/MOV-CR code exists.

## Memory-touching IOCTL table

None of the driver's own. Only storport-mediated SRB plane: SRB_FUNCTION_IO_CONTROL (private CDB/enclosure/firmware messages), SRB_FUNCTION_WMI (`MofResource`, CDB16/32 WMI), SRB_FUNCTION_RESET/POWER — all arrive through the storage stack's admin-gated disk/PDO device objects, not through any driver-owned device.

## Verdict + VM confirmation plan

**NO-WRITE.** The import table alone closes every candidate primitive class for round 2: no device-object creation, no memory-mapping/section APIs, no probe/identity APIs, no privileged instructions, no exports. Every kernel write funnels through storport-mediated SRBs on admin-gated storage PDOs. No unprivileged memory-write primitive exists.

VM plan (orchestrator-owned, non-destructive): if ever loaded, enumerate `!object` for any `\Device` objects owned by the driver (expected: none beyond storport-created adapter PDOs) and confirm a restricted-token open of the storage PDOs is denied; no IOCTL probing is warranted by the static evidence.

*End of report.*
