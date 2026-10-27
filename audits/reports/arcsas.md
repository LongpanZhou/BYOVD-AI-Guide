# Audit: arcsas.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\arcsas.sys` |
| Recorded SHA-256 | `96DCA25AE619F38640B22702A10BC3191626F3A36DE0E1B0EDA3B079EA9DEB24` (verified vs triage_index.csv; REA digest matched on every retained call) |
| Company/Version | PMC-Sierra 7.5.0.32048 (NT.150223-1854) - "Adaptec RAID Storport Driver", "Adaptec SAS RAID WS03 Driver" |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4; complete string inventory + complete procedure inventory; bridge contended, results digest-verified) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are Ghidra-linked VAs at image base `0x1c0000000`. Shared REA bridge was contended (agents A/B switching targets); every retained result was digest-verified against the SHA-256 above; mis-served responses (other agents' targets) were discarded.

## Entry surface

- Pure StorPort miniport. Complete import surface = **18 externals, all `STORPORT.SYS::StorPort*`** (StorPortInitialize, StorPortGetDeviceBase, StorPortGetUncachedExtension, StorPortGetPhysicalAddress, StorPortGetBusData, StorPortSetDeviceQueueDepth, StorPortPause/PauseDevice/Resume, StorPortBusy, StorPortGetScatterGatherList, StorPortExtendedFunction, StorPortNotification, StorPortGetMSIInfo-family strings, StorPortDebugPrint, StorPortStallExecution, StorPortQuerySystemTime, StorPortFreeDeviceBase, StorPortResumeDevice).
- **No `IoCreateDevice`/`IoCreateDeviceSecure`/`IoCreateSymbolicLink`/`WdfDeviceCreate` anywhere in the 152-procedure inventory** - the driver creates no control device object and publishes no device name. String inventory (462 strings, complete) contains **no `\Device\` or `\DosDevices\` name and no SDDL string**.
- The only user-reachable command plane is the storport SRB plane: strings `Handle IOCTL CMD with vector 0. srb->function: 0x%x, cdb[0]: 0x%x`, `ProcessIoctl: private cdb's here`, CSMI signatures (`CSMIALL/CSMIARY/CSMISAS/CSMIPHY`, boot config `CSMI=Restricted/Full`), WMI via `MofResource`/`ScsiMiniPort`, `EnableWMI`. These arrive as SRB_FUNCTION_IO_CONTROL / SRB_FUNCTION_WMI through the storage stack's disk device objects (admin-gated device DACLs), not through any driver-owned device.

## Memory-write analysis

- **No Mm\*/Zw\* surface:** zero imports matching MmMap/MmProbe/MmGetSystemAddress/MmCopyMemory/MmMapLockedPages/ZwOpenSection/ZwMapViewOfSection/ProbeFor*/SeSinglePrivilege across the complete procedure inventory (externals are the only import path for this driver).
- StorPortGetDeviceBase/GetUncachedExtension map only PCI-BAR/boot-config memory during HwFindAdapter/HwInitialize (strings `MapDeviceBase`, `StorPortGetDeviceBase failed, can't map the device base`, `AllocateConsumerProducerCommArea`) - kernel-initiated, not caller-influenced addresses.
- IOCTL plane (`ProcessIoctl` + private CDB + CSMI + WMI) operates on SRB data buffers marshalled by storport; the driver has no direct system-buffer access and no MDL/probe primitives. No unchecked copy/fill of user-length into fixed kernel buffers is implied by any string; nothing in the write-pattern catalogue (copy-length confusion, METHOD_NEITHER, caller-MDL->kernel-VA, `\Device\PhysicalMemory`, wrmsr) is present.

## Memory-touching IOCTL table

Driver owns no dispatch: no IOCTL codes of its own. SRB plane (storport-mediated, storage-stack gated): SRB_FUNCTION_IO_CONTROL (private CDB / CSMI), SRB_FUNCTION_WMI, SRB_FUNCTION_POWER, SRB_FUNCTION_RESET - one line each, no direct buffer access.

## Verdict + VM confirmation plan

**NO-WRITE.** Complete import inventory (18 StorPort DDIs) and complete string inventory (462 strings) show a StorPort miniport with no control device, no user-openable interface, no SDDL, and no memory-mapping/probe primitives. Every kernel write path funnels through storport-mediated SRBs (admin/storage-stack gated). No unprivileged memory-write primitive exists.

VM plan (orchestrator-owned, non-destructive): if ever loaded on the VM, confirm via `!object \Device\...` enumeration that the adapter device objects are admin-gated and that a restricted-token open of the storage PDOs fails; no IOCTL probing is warranted by the static evidence.

*End of report.*
