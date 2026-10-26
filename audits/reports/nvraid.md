# Audit: nvraid.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\nvraid.sys` |
| Recorded SHA-256 | `628927eb91c6a323ca67b97ef743775b68d30599a0f0593bc3b5c0ba6c5ab82c` (matches triage_index.csv row "nvraid") |
| Company/Version | NVIDIA Corporation — 10.6.0.23 (PART_L3.131021-1012), "NVIDIA® nForce(TM) RAID Driver" |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4, x86:LE:64) |
| Verdict | **NO-WRITE** |

> Static-only. No driver load, no device open, no IOCTL execution. Driver opened only for read-only static analysis.

---

## Entry surface

Legacy SCSI miniport + port driver pair (classpnp integration via statically-linked `Class*` shims; source strings `drivers\oem\src\storage\nvraid\`). Creates SCSI adapter device objects under the SCSI-port convention: `\Device\Scsi\nvraid%d`, `\Device\ScsiPort%d`, `\Device\ScsiPort00`, `\DosDevices\Scsi%d:` (strings `0x26980–0x26a40`). No interface GUID of its own (only interface enable/disable helpers used for GenDisk children created by the SCSI stack). No SDDL strings — DACLs are the OS-default (admin/system) device SDs. **No unprivileged open path**: SCSI adapter device objects are not exposed through permissive interfaces, and PnP disks route IOCTLs through classpnp.

## Memory-write analysis

- Imports/resolved names (`0x2dfc2–0x2e9c8`): only ntoskrnl/HAL/CLASSPNP-class DDI. Memory-mapping APIs present: `MmMapIoSpace`/`MmUnmapIoSpace` (hardware registers), `MmProbeAndLockPages`/`MmUnlockPages`, `MmMapLockedPagesSpecifyCache`, `IoAllocateMdl`, `MmBuildMdlForNonPagedPool`, `IoBuildSynchronousFsdRequest`, `IoBuildDeviceIoControlRequest` — all standard SG/transfer plumbing; MDL mapping is applied to kernel-issued IRP MDLs, not caller MDLs stashed from user mode.
- **Absent**: `ZwOpenSection`, `\Device\PhysicalMemory`, `MmCopyMemory`, `MmGetPhysicalAddress`, `MmMapLockedPages` on user MDLs, `WdfRequestRetrieveUnsafeUserBuffer`, `MmGetSystemRoutineAddress`-resolved native wrappers of the risky class.
- Device-control path: IOCTLs reach the miniport only via the SCSI port driver (Microsoft-owned probing/locking), with SRBs built by scsiport. No IOCTL code with METHOD_NEITHER handling is implemented in this binary's dispatch surface beyond scsiport passthrough.
- No MSR/GDT/IDT-touching code paths (no wrmsr-class utility names, no DDI of that class).
- Context/ring indexes: parity/stripe bookkeeping (`NvRaidParity*`) uses internally allocated buffers with lookaside lists; indexes are volume/disk-scoped, not user-visible.

## Memory-touching IOCTL table

None implemented natively — device-control requests are forwarded through the SCSI port class driver; mapping/copy operations are kernel-issued transfer plumbing (listed above for coverage, not user-reachable).

## Verdict + VM confirmation plan

**NO-WRITE.** Storage-controller driver with no user-openable device surface: the only device objects are SCSI adapter objects under default admin-only SDs; the dynamic-mapping imports serve kernel-issued I/O plumbing. No probe-less METHOD_NEITHER, no unchecked copy/fill, no physmem/MSR surface.

VM: not warranted; if desired, standard-user `CreateFile("\\\\.\\Scsi0:")` should fail access-denied — that alone confirms the reachability argument.

*End of report.*
