# Audit: amd_sata.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\amd_sata.sys` |
| Recorded SHA-256 | `247c474daf9ffff7fb46eb6185088b94b886a7685f98cabe1983efeaee1a8338` (matches triage_index.csv row "amd_sata") |
| Company/Version | Advanced Micro Devices - 1.2.001.0402 built by: WinDDK ("AHCI 1.2 Device Driver") |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4, x86:LE:64) |
| Verdict | **NO-WRITE** |

> Static-only. No driver load, no device open, no IOCTL execution. Read-only static analysis only.

---

## Entry surface

Pure StorPort AHCI miniport (138 procedures; DDI table `StorPort*` -> storport.sys, strings `0x2518a-0x253e2`). **No device object, no device/dos names, no SDDL, no interface GUIDs.** All opens/IOCTLs owned by storport/classpnp.

## Memory-write analysis

- `StorPortGetDeviceBase`/`StorPortGetPhysicalAddress`/`StorPortGetScatterGatherList` = class-issued transfer plumbing; hardware register mapping only.
- Registry config plane (AmdSata* values `0x22118-0x22510`) is HKLM admin config; no user pointer/length flow. `AmdSataPassThru`/`AmdSataScsiPassThruAtaProtocol` toggle class-driver pass-through features - gated by the Microsoft SCSI pass-through logic (probing/locking owned by storport/classpnp), not by this binary.
- Absent: ZwOpenSection, \Device\PhysicalMemory, MmCopyMemory, METHOD_NEITHER handling, MSR code.

## Memory-touching IOCTL table

None in-binary.

## Verdict + VM confirmation plan

**NO-WRITE.** No user-openable surface, no write primitive. VM: not warranted.

*End of report.*
