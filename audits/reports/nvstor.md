# Audit: nvstor.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\nvstor.sys` |
| Recorded SHA-256 | `f07cd88b7939c53df83e93d40fb5ab115946393afbe8dba75fee7247bf3063a9` (matches triage_index.csv row "nvstor") |
| Company/Version | NVIDIA Corporation - 10.6.0.23 (PART_L3.131021-1012), "NVIDIA(R) nForce(TM) SATA Driver" |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4, x86:LE:64) |
| Verdict | **NO-WRITE** |

> Static-only. No driver load, no device open, no IOCTL execution. Read-only static analysis only.

---

## Entry surface

Pure StorPort miniport: every exported interaction is via storport.sys DDIs (`StorPortInitialize`, `StorPortGetDeviceBase`, `StorPortNotification`, `StorPortGetPhysicalAddress`, ...; name table `0x371dc-0x37424`, import "storport.sys" `0x14037414`). **The miniport owns no device object and no IOCTL dispatch surface** - all opens and device-control requests are owned by the storport class driver. No `\Device\`/`\DosDevices\` names, no SDDL, no interface GUIDs.

## Memory-write analysis

- Mapping/copy DDIs available to a miniport (`StorPortGetDeviceBase` -> `MmMapIoSpace` inside storport; `StorPortGetScatterGatherList`; `StorPortGetPhysicalAddress`) operate on class-driver-issued I/O; physical addresses are hardware-derived, not caller-influenced.
- Registry config (DriverParameter: queuingEnable, AQEnable, ErrorInject*, etc.) is admin-key HKLM config - control-plane, out of scope; no user pointer flows.
- Absent: ZwOpenSection, \Device\PhysicalMemory, MmCopyMemory, METHOD_NEITHER handling, MSR/segment-table code.
- No lookaside/queue element with a user-supplied extent.

## Memory-touching IOCTL table

None - no device-control surface exists in this binary (storport-owned stack).

## Verdict + VM confirmation plan

**NO-WRITE.** No user-openable object, no IOCTL surface, no dynamic-mapping or unchecked-copy primitive. No VM testing warranted.

*End of report.*
