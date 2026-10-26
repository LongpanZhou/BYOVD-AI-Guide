# Audit: amdsbs.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\amdsbs.sys` |
| Recorded SHA-256 | `71C7E7E5AA74596A6725D8F70F1DE9A0C63D3C3E120D9CCF8A508854AC340A23` (verified vs triage_index.csv + local Get-FileHash) |
| Company/Version | AMD Technologies Inc. — 3.7.1540.43 (PART3.121207-1123) "AMD Technology AHCI Compatible Controller Driver" (Promise Technology-derived RAID/AHCI, 2012; in-box copy, signed CN=Microsoft Windows) |
| Method | Static-only via LOCAL Ghidra 12.1.4 headless (javac-compiled GhidraScript). REA bridge contended → per-protocol fallback; full import/string/priv sweep, 654 functions, entry chain + 12 selected + MmMapIoSpace-caller transitive closure (7 callers) decompiled |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are image VAs (PE base 0; decompiled ranges `0x00040xxx`–`0x0007xxxx`).

## Entry surface

Hybrid StorPort AHCI/RAID miniport + light driver-object hooking, **no user-openable device of its own**: import-name blob (`0x000741ea`–`0x000745d8`) contains StorPort DDIs + ntoskrnl registry/string/time DDIs — **no `IoCreateDevice`, no `IoCreateSymbolicLink`, no SDDL, no `\Device`/`\DosDevices` strings** (the `\Device-1`/`\settings`/`\CAM`/`\PBM`/`\Parameters` strings are registry key fragments). WMI surface = classic-provider telemetry (`PROMISEMOFRESOURCE` MOF, `WmiTraceMessage`).
Notable init hooks (DriverEntry `FUN_0004285c`, tail `0x0004816`–`0x0004821`):
- saves storport's `AddDevice` (`DAT_00071708`), replaces `DRIVER_OBJECT->DriverExtension->AddDevice` with `FUN_000427f8` (walks `IoGetAttachedDevice` chain to record the stack bottom in `DAT_00071550`, then chains to the saved storport AddDevice);
- saves and replaces `MajorFunction[(0xe0-0x70)/8 = 14 = IRP_MJ_SHUTDOWN]` with `FUN_00040f8c` (see below), forwarding to the saved storport handler afterwards.
All hooked planes are storport adapter-device dispatches (OS-default/admin DACL) or driver-internal — no unpriv open path.

## Memory-write analysis

- **Reserved/BIOS memory scanner (read-only):** wrappers `FUN_00040b20` (`MmMapIoSpace(phys, len, MmNonCached)`) / `FUN_00040acc` (`MmUnmapIoSpace`) are called from 7 functions mapping **fixed firmware physical ranges only**: `0x400/0x10` (BDA), `0xC0000/0x20000` (BIOS ROM), `0x0/0xA0000` (low-memory scan), and — from BDA EBDA field `+0xe` + `MyDataSeg` offsets — the EBDA/`_CAM`/`SHD_`/`Proe`-signed Promise reserved block (map result cached in `DAT_00071538`/`DAT_00071520`/`DAT_00071540`). The scan **only reads** through mapped pointers (signature compares, offset loads); writes are confined to driver `.data` globals. Range endpoints derive from firmware headers, never from user input. Not `\Device\PhysicalMemory`, not user-va.
- **IRP_MJ_SHUTDOWN hook (`FUN_00040f8c`):** sends `IOCTL_SCSI_GET_ADDRESS` (`0x41018`) to its own device, then `IoEnumerateDeviceObjectList(DAT_00071530 = its own DriverObject, ...)` and issues internal `'FAST'/'TRAK'` handshake requests (code from `DAT_0004d008`) with start/length computed from firmware block geometry (`0x1fffe00`-sector chunks) — driver-to-driver consolidation pass; no caller-influenced pointers/lengths; forwards to storport's saved handler.
- **Config plane:** `RtlQueryRegistryValuesEx` (dynamic, fallback `RtlQueryRegistryValues`) for ~20 HKLM keywords (`EnableALPEDisableHotplug`, `EnableCCC`, `CCCTimeoutValue`, `FlushPolicy`, `JbodOnly`, `RaidCount`, `SystemSetupInProgress` …); `RtlWriteRegistryValue`/`RtlCreateRegistryKey` write only the driver's own counters under its own key. All admin config.
- **SRB plane:** StorPort DDIs only (`OSDI_StartIO--SRB_FUNCTION_*` strings); storport/classpnp own probing/locking; admin-gated device opening.
- **Absent primitives:** no `ZwOpenSection`/`ZwMapViewOfSection`/`\Device\PhysicalMemory`/`MmCopyMemory`/`MmProbeAndLock*`/MDL-map-of-caller; no METHOD_NEITHER dispatch of its own; instruction sweep = **no privileged instructions** (`priv_ins.txt` = 2 CR8 reads only); no WRMSR/RDMSR/GDT/IDT/CR writes.

## Memory-touching IOCTL table

None of its own. Plane inventory (all non-user-influenced):
| Plane | Direction | Gate |
|---|---|---|
| StorPort SRB plane (adapter device) | kernel⇄kernel | storport-owned device object, OS default DACL (admin) |
| `IOCTL_SCSI_GET_ADDRESS` (0x41018) | driver→self (internal, `IoBuildDeviceIoControlRequest`) | driver-initiated at shutdown |
| `'FASTTRAK'` internal requests (`DAT_0004d008`) | driver→own sibling devices | driver-initiated |
| HKLM registry read/write | config | admin |

## Verdict + VM confirmation plan

**NO-WRITE.** No user-openable control device; the only physical-memory activity is a read-only scan/map of fixed firmware regions for the Promise BIOS handshake block; dispatch hooks chain into storport's own handlers; registry writes confined to its own keys. No unprivileged kernel memory-write primitive found.

VM plan (describe only; not warranted): confirm no control device exists (driver-object device list), restricted-token open of adapter devices (expect admin gate), `!poolused` for its tags; no corruption test indicated.

*End of report.*
