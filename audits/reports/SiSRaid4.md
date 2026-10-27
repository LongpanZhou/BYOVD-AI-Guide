# Audit: SiSRaid4.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\sisraid4.sys` |
| Recorded SHA-256 | `718C833E5EDFE642F3B254515E29641BF2D8E56E22F6B795024BF64721AB874E` (matches triage_index.csv row 85; verified before opening; REA reports the same digest) |
| Company/Version | Silicon Integrated Systems, 3.60.03 (NT.070926-1510) (triage row). StorPort miniport. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, **short-form** (no device object of its own; StorPort owns the device). The copy-call review that this driver needs is deep-form work, not done here |
| Verdict | **NO-WRITE (provisional, coverage-limited, ~20%)**. No mapping, probe, device, or SDDL import. The one copy primitive, an in-binary `memcpy` at `0x1F660`, has 42 call sites whose length arguments were not reviewed |
| Coverage | ~20%. Reviewed: import and string sweeps; the call count of the in-binary `memcpy`. Not reviewed: the StorPort callbacks (HwFindAdapter, HwStartIo, HwInterrupt, the IO_CONTROL handler), any of the 42 `memcpy` call sites, and the `StorPortDebugPrint` and `StorPortLogError` call sites |

> **Static-only.** No load, no device open, no SRB or IOCTL issued. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- No device object of its own: the Io sweep is empty, there is no `\Device\` string, and the `(A;` SDDL search is empty. StorPort creates the adapter and disk devices. No WDF.
- Reached through StorPort as SRBs. User mode reaches the miniport through the SCSI port device (IOCTL_SCSI_MINIPORT, which dispatches to the IO_CONTROL handler) and through SCSI pass-through to the disk device. Neither ACL is traced, so an admin gate is not established. The IO_CONTROL handler is not reviewed; per agent A's finding on the megasas family it may be `HwBuildIo` rather than `HwAdapterControl`, so verify per driver.
- StorPort imports (15): `StorPortGetBusData`, `StorPortGetScatterGatherList`, `StorPortDeviceReady`, `StorPortGetDeviceBase`, `StorPortLogError`, `StorPortSetBusDataByOffset`, `StorPortNotification`, `StorPortGetPhysicalAddress`, `StorPortInitialize`, `StorPortCompleteRequest`, `StorPortReady`, `StorPortGetUncachedExtension`, `StorPortDeviceBusy`, `StorPortStallExecution`, `StorPortDebugPrint`. Each also appears as a thunk procedure in `.text` at `0x1F99A`-`0x1FA42`.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Kernel mapping or MDL built by the driver | None (`Mm` sweep empty) | `ev_bb43f5bf...` |
| Probe and WDF APIs | None | `ev_99472d97...` (Probe), `ev_723520d2...` (Wdf) |
| Device-object APIs (`Io*`, `\Device\`) | None | `ev_c3ff3c3e...` (Io), `ev_8b517e1e...` (`\Device\`) |
| SDDL | None (`(A;` search empty) | `ev_ab199f0f...` |
| CPU copy imports (`copy` sweep) | None | `ev_400eae0d...` |
| In-binary `memcpy` at `0x1F660` | 42 incoming references (`0x11212` through `0x24300`). Lengths not reviewed. Decisive: any caller whose length comes from SRB, CDB, or device data | `ev_32fd566e...` (mem sweep), `ev_37254fbe...` (xrefs of `0x1F660`) |
| StorPort imports | 15, no direct write API among them | `ev_d143a2ca...` (StorPort sweep) |

## Verdict rationale

NO-WRITE, provisional. No mapping, probe, device, or SDDL primitive exists in-file. The one copy primitive is present, though, and a RAID miniport's SRB data paths would normally use it, so the 42 call sites are the decisive check, not a formality. Escalate to WRITE-* if a caller copies a length derived from SRB, CDB, or device data into a fixed buffer without a bound. This driver should move to deep-form on the `memcpy` callers before the verdict is final.

## Open items

- The 42 `memcpy` call sites (decisive): review their length arguments, starting with the ones reachable from the IO_CONTROL handler.
- The IO_CONTROL handler (`HwAdapterControl` or `HwBuildIo`; verify per driver): not reviewed.
- `StorPortLogError` and `StorPortDebugPrint` call sites (format string and buffer use): not reviewed.

## VM confirmation plan (orchestrator-owned; VM only)

Hardware-gated StorPort miniport (stopped driver; not run). In a snapshot VM with the adapter present, a read-only check would show the SCSI port device ACL and whether IOCTL_SCSI_MINIPORT reaches the IO_CONTROL handler.

## Evidence (REA, retained IDs)

- Mm sweep: `ev_bb43f5bff86b8e55c31221a81cc2473f08b4e056145cb4c37da08297409bdc2e`
- Io sweep: `ev_c3ff3c3e6de10ea26164aa903b569865c774290d8f35d891af07d839fb897534`
- Probe sweep: `ev_99472d9751513863c4c7a670a70de1268ef4aaa84b392e55b26e8efa55134f2e`
- Wdf sweep: `ev_723520d2fda13e3e5ec2cda12b4f48acbc2a66896fbc2345ee312334411a9f67`
- StorPort sweep: `ev_d143a2caf4ba6dd5c23150cfa76e0f5365b20bf2bcbaf196499d8cdf5768f68b`
- mem sweep (finds in-binary `memcpy`): `ev_32fd566e8c7904a3bf8c98ecbab08ccbd15a5a2327edd7da5a32af5f8654447d`
- copy sweep: `ev_400eae0d31b11103bd9e9e9f44f5f08f088800d9bee5b6f2c63f7f35e0cfa9aa`
- `(A;` SDDL search: `ev_ab199f0fdd6ab86c5846844e5fffd3c79185dba6e4e516421e8c052ab4ee0688`
- `\Device\` strings: `ev_8b517e1efd16950cdf6af780614d10039cdf9ca9f924668b40104fca10d28d8b`
- xrefs of in-binary `memcpy` `0x1F660`: `ev_37254fbe590bce1b863d428fc6e3c48826d8e232302edd77a9246b6b063b812f`
