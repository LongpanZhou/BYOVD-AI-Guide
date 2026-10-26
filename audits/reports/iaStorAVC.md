# Audit: iaStorAVC.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaStorAVC.sys` |
| Recorded SHA-256 | `7274F33E5EED8AF739FFCC80B9A62CDF12553EBD2724E2F8E93FD67376CC6E84` (matches triage_index.csv row 42; verified before opening; REA reports the same digest) |
| Company/Version | Intel Corporation, 15.44.0.1015 (triage row). Intel storage (AHCI/RST) StorPort miniport. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, **deep-form**. A write-relevant sink (`MmMapIoSpace`) takes a length from device-supplied data, so deep-form applies. The StorPort SRB_IO_CONTROL path was not reached |
| Verdict | **WRITE-MEDIUM (provisional, coverage-limited, ~20%)**. A device-supplied DWORD is passed unbounded as the length of a second `MmMapIoSpace` (mapping misuse). NO-WRITE is not available because that sink is not bounded in-file. The producer is device firmware (outside the file), and the consumers of the mapping are unreviewed |
| Coverage | ~20%. Reviewed: imports and xrefs (sweeps, `MmMapIoSpace`, `StorPortInitialize`, `IoWMIRegistrationControl`), `FUN_140084c30` and `FUN_140083694` (decompiled), their callers (addresses only), WMI teardown `FUN_140111000`. Not reviewed: DriverEntry (the `StorPortInitialize` call site `0x1400c1308` is not in a recovered procedure), HwAdapterControl, HwStartIo and HwBuildIo (SRB_IO_CONTROL path), WMI data-block callbacks (global `DAT_1400cb010`), `MmMapIoSpace` sites `0x14008a5a3` and `0x1400c1258`, callers `0x1400843a4`, `0x1400844d8`, `0x140084460`, `0x1400845c8`, copy helper `FUN_1400bac80`, ROM search helper `FUN_14008360c`, IRP and work-item helpers |

> **Static-only.** No load, no device open, no IOCTL, no MMIO access on the host. Addresses are REA default-space linked VAs (image base 0x140000000). The REA session was shared with another agent that switched targets repeatedly. Every result whose subject digest was not iaStorAVC was discarded; no fact below comes from a foreign-digest result.

## Entry surface

- **No device object created by this driver.** The `Io` sweep shows no `IoCreateDevice` or `IoCreateSymbolicLink`. No `\Device\` string, no SDDL, no WDF.
- **StorPort miniport.** 20 STORPORT imports (`StorPortInitialize`, `StorPortNotification`, `StorPortGetScatterGatherList`, `StorPortGetPhysicalAddress`, and others). Registry imports (`StorPortRegistryRead`/`Write`) are configuration-control and out of scope. The IOCTL_SCSI_MINIPORT path through the port device would reach HwAdapterControl and HwStartIo, but the callback table lives in DriverEntry, which was not recovered (see Open items).
- **Hardware mapping.** `MmMapIoSpace`/`MmUnmapIoSpace` are imported, with five call sites. Two sites are in recovered procedures: `FUN_140083694` (site `0x1400836df`) and `FUN_140084c30` (sites `0x140084c4f`, `0x140084c7d`). One is unreviewed (`0x14008a5a3`), and one is not in a recovered procedure (`0x1400c1258`).
- **WMI.** `IoWMIRegistrationControl` is imported with three call sites: `0x1400c1180` (not in a recovered procedure), `0x140111035` (in `FUN_140111000`, teardown only), and `0x1401110dd` (unreviewed). The WMI data-block callback is a global function pointer (`DAT_1400cb010`) and was not resolved.
- **IRP sending.** `IoAllocateIrp`, `IoBuildDeviceIoControlRequest`, `IofCallDriver`, `IoFreeIrp` are imported (the driver issues IOCTLs to a lower device; not reviewed). `IoGetRequestorProcessId` is imported (use not reviewed).
- **Admin gate.** Not traced in-file.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Probe, MDL, or locked pages | None. No `Probe*`, `MmProbeAndLockPages`, or `MmMapLockedPagesSpecifyCache` | `ev_bed5c4e5…` (`Probe`, empty), `ev_c1e6b026…` (`Mm`: MmIsAddressValid, MmGetPhysicalAddress, MmGetSystemRoutineAddress, MmMapIoSpace, MmUnmapIoSpace) |
| `MmMapIoSpace` with a device-supplied length (`FUN_140084c30`, sites `0x140084c4f`, `0x140084c7d`) | Maps 36 bytes at a caller-supplied physical address, reads a signed DWORD at +4 of that mapping (device data), unmaps, then maps that many bytes with `MmMapIoSpace(param_2, iVar1, 0)`. The result is stored at param_1+8. Not bounded in-file (mapping misuse) | `ev_994e2855…` (pseudocode), `ev_7c08a3ab…` (resolve), `ev_b7f1599e…` (callers `0x1400844d8`, `0x1400845c8`) |
| Option-ROM scan (`FUN_140083694`, site `0x1400836df`) | Fixed mapping of 0x30000 bytes at physical 0xC0000. Steps through ROM headers with ROM-declared lengths (`<<9`). Copies `param_4` bytes into caller buffer `param_3` through `FUN_1400bac80` (not reviewed). Bounded by the scan window and the caller's length; both are set by callers not reviewed | `ev_547ccc46…` (pseudocode), `ev_0ee27e2c…` (resolve), `ev_c3cf2c99…` (callers `0x1400843a4`, `0x140084460`) |
| WMI teardown (`FUN_140111000`) | No caller-supplied data. Calls `IoWMIRegistrationControl(list head, 0x80000002)` and a global callback. Not a write sink in-file | `ev_739aa5eb…` (pseudocode), `ev_aca7dc42…` (resolve) |
| `StorPortInitialize` site `0x1400c1308` and WMI site `0x1400c1180` | Not in recovered procedures. DriverEntry and the StorPort callback table are not recovered | `ev_814a8395…`, `ev_9670bbab…` (resolve), `ev_727ab914…`, `ev_a022dbd4…` (xrefs) |
| SRB_IO_CONTROL (HwAdapterControl, HwStartIo, HwBuildIo) | Not reviewed | — |
| Other `MmMapIoSpace` sites `0x14008a5a3`, `0x1400c1258` | Not reviewed (`0x1400c1258` is not in a recovered procedure) | `ev_0355b56d…` (xrefs) |

## Verdict rationale

WRITE-MEDIUM, provisional. The in-scope sink is `MmMapIoSpace` with a length taken from device data. The file does not bound that length (signed, unchecked), so NO-WRITE is not available. The producer is device firmware or register contents, outside the file. The mapping's consumers (writes through param_1+8) are unreviewed, so the claim that it becomes a write is not established. The StorPort SRB_IO_CONTROL path, which is the decisive user-reachable path for a StorPort miniport, was not reached because DriverEntry was not recovered. Coverage is about 20%.

Escalate to **WRITE-HIGH** if the SRB_IO_CONTROL or WMI path reaches `FUN_140084c30` or `FUN_140083694` with a caller-supplied physical address or length, or if the mapping's consumers write at device-supplied offsets beyond the mapping.

Drop to **NO-WRITE** if the unreviewed callers clamp the device length (to the BAR size or to 36 bytes) before the second `MmMapIoSpace`, the copy in `FUN_1400bac80` is bounded by the ROM window, and the SRB path is confirmed to bound `DataTransferLength`.

## Open items

1. Recover the DriverEntry that contains the `StorPortInitialize` call site `0x1400c1308` (not in a recovered procedure). Map HwAdapterControl, HwStartIo, and HwBuildIo. This is the decisive item for the SRB_IO_CONTROL path.
2. Callers of `FUN_140084c30` and `FUN_140083694` (`0x1400843a4`, `0x1400844d8`, `0x140084460`, `0x1400845c8`): the physical address source and any clamp on the device length.
3. `MmMapIoSpace` sites `0x14008a5a3` and `0x1400c1258` (not reviewed; the latter is not in a recovered procedure).
4. WMI: `IoWMIRegistrationControl` sites `0x1400c1180` and `0x1401110dd`, the callback behind `DAT_1400cb010`, and the WMI namespace ACL.
5. Bounds of `FUN_1400bac80` (copy) and `FUN_14008360c` (ROM search).
6. IRP helpers (`IoBuildDeviceIoControlRequest`, `IofCallDriver`): buffers and lengths passed, and whether they originate in a user request. `IoGetRequestorProcessId` use.
7. The device-length producer: the register block at the caller's physical address and whether firmware validates the DWORD at +4.

## VM confirmation plan (orchestrator-owned; VM only)

Hardware-gated (Intel storage controller). Not runnable on the host (stopped driver; MMIO-level trust boundary). In a snapshot VM with a stub PCI device whose register block sets the +4 DWORD to 0x7fffffff, check whether the second `MmMapIoSpace` succeeds and which consumers use the returned pointer. Run only in the VM, by the orchestrator.

## Evidence (REA, retained IDs)

- `ev_c1e6b026551164e4a9c1718b396a86a4cee361ae369def1013eadfe3010473ac` (`Mm` sweep: MmIsAddressValid, MmGetPhysicalAddress, MmGetSystemRoutineAddress, MmMapIoSpace, MmUnmapIoSpace)
- `ev_db55704ec083655f6c15c6844687a225aabe86bdc53053ad755c522a3ee26d3e` (`Io` sweep, case-sensitive)
- `ev_ca1d7dbd2b7a5c9562663fbf6be6717bc469cfdef344754ff8b212ff11075f8c` (`Wdf`, empty)
- `ev_5a368a00964fa59df12ce57e3de2b1dcf91d43b3a5626436fed05c239638dcfc` (`StorPort`, 20 imports)
- `ev_bed5c4e5cf9ea198f5c3ff0a2b483b26b4bc19010b7f02b4dbc5a6bb365fd913` (`Probe`, empty)
- `ev_b00009c1aaf3abba49686371bc7bb97c6cc29e55f85adaa592a7ef28128ad680` (`mem`: RtlCompareMemory, memcpy_s, memcmp, memset)
- `ev_5b212ed1370d37aef2181adfca4c42f0c01db483246581e1d6cc03a8c5af4460` (`copy`, empty)
- `ev_80b19d877c895e50eb5524e8025ef074645dc1fd969931d3a1b83aa901c5c8b3` (`(A;`, empty)
- `ev_75d89bbbed0643ca3a8d9d4270a91f84be808fe412d401bc26b89fc967b7f9d2` (`\Device\`, empty)
- `ev_0355b56d88a17b9ec271d354cdcd670a0058c438f45551f094b6a825e6464234` (xrefs of MmMapIoSpace: 0x1400836df, 0x140084c4f, 0x140084c7d, 0x14008a5a3, 0x1400c1258)
- `ev_727ab914cff89f36930d1faec25f46184a4d1b447be3931922e998e8c1a0a932` (xrefs of StorPortInitialize: 0x140010cde thunk, 0x1400c1308)
- `ev_a022dbd43eeebd5a97436c185e98b171884b86a16978f10ffd5d98d1582b9dcc` (xrefs of IoWMIRegistrationControl: 0x1400c1180, 0x140111035, 0x1401110dd)
- `ev_814a839536c418fc40bfbc5bcbc2b3ff26d5582f634fdeadfcbb35de933a320f` (0x1400c1308 → not in a procedure)
- `ev_fcf972543f3cecdfef60813bb4492bf50c6fafe0e8c8fb1074bb347ea34703f5` (0x1400c1258 → not in a procedure)
- `ev_9670bbaba39d6788686534645f2451a6107c5122cf29b9446c4ba4f0fc85109b` (0x1400c1180 → not in a procedure)
- `ev_0ee27e2cf907beb8600c080c92e974ba64359f1aac621004cbd0223e30d87188` (0x1400836df → FUN_140083694)
- `ev_7c08a3ab14e40f9463580166a688d030218778f1ee87bdde510c2044abf7b956` (0x140084c4f → FUN_140084c30)
- `ev_aca7dc42cb387decca038c11ae6b508142eea34f8cf30f307102184646d6e178` (0x140111035 → FUN_140111000)
- `ev_994e28554e367e23811e7cbd9f494d7327690926a0d7f5ff1693979382102fa8` (pseudocode FUN_140084c30)
- `ev_547ccc4692e2ef945da972913890f69ceb3f3808954675a2c088d2bc95c180b9` (pseudocode FUN_140083694)
- `ev_739aa5ebc9a361428432772b5c3d7a51beb8bc29c406d11422062b688056520d` (pseudocode FUN_140111000)
- `ev_b7f1599ed1883444807d6b286b568ef2b2b016d4b6b44dcd8c78b194f3ddaaf1` (callers of FUN_140084c30: 0x1400844d8, 0x1400845c8)
- `ev_c3cf2c99cc4f7901e1a7c78962d35e3d19943485623c15d8394742246720e3f7` (callers of FUN_140083694: 0x1400843a4, 0x140084460)
- Triage row check: Grep on the SHA (see final message; triage_index.csv row 42).
