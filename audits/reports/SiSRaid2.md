# Audit: SiSRaid2.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\SiSRaid2.sys` |
| Recorded SHA-256 | `567710C90BD71600A31A3408DB065B43C844DCFD12045FDE04CD59D932DC8353` (matches triage_index.csv row 86; verified before opening; REA reports the same digest) |
| Company/Version | Silicon Integrated Systems Corp., 2.60.01 (NT.070926-1510) (triage row). StorPort miniport. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, **short-form** (no device object of its own; StorPort owns the device). The copy-call review this driver needs is deep-form work, not done here |
| Verdict | **NO-WRITE (provisional, coverage-limited, ~20%)**. No mapping, probe, device, or SDDL import. The one copy primitive, an in-binary `memcpy` at `0x183F0`, has 20 call sites whose length arguments were not reviewed |
| Coverage | ~20%. Reviewed: import and string sweeps; the call count of the in-binary `memcpy`. Not reviewed: the StorPort callbacks (HwFindAdapter, HwStartIo, HwInterrupt, the IO_CONTROL handler), any of the 20 `memcpy` call sites, and the `StorPortLogError` call sites |

> **Static-only.** No load, no device open, no SRB or IOCTL issued. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- No device object of its own: the Io sweep is empty, there is no `\Device\` string, and the `(A;` SDDL search is empty. StorPort creates the adapter and disk devices. No WDF.
- Reached through StorPort as SRBs. User mode reaches the miniport through the SCSI port device (IOCTL_SCSI_MINIPORT, which dispatches to the IO_CONTROL handler) and through SCSI pass-through to the disk device. Neither ACL is traced, so an admin gate is not established. The IO_CONTROL handler is not reviewed; per agent A's finding on the megasas family it may be `HwBuildIo` rather than `HwAdapterControl`, so verify per driver.
- StorPort imports (11): `StorPortGetScatterGatherList`, `StorPortGetDeviceBase`, `StorPortLogError`, `StorPortSetBusDataByOffset`, `StorPortGetBusData`, `StorPortGetPhysicalAddress`, `StorPortInitialize`, `StorPortCompleteRequest`, `StorPortGetUncachedExtension`, `StorPortStallExecution`, `StorPortNotification`. Each also appears as a thunk procedure in `.text` at `0x1872A`–`0x187A2`.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Kernel mapping or MDL built by the driver | None (`Mm` sweep empty) | `ev_06dd5b0f…` |
| Probe and WDF APIs | None | `ev_53278720…` (Probe), `ev_6eb8c0fa…` (Wdf) |
| Device-object APIs (`Io*`, `\Device\`) | None | `ev_81e09547…` (Io), `ev_a5570767…` (`\Device\`) |
| SDDL | None (`(A;` search empty) | `ev_40046e5f…` |
| CPU copy imports (`copy` sweep) | None | `ev_28dbe497…` |
| In-binary `memcpy` at `0x183F0` | 20 incoming references (`0x134A7` through `0x1B1A4`). Lengths not reviewed. Decisive: any caller whose length comes from SRB, CDB, or device data | `ev_98a50919…` (mem sweep), `ev_1eee46ef…` (xrefs of `0x183F0`) |
| StorPort imports | 11, no direct write API among them | `ev_0a153d9e…` (StorPort sweep) |

## Verdict rationale

NO-WRITE, provisional. No mapping, probe, device, or SDDL primitive exists in-file. The one copy primitive is present, though, and a RAID miniport's SRB data paths would normally use it, so the 20 call sites are the decisive check. Escalate to WRITE-* if a caller copies a length derived from SRB, CDB, or device data into a fixed buffer without a bound. This driver should move to deep-form on the `memcpy` callers before the verdict is final. The same review applies to `SiSRaid4`, which has the same pattern.

## Open items

- The 20 `memcpy` call sites (decisive): review their length arguments, starting with the ones reachable from the IO_CONTROL handler.
- The IO_CONTROL handler (`HwAdapterControl` or `HwBuildIo`; verify per driver): not reviewed.
- `StorPortLogError` call sites (format string and buffer use): not reviewed.

## VM confirmation plan (orchestrator-owned; VM only)

Hardware-gated StorPort miniport (stopped driver; not run). In a snapshot VM with the adapter present, a read-only check would show the SCSI port device ACL and whether IOCTL_SCSI_MINIPORT reaches the IO_CONTROL handler.

## Evidence (REA, retained IDs)

- Mm sweep: `ev_06dd5b0f622ca7dba3d9b10992d0d3bea2ba588c2d640ef5b6ed57cbc2b9295b`
- Io sweep: `ev_81e095472a2ec62ccc070ef20aa7519b3b7e99239dd849364ea93d293084a20a`
- Probe sweep: `ev_532787203d927851d84ac34df09d462c0bc015e6770563c0eb6f758b67cc86f9`
- Wdf sweep: `ev_6eb8c0fa5850f9256e85e9585fac7df110af099df82f67b50db37e3fc1c6e810`
- StorPort sweep: `ev_0a153d9ec5019f2b8acaa2016dc5dd753c83ef580df267d52c810b85985ad763`
- mem sweep (finds in-binary `memcpy`): `ev_98a50919bfc847ba06eb880adf2563d08451b5e1e502f6e4143eae5508c3d052`
- copy sweep: `ev_28dbe4972daaf3c02d1b764cd0794cb55a4c7d51fb2553846ef3dd3d87491754`
- `(A;` SDDL search: `ev_40046e5f746428d8586544674a12eb604235a2e7408d7b4689c484ca06f8c386`
- `\Device\` strings: `ev_a5570767048f1077a18784f793ed41bf4365ad5e2ebe36655ab0d860c2419c1a`
- xrefs of in-binary `memcpy` `0x183F0`: `ev_1eee46ef6bc63f7d788b0213ebfdff26041c14596a4c13776e57e3960ee38d06`
