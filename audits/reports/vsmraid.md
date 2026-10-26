# Audit: vsmraid.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\vsmraid.sys` |
| Recorded SHA-256 | `E70778AF6B0C9709CB8CEF655C6DD8B5A61CC70BFD35A43304C1308EA478C550` (matches triage_index.csv row 90; verified before opening; REA reports the same digest) |
| Company/Version | VIA Technologies Inc.,Ltd, 7.0.9600,6352 (triage row). StorPort miniport. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, **short-form** (no device object of its own) |
| Verdict | **NO-WRITE (provisional, coverage-limited, ~25%)**. No mapping, probe, copy, or device API is imported. The one open sink is the in-binary `memset` at `0x332C0`, which has 109 call sites whose length arguments were not reviewed |
| Coverage | ~25%. Reviewed: import and string sweeps; the call counts of the in-binary `memset` and `memcmp`. Not reviewed: the StorPort callbacks (including `HwAdapterControl` (or `HwBuildIo`; verify per driver)), the 109 `memset` call sites, and the `StorPortLogError` call sites |

> **Static-only.** No load, no device open, no SRB issued. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- No device object of its own: no `Io*` import, no `\Device\` string, no `(A;` SDDL string.
- Reached through StorPort as SRBs. User mode reaches the miniport through the SCSI port device (IOCTL_SCSI_MINIPORT → `HwAdapterControl` (or `HwBuildIo`; verify per driver)) and through SCSI pass-through to the disk device. Neither ACL is traced in-file, so an admin gate is not established. `HwAdapterControl` (or `HwBuildIo`; verify per driver) is not reviewed (open item).
- StorPort imports (16): `StorPortStallExecution`, `StorPortGetPhysicalAddress`, `StorPortInitialize`, `StorPortGetUncachedExtension`, `StorPortGetBusData`, `StorPortPause`, `StorPortBusy`, `StorPortLogError`, `StorPortGetDeviceBase`, `StorPortSetBusDataByOffset`, `StorPortPauseDevice`, `StorPortSynchronizeAccess`, `StorPortDeviceBusy`, `StorPortGetScatterGatherList`, `StorPortResume`, `StorPortNotification`.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Kernel mapping or MDL built by the driver | None (`Mm` sweep empty) | `ev_81e663f9…` (Mm sweep) |
| Probe, WDF, and device-object APIs | None | `ev_7c3f0108…` (Probe), `ev_d1f60aff…` (Wdf), `ev_49ce40cd…` (Io) |
| CPU copy primitives imported | None (`copy` sweep empty) | `ev_cf0e5d11…` (copy) |
| In-binary `memset` at `0x332C0` | 109 incoming references. Lengths not reviewed. Decisive: any caller whose length comes from SRB, CDB, or device data | `ev_bfadab49…` (mem sweep), `ev_a46ecb68…` (xrefs of `0x332C0`) |
| In-binary `memcmp` at `0x32E70` | Read-only; no write | `ev_bfadab49…` (mem sweep) |
| `StorPortLogError` | Logging only; call sites not reviewed | `ev_31ff6a7f…` (StorPort sweep) |

## Verdict rationale

NO-WRITE, provisional. No imported mapping, probe, or copy primitive exists, and the driver owns no device surface in-file. The one in-binary write primitive, `memset`, has 109 callers whose length arguments were not reviewed. An SRB- or device-derived length at any of them would make this a candidate. Escalate to WRITE-* on such a caller. The verdict would become a conclusive NO-WRITE if every caller uses a constant or struct-size length.

## Open items

- The 109 `memset` call sites (decisive): review length arguments.
- `HwAdapterControl` (or `HwBuildIo`; verify per driver) (SRB_IO_CONTROL, reached from user mode via IOCTL_SCSI_MINIPORT): not reviewed.
- `StorPortLogError` call sites: not reviewed (logging only; recorded).

## VM confirmation plan (orchestrator-owned; VM only)

Hardware-gated (stopped driver; not run). In a snapshot VM with the adapter present, a read-only check would show the SCSI port device ACL and whether IOCTL_SCSI_MINIPORT reaches `HwAdapterControl` (or `HwBuildIo`; verify per driver).

## Evidence (REA, retained IDs)

- Mm sweep: `ev_81e663f965350722891733f5b37577bf50bb6feadb9d356e8120d26ae2fa08b8`
- Io sweep: `ev_49ce40cd8554cac6f4840df2e9cf36426016a501eae09b7a6e7c93eefc97ed01`
- Probe sweep: `ev_7c3f01081c9dd08599e91055b6072c4af3530bce7ed0926065d8010f25819521`
- Wdf sweep: `ev_d1f60aff78b5f9291c5d97f1f59bf0abe177db53bd0d06ba6452a5f7664349b2`
- StorPort sweep: `ev_31ff6a7fca97a9465d895ac9f5c60fa8a3c170f43b3b381f7f8d8ad1a5096e38`
- mem sweep: `ev_bfadab49b67f153b4b7d185b9dc56db7a99f76bc6e9a47274084ebbba9b56cbe`
- copy sweep: `ev_cf0e5d11f3941c87f326debb78b089c1d214f720f5c125ee910de4e792a896cd`
- `(A;` SDDL search: `ev_b0c418a1637385b0763e1e581c525bd1fb3697862123689b68787bca9dfc80c9`
- `\Device\` strings: `ev_3a327d2ce301f385bbdf9b6aa394945b4ca6d603f6c6ff6df1d4c71dc7b23ae0`
- xrefs of in-binary `memset` `0x332C0`: `ev_a46ecb688a49b47f445ca524af9f15eb9cf7fbc3a86b6ad89124f6e02f00b8ac`
