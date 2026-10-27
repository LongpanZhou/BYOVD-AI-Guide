# Audit: mvumis.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\mvumis.sys` |
| Recorded SHA-256 | `69FBB0692C37DA498014CC6CDC609E612A3207A17B280EDE5C02248571F91F11` (matches triage_index.csv row 54; verified before opening; REA reports the same digest) |
| Company/Version | Marvell Semiconductor, Inc., 1.0.5.1016 (PART_L3.131021-1012) (triage row). StorPort miniport. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, **short-form** (no device object of its own; StorPort owns the device) |
| Verdict | **NO-WRITE (provisional, coverage-limited, ~25%)**. No mapping, probe, device, or CPU-copy import. The one in-binary write primitive, `memset`, has 12 call sites whose length arguments are not reviewed |
| Coverage | ~25%. Reviewed: import sweeps (Mm, Io, Probe, Wdf, StorPort, mem, copy), the `(A;` SDDL string search, and the call count of the in-binary `memset`. Not reviewed: the StorPort callbacks (including `HwAdapterControl` (or `HwBuildIo`; verify per driver)), the 12 `memset` call sites, and the `\Device\` string search (not run; device creation is covered by the import sweep, see Entry surface) |

> **Static-only.** No load, no device open, no SRB issued. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- **No device object of its own.** The Io sweep shows only `IoAllocateErrorLogEntry` and `IoWriteErrorLogEntry`. There are no `IoCreateDevice`, `IoCreateDeviceSecure`, `IoCreateSymbolicLink`, or `IoGetDeviceObjectPointer` imports, so the driver creates no device. No WDF. No SDDL (`(A;` search empty). The `\Device\` string search was not run.
- The driver is reached through StorPort (SRBs from the storage stack). Two user-mode paths exist: SCSI pass-through to the disk device, and IOCTL_SCSI_MINIPORT on the SCSI port device, which dispatches to `HwAdapterControl` (or `HwBuildIo`; verify per driver). Neither ACL is traced in-file, so admin gating is not established. `HwAdapterControl` (or `HwBuildIo`; verify per driver) was not reviewed.
- StorPort imports (11): `StorPortInitialize`, `StorPortExtendedFunction`, `StorPortGetScatterGatherList`, `StorPortGetUncachedExtension`, `StorPortGetPhysicalAddress`, `StorPortGetBusData`, `StorPortGetDeviceBase`, `StorPortNotification`, `StorPortCompleteRequest`, `StorPortSetDeviceQueueDepth`, `StorPortStallExecution`.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Kernel mapping or MDL built by the driver | None (no `Mm*` imports) | `ev_ee8e9ec7...` (Mm sweep) |
| Probe, device, and WDF APIs | None | `ev_ea508d6a...` (Probe), `ev_e984dcca...` (Wdf), `ev_7529ccea...` (Io) |
| CPU copy primitives imported | None (`mem` and `copy` sweeps have no imports) | `ev_d03ebc08...` (mem), `ev_fa8d1c22...` (copy) |
| In-binary `memset` at `0x15740` | 12 incoming references: `0x110FB`, `0x11141`, `0x11440`, `0x11BB2`, `0x12172`, `0x1396F`, `0x13F32`, `0x14019`, `0x1444F`, `0x14555`, `0x14BAF`, `0x1824C`. Lengths not reviewed. Decisive: any call whose length comes from SRB, CDB, or device data | `ev_ba8e7dcb...` (xrefs of `0x15740`) |
| SRB data and SGL lengths | Supplied by StorPort, bounded by the miniport's reported transfer limit (not verified). `StorPortGetScatterGatherList` is the path; not decompiled | `ev_0d490638...` (StorPort sweep) |
| Hardware-written completion data | Lengths and indices read back from hardware are the trust boundary. Not analysable statically | - |
| Admin gate on the SRB path | Not established (ACLs not traced) | - |

## Verdict rationale

NO-WRITE within the scope that static import recon can reach. There is no imported mapping, probe, or copy API, and the driver owns no device. The one in-binary write primitive, `memset`, has 12 call sites whose lengths are unreviewed. A call with an SRB- or device-derived length would make this a candidate. Escalate to WRITE-* on such a call. The real trust boundary is device-written completion data, which needs hardware-level analysis or a VM test with the adapter present.

## Open items

- The 12 `memset` call sites (decisive): review their length arguments.
- `HwAdapterControl` (or `HwBuildIo`; verify per driver) (SRB_IO_CONTROL, reached from user mode via IOCTL_SCSI_MINIPORT): not reviewed.
- Miniport-reported maximum transfer length, SRB handlers, and the hardware completion path.
- Disk and SCSI port device ACLs (the admin gate).

## VM confirmation plan (orchestrator-owned; VM only)

Hardware-gated (Marvell adapter). The driver is stopped, and nothing here runs on the host. In a snapshot VM with the adapter present: a read-only check of the SCSI port and disk device ACLs, and whether IOCTL_SCSI_MINIPORT reaches `HwAdapterControl` (or `HwBuildIo`; verify per driver).

## Evidence (REA, retained IDs)

`ev_ee8e9ec739d076acda9fcb1733ffb3ee89565524f0226714ae132bb5dca5639a` (Mm sweep), `ev_7529ccea5fb79033bf4f7c7089f26ae377ab6dfbe7e0c08d0ac203c40ede8a4e` (Io sweep: `IoAllocateErrorLogEntry`, `IoWriteErrorLogEntry` only), `ev_0d49063859168cc6a8a4ccf7d579e592fd6eba88798b97edea252b47345b381c` (StorPort sweep), `ev_ea508d6ad454be10a706f250b8b9ea0d4a45639be7c92d3c186f761a7ab2a63b` (Probe sweep), `ev_e984dcca90afa01cfbf4fd95853885d140b36e2d1b9f0dc2e87130a7c877d3bd` (Wdf sweep), `ev_6908527cc68d0f7630cff82def799d2f3ea32ab1f33203f001c1e2f80c96acb8` (`(A;` SDDL search), `ev_d03ebc08b6a95398a47440f0d6044e2905f6fb5878cc52bb273dbe3b03b00ae1` (mem sweep), `ev_fa8d1c22efae08b13ca62a9acbe3f24ffc4f59d7bd05d3ec166f06afcf43d52b` (copy sweep), `ev_ba8e7dcb952d6ea3733d9e340128cf1c8b55446d3947ae2af776216ec470d41b` (xrefs of `memset` at `0x15740`).
