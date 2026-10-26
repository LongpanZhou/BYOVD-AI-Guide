# Audit: stexstor.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\stexstor.sys` |
| Recorded SHA-256 | `766FD1E1D2F73DE202FB337F6A6A5BA0317772AAAA644E9103BB5DF438162F51` (matches triage_index.csv row 77; verified before opening; REA reports the same digest) |
| Company/Version | Promise Technology, Inc., 5.1.0000.10 (triage row). StorPort miniport. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, **short-form** (no device object of its own; StorPort owns the device) |
| Verdict | **NO-WRITE (provisional, coverage-limited, ~25%)**. No in-file write primitive in the reviewed scope: no mapping, probe, device, or CPU-copy import. The one dynamic lookup resolves a registry-configured read into a fixed 4-byte global |
| Coverage | ~25%. Reviewed: import and string sweeps; the StorPort init routine `FUN_00011984` (StorPortInitialize setup, its dynamic lookup, and its registry read). Not reviewed: the miniport callbacks (HwFindAdapter, HwStartIo, HwInterrupt, HwAdapterControl, others), the callers of the unnamed memset-like helper `FUN_00014A30`, and the configuration helper `FUN_00012C6C` |

> **Static-only.** No load, no device open, no SRB or IOCTL issued. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- No device object of its own: no `Io*` imports, no `\Device\` string, no `(A;` SDDL string. StorPort creates the adapter and disk devices.
- Reached through StorPort as SRBs from the storage stack. User mode reaches the miniport through the SCSI port device (IOCTL_SCSI_MINIPORT → `HwAdapterControl` (or `HwBuildIo`; verify per driver)) and through SCSI pass-through to the disk device. Neither ACL is traced in-file, so an admin gate is not established. The `HwAdapterControl` (or `HwBuildIo`; verify per driver) path is not reviewed (open item).
- StorPort imports (13): `StorPortGetUncachedExtension`, `StorPortReady`, `StorPortInitialize`, `StorPortGetPhysicalAddress`, `StorPortStallExecution`, `StorPortSetBusDataByOffset`, `StorPortBusy`, `StorPortSetDeviceQueueDepth`, `StorPortGetDeviceBase`, `StorPortDeviceReady`, `StorPortGetScatterGatherList`, `StorPortGetBusData`, `StorPortNotification`.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Kernel mapping or MDL built by the driver | None. Its only `Mm` import is `MmGetSystemRoutineAddress` | `ev_2385ab4a…` (Mm sweep) |
| Probe, WDF, and device-object APIs | None | `ev_c387586f…` (Probe), `ev_71c65c06…` (Wdf), `ev_969b83a7…` (Io) |
| CPU copy primitives | None imported (`mem` and `copy` sweeps empty) | `ev_cfd4399d…` (mem), `ev_822a2dcd…` (copy) |
| Dynamic lookup `MmGetSystemRoutineAddress` | Call site `0x11A8A` in `FUN_00011984` resolves `RtlQueryRegistryValuesEx`, with the imported `RtlQueryRegistryValues` as fallback. `0x15020` is an IAT slot (RVA-like bytes), not a call. The resolved name is a registry query, not a write primitive | `ev_56a1aad5…` (xrefs), `ev_f4f01d44…` (resolve `0x11A8A`), `ev_0bdd09c5…` (resolve `0x15020`), `ev_aeedd455…` (bytes at `0x15020`) |
| Registry read in `FUN_00011984` | Queries value `RESET` under the service's `Parameters\Device` key as `REG_DWORD` (DefaultType 4, DefaultLength 4, `RTL_QUERY_REGISTRY_DIRECT`), writing into the fixed global `DAT_00016160`. Fixed size, so bounded. The registry input is configuration-control and out of scope | `ev_95d310aa…` (pseudocode of `FUN_00011984`) |
| Zeroing calls in init | `FUN_00014A30(…, 0, n)` with constant sizes (0xCC, 0x200, 0x70). The helper is unnamed, so name sweeps do not list it | `ev_95d310aa…` |

## Verdict rationale

NO-WRITE, provisional. Within the reviewed scope no write primitive takes an external length or address: no mapping, probe, copy, or device API is imported, and the one registry read is fixed-size. The miniport callbacks were not reviewed. The real trust boundary (SRB data and `HwAdapterControl` (or `HwBuildIo`; verify per driver)) sits there, so the verdict stays provisional. Escalate to WRITE-* if `HwAdapterControl` (or `HwBuildIo`; verify per driver), or any callback reached from SRBs, copies a length taken from SRB or CDB data into a fixed buffer without a bound.

## Open items

- Miniport callbacks, especially `HwAdapterControl` (or `HwBuildIo`; verify per driver) (SRB_IO_CONTROL via IOCTL_SCSI_MINIPORT, the one user-mode path into the miniport).
- Callers of the unnamed memset-like helper `FUN_00014A30`: count with xrefs and review the length arguments.
- Extension sizes computed by `FUN_00012C6C` (device, LU, and SRB extension) are not traced.
- Registry value `RESET`: configuration-control, out of scope, recorded only.

## VM confirmation plan (orchestrator-owned; VM only)

Hardware-gated StorPort miniport. The driver is stopped, and nothing here runs on the host. In a snapshot VM with the adapter present, a read-only check would show whether a non-admin can open the SCSI port device and whether IOCTL_SCSI_MINIPORT reaches `HwAdapterControl` (or `HwBuildIo`; verify per driver).

## Evidence (REA, retained IDs)

Sweeps: Mm `ev_2385ab4a9cd11da23c2e2b63c2c7ee14d22311d5c87b3a0b7a7c089e963460a8`; Io `ev_969b83a7e1f09c40a65c9c0c0c4fad8baff30811f755bdacc27f0cff858d4505`; Probe `ev_c387586f83c236551783c3cf927feb6c2426f266ea619ec23989a81facfad456`; Wdf `ev_71c65c0620d6fa83610cc6d7b6bf3581c22b851112e8cf46d7b8712214cf7a44`; StorPort `ev_c4556f469ffdfc06410873269c26a3234afb5993ceead9f9b02bb341cd8b4262`; mem `ev_cfd4399ddeef9fd41945cac8dd42fcba47219dd930881b2a11ae4ecd733ad32b`; copy `ev_822a2dcd4ec64c73099acf6f390f36ff3c57108103bdff2c5f456f9990356cb7`; `(A;` `ev_17df09eec53628892180d2a5de87aa9eb20c181825b8491958a1bf843d97f339`; `\Device\` `ev_6f381213f1b52d3ef545d778f1af9e8c3672fe089e0f6bb0ca827585c4be4710`.

Dynamic lookup and init: xrefs of `MmGetSystemRoutineAddress` `ev_56a1aad5e9578d2eb1518cef87802e3f56d364145bec3272613c297dfd413c66`; resolve `0x11A8A` `ev_f4f01d442362e4ccc3182112b117e1eb9ee51fe96482a0b8a756c9fe11c83e74`; resolve `0x15020` `ev_0bdd09c5c541a43b5ea098301e2087db702d80c2eac87e078e2644fa424ff4c1`; pseudocode `FUN_00011984` `ev_95d310aa6594b084266aa779359e432f9fe3f9969dda042b9d257121c80df053`; bytes at `0x15020` `ev_aeedd455c1abe2b75c85760e437c653636fdfcf195f6435d9c78f4a12af577c0`.
