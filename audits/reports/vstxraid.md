# Audit: vstxraid.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\vstxraid.sys` |
| Recorded SHA-256 | `33DAF53C81D5BAF9337192A84DF50C108BAE9B8A858081E2208939CCFF2622F8` (matches triage_index.csv row 89; verified before opening; REA reports the same digest) |
| Company/Version | VIA Corporation, 8.0.9200.8110 (triage row). StorPort miniport. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope. Kept short-form, but the driver publishes a user-openable device interface (see Entry surface), so the orchestrator should decide whether to move it to deep-form |
| Verdict | **NO-WRITE (provisional, coverage-limited, ~25%)**. The only in-file write primitive is `RtlCopyUnicodeString`, which is bounded by its destination. The published interface's IRP dispatch is not established in-file (no `IoCreateDevice`) |
| Coverage | ~25%. Reviewed: import and string sweeps; the interface registration `FUN_140010B38`; the call sites of `IoRegisterDeviceInterface` and `IoSetDeviceInterfaceState`; the interface GUID constant. Not reviewed: the StorPort callbacks (including `HwAdapterControl` (or `HwBuildIo`; verify per driver)), the StorPortNotification callbacks `FUN_14000D018` and `FUN_14000D33C`, the gate `FUN_14000A3A0`, the `RtlCopyUnicodeString` call sites, and any MajorFunction writes |

> **Static-only.** No load, no device open, no IOCTL, no SRB issued. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- **Published device interface.** `FUN_140010B38` (318 bytes) calls `StorPortExtendedFunction(8, adapter, …)` to obtain a PDO (identified from the call pattern; the meaning of extended function 8 is not verified in-file). It then calls `IoRegisterDeviceInterface(PDO, GUID, NULL, &symlink)` and `IoSetDeviceInterfaceState(symlink, TRUE)`. The class GUID is at `0x140045168`: **{4D36E97B-E325-11CE-BFC1-08002BE10318}**, decoded with read_bytes. From memory it matches the Windows SCSI-adapter setup-class family, but that is not verified in-file. The interface ACL (PDO default) is not traced, so user openability is likely but not established.
- No `IoCreateDevice` import. The Io sweep shows only the two interface calls. The in-file IRP dispatch is therefore not established, and MajorFunction writes were not traced. StorPort most likely owns FDO dispatch for this interface; that is an assumption to verify.
- The two `IoRegisterDeviceInterface` / `IoSetDeviceInterfaceState` call sites are `0x140010C2C` and `0x140010C3B`, both in `FUN_140010B38`. The other references (`0x140045030`, `0x140045028`) are not inside any procedure. They are presumably import-table slots, but their bytes were not checked.
- StorPortNotification callbacks registered in `FUN_140010B38`: `FUN_14000D018` and `FUN_14000D33C` (not reviewed).
- StorPort imports (14): `StorPortInitialize`, `StorPortResume`, `StorPortExtendedFunction`, `StorPortSetDeviceQueueDepth`, `StorPortPause`, `StorPortGetScatterGatherList`, `StorPortGetUncachedExtension`, `StorPortGetPhysicalAddress`, `StorPortGetDeviceBase`, `StorPortSynchronizeAccess`, `StorPortStallExecution`, `StorPortSetBusDataByOffset`, `StorPortGetBusData`, `StorPortNotification`. Each also appears as a thunk procedure in `.text`.
- The `HwAdapterControl` (or `HwBuildIo`; verify per driver) path (IOCTL_SCSI_MINIPORT through the port device) remains unreviewed.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Mm, Probe, Wdf, `\Device\`, `(A;` | None | `ev_670f338c…` (Mm), `ev_b289891c…` (Probe), `ev_8cd82cba…` (Wdf), `ev_fc940d43…` (`\Device\`), `ev_07df9768…` (`(A;`) |
| Device-interface APIs | `IoRegisterDeviceInterface` (one call site, in `FUN_140010B38`) and `IoSetDeviceInterfaceState` (one call site, same function). The interface is enabled unconditionally on success | `ev_9212fbad…` (Io sweep), `ev_38a2bffe…` (xrefs, `IoRegisterDeviceInterface`), `ev_f6bbbc87…` (xrefs, `IoSetDeviceInterfaceState`), `ev_b2d74ec8…` (resolve `0x140010C2C`), `ev_0c81f9c1…` (pseudocode `FUN_140010B38`) |
| CPU copy primitives | `RtlCompareMemory` only (a read). `RtlCopyUnicodeString` is a write, but it copies at most the destination's MaximumLength; its call sites are not reviewed | `ev_a8134a7d…` (mem sweep), `ev_18637978…` (copy sweep) |
| Interface GUID constant | Decoded as {4D36E97B-E325-11CE-BFC1-08002BE10318} | `ev_7f50c34c…` (bytes at `0x140045168`) |

## Verdict rationale

NO-WRITE, provisional. The one in-file write sink, `RtlCopyUnicodeString`, is bounded by its destination, and no owned dispatch is established in-file. The interface is likely user-openable, which is why this report flags it for the deep-form decision. If the interface's IRPs reach miniport code (through StorPort's routing or a MajorFunction write), its handlers must be reviewed. Escalate to WRITE-* if the interface or the `HwAdapterControl` (or `HwBuildIo`; verify per driver) path reaches a copy that takes a user-supplied length.

## Open items (decisive first)

1. MajorFunction writes and any dispatch assignment for the published interface. This decides whether any user IRP reaches this driver.
2. StorPort routing of IRP_MJ_DEVICE_CONTROL on the interface to the miniport (StorPort side; not in-file).
3. `HwAdapterControl` (or `HwBuildIo`; verify per driver) (SRB_IO_CONTROL via IOCTL_SCSI_MINIPORT): not reviewed.
4. `FUN_14000D018` and `FUN_14000D33C` (StorPortNotification callbacks): not reviewed.
5. `RtlCopyUnicodeString` call sites: destination sizes not reviewed. The copy itself is bounded.
6. Identity of the GUID is recalled from memory, not verified in-file.

## VM confirmation plan (orchestrator-owned; VM only)

Stopped driver with a hardware-gated path; not run. In a snapshot VM with the adapter present, a read-only check would cover the interface ACL (SetupDi or device properties) and whether a non-admin can open the interface. Open only; no IOCTLs.

## Evidence (REA, retained IDs)

- Mm sweep: `ev_670f338cae95976589cc62081ca1cd228e988753356e1ff7405fe116fa5a5e94`
- Io sweep: `ev_9212fbad18648a419fe33b8340d9cc3e4a1fae6aa341925240cc321ccf70acd4`
- Probe sweep: `ev_b289891c0fe6cde587b8d7c9eabb58f7bc924652705fba49d8ca4a8301752804`
- Wdf sweep: `ev_8cd82cba29af64dc96df4fa44d1dc37fa22ff2129c77e0be88e145bdaaa5d551`
- StorPort sweep: `ev_583364e38cb9de2c2c4f75e631d55784286b11f4b69c05bc518f06dbe7369f98`
- mem sweep: `ev_a8134a7d21870557011c157ebdc6f4d390b62c2d459e89e23a144c27d8bdd4a1`
- copy sweep: `ev_18637978dfeebef54b069b556b1a50dd466bdef8c2a06bb458b826bef136f2c1`
- `(A;` SDDL search: `ev_07df976845e6d5153c3939e92af69e8e3fdf2a2443bff67c24539d237bfd8765`
- `\Device\` strings: `ev_fc940d434fefba3102b9b4bd98e2fe53ed599be7a8d9136cbbb9a2faaff01003`
- xrefs of `IoRegisterDeviceInterface`: `ev_38a2bffe9283f4d88fccf842d1bddf73a6f439ee6d3dd2bb06818785458dd82d`
- xrefs of `IoSetDeviceInterfaceState`: `ev_f6bbbc8770cb4cc7fa6201bf991f7bb4b4d35d0f572ec9a47727d0c0923e16e7`
- resolve `0x140010C2C` (in `FUN_140010B38`): `ev_b2d74ec84ddf9072ea844c4be8cce49187c317644499395289e7775c35fa18ef`
- resolve `0x140045030` (not in a procedure; presumed import-table slot): `ev_0f0229a70fabd8a5128bb9a40fd448c0b3585258bc6bb14d56e7e4245c5dfcf2`
- pseudocode `FUN_140010B38`: `ev_0c81f9c1a71f2f4c5e4ae3a7c9d4c1bf80881145508f08ca485f7e970f17df81`
- bytes at `0x140045168` (GUID): `ev_7f50c34c2e58fcd88169ce122b7550858785b1554737c3065bf929d957714215`
