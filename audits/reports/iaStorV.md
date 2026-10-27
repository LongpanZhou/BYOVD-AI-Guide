# Audit: iaStorV.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaStorV.sys` |
| Recorded SHA-256 | `30BEE94794953E2DBF0FC5AFCE0566F335AF022E89819DE145329E7C09C636BD` (matches triage_index.csv row 43; verified before opening; REA reports the same digest) |
| Company/Version | Intel Corporation, 8.6.2.1019 (triage row). Non-StorPort storage driver: creates its own device objects (`\Device\Ide\iaStor%d`, `\Device\ScsiPort%d`, `\Device\Ide\IAAStorageDevice-%d`) and serves SCSI pass-through IOCTLs. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, **deep-form**: a user-openable device (`IoCreateDevice`, `IoCreateSymbolicLink`, `IoRegisterDeviceInterface` imported) and an IOCTL dispatch with user-buffer sinks |
| Verdict | **WRITE-HIGH (conditional, coverage-limited, ~30%)**. Two in-file sinks write zeros at an unchecked offset from the IOCTL system buffer: the DIRECT pass-through sense zero-fill (32-bit offset) and the non-direct data zero-fill (64-bit offset, with a wrapping bounds check). Both are behind one gate, `MinorFunction == 1` (IRP_MN_SCSI_CLASS). A standard user IOCTL carries MinorFunction 0 and is rejected before any write. User reach therefore depends on the unreviewed MajorFunction table and on the device ACL |
| Coverage | ~30%. Reviewed: IOCTL dispatch `FUN_0005c084` (switch structure), DIRECT pass-through `FUN_0005e300` (full), non-direct pass-through `FUN_0005dcf0` (full, excluding the `FUN_0005f908` gate), MDL helper `FUN_0005e968`, memset `FUN_00067410`, device creation `FUN_000582a8`, import and string sweeps. Not reviewed: DriverEntry and the MajorFunction table (decisive for reachability), `FUN_0005f908`, `FUN_0005d198` (IOCTL_SCSI_MINIPORT 0x4D008), `FUN_0005db80` (0x4100C), `FUN_0005daa0` (0x41020), `FUN_0005ec58` (0x4D02C), `FUN_0005f27c` (0x4D030), `FUN_0005ea28` (0x70000), `FUN_0005c4ac` (0x2D1400), `FUN_00040138` (0xC3512010), `FUN_0005eb8c` (0xC3512018), SRB helpers (`FUN_0005a3cc`, `FUN_00066884`, `FUN_000669f4`, `FUN_0003eb2c`, `FUN_00062cfc`), other `MmMapLockedPagesSpecifyCache` sites (`0x40296`, `0x40332`, `0x5c02b`, `0x5f3f5`, `0x6a190`), `MmMapIoSpace` sites, `IoRegisterDeviceInterface` call sites, and the device ACL |

> **Static-only.** No load, no device open, no IOCTL sent, no IRP built. Addresses are REA default-space linked VAs (image base 0x140000000). The REA session was shared with another agent that switched targets repeatedly. Every result whose subject digest was not iaStorV was discarded; no fact below comes from a foreign-digest result.

## Entry surface

- **User-openable device.** `IoCreateDevice` is called from `FUN_000582a8` (site `0x5830e`) with `Exclusive = FALSE` and no SDDL argument, so the device gets the default device security (not traced in-file). `IoCreateSymbolicLink` and `IoRegisterDeviceInterface` are imported (call sites not reviewed). Device-name strings: `\Device\Ide` (`0x68c00`), `\Device\Ide\iaStor%d` (`0x68c20`), `\Device\ScsiPort%d` (`0x68ce0`), `\Device\Ide\IAAStorageDevice-%d` (`0x694c0`).
- **IOCTL dispatch.** `FUN_0005c084` (1056 bytes, `SpIoCtl` messages) takes `IoControlCode` from the stack location (+0x18) and switches on it. Values by CTL_CODE (names not in the binary): `0x4D004` (IOCTL_SCSI_PASS_THROUGH) -> `FUN_0005dcf0`; `0x4D014` (IOCTL_SCSI_PASS_THROUGH_DIRECT) -> `FUN_0005e300`; `0x4D008` (IOCTL_SCSI_MINIPORT) -> `FUN_0005d198`; `0x41018` (IOCTL_SCSI_GET_ADDRESS) reviewed in part; `0xC3512014` copies 0x54 bytes into a driver global after a length check (bounded).
- **MinorFunction gate.** Both pass-through handlers return STATUS_INVALID_PARAMETER (0xC000000D) unless the stack-location byte at +1 (MinorFunction) equals 1. In the local WDK header `km\wdm.h` line 30832, `IRP_MN_SCSI_CLASS` is `0x01`. Ordinary IRP_MJ_DEVICE_CONTROL requests carry MinorFunction 0 and are rejected before any write.
- **MDL and mapping.** `MmProbeAndLockPages` (one site, `0x5e9d5`, in `FUN_0005e968`) and `MmMapLockedPagesSpecifyCache` (several sites) are imported, with `IoAllocateMdl`/`IoFreeMdl`. These serve the DIRECT pass-through data buffer.
- **Admin gate.** Not traced in-file (the device ACL).

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| DIRECT pass-through, sense zero-fill (`FUN_0005e300`, IOCTL 0x4D014) | Builds the request, then `memset(SysBuf + SenseInfoOffset, 0, SenseInfoLength)`. `SenseInfoOffset` is a ULONG at +0x20 (SCSI_PASS_THROUGH_DIRECT layout); the only check is a lower bound (>= 0x38). `SenseInfoLength` is a byte at +7 (<= 255). No check that offset + length fits the buffer. Unbounded 32-bit offset, zero fill. The zero-fill is not gated by `FUN_0005f908` | `ev_18c2c360...` (pseudocode), `ev_95b13853...` (memset semantics) |
| Non-direct pass-through, data zero-fill (`FUN_0005dcf0`, IOCTL 0x4D004) | Completion path (`CDB[0] == 0x28`, dev+0xf48 == 2, and `FUN_0005f908` returns 0) calls `memset(SysBuf + DataBufferOffset, 0, DataTransferLength)`. `DataBufferOffset` is a 64-bit ULONG_PTR at +0x18. `DataTransferLength` is bounded by the device limit (dev+0xecc). For DataIn == 1, the bounds check is `OutputBufferLength < DataTransferLength + DataBufferOffset`, computed in 64-bit arithmetic, so it can wrap | `ev_474e33f6...` (pseudocode), `ev_95b13853...` |
| Gate (both pass-through handlers) | Returns STATUS_INVALID_PARAMETER unless MinorFunction == 1 (IRP_MN_SCSI_CLASS). A user IRP_MJ_DEVICE_CONTROL carries 0, so in-file user reach is not established | `ev_18c2c360...`, `ev_474e33f6...`; WDK `km\wdm.h` line 30832 (local read, not REA) |
| IOCTL dispatch (`FUN_0005c084`) | Switch on IoControlCode. GET_ADDRESS writes 8 bytes after a length check. 0x41010 writes 0x18 bytes after length checks. 0xC3512014 copies a fixed 0x54 bytes into a driver global after a length check (bounded) | `ev_db140605...` (pseudocode) |
| MDL and mapping for DIRECT data buffer (`FUN_0005e968`, `FUN_0005e300`) | `IoAllocateMdl` on the user buffer, then `MmProbeAndLockPages(mdl, AccessMode, ...)`. The mapping call `MmMapLockedPagesSpecifyCache(..., KernelMode?, ...)` is in `FUN_0005e300`. Length is `DataTransferLength`, bounded by the device limit. AccessMode and mapping mode not confirmed | `ev_3afd6e9d...` (resolve), `ev_656f4d0d...` (pseudocode), `ev_b499c7d6...` (MmProbeAndLockPages xrefs), `ev_4095cdc9...` (MmMapLockedPagesSpecifyCache xrefs) |
| Device creation (`FUN_000582a8`) | `IoCreateDevice(DriverObject, extSize, \Device\..., DeviceType, DeviceCharacteristics, FALSE, &dev)`, default security, no SDDL. Device extension fields set from the stack name | `ev_cc582752...` (resolve), `ev_694d4936...` (pseudocode), `ev_af67b0f1...` (xrefs) |
| Other IOCTL handlers (0x4D008, 0x4100C, 0x41020, 0x4D02C, 0x4D030, 0x70000, 0x2D1400, 0xC3512010, 0xC3512018) | Not reviewed | - |
| Other `MmMapLockedPagesSpecifyCache` / `MmMapIoSpace` sites | Not reviewed | `ev_4095cdc9...` (xrefs) |

## Verdict rationale

WRITE-HIGH, conditional. The in-file write is genuine and unbounded. Two independent sinks zero-fill at an offset that the handler never checks against the buffer: a 32-bit offset in the DIRECT pass-through (IOCTL 0x4D014) and a 64-bit offset with a wrapping bounds check in the non-direct pass-through (0x4D004, DataIn == 1). Both are behind one gate, `MinorFunction == 1` (IRP_MN_SCSI_CLASS). A standard user IOCTL carries MinorFunction 0 and is rejected with STATUS_INVALID_PARAMETER before either write, so user-mode reach is not established in-file. Reach depends on three unreviewed conditions: (a) the MajorFunction table (DriverEntry), and whether any user request is re-stamped or forwarded with MinorFunction 1; (b) for the non-direct path, `FUN_0005f908` and dev+0xf48 == 2; (c) the device ACL on `\Device\Ide\iaStor%d` (default security, not traced). Coverage is about 30%.

Escalate to **WRITE-CRITICAL** if a user-mode request can reach `FUN_0005c084` with MinorFunction 1 (through the MajorFunction table, a re-stamping dispatch, or a class driver that forwards user buffers) and the device ACL admits non-admin callers.

Drop to **NO-WRITE** if MinorFunction 1 is produced only by kernel IRP_MN_SCSI_CLASS requests with kernel-owned buffers, and the MajorFunction table routes user IRP_MJ_DEVICE_CONTROL away from `FUN_0005c084`.

## Open items

1. **Decisive:** DriverEntry and the MajorFunction table. Which major function(s) reach `FUN_0005c084`, and whether any path sets MinorFunction to 1 for a user request.
2. Producers of MinorFunction 1 (IRP_MN_SCSI_CLASS): the class-driver path, and whether user IOCTL buffers are forwarded with that minor.
3. `FUN_0005f908` (gate for the non-direct memset) and the device state dev+0xf48.
4. The 64-bit wrap in the non-direct DataIn == 1 bounds check (reachability not established).
5. `FUN_0005d198` (IOCTL_SCSI_MINIPORT, 0x4D008) and the other unreviewed IOCTL handlers listed in the Coverage row.
6. Device ACL on `\Device\Ide\iaStor%d` and any interface GUID (IoCreateDevice default security; `IoRegisterDeviceInterface` call sites not reviewed).
7. SRB helpers, the other `MmMapLockedPagesSpecifyCache` and `MmMapIoSpace` sites.

## VM confirmation plan (orchestrator-owned; VM only)

Not runnable on the host (stopped driver, admin-gated device). In a snapshot VM with Driver Verifier special pool enabled for `iaStorV.sys`:
1. Confirm the MajorFunction routing with a debugger breakpoint on `FUN_0005c084` (not on the host). Send a user-mode IOCTL_SCSI_PASS_THROUGH_DIRECT (0x4D014) and record the MinorFunction and returned status (expected 0xC000000D per the in-file gate).
2. From a kernel test harness only, send IRP_MN_SCSI_CLASS (MinorFunction 1) with a 0x38-byte header, SenseInfoLength 16, and SenseInfoOffset 0x1000 in a 0x48-byte buffer. A special-pool fault would confirm the out-of-buffer zero-fill.
3. Repeat with the non-direct 0x4D004 path, DataIn 1, and DataBufferOffset near 2^64 to test the wrapping bounds check.

Run only in the VM, by the orchestrator.

## Evidence (REA, retained IDs)

- `ev_481e3d5445d25316f31ea87c992cd87887e4a9216561c55fb65c1a13a1e2cb98` (`Mm` sweep: MmProbeAndLockPages, MmMapLockedPagesSpecifyCache, MmMapIoSpace, MmUnmapIoSpace, MmIsAddressValid, MmGetPhysicalAddress)
- `ev_26f6c074ac0cb0fbd2d9f6f871e26b007422af02cc0555b2f61709423bc869ad` (`Io` sweep: IoCreateDevice, IoCreateSymbolicLink, IoRegisterDeviceInterface, IoAllocateMdl, IoConnectInterrupt, IofCallDriver, and others)
- `ev_75475b98169d8ecbd248199e140c370cc54ab402d744432bc28d346c20a99f06` (`Wdf`, empty)
- `ev_d4df2a9d542d7d995e4b05586eb0ea3e7aac3581d7f8e61fc5f2dd73581ca578` (`StorPort`, empty)
- `ev_eddab09b2e69df36ed2c8ad809442b659219810de816fed9490801689434a494` (`Probe`: MmProbeAndLockPages)
- `ev_8aa7ace3d9a8c324002e872737be31408442bf38abc097fb3e057925c7df3421` (`mem`: RtlCompareMemory, memcpy)
- `ev_cebc6ed8627cc2ab4d70a87f4ea01953792c3c9515cd661cd7b85f4a056a2906` (`copy`: RtlCopyUnicodeString)
- `ev_3e450ada02c32220d507e33d32961e061f8cb7567cb7bfc2754db0f994dec67b` (`(A;`, empty)
- `ev_70361abc42b69de4ea72aacfa19c6c5d5139daf582ee85a047880b218e18d59d` (`\Device\` strings, four hits)
- `ev_b499c7d6bfb754946ab0ec484ded77f959611da6cb28ed11ad1dfbb347c0c9dc` (xrefs of MmProbeAndLockPages: 0x5e9d5, 0x6a358)
- `ev_4095cdc9ccd0ca398f7f0c36596d8baaa0706aaf6dc4057a47eecdc84f7f4ce7` (xrefs of MmMapLockedPagesSpecifyCache: 0x40296, 0x40332, 0x5c02b, 0x5e5cd, 0x5f3f5, 0x6a190)
- `ev_af67b0f1aff81a70cf91bb25ea45fbc240a7dd564e7d07b5d072ea97718fa15e` (xrefs of IoCreateDevice: 0x5830e, 0x6a2e0)
- `ev_3afd6e9d8004be39d70cb23db154a5d1b2a4a6660987643e071f604c2a23095a` (0x5e9d5 -> FUN_0005e968)
- `ev_01ab679849e3406fdd5d30853690d72ca58d6e6c378d9390d7eb000b0d33c9db` (0x5e5cd -> FUN_0005e300)
- `ev_cc58275216c6525a25fb4bdacdccffc97309c6588f3d321b7620a491d8ae97ad` (0x5830e -> FUN_000582a8)
- `ev_18c2c3603d0e77025a266a5e6b793d0da53f3724387d0f47494a51696732ec3c` (pseudocode FUN_0005e300, DIRECT pass-through)
- `ev_656f4d0d78bf04708918f849aa0fdbda25f8a8049c12fb937b116998d81fd0c9` (pseudocode FUN_0005e968)
- `ev_694d4936a29fdba4f07fbd56f53174f4d08b0c25b11ce08d7231af70c8c26ae8` (pseudocode FUN_000582a8)
- `ev_3e1927fbe7ba7bbd9217f7f3309874e14175523cbf0af3655715edc5a0ce1f01` (callers of FUN_0005e300: 0x5c084)
- `ev_95b13853139354a906842927b2c2bb9c8d89045cc6a4b3d66f9f607c8f8765ff` (pseudocode FUN_00067410, memset semantics)
- `ev_b5d003adcde2970a451066a2a7a77c7f01b320d77b8dcc2cb4130155346a2592` (0x5c084 -> FUN_0005c084)
- `ev_db140605d7fab23fd7c4aeb45d33f1b8b60cfdd8f22644e7f67badc1ee603292` (pseudocode FUN_0005c084, IOCTL dispatch)
- `ev_474e33f61c2f091262c958efb5d6f9fa7832701f7d084d02dc574f6c1cbce5b5` (pseudocode FUN_0005dcf0, non-direct pass-through)
- Local WDK reads (not REA evidence): `km\wdm.h` line 30832 (`IRP_MN_SCSI_CLASS 0x01`); `shared\ntddscsi.h` (IOCTL_SCSI_PASS_THROUGH, _DIRECT, IOCTL_SCSI_MINIPORT via CTL_CODE; SCSI_PASS_THROUGH_DIRECT layout, lines 152-166).
- Triage row check: Grep on the SHA returned triage_index.csv line 43.
