# Audit: HpSAMD.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\HpSAMD.sys` |
| Recorded SHA-256 | `0ADE20523619D5705B941591DF0C19D6B0030F96FECEBBC7A4ADEF963A476383` (matches triage_index.csv row 31; verified before opening; REA reports the same digest) |
| Company/Version | Hewlett-Packard Company, 8.0.4.0 Build 1 Media Driver (x86-64) (triage row). StorPort miniport for HP Smart Array SAS/SATA controllers (the driver's own string: "Smart Array SAS/SATA Controller Media Driver"). Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, **deep-form**. StorPort miniport: the SRB_IO_CONTROL path reachable through IOCTL_SCSI_MINIPORT was reviewed in part (dispatcher, two CSMI handlers, the device-level gate, and the HwAdapterControl callback) |
| Verdict | **WRITE-MEDIUM (conditional, coverage-limited, ~35%)**. Two SRB_IO_CONTROL handlers bound their stores with the caller-supplied `SRB_IO_CONTROL.Length` and then store past the bound that check implies. Worst case: a 28-byte zero or constant write past the end of the IOCTL buffer. Conditions: the IOCTL path is admin-gated (ACL not traced), the device-level gate at `+0x9e60` passes, and StorPort passes a buffer sized from the caller |
| Coverage | ~35%. Reviewed: DriverEntry `FUN_00011008`, HwAdapterControl `FUN_00014480`, HwStartIo dispatch `FUN_000117d8`, CPQCISS handler `FUN_0001670c`, CSMIALL handler `FUN_00016c80`, gate `FUN_00017f5c`. Not reviewed: CPQCSMI handler `FUN_000165a0`, CSMISAS handler `FUN_00016e10`, CC2/CC4 subhandlers `FUN_00016858`, `FUN_00016a54`, `FUN_00016f2c`, SRB and queue helpers, HwBuildIo `FUN_000110e4`, HwInterrupt `FUN_00013018`, HwFindAdapter `FUN_00014624`, HwResetBus `FUN_000189f0`, HwInitialize `FUN_000152c8`, and the callers of the memset helper at `0x1b440` |

> **Static-only.** No load, no device open, no IOCTL sent, no SRB issued. Addresses are REA default-space values (image-relative), not linked VAs. The REA session was shared with another agent that switched targets repeatedly. Every result whose subject digest was not HpSAMD was discarded and the target re-opened; no fact below comes from a foreign-digest result.

## Entry surface

- **No device object of its own.** The `Io` sweep is empty. No `IoCreateDevice`, `IoCreateSymbolicLink`, or `IoGetDeviceObjectPointer` import, no `\Device\` string, no SDDL, no WDF. The port device is created by storport.sys.
- **DriverEntry** is `FUN_00011008`. It memsets a 0xd0-byte `HW_INITIALIZATION_DATA` and calls `StorPortInitialize(DriverObject, RegistryPath, &hwInit, 0)`. The layout was matched to the second `HW_INITIALIZATION_DATA` definition in the local WDK header `C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km\storport.h` (line 10864; a local file read, not REA evidence). Callbacks: HwInitialize `FUN_000152c8` (+0x08), HwStartIo `FUN_000117d8` (+0x10), HwInterrupt `FUN_00013018` (+0x18), HwFindAdapter `FUN_00014624` (+0x20), HwResetBus `FUN_000189f0` (+0x28), **HwAdapterControl `FUN_00014480` (+0x78)**, **HwBuildIo `FUN_000110e4` (+0x80)**. DeviceExtensionSize 0xa0a8, SrbExtensionSize 0x1148, AdapterInterfaceType 5 (PCIBus).
- **Admin gate.** IOCTL_SCSI_MINIPORT on the port device. The ACL is set by storport and was not traced in-file.
- **Imports.** 23 STORPORT functions. No `Mm*`, no `Probe*`, no `Io*`, no WDF. The only `mem` hit is a local `memset` at `0x1b440`.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Kernel mapping, MDL, or probe | None. No `Mm*` or `Probe*` procedures or imports | `ev_87f7ce2c…` (`Mm`, empty), `ev_5e3783ea…` (`Probe`, empty) |
| Caller-controlled kernel address | None in the reviewed code. Stores go through device-extension pointers set at init | `ev_3868cd52…` |
| HwAdapterControl, ControlType 0 | Writes the Parameters buffer at fixed offsets +4, +6, +8. No caller length read | `ev_3868cd52…` |
| HwAdapterControl, ControlType 1 | Read-modify-write (`|= 1`) through up to 4 device-extension pointer slots; index guarded by `< 4`. Indirect call through dev+0x50 | `ev_3868cd52…` |
| HwStartIo dispatch, SRB function 2 | Reads the 8-byte CSMI signature from the IOCTL buffer. Writes ReturnCode (buffer+0x14) at a fixed offset. Requires a buffer of at least 0x18 bytes, which is not checked in-file | `ev_6d0ef31c…` |
| CPQCISS handler `FUN_0001670c` | CC1 writes 8 bytes at +0x1f; CC3 writes 3 bytes at +0x24..+0x26. Both gated by Length ≥ 12, extent ≤ 0x27, inside the claimed 28+Length. Overflow needs an IOCTL buffer smaller than the claimed size, which the code does not check (up to 8 bytes) | `ev_547bbc57…` |
| CSMIALL handler `FUN_00016c80`, CC3 | `memset(+0x1c, 0, 0x24)` gated only by Length ≥ 8. Store extent reaches +0x40, against a claimed end of 28+Length. Overflow of up to **28 bytes** (zero fill) when Length < 36, even for a buffer sized exactly to the claim | `ev_338298f6…` |
| CSMIALL handler, CC1 | DWORD stores at +0xbe, +0xc2, +0xc6 (extent +0xca) plus two driver-string copies at fixed offsets. Gated by Length ≥ 0x92, claimed end 0xae. Overflow of up to **28 bytes** with a buffer sized exactly to the claim | `ev_338298f6…` |
| Gate `FUN_00017f5c(dev, 4, 0, CC)` for CC 1–4 | Passes only when dev+0x9e60 ≤ 2. The value is set outside this file | `ev_35bb164d…` |
| CSMIARY and CSMIPHY (inline in HwStartIo) | Fixed-offset ReturnCode writes only, gated by the same FUN_00017f5c | `ev_6d0ef31c…` |
| CPQCSMI `FUN_000165a0`, CSMISAS `FUN_00016e10`, CC2/CC4 subhandlers | Not reviewed | — |
| HwBuildIo, HwInterrupt, HwFindAdapter, HwResetBus, HwInitialize | Not reviewed | — |
| memset helper `0x1b440` callers | Not counted; not reviewed | `ev_f950d909…` (`mem`) |

## Verdict rationale

WRITE-MEDIUM, conditional. The overflow is real in-file. Two SRB_IO_CONTROL handlers gate their stores on the caller-supplied `SRB_IO_CONTROL.Length` (+0x18), then store beyond the bound that the gate implies. The CSMIALL CC3 path is self-contained: the memset extent (+0x40) exceeds the Length-8 claim (+0x24). The CSMIALL CC1 path is self-contained too: the extent (+0xca) exceeds the Length-0x92 claim (+0xae). Both overflow by up to 28 bytes with zero fill or driver constants, so the write is bounded in size and not attacker-chosen in content. Reachability depends on three conditions: (a) the IOCTL_SCSI_MINIPORT path is admin-only (ACL not traced); (b) dev+0x9e60 ≤ 2 (set by hardware or init, not traced); (c) StorPort passes an IOCTL buffer sized from the caller (not verified).

Escalate to **WRITE-HIGH** if the port device ACL allows non-admin callers, or if the unreviewed CPQCSMI (`FUN_000165a0`) or CSMISAS (`FUN_00016e10`) handler copies with a Length-derived size into the same buffer.

Drop to **NO-WRITE** if StorPort enforces a minimum IOCTL_SCSI_MINIPORT buffer of 0xca bytes (which covers both CC1 and CC3), or if the device gate at dev+0x9e60 is shown to be above 2 on all shipping hardware, which makes CC1–CC4 unreachable.

## Open items

1. Review `FUN_000165a0` (CPQCSMI) and `FUN_00016e10` (CSMISAS) for copy lengths taken from the SRB_IO_CONTROL header. These are the decisive unreviewed sinks.
2. Confirm whether storport.sys enforces a minimum buffer for IOCTL_SCSI_MINIPORT (drop condition) and whether SRB DataTransferLength equals the IOCTL buffer size (escalation condition).
3. Source of the value at dev+0x9e60, which gates CC1–CC4 through `FUN_00017f5c`.
4. Port device ACL (the admin gate).
5. Two references to the StorPortInitialize IAT slot (`0x101d0`, `0x10224`) lie outside any Ghidra procedure and were not decoded. If they are live calls with a different HW_INITIALIZATION_DATA, the callback set above is incomplete.
6. Not reviewed: HwBuildIo `FUN_000110e4`, HwInterrupt `FUN_00013018`, HwFindAdapter `FUN_00014624`, HwResetBus `FUN_000189f0`, HwInitialize `FUN_000152c8`, and the callers of the memset helper `0x1b440`.

## VM confirmation plan (orchestrator-owned; VM only)

Hardware-gated (HP Smart Array). Not runnable on the host (stopped driver, admin-gated IOCTL). In a snapshot VM with Driver Verifier special pool enabled for `HpSAMD.sys`, and an attached Smart Array controller or a stub adapter:
1. IOCTL_SCSI_MINIPORT with signature `CSMIALL`, ControlCode 3, Length 8, in a 36-byte buffer. A special-pool fault would show the 0x24-byte memset overrunning the buffer.
2. The same with ControlCode 1, Length 0x92, in a 174-byte buffer. This exercises the DWORD stores at +0xbe, +0xc2, +0xc6.
3. A 28-byte IOCTL buffer, to find whether StorPort rejects undersized buffers (the drop condition).

Run only in the VM, by the orchestrator. Nothing here is to be run on the host.

## Evidence (REA, retained IDs)

- `ev_87f7ce2c2dc5a2ff407c8567612551fcd2db935c8b8f3b27915214523819c73e` (`Mm`, empty)
- `ev_e8b5f13cb9e1252c875157b66c2bc736674cc0ac702bda23e788a805ae48dde3` (`Io`, empty)
- `ev_92749afa2829851687c0a7ab85fc4447a56d030f15bf8bc422f18496f16a4e79` (`Wdf`, empty)
- `ev_0168f4264c50e8b4cdf4d5b69c113a473668524a11965667cc1d61db440b12e2` (`StorPort`, 23 imports)
- `ev_5e3783ea4fa203f8d3f7d0724367aa07de4d4816f69b6f4938102524365cc4ef` (`Probe`, empty)
- `ev_f950d90950c582ff51dfd8d4e5759fbd45b170ea325d335946256eedab0602d7` (`mem`, `memset` at 0x1b440 only)
- `ev_99929f73d614ae8be087c4d7f777453fbc6ed7fa5c03480675503d20b9d774f6` (`copy`, empty)
- `ev_aa417e57421457b03d06d9dfd5a5c025f6c36ee7393c74a94bd59d6d5ea636b4` (`(A;`, empty)
- `ev_081b2ebda2519a526e802e6b705601d5e7846e29dc9ea7888c364cdb6ac58b1f` (`\Device\`, empty)
- `ev_07c94000fd76b7b32c3b3b2307bbc6acf948d08b36fe25de99545fb8b19d50fc` (xrefs of `STORPORT.SYS::StorPortInitialize`: 0x110c2, 0x1c000)
- `ev_fc780a2ea28c72fac42b391e092abfd26ba2b4e8d5c8f008c55cdff5e2dcd953` (xrefs of 0x1c000: 0x101d0, 0x10224, 0x110c2)
- `ev_86236775f95f7436cc42a38a30710a77c41cefca933aac1f00c815fb3be2271f` (bytes at 0x1c000, IAT name RVAs)
- `ev_a5e1ed992bc58ff5dd3eb08e47e78429f14f597d0e1ea4ec8bb03edf85e5902b` (0x110c2 → FUN_00011008)
- `ev_412fb4ff57c46d0ab1fa4ee53c7e21a617eb70ba582482c4946847ac7e098352` (0x101d0 → not in a procedure)
- `ev_0335a82a990f6984c5c389775273ed2bb6d85c82414a5afa5c951a62520673ef` (0x10224 → not in a procedure)
- `ev_9f0956c4bcfc0195ccfab836c028c5303aae95fa9f79a263bc10bbfbd60d14ad` (bytes at 0x101c0)
- `ev_b55f86b8ff9f439ae6f31e4ccdbf5cf2b9fe5bbc23ebd473bec6082d08d38974` (DriverEntry FUN_00011008)
- `ev_3868cd52178d5624fc32bc126a48ee71695c1086f280655ec70b9ebb4ae83833` (HwAdapterControl FUN_00014480)
- `ev_6d0ef31c5b9eb35fb02bc6796d5b1d1516b1a79b1c7f23f505a8717e44814263` (HwStartIo FUN_000117d8)
- `ev_547bbc5722409491e286a35f373c85a03763b36011d1a3fedec51761d89d22b2` (CPQCISS handler FUN_0001670c)
- `ev_338298f64386c4845b2f6111aa2ab179015e5fad4f1f7a598b99f67368ca1df3` (CSMIALL handler FUN_00016c80)
- `ev_35bb164d5aceb012c3cab51a6880ebe6e7153f9654f7e2add89205ac827643ac` (gate FUN_00017f5c)
- Triage row check: Grep on the SHA returned triage_index.csv line 31 (`HpSAMD`, `Stopped`).
