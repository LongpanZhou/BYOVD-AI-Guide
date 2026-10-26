# Audit: megasas35i.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\megasas35i.sys` |
| Recorded SHA-256 | `83C982FC61094A9E9F3E3CB5174B7409698C12FE3B6BF9B2F4C9365E56C642B2` (matches triage_index.csv row 18; verified before opening; REA reports the same digest) |
| Company/Version | Avago Technologies, MegaRAID SAS 35xx driver 7.710.10.00. x64 StorPort miniport. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope. Deep-form for the SRB_IO_CONTROL path (storage miniport, user-mode reachable through the port device): traced from HwBuildIo through the Function 0x02 dispatch into the IO_CONTROL handler, which was reviewed in full |
| Verdict | **WRITE-MEDIUM (conditional, coverage-limited, ~40%)**. The IO_CONTROL handler writes past the end of the caller's SRB buffer in two sub-code paths. Their minimum-length checks (`DataTransferLength > 199`) are smaller than the offsets they write. Admin-gated port device |
| Coverage | ~40%. Reviewed: `entry` (HW_INITIALIZATION_DATA), HwBuildIo `FUN_1400021a0`, the Function dispatch `FUN_140001430` (case table read; the full body was not), IO_CONTROL handler `FUN_140009ec0` (complete), and the import, string and procedure sweeps. Not reviewed: see Open items |

> **Static-only.** No load, no device open, no IOCTL, no SRB issued. Addresses are Ghidra-linked VAs (image base `0x140000000`). The WDK `storport.h` offsets (km, 10.0.26100.0) were applied as static text to the decompiled struct stores.

> **Shared-server note.** Three REA calls ran against another agent's target (iaStorAVC.sys) and were discarded. The target was re-opened each time (digest verified) and the calls were repeated. Two large results were read from the saved tool-output file, and their subject digest was checked.

## Entry surface

- **No device of its own.** The `Io`, `Wdf`, `Probe`, `copy` and `(A;` sweeps are empty, and the `\Device\` search is empty. The StorPort sweep returns 15 STORPORT.SYS externals and their thunks. StorPort owns the port device.
- **Single init site.** The `StorPortInitialize` thunk (`0x140013f70`) has one resolved caller, `FUN_14000a4e0` (`entry`). It passes a 0xd0-byte `HW_INITIALIZATION_DATA` with AdapterInterfaceType 5 (PCIBus).
- **Callback table** (`storport.h` offsets): HwInitialize `0x08` = `FUN_140008150`; HwStartIo `0x10` = `FUN_1400129a0`; HwInterrupt `0x18` = `FUN_140008f30`; HwFindAdapter `0x20` = `FUN_14000a8c0`; HwResetBus `0x28` = `FUN_14000f370`; HwAdapterControl `0x78` = `FUN_14000bbf0`; HwBuildIo `0x80` = `FUN_1400021a0`. DeviceExtensionSize `0x40` = 0x4c40, SrbExtensionSize `0x48` = 0x700, NumberOfAccessRanges `0x4c` = 2.
- **User-reachable path.** `IOCTL_SCSI_MINIPORT` on the port device delivers an SRB. `SRB_FUNCTION_IO_CONTROL` (Function 0x02) is consumed in the worker `FUN_140001430`, which calls the IO_CONTROL handler `FUN_140009ec0` with a type argument of 3. HwAdapterControl is not on this path.
- **Access gate.** The port device uses the storage-stack default security descriptor, which is admin-only by default. The DACL is not traced in this file.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Caller-controlled kernel address or mapping | None. The `Mm`, `Probe` and `\Device\` sweeps are empty. No section, `MmCopyMemory` or PhysicalMemory references | `ev_dd04b409…` (Mm, empty), `ev_da578080…` (Probe, empty), `ev_33564784…` (`\Device\`, empty) |
| IO_CONTROL routing | Dispatch `FUN_140001430` on Function: `case 2` calls `FUN_140009ec0(adapter, SRB, 3)`. `case 8` (flush) allocates a 0x600-byte frame | `ev_0d522e9d…` |
| Buffer length, minimum (`DataTransferLength`, SRB+0x10) | Checked `>= 0xbc` before any buffer access. On failure: SRB status 6, ReturnCode 1 | `ev_45d9b317…` (`FUN_140009ec0`) |
| Special ControlCodes | `0x001b0780` returns `0x1b0701`. `0x80727474` goes to `FUN_140009ae0` (not reviewed) | `ev_45d9b317…` |
| Signature and ControlCode gate | `LSILOGIC` at buffer+4. ControlCode family `F001` or `F002`. Anything else goes to the fallback `FUN_140009760` (not reviewed) | `ev_45d9b317…` |
| Fixed copy, sub-code `0xF0010100` / `0xF0010200` | 0x70 bytes to buf+0xbc. Guarded by `DataTransferLength >= 300` (ends at 0x12c, correct) | `ev_45d9b317…` |
| Fixed store, sub-code `0xF0020300` | 4 bytes at buf+0xbc, guarded by `>= 0xc0` (correct) | `ev_45d9b317…` |
| **Sub-code `0xF0020C00` (mode byte buf+0x38 = 0)** | Guard is `DataTransferLength > 199` (minimum 200). Writes at buf+0xc0, 0xc4, 0xc8 (4 bytes) and buf+0xcc (1 byte). The last written byte is index 204, so a buffer of 200-204 bytes is overrun by up to 5 bytes. **In-file out-of-bounds write** | `ev_45d9b317…` |
| **Sub-code `0xF0020B00`, mode 0 (buf+0x38 = 0)** | Guard is `DataTransferLength > 199`. Then `FUN_14000cdb0(buf+0xbc, adapter+0x4170 structure, 0x80)` writes 0x80 bytes, ending at buf+0x13c (index 316). A buffer of 200-315 bytes is overrun by up to 116 bytes. The source is adapter-internal data, not the caller's. **In-file out-of-bounds write** | `ev_45d9b317…` |
| **Sub-code `0xF0020B00`, mode 1 (buf+0x38 = 1)** | Walks an adapter-internal node list (`adapter+0x4158/0x4168`). Copies each node's own payload to buf+0xc4 + offset. The copy extent is capped by the caller-supplied `buf+0xbc`, not by `DataTransferLength`. Node lengths are adapter-supplied. Copies can run past the caller's buffer when the node data is larger than `DataTransferLength - 0xc4` | `ev_45d9b317…` |
| Output count `buf+0xbc` in mode 1 | Read as the remaining-space limit. Not checked against `DataTransferLength` | `ev_45d9b317…` |
| Fixed-length fallbacks | Not reviewed (see Open items) | — |

## Verdict rationale

**WRITE-MEDIUM (conditional).** Reviewed code shows three in-file writes past the end of the caller's SRB buffer. Each is reachable with a `DataTransferLength` that passes the handler's own minimum check, and each is in the IO_CONTROL sub-code path. The MegaSas2i and megasas handlers do not have this mismatch in their reviewed sub-codes. The sizes are:
- `0xF0020C00`: up to 5 bytes past a 200-byte buffer, using fixed offsets (adapter-internal values written).
- `0xF0020B00` mode 0: up to 116 bytes past a 200-byte buffer, a fixed 0x80-byte copy from adapter-internal data.
- `0xF0020B00` mode 1: the extent is set by the caller's `buf+0xbc` value and by adapter-supplied node data, so it can exceed the buffer.

The writes need the admin-gated port device. They can only overrun a kernel buffer if storport sizes that buffer from `DataTransferLength` (conditional; not verified in-file).

- **Escalate to WRITE-HIGH** if a non-admin token can open the port device, or if the write content is shown to be caller-chosen.
- **Drop** the mode-0 and `0xF0020C00` findings only if storport is shown to allocate at least 0x13c bytes whenever `DataTransferLength >= 200` (not expected).

## Open items

1. **Decisive:** confirm how storport sizes the system buffer for `IOCTL_SCSI_MINIPORT` (is it exactly `DataTransferLength`?). This decides whether the overruns reach kernel pool.
2. The fallback `FUN_140009760` (every ControlCode outside the family, and unlisted sub-codes) and `FUN_140009ae0` (ControlCode `0x80727474`). Not reviewed. These may hold more caller-length paths.
3. `FUN_1400096d0`, the producer used by sub-code `0xF0020200`, and the node-list builders behind `adapter+0x4148/0x4158/0x4168`. Not reviewed.
4. `FUN_14000cdb0` (copy helper): confirm it copies exactly the length argument with no internal bound.
5. HwStartIo `FUN_1400129a0`, the fast-path builders `FUN_140006700` and `FUN_140006c30` (called from `FUN_1400021a0`), and the sub-builders of `FUN_140001430`.
6. HwAdapterControl `FUN_14000bbf0`. Not reviewed.
7. The WMI path `FUN_140013de0` (Function 0x17) and the gate `FUN_140012300`.
8. Callers of `memset` at `0x140014840` and `memcmp` at `0x140013fa0`.
9. Port-device DACL (admin-only by default; not traced in-file).
10. **Cross-driver check:** the megasas and MegaSas2i handlers reviewed here do not have the length mismatch, so their reviewed sub-codes are consistent. Their unreviewed fallbacks still need the check (see `megasas_rea.md` and `megasas2i.md`).

## VM confirmation plan (orchestrator-owned; VM only)

1. Host: no load. The driver is stopped, and its data path needs a MegaRAID 35xx adapter.
2. Snapshot VM, read-only: check the security descriptor on the storport port device for a restricted token (expected: admin-only). Confirm whether storport sizes the IOCTL system buffer from `DataTransferLength`, using static reading of the storport behavior or a driver-verifier-style check on a stock VM.
3. Only if a non-admin token can open the port device: the orchestrator decides whether a boundary-length IO_CONTROL test (lengths 200 to 316) is in scope. It needs an adapter, so it is probably not runnable in a stock VM. Run it solo in the VM, never on the host.

## Evidence (REA, retained IDs)

Standard sweeps (`open_binary` digest `83c982fc…`):
- `StorPort` (case-sensitive): `ev_56208bdca13f0a9f2e7eacbea0c8ca1e08076d68e0cf2a7c7e72ec0b34acb46b` (15 externals and thunks)
- `Mm` (case-sensitive): `ev_dd04b40fffce06175a8277fdd6a2e0ae5576da9c6e58c9fe142e8bb312ddca20` (empty)
- `Io` (case-sensitive): `ev_9ae37205f1fc1ee7aa9f29a8b97a96e3d731653c224cea0fe8c84bc2f4f4dfb6` (empty)
- `Wdf` (case-sensitive): `ev_e2bbec751659a597ad182af261343df61d3075ca1051b8d63c7d1e29a51c064a` (empty)
- `Probe` (case-insensitive): `ev_da578080c797ef27d517f210e2faef34eb15236e306262b0a6c47a0670878181` (empty)
- `mem` (case-insensitive): `ev_e03aa5e80a39b859b851c5000f0e7dd8f710db4ee8ae6c061207a1888acf16dc` (memcmp, memset)
- `copy` (case-insensitive): `ev_02325e8d1578df34b77763c30c8d296d4f2609b0ddb3d6d84d0de71e366eacda` (empty)
- `(A;` SDDL (case-sensitive): `ev_aa09a8501df45ac90bb336647ef15d80c53184a6dd6348488bc5fe5bcfb35b25` (empty)
- `\Device\` (case-insensitive): `ev_33564784594267a99429d6cc23dd8e65a63dd21628b06b21e6efd601deb170b0` (empty)

Analysis:
- Caller of the StorPortInitialize thunk `0x140013f70`: `ev_c9a893437076b33801147f44d53af9eaf00e1da7587cc66ba75f84c19edd498d` (`0x14000a4e0`)
- `entry` `FUN_14000a4e0`: `ev_f96bf1fc9d07dce0d4500701d3c73322b7c61404afe8c64fffa7dec4dbc1907d`
- HwBuildIo `FUN_1400021a0`: `ev_71141822bf6e853afbc50b6e7b92edadbe76d9b3087a2bc27308a165d24cc809`
- Dispatch `FUN_140001430` (read from the saved tool output, digest checked): `ev_0d522e9d96fe7a54618c5f4317888d1c0a6a53c446cab6d872cf32c707092ed3`
- IO_CONTROL handler `FUN_140009ec0`: `ev_45d9b3178ca091bd2d67e83da3b4359f16cbf028bb8eb7bcc8fba16acbecbfa4`

REA session note: 21 REA calls in total, including 3 discarded results from another agent's target (iaStorAVC.sys), each followed by a re-open. `close_binary` was not called because the active target at the end belonged to another session.
