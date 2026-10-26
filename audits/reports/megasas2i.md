# Audit: MegaSas2i.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\MegaSas2i.sys` |
| Recorded SHA-256 | `6D67F52F0B63724126DD7B75B3489D14A6CBC3BD1E0D19188026DA21E85A620A` (matches triage_index.csv row 17; verified before opening; REA reports the same digest) |
| Company/Version | Avago Technologies, MegaRAID SAS driver 6.714.20.00. x64 StorPort miniport. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope. Deep-form for the SRB_IO_CONTROL path: a storage miniport whose IO_CONTROL SRBs are reachable from user mode through the port device, traced from HwBuildIo through the IO_CONTROL fallback into the scatter-gather builder |
| Verdict | **WRITE-MEDIUM (conditional, coverage-limited, ~50%)**. The IO_CONTROL fallback `FUN_140005f80` passes a caller-supplied length (buffer+0x30) to the scatter-gather builder `FUN_140001000`. The in-file bound allows max+1 entries, and the entries can run past the 0x600-byte request frame. Whether they do depends on the adapter's max-SGE value, which is not traced. The port device is admin-gated by default |
| Coverage | ~50%. Reviewed: `entry` (HW_INITIALIZATION_DATA), HwBuildIo `FUN_140001670`, worker `FUN_140001290`, IO_CONTROL handler `FUN_140006400`, fallback `FUN_140005f80`, SGE builder `FUN_140001000`, frame allocator `FUN_140001200`, and the import, string and procedure sweeps. Not reviewed: `FUN_1400062f0`, the max-SGE source, and the StorPort translation behavior. See Open items |

> **Static-only.** No load, no device open, no IOCTL, no SRB issued. Addresses are Ghidra-linked VAs (image base `0x140000000`). The WDK `storport.h` offsets (km, 10.0.26100.0) were applied as static text to the decompiled struct stores.

> **Shared-server note.** Nine sweep calls ran against another agent's target (HpSAMD.sys) and were discarded. The sweep results recorded below were re-run with this target active. Ghidra stalled during the analysis, and the coordinator closed the target. The target was re-opened (digest verified), and the one call that returned `target_unavailable` was retried after the re-open.

## Entry surface

- **No device of its own.** The `Io`, `Wdf`, `Probe`, `copy` and `(A;` sweeps are empty. The `\Device\` search is empty. The StorPort sweep returns 17 STORPORT.SYS externals (`StorPortInitialize`, `StorPortNotification`, `StorPortGetScatterGatherList`, `StorPortSynchronizeAccess`, and others). StorPort owns the port device.
- **Single init site.** The `StorPortInitialize` thunk (`0x14000e490`) has one resolved caller, `FUN_140006750`. That is the `entry` routine, with a 0xd0-byte `HW_INITIALIZATION_DATA` and AdapterInterfaceType 5 (PCIBus).
- **Callback table** (`storport.h` offsets): HwInitialize `0x08` = `FUN_140005290`; HwStartIo `0x10` = `FUN_14000cc80`; HwInterrupt `0x18` = `FUN_140005cc0`; HwFindAdapter `0x20` = `FUN_140006860`; HwResetBus `0x28` = `FUN_14000b120`; HwAdapterControl `0x78` = `FUN_1400077e0`; HwBuildIo `0x80` = `FUN_140001670`. DeviceExtensionSize `0x40` = 0x7440, SrbExtensionSize `0x48` = 0x700, NumberOfAccessRanges `0x4c` = 2.
- **User-reachable path.** `IOCTL_SCSI_MINIPORT` on the port device delivers an SRB. In this binary, `SRB_FUNCTION_IO_CONTROL` (Function 0x02) is consumed in **HwBuildIo**. `FUN_140001670` calls the worker `FUN_140001290`, which dispatches Function 0x02 to `FUN_140006400`. HwAdapterControl is not on this path (see Open items).
- **Access gate.** The port device uses the storage-stack default security descriptor, which is admin-only by default. The DACL is not traced in this file.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Caller-controlled kernel address or mapping | None. The `Mm`, `Probe` and `\Device\` sweeps are empty. No section, `MmCopyMemory` or PhysicalMemory references | `ev_24b9978f…` (Mm, empty), `ev_444d50ab…` (Probe, empty), `ev_e3a1f8eb…` (`\Device\`, empty) |
| IO_CONTROL routing | Worker `FUN_140001290`: the gate `FUN_14000c740` (not reviewed) runs first. `switch(Function)`: 0x02 returns `FUN_140006400`; 0x08 (flush) allocates a frame with `FUN_140001200`; 0x07 and 0x17 go to separate handlers; default sets SRB status 6 | `ev_0f09755f…` (worker), `ev_ac6d9c73…` (HwBuildIo) |
| Buffer length (`DataTransferLength`, SRB+0x10) | Checked `>= 0xbc` before any buffer access. On failure: SRB status 6, ReturnCode 1 | `ev_742a8ff2…` (`FUN_140006400`) |
| Special ControlCode `0x001b0780` | Returns success with no action | `ev_742a8ff2…` |
| Signature and ControlCode gate | 8-byte signature `LSILOGIC` at buffer+4. ControlCode high word `F001` or `F002` (mask `0xfffeffff`). Anything else goes to the fallback `FUN_140005f80` | `ev_742a8ff2…` |
| Fixed copy, sub-code `0xF0010100` (buffer+0x34) | `FUN_140008ba0(buf+0xbc, "LSILOGIC" constant, 0x70)`. Constant length, guarded by `DataTransferLength > 299` (ends at 0x12c) | `ev_742a8ff2…` |
| Fixed copy, sub-code `0xF0010200` | 0x70 bytes from adapter field `param_1+8` to buf+0xbc, same guard | `ev_742a8ff2…` |
| Fixed 4-byte store, sub-code `0xF0020300` | Adapter field `param_1+0x78` stored at buf+0xbc, guarded by `DataTransferLength >= 0xc0` | `ev_742a8ff2…` |
| Sub-code `0xF0020100` | `StorPortNotification(7, adapter, buf+0x38 byte)`. No write | `ev_742a8ff2…` |
| Fallback header copy (types 3, 4, 5, 7, 8) | Fixed 0x40 or 0x38 bytes from buf+0x1c into the frame at +0x100. Source is inside the checked 0xbc-byte buffer | `ev_68e04ef2…` (`FUN_140005f80`) |
| Caller-length SGE build (buffer+0x30) | Types 3, 4 and 5 pass `buf+0x30` directly as the length to `FUN_140001000`, with no check against `DataTransferLength - 0xbc`. Type 7 uses `buf+0x30` for its first build and `DataTransferLength - 0xbc - buf+0x30` for the second. Type 8 uses only the derived length. `FUN_140001000` calls `StorPortGetPhysicalAddress` per chunk and writes one SGE per chunk into the frame. Its count check `adapter+0x8e8 < count` allows max+1 entries (off-by-one). **Conditional sink** | `ev_68e04ef2…` (`FUN_140005f80`), `ev_878b7348…` (`FUN_140001000`) |
| Request frame capacity | `FUN_140001200` zeroes 0x600 bytes of the SRB extension and places the SGE array at +0x120 (type 7), +0x128 (type 5) or +0x130 (types 3, 4, 8). An SGE write past the frame end needs (max+1) x SGE size above about 0x4d0. That is about 108 entries of 12 bytes (64-bit SGEs) or about 153 of 8 bytes. The SRB extension is 0x700 bytes | `ev_c2c578b8…` (`FUN_140001200`), `ev_b726edfa…` (SrbExtensionSize 0x700) |
| Caller-length copy (buffer `Length`, buf+0x18) | Not read in `FUN_140006400` or in the reviewed fallback. A user-length copy, if one exists, would be in `FUN_1400062f0` (sub-code `0xF0020200`). **Not reviewed** | `ev_742a8ff2…` (no +0x18 reference) |
| Signature zeroing helper `FUN_140008bf0` | Fixed 8 bytes at buf+4. `entry` zeroes 0xd0 bytes of the init struct | `ev_742a8ff2…`, `ev_b726edfa…` |
| Shared `memset` (`0x14000ec40`) | Only named mem-helper in the sweep. Callers and length arguments not enumerated | `ev_094f0392…` (mem sweep) |

## Verdict rationale

**WRITE-MEDIUM (conditional).** The reachable sink is the scatter-gather build in the IO_CONTROL fallback. A caller-supplied length (buffer+0x30) drives one SGE write per physical chunk into a 0x600-byte request frame. The only in-file bound is the adapter's max-SGE count, and it allows max+1 entries. Whether the write leaves the frame depends on the max-SGE value at `adapter+0x8e8`, whose source is not traced here. The path is reached for any ControlCode outside the F001 and F002 families, and for any unlisted sub-code.

- **Conditions for the write to be real:** the max-SGE value must be large enough that (max+1) x SGE size passes the end of the frame (about 108 entries of 12 bytes, or about 153 of 8), and a fragmented user buffer must produce that many physical chunks. The port device must be reachable, which is admin-gated by default.
- **Escalate to WRITE-HIGH** if (a) a non-admin token can open the port device, or (b) `StorPortGetPhysicalAddress` accepts virtual addresses outside the SRB data buffer. Under (b), the types 3, 4 and 5 lengths would let the adapter transfer memory past the payload. Whether StorPort behaves this way is unverified.
- **Drop to NO-WRITE** only if the max-SGE value is shown to be fixed at or below about 100 entries and StorPort translation is confined to the SRB buffer.

## Open items

1. **Decisive:** trace the source of the max-SGE field `adapter+0x8e8` (firmware reply, registry, or a constant). This decides whether the 0x600-byte frame can be overrun.
2. **Decisive:** confirm `StorPortGetPhysicalAddress` behavior for a virtual address outside the SRB data buffer. This is storport-side behavior and not in-file.
3. `FUN_1400062f0` (sub-code `0xF0020200`). Not reviewed.
4. Gate `FUN_14000c740`. Not reviewed.
5. HwAdapterControl `FUN_1400077e0`. Not reviewed. The control-type handling is expected to match megasas (types 0-2 only), but that is not verified for this binary.
6. HwStartIo `FUN_14000cc80` (EXECUTE_SCSI path, frame builders `FUN_140001590`, `FUN_1400017a0`, `FUN_140007e10`, `FUN_140007fa0`, `FUN_1400094c0`), WMI `FUN_14000da70`, and the shutdown path (`FUN_140006650`).
7. Callers of `memset` at `0x14000ec40`, and the copy helper `FUN_140008ba0` (the length is constant 0x70 on the sub-code copies and 0x38 or 0x40 on the fallback header copies).
8. Port-device DACL (admin-only by default; not traced in-file).
9. **Cross-driver lead:** megasas (same MegaRAID family) has the same IO_CONTROL fallback shape. Its fallback `FUN_1c00084d0` (see `megasas_rea.md`, open item 1) should be checked for the same caller-length SGE path before megasas is considered NO-WRITE.
10. **Process note for the orchestrator:** the rule that "IOCTL_SCSI_MINIPORT dispatches to HwAdapterControl" does not hold for this binary. The IO_CONTROL SRB is consumed in HwBuildIo (0x80). Other storport miniports should be checked for the same routing rather than assumed to use HwAdapterControl.

## VM confirmation plan (orchestrator-owned; VM only)

1. Host: no load. The driver is stopped, and its data path needs a MegaRAID adapter.
2. Snapshot VM, read-only: check the security descriptor on the storport port device for a restricted token (expected: admin-only). No IOCTL is needed to establish the gate.
3. Only if a non-admin token can open the port device: the orchestrator decides whether a boundary-length IO_CONTROL test is in scope. It needs an adapter, so it is probably not runnable in a stock VM. Run it solo in the VM, never on the host.

## Evidence (REA, retained IDs)

Standard sweeps (`open_binary` digest `6d67f52f…`):
- `StorPort` (case-sensitive): `ev_b6545e6c8182bd79fb3e04cc19545f2ca64c2fd3ffd3cf399f2786eb31a283fc` (17 externals)
- `Mm` (case-sensitive): `ev_24b9978f30c4a04a1e8480eee632a4cab9b46e4546fb2d5ed1e2d64dfe1e6e82` (empty)
- `Io` (case-sensitive): `ev_f2d60c435ba1b68d92748d139d2de7786e399224e234fd03497ae1976471ad61` (empty)
- `Wdf` (case-sensitive): `ev_cfec6566ef57201a69aa1a921335bfee54b8225e42f5bc32dd41e10491ae7948` (empty)
- `Probe` (case-insensitive): `ev_444d50ab9cab5144d83e07a223d42f03f9a5817338fa46487518d8c268191b54` (empty)
- `mem` (case-insensitive): `ev_094f0392c567d38a7eec997038733099dfda287aca3a5d33c2bb768b422b12c6` (memset only)
- `copy` (case-insensitive): `ev_855f42ef43a8c81bcb2be7ac3528e7e2fb115092b1a25c6eee4c6b2a9f9aff3f` (empty)
- `(A;` SDDL (case-sensitive): `ev_d1b91db862bd961a3901baf485b8b292d4280d1b88ed94da27498f74f901fa11` (empty)
- `\Device\` (case-insensitive): `ev_e3a1f8eb568586e8ecc630fdacca1e35bde2966db61d066366c23ac173a404cc` (empty)

Analysis:
- Callers of the StorPortInitialize thunk `0x14000e490`: `ev_83ee1ed3c7bbd9fb634e7d0ab41a7f775f1fd66b687a938034f62958b36cdc25` (one caller, `0x140006750`)
- `entry` `FUN_140006750`: `ev_b726edfab7172e258ba4bf8597fdf80755efde4e2d2a531542bee2688cc9d3e0`
- HwBuildIo `FUN_140001670`: `ev_ac6d9c7307477956cbb33c958f144537ac681f76bc4326a32c306cd9af974bc7`
- Worker `FUN_140001290`: `ev_0f09755f5b5eebb04825faa94eb37352dfee314c5f04d64183109173d3591897`
- IO_CONTROL handler `FUN_140006400`: `ev_742a8ff289f4984eef69f7fad60e8f0508e435e74380892514433e721af3acb8`
- Fallback `FUN_140005f80`: `ev_68e04ef2b83e62dd3bd9b20500a861802e80e7e04cb24082aad4e85fa9e7d0b1`
- SGE builder `FUN_140001000`: `ev_878b7348b9366a36bf25323d74aab392ecb70c59ab8ed1039b52d2cb98909a52`
- Frame allocator `FUN_140001200`: `ev_c2c578b8274a9871b7682c886e8b0957b32677d4ca13a03b602d3c1e698099fe`

REA session note: the analysis calls ran with an open target and were checked against the subject digest. The 9 discarded sweeps ran against another agent's target (HpSAMD.sys) and are not recorded above. `close_binary` was not called because the active target at the end belonged to another session.
