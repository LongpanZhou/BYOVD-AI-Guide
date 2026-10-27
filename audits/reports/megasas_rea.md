# Audit: megasas.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\megasas.sys` |
| Recorded SHA-256 | `9041FDEB932F2CBBCE4A017256C81B3733604403AA343D4532910436E8288CA9` (matches triage_index.csv row 16; verified before opening; REA reports the same digest) |
| Company/Version | Avago Technologies, MEGASAS RAID controller driver 6.706.06.00 (NT.150223-1854). x64 StorPort miniport for MegaRAID SAS. Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope. Deep-form for the SRB_IO_CONTROL path: a storage miniport whose IO_CONTROL SRBs are reachable from user mode through the port device, so that path was traced from HwBuildIo into the IO_CONTROL handler |
| Verdict | **NO-WRITE (provisional, coverage-limited, ~50%)**. Every sink reviewed on the IO_CONTROL path is bounded. The decisive fallback handler `FUN_1c00084d0` is not reviewed. Downgrade risk: the same family's MegaSas2i fallback has a caller-length SGE write (`megasas2i.md`) |
| Coverage | ~50%. Reviewed: `entry` (HW_INITIALIZATION_DATA), HwAdapterControl `FUN_1c0001d60`, HwBuildIo `FUN_1c00036a0` and its worker `FUN_1c00036e4`, the SRB_FUNCTION_IO_CONTROL handler `FUN_1c000824c`, and the import, string and procedure sweeps. Not reviewed: see Open items |

> **Note.** `audits\megasas.md` (agentH, local Ghidra, NO-WRITE ~85%) already existed and was **not overwritten**. This REA audit is written to `megasas_rea.md` so the orchestrator can reconcile the two. agentH's HwAdapterControl and IO_CONTROL routing differ from this report (see Entry surface).

> **Static-only.** No load, no device open, no IOCTL, no SRB issued. Addresses are Ghidra-linked VAs (image base `0x1c0000000`). The WDK header `storport.h` (km, 10.0.26100.0) was read as static text only, to fix struct field offsets.

## Entry surface

- **No device of its own.** The `Io` and `Wdf` sweeps are empty. The `\Device\` string search and the `(A;` SDDL search are empty. The 17 STORPORT.SYS externals are the only imports in the StorPort sweep (`StorPortInitialize`, `StorPortNotification`, `StorPortGetScatterGatherList`, `StorPortLogError`, and others). StorPort owns the port device.
- **Callback table.** `entry` (`0x1c000f000`) calls `StorPortInitialize` with a 0xd0-byte `HW_INITIALIZATION_DATA` and AdapterInterfaceType 5 (PCIBus). Field offsets follow the `storport.h` layout: HwInitialize `0x08` = `FUN_1c0002060`; HwStartIo `0x10` = `FUN_1c0003ce0`; HwInterrupt `0x18` = `FUN_1c0007bb0`; HwFindAdapter `0x20` = `FUN_1c0001000`; HwResetBus `0x28` = `FUN_1c0008e50`; HwAdapterControl `0x78` = `FUN_1c0001d60`; HwBuildIo `0x80` = `FUN_1c00036a0`.
  - This differs from agentH's labels (BuildIo = `FUN_1c0003ce0`, StartIo = `FUN_1c0007bb0`), which are shifted by one slot.
- **User-reachable path.** `IOCTL_SCSI_MINIPORT` on the port device delivers an SRB. In this binary, `SRB_FUNCTION_IO_CONTROL` (Function 0x02) is consumed in **HwBuildIo** (`FUN_1c00036a0` calls `FUN_1c00036e4`), which hands it to `FUN_1c000824c`. It is **not** dispatched to HwAdapterControl. `FUN_1c0001d60` handles only ScsiQuerySupportedControlTypes (0), StopAdapter (1) and RestartAdapter (2), and returns 1 for any other control type.
- **Access gate.** The port device uses the storage-stack default security descriptor, which is admin-only by default. The DACL is not traced in this file.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Caller-controlled kernel address or mapping | None. The `Mm`, `Probe` and `\Device\` sweeps are empty. No section, `MmCopyMemory` or PhysicalMemory references | `ev_462cecff...` (Mm, empty), `ev_ae3d0136...` (Probe, empty), `ev_c35434c1...` (`\Device\`, empty) |
| IO_CONTROL routing | HwBuildIo worker: the gate `FUN_1c0004264` (not reviewed here) runs first. Function 0x02 is handed to `FUN_1c000824c` and returned | `ev_bb984879...` (`FUN_1c00036e4`), `ev_8cd9dc1a...` (`FUN_1c00036a0`) |
| Buffer length (`DataTransferLength`, SRB+0x10) | Checked `>= 0xbc` before any buffer access. On failure: SRB status 6, ReturnCode 1 | `ev_be857e5e...` (`FUN_1c000824c`) |
| Signature and ControlCode gate | The 8-byte signature `LSILOGIC` must sit at buffer+4. ControlCode must have high word `F001` or `F002` (mask `0xfffeffff`). Anything else goes to the fallback `FUN_1c00084d0` (not reviewed) | `ev_be857e5e...` |
| Fixed copy, sub-code `0xF0010100` (at buffer+0x34) | `FUN_1c00026fc(buf+0xbc, "LSILOGIC" constant, 0x70)`. Constant length, guarded by `DataTransferLength > 299`, so the write ends at 0x12c, inside the guard | `ev_be857e5e...` |
| Fixed copy, sub-code `0xF0010200` | 0x70 bytes from adapter field `param_1+8` to buf+0xbc, same guard | `ev_be857e5e...` |
| Fixed 4-byte store, sub-code `0xF0020300` | Adapter field `param_1+0x78` stored at buf+0xbc, guarded by `DataTransferLength >= 0xc0` | `ev_be857e5e...` |
| Caller-length copy (buffer `Length`, buf+0x18) | Not read anywhere in `FUN_1c000824c`. A user-length copy, if one exists, is in the fallback `FUN_1c00084d0` or in `FUN_1c00083dc` (sub-code `0xF0020200`). **Not reviewed** | `ev_be857e5e...` (no +0x18 reference) |
| HwAdapterControl self-describing write | `FUN_1c0001d60` ControlType 0 writes `*param_3` bytes at `param_3+4` from a fixed 5-entry list. The count is storport-supplied. This callback is not reached from the IOCTL payload | `ev_c01336be...` |
| Zeroing helper `FUN_1c00026a8` | Fixed 8 bytes at buf+4 on the signature path. `entry` zeroes 0xd0 bytes of the init struct | `ev_be857e5e...`, `ev_aad60378...` |
| Shared `memset` (`0x1c000aa00`) | Only named mem-helper in the sweep. Callers and length arguments not enumerated | `ev_624bffcc...` (mem sweep) |
| Copy helpers by name | `copy` sweep empty; the copy call sites are unnamed helpers (see Open items) | `ev_d99fe3f1...` (copy, empty) |

## Verdict rationale

**NO-WRITE (provisional).** Every sink I reviewed on the user-reachable SRB_IO_CONTROL path is bounded, either by a constant size or by `DataTransferLength`. The one self-describing write (HwAdapterControl) takes a storport-supplied count and is not reachable from the IOCTL payload. The verdict is provisional because the decisive code is unreviewed. `FUN_1c00084d0` is the fallback for every ControlCode outside the F001 and F002 families and for every unlisted sub-code. The buffer's `Length` field (+0x18) is never read in the reviewed handler, so any user-length copy must sit in `FUN_1c00084d0` or `FUN_1c00083dc`.

- **Escalate to WRITE-MEDIUM** if `FUN_1c00084d0` or `FUN_1c00083dc` copies the buffer's `Length` (+0x18) into a fixed-size buffer without a bound. The path is admin-gated by the port-device DACL (not traced here), so WRITE-HIGH only if a non-admin token can open the port device.
- **Firm NO-WRITE** if both handlers copy only constants or check `Length` against the destination size.

## Open items

1. **Decisive:** review `FUN_1c00084d0` (the general IO_CONTROL path and its DCMD builder callees) for any copy that takes `Length` (+0x18) from the user buffer. Also check for a caller-length scatter-gather build (buffer+0x30, or a length derived from DataTransferLength, with one SGE per physical chunk). MegaSas2i, the same MegaRAID family, has exactly that pattern in its IO_CONTROL fallback (see `megasas2i.md`, verdict WRITE-MEDIUM conditional), so this fallback is the highest-priority re-check for megasas.
2. `FUN_1c00083dc` (sub-code `0xF0020200`), `FUN_1c0008c30` (WMI, Function 0x17) and `FUN_1c0003618` (Function 0x08).
3. Gate `FUN_1c0004264`. Only agentH's local-Ghidra report covers it; it is not verified here.
4. HwStartIo `FUN_1c0003ce0` (EXECUTE_SCSI path, which builds frames in SRB+0x38) and its frame and DCMD builders `FUN_1c00047dc`, `FUN_1c0004960`, `FUN_1c0005664`.
5. The unnamed copy helper that agentH labels `FUN_1c000a6c0`, and the callers of `memset` at `0x1c000aa00`. Length arguments not reviewed.
6. Port-device DACL (admin-only by default; not traced in-file).
7. Record only, not a write and not user-reachable: `FUN_1c0001d60` ControlType 0 reads up to `*param_3` bytes from a short stack buffer. The count is storport-supplied, so this is a stack over-read only if that count is ever large.
8. **Process note for the orchestrator:** the rule that "IOCTL_SCSI_MINIPORT dispatches to HwAdapterControl" does not hold for this binary. The IO_CONTROL SRB is consumed in HwBuildIo (0x80). Other storport miniports should be checked for the same routing rather than assumed to use HwAdapterControl.

## VM confirmation plan (orchestrator-owned; VM only)

1. Host: no load. The driver is stopped, and its data path needs a MegaRAID adapter.
2. Snapshot VM, read-only: check the security descriptor on the storport port device for a restricted token (expected: admin-only). No IOCTL is needed to establish the gate.
3. Only if a non-admin token can open the port device: the orchestrator decides whether a boundary-length IO_CONTROL test is in scope. It needs an adapter, so it is probably not runnable in a stock VM. Run it solo in the VM, never on the host.

## Evidence (REA, retained IDs)

Sweeps (`open_binary` digest `9041fdeb...` on every result):
- `Mm` (case-sensitive): `ev_462cecffedfd5926ffba291178d54282af968be4d3437c02538975ff786e45f0` (empty)
- `Io` (case-sensitive): `ev_9ca5a4241a94d124590c567f9fcd61cf1542b7b90ca3b3c56e79f9e349b7d103` (empty)
- `Wdf` (case-sensitive): `ev_7226ac01de76e87c47ae0b16f24c1f16a1919d0b288efccf85d90a72b8e2d3e6` (empty)
- `StorPort` (case-sensitive): `ev_1cb1fddc9c2161da4d3d0771568f84ebea277fdca0222d7a15e97a3a2cb8d431` (17 STORPORT.SYS externals)
- `Probe` (case-insensitive): `ev_ae3d013655749308456c85d235a45a551db970e9bddb2d20770a935f77a989d3` (empty)
- `mem` (case-insensitive): `ev_624bffcc2d29a842c1b3d43ce4e72eb783aa4c88dbc81967fe730a5eed6f40fb` (memset only)
- `copy` (case-insensitive): `ev_d99fe3f1dcad8ba35b7767692bf9d846016d2462b21c723dfe20cdbadabba796` (empty)
- `(A;` SDDL (case-sensitive): `ev_2392e60855a141727b49fbc79df2acfb4688a9e6ea381399d591327a55de5c99` (empty)
- `\Device\` (case-insensitive): `ev_c35434c1e0a2974589362372f99e7f3867578149e14bda45aded93f7ad0375f1` (empty)

Analysis:
- StorPortInitialize xrefs (`0x1c000e020`, `0x1c000f0cc`): `ev_da55bcf2b4db546241086dc2071ffe233db51aad1c5aeeb17778b2eb02621b14`
- `entry` (`0x1c000f000`): `ev_aad603783baa6b005c19aa1d252a22303e35387a6ec87ba48d52394d7871ccb7`
- HwAdapterControl `FUN_1c0001d60`: `ev_c01336be935984a230ec1e1eb2ba13caa18ec2b92e0e50ecec3a9f354c99e6fc`
- HwBuildIo `FUN_1c00036a0`: `ev_8cd9dc1a5ea838116776658a22b34a4732387edbe4a40b888bb064716d897448`
- BuildIo worker `FUN_1c00036e4`: `ev_bb9848791ecd7f57c2a48d9cfb1389c125534282f95ed2ffa3a72396573887b8`
- IO_CONTROL handler `FUN_1c000824c`: `ev_be857e5e97a951a6aaf80c1f16ee0bea293690ad95269c9d6f89f5d4e41ce120`

REA session note: four calls in this audit ran while another agent's target (nvlddmkm.sys, then HpSAMD.sys) was active on the shared server. Their results were discarded and nothing from them is recorded above. `close_binary` was not called because the active target at the end belonged to another session. The megasas target was re-opened before each analysis call.
