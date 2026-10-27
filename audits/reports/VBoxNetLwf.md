# Audit: VBoxNetLwf.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\VBoxNetLwf.sys` |
| Recorded SHA-256 | `CD3AF3B853C27626FCFC85997FEEAD0A48E56D618E2129F62FE1B96A203A44C7` (matches triage_index.csv row 72; verified before opening; REA reports the same digest) |
| Company/Version | Oracle and/or its affiliates, 7.0.14.161095 (triage row). NDIS **Lightweight Filter** ("VirtualBox NDIS Light-Weight Filter", filter ID `{7af6b074-048d-4444-bfce-1ecc8bc5cb76}`). Kernel client of `\Device\VBoxDrv`. Triage state: **Running** on this host |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope. Hypervisor-adjacent: analyzed, not loaded (per ledger rule) |
| Verdict | **WRITE-HIGH (candidate; SG producer not in file; guest influence not established; not reachable through this driver's own IOCTL surface)**. The VBox-to-NBL conversion copies the sum of segment lengths into an NB data area sized by `total`, with no check between them. Same invariant gap as `VBoxNetAdp6`. The device's IOCTL dispatch is dead (`STATUS_NOT_SUPPORTED`). The producer invariant lies in VBoxDrv, which is not in this file |
| Coverage | ~50%. Reviewed: DriverEntry and device registration, the IRP dispatch, the VBox entry `FUN_140004020`, the SG-to-NBL conversion `FUN_140003130`, the NBL classifier `FUN_140002570`, the NB-to-descriptor builder `FUN_140002920`, the indicate/return router `FUN_140002DC0`, and `RTMemContAlloc`. Not traced: the VBox caller of `FUN_140004020`, the copy helper `FUN_1400202C0` body, `FUN_140020280`, `FUN_140003670` (unload), the filter attach and OID paths, and the producer of the SG descriptor |

> **Static-only.** No load, no device open, no IOCTL, no SG injected. Addresses are linked VAs (image base `0x140000000`). Hypervisor-adjacent: the open question is answered by reading the producer's invariant, not by testing on the host.

## Entry surface

- `DriverEntry` (`0x140003A70`): `NdisFRegisterFilterDriver` (filter ID above), then `NdisRegisterDeviceEx` with:
  - `DeviceName = \Device\VBoxNetLwf`
  - `SymbolicName` **empty**, so no `\DosDevices\` link is created
  - `DefaultSDDLString` **NULL** (NDIS default device ACL; not established in-file)
  - `MajorFunctions` set for CREATE (0), CLOSE (2), DEVICE_CONTROL (14), CLEANUP (18), all -> `FUN_1400023D0`
- `FUN_1400023D0` (the only device dispatch): completes `IRP_MJ_DEVICE_CONTROL` with **`STATUS_NOT_SUPPORTED` (0xC00000BB)** and everything else with success. **The device has no working IOCTL handler.** The user-reachable surface is the object name only (open by `\Device\VBoxNetLwf`), with no IOCTL.
- The live data path is NDIS filter callbacks (`FUN_140002DC0`, `FUN_140004020`, `FUN_140002920`, ...), driven by the host stack and by VBoxDrv.
- Imports of note: `MmMapLockedPagesSpecifyCache` (1 site in `FUN_140002920`), `MmGetPhysicalAddress` / `MmAllocateContiguousMemory` (in `RTMemContAlloc`, `FUN_140011150`), `MmIsAddressValid`, `NdisRegisterDeviceEx` / `NdisDeregisterDeviceEx`, `NdisFIndicateReceiveNetBufferLists` (4 call sites, all in `FUN_140002DC0` and `FUN_140004020`).

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| **VBox SG to NBL, no sum check** | `FUN_140003130`: `total = *(uint*)(SG+0x20)`. Bucket chosen from `total + 0x2A` (5 buckets; "frame too big" drop above the largest). `NdisGetDataBuffer(NB, total)`. Then for each of `count = *(ushort*)(SG+0x2C)` segments, `FUN_1400202C0(dst, seg.ptr, seg.len); dst += seg.len`. Nothing checks `Sigma seg.len <= total`. Overflow beyond `total` (and beyond the bucket if large) | `ev_6db9ba38...` (`FUN_140003130`) |
| VBox entry | `FUN_140004020`: under filter state `== 4` and a mutex, flags `1` (send) and `2` (indicate) each call `FUN_140003130` on the caller-supplied SG (`param_3`). The SG is a VBoxDrv-side input | `ev_6fe46386...` (`FUN_140004020`) |
| Descriptor builder | `FUN_140002920` (NB to descriptor): allocation `(count+2);0x18`, entries `<= count`. Bounded. Maps MDLs with `(flags & 5) == 0` via `MmMapLockedPagesSpecifyCache` and stores the VA; **no matching unmap** in the teardown (`FUN_140002570` frees the descriptor only). Mapping leak: DoS-class, not a write | `ev_e2c6075c...`, `ev_9a04eeaf...` (`FUN_140002570`) |
| Router | `FUN_140002DC0`: splits NBLs by `FUN_140002570` into indicate and return lists. No memory writes beyond list pointers | `ev_a4008bac...` |
| Device dispatch | `FUN_1400023D0`: MJ_DEVICE_CONTROL to `STATUS_NOT_SUPPORTED`. No IOCTL handler, no caller buffer touched | `ev_ec103b28...` |
| Contiguous allocation | `RTMemContAlloc` (`FUN_140011150`): same pattern as `VBoxNetAdp6` and `VBoxUSBMon`. Writes the PA low dword to the caller's pointer. Callers not traced | `ev_7883d1d9...` (resolve) |

## Verdict rationale

The VBox-to-NBL conversion writes `Sigmalen` bytes into an NB data area sized by `total`, with no check between the two. That is a memory-safety defect with length- and content-controlled bytes. Reachability is the question, and the answer splits three ways:

- **Not** reachable through the device: the IOCTL dispatch returns `STATUS_NOT_SUPPORTED`. A host user can open the object name at most, and nothing user-facing is handled.
- **Not** reachable from the host network stack: packets sent by the host go through the send-side descriptor builder, which is bounded.
- **Reachable** if VBoxDrv can deliver an SG whose segments do not sum to `total`. Whether it can is the open invariant. The producer is in VBoxDrv.

This is the same invariant gap as `VBoxNetAdp6`. The two drivers are the same family, and the producer invariant is shared. Escalate to **WRITE-CRITICAL** if an unprivileged host user can produce such an SG through any path. Drop to **NO-WRITE** if the producer guarantees `Sigmalen <= total`.

## Open items

- **Producer invariant (decisive, shared with `VBoxNetAdp6`).** Audit the VBoxDrv SG builder for the intnet receive path, including how `total` is derived.
- The VBox caller of `FUN_140004020` (indirect; registration not traced).
- `FUN_1400202C0` body (copy helper) and `FUN_140020280`.
- Mapping lifetime on the send side (leak, DoS-class; not in write scope).
- `RTMemContAlloc` callers and the origin of the output pointer.

## VM confirmation plan (orchestrator-owned; VM only)

1. **Host: no loading.** Running and hypervisor-adjacent. The static item is the producer invariant.
2. **VM, read-only first.** In a snapshot guest, record the SG descriptors delivered to `FUN_140004020` (read-only kernel breakpoint) and check `Sigmalen` against `total` for normal and boundary frames.
3. **Destructive step only if step 2 shows a violable invariant.** Run solo in the VM per the pool-corruption protocol. Never on the host.

## Evidence (REA, retained IDs)

`ev_e3718acaaebabe1c481b892621397f6b63f2ed72ac6426212b5a26a9d736d0bd` (DriverEntry `0x140003A70`), `ev_ec103b2818e6a8836b56cdf4889329bb7f55d25509ff038a95e21a915fd7b4de` (dispatch `FUN_1400023D0`), `ev_6fe46386d45d818154e89a372b8e0fdcbd4c469953165439947d18563ba03fb0` (`FUN_140004020`), `ev_6db9ba387940a5cfd303f5551727a2cb0c802e25596e2ae281975c14a173528d` (`FUN_140003130`), `ev_a4008bac19da60266217d694f1662fe0b77cfa45f9380d506815ecf3d6945dcd` (`FUN_140002DC0`), `ev_9a04eeafc51dc527488c547b85041d2224bcbc341c8c423c68b866b31b519406` (`FUN_140002570`), `ev_e2c6075ce84d40efb549f79203c1398e9b03ff3b0aa8252c80f5f41b3e6fefa6` (`FUN_140002920`), `ev_7883d1d94fcc4bb70732bc3bd85135c202577895f984a3e04f6decd46c128829` (`RTMemContAlloc` resolve), `ev_1bba9215839d563061ae5f60ae49740940b75c87337c32204585565ad8783d9f` (`NdisRegisterDeviceEx` thunk xrefs), `ev_d9cf3143fcb75ec5033dc60dae5e0cfe52f334ecfb588502fc22af78908362d6` (indicate thunk xrefs), `ev_a0ecd5bcdf9bcf0d027864c990245ffa41a92be80d524c3a88b8471c216de70a` (`\Device\` strings), `ev_1beb30c9c1c9768f3887ad4cd49f0b8cd4d6328b78ed15e5d39512a9d0639904` (`Device` sweep), `ev_6f853593cfa21375a9ad4ca463d5bdce6967e91e0fb44935c472042cac6667f1` (`Mm` sweep), `ev_dd4378cf4524085932843dfd32f01b63e1a6628de6f72d1c5fc06c0750336c2e` (`Io` sweep), `ev_5a4356f77f26aa50809da572ebd144fed04739d97a1ef55c4e30e1c9404b7f8d` (`NdisF` sweep).
