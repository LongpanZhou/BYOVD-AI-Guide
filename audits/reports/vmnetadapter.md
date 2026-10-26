# Audit: vmnetadapter.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\vmnetadapter.sys` |
| Recorded SHA-256 | `375B2D5D98A91D866E253028918505223109D97C8832588F60E7F971C8EFB4FF` (matches triage_index.csv row 22; verified before opening; REA reports the same digest) |
| Company/Version | Broadcom Inc. (VMware), 17.6.0.0 (triage row). NDIS **miniport** (`NdisMRegisterMiniportDriver`) for the VMware host-only/bridged virtual adapter. Triage state: **Running** on this host |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, short-form (no device object of its own) |
| Verdict | **NO-WRITE (coverage ~55%)**. Every call site of the copy-relevant imports is in a reviewed procedure. The receive copy is gated by `NdisRetreatNetBufferDataStart`, and the send copy is capped by allocated packet capacity. The region previously marked "unrecognized" is the import address table, not code |
| Coverage | ~55%. Reviewed: `FUN_140001CD0` (VNet receive, 726 bytes) and `FUN_140002080` (send, 961 bytes), including every call site of the Retreat, Indicate, and MmMap imports. Not reviewed: the miniport OID handlers, the initialization and configuration paths, the VNet producer of receive packets, and the body of the copy helper `FUN_140003840` (its call signature was checked, not its body) |

> **Static-only.** No load, no device open, no IOCTL, no packet injected. Addresses are linked VAs (image base `0x140000000`). Hypervisor-adjacent (VMware networking): analysed, not loaded.

## Entry surface

- **No device object of its own.** No `IoCreateDevice`, no `IoGetDeviceObjectPointer`, no `NdisRegisterDeviceEx`, no `\Device\` string, no SDDL. The `Io` sweep is empty.
- The adapter's user-visible surface is the NDIS-created adapter device (NDIS builds `\Device\{GUID}` for miniports). Its OID requests dispatch into this driver's OID handler, which was **not traced**.
- Data paths: send from NDIS (`FUN_140002080` → `VNet_Send`); receive from the VNet switch (`FUN_140001CD0` → `NdisMIndicateReceiveNetBufferLists` through thunk `0x140003752`, called at `0x140001F01`). Both use `VNet_*` helpers in the VMware bus.
- Memory imports: `MmMapLockedPagesSpecifyCache` has two code call sites: `0x140001E9C` (in `FUN_140001CD0`) and `0x140002275` (in `FUN_140002080`). **No `MmUnmapLockedPages` import**, so mappings are not unmapped on the traced paths (see the mapping row below).

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Receive copy into NB data | `FUN_140001CD0` calls `NdisRetreatNetBufferDataStart(NB, len)` first (call at `0x140001E4F`, its only call site). Retreat fails when headroom is short, which guards the copy `FUN_140003840(NB data + offset, VNet packet, len)`, which uses the same `len`. Bounded for writes | `ev_5813f262…` (`FUN_140001CD0`), `ev_f96dc60a…` (Retreat xrefs) |
| Receive source length | `len = *(int*)(VNet pkt+4)` is VNet-supplied and signed. A length larger than the VNet packet buffer over-reads the source into the NB. Information disclosure, not a write | `ev_5813f262…` |
| Send copy | `FUN_140002080`: packet allocated with capacity `uVar13` (NB data length, bounded to `[14, 0x2400)`). The copy loop subtracts `uVar7` from `uVar13` before each copy, so total writes stay within capacity. Bounded | `ev_1162968b…` (`FUN_140002080`) |
| MDL mapping without unmap | `MmMapLockedPagesSpecifyCache` at `0x140001E9C` (receive, `FUN_140001CD0`) and `0x140002275` (send, `FUN_140002080`, for MDLs with `(flags & 5) == 0`). No unmap import, so each mapping leaks system PTEs. Denial of service, not a write | `ev_d3555fc9…` (MmMap xrefs), `ev_8a46d9f5…`, `ev_32b6d32d…` (resolves of both call sites) |
| Indicate call | `NdisMIndicateReceiveNetBufferLists` through thunk `0x140003752`. Its only caller is `0x140001F01` in `FUN_140001CD0`. It hands NBLs up and copies nothing | `ev_273c0768…` (thunk xrefs), `ev_70fdafaf…` (resolve thunk) |
| Region `0x140004000`–`0x140004150` | The import address table, not code: the entries are RVA-like name pointers (data). The references at `0x1400001D8` and `0x14000022C` are data outside any procedure, not call sites | `ev_c7a5ff2a…` (bytes at `0x140004000`), `ev_001bba18…` (xrefs of `0x140004000`), `ev_f9548de8…` (xrefs of `0x140004038`), `ev_4801a2e2…` (xrefs of `0x140004140`), `ev_9cf7bb1a…` and `ev_1bc72c94…` (resolves of the two data references) |

## Verdict rationale

NO-WRITE. Both copies are bounded by a checked headroom (the retreat gate on receive) or a checked capacity (the send path). Every call site of the receive and send imports is inside `FUN_140001CD0` or `FUN_140002080`, and both are reviewed. The former "unrecognized region" is the import table, so it is no longer an open item. No write escalation was identified in the reviewed paths. The receive copy uses the same `len` for the retreat and the copy. The remaining question is the source over-read, which is information disclosure.

## Open items

- **Miniport OID handlers** reachable through the NDIS-created adapter device (the user-openable path). Not traced; this is the decisive item for user reach.
- **VNet receive producer:** whether the packet length is validated against the buffer before `FUN_140001CD0` runs. This decides the information-disclosure read, not a write.
- **MDL mapping lifetime:** no unmap import, so each mapping leaks system PTEs (denial of service). Confirm with a read-only check of the NDIS return path.
- `FUN_140003840` (copy helper): only its call signature was checked; its body was not reviewed.

## VM confirmation plan (orchestrator-owned; VM only)

1. Host: no loading (running, hypervisor-adjacent).
2. Snapshot VM with a VMware guest: read-only observation of the VNet receive length against the packet buffer size for boundary frames.
3. No destructive step is planned.

## Evidence (REA, retained IDs)

`ev_4378ea1ffdf7b4f8b029dc1879da676c576bd96eb6d903e4a59bb6a6ee10bb9b` (`Mm` sweep), `ev_8883e82847a6ad94eb5842897ec0a3d96fe694ebea2e655db081d3fbcf276b65` (`Io` sweep, empty), `ev_92d283f830165f1b58b6c9bd1bb1ddc4ed7418d8405d85366bddd3df0845ad6c` (`Ndis` sweep), `ev_678850411ab5ed0f961780af6ea1d996390ecace6d1d86c3021f1bb67c079c0c` (`Probe` sweep, empty), `ev_78dd979ed8b08d9b3c74b33795ba018a3e12ecfe397bb9d613ecf26cd2ca0019` (`\Device\` strings, empty), `ev_307a873c2c1a5e30cacadc73a814d31d1eaca48d5c9e852680edf7e25e331199` (`(A;` SDDL search, empty), `ev_d3555fc918ee8edc07a02a149a8c237570e5efef9d5f1f7beaed33bf9bc825d9` (`MmMapLockedPagesSpecifyCache` xrefs), `ev_88c77a01deeb5dbbf6624ba022e4389b1000f8f6ab63c440ccacc2e9a210090f` (`NdisMIndicateReceiveNetBufferLists` xrefs, pre-compaction), `ev_f96dc60a6afca8e616416b4afc4b40e26a92a6233e6563c42c3ad8ade190483e` (`NdisRetreatNetBufferDataStart` xrefs), `ev_5813f2625641ac870efa6f90e4bc1043a25441b87b8391a20452a88fa9201932` (`FUN_140001CD0`), `ev_1162968bfca8a4d55340b1c84385bb2a2a6d51defcded37c8ab31b46b574be54` (`FUN_140002080`), `ev_8a46d9f5f5c769f2d7a3a8d71081113f468f4f6b2ac223d280edf991543239bb` (resolve `0x140001E9C` → `FUN_140001CD0`), `ev_32b6d32dc5c658e42ad58e4ef04e713a355a2dca3188a3634affbc6716b73141` (resolve `0x140002275` → `FUN_140002080`), `ev_2789887e590968a3fb28f71819e8b2a10b72aefe14dc9430fb50e68f2887e7b8` (resolve `0x140001E4F` → `FUN_140001CD0`), `ev_70fdafafe0aca258aaab0a405891784dad394a1563758658a6de06ae2f4a6307` (resolve thunk `0x140003752`), `ev_273c0768c17e3bc8299e3322cadd334be3221c685cc61a3a8e53aba8eca0615d` (xrefs of thunk `0x140003752`), `ev_c7a5ff2a59e525b23eec4224ae04f7c315c3f3221e326aefa347d6823c3ca38f` (bytes at `0x140004000`), `ev_001bba1879529d287879c4f7ea05f25ef1ab961271a8ecc05ec1c41227f30646` (xrefs of `0x140004000`), `ev_f9548de8815ead76ce9b3d73855085c3a335bee1ba546731c6f54c0aea9a1923` (xrefs of `0x140004038`), `ev_4801a2e2e2bbfc277e0561018772df251a03ed928e0b1235c8676bfdd2ee357b` (xrefs of `0x140004140`), `ev_9cf7bb1afcfca5581efe847a5bedc0504a7f2c91e341305d2390578b8c510bd4` (resolve `0x1400001D8`, not in a procedure), `ev_1bc72c94cc137886972772f20b7a510a6051bd8e96f0a50adfd01fc4a9a5daad` (resolve `0x14000022C`, not in a procedure), `ev_c7e9cac293710ab1caa31d8f2a9acc29c33e547b463faf6bb8db26ddac70de12` (resolve `0x140004140`, `not_in_procedure`, pre-compaction).
