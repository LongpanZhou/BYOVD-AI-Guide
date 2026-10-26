# Audit: vmnetbridge.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\vmnetbridge.sys` |
| Recorded SHA-256 | `3EB3F337D10EA5EC94EE747C3D25809282B2EF61BC18443D4708EF7D550D7525` (matches triage_index.csv row 23; verified before opening; REA reports the same digest) |
| Company/Version | Broadcom Inc. (VMware), 17.6.0.0 (triage row). NDIS **protocol** driver (`NdisRegisterProtocolDriver`, `NdisOpenAdapterEx`): binds to the physical adapter and bridges frames between the host NIC and the VMnet switch. Triage state: **Running** on this host |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope. Hypervisor-adjacent (VMware networking): analysed, not loaded |
| Verdict | **NO-WRITE (conditional, coverage-limited, ~60%)**. Two conditions decide it, and both are outside this file: (a) for the single-MDL copy, `VNet_PacketAllocate(n)` reserves the `0x2E` header beyond `n` bytes (VNet module); (b) for the two-MDL split copy, the received NB's `DataLength` equals the sum of its MDL byte counts (NIC/NDIS producer) |
| Coverage | ~60%. Reviewed: receive handler `FUN_1400076A0` (1530 bytes), copy helper `FUN_1400063FC`, send path `FUN_140001C90` (604 bytes) and its single caller, all four `MmMapLockedPagesSpecifyCache` code call sites, and the Mm, Io, Ndis, Probe, `\Device\`, and `(A;` sweeps. Not reviewed: `FUN_140007338` (special-frame branch), `FUN_1400045F8` and `FUN_140004B14` (filter callbacks), `FUN_1400083C0` (copy helper body), `FUN_140008680` (NB init), `FUN_140002C38`, the OID and configuration paths, and the protocol registration call site |

> **Static-only.** No load, no device open, no packet injected. Addresses are linked VAs (image base `0x140000000`). Hypervisor-adjacent: the open conditions are answered by reading producer conventions, not by testing on the host.

## Entry surface

- **No device object.** The Io sweep is empty; no `\Device\` string; no SDDL.
- **Receive (LAN-reachable).** `FUN_1400076A0` takes NBLs from the bridged physical NIC. It is presumed to be the protocol receive handler; its registration (ProtocolReceiveNetBufferLists) is not traced in-file. Frames arrive from the LAN segment the NIC is on, subject to the NIC's and the bridge's state checks.
- **Send.** `FUN_140001C90` takes VNet packets and sends them out the NIC: `NdisAllocateMdl` over the VNet packet data, then `NdisAllocateNetBufferAndNetBufferList`, then `NdisSendNetBufferLists`. The only caller of the send thunk `0x140008260` is at `0x140001EAA`, inside `FUN_140001C90`.
- NDIS imports (23): protocol lifecycle (`NdisRegisterProtocolDriver`, `NdisDeregisterProtocolDriver`, `NdisOpenAdapterEx`, `NdisCloseAdapterEx`, `NdisCompleteUnbindAdapterEx`); `NdisOidRequest`; configuration (`NdisOpenConfigurationEx`, `NdisReadConfiguration`, `NdisWriteConfiguration`, `NdisCloseConfiguration`); `NdisQueryAdapterInstanceName`; MDL and NBL (`NdisAllocateMdl`, `NdisFreeMdl`, `NdisAllocateNetBufferAndNetBufferList`, `NdisAllocateNetBufferListPool`, `NdisFreeNetBufferListPool`, `NdisFreeNetBufferList`, `NdisReturnNetBufferLists`, `NdisSendNetBufferLists`); and events (`NdisInitializeEvent`, `NdisSetEvent`, `NdisWaitEvent`, `NdisResetEvent`).
- Memory imports: `MmMapLockedPagesSpecifyCache` only. Four code call sites: `0x14000647F` (in `FUN_1400063FC`), and `0x1400077A3`, `0x14000780C`, `0x140007A05` (all in `FUN_1400076A0`). The fifth reference, `0x140009200`, is the IAT slot (its bytes are RVA-like), not a call. **No `MmUnmapLockedPages` import.**

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Receive length fields | Inferred from the decompiled offsets and the NET_BUFFER layout: `DataLength` = NB+0x18 (`uVar14`), `CurrentMdl` = NB+0x08, `CurrentMdlOffset` = NB+0x10, MDL `ByteCount` = MDL+0x28. Dropped when `DataLength > bridge+0x138 + 14` (MTU + 14). Runt dropped when the first MDL's `ByteCount − CurrentMdlOffset < 14` | `ev_5d20e003…` (`FUN_1400076A0`) |
| Single-MDL copy | `VNet_PacketAllocate(DataLength)`; copy target `pkt+0x2E`; `FUN_1400063FC(pkt+0x2E, DataLength, …)` copies exactly `DataLength` bytes across the MDL chain and returns `0xC001000F` if the chain ends early. Bounded by `DataLength`, provided the VNet allocator reserves the `0x2E` header beyond `DataLength` (VNet module, not in file) | `ev_3e28d1ac…` (`FUN_1400063FC`) |
| Two-MDL split copy | Taken when the bridge flag at `+0xFC` is nonzero and the NB has exactly two MDLs. Copies the first MDL's remainder (`uVar10`), then the second MDL's `ByteCount` (`uVar14`), using `FUN_1400083C0` twice, with **no cap against `DataLength`**. Bounded only if `DataLength` equals the remainder plus the second `ByteCount` (NB invariant from the NIC/NDIS producer). Candidate, not established | `ev_5d20e003…` (`FUN_1400076A0`, split branch) |
| MDL mapping without unmap | `MmMapLockedPagesSpecifyCache` runs for MDLs with neither the MAPPED nor the NONPAGED flag (`(flags & 5) == 0`). No unmap import, so such mappings leak system PTEs. Denial-of-service class, not a write. Which MDLs reach it is not established | `ev_de62bcda…` (MmMap xrefs) |
| Send path `FUN_140001C90` | No CPU copy. `NdisAllocateMdl(VA = pkt+0x2E, length = pkt+4)` maps the VNet data for the NIC to read. NBL context writes at NBL+0x40 and NBL+0x78 are fixed offsets in an NDIS-allocated structure. A VNet length beyond the buffer makes the NIC read past it: information disclosure to the wire, out of memory-write scope, recorded only | `ev_abf5cb47…` (pseudocode) |

## Verdict rationale

NO-WRITE, conditional. Every write in the single-MDL path is capped by `DataLength`, which is checked against MTU + 14 before allocation. The two-MDL split path is capped only by the MDL byte counts, which match `DataLength` if the NIC/NDIS producer keeps the NB consistent. That producer is outside this file, and it is the decisive open item. The VNet allocator's `0x2E` reservation is the second condition.

Escalate to **WRITE-MEDIUM** if an NB with a `DataLength` that disagrees with its MDL counts can be produced from a remote-controlled frame. Escalate to **WRITE-HIGH** if that is also reachable remotely without the bridge being administratively configured. Drop to a clean NO-WRITE if both conditions are confirmed.

## Open items

- **NB invariant (decisive):** whether `DataLength` always equals the sum of MDL byte counts for received NBs (NIC/NDIS producer), and whether the split branch (bridge flag `+0xFC`) is enabled in the default configuration.
- **VNet allocator:** `VNet_PacketAllocate(n)` must reserve the `0x2E` header; its allocation size decides whether the single-MDL copy can overflow.
- `FUN_140007338` (special frames for ethertypes 0x800 and 0x86DD with flag `0x8000`): not reviewed.
- `FUN_1400045F8` and `FUN_140004B14` (filter callbacks; return value `0x4548` gates the copy): not reviewed.
- MDL mapping leak (DoS-class): recorded.
- Information disclosure in the send path (MDL length taken from the VNet packet): recorded; out of scope.

## VM confirmation plan (orchestrator-owned; VM only)

1. Host: no load (running; hypervisor-adjacent; the receive path is LAN-reachable).
2. Snapshot VM with a VMnet bridge: read-only check of the VNet allocation size for boundary frames (the maximum MTU frame and a minimum frame), and of the NB layout for a two-MDL frame. Whether to test the split branch is the orchestrator's decision.
3. Any flooding or destructive test runs solo in the VM under the protocol, never on the host.

## Evidence (REA, retained IDs)

`ev_5d20e003b8004d71c894d7cf33bdb95f32c819c99f6d993b4c754abb8b4bcdb7` (`FUN_1400076A0`), `ev_3e28d1ac1439fefc56130b46241a5ea082287a980bfd3a4cb5fafc354f9a2a77` (`FUN_1400063FC`), `ev_abf5cb47c60ede11e23b88bc1559d94bd3ace57aa40ee081ca3a7aed83aad4e2` (`FUN_140001C90`), `ev_6e46d31fc96835a48a87fe772782408ac3cbcf6ac2b0ec24dda7d297049e9d79` (resolve `0x140001EAA` → `FUN_140001C90`), `ev_8cbf923d0f57cedd6fd3fc6fb4b5f88feb93b911ff0539eba56e02ac60a79582` (xrefs of send thunk `0x140008260`), `ev_2e899075150af6be7aecfdd9f73ab979a5601e30a67a38eb48bab24ee4e7eaa5` (resolve `0x14000647F`), `ev_17ce7b1d5bb3fa7ef0970ac1415ffbb51dd42d5c13870411b5c71b46e1981ca9` (resolve `0x1400077A3`), `ev_c84a54ed0449376a7d37220ee73036aca57734250f2d835b1d4428035a68cb92` (resolve `0x140007A05`), `ev_16d3c56876204628943852efc814608fe8efa2f35d2fdec43153f9a58a612c97` (resolve `0x140009200`: IAT slot, not a procedure), `ev_ee3840af2dc78b0e6805f12f2e962b9fe968ac2d3627fc628f4c55c108e7dbdd` (resolve `0x140009008`: IAT slot, not a procedure), `ev_5f49325b7d4a39ef8b11319cf8da48c882d1c4feb106b09f7fe22b9a97af1057` (bytes at `0x140009200`), `ev_31cc807b76f0651cef0aaf71e2ff697a47aca9e7d6e1c28a77c08bc1e195ba43` (bytes at `0x140009008`), `ev_de62bcda2f7554ea2516b806bcb8927934d5dc500a7f48f65adfa6f0ade9e1b6` (`MmMapLockedPagesSpecifyCache` xrefs), `ev_6352242cd4f84db943122f553a083658060f4f80201bb0e2ffbdd4635803df29` (`NdisSendNetBufferLists` xrefs), `ev_da7a1909c15aa2e162e1117c13e12c9f94b1f0619deb2cfcfbe9e9876fe7c667` (`Mm` sweep), `ev_8ec5599a25fc4625ea2badd8f6f08ef3696d787ed210bb5e6d0dc4c4e38a09ee` (`Io` sweep, empty), `ev_e58315428930e19b086ac557a6876f5666e105153de861799c8f5a6d28759729` (`Ndis` sweep, 23 imports), `ev_a5326028091885b03bf52d7784f0a0b338a10d102d5b92a4c9007d56f7ae4819` (`Probe` sweep, empty), `ev_a7f0e69abe5e4c8644c2bc3150a4c25150e62b522301a79744f5d2107904df6b` (`\Device\` strings, empty), `ev_57f12fd237cbc2f0fe1d3a0df23822e5254b36c1d7ed2eee9881c1ccde9eb2af` (`(A;` SDDL search, empty).
