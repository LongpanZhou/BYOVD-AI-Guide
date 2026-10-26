# Audit: VBoxNetAdp6.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\VBoxNetAdp6.sys` |
| Recorded SHA-256 | `4E619BB6370F4BC4BE52F43D6C43F3A86E3E2CE7BB04BAADFF17D3B731F18F3F` (matches triage_index.csv row 71; verified before opening; REA reports the same digest) |
| Company/Version | Oracle and/or its affiliates, 7.0.14.161095 (triage row). NDIS 6 miniport (host-only adapter) that is a **kernel client of `\Device\VBoxDrv`** (`IoGetDeviceObjectPointer`). Triage state: **Running** on this host |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope. Hypervisor-adjacent: analyzed, not loaded (per ledger rule) |
| Verdict | **WRITE-HIGH (candidate; SG producer not in file; guest influence not established; not host-user reachable through this driver's own surface)** — the receive conversion `FUN_140002450` copies the sum of segment lengths into a buffer sized by a separate `total` field, with no check between them. Exploitability depends on whether the SG producer in VBoxDrv guarantees `sum(len) <= total`. That producer is not in this file |
| Coverage | ~50%. Reviewed: receive entry `FUN_1400021C0`, SG-to-NB conversion `FUN_140002450`, copy helper `FUN_14001EC40`, gate `FUN_140001AC0`, send path `FUN_140002600`, descriptor builder `FUN_140001B20`, MDL teardown `FUN_140001710` / `FUN_140002350`, `RTMemContAlloc`, `FUN_140012740`, VBoxDrv client `FUN_14001EA00`. Not traced: the SG producer (VBoxDrv), the miniport init and OID paths, `FUN_1400029D0`, `FUN_14001EBE0`, and the indirect callers of `FUN_1400021C0` |

> **Static-only.** No load, no device open, no IOCTL, no SG injected. Addresses are linked VAs (image base `0x140000000`). Hypervisor-adjacent: the open question is answered by reading the producer's invariant, not by testing on the host.

## Entry surface

- Miniport registration via `NdisMRegisterMiniportDriver`; NDIS handler table not resolved. `FUN_140002600` (send path) and `FUN_140002350` (NBL return, no direct callers, indirect) are the two handlers reached from NDIS.
- `FUN_1400021C0` (receive entry, `NdisMIndicateReceiveNetBufferLists` at `0x140002265`) has **no direct callers** in the call graph. It is reached through an indirect callback from the VBox transport. Its argument `param_3` is an SG descriptor supplied by that transport. The SG is therefore **not** created by the NDIS side.
- Imports relevant to memory: `MmMapLockedPagesSpecifyCache` (3 in-procedure sites via thunk `0x1400200B0`, all `KernelMode`, flags `0x40000010`), `MmGetPhysicalAddress` (1 site, in `RTMemContAlloc`), `MmIsAddressValid` (1 site, in `FUN_140012740`), `MmAllocateContiguousMemory` (1 site, in `RTMemContAlloc`).
- No `IoCreateDevice` / symbolic link / SDDL. The host user has no device object of this driver's own. `\Device\VBoxDrv` is the only device name, and it is opened as a client.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| **SG-to-NB copy with no sum check** | `FUN_140002450`: `NdisAllocateMemoryWithTagPriority(adapter, total, …)` where `total = *(uint*)(SG+0x20)`. Then, for each of `count = *(ushort*)(SG+0x2c)` segments, `FUN_14001EC40(dst, seg.ptr, seg.len)` and `dst += seg.len`. Nothing compares `Σ seg.len` to `total`. `FUN_14001EC40` is an unbounded `memmove`. Result: a pool overflow of `Σlen − total` bytes whenever the producer's invariant fails | `ev_12be20d7…` (`FUN_140002450`), `ev_d726c3a7…` (`FUN_14001EC40`) |
| Gate before the copy | `FUN_140001AC0` checks adapter state (`+0x88 == 3`, `+0x8C == 2`) and that a stored pointer is canonical. It does not look at the SG lengths | `ev_1e560f75…` |
| Receive entry | `FUN_1400021C0`: canonical check on `+0x58`, refcount, gate, convert, indicate. No SG validation | `ev_42362581…` |
| Send path | `FUN_140002600` builds a descriptor per NBL with `FUN_140001B20` (count-bounded: allocation `(count+2)·0x18`, entries `≤ count`). Frame reads are gated on length ≥ 6 | `ev_0f8d991a…`, `ev_0682d9b9…` |
| MDL teardown mapping mismatch | `FUN_140001710` (MDL free list, called from the `FUN_140002450` error path) and `FUN_140002350` (NBL return, indirect): when `(MdlFlags & 5) == 0` they call `MmMapLockedPagesSpecifyCache` and then `NdisFreeMemory(mappedVA)`. That is correct only if the MDL is pool-sourced. For non-pool MDLs it is an invalid pool free. Which MDLs reach this branch was not established | `ev_68e0ba7c…`, `ev_46ff714c…` |
| Contiguous allocation and physical address | `RTMemContAlloc` (`FUN_140013FF0`): `MmAllocateContiguousMemory(roundup(size), 0xFFFFFFFF)`, then `MmGetPhysicalAddress`, then writes the low 32 bits of the PA to `*param_1`, the caller's output pointer. Callers not resolved (indirect). The same pattern appeared in the `VBoxUSBMon` audit | `ev_11564af9…` |
| Probe-like read | `FUN_140012740`: `MmIsAddressValid` checks one byte (`base+off+11`), then `memcmp` reads up to 12 bytes. Read-side only; a page crossing is a DoS. Writes only fixed globals `DAT_140033428..30`, from a matched entry | `ev_b627e548…` |
| VBoxDrv client | `FUN_14001EA00` opens `\Device\VBoxDrv` (`0x1F01FF`) and issues one fixed IOCTL (`0x22A7BC`). No caller-controlled code or size | `ev_9300e75a…` |

## Verdict rationale

The receive conversion writes `Σlen` bytes into a pool block sized `total`, and the only inputs are the SG descriptor's `total`, `count`, and segment lengths. The driver does not check that they are consistent. That is a real pool overflow with length- and content-controlled bytes. Reachability is the question:

- **Not** reachable from a host user through this driver's surface: packets sent by the host go through `FUN_140002600`, which is bounded.
- **Reachable** if the VBox transport can deliver an SG whose segments do not sum to `total`. Whether it can is the open invariant. The producer is in VBoxDrv and was not audited here. A guest-influenced SG (guest frame lengths reaching the SG builder) would make this a guest-to-host write primitive.

Escalate to **WRITE-CRITICAL** if the invariant can be violated from an unprivileged host user through any VBox IOCTL. Drop to **NO-WRITE** if the VBoxDrv producer guarantees `Σlen ≤ total` for every SG it delivers.

## Open items

- **Producer invariant (decisive).** Audit the VBoxDrv SG builder for the intnet receive path: whether `total` is derived from the same segment set, and whether the guest-side frame length is clamped before it reaches the SG.
- Indirect callers of `FUN_1400021C0`, and the callback registration (which VBoxDrv function calls it).
- The `MdlFlags` provenance for the `FUN_140002350` / `FUN_140001710` teardown branch (which MDLs have `(flags & 5) == 0`).
- `RTMemContAlloc` callers and the origin of the `*param_1` output pointer.
- `FUN_1400029D0` and `FUN_14001EBE0` (post-receive and send-to-VBox routines).

## VM confirmation plan (orchestrator-owned; VM only)

1. **Host: no loading.** This is a running driver on the host and hypervisor-adjacent. The static item is the producer invariant.
2. **VM, read-only first.** In a snapshot guest, record the SG descriptors that the intnet receive path delivers (kernel breakpoint on `FUN_1400021C0`, read-only). Check `Σlen` against `total` for normal and boundary frames.
3. **Destructive step.** Only if step 2 shows a violable invariant. Run it solo in the VM per the pool-corruption protocol. Never on the host.

## Evidence (REA, retained IDs)

`ev_12be20d7020a495c29f8777198e9cee82de0e530b922dee2eac22b8d7f7734ed` (`FUN_140002450`), `ev_42362581…` (`FUN_1400021C0`, full ID `ev_423625810b50238a072ac94f43492e0b1f4190fa5e0b7165a82970b22418b861`), `ev_d726c3a7e5bde9b054841f0e5c4cf1350ad1a5c267fa5cd4eb462a4cea8f9df0` (`FUN_14001EC40`), `ev_1e560f75083e0f4058f53b41b5e861c7354dff4074705715acedbb6a3bbeda38` (`FUN_140001AC0`), `ev_0f8d991ae2e82fc1787fdc8c9b6a03baa3a01f260214d36f6e1cb554d566923c` (`FUN_140002600`), `ev_0682d9b92eb0eee7a7725f7c6e85395f6e893d88847e64a80defa8ef7a460bde` (`FUN_140001B20`), `ev_68e0ba7c5e4cdde13372bd6ed13d0806f0aa5aec00de15b22c89fdaf51f1419b` (`FUN_140001710`), `ev_46ff714cdd1f4c95868ece0b21c9e044514820f1fd3f571c38639080147dc2bc` (`FUN_140002350`), `ev_11564af9a7f936e02d6e068161c3d4c188550e236ce7977ebe731a6255018c6e` (`RTMemContAlloc`), `ev_b627e54870c44a41dc5f008ab544352dfb93fa1171d2a119dbe573de5409a9ab` (`FUN_140012740`), `ev_9300e75a81c9c8993dc482ca3d6838eb12b1d4cdd21cb919020f0e8397806767` (`FUN_14001EA00`), `ev_e9dfbff929241a1f21ff36de3e220ea0a6a1afb491d34644e0d905d44ea86d2d` (callers of `FUN_140002450`), `ev_14d6dc68a397915d61d65b615fc56d7281fb03dee8646be59b6b30e4563d4fe3` (callers of `FUN_1400021C0`, none), `ev_b9263466a41b0f317ea4f5695e6e84c3b970de6ddf4f1d459b71d6936a274bfa` (`MmMapLockedPagesSpecifyCache` xrefs), `ev_773bd6f64d253ab024c61e03ca1d3256e3885d15b0ff88c1be21cb5225ebf7ec` (`Mm` sweep), `ev_4930f97a2919983ad331d33b49afaba575cb87a803af2160cc36d050559334d8` (`Ndis` sweep), `ev_dbf3114c723c18c7246a04e1110942cdaf7e46775fc4eedbfb90adf949c6d5bc` (`\Device\` strings).
