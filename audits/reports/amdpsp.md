# Audit: amdpsp.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\amdpsp.sys` |
| Recorded SHA-256 | `0A3AF18439B6BB4AF119C8020A3D0220ED6CC8AE04E20032F846E77777700A0A` (matches triage_index.csv row `amdpsp`; sha256 recomputed in-session) |
| Company/Version | Advanced Micro Devices, Inc. (AMD Platform Security Processor driver; KMDF; PDB `amdpsp.pdb`) |
| Method | Static-only audit via REA/Ghidra 12.1.4, memory-write scope only |
| Verdict | **WRITE-HIGH (candidate, provisional)** - an unprivileged-reachable path (per in-file SDDL) returns a user-mapped RW view of physically-contiguous kernel memory **with its physical address**; a kernel-side write is **not yet demonstrated** (the PSP mailbox consumer is untraced) |
| Coverage | ~60%. Not traced: the PSP mailbox/command submit (`FUN_140005980`, `FUN_140002e20`, `FUN_140003810` slot-free path), `FUN_140002b50` (allocator selection), the SDDL apply site, WDF request wrappers, `FUN_1400026a0` case bodies beyond the allocation IOCTLs |

> **Static-only.** No load, no device open, no IOCTL execution. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- KMDF driver. IOCTL dispatch `FUN_1400017b0` (WDF request APIs, `DAT_14001af50` table). IOCTL codes `0x9c422000`-`0x9c422009` (with `0x9c422800+` routed to `FUN_1400026a0`).
- SDDL in the binary at `0x140009210`: `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)`. **Grants Everyone (`WD`) read/write/execute.** This descriptor is present in-file; the call that applies it to the IOCTL device was not traced.
- No `IoCreateDevice`, `IoCreateSymbolicLink`, or `IoRegisterDeviceInterface` in the NTOSKRNL import table. Device creation is through WDF.

## IOCTL surface (memory-touching)

| Code | Handler | Input | Action |
|---|---|---|---|
| `0x9c422002` | `FUN_140003020` (via `FUN_1400017b0`) | 8 bytes (size, `uint`) in; 0x38 out | `FUN_140002b50` / `FUN_140002c30` allocates **contiguous** kernel memory of the caller's size (`MmAllocateContiguousMemorySpecifyCache(size, 0, 0xFFFFFFFFF, 0x4000000, 0)`); `MmGetPhysicalAddress` -> output; `IoAllocateMdl` + `MmBuildMdlForNonPagedPool` + `MmMapLockedPagesSpecifyCache(mdl, **UserMode**, ...)` -> **user VA** returned to the caller |
| `0x9c422009` | `FUN_1400017b0` case | 16 bytes in | MDL/WDF memory helper (not traced) |
| `0x9c422003` | `FUN_140003810` | 8 bytes | Frees a slot's mapping (slot lookup, `FUN_140002e20`) |
| `0x9c422004` / `0x9c422005` | `FUN_140003fb0` | 8 bytes | Slot table (16 slots) of **caller-supplied buffers** referenced through WDF memory objects; buffer address stored into slot |
| `0x9c422800+` | `FUN_1400026a0` | 0x28-byte header | Allocation/mapping case bodies; `0x9c422820` -> `FUN_140006920` (`MmMapLockedPagesSpecifyCache` **UserMode**) |

## Memory-write analysis

| Pattern | Result | Evidence |
|---|---|---|
| User-controlled allocation size | **Present.** `FUN_140003020` takes the 4-byte size from the input and passes it to a contiguous allocator with no visible cap in the function (`param_2 != 0` only). Allocator selection in `FUN_140002b50` not traced | `ev_8594f8ee...`, `ev_530c6617...` |
| Kernel memory mapped RW into the caller | **Present.** `MmMapLockedPagesSpecifyCache(mdl, 1 = UserMode, 1, ...)` in `FUN_140003020` and `FUN_140006920` maps the driver buffer into the **calling process** and returns the user VA | `ev_5a675094...`, `ev_6399e98a...` |
| Physical address disclosure | **Present.** `MmGetPhysicalAddress` result returned in the output struct (`*param_3`) | `ev_8594f8ee...` (`FUN_140002c30`) |
| Caller buffer registered as a device-side buffer | **Present.** `FUN_140003fb0` stores a WDF memory reference for a caller buffer into a 16-slot table (`+0xc4 + 0x120*i`). These slots are the buffers the PSP consumes | `ev_a39aefdd...` |
| Kernel write driven by caller-chosen address | **Not established.** No direct store to a caller-supplied kernel address in the decompiled paths. The mailbox consumer that could turn registered buffers or physical addresses into writes is untraced | - |
| `ProbeFor*` in the module | **Absent.** Caller buffers are handled through WDF request/memory APIs (framework probes), not visible here | import sweep |
| Physical MMIO mapping | `FUN_14001d590` maps firmware/BAR ranges from a kernel-provided resource list (not caller-controlled); its caller `FUN_14001d130` not traced | `ev_92e72227...`, `ev_ede9b250...` |

## Findings

1. **Unprivileged primitive (candidate).** If the Everyone-writable SDDL is applied to the IOCTL device, any local user can request contiguous kernel memory of a chosen size, map it RW into their process, and read its physical address. The memory is then usable as shared kernel/PSP memory.
2. **Confidentiality impact is immediate.** The user receives the physical address of driver-owned contiguous memory (KASLR/PA disclosure) regardless of whether a write exists.
3. **Write impact is unproven.** A kernel write requires the PSP or the driver to act on user-written contents. That path (mailbox submit, `FUN_140005980`, `FUN_140002e20`) is the main open item.

## Verdict rationale

WRITE-HIGH (candidate, provisional). The reachability and RW-mapping primitives are established in-file (conditional on the SDDL assignment). The kernel-write step is not yet traced, so this is a candidate rather than a confirmed write. Escalate to **WRITE-CRITICAL** if the mailbox consumer uses caller-written physical addresses for memory writes. Drop to **WRITE-MEDIUM** if the SDDL is not applied to the device or if the consumer validates addresses.

## Next steps (for the write-only pass)

- Apply/trace the SDDL: find the call that consumes `0x140009210` (WDF `WdfDeviceInitAssignSDDLString` or device-interface SD).
- Trace `FUN_140005980` and `FUN_140002e20` for mailbox writes and whether registered buffer physical addresses are written to MMIO or memory.
- Decompile `FUN_140002b50` to confirm the allocator's size cap.

## VM confirmation plan (orchestrator-owned; non-destructive; no host load)

1. Snapshot, unprivileged token: `CreateFile` on the WDF device interface. Record whether Everyone access holds.
2. If open: request `0x9c422002` with a small size (e.g., 0x1000). Check the returned user VA is writable and that the physical address matches the kernel's `MmGetPhysicalAddress` view (kd, read-only).
3. Any write test that causes the PSP to act on caller-written addresses is **out of scope** here and reserved for the solo VM phase.

## Evidence (REA, retained IDs)

`ev_8594f8ee5a478e1fe80272ff9d51065fed4a2a8c0cf3d7940379996acbd91402` (`FUN_140002c30`), `ev_530c6617379cb964ed6cb38513b702cc1ddd497bc569cdd2356d05bab6ad16bb` (`FUN_1400017b0`), `ev_cd1ea4739a5031ae589f097e6e6c01ce9167cc323412dbff70d522b8bdddee11` (`FUN_1400026a0`), `ev_5a67509474a8019d0f36c5cb4874d351bea8954a11897a51e32bf528630b199e` (`FUN_140003020`), `ev_8d6cf363cdbd288041de47ba995c4f1f6f60d99ed6b5f69daa380846de0ff704` (`FUN_140006920`), `ev_df5127f6df89481add181d1d44e4e716d9d37e517b60c6fcd7952ffea3382238` (`FUN_140003810`), `ev_a39aefdd43889665581cf6a939722c061ab92eb48e09902871e87d33ab861081` (`FUN_140003fb0`), `ev_5e36b9268161996c204e99a2034293bc1a7f5b03edf29af0c49812d7fb5af291` (SDDL string), `ev_92e722279367301002ef29e8354e487959b1c066a92214e12e6905d5348770a3` (`FUN_14001d590`), `ev_ede9b2502905be87cb5746279fc516d605147c4766ff757fd5e25732f053c4eb` (callers of `FUN_14001d590`).
