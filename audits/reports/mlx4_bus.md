# Audit: mlx4_bus.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\mlx4_bus.sys` |
| Recorded SHA-256 | `2C6B268486AD0F3BFB82DE0F61D076DF7C334C1C94A0316084713EBDB0C9C518` (matches triage_index.csv row `mlx4_bus`; sha256 recomputed in-session) |
| Company/Version | Mellanox Technologies (WinOF 5.50 bus driver; PDB `mlx4_bus.pdb`; source tree `MLNX_WinOF-5_50\hw\mlx4\kernel\bus`) |
| Method | Static-only audit via REA/Ghidra 12.1.4, memory-write scope only. Deep form for the probed user-buffer path; short coverage elsewhere |
| Verdict | **NO-WRITE (kernel), coverage-limited (~30%)** - no write through a caller-controlled kernel address found; one probe-length mismatch on the user-buffer out-path (writes past the probed user range, DoS-class). Not reviewed: 27 `MmMapIoSpaceEx` BAR sites, 5 `MmMapLockedPagesSpecifyCache` sites, `MmSecureVirtualMemory` sites |
| Coverage | Reviewed: `FUN_1400289b8` (bus_verbs out-path), `FUN_1400c17a0` (user-buffer lock/map), `FUN_1400c9bc8` (iobuf build). Not reviewed: device/BAR init, the 27 `MmMapIoSpaceEx` callers, provider callback `*(lVar9+0xca78)` targets, `FUN_140028744` (handle lookup), `FUN_140031474` (allocator), `FUN_1400ca980` (copy helper) |

> **Static-only.** No load, no device open, no IOCTL execution. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- WDM bus driver with no `IoCreateDevice` in the import table. The IOCTL/verbs surface is reached via WDF request helpers (`DAT_140109568` table) and is the bus-verbs path used by the IB-AL provider (`ibbus.sys`, audited NO-WRITE in the C batch).
- Memory-relevant imports: `ProbeForWrite` (2 xrefs; 1 in-procedure), `MmProbeAndLockPages` (3; 2 in-procedure), `MmMapLockedPagesSpecifyCache` (5), `MmMapIoSpaceEx` (27), `MmUnmapIoSpace`, `IoAllocateMdl`, `MmBuildMdlForNonPagedPool`, `MmAllocateContiguousNodeMemory`, `MmSecureVirtualMemory`, `MmUnsecureVirtualMemory`, `IoGetDmaAdapter`.
- No SDDL string found in the binary (`D:P` search empty). Device DACL is therefore the I/O-manager default for whichever device the verbs path uses (not established in-file).

## Reviewed memory paths

### `FUN_1400289b8` - bus-verbs out-path (`ProbeForWrite`)

- Input: 16-byte request (`local_60`): handle (`*local_60`), user output VA (`*(local_60+4)`), size (`*(uint*)(local_60+2)`, `local_64`).
- Allocates a kernel buffer of `local_64` bytes (`FUN_140031474`, `bus_verbs.c:277`), calls provider callback `*(lVar9+0xca78)` which may return status 2 (`local_64` reset to needed size) or 0 (success).
- On success: `ProbeForWrite(userVA, local_64, 8)`, then `FUN_1400ca980(userVA, kbuf, *(uint*)(kbuf+3))` copies `*(uint*)(kbuf+3)` bytes to the user buffer.
- Probe-length mismatch: the copy length comes from the provider-written header (`kbuf+3`), while the probe covers only `local_64`. If the header value exceeds `local_64`, the copy writes past the probed user range. The destination is **user** memory; the kernel-side fault or overrun is DoS-class, not a kernel write.
- Relocation loop after the copy adds `userVA` to pointer fields at `+0x128` / `+0x130` of up to `*(byte*)(user+0xe4)` entries of `0x138` bytes. Those writes land in the same user region and use provider-derived offsets. Same bound caveat.

### `FUN_1400c17a0` - user-buffer lock and map (conditional on `ctx+0xa4`)

- If `ctx+0xa4 == 0`: passes the VA through (no lock). Otherwise: `IoAllocateMdl(VA, len)`, `MmProbeAndLockPages(mdl, 1 = UserMode, IoWriteAccess flag from request)`, `MmMapLockedPagesSpecifyCache(mdl, KernelMode, cached, ...)`. The mapping is kernel-side; failure paths unlock and free the MDL.

### `FUN_1400c9bc8` - iobuf construction (`iobuf.c:193`)

- `IoAllocateMdl(VA, len)`, `MmProbeAndLockPages(mdl, AccessMode, IoWriteAccess*2)`. Page count `(len + 0xfff + (VA & 0xfff)) >> 12` is computed correctly (shift binds after the additions).
- Failure path unwinds. No caller-controlled kernel address reaches a write in the reviewed code.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Write through caller-controlled kernel address | None found in reviewed paths | `ev_9b56cd09...`, `ev_7f65e52e...`, `ev_dac318fb...` |
| Probe-length vs copy-length mismatch (user out-path) | **Present.** `ProbeForWrite(userVA, local_64)` vs copy of `*(uint*)(kbuf+3)`. Writes to user memory past the probed range. DoS-class | `ev_9b56cd09...` |
| MDL lock with caller access mode | `FUN_1400c9bc8`: AccessMode and IoWriteAccess flags come from the caller; not traced further | `ev_dac318fb...` |
| BAR mapping (`MmMapIoSpaceEx`, 27 sites) | Not reviewed. Expected to be hardware-driven (BAR ranges from resource list); caller reachability unknown | import xrefs |
| `MmSecureVirtualMemory` | Not reviewed | import sweep |

## Findings

1. **Probe-length mismatch (DoS-class, user memory).** The out-path can write past the probed user range when the provider header exceeds the provider-returned size. This is a memory-safety defect in the driver, but the write target is the caller's own user memory.
2. **No kernel write** in the reviewed paths. The driver's kernel-side writes are provider-owned buffers.
3. **Coverage gap.** 27 BAR-mapping sites and the provider callback targets were not reviewed. A caller-controlled BAR offset or length in those paths is the main escalation route.

## Verdict rationale

NO-WRITE (kernel), coverage-limited. Escalate to WRITE-MEDIUM if a caller-controlled value reaches a `MmMapIoSpaceEx` offset or length, or if the provider header can be made to exceed the probed size with a kernel-side effect. Escalate to WRITE-HIGH if the BAR mapping is user-reachable and writable.

## Next steps (for the write-only pass)

- Enumerate the 27 `MmMapIoSpaceEx` call sites (resolve containing functions) and check which take caller-derived offsets or lengths.
- Trace the provider callback `*(lVar9+0xca78)` for the bus-verbs path and confirm the header size bound.
- Confirm the device/ibal DACL for the verbs path (default `IoCreateDevice` assumptions in `ibbus.md`).

## VM confirmation plan (orchestrator-owned; non-destructive)

1. Unprivileged token: confirm whether the ibal device opens. Record the result.
2. If open: issue a bus-verbs query with a small user buffer and check the returned size. No overrun test in this round.

## Evidence (REA, retained IDs)

`ev_9b56cd0908d4fb6ae5be25d3d950728d9e6c7d6307b33d415b112a963e5f16ad` (`FUN_1400289b8`), `ev_7f65e52e3b4afa65ebc74156c52fcc352bc1f9b6edda1719bdaac636efa89cff` (`FUN_1400c17a0`), `ev_dac318fbf8984cd1d7322beb207b081e24e06afae3a0830efe0999929a90cd9a` (`FUN_1400c9bc8`), `ev_eea8c2cfe3ab39be10c947af7223956a80fa0da1baefe6dd7ad5ab0ac2b69404` (`ProbeForWrite` xrefs), `ev_64bb12dadcb4691f09f3ac0321d161b63a419ae3bbdb18002a6f61c9a14ad4f9` (`MmProbeAndLockPages` xrefs), `ev_2ef5b89115a40a16dc9b36a1cf7ad5b0170f3105c210fe416d2a63384539f7c1` (`MmMapLockedPagesSpecifyCache` xrefs), `ev_e7238ea941ec150aea5f78393fc35a48a8e8f7e27852bf830ffe31cd44aff0ca` (`MmMapIoSpaceEx` xrefs).
