# Audit: winverbs.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\winverbs.sys` |
| Recorded SHA-256 | `D2A5ED039ED83010E0BB4BB1A69F9D142D42BE2C75E56CFCF3F157A735CB688E` (verified against triage_index.csv) |
| Company/Version | Mellanox 5.50.14695 (MLNX_WinOF `core\winverbs\kernel`) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless, private project; REA shared bridge contended by parallel agents) |
| Verdict | **NO-WRITE** (no kernel memory-write primitive in-file; user-memory mapping surface lives in the ibcore provider = ibbus.sys, audited separately) |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (document `target-d2a5ed039ed8.sys`).

## Entry surface

- KMDF driver, same WinOF bootstrap family as winmad.sys.
- Device creation `FUN_140001968`: `\Device\WinVerbs` (`STR 14000d310`, xref `0x140001996`) + `\DosDevices\WinVerbs` (`STR 14000d340`, xref `0x1400019d7`).
- **No SDDL assignment** (no SDDL strings, no `WdfDeviceInitAssignSDDLString`, no `IoCreateDeviceSecure`); OS default device security applies. Worst case (standard user can open) assumed, per NiSerP.md precedent.
- Publishes no device interface of its own; `GUID_RDMA_INTERFACE_VERBS` / `GUID_INFINIBAND_INTERFACE_CM` / `GUID_MLX4_COMMON_INTERFACE` strings are consumed ("Taken/Released") — the driver is a verbs *manager* on top of ibcore.
- Dispatch `WvIoDeviceControl` = `FUN_1400020d0` (queue-config callback chain in device add). No EvtIoRead/EvtIoWrite handlers are registered (no "reject WmIoRead/Write" strings — only the ioctl rejection path).

## Memory-write analysis

WDF runtime table at `DAT_140010468`: `+0x868` RetrieveInputBuffer, `+0x870` RetrieveOutputBuffer, `+0x838` Complete, `+0x848` CompleteWithInformation.

**Encoding:** ~48 codes, device type `0x3BE`, Fn `0x001`–`0x035` (raw `0x3BE004`…`0x3BE0D4`), all `METHOD_BUFFERED` + `FILE_ANY_ACCESS`.

**Checked patterns (all bounded):**
- Object-handle lookups (`FUN_140006e94` MR-key ctx, `FUN_1400081e4` SRQ/QP ctx, `FUN_140009a7c`, `FUN_1400012f4` free-list pop): every indexed access is guarded by `idx < ctx+0xNN` before `arr + 0x10 + idx*0x18` or the list `*0x18` stride. ✓
- `0x3BE004` → `FUN_140001fbc` (query provider list): retrieve **output** min `0x10`; writes `out[1 + idx] = provider[0xb]` under the condition `idx < (outLen-8)>>3`, so the highest byte written is `out + 8*floor((outLen-8)/8)` < `out + outLen`. Count at `out[0]`. **Bounded by the retrieved output length.**
- `0x3BE034` → `FUN_140006914` (register MR): output min 8; the 8-byte MR key returned by the **provider callback** (`prov[1]+0x140`) is read from the user output buffer and inserted into an AVL tree (`FUN_14000cc24`) — key comes from the provider, not attacker-arbitrary kernel pointer. Allocation is a fixed `0x40` (`Mxrm`).
- `0x3BE088` → `FUN_14000826c` (create SRQ): fixed-field copies from the min-`0x20` input into a `0x30` pool object (`Mxcm`); all offsets `≤ 0x1c` inside the guaranteed input. ✓
- `FUN_1400058c0` (get-size-then-get via provider callback `+0x60`): allocation size comes from the provider's own query result, second query bounded to the same size. ✓
- `FUN_14000ce80` = memmove, `FUN_14000cb1c/cb74` = list splice, `FUN_140003ea4/f20/...` = ref-count helpers — no data-dependent kernel writes.

**Not found in-file:** no `MmProbeAndLockPages`, `MmMapLockedPagesSpecifyAccess`, `MmMapIoSpace`, `MmGetPhysicalAddress`, `ZwOpenSection`, `MmCopyMemory`, `Se*` imports; no METHOD_NEITHER; no MSR/GDT/IDT paths on any dispatch (the `rdmsr`/SGDT code is confined to the `tdb`/INIT compiler-library blob, entered only from library init).

**Cross-module caveat:** the actual user-memory registration (verbs `reg_mr` → MDL probe/lock/map) executes inside the **provider module** through `classCtx` function pointers (ibcore, shipped in `ibbus.sys`). Any unchecked copy or mapping there belongs to the ibbus.sys audit (#10 in this batch), not to this file.

## Memory-touching IOCTL table

| Code | Fn | Method | Handler | Data action |
|---|---|---|---|---|
| `0x3BE004` | 1 | BUFFERED, ANY | `FUN_140001fbc` | bounded provider-list copy-out |
| `0x3BE034` | 0xD | BUFFERED, ANY | `FUN_140006914` | provider MR key (8 B) out; AVL insert |
| `0x3BE088` | 0x22 | BUFFERED, ANY | `FUN_14000826c` | fixed-field header copies |
| remaining ~45 codes | | BUFFERED, ANY | provider-forwarding / query stubs | no in-file kernel copy beyond fixed fields |

## Verdict + VM confirmation plan

**NO-WRITE.** No kernel memory-write primitive is reachable from winverbs.sys itself: all copies are length-bounded by retrieved buffer sizes, all array/list writes are index-checked, and the data-heavy verbs (memory registration, QP/CQ operations) execute in the ibcore provider module.

VM plan (orchestrator-owned, non-destructive): open `\\.\WinVerbs` under a restricted token (record effective DACL); call `0x3BE004` (provider list) and observe writes; verb paths require an active HCA (mlx4_bus) and will fail with STATUS_INVALID_DEVICE_STATE without hardware — record that as a reachability limitation, no corruption test warranted.

*End of report.*
