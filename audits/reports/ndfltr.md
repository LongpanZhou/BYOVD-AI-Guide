# Audit: ndfltr.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\ndfltr.sys` |
| Recorded SHA-256 | `E3708D62DEA31BA03D7CE7EEF6A270DA2B3556559140B556F5AB4EA289F921E2` (verified against triage_index.csv) |
| Company/Version | Mellanox 5.50.14695 (NetworkDirect kernel provider "ndfltr", symlink `\DosDevices\Global\NetworkDirect`) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless, private project; REA shared bridge contended by parallel agents) |
| Verdict | **NO-WRITE** (no kernel memory-write primitive in-file; MDL mappings point driver-pages -> user VA, not the reverse) |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (document `target-e3708d62dea3.sys`).

## Entry surface

- KMDF bootstrap (same WinOF family); device `\Device\Ndfltr` (`STR 14001CD60`, site `0x1400027C8` in `FUN_14000278C`) with symbolic link `\DosDevices\Global\NetworkDirect` (`STR 14001CDD0` chain).
- Device type set via WDF slot `+0x210` -> `0x12` (FILE_DEVICE_NETWORK); **no SDDL assignment** -> OS default device security (worst case assumed openable, per repo precedent).
- Dispatch (`FUN_14000278C` queue config -> `FUN_1400030A0` -> `FUN_1400024A8`): IOCTL code decoded into (family `uVar9 = (code>>8)&0x3F`, function `uVar7 = (code>>2)&0x3F`) and dispatched through a bounds-checked table `(&DAT_14001E6B0 limits / &DAT_14001E6D0 callbacks)` - calls the callback only when `uVar7 < table[family]>>8`, else `0xC0000010`.
- `EvtFileCreate` (`FUN_140003020`): pure ref-count bump, no gate, no data.
- Special codes: `0x120000` (Fn 0) -> `FUN_140002200` (open CQ/file context - internal ring-slot allocation, bounded), `0x120010` (Fn 4) -> `FUN_140007878` (alloc handle, 8 B out), `0x120014` (Fn 5) -> `FUN_140008378` (release by handle), `0x120410` -> direct NULL-status completion.

## Memory-write analysis

- **Caller identity:** the adapter-open path (`FUN_140013840`) captures the caller subject context (`SeCaptureSubjectContext`/`SeLockSubjectContext`), queries `SeQueryAuthenticationIdToken`, and stamps the **token-derived** AuthenticationId into the adapter context (`FUN_140010010`) - identity comes from the token, not from input. `SeTokenIsAdmin` is invoked but its result is discarded (vestigial check - access-control observation only; no memory-write path depends on it).
- **MDL plane:** `FUN_140019120` allocates driver-owned pages (`MmAllocateNodePagesForMdlEx`); `FUN_140019258` maps such a driver-owned MDL into **USER** address space (`AccessMode=1`) - the ND shared-memory API. The trust direction is kernel->user: no caller MDL is ever mapped into system VA in this file.
- Ring/free-list operations (`FUN_140002200`, `FUN_140002F30`-family): fixed stride bookkeeping with slot allocations drawn from the driver's own ring state; indexed writes occur at slots obtained from the allocator (bounded by construction).
- **Not found:** no `MmProbeAndLockPages` on any request MDL, no `MmMapIoSpace`/`MmGetPhysicalAddress`/`ZwOpenSection`/`MmCopyMemory`, no METHOD_NEITHER, no MSR/GDT/IDT patterns, no user-length-driven fills.

## Memory-touching IOCTL table

| Code | Fn | Method | Action |
|---|---|---|---|
| `0x120000` | 0 | BUFFERED, ANY | `FUN_140002200` - open context, bounded ring-slot write |
| `0x120010` | 4 | BUFFERED, ANY | `FUN_140007878` - 8 B handle out |
| `0x120014` | 5 | BUFFERED, ANY | `FUN_140008378` - release by handle |
| `0x120410` | 0x104 | BUFFERED, ANY | direct completion, no data |
| table family routes | various | BUFFERED, ANY | bounds-checked callback dispatch |

## Verdict + VM confirmation plan

**NO-WRITE.** The ND provider's dispatch is table-bounds-checked, identity is token-derived, and all mapped memory is driver-owned; no caller-controlled kernel write path was found.

VM plan (orchestrator-owned, non-destructive): open `\\.\Global\NetworkDirect` under a restricted token to record the effective DACL; register a provider via `0x120000`-family routes and observe allocations (pool tags); no corruption test warranted by static evidence.

*End of report.*
