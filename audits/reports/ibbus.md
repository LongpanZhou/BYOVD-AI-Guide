# Audit: ibbus.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\ibbus.sys` |
| Recorded SHA-256 | `0F3E4F33B019B278B6657B4ECEC25D04B128578622539FF5855330BDB6537545` (verified against triage_index.csv; recomputed with Get-FileHash) |
| Company/Version | Mellanox 5.50.14695 (MLNX_WinOF `core\al\kernel` - InfiniBand Access Layer core + bus) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless, private project; REA shared bridge contended by parallel agents) |
| Verdict | **NO-WRITE** (no kernel memory-write primitive found in-file; reachability gated by the OS default device DACL) |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (document `target-0f3e4f33b019.sys`, SHA `0F3E4F33B019B278B6657B4ECEC25D04B128578622539FF5855330BDB6537545`).

## Entry surface

- DriverEntry `FUN_140001000`: DriverObject MajorFunction stores - MJ_CREATE `FUN_140002EE0` (fails with `0xC0000184`/STATUS_NOINTERFACE until provider-registered), MJ_CLOSE `FUN_140002E20`, MJ_CLEANUP `FUN_140002DE0`, MJ_CANCEL `FUN_140003170`, MJ_PNP `FUN_140002F60`, **MJ_DEVICE_CONTROL `FUN_140002E60`**.
- Control device `\Device\ibal` + links `\DosDevices\Global\ibal`, `\DosDevices\Global\ibat` (file bytes RVA `0x76950`).
- **No SDDL string and no `Se*`/`ZwSetSecurityObject` imports** -> OS default device security for FILE_DEVICE_NETWORK applies (admin-gated in practice; worst case assumed openable, per repo precedent).
- MJ_DEVICE_CONTROL first runs the AL processor `FUN_140011434`; unrecognized codes forward to the lower stack.

## Memory-write analysis

**AL ioctl architecture:** `FUN_140011434` decodes `IoControlCode` and routes ~200 codes across 8 range sub-switches: `0x3B0001-2B` -> `FUN_140058184` (core), `0x3B002D-DB` -> `FUN_14006202C` (CA/adapter, `al_proxy_verbs.c`), `0x3B013D-93` -> `FUN_140064D00`, `0x3B0195-B3` -> `FUN_140057288`, `0x3B00DD-117` -> `FUN_140064AF4`, `0x3B0119-3B` -> `FUN_140067EB4`, `0x3B01B5-EF` -> `FUN_140069764`, vendor `0x222008-20` -> `FUN_14006A31C`. Unrecognized -> `0xC0000010`.

**Checked patterns:**
- Range routing and sub-switches are table-driven with bounds checks (no attacker-indexed OOB into the callback tables observed on the sampled paths).
- **METHOD_NEITHER discipline (sampled al_proxy paths, `FUN_14005FF88` etc.):** fixed-size validation first (`InputBufferLength == 0x30`, `OutputBufferLength == 0x20`); user out-pointers taken from the input struct (`in[5]`) are **ProbeForWrite'd** before `FUN_14006A678` copies the kernel result out; the copy helpers (`FUN_140057470`, `FUN_140059744`, `FUN_140059764`) **ProbeForRead** before `memmove`. ProbeForWrite/ProbeForRead raise on kernel-VA targets (buffers above `MmHighestUserAddress`), so no user-supplied pointer can be turned into a kernel write on these paths.
- **File-object association** (`FUN_1400575DC`): user-supplied handle -> `ObReferenceObjectByHandle(READ_CONTROL)`, then the driver writes its OWN context pointers into the referenced FILE_OBJECT (`FsContext`/`FsContext2`). Object is owned by the driver; not attacker data.
- **MDL directions:** `MmAllocateNodePagesForMdlEx` (driver-owned pages) + `MmMapLockedPagesSpecifyCache(AccessMode=User)` - kernel pages mapped out to the user process. No request-MDL->system-VA mapping exists in this file.
- memmove helper `FUN_140076440` has 33 callers; the sampled user-adjacent ones all probe first; remaining callers operate kernel->kernel (AL descriptor/attribute plumbing).

**Not found:** no `MmProbeAndLockPages` on caller MDLs, no `MmMapIoSpace`/`MmGetPhysicalAddress`/`ZwOpenSection`/`MmCopyMemory`, no MSR/GDT/IDT patterns, no user-length-driven fills/fixed-destination mismatches in the sampled dispatcher and proxy paths.

**Residual unknown (accepted scope):** the CM/AT sub-switch handlers (`FUN_140064AF4`, `FUN_140067EB4`, `FUN_140069764` ranges - connection-manager MAD plumbing) were routed, not exhaustively audited; they receive the same probed request plumbing.

## Memory-touching IOCTL table

Summarized above by range - ~200 buffered/METHOD_NEITHER codes routed through the AL proxy; the decisive ones are the vendor range `0x222008-20` (attribute query - probed write-back) and the adapter-open range (token-derived identity).

## Verdict + VM confirmation plan

**NO-WRITE.** The historic "ibbus maps user memory into kernel" pattern is NOT in this file statically: the mapping plane is delegated to the registered provider (mlx4 verbs provider via the `GUID_MLX4_COMMON_INTERFACE`/`GUID_RDMA_INTERFACE_VERBS` interfaces taken at D0), and in-file METHOD_NEITHER paths probe both directions correctly.

VM plan (orchestrator-owned, non-destructive): open `\\.\ibal` under a restricted token to record the effective DACL; issue the attribute-query vendor code `0x222008` with a 0x30/0x20 pair to confirm the probed path executes; no corruption test warranted by static evidence.

*End of report.*
