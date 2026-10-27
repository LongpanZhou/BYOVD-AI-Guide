# Audit: nvvhci.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\nvvhci.sys` |
| Recorded SHA-256 | `9bf2401b21ff9b1cc3d8de7e1b0c229e0912830e98aa6d3e6791eb0fc5763a9b` (matches triage_index.csv row "nvvhci") |
| Company/Version | NVIDIA Corporation - 3.05.0.1 ("Virtual USB Host Controller driver", (C) 2021) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4, x86:LE:64) |
| Verdict | **NO-WRITE** |

> Static-only. The driver was never loaded, no device object was opened, and no IOCTL was executed on host or VM. All addresses are linked VAs at image base `0x140000000`.
> Note on session integrity: the REA Ghidra session is shared across concurrently running agents and the active program was switched by other agents twice; every result in this report was re-obtained after re-binding `target-9bf2401b21ff.sys` and validated against its SHA-256.

---

## Entry surface

Architecture is the WDM toaster/"busenum" pattern (string `BusEnumWMI` at `0x14000c8f0`, `Virtual USB Device` / `on NVVHCI Enumerator` at `0x14000c900/0x14000c930`), with the `WdmlibIoCreateDeviceSecure` shim statically linked (`WdmlibInit` `0x14000acfc`, `WdmlibIoCreateDeviceSecure` `0x14000ad88`, `SepSddl*` `0x14000b7ac-0x14000c208`).

- **Bus FDO** - `AddDevice` = FUN_140009d00 (`0x140009d00`): `IoCreateDevice(DriverObject, ext=0x120, name=NULL, DeviceType=0x2A, Characteristics=0x180, Exclusive=1)` at `0x140009d1a` - **unnamed, no SDDL**. It registers device interface GUID `{01EE4B4F-6FB0-4763-A843-415591F1F001}` (bytes at `0x140005290`) on the bus PDO and attaches to the stack (`0x140009d3c`, `0x140009d5e`).
- **Child PDOs** ("Virtual USB Device") - FUN_140003230 (`0x140003230`): `WdmlibIoCreateDeviceSecure(..., ext=0x138, name=NULL, 0x2A, 0x180, exclusive=0, SDDL, ClassGuid={CF71EB5F-385C-4FA3-93DD-712BEE3D3AFC})` at `0x140003294`, with SDDL `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)` (UNICODE_STRING at `0x140005400`, string at `0x140005410`) - **Everyone GRGWGX**, but the PDO is **unnamed** and no interface is registered on it, so it is not directly openable by user mode; it only feeds PnP.
- **DACL gate for the control plane**: the FDO gets the default device-object SD (no `SecurityQualityOf`, and read-only registry check on this machine shows the class keys `Control\Class\{CF71EB5F-...}` / `{01EE4B4F-...}` are absent, so no class-key `Security` override). Unprivileged opens of the interface therefore fail the default admin/system SD - **admin-gated**.

Dispatch roles pinned by decompilation (MajorFunction stores in DriverEntry FUN_14000d000; store sites `0x14000d098-0x14000d12f`): create/close = FUN_1400090d0 (`0x1400090d0`, no caller-identity check, gated only on devext+0x08 device-state flag); device control = FUN_140009190 (`0x140009190`); read = FUN_140009320 -> FUN_140001c60; write = FUN_1400093e0 -> FUN_140001e00; PnP = FUN_14000a860 -> FUN_140009f50 (via devext fn table at +0x10); internal device control = FUN_140001070.

## Memory-write analysis

Checked patterns and results:

| Pattern | Result |
|---|---|
| Copy-length confusion (out-bounds driven by user field) | None. All five control handlers (0x2A6000-0x2A6010) bound data by fixed struct offsets against checked input lengths >=0x10/0x18; the 0x2A6010 list fill is a fixed 0x80 zero-fill + bounded bitmap fill gated on `OutputBufferLength == 0x80` (FUN_14000a4b0 `0x14000a4b0`; fill helper FUN_1400036f0 `0x1400036f0` indexes `param_1[id]` only for `id < 0x80 && id != 0`). |
| METHOD_NEITHER user pointers | None used: every compared code is METHOD_BUFFERED (bits 1-0 = 00) and FILE_ANY_ACCESS (bits 15-14 = 00). Buffers come from `Irp->AssociatedIrp.SystemBuffer` only. |
| Caller MDL -> system VA | `MmMapLockedPagesSpecifyCache` (import, resolved via `MmGetSystemRoutineAddress`, name string `0x14000d59c`) is used at `0x14000139a`(FUN_140001070), `0x14000226c`, `0x140001384`(FUN_140001510/840/16a0) - **only on MDLs carried by URBs submitted by the child function-driver stack (kernel callers)**, never on caller/user MDLs; no `MmProbeAndLockPages` on user buffers anywhere. |
| `\Device\PhysicalMemory` / `ZwOpenSection` / `MmMapIoSpace` / `MmCopyMemory` | Absent from strings and from the full runtime-resolved name table (`0x14000d462-0x14000d8b2`). |
| wrmsr/rdmsr/GDT/IDT | No MSR/segment-table imports or names; no `MmGetSystemRoutineAddress` candidates of that class. |
| User-trusted length/count driving writes | READ path (FUN_140001c60 -> FUN_1400025d0 -> FUN_140001510/140001840/1400016a0): every response builder requires `readLen >= 0x30 (+ payload)` before writing into the READ IRP's SystemBuffer; payload copy = `readLen`-bounded (e.g. FUN_140001510 checks `param_3 < TransferBufferLength+0x30 -> STATUS_INVALID_PARAMETER` then copies exactly `TransferBufferLength` bytes). WRITE path (FUN_140001e00): copy into the URB's transfer buffer (possibly MDL-mapped) is double-bounded - `writeLen >= skip+0x30+copyLen` (packet bound, `0x1400022xx`) and `URB->TransferBufferLength >= copyLen` (`0x140002288` block). Config-descriptor walker FUN_1400024b0 and FUN_140002550 are wTotalLength/count-bounded. |
| Attacker-controlled index x size | Child-eject serial index is clamped `< 0x80` (FUN_14000a900 `0x14000a900`); bus list walk in FUN_1400036f0 clamps `id < 0x80`. |
| RtlFillMemory/memset with user length | FUN_140003dc0 (memset) callers pass fixed/constant sizes (0x120, 0x138, allocated sizes); none user-driven. |
| Registry/security-desc writes | ZwSetSecurityObject/Ob* /RtlGet*/SeCapture* helpers manipulate the driver's own device SDs (fix-DACL path); not reachable as a memory primitive. |

Out-of-scope for this round (recorded for context only): 0x2A6000/0x2A6004 let an (admin-gated) caller create/destroy virtual USB child devices; 0x2A6008/0x2A600C eject them. No kernel memory-corruption path found in any of them.

## Memory-touching IOCTL table

| Code | Method | Handler | Write action | Bound |
|---|---|---|---|---|
| `0x2A6000` | BUFFERED/ANY | FUN_14000a530 | creates child PDO, fills its devext (VID/PID/serial) | fixed 0x138 ext; fields fixed offsets |
| `0x2A6004` | BUFFERED/ANY | FUN_14000a6a0 | destroys child PDO (frees + IoDeleteDevice) | - |
| `0x2A6008` | BUFFERED/ANY | FUN_14000a900 | marks entry ejected (1 byte) | serial `< 0x80` |
| `0x2A600C` | BUFFERED/ANY | FUN_140009ea0 | IoRequestDeviceEject per entry | input == 0x10 required |
| `0x2A6010` | BUFFERED/ANY | FUN_14000a4b0 | zero-fills 0x80 + bitmap fill | out == 0x80 required |
| `0x220003/0x220007/0x220013` | INTERNAL | FUN_140001070/FUN_140002b10 | URB submission/completion into child PDO ext and READ buffers | kernel callers only |
| IRP_MJ_READ / IRP_MJ_WRITE | - | FUN_140009320/FUN_1400093e0 | dequeue/enqueue transfer results | IRP-length bounded |

All other MJ_* handlers: state-flag gating and forward/complete only.

## Verdict + VM confirmation plan

**NO-WRITE.** No user-reachable kernel memory-write primitive exists in the audited surface: the control plane (FDO interface `{01EE4B4F-6FB0-4763-A843-415591F1F001}`) carries only bounded list/config IOCTLs, the Everyone-DACL applies to unnamed child PDOs that cannot be opened directly, and the only dynamic mapping API operates on kernel-supplied URB MDLs with TransferBufferLength bounds. The five control codes are config-control (out of scope this round) and additionally admin-gated by the default device SD.

Coverage: ~85% of procedures accounted for (DriverEntry, AddDevice, full dispatch table, all 5 control IOCTLs + read/write + internal-URB paths decompiled; the PnP switch FUN_140009f50 and WMI context not fully decompiled - both receive only kernel-issued IRPs). VM plan if the orchestrator wants reachability data anyway: (1) open interface as standard user -> expect access-denied (DACL confirmation); (2) as admin, run the 5 control codes with benign payloads to confirm reachability - no destructive test needed since no primitive exists.

*End of report.*
