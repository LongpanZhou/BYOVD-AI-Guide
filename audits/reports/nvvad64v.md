# Audit: nvvad64v.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\nvvad64v.sys` |
| Recorded SHA-256 | `de0d4dbe87cf90f5a18b7c3cbd07f5041b2106855c4826fa1bb1df657276c807` (matches triage_index.csv row "nvvad_WaveExtensible") |
| Company/Version | NVIDIA Corporation — 4.65.0.3 ("NVIDIA Virtual Audio Driver") |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4, x86:LE:64) |
| Verdict | **NO-WRITE** |

> Static-only. No driver load, no device open, no IOCTL execution. Addresses at image base `0x140000000`. Every result re-validated against the target SHA-256 after observed cross-agent program switches of the shared Ghidra session.

---

## Entry surface

PortCls adapter driver (imports `PcInitializeAdapterDriver`, `PcDispatchIrp`, `PcAddAdapterDevice`, `PcRegisterSubdevice`, `PcNewPort`, `PcRegisterAdapterPowerManagement`, `PcRegisterPhysicalConnection` from portcls.sys). **No IoCreateDevice/IoCreateSymbolicLink import** — the driver creates no named device object of its own; all device objects and interfaces come from portcls (KS filters "Topology"/"Wave", registered via the MSVAD-sample-derived adapter in FUN_140007520/FUN_140007740).

- DriverEntry (from `entry` `0x14000c000`) → `PcInitializeAdapterDriver` + AddAdapter wrapper FUN_140007000 (`PcAddAdapterDevice(..., StartDevice=FUN_140007740)`).
- Custom dispatch: FUN_140007030 (`0x140007030`) handles MJ_CREATE/MJ_CLOSE/MJ_DEVICE_CONTROL and forwards everything else to `PcDispatchIrp`.
- **"\audioparameters" single-open control file**: CREATE/CLOSE compare the FileObject name against `\audioparameters` (string `0x14000b1e0`; compare at `0x140007444/0x14000749a`) and manage a refcount (global `DAT_140005830`, hard-capped: open fails with `0xC0000001` once count > 1 — `0x140007437`). The SD on the opened device is portcls/KS-owned (audio endpoint security; typically user-openable, but the KS/portcls gate is not this binary's code).
- No SDDL strings (`D:P`, `(A;;`) anywhere; no `\Device\`/`\DosDevices\` strings; no interface GUID of its own.

## Memory-write analysis

| Pattern | Result |
|---|---|
| Device-control surface | 5 custom codes, all METHOD_BUFFERED/FILE_ANY_ACCESS: `0x258810`, `0x258814` (input len must equal header dword at +8, and > 0xB: `0x1400074a8`), `0x26480c` (in==8, out==8, request id 1..8: `0x1400075xx`), `0x264810` (in-driven, information=in), `0x26880c` (format-set with fully validated rate/depth/channel table — enumerated valid values only, `0x1400075xx`). All then delegate to adapter-object vtable methods with the IO-manager-provided SystemBuffer + the gated length. |
| Copy-length confusion | None observed in the dispatcher; every code binds on explicit length checks before any write. Information fields set from gated lengths. |
| METHOD_NEITHER | None (all codes bits 1–0 = 00). |
| Caller MDL mapping | Only `IoAllocateMdl` + `MmBuildMdlForNonPagedPool` (driver-own allocation, `0x14000c50c`); no `MmProbeAndLockPages`, no `MmMapLockedPagesSpecifyCache`, no `MmMapIoSpace`. |
| Physical memory / section mapping | No `ZwOpenSection`, no `\Device\PhysicalMemory`, no `MmCopyMemory`. |
| MSR/GDT/IDT | None. |
| User length into fixed kernel buffer | Registry read path FUN_140001000 uses a fixed 0x14-byte pool buffer with fixed-length registry read (`0x140001042–0x1400010a6`). CSaveData (strings `0x140002c60–0x140002ca0`) — file-write helper, not a kernel-buffer write path. |
| Array/index primitives | 0x26480c/0x26880c index/select values validated against enumerated tables before use. |

Residual gap (honest coverage note): the adapter COM object's vtable methods invoked at vtable offsets +0xA8/+0xB0/+0xB8/+0xC0/+0xE8/+0x100 (COM indirection through `*(devext+0x20)`, object destroyed in FUN_140007840) were not individually decompiled. The dispatcher hands them the IO-manager-sized buffered buffer with a gated length; structurally they cannot exceed that buffer without a second length source, none of which is user-visible in the audited dispatch path. Coverage ≈ 75% (full COM method bodies unverified).

## Memory-touching IOCTL table

| Code | Handler site | Action | Bound |
|---|---|---|---|
| `0x258810` | `0x140007482` | query adapter state via server fn@+0xC0 | `inLen == header.len && inLen > 0xB` |
| `0x258814` | `0x1400074c8` | property get via server fn@+0xC0 | same gate |
| `0x26480c` | `0x140007510` | select channel/format, id 1..8 | `in==8 && out==8 && id≤8` |
| `0x264810` | `0x140007530` | get stream/adapter params | in-driven, information=in |
| `0x26880c` | `0x140007566` | audio format set | enumerated valid rate/depth/channels |

All other MJ_* : forwarded to `PcDispatchIrp` (portcls-owned KS surface, out of this file's scope).

## Verdict + VM confirmation plan

**NO-WRITE.** The driver's own dispatch plane is a length-gated, METHOD_BUFFERED config/query protocol over portcls-created KS devices; no probe-less buffers, no dynamic mapping, no physical-memory or MSR surface, no unchecked copy found in the custom path.

VM plan (non-destructive, optional): standard user opens the default wave endpoint's KS filter and issues the five codes with nominal 8/12-byte headers to confirm reachability of the custom dispatcher; no corruption test warranted — no primitive to trigger.

*End of report.*
