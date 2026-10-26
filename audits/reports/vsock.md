# Audit: vsock.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\vsock.sys` |
| Recorded SHA-256 | `CBF13689A852E6062FA656E15DB2A22DD6D83091BDA5F573A98502215556CA68` (matches triage_index.csv row `vsock`; sha256 recomputed in-session) |
| Company/Version | Broadcom Inc. / 9.8.23.0 (VMware VSOCK; PDB `vsock.pdb`) |
| Method | Static-only audit via REA/Ghidra 12.1.4, memory-write scope only |
| Verdict | **NO-WRITE** (coverage ~55%) — every user-pointer write is probed and fixed- or bounded-length; the MJ_READ/WRITE copy targets are unresolved (indirect vtable) and are the open item |
| Coverage | Not traced: MJ_READ/WRITE vtable targets (`ctx+0x130`/`ctx+0x140`), most IOCTL handlers (`FUN_140005f50`, `FUN_140006060`, `FUN_140002e68`, `FUN_140002f80`, `FUN_140006090`, `FUN_1400060b0`, `FUN_1400062a0`, `FUN_140003228`), device SDDL (`DAT_14000e608`, not decoded) |

> **Static-only.** No load, no device open, no IOCTL execution. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- DriverEntry = `FUN_140002544` (wrapped by `entry`). Creates `\Device\vmci` via `WdmlibIoCreateDeviceSecure` (device type `0x22`, characteristics `0x100`, SDDL pointer `DAT_14000e608`) + `\DosDevices\vmci`. Note: device name collides with VMCI's `\Device\vmci` naming; this driver's device is a VSOCK front end.
- Dispatch: `MJ_CREATE` = `FUN_140002840`; `MJ_CLOSE` = `FUN_1400027c0`; `MJ_CLEANUP` = `FUN_140002770`; `MJ_DEVICE_CONTROL` = `FUN_140002c40`; `MJ_READ` and `MJ_WRITE` = `FUN_140002f30`; `DriverUnload` = `FUN_1400032d0`.
- Import surface for memory-write APIs: `ProbeForRead` and `ProbeForWrite` (only from `FUN_1400048bc`). **No** `MmMapIoSpace`, `MmMapLockedPages`, `MmProbeAndLockPages`, `IoAllocateMdl`, `ZwMapViewOfSection`, `MmCopyMemory` in the import table. Registry and security APIs present (`ZwCreateKey`, `ZwSetValueKey`, `ZwSetSecurityObject`) — not memory-write.

## Memory-write analysis

| Pattern | Result | Evidence |
|---|---|---|
| User-pointer copy helper | `FUN_1400048bc(struct, src, len, flag)`: destination = `*(struct+0x10)` (stored user pointer), bound `len <= *(struct+4)`, `ProbeForWrite` when `flag == 1`, copy via `FUN_14000d2c0` | `ev_e641b0b4…` |
| Helper callers | Five: `0x140004fec`, `0x140005d70`, `0x140006c00`, `0x140007144`, `0x140007f00` | `ev_0ed85504…` |
| Property get/set writer (IOCTL `0x81032074`) | `FUN_140005d70`: writes a **fixed 4-byte** value (driver state or zero) via `FUN_1400048bc`; requires `*(param_4+4) == 4`; probe applies for user callers | `ev_d2f0346a…` |
| Kernel-only IOCTL branch (`0x810320c0`) | Requires `RequestorMode == KernelMode`; writes a fixed `0xB4`-byte block (function-pointer table) into SystemBuffer; length gate `0x97 < outLen-0x1c`. Information disclosure of driver code addresses to kernel callers; not a write primitive | `ev_72249e2f…` |
| Common IOCTL dispatch | `FUN_140003738`: buffered; requires `InLen == OutLen`; user-mode branch covers `0x81032080`–`0x810320c7` with per-code length checks | `ev_72249e2f…` |
| READ/WRITE dispatch | `FUN_140003ea8` passes raw `IRP+0x70` (UserBuffer) into a local context structure and calls `FUN_140006050` / `FUN_140006080`. Both are **indirect call stubs** through the context vtable (`+0x130` / `+0x140`); targets are **not resolved** statically | `ev_9d245029…`, `ev_df4b8af0…`, `ev_127876749…` |
| Kernel address write from user input | None found in decompiled paths | — |
| MDL / physical map / section map | Absent from import table | import sweep |
| Unchecked copy lengths (decompiled) | None: `FUN_1400048bc` bounded by `*(struct+4)`; `FUN_140005d70` fixed 4-byte copies; `FUN_140003738` fixed-size writes after length gates | the decompiles above |

## IOCTL table (memory-touching; user branch unless noted)

| Code | Handler | Method | Write behaviour |
|---|---|---|---|
| `0x810320c0` | inline (kernel only) | buffered | Writes `0xB4` bytes of driver code pointers into SystemBuffer (disclosure) |
| `0x81032074` | `FUN_140005d70` | buffered | Fixed 4-byte write to user struct pointer via `FUN_1400048bc` (probed) |
| `0x81032080` | `FUN_140005f50` | buffered | Not decompiled |
| `0x81032088` | `FUN_140006060` | buffered | Not decompiled |
| `0x8103208c` | `FUN_140002e68` / `FUN_140002f80` | buffered | Not decompiled (registration/buffer setup; would store user pointers consumed by `FUN_1400048bc`) |
| `0x81032094` | `FUN_140006090` | buffered | Not decompiled |
| `0x81032098` | `FUN_1400060b0` | buffered | Not decompiled |
| `0x8103209c` | `FUN_1400062a0` | buffered | Not decompiled |
| `0x810320c7` | `FUN_140003228` | buffered | Not decompiled |

## Findings

1. **No kernel write with a user-controlled destination observed.** User-pointer writes are probed for write (user callers carry `RequestorMode == UserMode`), bounded by stored size, and fixed-length where tested.
2. **Kernel-only path** (`0x810320c0`, `RequestorMode == KernelMode`) is not reachable from a user IRP if `IRP+0x40` is `RequestorMode`. This offset is consistent with the x64 `IRP.RequestorMode` layout but is **inferred, not confirmed in-file**.
3. **Open item:** the READ/WRITE copy targets sit behind an unresolved context vtable (`+0x130`/`+0x140`). If one of them writes to the raw `IRP+0x70` UserBuffer without `ProbeForWrite`, that is an unprobed user-address write. For user callers, NtReadFile/NtWriteFile validate the buffer before the IRP is built, so this is a TOCTOU and coverage question rather than a demonstrated kernel write.

## Verdict rationale

NO-WRITE on the statically visible surface. Escalation would require: (a) a resolved vtable target that writes to a caller-controlled kernel address, or (b) an unprobed user write reachable with `RequestorMode == KernelMode` from an unprivileged IRP. Neither is supported by the decompiled code.

## VM confirmation plan (orchestrator-owned; non-destructive)

1. Unprivileged token: `CreateFile("\\\\.\\vmci", ...)`. Record whether the SDDL admits the caller (decode `DAT_14000e608` first).
2. If open succeeds: issue `0x81032074` with a user struct whose `+4 == 4` and a user-buffer pointer in a committed page. Expect a 4-byte write to that page and the probe to hold.
3. Resolve the vtable targets (search for stores into `ctx+0x130` / `ctx+0x140`) and re-audit before any dynamic work on READ/WRITE.

## Evidence (REA, retained IDs)

`ev_95f898fdaecea80ef565f539e64ae8a3f955945dae00b5a4af26fc2629146dfa` (`entry`), `ev_021b7aa48dfc854de0f4b148d702ec388a33f2320276bd177c4a4d81a879d815` (DriverEntry `FUN_140002544`), `ev_e641b0b4cf41e5035117515befa3f83b08c643d7a3cac7d11d86e0d9517561c0` (`FUN_1400048bc`), `ev_0ed85504f9f9e87e15b82c3558c381c57472e8d092fde889ad09438a7b04d441` (callers), `ev_d2f0346a017f9b02380a359095e49bfb4c33ac13157bb514f429d2948e35250c` (`FUN_140005d70`), `ev_72249e2fa55a6e667e3d96a4db8ab0948d39496cdce611506823307cc458dc53` (`FUN_140003738`), `ev_9d245029b28481f5088084fcf3c2535bb1a4da90367cd6a50aee68818afe06f9` (`FUN_140003ea8`), `ev_df4b8af0a8ab456eede8b8215c43d622207b0ccc831a2aa82f753b29d41be37a` / `ev_127876749a11c6ebec58032ae65f72d5f69e5f21fdd4d5add718fdcebe619e99` (indirect stubs), `ev_4498f80dd786524633d09ac33a43b0ba1af8f82735612bdb7a9a8a3dcd35f2e7` (`FUN_140002f30`), `ev_5c6e26ee9614ab029882664f5f01bdb7944648466a5c709cd4c77b43b5fdf88c` (`FUN_140002c40`).
