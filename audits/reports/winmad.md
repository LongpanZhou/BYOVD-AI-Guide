# Audit: winmad.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\winmad.sys` |
| Recorded SHA-256 | `F6A9E7026AA60A6627680F232AE785EA9CF55FE970708E6E49151F601CC42FEE` (verified against triage_index.csv) |
| Company/Version | Mellanox 5.50.14695 (MLNX_WinOF; source paths `core\winmad\kernel\wm_provider.c`, `wm_reg.c`) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless, private project; REA shared bridge contended by parallel agents, results cross-checked) |
| Verdict | **NO-WRITE** (no kernel memory-write primitive in-file; DACL-conditional reachability assumed worst case) |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (Ghidra document `target-f6a9e7026aa6.sys`).

## Entry surface

- KMDF driver (`FxDriverEntryWorker` → real DriverEntry in `INIT` at `0x140009200` region; INIT `0x14000a000` is only `__security_init_cookie`).
- Device creation `FUN_14000174c`: builds `\Device\WinMad` (`STR 140005050`, xref `0x140001775`) + `\DosDevices\WinMad` symbolic link (`STR 140005070`, xref `0x1400017d4`).
- **No SDDL string, no `WdfDeviceInitAssignSDDLString`, no `IoCreateDeviceSecure`** — device type defaults to `FILE_DEVICE_UNKNOWN`, so the OS default security descriptor applies. As in NiSerP.md, the worst case (standard user can open) is assumed for the verdict; a restrictive DACL only lowers exposure.
- No device interface of its own is published: the `GUID_MLX4_COMMON_INTERFACE` / `GUID_IB_AL_INTERFACE` strings are **consumed** ("Taken/Released ... interface" log lines in `finish_d0_entry/exit`), not registered.
- EvtFileCreate `FUN_140001c70`: no caller-identity check, only adds a context to a global mutex-protected list — no security gate, no data path.

Queue config built in `FUN_14000174c` (0x60-byte config, memset-zeroed): EvtIoDeviceControl = `FUN_140001f50`, EvtIoRead = `FUN_140002070`, EvtIoWrite = `FUN_140002140`.

## Memory-write analysis

WDF services are called through the runtime table `DAT_140007468` (KMDF dispatch table): `+0x868` = RetrieveInputBuffer, `+0x870` = RetrieveOutputBuffer, `+0x838` = Complete, `+0x848` = CompleteWithInformation.

**IOCTL plane (`WmIoDeviceControl` = `FUN_140001f50`):** exactly three codes, device type `0x3BE`, all `METHOD_BUFFERED` + `FILE_ANY_ACCESS`:
- `0x3BE004` (Fn 1) → `FUN_140004288`: retrieves input (min `0x28`) + output (min 8); allocates 0x60-byte pool `Mxrg`, zero-fills **0x60** (exact allocation size); registration helper `FUN_140003e70` copies only fixed-size fields; the 0x80-bit user bitmap loop writes exactly 128 ints into a 512-byte stack array (exact fit); completes with 8 bytes out. **Bounded.**
- `0x3BE008` (Fn 2) → `FUN_140003ccc`: user-supplied 8-byte index; checked `idx < ctx+0x20` before `arr + 0x10 + idx*0x18` lookup (`0x140003c...`). **Bounds-checked.**
- `0x3BE00C` (Fn 3) → `FUN_1400030e0`: drains/purges the default queue; no data copy.
- Default: `0xC000007A` rejection.

**MJ_WRITE (`WmIoWrite` = `FUN_140002140` → `FUN_140003818`):** retrieves input min `0x58`; looks up MAD class `FUN_140003dc8` — index checked `param_2 < ctx+0x20` before `+0x10 + idx*0x18` (`0x140003df7` region), ref-counted under mutex; then `FUN_140003b34(classCtx, in, inLen - 0x40)` copies `inLen-0x40` from `in+0x40` into the MAD data buffer that the **provider callback** (`classCtx+8 → +0x270`) allocated **with the same `param_3` length** (`wm_provider.c:159` trace at `0x140003b55`). Since `inLen ≥ 0x58`, no `0x40` subtraction underflow; the copy length never exceeds the caller's own input buffer. Header fields (`+0x28/+0x3c/+0x40/...`) are fixed-size reads inside the `0x58` minimum. **No in-file unchecked copy.**

**MJ_READ (`WmIoRead` = `FUN_140002070` → `FUN_14000357c`):** retrieves output min `0x40`; `FUN_140003004` checks `outLen ≥ madDataLen + 0x40` **before** the `FUN_140004b40` copy (`0x1400030..` region; failure returns `0x105`/`STATUS_BUFFER_OVERFLOW`-family with `*param_3 = 0x40`). **Bounds-checked** (kernel→user direction anyway).

**Ring growth (`FUN_140002e5c`):** grows `(count+0xaa)*0x18`, copies old `count*0x18` entries before freeing. Standard free-list growth; insert `FUN_140002f30` writes at `tail*0x18` where `tail` < new capacity. **Bounded.**

**No suspicious primitives found:** no `MmMapIoSpace`, `MmProbeAndLockPages`, `MmMapLockedPagesSpecifyAccess`, `MmGetPhysicalAddress`, `ZwOpenSection`, `MmCopyMemory`, or `Se*` imports; no SGDT/WRMSR paths reachable from any dispatch (the only `rdmsr`/GDT code lives in the `tdb`/INIT compiler-library blob around `0x140009034`/`FUN_140009200`, invoked from library init, not from any IOCTL path); no METHOD_NEITHER anywhere.

**Cross-module caveat (accepted scope):** the MAD buffer for MJ_WRITE is allocated by the provider callback registered from `ibcore`/`ibbus` (function pointers out of `classCtx+8`). If that module sized its allocation below the requested length, the overflow would live in `ibbus.sys`, not in this file; the same-session ibbus audit covers that surface.

## Memory-touching IOCTL table

| Code | Fn | Method | Path | Copy | Check |
|---|---|---|---|---|---|
| `0x3BE004` | 1 | BUFFERED, ANY | `FUN_140004288` | fixed fields into 0x60 ctx | exact-fit (in min 0x28) |
| `0x3BE008` | 2 | BUFFERED, ANY | `FUN_140003ccc` | indexed ptr read | `idx < count` ✓ |
| `0x3BE00C` | 3 | BUFFERED, ANY | `FUN_1400030e0` | none (queue drain) | n/a |

MJ_READ/MJ_WRITE copy paths: length-checked as described above. All other MJ codes: forwarded to WDF or rejected.

## Verdict + VM confirmation plan

**NO-WRITE.** Every kernel-side copy, fill, and indexed write in winmad.sys is bounded by an explicit length/index check; the only length carried from the caller (`inLen-0x40` MJ_WRITE) is bounded by the caller's own buffer and matched against a same-length allocation request issued to the provider. The device relies on the OS default DACL (worst case assumed reachable); even so, no memory-write primitive exists on the reachable surface.

VM plan (orchestrator-owned, non-destructive): open `\\.\WinMad` under a restricted token to record the actual DACL behavior; issue `0x3BE004` (register provider) and a small `MJ_WRITE` MAD to confirm the path executes; observe pool tags `Mxrg` allocations with `!poolused` — no corruption test is warranted by the static evidence.

*End of report.*
