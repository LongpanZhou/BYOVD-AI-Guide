# Audit: BlackmagicUsbIO_legacy_598A6C3C.sys (BLOCKED: unsigned; static MW4 exposure; IOCTL set partial)

| Field | Value |
|---|---|
| File | drivers\BlackmagicUsbIO_legacy_598A6C3C.sys |
| SHA-256 | 598A6C3C5A4498EFDC442796BBC6B8A815425DD5666C673779A4A005DB9A660A (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\BlackmagicUsbIO_legacy_598A6C3C.txt`, 724 functions, `=== DONE` at last line). REA not used. |
| Reach | R3 (Blackmagic USB I/O device; device interfaces exist only with the USB device present) |
| Setup required | hardware |
| Write quality | W3 |
| Severity | BLOCKED (static MW4: unsigned, cannot load under HVCI as shipped; the static primitive is MW4) |
| HW-only | no |

Identity: Company Blackmagic Design; FileVersion 1.0.0.0; signature NotSigned (Get-AuthenticodeSignature). Load: unsigned.

## 1 Internals

Same codebase as `BlackmagicUsbIO_B48DF15C` (see that report). Identical imports and call structure; function addresses shift by the amount in the table below.

## 2 Entry / device / interface / effective DACL

- Device objects: `IoCreateDevice(..., 0x20, 0, 0x22, ...)` at line 23673 in `FUN_14001d000 @ 14001d000` (header 23662), and `IoCreateDevice(param_1, 0x1c8, 0, 0x22, 0, 0, &local_res18)` at line 24272 in `FUN_14001dc50 @ 14001dc50` (header 24259). Both unnamed.
- Device interfaces: `IoRegisterDeviceInterface` at lines 24302, 24306, 24310 (same three GUIDs as the signed build). Interface DACL not set in the call (IoRegisterDeviceInterface default).
- Effective DACL: not resolved beyond the default. No SDDL string in the image.

## 3 Dispatch and IOCTL table (partial)

- IOCTL dispatcher `FUN_14000ff80 @ 14000ff80` (header 13253). Compares `in_EDX` (IOCTL code) at lines 13662 (`== 0x222403`) and onward.
- 0x222403: METHOD_NEITHER, FILE_ANY_ACCESS (decoded). Handler at line 13662-13665: `ProbeForWrite(puVar1, 8)`, then `FUN_14000fdb8(..., 2, ...)` at line 13665, then `*puVar1 = CONCAT44(...)`.
- Other codes: not traced in this pass (same set as the signed build).

## 4 Access-control audit

- No privilege or caller-identity checks in the traced path. Access is the device-interface DACL (default, not resolved).

## 5 Memory-write trace

1. **User-mode mapping of a kernel page (IOCTL 0x222403):** `FUN_14000ff80` line 13662 (`in_EDX == 0x222403`) and the call `FUN_14000fdb8(param_1, 2, ...)` at line 13665 (the helper is `FUN_14000fdb8`, header 13176 in this build, line 13204 MmMapLockedPagesSpecifyCache with AccessMode 1 = **UserMode**). `ProbeForWrite(puVar1, 8)` at line 13664, and the user VA is written to the caller's output buffer at line 13667 (`*puVar1 = ...`).
2. **Kernel page contents:** block from `FUN_14000e828` (not traced in this build).
3. **Kernel-mode MDL mappings** at lines 477 and 536 (AccessMode 0). Inputs not traced.
4. **User buffer probes:** as in the signed build (`ProbeForWrite` / `ProbeForRead` with fixed sizes 8 and 0x10).

Write classification: target fixed (one page), value arbitrary within page, size fixed. Overall W3.

## 6 Most dangerous exposed capability

IOCTL 0x222403 (METHOD_NEITHER, FILE_ANY_ACCESS): writable user mapping of a kernel nonpaged page.

## 7 Verdict

- Static primitive: **MW4** (R3 hardware, W3). Load: **unsigned**, not loadable under HVCI as shipped.
- Severity: **BLOCKED** (unsigned; static MW4 per SEVERITY.md BLOCKED rule).

## 8 Limitations

- Same IOCTL and page-use limitations as `BlackmagicUsbIO_B48DF15C`.
- Interface DACL not resolved.
- Static only; not loaded.
