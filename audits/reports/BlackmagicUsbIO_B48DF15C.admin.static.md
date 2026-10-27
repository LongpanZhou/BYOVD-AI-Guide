# Audit: BlackmagicUsbIO_B48DF15C.sys (PARTIAL: IOCTL set not fully enumerated; interface DACL unresolved)

| Field | Value |
|---|---|
| File | drivers\BlackmagicUsbIO_B48DF15C.sys |
| SHA-256 | B48DF15CC141F8C602EEFF7E3970EF55DDD74570AD9692D549A272F27DD7E716 (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\BlackmagicUsbIO_B48DF15C.txt`, 724 functions, 0 decompile failures, `=== DONE` at last line). REA not used. |
| Reach | R3 (Blackmagic USB I/O device; device interfaces exist only with the USB device present) |
| Setup required | hardware |
| Write quality | W3 (fixed 4 KB kernel page exposed to user mode; caller controls the bytes, not the target page) |
| Severity | MW4 (provisional: R3 hardware with W3, per SEVERITY matrix) |
| HW-only | no |

Identity: Company Blackmagic Design; FileVersion 1.0.0.0; signature Valid (WHCP).

## 1 Internals

- Driver type: WDM/PnP USB function driver with device objects and device interfaces (`IoCreateDevice`, `IoRegisterDeviceInterface`, `IoAttachDeviceToDeviceStack`, `IoBuildDeviceIoControlRequest`).
- Dangerous imports: `MmMapLockedPagesSpecifyCache`, `IoAllocateMdl`, `IoBuildPartialMdl`, `MmBuildMdlForNonPagedPool`, `MmUnmapLockedPages`, `MmProbeAndLockPages`, `ProbeForWrite`, `ProbeForRead` (indirect via `FUN_14000ff80`), `IoCreateDevice`, `IoRegisterDeviceInterface`. No `IoCreateSymbolicLink` import in the dump.

## 2 Entry / device / interface / effective DACL

- Device objects: `IoCreateDevice(..., 0x20, 0, 0x22, 0x80, 0, ...)` at line 23727 in `FUN_14001d000 @ 14001d000` (header 23716), and `IoCreateDevice(param_1, 0x1c8, 0, 0x22, 0, 0, &local_res18)` at line 24326 in `FUN_14001dc50 @ 14001dc50` (header 24313). Both are **unnamed** (DeviceName = 0).
- Device interfaces: `IoRegisterDeviceInterface(param_2, &DAT_140024c58, 0, _Dst+0x60)` at line 24356, `(...&DAT_140024c48..., _Dst+0x66)` at line 24360, `(...&DAT_140024c38..., _Dst+0x6c)` at line 24364, all in `FUN_14001dc50`. These three GUIDs are the user-mode route to the device. The interface DACL is not set in the call (no SDDL argument); it is the IoRegisterDeviceInterface default.
- Effective DACL: not resolved beyond the IoRegisterDeviceInterface default. No SDDL string appears in the image (strings file).
- Dispatch: IRP_MJ_DEVICE_CONTROL is assigned at line 25644 `*(code **)(param_1 + 0xe0) = FUN_14001de30;` inside `FUN_14001f784 @ 14001f784` (header 25627). The IOCTL dispatcher with the IOCTL code as `in_EDX` is `FUN_14000ff80 @ 14000ff80` (header 13256). Its direct caller was not identified (indirect dispatch).

## 3 Dispatch and IOCTL table (partial)

The dispatcher `FUN_14000ff80` (header 13256, size 7661) compares `in_EDX` (the IOCTL code) at lines 13306-13428, 13665 and onwards. The ones traced:

| IOCTL | Decoded (device 0x22, function, method, access) | Line | Handler / note |
|---|---|---|---|
| 0x222403 | fn 0x900, **METHOD_NEITHER**, FILE_ANY_ACCESS | 13665 | `FUN_14000ff80`: `puVar1 = *(param_4+0x20)` (raw user output pointer, line 13666), `ProbeForWrite(puVar1, 8)` (line 13667), `FUN_14000fdb8(..., 2, ...)` (line 13668), then `*puVar1 = <user VA>` (line 13670). Traced in section 5. |
| 0x222404 | fn 0x901, METHOD_NEITHER, FILE_ANY_ACCESS | 13673 | size check `*(param_4+0x10) == 0x58`; handler not traced |
| 0x222140, 0x222144, 0x222148, 0x22214c | fn 0x850-0x853, METHOD_BUFFERED/NEITHER by low bits | 13620-13660 region | not traced |
| 0x222414 | fn 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS | 13636-13641 | `ProbeForRead/ProbeForWrite(puVar14, 0x10, 1)`, then `FUN_140016168(...)` (line 13642). Not traced further. |
| 0x222408, 0x222503, 0x222504, 0x22255c, 0x222520, 0x22258c, 0x2224d4, 0x2224d8, 0x2224dc, 0x2224e0, 0x2224e4, 0x2224e8, 0x2224ec, 0x2224f0, 0x2224f4, 0x2224f8 | various | 13306-13428 | in dispatcher; handlers not traced |

Other ranges in the image (0x222643-0x222668, 0x222784, 0x222521) are range-checked in the dispatcher (lines 13306-13313). Handlers not traced.

Only IOCTL 0x222403 is traced to the memory operation. The full IOCTL table is not enumerated (section 8).

## 4 Access-control audit

- No `SeSinglePrivilegeCheck` / `SeAccessCheck` / caller-identity check in the traced path. Access is the device-interface DACL (not resolved; IoRegisterDeviceInterface default). For METHOD_NEITHER with FILE_ANY_ACCESS, the handler relies on the interface DACL alone.
- Reach: the device interface exists with the USB device present (R3). Administrator reach is not separately gated.

## 5 Memory-write trace

1. **User-mode mapping of a kernel page (IOCTL 0x222403):**
   - Line 13665 `if (in_EDX == 0x222403)`; line 13666 `puVar1 = *(param_4 + 0x20)` (user-supplied output pointer, METHOD_NEITHER); line 13667 `ProbeForWrite(puVar1, 8)`.
   - Line 13668 `FUN_14000fdb8(param_1, 2, 0, &local_78)`, the mapping helper (header 13176).
   - Inside `FUN_14000fdb8`: returns cached `*(param_1+0x78)` if set; otherwise `FUN_14000e828(*(param_1+0x20))` supplies the kernel block (size 0x50, line 13186 region), `IoAllocateMdl(lVar1, 0x1000, ...)` at line 13200, `MmBuildMdlForNonPagedPool` (line ~13202), and `MmMapLockedPagesSpecifyCache(lVar1, 1, 1, 0, ...)` at line 13204 with `AccessMode = 1` = **UserMode**. The user VA is stored in `*param_4` and cached in `param_1+0x78`.
   - Line 13670 `*puVar1 = CONCAT44(uStack_74, local_78)`: the user-mode VA of the kernel page is written to the caller's output buffer.
2. **Kernel page contents:** the block is supplied by `FUN_14000e828` (returns a buffer pointer from the device context at +0x20); the allocator and the block's contents were not traced. The 4 KB page is mapped to user mode; the rest of the page is not zeroed by the mapping.
3. **Driver use of the mapped page:** not traced. Whether the driver reads control values back from the block is unknown.
4. **Kernel-mode MDL mappings (not caller-driven):** `MmMapLockedPagesSpecifyCache(lVar1, 0, 1, 0, 0, 0x10)` at line 477 (`FUN_1400014f0 @ 1400014f0`, header 467) and line 536 (`FUN_140001600 @ 140001600`, header 526). AccessMode 0 = KernelMode; inputs not traced.
5. **User buffer probes:** `ProbeForWrite(*plVar11, iVar6, 1)` (line 13379), `ProbeForWrite(puVar14, 8, 1)` (13424), `ProbeForRead(puVar14, 0x10, 1)` / `ProbeForWrite(puVar14, 0x10, 1)` (13640-13641), `ProbeForWrite(puVar1, 8)` (13667), `ProbeForRead(puVar14, 8, 1)` (13689) in `FUN_14000ff80`. Lengths are fixed in these sites (8, 0x10).

Write classification:

- Target control: fixed (one 4 KB kernel page chosen by the driver).
- Value control: the caller can write arbitrary bytes into the mapped page after mapping; effect on driver behaviour unknown.
- Size control: fixed (one page).
- Overall: W3.

## 6 Most dangerous exposed capability

IOCTL 0x222403 (METHOD_NEITHER, FILE_ANY_ACCESS, `FUN_14000ff80` line 13665 to `FUN_14000fdb8` line 13204): a writable user-mode mapping of a kernel nonpaged page, through the device interface route.

## 7 Verdict

- Provisional: **MW4** (R3 hardware, W3 fixed page, setup hardware, signed). A user-writable kernel page is a real memory exposure, but the target is fixed to one page and the use of that page by the driver is not established.
- Status: partial (section 8).

## 8 Limitations

- IOCTL enumeration incomplete. Handlers for 0x222404, 0x222414, 0x222140-0x22214c, and the other dispatcher codes were not traced.
- Device-interface DACL not resolved (IoRegisterDeviceInterface default; no SDDL in the image).
- Caller of `FUN_14000ff80` (dispatch) not identified.
- Driver use of the mapped page (block from `FUN_14000e828`) not traced.
- Static only; the driver was not loaded.
