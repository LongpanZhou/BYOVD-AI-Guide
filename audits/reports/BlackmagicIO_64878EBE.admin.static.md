# Audit: BlackmagicIO_64878EBE.sys (PARTIAL: IOCTL enumeration incomplete, device access route unresolved)

| Field | Value |
|---|---|
| File | drivers\BlackmagicIO_64878EBE.sys |
| SHA-256 | 64878EBE6F4E0E8EC2B6690F5A5E14F6BA3C53C3C7DC122D7B50B8597E3B335E (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\BlackmagicIO_64878EBE.txt`, 2625 functions, 0 decompile failures, `=== DONE` at last line). REA not used. |
| Reach | R3 (Blackmagic PCIe card; the device exists only with the card present). The route by which a user-mode caller obtains a handle is not identified (section 2). |
| Setup required | hardware |
| Write quality | W3 (fixed 4 KB kernel page exposed to user mode; the bytes written are caller-controlled, the target page is fixed) |
| Severity | MW4 (provisional: R3 hardware with W3, per SEVERITY matrix) |
| HW-only | no (one kernel-memory exposure found; BAR MMIO also present, fixed) |

Identity: Company Blackmagic Design; FileVersion 15.3.1; signature Valid (WHCP). Note: the image contains macOS IOKit-style class strings (`BlackmagicIODriver::start`, `IOPCIDevice::mapDeviceMemoryWithRegister`) under a KMDF-style stub (`FxDriverEntryWorker`), so the WDF calls go through an indirect function table.

## 1 Internals

- DriverEntry: `FxDriverEntryWorker @ 140062430` (header line 78770). Driver unload stub `FxStubDriverUnload` (line 78814).
- Dangerous imports (EXT list): `MmMapIoSpace`, `MmUnmapIoSpace`, `MmMapLockedPagesSpecifyCache`, `IoAllocateMdl`, `MmBuildMdlForNonPagedPool`, `ProbeForRead`, `ProbeForWrite`, `MmProbeAndLockPages`, `IoCreateDevice`, `ExAllocatePoolWithTag`, `HalGetBusDataByOffset`, `HalSetBusDataByOffset`, `IoSetDevicePropertyData`. WDF is bound through `WdfVersionBind` / `WdfVersionUnbind` only; WDF API calls are indirect (`PTR__guard_dispatch_icall_1400692a8`).
- No `IoCreateSymbolicLink`, no `IoRegisterDeviceInterface`, no `WdfDeviceCreate` / `WdfDeviceCreateDeviceInterface` import in the dump. Their use through the indirect table cannot be ruled out (section 2).

## 2 Entry / device / interface / effective DACL

- Device creation: `IoCreateDevice(uVar5, 0, 0, 0x22, ..., 1, plVar1)` at line 7960, inside `FUN_140008020 @ 140008020` (header 7943). DeviceName = NULL (unnamed device), DeviceType = 0x22 (FILE_DEVICE_UNKNOWN), DeviceExtensionSize = 0, Exclusive = 1.
- Because the device is unnamed and no symbolic link or device interface is created in the image, a user-mode caller cannot open it by name. Access therefore depends on a route not visible in this image (for example, an indirect WDF interface call or the IOKit personality). That route is unresolved.
- Effective DACL: no SDDL string in the image (strings file has no `D:` SDDL text). No `WdfDeviceInitAssignSDDLString` is identifiable because indirect table calls do not show the callee. The DACL is therefore not resolved, and the default is assumed.
- Device-object DACL for the admin path: not resolved. Admin reach is not separately gated in code that was analysed.

## 3 Dispatch and IOCTL table (partial)

IOCTL dispatch: the IOCTL dispatcher `FUN_140059d40 @ 140059d40` (header 72601, size 7314) compares the IOCTL code parameter (`param_2`) against the following codes (dump lines 72652-72863):

| IOCTL | Decoded (device 0x22, function, method, access) | First dump line | Handler / note |
|---|---|---|---|
| 0x222084 | fn 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS | 72692 | in dispatcher |
| 0x222088 | fn 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS | 72701 | in dispatcher |
| 0x22208c | fn 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS | 72714 | in dispatcher |
| 0x2220b4 | fn 0x82d, METHOD_BUFFERED, FILE_ANY_ACCESS | 75477 | `FUN_14005cf10 @ 14005cf10` (header 74982) |
| 0x2220bc | fn 0x82f, METHOD_BUFFERED, FILE_ANY_ACCESS | 75478 | `FUN_14005cf10`, maps kernel page to user (section 5 item 1) |
| 0x2220c0 | fn 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS | 75492 / 75518 | `FUN_14005cf10` |
| 0x2220c4 | fn 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS | 75492 / 75521 | `FUN_14005cf10` |
| 0x222403 | fn 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS | 72728 | in dispatcher |
| 0x22240f | fn 0x903, METHOD_NEITHER, FILE_ANY_ACCESS | 72739 | in dispatcher |
| 0x222413 | fn 0x904, METHOD_NEITHER, FILE_ANY_ACCESS | 72691 | in dispatcher |
| 0x222414 | fn 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS | 72690 / 72776 | in dispatcher |
| 0x222418 | fn 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS | 72797 | in dispatcher |
| 0x22241c | fn 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS | 72829 | in dispatcher |
| 0x222424 | fn 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS | 72830 | in dispatcher |
| 0x22242b | fn 0x90a, METHOD_NEITHER, FILE_ANY_ACCESS | 72863 | in dispatcher |
| 0x222443 | fn 0x910, METHOD_NEITHER, FILE_ANY_ACCESS | 72669 | in dispatcher |
| 0x222444 | fn 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS | 72668 | in dispatcher |
| 0x2224c4 | fn 0x931, METHOD_BUFFERED, FILE_ANY_ACCESS | 72653 | in dispatcher |
| 0x2224c5 | fn 0x931, METHOD_IN_DIRECT, FILE_ANY_ACCESS | 72652 | in dispatcher |

Other comparisons against `0x2ff3b9` appear in `FUN_14001d410`, `FUN_14001d6e4`, `FUN_14001d9b8`, `FUN_14001dc50`, `FUN_14001deb8`, `FUN_14001e0a8`, `FUN_14001e310`, `FUN_14001e51c` (lines 25790-26494) and are not CTL codes (value compare on `param_3`/`param_2`); they are not counted as IOCTLs here.

Only `0x2220bc` is traced to the memory operation. Each other code's handler body was not traced (section 8).

## 4 Access-control audit

- No `SeSinglePrivilegeCheck` / `SeAccessCheck` / caller-identity check in the analysed IOCTL path. Access is governed by the device DACL, which is unresolved (section 2).
- For METHOD_BUFFERED codes with FILE_ANY_ACCESS, the access gate is only the device-object DACL. If that DACL admits a caller (including administrators), the IOCTL is reachable at that privilege.

## 5 Memory-write trace

1. **User-mode mapping of a kernel page (IOCTL 0x2220bc):** at line 75478 the handler calls `FUN_14005cde0 @ 14005cde0` (header 74936) with `param_2 = 2`, which:
   - obtains the block via `FUN_14000e3b0(...)` (returns `*(obj+0x58)`, the 0x50-byte block set by `FUN_14000dc10`) or a cached MDL (`*(...+0x318)+0x30`), in the `param_2 == 2` branch, header 74936;
   - `IoAllocateMdl(lVar1, 0x1000, ...)` at line 74961 (size = 0x50 rounded to a page); `MmBuildMdlForNonPagedPool` at line 74964;
   - `MmMapLockedPagesSpecifyCache(lVar1, 1, 1, 0, ...)` at line 74965, where `1` = **UserMode** (AccessMode), so the page is mapped into the calling process's address space.
   The user-mode VA is returned through `local_4a0` and written to the 8-byte output buffer (call at line 75485 `FUN_14005cde0(...,2,...)`; store at line 75488 `*(ulonglong *)local_4c0 = CONCAT44(uStack_49c, local_4a0)`).
2. **Kernel page contents:** the 0x50-byte block is allocated in `FUN_14000dc10 @ 14000dc10` (header 12716; allocator call at line 12726 `FUN_140003b44(0x10002, 0x50, 0x1000)`; `memset(_Dst, 0, 0x50)` and `*puVar1 = 0xbd` at line 12734). The caller of `FUN_14000dc10` is not identified in the dump (indirect dispatch). The whole 4 KB page is mapped to user mode; the rest of the page is not zeroed by the mapping and could contain other allocations (not verified).
3. **Driver use of the page:** not traced. The driver's reads of the 0x50-byte block (for state, pointers or lengths) were not followed. The effect of user writes on driver behaviour is therefore unknown.
4. **PnP BAR mappings (fixed):** `MmMapIoSpace(*(pcVar5+4), *(pcVar5+0xc), 0)` at line 78368 inside `FUN_140061e68 @ 140061e68` (header 78344), called from `FUN_14005f6c0` (line 76551, header 76541) and `FUN_140060760` (line 77317, header 77305). The base and length come from the PnP resource list (type 0x03 entries), not the caller. Fixed-window MMIO.
5. **Kernel MDL mappings in kernel mode:** `MmMapLockedPagesSpecifyCache(...,0,1,0,0,0x10)` at lines 5045 (in `FUN_140004c80 @ 140004c80`, header 5035) and 5104 (in `FUN_140004d90 @ 140004d90`, header 5094). AccessMode 0 = KernelMode. Inputs not traced.
6. **User buffer probes:** `ProbeForRead` / `ProbeForWrite` in `FUN_14005cf10` at lines 75185, 75187, 75259, 75412, 75414 (user buffer size/element computed from the caller's descriptor `local_4c8`). The probes check address range; the caller-supplied element count and stride are used in the probe length (line 75187, 75414). Not further traced.

Write classification:

- Target control: fixed (one 4 KB kernel page, the page is chosen by the driver; the caller only learns its user-mode VA).
- Value control: arbitrary bytes within the page (the caller can write to the page), effect unknown.
- Size control: fixed (one page).
- Overall: W3 (fixed narrow target, arbitrary value within the page).

## 6 Most dangerous exposed capability

IOCTL 0x2220bc (METHOD_BUFFERED, FILE_ANY_ACCESS, `FUN_14005cf10` / `FUN_14005cde0`): gives the caller a writable user-mode mapping of a kernel nonpaged page (dump lines 74965, 75478, 75485). Whether this yields a memory write that matters depends on the driver's use of that page (not traced) and on the device DACL (not resolved).

## 7 Verdict

- Provisional: **MW4** (R3 hardware, W3 fixed page, setup hardware, signed). The user-writable kernel page is a real memory exposure. It is not arbitrary, and the device access route is not identified in this image.
- If the page holds control data read back by the driver, this could be raised. That check was not completed, so the rating stays at MW4.
- Status: partial (see section 8).

## 8 Limitations

- Full IOCTL enumeration not completed. Handlers other than `0x2220bc` were not traced (`FUN_140059d40` body lines 72601-74935 not fully decoded).
- Device access route and DACL not resolved (unnamed device; indirect WDF calls).
- Driver use of the 0x50-byte block (page offset 0 of the user-mapped page) not traced. The rest of the page (up to 0xFB0 bytes) was not checked for neighbouring kernel objects.
- The BAR MMIO path and the `setVirtualAddressForBAR` / `mapDeviceMemoryWithRegister` helpers were not checked for user-controlled register offsets (HW-only if present).
- Static analysis only; the driver was not loaded.
