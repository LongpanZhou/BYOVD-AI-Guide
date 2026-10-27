# Audit: CoreTemp ALSysIO - current x64 build (`BA78A7BD`) and Legacy x86 build (`E586DB87`)

| Field | Value |
|---|---|
| File(s) | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\CoreTemp_ALSysIO64_x64_BA78A7BD.sys` (67,584 B)<br>`C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\CoreTemp_ALSysIO64Legacy_x86_E586DB87.sys` (57,856 B) |
| SHA-256(s) | `BA78A7BD47C86058D5B4DBE0905679907C5FFAA397635521ABFE1F9474D0DD88`<br>`E586DB87BD070FC41AEAD3AF372C353573742607B73BF7127D13E1B172E05988` |
| Analysis date | 2026-10-24 |
| Method | Static-only via local Ghidra 12.1.4 headless (import + full analysis + decompiler/listing scripts). No REA session used. No load, no execution, no service creation, no registry write. |
| Reach tier | **R2** - local administrator (protected DACL: SYSTEM + Administrators only, on both files) |
| Setup required | **service** (create/start the ALSysIO kernel service; no devnode, no hardware, no composition) |
| Write quality | **W2** - attacker-chosen value written to a fixed offset inside an attacker-selected device object's extension (8 B on x64, 4 B on x86); all other writes are PCI config / MSR / fixed MMIO (`HW-ONLY`) |
| Verdict | **BLOCKED (static MW2)** - reach=R2 setup=service write=W2 load=unsigned; x86 additionally cannot load on an x64 host |
| Baseline compared against | `audits/reports/CoreTemp_ALSysIO64Legacy.md` (x64 `A0484FDC...A0F131`, `BLOCKED (static MW2)`) - **not** re-audited; every claim below was re-derived from the two hashes above |

---

## 0. Per-file result

| File | Arch / toolchain | SHA-256 | Device / symlink | Effective DACL | Kernel-memory write | Load | Verdict |
|---|---|---|---|---|---|---|---|
| `CoreTemp_ALSysIO64_x64_BA78A7BD.sys` | PE32+ x64, VS2019/2022 (link 14.51), CFG + GS, image base `0x140000000` | `BA78A7BD...4D0DD88` | `\Device\ALSysIO` / `\DosDevices\ALSysIO` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | `0x9C402648` extension-slot swap, `W2`, 8 B | **unsigned** (cert table points at EOF) | **BLOCKED (static MW2)** |
| `CoreTemp_ALSysIO64Legacy_x86_E586DB87.sys` | PE32 i386, VS2008 (link 9.0), image base `0x10000` | `E586DB87...2E05988` | `\Device\ALSysIO` / `\DosDevices\ALSysIO` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | `0x9C402648` extension-slot swap, `W2`, 4 B | **unsigned**; PE32 not loadable on this x64 host | **BLOCKED (static MW2)** |
| **Overall** | | | | | | | **BLOCKED (static MW2)** |

Both files are version **2.3.2.41** (`FileVersion`/`ProductVersion`), company *Arthur Liberman*, original names `ALSysIO64.sys` and `ALSysIO64Legacy.sys`. The runtime version IOCTL `0x9C402624` returns `0x00020302` on both.

---

## 1. Internals

### 1.1 File A - `CoreTemp_ALSysIO64_x64_BA78A7BD.sys` (current x64)

| Section | VA range | Notes |
|---|---|---|
| `.text` | `0x140001000`-`0x14000AC25` | 163 functions recovered by Ghidra |
| `fothk` | `0x14000B000` | CFG dispatch thunks |
| `.rdata` | `0x14000C000`-`0x14000DABC` | SDDL, device names, MSR tables |
| `.data` | `0x14000E000` | globals (device-object cache, MSR hash table, MCHBAR base/size) |
| `.pdata` | `0x14000F000` | |
| `PAGE` | `0x140010000`-`0x140011DE3` | paged helpers + WDK *wdmsec* |
| `INIT` | `0x140012000`-`0x140012818` | entry stub |
| `.rsrc`, `.reloc` | `0x140013000`, `0x140014000` | |

* PE `AddressOfEntryPoint` = `0x140012000`: `__security_init_cookie` (`0x14001202C`) then **`DriverEntry` = `FUN_140004038`** (`0x14001201B`).
* `DriverEntry` `0x140004038`:
  * `0x140004045` `[rcx+0x60]` = `DriverStartIo` = NULL; `0x140004073` `[rcx+0x68]` = `DriverUnload` = `FUN_1400040E0`.
  * `MajorFunction[0]`, `[2]`, `[0x0E]` all = **`FUN_140003B40`** (`0x14000404D`, `0x140004056`, `0x140004060`).
  * `0x14000407E` -> `FUN_140003A74(L"\\Device\\ALSysIO", 40000, DriverObject, &devobj)`.
  * `0x140004097`-`0x1400040BA`: stamps `DeviceObject` at `ext+8` and `DeviceType = 0x9C40` at `ext+0`, then zeroes 16 x `0x38`-byte per-slot records (`[ext + i*0x38 + 0x18]`, `[ext + i*0x38 + 0x38]`).
  * `0x1400040BC`-`0x1400040D0`: one-time init (`SetupGetOsVersionApis`, MSR whitelist, Intel MCHBAR, AMD SMU, PM tables).
* `DriverUnload` `0x1400040E0`: deletes the symlink, `ZwClose`s 16 cached device handles at `ext+0x38`, `IoDeleteDevice`.

**Import surface (60 ntoskrnl + 2 HAL).** Security-relevant: `IoCreateDevice`, `MmMapIoSpace`/`MmUnmapIoSpace`, `MmIsAddressValid`, `IoGetDeviceObjectPointer`, `IoBuildDeviceIoControlRequest`, `IofCallDriver`, the WDK *wdmsec* set (`RtlCreateSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlAddAccessAllowedAce`, `SeCaptureSecurityDescriptor`, `RtlAbsoluteToSelfRelativeSD`, `ObOpenObjectByPointer`, `ZwSetSecurityObject`), and `HalGetBusDataByOffset`/`HalSetBusDataByOffset`.
**Absent:** `ProbeForWrite`, `ProbeForRead`, `SeAccessCheck`, `SeSinglePrivilegeCheck`, `IoGetRequestorProcess`, `MmProbeAndLockPages`, `IoAllocateMdl`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`.

### 1.2 File B - `CoreTemp_ALSysIO64Legacy_x86_E586DB87.sys` (Legacy x86)

| Section | VA range |
|---|---|
| `.text` | `0x00011000`-`0x0001AFD6` |
| `.rdata` | `0x0001B000`-`0x0001BEF8` |
| `.data` | `0x0001C000`-`0x0001C200` |
| `PAGE` | `0x0001D000`-`0x0001E4E6` |
| `INIT` | `0x0001F000`-`0x0001F738` |
| `.rsrc` / `.reloc` | `0x00020000` / `0x00021000` |

* `AddressOfEntryPoint` = `0x0001F03E`: `CALL 0x1F005` (`__security_init_cookie`) then `JMP 0x114F0` = **`DriverEntry`**.
* `DriverEntry` `0x114F0`: `MajorFunction[0]=[2]=[0x0E] = 0x110B0` (`0x114FE`, `0x11501`, `0x11504`), `DriverUnload = 0x11460` (`0x11516`), then `0x11524 CALL 0x11010` with `L"\\Device\\ALSysIO"` (`0x191B0`), type `0x9C40`, ext size `0x248`.
* Dispatch = **`FUN_000110B0`**; unload = `FUN_00011460`.

**Import surface** (ntoskrnl + HAL): same functional set as File A plus `READ_REGISTER_BUFFER_UCHAR` / `WRITE_REGISTER_BUFFER_UCHAR` (used by the ECAM helper) and minus `ExAllocatePool2`. **Absent:** all probe/access-check/MDL APIs, as in File A.

### 1.3 Signature status (both files)

Both have a **PE certificate-table entry that resolves to EOF** and no signature bytes:

| File | Security dir offset | Size | File size | Result |
|---|---|---|---|---|
| x64 | `0x10800` | `0x28B0` | `0x10800` | zero bytes available |
| x86 | `0x0E200` | `0x28B0` | `0x0E200` | zero bytes available |

`Get-AuthenticodeSignature` returns **NotSigned** for both. This differs from the legacy x64 baseline, which had security-directory size 0 (no entry at all) - both new files look like *signature-stripped* copies of a signed build. Catalog signing cannot be determined from the `.sys`; under default DSE/HVCI both are treated as unsigned, hence `BLOCKED`.

---

## 2. Entry / device / interface / effective DACL

### 2.1 Creation call (identical construction in both files)

| File | Trampoline | Arg 7 (SDDL) | Ext size | Type | Characteristics | Exclusive |
|---|---|---|---|---|---|---|
| x64 | `FUN_140003A74` -> `FUN_140010204` (`WdmlibIoCreateDeviceSecure`) | `&DAT_14000CB58` - `LEA` at `0x140003A9E`, stored as 7th arg at `0x140003AB3` | `0x390` | `0x9C40` | `0x100` (`FILE_DEVICE_SECURE_OPEN`) | 1 |
| x86 | `FUN_00011010` -> `0x1D168` (`_WdmlibIoCreateDeviceSecure@36`) | `0x1B8E0` - `PUSH 0x1B8E0` at `0x11036` | `0x248` | `0x9C40` | `0x100` | 1 |

Both trampolines are the stock WDK `WdmlibIoCreateDeviceSecure`: an init flag (`DAT_14000E830` / `DAT_0001C688`) plus a `MmGetSystemRoutineAddress(L"IoCreateDeviceSecure")` resolve (`WdmlibInit` @ `0x140010178` / `0x1D109`), with a local fallback (`0x1400102A0` / `0x1D228`) that applies the *same* descriptor through `ObOpenObjectByPointer` + `ZwSetSecurityObject` (`0x140010430`). On Win10/11 the kernel export exists, so the fallback is not entered; either path yields the same DACL.

`IoValidateDeviceIoControlAccess` is resolved into `DAT_14000E820` / `_DAT_0001C690` and **never read** (single store, no load in either image) - dead code.

### 2.2 Effective SDDL

| File | UNICODE_STRING | Length / Max | Buffer | Bytes | Effective SDDL |
|---|---|---|---|---|---|
| x64 | `0x14000CB58` | `0x36` / `0x38` | `0x14000CB20` | `44 00 3A 00 50 00 ...` | **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`** |
| x86 | `0x0001B8E0` | `0x36` / `0x38` | `0x0001B8A8` | `44 00 3A 00 50 00 ...` | **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`** |

`D:P` = DACL present and **protected**; `GA` = `GENERIC_ALL`; `SY` = `NT AUTHORITY\SYSTEM`; `BA` = `BUILTIN\Administrators`. No `WD`, `AU`, `BU`, `IU` or `RC` ACE.

The x86 image contains the same graded table of eight `D:P` constants (`0x1B870` = `D:P`, `0x1B880` = `SY` only, **`0x1B8A8` = `SY`+`BA` (used)**, `0x1B8E8` = `GRGX`, then `GRGWGX` variants that add `GR`/`GRGW`/`GRGWGX` for `WD` and `RC`) - the seven wider ones have **zero** code references. Only the `UNICODE_STRING` at `0x1B8E0` appears in code (`0x11036`). File A contains a single `D:P` descriptor (`0x14000CB20`), also the only one referenced.

**The handle DACL is the only gate on every IOCTL in both files.** A UAC-filtered administrator at medium integrity (deny-only `BUILTIN\Administrators`) is rejected by the object manager before `IRP_MJ_CREATE`; a full-token administrator passes.

---

## 3. Dispatch and IOCTL table

`IRP_MJ_CREATE` (0), `IRP_MJ_CLOSE` (2) and `IRP_MJ_DEVICE_CONTROL` (0x0E) share one routine in each file (`FUN_140003B40` / `FUN_000110B0`). CREATE and CLOSE return `STATUS_SUCCESS` with **no identity, access-mask or privilege check**. Any other major returns `0xC0000002`. `IRP_MJ_READ`/`IRP_MJ_WRITE` are not hooked.

Every code satisfies `(code & 3) == 0` -> **METHOD_BUFFERED only**. `SystemBuffer` (`+0x18`) is used as both input and output; `Type3InputBuffer` (`+0x20`) is never read. Access bits: `0x9C4026xx` = `FILE_ANY_ACCESS`, `0x9C4040xx` = `FILE_READ_ACCESS`; inert because `IoValidateDeviceIoControlAccess` is never called.

| IOCTL | Fn | Method / Access | In >= | Out >= | x64 handler | x86 handler | Kernel / hardware action |
|---|---|---|---|---|---|---|---|
| `0x9C402604` | `0x981` | BUFFERED / ANY | 4 | 8 | `0x140004BE8` | `0x00011590` | Read MSR (whitelist, read bit required) |
| `0x9C402608` | `0x982` | BUFFERED / ANY | 0xC | 0 | `0x140005C44` | `0x00011650` | Write MSR - whitelist check requires write bit; **all entries have write=0**, so always `STATUS_ACCESS_DENIED` |
| `0x9C402610` | `0x984` | BUFFERED / ANY | 0x10 | 4 | `0x140004CA8` | `0x000116D0` | Read PCI config dword (`HalGetBusDataByOffset`, or x86 ECAM/CF8) |
| `0x9C402614` | `0x985` | BUFFERED / ANY | 0x14 | 0 | `0x140005CD4` | `0x00011750` | **Write PCI config dword** (4 B) |
| `0x9C402620` | `0x988` | BUFFERED / ANY | 0xC | 4 | `0x14000496C` | `0x00011830` | `HalGetBusDataByOffset` raw |
| `0x9C402624` | `0x989` | BUFFERED / ANY | 0 | 4 | `0x140004520` | `0x000119B0` | Version = `0x00020302` |
| `0x9C40262C` | `0x98B` | BUFFERED / ANY | 4 | 4 | `0x140004398` | `0x00011F70` | Base-clock measure (PM timer / **APIC MMIO writes** / HPET) |
| `0x9C402648` | `0x992` | BUFFERED / ANY | `0x228` | `0x228` | `0x140004E40` | `0x00012220` | **ACPI/PNP walk + device-extension slot swap** (see section 5.1) |
| `0x9C402650` | `0x994` | BUFFERED / ANY | 0 | 0x10 | `0x140004DB4` | `0x00011A00` | Read PM timer |
| `0x9C402654` | `0x996` | BUFFERED / ANY | 0 | 0x10 | `0x140004AC4` | `0x00011A90` | Read HPET (ACPI-mapped) |
| `0x9C402658` | `0x997` | BUFFERED / ANY | 0 | 0 | `0x1400045B8` | `0x00011B20` | Intel: RMW `IA32_FIXED_CTR_CTL` 0x38D / `IA32_PERF_GLOBAL_CTRL` 0x38F |
| `0x9C40265C` | `0x998` | BUFFERED / ANY | 4 | 0 | `0x1400046D0` | `0x00011B50` | Intel: `wrmsr 0x1A0` bit set/clear |
| `0x9C402660` | `0x999` | BUFFERED / ANY | 3 | 8 | `0x140004654` | `0x00011BA0` | Intel: OC mailbox, `rdmsr`/`wrmsr 0x150` |
| `0x9C402664` | `0x99A` | BUFFERED / ANY | 4 | 4 | `0x140004B50` | `0x00011CF0` | Read ACPI RSDP/table from mapped BIOS space |
| `0x9C402668` | `0x99B` | BUFFERED / ANY | 0xC | 0x1000 | `0x140004D34` | `0x000117B0` | Read 0x1000 B PCI config block |
| `0x9C40266C` | `0x99D` | BUFFERED / ANY | 0x18 | 4 | `0x14000426C` | `0x00011D90` | **PCI write + read-back** |
| `0x9C402674` | `0x99E` | BUFFERED / ANY | 0x18 | 4;n | `0x140004308` | `0x00011E20` | **PCI write loop** (`n = OutLen/4` dwords, value `base+i;4`, fixed register) + read-back |
| `0x9C402678` | `0x99F` | BUFFERED / ANY | 8 | >=8 | `0x140004194` | `0x00011EB0` | AMD SMU PM-table read (`AmdRdPmTables`) |
| `0x9C40267C` | `0x9A0` | BUFFERED / ANY | 8 | >= size | `0x1400045E4` | `0x00011C30` | Intel **MCHBAR read** `{offset,size}` |
| `0x9C404000` | `0x1000` | BUFFERED / READ | 0 | 0 | `0x1400044F8` | `0x00012F40` | No-op success |
| `0x9C404004` | `0x1001` | BUFFERED / READ | 0 | 0 | `0x1400044A8` | `0x00013100` | Vendor init/misc |
| `0x9C404008` | `0x1002` | BUFFERED / READ | 0 | 4 | `0x140004568` | `0x00011CA0` | Intel MCHBAR size or `0xC00000BB` |

Codes in the gaps (`0x9C402618`, `0x61C`, `0x628`, `0x630`-`0x644`, `0x64C`, `0x670`, ...) return `0xC0000002`. Minimum-length gates were verified on every File A handler and spot-verified on File B at `0x9C402604/608/610/620/648/66C/674/678/67C`; the remaining File B handlers are the same source line and show the same `param_3/param_5` comparisons.

---

## 4. Access-control audit

| Control | File A (x64) | File B (x86) | Evidence |
|---|---|---|---|
| Device DACL | **Yes** - `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | **Yes** - same | section 2.2; `0x140003AB3`, `0x11036` |
| `FILE_DEVICE_SECURE_OPEN` | Yes (`0x100`) | Yes (`0x100`) | `0x140003AC7`, `0x1103D` |
| Exclusive open | Yes (`1`) | Yes (`1`) | `0x140003AC0`, `0x1103B` |
| CREATE identity/access check | **None** | **None** | `0x140003B40` / `0x110B0`, major 0 |
| `SeAccessCheck` / `SeSinglePrivilegeCheck` | Not imported | Not imported | import tables |
| `FILE_WRITE_ACCESS` check | Not called | Not called | `IoValidateDeviceIoControlAccess` resolved but never loaded |
| Caller SID / token check | None | None | no token/process APIs imported |
| Probe of user pointers | Not needed (all buffered) | Not needed | `code & 3 == 0` for all 22 codes |
| Runtime DACL rewrite | None reachable | None reachable | `ZwSetSecurityObject` only in the wdmsec fallback |

**Conclusion.** Both devices are administrator-only. Nothing in the IOCTL path inspects the caller, so the DACL is the sole gate, and it holds for both images.

---

## 5. Memory-write trace

### 5.1 `0x9C402648` - device-extension pointer swap (the only kernel-memory write)

This is the one construct in either binary that writes a caller-controlled value into kernel memory, and it is present, essentially unchanged, in both builds.

**Input block (0x228 bytes, SystemBuffer):**

| Offset | Meaning |
|---|---|
| `+0x00` | mode byte: `0` = rediscover/walk ACPI, non-zero = use supplied values |
| `+0x48` | qword (x64) / dword (x86) - value to install |
| `+0x60` | second value to install (qword/dword) |
| `+0x128` | ANSI device path passed to `IoGetDeviceObjectPointer` |

**Flow (File A, `FUN_140004E40`):**

1. `0x140004E90` / `0x140004EA6` length gates: `InLen >= 0x228` **and** `OutLen >= 0x228`, else `0xC0000023` (`0x140005C0F`).
2. `0x140004F7C` `RtlInitAnsiString` on `input+0x128` -> `0x140004F95` `RtlAnsiStringToUnicodeString`.
3. `0x140004FB5` `IoGetDeviceObjectPointer(path, 0x80, &file, &device)`.
4. `0x140005000` **`DeviceObject->DeviceExtension`** = `[device+0x40]`.
5. Slot-select: `ext + 0x1E8` or `ext + 0x240`, chosen by `FUN_14000471C()` (`+0x58` delta).
6. Mode `0`: walks the ACPI namespace (`_PGS_`, `\___`, `_SB_`, `_TZ_`, `_TMP`, `_CRT`, `ATKD`, `PCI0`, `TMPR`, `LPC_`, `LPCB`, `EC0_`, `CTMP`) with `MmIsAddressValid` on every hop; writes discovered kernel pointers **into the caller's SystemBuffer** (KASLR/pointer leak) and sets `input[0]=1`.
7. Mode non-zero: `0x1400057D2` `RDI = [input+0x48]`; `0x140005826` `MmIsAddressValid(RDI)`; `0x14000583F` `RSI = *slot`, must be non-NULL.
8. **`0x14000584B` `MOV [R14], RDI`** - the swap. `R14` = slot pointer from step 5.
9. `0x1400058CB` `IoBuildDeviceIoControlRequest(0x32C004, device, ...)`; `0x1400058F6` `IofCallDriver`; `0x14000596E` restores the old slot value.
10. Two more swap blocks with the same shape but *no* `MmIsAddressValid` on the value:
    * `0x140005994` `MOV [R14], RAX` where `RAX = [input+0x60]`;
    * `0x140005AC9` `MOV [R14], RAX` where `RAX = [input+0x48]`.
    Restores at `0x140005AAD` / `0x140005BE2`.

**Flow (File B, `FUN_00012220`):** identical construction with 32-bit structure offsets.

1. `0x12273` / `0x12282` gate `InLen >= 0x228` / `OutLen >= 0x228` (else `0xC0000023` at `0x12287`).
2. `0x12376` `PUSH 0x80` + `0x12382` `IoGetDeviceObjectPointer(input+0x128, ...)`.
3. `0x123CC` `DeviceExtension = [device+0x28]`; slot = `ext + 0x12C` or `ext + 0x168`.
4. Mode byte `0` -> the same ACPI walk; mode non-zero -> `0x12B13` `EBX = [input+0x48]`, `0x12B34` `MmIsAddressValid(EBX)`, `0x12B48` `EAX = *slot`, `0x12B5A` **`MOV [EAX], EBX`**.
5. `0x12BBA` `IoBuildDeviceIoControlRequest(0x32C004, ...)`, `0x12BE4` `IofCallDriver`, `0x12C5B` restore.
6. Additional writes: `0x12C88` `MOV [EDX], ECX` (`ECX = [input+0x60]`) and `0x12DA9` `MOV [ECX], EAX` (`EAX = [input+0x48]`).

**What constrains it.**

| Axis | Constraint |
|---|---|
| Target | `DeviceObject->DeviceExtension + 0x1E8/0x240` (x64) or `+0x12C/0x168` (x86) of a device the caller names by ANSI path. The slot must be non-NULL. `MmIsAddressValid` is the only validation. |
| Value | Fully caller-controlled (`input+0x48` or `input+0x60`), no canonical-address check. |
| Size | Fixed: 8 B (x64), 4 B (x86). |
| Lifetime | Temporary - restored after the `0x32C004` IRP is sent, so the window is the duration of one synchronous/async IRP. |
| Gate | Handle DACL (Administrators) + the target slot being non-NULL. |

That is a **W2** write: controlled value, constrained target (a fixed offset in an attacker-chosen object), fixed size, transient. It is not an arbitrary kernel VA write.

### 5.2 PCI configuration writes - `HW-ONLY`

| IOCTL | File A path | File B path |
|---|---|---|
| `0x9C402614` | `0x140005CD4` -> tail `JMP 0x140007808`; `HalSetBusDataByOffset(PCIConfiguration, bus, (fn<<5)\|dev, &value, offset, 4)` (`0x14000786B`); bounds `bus<0x100`, `dev<0x20`, `fn<8`, `offset<0x1000` | `0x11750` -> `0x13A50`: ECAM (`MmMapIoSpace` + `WRITE_REGISTER_BUFFER_UCHAR`) or CF8/CFC `out` |
| `0x9C40266C` | `0x14000426C` -> `0x14000665C` (write) + `0x14000742C` (read) | `0x11D90` -> `0x13F50` |
| `0x9C402674` | `0x140004308` -> `0x1400066CC` loop (write value `base+i;4`, read-back) | `0x11E20` -> `0x13FB0` loop |

File A has **no** CF8/CFC or ECAM *write* helper; all PCI config access is via HAL. File B has both (`0x13350` read / `0x134C0` write use `MmMapIoSpace` + `READ/WRITE_REGISTER_BUFFER_UCHAR` over the firmware-provided ECAM ranges at `0x1C22C`/`0x1C230`, falling back to `0xCF8`/`0xCFC`).

PCI config space is a path to BAR remapping -> arbitrary physical memory/DMA, but the write itself is a 4-byte store in a **fixed hardware window** with a bus/dev/fn/offset the caller controls. Per `SEVERITY.md` this is `HW-ONLY`, not a memory-write level. It does not become MW1/MW3 because the chained effect (BAR remap) is not implemented in the driver.

### 5.3 MSR writes - `HW-ONLY`

| Path | File A | File B |
|---|---|---|
| Generic `0x9C402608` | `0x140005C44` -> `FUN_1400082B0(msr,2)`; entry write bit at `+6` | `0x11650` -> `FUN_00016340(msr,2)`; same layout |
| Whitelist contents | 3 tables, 44 + 41 + 16 = **101 entries**; every entry read=1, **write=0** | 3 tables, 44 + 41 + 16 = **101 entries**; every entry read=1, **write=0** |
| Result | every generic `wrmsr` returns `STATUS_ACCESS_DENIED` (`"WriteMSR 0x%08X ACCESS DENIED"`) | same |
| Fixed writes | `wrmsr 0x1A0` (`0x1400063D4`), `0x38D`/`0x38F` (`0x140006030`), `0x150` (`0x140006280`) | `0x15B50`, `0x15950`, `0x15800` |

The fixed MSR writes move fixed bits (`CPUID maxval` limit, fixed-counter enables, OC mailbox command) and are `HW-ONLY`.

### 5.4 MMIO writes - `HW-ONLY`

* `0x9C40262C`: `MmMapIoSpace(APIC_base + 0x300, 0x100)` then stores at `+0x20`, `+0x80`, `+0xE0` (`0x140006A5C`, File A). Local-APIC timer programming; not kernel memory.
* MCHBAR (`0x140005D7C`, `PCI 0:0.0 +0x48/0x4C`), HPET (`0x140007268`), ACPI/BIOS windows (`0x1400070A4`), and AMD SMU PM tables (`0x1400020E0`, SMU-provided PAs) are all firmware-derived, never caller-supplied.

### 5.5 What is *not* present

* No IOCTL takes a physical address from the caller into `MmMapIoSpace`. Every `MmMapIoSpace` argument is derived from PCI config, ACPI, or SMU data.
* No `MmMapLockedPagesSpecifyCache`, `MmProbeAndLockPages`, `MmCopyMemory`, `ZwMapViewOfSection`, or `\Device\PhysicalMemory`.
* No `ProbeForWrite`/`ProbeForRead` and no `METHOD_NEITHER`, so no raw user pointer is ever dereferenced.
* No pool overflow found: allocations in the IOCTL path are bounded by ACPI-table sizes (`ExAllocatePool2(0x40, n, ...)` / `ExAllocatePoolWithTag`), and the one caller-length allocation (`ExAllocatePoolWithQuotaTag(0x409, OutLen+0x10)`, `0x140010000` = AuxKlib query) is not IOCTL-reachable.
* Known low-severity defect retained from the baseline: the Intel MCHBAR read bound `if (MchbarSize < offset + size)` is a 32-bit add and can wrap (File B `0x15720`, File A `0x1400061C4`). It yields an **out-of-bounds read** into the output buffer, not a write.

---

## 6. How the new builds differ from the legacy x64 baseline (and from each other)

| Aspect | Legacy x64 `A0484FDC` (baseline) | New x64 `BA78A7BD` | Legacy x86 `E586DB87` |
|---|---|---|---|
| Toolchain | older MSVC, image base `0x10000`, 161 functions | VS2019/2022, image base `0x140000000`, 163 functions, CFG + `__GSHandlerCheck_SEH`, `fothk` | VS2008, image base `0x10000` |
| Device / SDDL | `\Device\ALSysIO`, `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | **identical** | **identical** |
| Device type / ext size | `0x9C40` / `0x390` | **identical** (`0x390`) | `0x9C40` / `0x248` (32-bit layout) |
| IOCTL set | 22 codes, all buffered | **identical 22 codes** | **identical 22 codes** |
| `0x9C402648` slot | `ext+0x1E8` / `+0x240` | **same offsets** | `ext+0x12C` / `+0x168` |
| PCI config write | ECAM `WriteMemorySpace` + CF8/CFC | **HAL only** (`HalSetBusDataByOffset`) | ECAM + CF8/CFC |
| MSR whitelist | all write bits 0 | **same** (101 entries, write=0) | **same** |
| Signature | security dir size 0 | entry present but points at EOF -> unsigned | entry present but points at EOF -> unsigned |
| Extra code | - | AMD RSMU/HSMP mailbox, CPU codename table, dynamic affinity APIs, AuxKlib module query | - |

**Net:** the current x64 build is a modernized re-compile of the same driver. Its reachable surface is the same 22 IOCTLs, the same SDDL, and the same `0x9C402648` slot swap; the only material difference is that PCI config access moved from an in-driver ECAM/CF8 helper to `HalSetBusDataByOffset`, which removes one `MmMapIoSpace`-based MMIO store path but does not change the rating.

The x86 build is the legacy source line compiled for 32-bit. It has the **same reach and the same primitives**, but the pointer swap is a **4-byte** write instead of 8, and it additionally retains the ECAM/CF8 PCI path. It cannot load on this x64 host at all.

---

## 7. Most dangerous exposed capability

For an administrator who can open the handle (and only for such a caller):

1. **`0x9C402648` - 8-byte (x64) / 4-byte (x86) write into an attacker-named device's extension**, at a fixed offset, with an attacker-chosen value, plus a `0x32C004` IRP delivered to that device while the value is installed. This is a genuine kernel-memory write (W2) and the only one in either binary. The same IOCTL's rediscover mode returns kernel pointers and ACPI object signatures to the caller - a KASLR/pointer leak that makes the write easier to aim.
2. **PCI configuration writes** (`0x9C402614`, `0x9C40266C`, `0x9C402674`) - the standard route to a BAR remap, i.e. arbitrary physical memory/DMA, but the driver stops at the config write (`HW-ONLY`).
3. **Fixed MSR writes** (`0x1A0`, `0x38D/0x38F`, `0x150`) and **APIC/HPET/MCHBAR MMIO** - privileged hardware access, `HW-ONLY`.
4. **No arbitrary kernel VA write, no caller-controlled physical address, no MDL/user mapping.**

---

## 8. VERDICT

**File A - `CoreTemp_ALSysIO64_x64_BA78A7BD.sys`:** `BLOCKED (static MW2)` - reach=R2 setup=service write=W2 load=unsigned.

* Device `\Device\ALSysIO`, symlink `\DosDevices\ALSysIO`, type `0x9C40`, `0x390`-byte extension, `FILE_DEVICE_SECURE_OPEN`, exclusive.
* Effective SDDL **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`** (`0x14000CB58` -> `0x14000CB20`, applied at `0x140003AB3`), the only descriptor referenced in the image.
* CREATE/CLOSE return success without checks; the DACL is the only gate and it is administrator-only.
* All 22 IOCTLs are `METHOD_BUFFERED`; no user pointer is dereferenced; no probe/access-check imports.
* The single kernel-memory write is the `0x9C402648` device-extension slot swap (`0x14000584B`, plus `0x140005994`/`0x140005AC9`), gated only by `MmIsAddressValid` and a non-NULL slot -> **W2**.
* The image carries no valid Authenticode signature (certificate table points at EOF; `NotSigned`), so on default DSE/HVCI it will not load -> **BLOCKED**, with the static primitive recorded as MW2.

**File B - `CoreTemp_ALSysIO64Legacy_x86_E586DB87.sys`:** `BLOCKED (static MW2)` - reach=R2 setup=service write=W2 load=unsigned (and PE32).

* Same device, same SDDL (`0x1B8E0` -> `0x1B8A8`), same 22-IOCTL set, same access model.
* Same `0x9C402648` primitive at `0x12B5A` / `0x12C88` / `0x12DA9`, 4-byte value, slots `ext+0x12C`/`+0x168`.
* Additional ECAM/CF8 PCI write path (`0x13A50` -> `0x134C0`) - still `HW-ONLY`.
* Unsigned and 32-bit: not loadable on this x64 host, and blocked by DSE even on 32-bit Windows without test-signing.

**Overall verdict: `BLOCKED (static MW2)`.** Neither file adds a new primitive over the legacy x64 baseline. The `0x9C402648` slot swap is a real but constrained, administrator-only, transient kernel write; the PCI/MSR/MMIO paths are `HW-ONLY`. Both images are unsigned, and the x86 image is additionally non-loadable on this host. If either image were signed (or loaded with enforcement off), the rating would be **MW2 - reach=R2 setup=service write=W2**, because the DACL still confines the handle to administrators.

---

## 9. Limitations

1. **Static only.** No driver was loaded, no IOCTL issued, no VM/kernel debugger used. DACL enforcement and `MmIsAddressValid` semantics follow documented kernel behaviour, not runtime observation.
2. **Tooling.** Ghidra 12.1.4 headless only; REA was deliberately not used to avoid the documented 4-session contention, so no REA evidence IDs exist for this report. All addresses are Ghidra VAs on the two verified SHA-256 images.
3. **Decompiler output.** No PDB/symbols were applied; function boundaries, parameter counts and stack-argument recovery are inferred. Where it mattered (the store instructions, the SDDL load, the MSR table walk, the PCI write tail-call) the claims rest on instruction-level addresses, not pseudocode.
4. **Signature status.** Only the *absence of a valid embedded signature* is established. Catalog signing, WHQL/attestation and revocation cannot be determined from the `.sys` alone; if a catalog covers these exact hashes, the load gate would move from `BLOCKED` to loadable (the primitive rating would not change).
5. **`0x9C402648` slot semantics.** What the overwritten pointer is *used for* by the target driver (ACPI thermal zone, `ATKD`/`PCI0`/`EC0_` devices) is outside these images. The report establishes only that the driver installs a caller value at a fixed extension offset and sends one `0x32C004` IRP while it is installed.
6. **MSR whitelist.** The write-permission halfword `+6` is zero in all 101 static entries of both images; the runtime hash table built from those entries was not exercised.
7. **Vendor branches.** Behaviour differs by CPU vendor (`DAT_14000E750` / `DAT_0001C24C`); only static branches were inspected. The MCHBAR path additionally depends on firmware PCI state.
8. **x86 load model.** The PE32 image's inability to load on an x64 host is architectural; 32-bit Windows behaviour (including the `0x12C`/`0x168` extension offsets, which depend on the 32-bit `_DEVICE_OBJECT` layout) was not validated at runtime.
