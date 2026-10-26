# Audit: CoreTemp ALSysIO64Legacy

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected5\agentR4\new\CoreTemp_ALSysIO64Legacy_x64_A0484FDC.sys` |
| SHA-256 | `A0484FDCFBAFB6EDE4ABBBE1E2860D1E361B0EC0C1E61BB10142F9AF75A0F131` |
| Analysis date | 2026-10-24 |
| Method | Static-only audit via REA/Ghidra (no execution, no driver load, no service creation) |
| Reach tier | **R2** — local administrator (protected SDDL, SYSTEM + Administrators only) |
| Setup required | none (driver load) |
| Write quality | W2 — user-value-controlled 8-byte write into an attacker-selected driver's device extension, plus PCI config/MSR |
| Verdict | **BLOCKED** (static MW2) — reach=R2 setup=none write=W2 load=unsigned |
| Format / architecture | PE32+ native, x86-64, image base `0x10000` |
| Reported version | 2.3.2.41 (runtime version IOCTL returns `0x00020302` = 2.3.2) |
| Signature | No embedded Authenticode image signature (PE Data Directory 4 size = 0) |
| Imports | 59 × `ntoskrnl.exe`, 1 × `HAL.dll` (60 total) |

Evidence IDs referenced below are REA/Ghidra observations of this exact SHA-256.
Key observations: `ev_c7775968…c4bfdb` (DriverEntry), `ev_96d97cb2…b4555f` (dispatch), `ev_ed8f1573…a60c481` (SDDL table), `ev_a8aff358…b0ee65a` (WriteMemorySpace), `ev_c76192ca…54226eb` (IOCTL `0x9C402648`), `ev_f7a87512…1f3f0e` (PDATA/instruction listing), `ev_af8d011f…f0bd92` (inventory), `ev_e6b8d135…3457f5` (strings).

---

## 1. Internals

**Binary layout.** Ten mapped blocks; `Headers` `0x10000–0x103FF`, `.text` `0x11000–0x1C5FF`, `.rdata` `0x1D000–0x1EDFF`, `.data` `0x1F000–0x1F8A7`, `.pdata` `0x20000–0x209FF`, `PAGE` `0x21000–0x22BFF`, `INIT` `0x23000–0x239FF`, `.rsrc`, `.reloc`. Ghidra recovers 161 internal procedures and 315 defined strings (`ev_af8d011f…f0bd92`, `ev_e6b8d135…3457f5`).

**PE entry chain.** The PE `AddressOfEntryPoint` is RVA `0x13064` → address `0x23064` in `INIT`:

```c
void entry(longlong DriverObject)        // 0x23064
{
    FUN_00023008();                      // __security_init_cookie / GS setup
    FUN_00011010(DriverObject);          // real DriverEntry
}
```

`FUN_00011010` is therefore DriverEntry (`0x11010`).

**DriverEntry (`0x11010`, `ev_c7775968…c4bfdb`) in order:**

| Addr | Action |
|---|---|
| `0x11026`, `0x1102a`, `0x11031` | `DriverObject->MajorFunction[IRP_MJ_CREATE(0)]`, `[IRP_MJ_CLOSE(2)]`, `[IRP_MJ_DEVICE_CONTROL(0x0E)]` = `0x111F0` |
| `0x1103f` | `DriverObject->DriverStartIo` = NULL |
| `0x1104a` | `DriverObject->DriverUnload` = `0x11840` (`FUN_00011840`, symbolic-link delete + `IoDeleteDevice`) |
| `0x11053` | `RtlInitUnicodeString(&name, L"\\Device\\ALSysIO")` (`0x1A5D0`) |
| `0x11097` | `WdmlibIoCreateDeviceSecure(...)` → `0x211EC` |
| `0x110CB` | `RtlInitUnicodeString(&link, L"\\DosDevices\\ALSysIO")` (`0x1A5F0`) |
| `0x110DB` | `IoCreateSymbolicLink(&link, &name)` |
| `0x11130` | zero 16 × `0x38`-byte per-CPU/per-slot state records in the device extension |
| `0x11141`–`0x111B2` | one-time init: `FUN_19D60`, `FUN_16DC0`, MSR whitelist build `FUN_173B0` selected by CPU vendor `DAT_1F3D0` (`0x1114B`: AMD→`0x1D7D0`/0x2C entries, Intel→`0x1D930`/0x29, second Intel table→`0x1DA80`/0x10), `FUN_19720`, `FUN_162C0` |

`FUN_00011840` (unload) also unmaps the Intel MCHBAR (`MmUnmapIoSpace` at that routine's `DAT_1F3C0/DAT_1F3C8`).

**Import surface relevant to security.** The import table contains *no* `ProbeForWrite`, *no* `ProbeForRead`, *no* `SeAccessCheck`, *no* `SeSinglePrivilegeCheck`, *no* `IoGetRequestorProcess`, and *no* `MmCopyMemory`/`ZwMapViewOfSection`. The security-relevant imports are `IoCreateDevice`, `ObOpenObjectByPointer`, `ZwSetSecurityObject`, `RtlCreateSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlAddAccessAllowedAce`, `SeCaptureSecurityDescriptor`, `RtlAbsoluteToSelfRelativeSD`, `IoDeviceObjectType` — all of which are consumed by the statically linked *wdmsec* fallback (see §2), not by the IOCTL path. `MmMapIoSpace`/`MmUnmapIoSpace` are imported (IAT slots `0x1D0C0`/`0x1D0A8`). `IoCreateDeviceSecure` and `IoValidateDeviceIoControlAccess` are resolved dynamically with `MmGetSystemRoutineAddress` (`0x21180`, `FUN_00021180` = `WdmlibInit`).

**Device type / extension.** `DeviceType` = `40000` (`0x9C40`); `DeviceExtensionSize` = `0x390`; every IOCTL code uses device type `0x9C40`, which is consistent. The device is created exclusive (`Exclusive = TRUE`).

---

## 2. Entry / device / SDDL

### 2.1 The creation call

`WdmlibIoCreateDeviceSecure` is statically linked at `0x211EC`; it is a thin trampoline (`ev_96d97cb2…b4555f` is the dispatcher, the trampoline was read separately):

```c
void WdmlibIoCreateDeviceSecure(...9 args...)      // 0x211EC
{
    if (DAT_0001F310 == 0) WdmlibInit();           // 0x21180
    (*DAT_0001F318)(arg1..arg9);                   // resolved IoCreateDeviceSecure
}
```

`WdmlibInit` (`0x21180`) does:

```c
RtlInitUnicodeString(&s, L"IoCreateDeviceSecure");
DAT_0001F318 = MmGetSystemRoutineAddress(&s);      // 0x21196
if (DAT_0001F318 == NULL) DAT_0001F318 = IoDevObjCreateDeviceSecure;  // 0x21330
RtlInitUnicodeString(&s, L"IoValidateDeviceIoControlAccess");
DAT_0001F320 = MmGetSystemRoutineAddress(&s);      // stored, never called
```

`DAT_0001F320` has exactly one xref, `0x211DA` (the store itself), so `IoValidateDeviceIoControlAccess` is dead code. On every supported OS the kernel export exists, so the local fallback `0x21330` is never entered (it has **zero** call xrefs; `0x21284` `IopDevObjApplyPostCreationSettings`, the only `ZwSetSecurityObject` caller at `0x21307`, is called only from `0x21330`).

### 2.2 Argument mapping at the call site (`0x11059`–`0x11097`)

| Win64 arg | Register / stack | Value at call | Meaning |
|---|---|---|---|
| 1 | `RCX` | `RBX` = DriverObject | DriverObject |
| 2 | `EDX` | `0x390` | DeviceExtensionSize |
| 3 | `R8` | `&[RSP+0x50]` | DeviceName = `\Device\ALSysIO` |
| 4 | `R9D` | `0x9C40` (40000) | DeviceType |
| 5 | `[RSP+0x20]` | `0x100` | `FILE_DEVICE_SECURE_OPEN` |
| 6 | `[RSP+0x28]` | byte `0x1` | Exclusive |
| 7 | `[RSP+0x30]` | **`0x1D2E0`** | `PCUNICODE_STRING DefaultSDDLString` |
| 8 | `[RSP+0x38]` | `0` | DeviceClassGuid = NULL |
| 9 | `[RSP+0x40]` | `&[RSP+0x80]` | out DeviceObject |

The 7th argument is the only SDDL ever handed to the device creator:

```
0x11061  LEA RAX, [0x1D2E0]
0x11072  MOV qword ptr [RSP+0x30], RAX      ; arg 7 = &UNICODE_STRING at 0x1D2E0
```

### 2.3 The effective SDDL

`0x1D2E0` is a `UNICODE_STRING` (not a raw literal), which is why plain string inventory misses it (`ev_ed8f1573…a60c481`):

| Field | Value |
|---|---|
| `Length` | `0x0036` (54 bytes = 27 UTF-16 chars) |
| `MaximumLength` | `0x0038` |
| `Buffer` | `0x1D2A8` |

Bytes at `0x1D2A8`, 54 bytes, NUL-terminated at `0x1D2DE`:

```
44 00 3A 00 50 00 28 00 41 00 3B 00 3B 00 47 00 41 00 3B 00 3B 00 3B 00 53 00 59 00 29 00
28 00 41 00 3B 00 3B 00 47 00 41 00 3B 00 3B 00 3B 00 42 00 41 00 29 00
```

**Effective SDDL: `D:P(A;;GA;;;SY)(A;;GA;;;BA)`**

Decoded:

- `D:P` — a DACL is present and **protected**: no inherited ACEs are merged.
- `(A;;GA;;;SY)` — Allow, no inheritance, `GENERIC_ALL`, to `NT AUTHORITY\SYSTEM` (S-1-5-18).
- `(A;;GA;;;BA)` — Allow, no inheritance, `GENERIC_ALL`, to `BUILTIN\Administrators` (S-1-5-32-544).

There is **no** ACE for `WD` (Everyone, S-1-1-0), `AU` (Authenticated Users, S-1-5-11), `BU` (Builtin Users), `IU` (Interactive), or `RC` (Restricted Code). The descriptor is applied by the kernel's `IoCreateDeviceSecure` and the object is opened with `FILE_DEVICE_SECURE_OPEN`, so the DACL is evaluated on every `IRP_MJ_CREATE`, including opens through the `\??\ALSysIO` / `\\.\ALSysIO` symbolic link (symbolic links carry no DACL of their own; access is checked on the target device object).

### 2.4 The other seven SDDL constants are dead

Eight `D:P` UTF-16 strings exist in `.rdata`. Only one has any code xref (`0x11061` / `0x11072`); the other seven have **zero** xrefs (`xrefs` on each descriptor address returned `[]`):

| # | UNICODE_STRING | len | SDDL | Code xrefs |
|---|---|---|---|---|
| 0 | `0x1D268` | 6 | `D:P` (empty, deny-all DACL) | **0** |
| 1 | `0x1D290` | 30 | `D:P(A;;GA;;;SY)` | **0** |
| **2** | **`0x1D2E0`** | **54** | **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`** | **`0x11061`, `0x11072` — USED** |
| 3 | `0x1D330` | 58 | `D:P(A;;GA;;;SY)(A;;GRGX;;;BA)` | **0** |
| 4 | `0x1D398` | 86 | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR;;;WD)` | **0** |
| 5 | `0x1D420` | 110 | `…(A;;GR;;;WD)(A;;GR;;;RC)` | **0** |
| 6 | `0x1D4A8` | 114 | `…(A;;GRGW;;;WD)(A;;GR;;;RC)` | **0** |
| 7 | `0x1D540` | 126 | `…(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)` | **0** |

The graded table (#0 → #7, deny-all → Everyone `GR`, `GRGW`, `GRGWGX`) is a compile-time artifact of the driver source's SDDL enum; the linker kept all constants, but the code only ever references entry #2. **The `Everyone`/`WD` variants are not reachable by any code path in this binary**, and no runtime path rewrites the device DACL (`ZwSetSecurityObject` is reachable only from the never-called `0x21330` fallback).

Triage note: the earlier "SDDL-ACTIVE-RESTRICTED / effective DACL unresolved" label is now resolved — the active SDDL is the *most restrictive* non-empty variant, administrator-only. The triage count of seven corresponds to entries #1–#7 (or #0–#6 depending on whether the empty `D:P` is counted).

---

## 3. IOCTL table

### 3.1 Dispatch mechanics

`IRP_MJ_CREATE`, `IRP_MJ_CLOSE` and `IRP_MJ_DEVICE_CONTROL` all route to `FUN_000111F0` (`0x111F0`, `ev_96d97cb2…b4555f`). The routine:

1. `pcVar4 = Irp->Tail.Overlay.CurrentStackLocation` (`Irp+0xB8`).
2. Clears `Irp->IoStatus.Status`/`.Information` (`Irp+0x30`/`Irp+0x38`).
3. Switches on `MajorFunction` (`[pcVar4+0]`). `0` (CREATE) and `2` (CLOSE) complete with `STATUS_SUCCESS` immediately, with no checks. Any major other than `0x0E` completes `0xC0000002` (`STATUS_NOT_IMPLEMENTED`).
4. For `0x0E`: reads `IoControlCode` = `[pcVar4+0x18]`, `InputBufferLength` = `[pcVar4+0x10]`, `OutputBufferLength` = `[pcVar4+8]`, and passes `Irp->AssociatedIrp.SystemBuffer` (`Irp+0x18`) as both input and output buffer. It writes the byte count into `Irp->IoStatus.Information` (`Irp+0x38`) and finishes with `IofCompleteRequest`.
5. Unmatched codes fall through with `0xC0000002`.

All codes satisfy `(code & 3) == 0` → every IOCTL is **METHOD_BUFFERED**. There is no `METHOD_NEITHER`, no `Type3InputBuffer` use (`[pcVar4+0x20]` is never read), and therefore **no user-mode pointer is ever dereferenced by this driver**.

### 3.2 Codes

Device type is `0x9C40` (= 40000) in every code, matching `DeviceType`. Access bits `(code >> 14) & 3`: all `0x9C4026xx` codes are `0` (`FILE_ANY_ACCESS`); the three `0x9C4040xx` codes are `1` (`FILE_READ_ACCESS`). Because `IoValidateDeviceIoControlAccess` is never called, these access bits are inert — the handle DACL is the only gate.

| IOCTL | Function | Method | Access | In (min) | Out (min) | Handler | Kernel / hardware action |
|---|---|---|---|---|---|---|---|
| `0x9C402604` | `0x981` | BUFFERED | ANY | 4 | 8 | `0x11940` | **Read MSR**: index from user, must match MSR whitelist (`DAT_1F3D8` hash of `0x1D7D0`/`0x1D930`/`0x1DA80`); returns 8-byte `rdmsr` value |
| `0x9C402608` | `0x982` | BUFFERED | ANY | 12 | 0 | `0x11A80` | **Write MSR**: index + u64 value; exact-match whitelist; per-entry write-permission halfword at entry `+6` is `0` in all three embedded tables, so this path denies every MSR (`WriteMSR 0x%08X ACCESS DENIED`) |
| `0x9C402610` | `0x984` | BUFFERED | ANY | 16 | 4 | `0x11B80` → `0x14360` | **Read PCI config dword**: bus/dev/fn/reg, bus < 0x100; CF8/CFC or ECAM-MMIO path |
| `0x9C402614` | `0x985` | BUFFERED | ANY | 20 | 0 | `0x14500` | **Write PCI config dword**: bus/dev/fn/offset/value; bus<0x100, dev<0x20, fn<8, offset<0x1000 (legacy path additionally `<0x100`); writes via `out 0xCF8/0xCFC` or `MmMapIoSpace`+`WriteMemorySpace` on ECAM |
| `0x9C402620` | `0x988` | BUFFERED | ANY | 12 | 4 | `0x11C40` | `HalGetBusDataByOffset(PCIConfiguration, …)`, returns dword + bytes-read |
| `0x9C402624` | `0x989` | BUFFERED | ANY | 0 | 4 | inline | Returns version `0x00020302` (2.3.2) |
| `0x9C40262C` | `0x98B` | BUFFERED | ANY | 4 | 4 | `0x122C0` | Measures base clock (PM timer / APIC / HPET), returns u32 |
| `0x9C402648` | `0x992` | BUFFERED | ANY | `0x228` | `0x228` | `0x125F0` | **ACPI/PNP object walk + device-extension pointer swap** (see §5); user-chosen ANSI device path at input `+0x128`; sends IRP `0x32C004` to that device |
| `0x9C402650` | `0x994` | BUFFERED | ANY | 0 | 16 | `0x11D90` | Read PM timer port (`DAT_1F358`), returns 16 bytes |
| `0x9C402654` | `0x995` | BUFFERED | ANY | 0 | 16 | `0x148A0` | Read HPET (`MmMapIoSpace` of ACPI-derived `DAT_1F368`), returns 16 bytes |
| `0x9C402658` | `0x996` | BUFFERED | ANY | 0 | 0 | `0x16A70` | Intel only: read/modify/restore `IA32_FIXED_CTR_CTL` (0x38D) and `IA32_PERF_GLOBAL_CTRL` (0x38F) |
| `0x9C40265C` | `0x997` | BUFFERED | ANY | 4 | 0 | `0x16CA0` | Intel only: **`wrmsr 0x1A0`** (`IA32_MISC_ENABLE`) to set/clear the CPUID-maxval limit bit, based on a user dword |
| `0x9C402660` | `0x998` | BUFFERED | ANY | 3 | 8 | `0x168F0` | Intel only: **OC mailbox** via `rdmsr/wrmsr 0x150` with three user bytes, returns 8-byte message |
| `0x9C402664` | `0x999` | BUFFERED | ANY | 4 | ≥ size | `0x11F00` → `0x172D0` | Reads ACPI RSDP/PM table from `MmMapIoSpace`-mapped BIOS space; size comes from the table, not the user |
| `0x9C402668` | `0x99A` | BUFFERED | ANY | 12 | 0x1000 | `0x14690` | Read 0x1000-byte PCI config block (legacy CF8 loop + ECAM `ReadMemorySpace`) |
| `0x9C40266C` | `0x99B` | BUFFERED | ANY | 24 | 4 | `0x11FD0` | PCI config **write then read-back** (6 dwords in, 1 dword out) |
| `0x9C402674` | `0x99D` | BUFFERED | ANY | 24 | 4·n | `0x12100` → `0x14960` | PCI config **write loop**: writes `n = outlen/4` dwords, value `base + i*4`, at fixed register `param_2[3]`, then reads back at `param_2[4]` |
| `0x9C402678` | `0x99E` | BUFFERED | ANY | 8 | 8 | `0x121C0` → `0x19B10` | AMD SMU PM-table read (`AmdRdPmTables`) |
| `0x9C40267C` | `0x99F` | BUFFERED | ANY | 8 | ≥ size | `0x11E70` → `0x16800` | Intel **MCHBAR read**: `{offset,size}` from user, bounds-checked against `DAT_1F3C8`; `memcpy` from `DAT_1F3C0+offset` |
| `0x9C404000` | `0x1000` | BUFFERED | READ | 0 | 0 | inline | No-op success |
| `0x9C404004` | `0x1001` | BUFFERED | READ | 0 | 0 | `0x19A20` / `0x13500` | Vendor-specific (AMD/Intel) init/misc call |
| `0x9C404008` | `0x1002` | BUFFERED | READ | 0 | 4 | inline | Returns Intel MCHBAR size (`DAT_1F3C8`) or `0xC00000BB` |

Codes in the gaps (`0x9C402618`, `0x61C`, `0x628`, `0x630`–`0x644`, `0x64C`, `0x670`, …) are unhandled and return `0xC0000002`.

### 3.3 Validation quality

Every handler checks its minimum input length before reading (`param_3 < N` → `0xC0000023`/`0xC000000D`) and, where it writes, checks the output length against the exact byte count it will produce. Spot checks: `0x11940` (out ≥ 8, writes 8), `0x11B80` (out ≥ 4, writes 4), `0x11D90`/`0x148A0` (out ≥ 0x10, write 16), `0x14690` (out ≥ 0x1000, writes 0x1000), `0x11E70` (size ≤ outlen, bounded by MCHBAR size), `0x12100` (outlen multiple of 4, writes exactly outlen bytes), `0x11C40` and `0x14500` (minimum input lengths enforced before the fixed-size struct reads). No pool overflow or unchecked caller-length copy was found in the IOCTL path.

One low-severity defect exists in `0x16800` (`IntelReadMchbar`): the upper-bound test `if (DAT_1F3C8 < param_1 + param_3)` is a 32-bit addition and can wrap when the caller of the IOCTL supplies `offset` and `size` whose sum overflows (`0x16800` block after the `0x1F3C8 <= param_1` check). A wrapped sum lets `memcpy` read past the end of the MCHBAR mapping into the 0x228-byte (or larger) output buffer. That is an information-disclosure bug reachable only through an already-authorized handle, not a write primitive.

---

## 4. Access-control audit

| Control | Present? | Evidence |
|---|---|---|
| Device DACL | **Yes** — protected admin-only DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | §2.3, `0x1D2E0`/`0x1D2A8`, xref `0x11061` |
| `FILE_DEVICE_SECURE_OPEN` | **Yes** (`0x100`) | `0x1108F` |
| Exclusive open | **Yes** (`Exclusive=1`) | `0x1108A` |
| `IRP_MJ_CREATE` identity check | **No** — returns `STATUS_SUCCESS` with no inspection | `0x111F0`, case `0` |
| `SeAccessCheck` / `SeSinglePrivilegeCheck` | **No** — not imported, no call | import table (60 entries) |
| `FILE_WRITE_ACCESS` / `FILE_READ_ACCESS` check | **No** — `IoValidateDeviceIoControlAccess` resolved but never called | `0x1F320` single xref `0x211DA` |
| Caller SID / token check | **No** — no `SeQueryInformationToken`, `PsGetCurrentProcess`, `IoGetRequestorProcess` imports | import table |
| `ProbeForWrite` / user-pointer probing | **Not needed / not present** — all IOCTLs METHOD_BUFFERED | code `& 3 == 0` for all codes |
| Runtime DACL rewrite | **No** — `ZwSetSecurityObject` only from never-called fallback | `0x21307` ← `0x21284` ← `0x21330` (no call xrefs) |

**Conclusion.** The handle DACL is the *only* gate, and that gate is administrator-only. An unprivileged authenticated user (or even a UAC-filtered administrator at medium integrity, whose `BUILTIN\Administrators` SID is deny-only) gets `STATUS_ACCESS_DENIED` from the object manager before `IRP_MJ_CREATE` reaches `0x111F0`. None of the 22 IOCTL codes is reachable, so none of the underlying hardware primitives is reachable.

The triage hypothesis that this might be an "SDDL-ACTIVE-RESTRICTED" driver with an unresolved effective DACL is disproved: the active descriptor is the most restrictive non-empty entry in the table.

---

## 5. Most dangerous exposed capability

The SDDL makes these administrator-only, but if the descriptor were ever one of the `WD` variants (or the binary were patched), the surface is a full hardware-privilege bridge — considerably stronger than a typical "read a temperature" driver:

1. **Arbitrary PCI configuration-space write** — `0x9C402614` (`0x14500`), `0x9C402674` (`0x12100`→`0x14960`), `0x9C40266C` (`0x11FD0`). The ECAM path computes `ECAM_base | (bus<<20 | dev<<15 | fn<<12) | (offset & 0xFFC)` and calls `WriteMemorySpace` (`0x140D0`, `MmMapIoSpace(addr,4)` + 4-byte store at `0x14048`/`0x14127`), i.e. a 4-byte store anywhere in the PCI ECAM window; the legacy path programs `0xCF8`/`0xCFC` directly. PCI config write is the canonical route to re-program a device BAR and obtain arbitrary physical-memory / DMA access, making this an effective kernel-memory-write primitive *for a caller who can open the handle*.

2. **Device-extension pointer swap with a user-chosen target device** — `0x9C402648` (`0x125F0`). The input buffer is a 0x228-byte control block whose first byte selects "rediscover" vs "use supplied pointers" and whose bytes at `+0x128` are an ANSI device path. The driver calls `IoGetDeviceObjectPointer(path, 0x80, …)` (`0x1277F`), takes `DeviceObject->DeviceExtension` (`0x127CA`, `[obj+0x40]`), selects slot `+0x1E8` or `+0x240` (`0x127EC`/`0x127DB`), then at `0x13052` loads the user qword `[input+0x48]` (or `[input+0xC8]`), validates only `MmIsAddressValid`, and executes `MOV [slot], RDI` at **`0x130D2`**. It then builds `IRP_MJ_DEVICE_CONTROL` `0x32C004` with `IoBuildDeviceIoControlRequest` (`0x1314B`) and sends it to that device with `IofCallDriver` (`0x13178`), restoring the old slot value at `0x131EA`. This is a temporary, user-value-controlled 8-byte kernel write into an attacker-selected driver's device extension, used as a trampoline to make another driver act on attacker data. It is the most dangerous single construct in the binary.

3. **MSR writes** — fixed but privileged: `wrmsr 0x1A0` (CPUID maxval / `IA32_MISC_ENABLE`) at `0x16CA0`, `wrmsr 0x38D`/`0x38F` at `0x16A70`, `wrmsr 0x150` OC mailbox at `0x168F0`; generic `wrmsr` (`0x13F90`) is whitelist-gated.

4. **I/O port and MMIO access** — `in`/`out` on `0xCF8`/`0xCFC` (`0x141B0`, `0x14200`), `MmMapIoSpace` of MCHBAR/HPET/PM tables (`0x19080`).

There is **no** IOCTL that passes a caller-supplied physical address into `MmMapIoSpace`, and no caller-supplied virtual address is ever written. `ReadMemorySpace` (`0x13FE0`) and `WriteMemorySpace` (`0x140D0`) are internal helpers; their 15 call sites (`0x14360`, `0x14690`, `0x148A0`, `0x14A60`, `0x156A0`, `0x159C0`, `0x15DE0`, `0x160F0`, `0x162C0`, `0x17100`, `0x171E0`, `0x172D0`, `0x19480`, plus the PCI/ECAM writers) all compute the address from PCI/ACPI/MCHBAR state.

---

## 6. VERDICT

**No unprivileged kernel memory-write primitive is reachable.**

- The device `\Device\ALSysIO` (symbolic link `\DosDevices\ALSysIO`) is created at `0x11097` with the static SDDL **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`** (`UNICODE_STRING` at `0x1D2E0` → buffer `0x1D2A8`), a protected DACL granting `GENERIC_ALL` only to `SYSTEM` and `BUILTIN\Administrators`, with `FILE_DEVICE_SECURE_OPEN` and `Exclusive=TRUE`.
- The other seven embedded SDDLs — including the `Everyone`/`WD` `GR`, `GRGW`, `GRGWGX` variants at `0x1D398`, `0x1D420`, `0x1D4A8`, `0x1D540` — are unreferenced constants. No code path selects them, and nothing rewrites the DACL after creation.
- `IRP_MJ_CREATE`, `IRP_MJ_CLOSE` and `IRP_MJ_DEVICE_CONTROL` share `0x111F0`; CREATE completes with `STATUS_SUCCESS` without any identity or access-mask check. The I/O manager's DACL check is therefore the sole gate, and it denies unprivileged and non-elevated callers.
- All 22 handled IOCTLs are `METHOD_BUFFERED`; the driver never touches a user-mode pointer and never calls `ProbeForWrite` (that import does not exist). Buffer-length validation in the handlers is generally correct.
- The binary has **no embedded Authenticode signature** (security directory size 0). That is a separate load gate: on a default x64 Windows with driver signature enforcement and Secure Boot, this image will not load (`STATUS_INVALID_IMAGE_HASH`) unless test-signing / enforcement-disable is used or the file is catalog-signed (not determinable from the `.sys` alone). It should therefore be treated as a BYOVD-class artifact: the primitive is admin-only, but the image is unsigned.
- Residual risk is high **if** the effective SDDL is changed to one of the `WD` variants (source-level regression, binary patch, or a sibling build): the IOCTL set then yields arbitrary PCI config writes (→ BAR remap → arbitrary physical memory), fixed MSR writes, and the `0x9C402648` device-extension pointer swap — i.e., a straightforward admin-to-kernel / unprivileged-to-kernel escalation chain.

**Rating (this binary, as shipped):** not an unprivileged local privilege-escalation primitive. It is a highly privileged, administrator-only hardware-access driver with an unnecessarily dangerous IOCTL surface, and it is unsigned.

---

## 7. Limitations

1. **Static analysis only.** No driver was loaded, no IOCTL was issued, no VM or kernel debugger was used. All conclusions about DACL enforcement follow from the documented semantics of `IoCreateDeviceSecure` + `FILE_DEVICE_SECURE_OPEN`, not from runtime observation.
2. **File relocation during analysis.** The originally assigned path (`...\_collected5\agentR4\new\...`) was deleted by another process mid-audit. Analysis continued on a byte-identical copy at `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\CoreTemp_ALSysIO64Legacy_x64_A0484FDC.sys`; SHA-256 was re-verified as identical before continuing. All addresses and evidence IDs refer to the same image.
3. **Ghidra decompiler output.** Pseudocode is Ghidra 12.1.4's representation; type recovery is incomplete (no PDB symbols were applied). Function boundaries and local names are inferred. Conclusions rest on the cited instruction-level addresses where they matter (`0x11061`, `0x11072`, `0x11097`, `0x13052`, `0x130D2`, `0x14048`, `0x16800`).
4. **SDDL parser not reversed.** The kernel's `IoCreateDeviceSecure` implementation is outside the image; only the input string and the call arguments were verified. The wdmsec fallback path (`0x21330` / `0x21284`) was not fully decompiled because it is unreachable on any OS that exports `IoCreateDeviceSecure`.
5. **Signature status.** Only the absence of an *embedded* signature is established (PE security directory size 0). Catalog signing, WHQL/attestation status, and revocation state cannot be determined from the `.sys` alone.
6. **MSR whitelist semantics.** The per-entry write-permission halfword is at source-entry offset `+6`; all three embedded tables read `0` there, so the generic `WriteMSR` IOCTL appears to deny all MSRs. This was inferred from `0x11A80` and `0x173B0`, not exercised.
7. **Vendor-dependent paths.** Several handlers behave differently on AMD vs Intel (`DAT_1F3D0`); only the static branches were inspected. Behaviour on a specific machine depends on the CPU vendor and firmware-provided ACPI/MCHBAR data.
