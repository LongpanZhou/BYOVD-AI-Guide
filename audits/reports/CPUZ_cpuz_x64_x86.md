# Audit: CPU-Z `cpuz_x64` (`68428A60`) and `cpuz_x86` (`D87DE694`) — collected5

| Field | Value |
|---|---|
| File(s) | `drivers/CPUZ_cpuz_x64_68428A60.sys` (32,768 bytes)<br>`drivers/CPUZ_cpuz_x86_D87DE694.sys` (31,488 bytes) |
| SHA-256(s) | `68428A604DB6E9CD08A1FEAF9A04542AEF0AFCA0315E590520168A44DE35B011`<br>`D87DE6941275D8980CFDEB4B432D11EE271AA885FC44AF87860C92E941B5BE86` |
| Analysis date | 2026-10-24 |
| Method | Static-only. Ghidra 12.1.4 headless decompile (`%TEMP%\opencode\cpuz5\dumps\cpuz64.txt`, 4,716 lines; `cpuz86.txt`, 4,803 lines; complete, 27 / 34 functions), read-only PE parsing, and Authenticode/PE security-directory inspection. Nothing loaded, installed, executed, or written to the registry. No web access. |
| Reach tier | **R2 — local administrator** (`IRP_MJ_CREATE` requires `SeSinglePrivilegeCheck` on LUID 10 = `SeLoadDriverPrivilege`) |
| Setup required | **service** (legacy kernel service; no devnode, hardware, or composition). Rates as `none` for an administrator per `SEVERITY.md`. |
| Write quality | **W2** — arbitrary 64-bit destination, value constrained to SMBus controller data (`0x9C4026A8`). Secondary W3P arbitrary physical write (`0x9C402594`). |
| Verdict | **BLOCKED (static MW2)** — both files. As-shipped bytes are unsigned: the embedded certificate table was removed (Security Directory points exactly at EOF). Static primitive is MW2 / W2. |

> Static-only audit. This report records gates and primitives. It contains no test code and no operating steps. Nothing was loaded or run.

## 0. Relationship to the already-audited collected1 CPU-Z builds

These are **different binaries**, not the same driver re-signed. Verified by hash, section, string, import and behavioural comparison:

x86 pair, same conclusion:

|---|---|---|---|
| Device name | `\Device\cpuz165` | not listed here | not listed here |
| `.text` raw size / SHA-256 | `0x6480` / `4C2D944B…B9DEF1A` | `0x5180` / `7F25E80A…6F0D9086` | `0x6C80` / `28A83D11…8B0C512` |
| Import count | 23 | 33 | 33 |

The collected5 builds are a **leaner, later CPU-Z generation** with a rearranged IOCTL surface. The collected1 reports are not transferable: the old `0x9C402540` caller-destination copy has been replaced by a bounded physical read, and the caller-pointer write now lives in `0x9C4026A8` with a different value source. The verdict below is derived independently.

## 1. Internals

| | x64 | x86 |
|---|---|---|
| PE | PE32+, image base `0x10000`, `SizeOfImage 0xD000`, 6 sections | PE32, image base `0x10000`, `SizeOfImage 0x7B00`, 6 sections |
| Entry point | `0x1B064` → `FUN_0001B008` (cookie init) → `FUN_00011B00` (DriverEntry body) | `0x170BE` → `FUN_00017085` → `FUN_000162D0` |
| Version resource | CPUID / `6.1.7600.16385` "built by: WinDDK" / "CPUID Driver" | same |
| Imports | `ntoskrnl`: `IoCreateDevice`, `IoCreateSymbolicLink`, `IoDeleteDevice`, `IoDeleteSymbolicLink`, `IofCompleteRequest`, `KeBugCheckEx`, `MmMapIoSpace`, `MmUnmapIoSpace`, `PsGetVersion`, `RtlInitUnicodeString`, `RtlUnwindEx`, `SeSinglePrivilegeCheck`; `HAL`: `HalGetBusDataByOffset`, `HalSetBusDataByOffset`, `KeQueryPerformanceCounter`, `KeStallExecutionProcessor` | `ntoskrnl`: same set plus `KeTickCount`, `RtlUnwind`; `HAL`: same plus `READ_PORT_UCHAR/USHORT/ULONG`, `WRITE_PORT_UCHAR/USHORT/ULONG` |
| Not present | `IoCreateDeviceSecure`, `IoSetSecurityInfo`, `MmMapLockedPagesSpecifyCache`, `MmGetPhysicalAddress`, `MmCopyMemory`, `ZwMapViewOfSection`, `\Device\PhysicalMemory`, `ProbeForWrite`, pool APIs | same |

The absence of `MmGetPhysicalAddress`, `MmMapLockedPagesSpecifyCache`, `ProbeForWrite` and the pool/IRP-builder imports is itself a structural difference from the collected1 images. There is **no probe/capture of any caller-supplied pointer** anywhere in either image.

## 2. Entry / device / interface / effective DACL

**Device creation (x64 `FUN_00011B00`, lines 1252–1296; x86 `FUN_000162D0`, lines 4331–4384):**

- `IoCreateDevice(DriverObject, 4, &"\Device\cpuz165", 0x9C40, 0, TRUE)` — x64 at line 1268, call site `0x11C2D`; x86 at line 4355, call site `0x1634F`.
  - Device type `0x9C40` (40000). Extension size 4.
  - `Exclusive = TRUE` (arg 6 pushed as `1` on both; x64 `movb $0x1, 0x28(%rsp)`). One handle at a time.
  - The 7th push on both (`&local_c0` / `&local_8c`) is an extra argument to a 6-parameter import; it is never written by `IoCreateDevice`, so `local_c0` always reads 0. Consequence: **if `IoCreateSymbolicLink` fails, the device object is leaked** (the cleanup branch is dead). Not a memory-write issue.
- Symlink: `PsGetVersion` is used to choose `\DosDevices\Global\CPUZ165` (NT major ≥ 5) instead of `\DosDevices\CPUZ165`; `IoCreateSymbolicLink` at x64 line 1276 / x86 line 4363.
- No `IoRegisterDeviceInterface`; no GUID interface. DOS symlink only.

**Effective DACL/SDDL:**

- **No security descriptor is supplied.** There is no `IoCreateDeviceSecure` import, no `IoSetSecurityInfo`, and no SDDL literal anywhere in either image. A byte scan for `D:P(`, `D:(A;`, `D:PAI`, `SDDL` over both ASCII and UTF-16 returns nothing. The dump's "SDDL / DEVICE STRING XREFS" section finds only the three device/symlink names.
- The device object's `SecurityDescriptor` therefore remains `NULL`; the effective DACL is the I/O-manager default for a device object created by the service loader (SYSTEM context), with **no driver-contributed ACE**. It is not widened by the driver and does not add a restriction beyond the explicit open-time privilege check.
- **The binding gate is the CREATE handler**, not the DACL: `SeSinglePrivilegeCheck(LUID 10, PreviousMode = UserMode)`; failure sets `0xC0000022`. LUID 10 is `SeLoadDriverPrivilege` (`winnt.h`), which a standard user does not hold and an elevated administrator does. This is the same gate the two collected1 builds use.

**Dispatch installation:**

| DRIVER_OBJECT offset | IRP | Handler |
|---|---|---|
| x64 `+0x70` / x86 `+0x38` | `IRP_MJ_CREATE` | `FUN_00011D20` / `FUN_00010F10` |
| x64 `+0x80` / x86 `+0x40` | `IRP_MJ_CLOSE` | `FUN_00011D20` / `FUN_00010F10` |
| x64 `+0xE0` / x86 `+0x70` | `IRP_MJ_DEVICE_CONTROL` | `FUN_00011D20` / `FUN_00010F10` |
| x64 `+0x68` / x86 `+0x34` | `DriverUnload` | `FUN_00017290` / `FUN_00016200` |

No `IRP_MJ_READ`, `IRP_MJ_WRITE`, `IRP_MJ_INTERNAL_DEVICE_CONTROL`, `IRP_MJ_CLEANUP` or FastIo handler is installed; unset majors fall to `IopInvalidDeviceRequest`.

## 3. Dispatch and IOCTL table

- Dispatcher: x64 `FUN_00011D20 @ 0x11D20` (19,866 bytes); x86 `FUN_00010F10 @ 0x10F10` (16,952 bytes).
- Major-function switch reads `CurrentStackLocation->MajorFunction`: `0` = CREATE (privilege check, line 1430 / 1595), `2` = CLOSE (handle refcount), `0x0E` = DEVICE_CONTROL (IOCTL switch). Anything else completes with the IRP status untouched.
- IOCTL code: x64 `*(uint *)(CurrentStackLocation + 0x18)`, x86 `+0x0C`. Unknown codes return `0xC000000D` (`STATUS_INVALID_PARAMETER`).
- **Every** case is `METHOD_BUFFERED` (code & 3 == 0) with access bits `(code >> 14) & 3 == 0` (`FILE_ANY_ACCESS`), device type `0x9C40`. A few IOCTL codes repeat the LUID-10 check (`0x9C402540`, `0x9C40259C`, `0x9C4025A0`, `0x9C4024C0/C4/C8`, `0x9C402728`); all others rely on the open gate — including the write-what-where at `0x9C4026A8`.
- Length checks are against `OutputBufferLength` (x64 `+0x08`, x86 `+0x04`) and `InputBufferLength` (x64 `+0x10`, x86 `+0x08`). Table below gives the minimums; "out == n+4" means the driver requires `OutputBufferLength` to equal the caller count plus 4 exactly.

`in` = InputBufferLength minimum, `out` = OutputBufferLength minimum. All rows are METHOD_BUFFERED / FILE_ANY_ACCESS.

| IOCTL | in / out | Kernel action | Memory write? |
|---|---|---|---|
| `0x9C402400` | – / 4 | returns `0x165` | no |
| `0x9C402404` | – / 0xC | `PsGetVersion` → 3 dwords | no |
| `0x9C402408` | – / 4 | returns open-handle refcount | no |
| `0x9C402440` | 4 / 8 | `rdmsr(index)`, **denylist** (denies `0x174–0x176`, `0xC0000081–0xC0000083`) | no |
| `0x9C402444` | 0xC / 8 | `wrmsr(index,value)`, **allowlist only**: `0x8B`, `0x150`, `0x186–0x188`, `0x19A`, `0x19C`, `0x1B1`, `0x38D`, `0x38F`, `0x607–0x608`, `0xC0010000–0xC0010003`, `0xC0010015`, `0xC0010064`, `0xC0010200`, `0xC0010202/204/206/208/20A`, `0xC0010230`, `0xC0010232–0xC001024A` (even steps); all else `0xC0000022` | HW-ONLY |
| `0x9C402448` | 8 / 8 | `wrmsr(0x150, value)` fixed MSR, poll | HW-ONLY |
| `0x9C40244C` | 0x14 / 0xC | `MmMapIoSpace(cfg(BAR+0x5DA0), 0x10)`; write caller dword at +0 and +4 | HW-ONLY (device MMIO) |
| `0x9C402480` | 4 / 8 | port `in` byte | HW-ONLY |
| `0x9C402484` | 4 / 8 | port `in` word | HW-ONLY |
| `0x9C402488` | 4 / 8 | port `in` dword | HW-ONLY |
| `0x9C4024C0` | 8 / 8 | port `out` byte (privileged) | HW-ONLY |
| `0x9C4024C4` | 8 / 8 | port `out` word (privileged) | HW-ONLY |
| `0x9C4024C8` | 8 / 8 | port `out` dword (privileged) | HW-ONLY |
| `0x9C402500` | 0xC / 4 | port `out` then `in` | HW-ONLY |
| `0x9C402504` | 0x10 / 4 | two port `out`s | HW-ONLY |
| `0x9C402540` | 0xC / n+4 | **whitelisted physical read** into `SystemBuffer+4` (privileged) | no |
| `0x9C402544` | 0x10 / 8 | cfg-derived base + caller offset → physical read 8 | no |
| `0x9C402548` | 8 / 4 | cfg `0xF0` base + offset (<0x8000) → physical read 4 | no |
| `0x9C40254C` | 0xC / 4 | cfg `0xF0` base + offset (<0x8000) → **physical write 4** | HW-ONLY (device MMIO) |
| `0x9C402550` | 0xC / 8 | cache an `MmMapIoSpace` mapping (32-entry table) | state only |
| `0x9C402554` | 0xC / 8 | unmap cached mapping | no |
| `0x9C402560` | 0x14 / 4 | cfg-derived base + offset (<0x90000) → **physical write 4** | HW-ONLY (device MMIO) |
| `0x9C402564` | 8 / 8 | cfg `0xD0/0xD4` base + offset (<0x2FF000) → physical read 8 | no |
| `0x9C402568` | 0xC / 4 | cfg `0xD0/0xD4` base + offset (<0x2FF000) → **physical write 4** | HW-ONLY (device MMIO) |
| `0x9C402584` | 0xC / 4 | cfg read-modify-write at `0x60/0xB8/0xC4`, restore | HW-ONLY |
| `0x9C402588` | 0x10 / 4 | cfg **write** two dwords at `0x60/0xB8/0xC4` | HW-ONLY |
| `0x9C40258C` | 0x44 / 0x1C | CPU ratio via repeated cfg writes (`FUN_00011470`) | HW-ONLY |
| `0x9C402594` | 0x20 / 8 | `MmMapIoSpace(cfgbase + 4*idx, 0x40)`; **three unchecked dword-index writes** | **YES — §5.2 (W3P)** |
| `0x9C402598` | 4 / 0x20 | cfg base + 0x3000 → **fixed `0x1E520` write** + poll | fixed MMIO |
| `0x9C40259C` | 0x4C / n+4 | physical read from cfg-derived base → `SystemBuffer+4` (privileged) | no |
| `0x9C4025A0` | 0x28 / n+4 | cfg/phys read + two `FUN_000116C0` calls with `param_8 = 0` (privileged) | **YES — §5.2 (W3P)** |
| `0x9C4025D4` | 0x10 / 8 | cfg read of a BAR | no |
| `0x9C402600` | 8 / 8 | `rdmsr` + port `in` (FSB timing) | HW-ONLY |
| `0x9C402604` | 8 / 8 | map caller PA, 0x200; read `+0xF0/+0xF4`; `rdmsr` timing | no |
| `0x9C402608` | 4 / 8 | `rdmsr` timing | no |
| **`0x9C402640`** | 8 / 0x10 | `MmMapIoSpace(input_PA + 0x300, 0x100)`; **fixed writes** +0x20 (clear bit 17), +0xE0 (=2), +0x80 (=0xFFFFFFFF); poll `+0x90`; restore | **YES — §5.3 (transient)** |
| **`0x9C402644`** | 4 / 0x10 | same as `0x9C402640` with `KeQueryPerformanceCounter` | **YES — §5.3 (transient)** |
| `0x9C402648` | 4 / 0x10 | `wrmsr` `0x832/0x83E/0x838` + port timing | HW-ONLY |
| `0x9C40264C` | – / 0x10 | `wrmsr` `0x832/0x83E/0x838` + QPC | HW-ONLY |
| `0x9C402680` | 0x10 / 0x10 | port transaction (SMbus-style) | HW-ONLY |
| `0x9C402684` | 0x14 / 0x10 | cfg **write** two dwords via `HalSetBusDataByOffset` | HW-ONLY |
| `0x9C402688` | 0xC / 0x10 | port transaction | HW-ONLY |
| `0x9C40268C` | 0x1C / 0x10 | cfg **write** + read | HW-ONLY |
| `0x9C402690` | 0x14 / 8 | port transaction | HW-ONLY |
| `0x9C402694` | 0xC / 0x10 | fixed MMIO `0xFED80A00` writes | HW-ONLY |
| `0x9C402698` | 0x10 / 8 | fixed MMIO `0xFED80A00` writes | HW-ONLY |
| `0x9C40269C` | 0x18 / 0x10 | port transaction | HW-ONLY |
| **`0x9C4026A8`** | 0x20 / 8 | SMBus MMIO `0xFEDC2000+off` (off ≤ 0x9000); **byte store to a caller-supplied absolute pointer** (and byte read from a caller-supplied source) | **YES — §5.4 (write-what-where)** |
| `0x9C4026C0` | 0x10 / 0x10 | `out(0xB2)` | HW-ONLY |
| `0x9C402700` | 0x14 / – | cfg read → `SystemBuffer` | no |
| `0x9C402720` | 0x10 / 8 | cfg read 4 | no |
| `0x9C402728` | 8 / 0x14 | SMBus transaction, **privileged**, PCI device-ID whitelist | HW-ONLY |
| `0x9C402740` | 0x10 / 4 | SuperIO `out(0x2E/0x4E)` | HW-ONLY |

Output-length safety: the variable-length physical-read cases require `OutputBufferLength == count + 4` and copy exactly `count` bytes to `SystemBuffer+4`, where the I/O manager sized the buffer to `max(InputBufferLength, OutputBufferLength)`. The copy therefore fits. The fixed-size cases return no more than their checked output minimum. **No output-buffer overflow was found.** One non-write defect is recorded in §9.

## 4. Access-control audit

| Gate | Where | Who can satisfy |
|---|---|---|
| DACL | none set by driver (§2) | I/O-manager default; no standard-user grant, no admin block |
| `SeSinglePrivilegeCheck(LUID 10, UserMode)` | `IRP_MJ_CREATE`, x64 line 1430 / x86 line 1595 | elevated administrator with `SeLoadDriverPrivilege` enabled |
| Repeat LUID-10 check | `0x9C402540`, `0x9C40259C`, `0x9C4025A0`, `0x9C4024C0/C4/C8`, `0x9C402728` | same |
| `FILE_WRITE_ACCESS` / `RequestorMode` | **not checked anywhere** | n/a (buffered I/O) |
| Per-IOCTL access mask | all `FILE_ANY_ACCESS` | any handle |
| Pointer probe/capture | **absent** | — |

Consequence: a standard user is stopped at open (`0xC0000022`). An elevated administrator opens once and then reaches every IOCTL, including the write-what-where `0x9C4026A8` (`in` ≥ 0x20), which has **no** additional privilege check.

## 5. Memory-write trace

### 5.1 `0x9C402540` — the collected1 primitive is gone

x64 lines 1857–1924; x86 3113–3180. Input is 12 bytes: physical address (`in[0..7]`), byte count (`in[8..11]`). `OutputBufferLength` must equal `count + 4`.

- The physical address is checked against a **fixed whitelist**: `0xFEC70`, `0xFED80E40`, `0xFED80000–0xFED81000`, `0xC0000–0x1C0000`, `0xE0000–0x1E0000`, `0xF0000–0x200000`, `0xFFC00000–0xFFC80000` (no length cap on this one), and `0xFE000000–0xFE00FFFF`; counts are capped at 0x10 except the low-memory windows (0x10000).
- On success the driver maps only that range and copies bytes **into `Irp->AssociatedIrp.SystemBuffer + 4`**, then writes `SystemBuffer[0] = bytes copied`. The destination is not a caller pointer, and there is no caller-chosen destination field.
- **This is a read, not a write.** The collected1 behaviour (physical read copied to a caller-chosen kernel address) does not exist at this IOCTL.

### 5.2 `0x9C402594` / `0x9C4025A0` — arbitrary physical write + unmapped-base kernel-VA OOB write

Helper x64 `FUN_000116C0 @ 0x116C0` (lines 1031–1105); x86 `FUN_00010B50 @ 0x10B50` (lines 1236–1310).

```
base = HalGetBusDataByOffset(BDF, config_offset, 4) & 0xFFFFFFF0
map  = MmMapIoSpace(base + param_3 * 4, 0x40, MmNonCached)
*(u32 *)(map + param_6 * 4) = 0
if (param_8) *(u32 *)(map + param_5 * 4) = param_8
*(u32 *)(map + param_4 * 4) = param_7
```

- `param_3`, `param_4`, `param_5`, `param_6`, `param_7`, `param_8` all come straight from the 0x20-byte input buffer (offsets `0x08`, `0x0C`, `0x10`, `0x14`, `0x1C`, `0x18`). **No bound check on any index.**
- `param_3` selects the physical dword offset; `base + 4*param_3` wraps mod 2³², so any 32-bit physical address is reachable.
- `param_4/5/6` select a dword offset **relative to the mapped VA**. For indices `< 0x400` the write stays inside the mapped 4 KB page, i.e. a well-defined **physical dword write of an arbitrary value at an arbitrary physical address** (`base + 4*param_3 + 4*param_4`).
- For indices `>= 0x400` the store leaves the mapping and writes into adjacent system VA. The mapping base is chosen by the memory manager and is **not returned to the caller**, so this variant is a kernel-VA OOB write with an uncontrolled base — arbitrary value and arbitrary offset, but no target selection and no leak. Secondary W2-class primitive; it does not exceed the `0x9C4026A8` finding.
- `0x9C402594` passes all six fields; `0x9C4025A0` makes the same call twice with `param_8 = 0` and caller-controlled indices.
- x86 is semantically identical (`FUN_00010B50` lines 1255–1276), with 32-bit pointer arithmetic.

### 5.3 `0x9C402640` / `0x9C402644` — fixed-value write at a caller-chosen physical page

x64 lines 2691–2759 and 2762–2819; x86 1665–1740 and 1742–1804.

```
pa   = input_dword + 0x300                // caller-controlled, 32-bit
                                           // 0x9C402640: dword at +4 (dword +0 is the I/O port)
                                           // 0x9C402644: dword at +0
map  = MmMapIoSpace(pa, 0x100, MmNonCached)
save = map[0x20], map[0xE0], map[0x80]
map[0x20] &= 0xFFFDFFFF                   // clear bit 17
map[0xE0]  = 2
map[0x80]  = 0xFFFFFFFF
... poll map[0x90] / timing ...
map[0x20] = save[0]; map[0xE0] = save[1]; map[0x80] = save[2]
MmUnmapIoSpace(map, 0x100)
```

- Target: **arbitrary physical address** (full 32-bit range), fixed offsets `0x20/0x80/0xE0`, fixed values; the original values are restored afterwards.
- A transient physical RMW, not a persistent controlled write. It is a genuine physical write while the window is open (and would persist on a crash), but it cannot plant an arbitrary value.

### 5.4 `0x9C4026A8` — write-what-where through a caller-supplied pointer

x64 case lines 3450–3630 plus tail `LAB_00015F10` at 4398–4411; x86 2373–2534 (store at 2490). No privilege check beyond the open gate.

Input layout (0x20 bytes, x64 offsets):

| Offset | Field |
|---|---|
| `+0x00` | MMIO offset from `0xFEDC2000`; must be ≤ `0x9000` |
| `+0x04` | SMBus slave address (byte) |
| `+0x08` | "write length"; **set to 0 to select the read-back path** |
| `+0x0C` / `+0x10` | 64-bit **source pointer** (`high` / `low`) |
| `+0x14` | transfer length cap |
| `+0x18` / `+0x1C` | 64-bit **destination pointer** (`high` / `low`) |

Store site (x64 line 4408, x86 line 2490):

```
for (i = 0; i < count; i++)
    *(char *)(destination + i) = (char)smbus->data;   // puVar25[4]
```

- `destination` is `CONCAT44(input[+0x18], input[+0x1C])` on x64 (assigned once at line 3463, used nowhere else) and `input[+0x1C]` on x86. It is **never validated, probed, or range-checked**. This is a raw kernel-mode byte store to an absolute address chosen by the caller.
- `count` = `min(input[+0x14], (smbus->status >> 8 & 0xFF) + 1)`, i.e. 0–256 bytes (0 performs no store).
- The **value** is the SMBus controller data-register byte, not caller data. It is bounded but not freely chosen; a caller who can influence the addressed SMBus device could influence it, which is not proven here.
- The same IOCTL has a second branch (`input[+0x08] != 0`) that reads bytes from the **source pointer** and writes them to the SMBus controller: `*(byte *)(source + i)` (x64 line 3573/3576). That is an arbitrary kernel **read**, but the data goes to the SMBus controller and is not returned to the caller, so it is not an info leak; it is a kernel-address dereference that will fault on a bad address.
- Preconditions: `MmMapIoSpace(0xFEDC2000 + off, 0x200)` must succeed and the controller must complete the transaction. On systems without that Intel SMBus window the case returns an error before the store.
- `0x9C402728` is the closely related privileged SMBus path and does **not** accept a caller pointer.

### 5.5 Everything else

`0x9C40254C`, `0x9C402560`, `0x9C402568`, `0x9C402598`, `0x9C40244C` write through `MmMapIoSpace` into **device/MMIO windows derived from PCI configuration space** of a caller-selected bus/device/function, with caller offset and (for `0x54C/0x560/0x568`) caller value. They are `HW-ONLY` under `SEVERITY.md`: the window is a device BAR, not system RAM, and offsets are bounded (`<0x8000`, `<0x90000`, `<0x2FF000`). `0x9C402684/68C/588/584/58C` write PCI configuration space; `0x9C402694/698` write the fixed `0xFED80A00` SMBus window; the `0x9C4024xx`/`0x9C4026xx` port cases write I/O ports; `0x9C402444/448/648/64C` write MSRs from a narrow allowlist. None of these is a kernel virtual-address write.

Outside `0x9C4026A8` there is **no** store through a pointer taken from the request buffer: a full scan of the dispatcher's store sites shows only `SystemBuffer`, `param_2` (IRP status fields), `MmMapIoSpace` results, and the mapping-cache table. No pool copy, no MDL, no `MmCopyMemory`, no `\Device\PhysicalMemory`.

## 6. Most dangerous exposed capability

**Write-what-where to any 64-bit kernel address, up to 256 bytes, with SMBus controller data as the value** (`0x9C4026A8`). The destination comes straight from the request buffer (`+0x18/+0x1C` on x64, `+0x1C` on x86) and is dereferenced without a probe. Target control is absolute; value control is constrained to the hardware register content, so this is W2 rather than W1. It is reachable by any holder of the handle, with no additional privilege check, and requires only that the `0xFEDC2000` SMBus window maps and the transaction succeeds.

Second: arbitrary **physical** dword write with an arbitrary value (`0x9C402594`, and `0x9C4025A0` in the `param_8 = 0` form), via an unchecked `index * 4` on a 0x40-byte `MmMapIoSpace` mapping. Keeping the index inside the mapped page yields a clean `<physical address> = <value>` write across the 32-bit physical space.

Third: `0x9C402640/644` transient fixed-value physical writes at an arbitrary caller-chosen physical page (`+0x20` bit-17 clear, `+0xE0 = 2`, `+0x80 = 0xFFFFFFFF`), restored after the measurement.

## 7. Verdict

| File | SHA-256 | Reach | Setup | Write | Severity | Load |
|---|---|---|---|---|---|---|
| `CPUZ_cpuz_x64_68428A60.sys` | `68428A60…5B011` | R2 | service | W2 | **BLOCKED (static MW2)** | unsigned as-shipped |
| `CPUZ_cpuz_x86_D87DE694.sys` | `D87DE694…5BE86` | R2 | service | W2 | **BLOCKED (static MW2)** | unsigned as-shipped |

**Overall: BLOCKED (static MW2) — reach=R2 setup=service write=W2 load=unsigned.**

- The static primitive is a real kernel memory write: an arbitrary-destination byte store at `0x9C4026A8` with a hardware-constrained value, plus an arbitrary physical write at `0x9C402594`. Under the `SEVERITY.md` matrix (`R2` + `W2`) this is **MW2**.
- It is not MW1: the write value is not caller-chosen. It is not MW3: the `0x9C4026A8` target is a kernel virtual address, not a physical address.
- **Loadability blocks the verdict.** Both files are `NotSigned`. Their PE `Security Directory` (`RVA 0x8000 / 0x7B00`, size `0x28B0`) points **exactly at end-of-file**, and every section's raw data ends exactly at the same offset. The image proper is complete; only the PKCS#7 certificate blob (10,416 bytes) was removed. Windows code integrity will reject the audited bytes on a default x64 system. The vendor original may be signed, but the audited artifacts are not, and no catalog was supplied.
- The collected1 MW1 rating is **not** inherited here. These are different images (different device name, `.text`, imports), the old `0x9C402540` caller-destination copy is gone, and the surviving caller-pointer write is value-constrained.

## 8. x64 vs x86

Same source, two compilations:

- Identical device name `\Device\cpuz165`, symlinks, `0x9C40` device type, exclusive open.
- Identical gate: `SeSinglePrivilegeCheck(10, UserMode)` at CREATE.
- Identical 53-IOCTL set with the same codes, methods and length checks; identical MSR allowlist and denylist; identical SMBus/MMIO fixed addresses (`0xFED80A00`, `0xFEDC2000`, `0x2E/0x4E`, `0xB2`); identical unchecked-index physical write helper.
- **Identical write-what-where.** x64 dereferences the full 64-bit destination from `+0x18/+0x1C`; x86 uses the low dword at `+0x1C` (32-bit kernel addresses). Both store `smbus->data` with no probe. x64 can therefore target the full canonical address space; x86 is limited to 4 GB, which is the whole kernel address space on 32-bit Windows.
- Compiler-level differences only: x86 links `KeTickCount` and the HAL port helpers and uses SEH (`__except_handler4`); x64 uses inline port intrinsics and pdata/unwind. x64 builds the `0x9C402540` physical address from two dwords (`CONCAT44`); x86 uses a 32-bit pair.
- **No security-relevant divergence found between the two architectures.** Both are unsigned and both are W2.

## 9. Limitations and unresolved paths

1. **Signature.** The certificate table is absent, not merely invalid. `Get-AuthenticodeSignature` returns `NotSigned` for both. The original vendor signature chain cannot be reconstructed offline; the report treats the audited bytes as unsigned. If a signed original is located later, the loadability flag should be re-evaluated against the same `.text` hash, not against the file hash.
2. **Value control at `0x9C4026A8`.** The destination is fully controlled, the value is the SMBus data register. Whether the value can be influenced (by selecting a writable/attacker-influenced SMBus target) was not established; the finding is rated W2 on the conservative assumption that it cannot. If value control were proven, the rating would rise to W1/MW1.
3. **Platform dependence of `0x9C4026A8`.** The case needs `MmMapIoSpace(0xFEDC2000 + off, 0x200)` to succeed and the SMBus transaction to complete. On non-Intel or locked-down platforms it may fail before the store. This is a runtime condition, not a privilege gate; it does not change `Setup: service`.
4. **DACL.** The effective DACL is assigned by the object manager at device creation and is not present in the image; the report states what the driver does *not* set (no SD, no SDDL, no `IoCreateDeviceSecure`) and relies on the explicit LUID-10 gate. A dynamic `\\.\CPUZ165` security query would settle the exact SDDL but was out of scope (static only).
5. **`0x9C402594` base selection.** The physical base is a PCI config dword at a caller-chosen offset of a caller-chosen BDF. The report assumes a valid BDF whose config space yields a usable base (the driver returns error 4 on a zero base); `param_3` supplies the remaining physical range.
6. **OOB VA variant.** The `index >= 0x400` case was read from the decompiler only. Actual VA layout after `MmMapIoSpace` is not statically knowable, so the reliability of the kernel-VA OOB write is unresolved. It is not rated above the `0x9C4026A8` finding.
7. **Non-write defect (recorded, out of scope).** In `0x9C402540`/`0x9C40259C`/`0x9C4025A0`, if the physical address is **not** whitelisted (or the map fails), the driver still returns `Information = count + 4` without filling the tail of `SystemBuffer`. Because `OutputBufferLength` may exceed `InputBufferLength`, the un-filled tail is uninitialized pool memory and is copied back to the caller. That is an uninitialized-kernel-pool disclosure of up to `count` bytes — no memory write, so it does not affect the MW rating, but it is a real bug worth a separate note.
8. **Coverage.** All 27 x64 / 34 x86 functions were decompiled; all 53 dispatch cases were read; every store site in the dispatcher was enumerated mechanically to locate caller-pointer writes. Port/MSR/PCI-config bodies were checked at their call sites, not re-derived instruction by instruction.
9. Nothing was run. No dynamic confirmation of the whitelist, the LUID gate, the SMBus write, or the physical write was performed.
x64 comparison (trimmed): the two already-audited prior x64 builds (one CPUID-signed, one
Microsoft-attested) are **different binaries from this c5 build*** and were exported out of this
repo on 2026-10-25; per gate-keeping policy their hashes, device names, and IOCTL mapping are not
reproduced here. Deriving the c5 verdict independently requires only the c5 columns below.

| Property | CPUZ_cpuz_x64_68428A60 (this) |
|---|---|
| SHA-256 | 68428A60.5B011 |
| Device name | \Device\cpuz165 (not listed further) |
| .text raw size / SHA-256 |  x6800 / B5F91B58.700A16 |
| Import count | 16 |
| Pool / IRP-building imports | **absent** |
| Caller-pointer write |  x9C4026A8 - byte store, **SMBus data as value** |
|  x9C402540 in this build | **whitelisted physical read into SystemBuffer** (5.1) |

x86 pair, same conclusion: