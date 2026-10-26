# Audit: SteelSeries `ssdevfactory` ×5 + `xusb21` ×4

| Field | Value |
|---|---|
| File(s) | `drivers\ssdevfactory_3F76D97A.sys`, `_49E69A7F.sys`, `_63D7C6F1.sys`, `_A7F7DC6A.sys`, `_BB05D258.sys`; `drivers\xusb21_0AABCEB6.sys`, `_785DEFAE.sys`, `_9D614C5D.sys`, `_B7A7A906.sys` |
| SHA-256(s) | see §0.2 (all nine verified against the assigned files) |
| Analysis date | 2026-10-25 |
| Method | **Static only** — local Ghidra 12.1.4 headless (`DumpAll.java`: all functions decompiled + import/string cross-reference), `llvm-objdump` disassembly, raw PE/resource parsing, Authenticode status read locally. Nothing loaded, executed, installed, or written to the registry. **REA cross-check was not used: the four shared REA sessions are at capacity.** All findings below are Ghidra/objdump-only. |
| Reach tier | **R1** for the `ssdevfactory` child interfaces (Everyone-RWX SDDL); **R2–R3** for `xusb21` (no SDDL, PnP devnode, Xbox-360 controller required) |
| Setup required | **composition** (`ssdevfactory`, SteelSeries stack must be installed and bound) · **hardware** (`xusb21`) · **none** beyond installation for the i386 builds' static content |
| Write quality | **W2** (`ssdevfactory` x64) · **W0** (`xusb21` x64) · W2 latent for the i386 `ssdevfactory` builds (same code, not loadable) |
| Verdict | **MW2** — `ssdevfactory` x64 ×3; **BLOCKED** — `ssdevfactory` i386 ×2 and `xusb21` i386 ×2; **NO-MEMORY-WRITE** — `xusb21` x64 ×2 |

Canonical form: `MW2 — reach=R1 setup=composition write=W2 load=signed` for `ssdevfactory` x64.
`NO-MEMORY-WRITE — reach=R3 setup=hardware write=W0 load=signed` for `xusb21` x64.

---

## 0. Scope, hashes, per-file result

### 0.1 Why this is a re-audit

Both families were previously dismissed as `NO-WRITE`/`NEEDS-DYNAMIC` under the old
unprivileged-only scope (`steelseries_hid.static.md`, `steelseries_hid_miniport.static.md`).
Those verdicts are not inherited. `ssdevfactory` was explicitly left as *NEEDS-DYNAMIC* on the
`0x220003` `METHOD_NEITHER` branch; that branch is the core of this report and is now resolved
statically as far as the binary allows (§5.2, §9.1). `xusb21` was never enumerated — only
"hardware-gated" — and is enumerated in §3.3.

### 0.2 Per-file table

| File | Arch | Version / link date | SHA-256 | Signer | Open gate | Verdict |
|---|---|---|---|---|---|---|
| `ssdevfactory_63D7C6F1.sys` | x64 | 1.3.3.0 / 2025-10-06 | `63D7C6F16CB3BB4C71848627D7D0C418E1AC53915418C55ABD05850C9F993B0E` | Microsoft Windows Hardware Compatibility Publisher | Everyone-RWX interface `{BEA3CED6-38EC-45B0-9DB6-557CC54D7021}` | **MW2** (W2) |
| `ssdevfactory_49E69A7F.sys` | x64 | 1.2.0.0 / 2020-09-15 | `49E69A7F24C38810CE375D83A0589F0F3BDCF6D97324F525C46DA7DA5D787BEC` | SteelSeries ApS | same SDDL / interface | **MW2** (W2) |
| `ssdevfactory_BB05D258.sys` | x64 | 1.1.4.1 / 2017-05-08 | `BB05D2585D589A7351C34424CBF0C3EE6AAF00605A8CC53943DF63DBE94D5198` | SteelSeries ApS | same SDDL / interface | **MW2** (W2) |
| `ssdevfactory_3F76D97A.sys` | **i386** | 1.2.0.0 / 2020-09-15 | `3F76D97AE2173A70CBEF2928EB091432E3F2EDFCD6D0E44E30C299667C83C737` | SteelSeries ApS | same SDDL (static) | **BLOCKED** (i386) |
| `ssdevfactory_A7F7DC6A.sys` | **i386** | 1.1.4.1 / 2017-05-08 | `A7F7DC6AC8916EC2F70AAED08EA3F2343D57906821CA977F20FFBB51D141C123` | SteelSeries ApS | same SDDL (static) | **BLOCKED** (i386) |
| `xusb21_0AABCEB6.sys` | x64 | 9.18.1034.0 / 2009-08-13 | `0AABCEB627E274E338DDD9BA664BAA128D7C00AF04C95C776C2AFFA6BB17F680` | Microsoft (MOPR) | PnP devnode, default DACL (SYSTEM/admin) | **NO-MEMORY-WRITE** (W0) |
| `xusb21_B7A7A906.sys` | x64 | 9.18.1015.0 / 2009-04-08 | `B7A7A906A7BB0F760ED241F998C647D728C4DB5D8778AFE585DF38331165803F` | Microsoft (MOPR) | PnP devnode, default DACL (SYSTEM/admin) | **NO-MEMORY-WRITE** (W0) |
| `xusb21_9D614C5D.sys` | **i386** | 9.18.1034.0 / 2009-08-13 | `9D614C5D3BB679CCF15CA6DD044318692EA6D89B89D80D690E79A1C0B941430F` | Microsoft (MOPR) | — | **BLOCKED** (i386) |
| `xusb21_785DEFAE.sys` | **i386** | 9.18.1015.0 / 2009-04-08 | `785DEFAE550CAB5BDFA15CF195A1DEF5AD188EFEAD2D8B1508972CF892BB75A9` | Microsoft (MOPR) | — | **BLOCKED** (i386) |

Notes on the table:

* The historical baseline (`steelseries_hid_miniport.static.md`) recorded `xusb21_785DEFAE` and
  `9D614C5D` as "other builds" without an architecture. They are **PE32/i386**
  (`Machine=0x014C`, entry `0x0000A334` / `0x0000AD2A`), not x64. `0AABCEB6` and `B7A7A906` are
  PE32+/AMD64.
* `ssdevfactory_3F76D97A` (2020) and `A7F7DC6A` (2017) are also PE32/i386; the 2020 x86 build is
  the same source generation as the 2020 x64 build, and the 2017 x86 build the same as 2017 x64.
* All nine Authenticode signatures are **Valid** (local `Get-AuthenticodeSignature`), and none of
  the nine SHA-256 values is in `indexes\dedupe\known_bad_hashes.txt` (checked). The four i386
  images are `BLOCKED` on architecture only, not on reputation.

---

## 1. Internals

Both families are **KMDF** drivers (import `WdfVersionBind`/`WdfVersionBindClass` from
`WDFLDR.SYS`); almost all kernel services are reached through the per-driver WDF function table,
so the import table is nearly empty and every interesting call is an indirect
`call [WdfFunctions+offset]` / `call guard_dispatch_icall`. Function-table offsets were resolved
against the local `Wdf01000.pdb` (`_WDFFUNCTIONS` member offsets), which makes the dispatch
readable; the resolutions used are:

| Table offset | Function | Evidence |
|---|---|---|
| `+0x220` | `WdfDeviceInitAssignSDDLString` | `ssdevfactory_63D7C6F1` @`0x140002549`, `0x140003ab6`, `0x140004455` |
| `+0x258` | `WdfDeviceCreate` | @`0x14000285e`, `0x140003dd4` |
| `+0x268` | `WdfDeviceCreateDeviceInterface` | @`0x14000298d`, `0x140003eea`, `0x14000b260` |
| `+0x4c0` | `WdfIoQueueCreate` | @`0x1400029ed`, `0x140002a3f`, `0x140002aa0` |
| `+0x4e8` | `WdfIoQueueGetDevice` | @`0x140001bed` |
| `+0x4f0` | `WdfIoQueueRetrieveNextRequest` | @`0x140001cea` |
| `+0x650` | `WdfObjectGetTypedContextWorker` | @`0x140001c15` |
| `+0x838` | `WdfRequestComplete` | @`0x140001f71` |
| `+0x848` | `WdfRequestCompleteWithInformation` | @`0x140001d82` |
| `+0x850` | `WdfRequestGetParameters` | @`0x140001c5b` |
| `+0x868` | `WdfRequestRetrieveInputBuffer` | @`0x140001cc4` |
| `+0xC58` | `WdfRequestForwardToParentDeviceIoQueue` | `ssdevfactory_63D7C6F1` `FUN_1400023e8` |

`ssdevfactory` additionally imports only `RtlCopyUnicodeString`,
`RtlIntegerToUnicodeString`, `RtlCompareMemory`, `RtlGetVersion`, `DbgPrintEx`,
`IofCompleteRequest`, `_vsnwprintf`, `KeQueryPerformanceCounter` and
`IoRegisterPlugPlayNotification`/`IoUnregisterPlugPlayNotification`. **There is no
`MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `MmGetPhysicalAddress`,
`ZwMapViewOfSection`, `ZwCreateFile`, `ProbeForRead`, `ProbeForWrite`, `memcpy`, `memset`,
`KeStackAttachProcess`, `WRMSR`, or PCI/SMBus HAL call in any x64 build.** The two i386
`ssdevfactory` builds add `memcpy`/`memset`/`_allmul`/`_alldiv` and `READ_PORT_ULONG`/
`WRITE_PORT_ULONG` (§6.2).

`xusb21` imports only `ExAllocatePoolWithTag`, `ExAllocatePoolWithQuotaTag`,
`ExFreePool(WithTag)`, `RtlCopyUnicodeString`, `RtlCompareMemory`, `RtlInitUnicodeString`,
`PoSetSystemState`, `KeBugCheckEx`, `_purecall`, `_vsnwprintf`, `memcpy`/`memset`
(x86 builds), `BCrypt*` (x64 `0AABCEB6`/`9D614C5D` only) and the WDFLDR bindings. **No memory
mapping, no port I/O, no PCI config, no MSR, no DMA, no `\Device\PhysicalMemory`.**

---

## 2. Entry / device / interface / effective DACL

### 2.1 `ssdevfactory` — Everyone-RWX, live in all five builds

The driver is a PnP function driver that creates **virtual child devices**
("SteelSeries Keyboard", "SteelSeries MB Lighting Interface", XInput controller). Each
`WdfDeviceInitAllocate` result is given the same SDDL before `WdfDeviceCreate`:

```
UNICODE_STRING @ 0x140007640 (63D7C6F1):  Length=0x7E  MaximumLength=0x80  Buffer=0x140007650
"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)"
```

Call sites in `ssdevfactory_63D7C6F1` (three, one per device class):

```
140002536  lea r8,[0x140007640]     ; &SDDL
140002549  mov rax,[rax+0x220]      ; WdfDeviceInitAssignSDDLString
...
14000285e  mov rax,[rax+0x258]      ; WdfDeviceCreate
14000298d  mov rax,[rax+0x268]      ; WdfDeviceCreateDeviceInterface
14000297f  lea r8,[0x140007190]     ; &GUID {BEA3CED6-38EC-45B0-9DB6-557CC54D7021}
```

equivalent sites at `0x140003aa3` / `0x140003dd4` / `0x140003eea` and
`0x140004455` / `0x14000b260`. The same `Everyone`-RWX literal is present as a UNICODE_STRING
and referenced from a `WdfDeviceInitAssignSDDLString` slot in all five binaries, including the
two i386 builds.

Effective DACL: **protected** (`P`), owner `SYSTEM` full, `BUILTIN\Administrators` RWX,
**`Everyone` (WD) RWX**, `RESTRICTED` RWX. No `\DosDevices\`/`\??\` name string exists in any of
the five binaries and no `WdfDeviceCreateSymbolicLink` (`+0x280`) slot is loaded in the three x64
builds, so the exposure is the **device interface**
`{BEA3CED6-38EC-45B0-9DB6-557CC54D7021}` (`WdfDeviceCreateDeviceInterface`), enumerable and
openable by any user through `CM_Get_DeviceInterfaceList` → `CreateFile`; the interface open is
authorised by the device DACL above, i.e. **Everyone**.

`Setup required` is therefore **composition**: the SteelSeries stack must be installed and the
parent devnode bound so the factory runs and publishes the children. Once it is, no extra
privilege and no hardware poke is needed to open the child interface.

### 2.2 `xusb21` — no SDDL, no interface, no symlink

`xusb21` is Microsoft's XUSB 2.1 bus driver (`e:\xusb\main\private\drivers\xusb\…` source paths
in all four builds). It creates **no** `IoCreateDevice`/`IoCreateSymbolicLink` (no such imports),
applies **no** SDDL (the byte patterns `D:P(` in ASCII and UTF-16 are absent from all four
images), contains no `\Device\` or `\DosDevices\` string, and registers **no** device interface:
no interface GUID constant exists and the `WdfDeviceCreateDeviceInterface` / `WdfDeviceCreateSymbolicLink`
table slots are never referenced in either x64 build (no `+0x268`/`+0x280` slot load). Its only
naming is the hardware-ID text used for child PDOs
(`XUSB\TYPE_%02X\SUB_%02X\VEN_%02X%02X\REV_%02X%02X`, `XUSB\Audio\Type_%02X`).

Consequently the FDO/PDOs carry the KMDF/PnP **default** device security (SYSTEM +
Administrators, no Everyone ACE) and are reachable only through the devnode's device-instance
path, which exists only when the XUSB controller/controller-child hardware enumerates. This is
`R2`/`R3`, `setup=hardware`, and no hardware-only MMIO/port path exists to chain from.

---

## 3. Dispatch and IOCTL table

### 3.1 `ssdevfactory` (identical code set in all five builds)

| IOCTL | Decode (DeviceType, Function, Method, Access) | Input | Action |
|---|---|---|---|
| `0x220003` | `0x22, 0x800, METHOD_NEITHER, ANY` | caller block (see §5.2) | three instances — keyboard queue `FUN_140001ba0@0x140001ba0`, MB-lighting queue `FUN_140002ef0@0x140002ef0`, third child `FUN_140004cb0@0x140004cb0`. Copies a fixed HID report-descriptor template into the caller block; selector 0/9/0xB/0x1B/0x28 |
| `0x220013` | `0x22, 0x804, METHOD_NEITHER, ANY` | same block | writes `dword 3` at `+0x00`, `word 0` at `+0x02` of the block |
| `0x2A0000` | `0x2A, 0x000, METHOD_BUFFERED, ANY` | 6 B | copies 6 B into a local 0x10-byte LED struct, sends to HID target (`FUN_1400013b4`) |
| `0x2A0004` | `0x2A, 0x001, METHOD_BUFFERED, ANY` | 6 B | same, variant (`FUN_140001590`) |
| `0x2A0008` | `0x2A, 0x002, METHOD_BUFFERED, ANY` | 4 B, `in[0]==7` | `in[1]`/`in[2]` select LED sub-command; retrieves a pending report request from a queue and copies ≤0x20 B into its buffer (`FUN_140001d8d` region) |
| `0x2A000C` | `0x2A, 0x003, METHOD_BUFFERED, ANY` | 4 B | returns a 4-byte version (`FUN_140001764`) |
| `0x2A0010` | `0x2A, 0x004, METHOD_BUFFERED, ANY` | **0x41 B exactly** | copies ≤0x41 B to a pending report buffer |
| `0x2A0014` | `0x2A, 0x005, METHOD_BUFFERED, ANY` | 8 B | 8-byte LED struct (`FUN_1400014ac`) |
| `0x2A0018` | `0x2A, 0x006, METHOD_BUFFERED, ANY` | 8 B | 8-byte LED struct (`FUN_140001684`) |
| `0x2A0028` | `0x2A, 0x00A, METHOD_BUFFERED, ANY` | — | forwarded internally (`WdfRequestForwardToParentDeviceIoQueue`, `+0xC58`) |
| `0x2A0440`/`0x2A0444`/`0x2A0448` | `0x2A, 0x110/0x111/0x112, METHOD_BUFFERED, ANY` | 8/8/0x1C B | child-device configuration (`FUN_1400017c8`, `FUN_1400018ac`, `FUN_14000198c`); no caller pointer |

Only `0x220003` and `0x220013` are `METHOD_NEITHER`; everything else is `METHOD_BUFFERED` with a
hard input-length check before `WdfRequestRetrieveInputBuffer`, so the I/O manager's system
buffer copy bounds those paths.

`0x2A0448` (`FUN_14000198c`) additionally walks the FDO's default child list
(`WdfFdoGetDefaultChildList`, table `+0x420`) and hands the child-list request to
`FUN_140004fc8`; that function performs a
`memcpy(dst = *(params+0x28), src = local, len = min(0x14, *(params+0x24)))` — the same
descriptor-shape copy discussed in §5.3, length-clamped.

### 3.2 `ssdevfactory` queues

Three `WdfIoQueueCreate` calls per device set (`+0x4C0` at `0x1400029ed`, `0x140002a3f`,
`0x140002aa0`), each with an `EvtIoDeviceControl`. The handler signature is the 5-argument
`(Queue, Request, OutputBufferLength, InputBufferLength, IoControlCode)` form — confirmed by the
prologue reading the 5th argument from `[rsp+0x28]` (`movl 0x7f(%rbp),%ecx` @`0x140001c61`
with `rbp = rsp+0x81`) and the 4th from `r9` (`movq %r9,%rbx` @`0x140001be1`).

### 3.3 `xusb21` (both x64 builds; identical code)

| Code | Method | Handler | Action |
|---|---|---|---|
| `0x220003` | **NEITHER** | `FUN_00015454@0x15454`, alternate `FUN_00013ec0@0x13ec0` | XUSB report-descriptor protocol (selectors `0`,`1`,`2`,`10`,`0xB`,`0x1B`,`0x1E`); templates copied into the request's descriptor buffer, **every copy gated on the descriptor length** (`0x12`, `0xC0`, `1`, `2`, …) |
| `0x220013` | **NEITHER** | `FUN_00013ec0@0x13ec0` | completes `STATUS_INVALID_DEVICE_REQUEST`, information `3` |
| `0x2F0003` | — | `FUN_00013ec0` region | device-level query on the queue's device |
| `0x80006000`, `0x8000A010`, `0x8000A01C`, `0x8000E004/8/C/14/18/20/3FC` | internal | `FUN_0001a684@0x1a684` | XUSB bus-interface/power packets; each writes a fixed `0x102`-tagged block after checking the caller-provided buffer length (`0xb < param_3[3]`) |

`0x220003`/`0x220013` decode as `0x22, 0x800/0x804, METHOD_NEITHER, FILE_ANY_ACCESS` — the
**same vendor code pair as `ssdevfactory`**, i.e. the SteelSeries package reused the XUSB
report-descriptor protocol. In
`xusb21` the descriptor object is reached from the request's own context
(`*(*(request+0xB8)+8)`), not from the `WDF_REQUEST_PARAMETERS` block, and each field access is
preceded by an explicit length test (`FUN_00016278`: `if (*(uint*)(d+0x24) < 0x12) return
STATUS_INVALID_PARAMETER;` before the 0x12-byte store; the 0xC0-byte template is clamped to
`min(0xC0, *(uint*)(d+0x24))`; `FUN_00017c24` requires `len == 1` or `len == 2`). No caller
pointer is dereferenced without a matching length check.

---

## 4. Access-control audit

* `ssdevfactory`: **no** `SeSinglePrivilegeCheck`, `SeAccessCheck`, `FILE_WRITE_ACCESS` gate, or
  caller-identity test anywhere. Authorisation is the device DACL only, and that DACL grants
  `Everyone` `GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE` (SDDL `A;;GRGWGX;;;WD`). Every IOCTL in
  §3.1 is `FILE_ANY_ACCESS`, so `CreateFile` with `GENERIC_READ` suffices for all of them.
  An administrator does not need to do anything extra; an ordinary user can open the same
  interface. This is the R1 case.
* `xusb21`: no explicit checks either, but also no permissive DACL — default device security.
  Reaching any of the codes requires the devnode (hardware) and, for a non-admin, an ACL change.
  The 5th-argument codes `0x8000xxxx` are internal bus-interface packets used by the child
  stacks, not a user surface.
* Privilege gates therefore do not raise any `ssdevfactory` path; they do make `xusb21` R2/R3.

---

## 5. Memory-write trace

### 5.1 What is *not* present

No pool arithmetic, no `ExAllocatePool*` with a caller length, no `memcpy` into a kernel
destination whose destination is caller-chosen in a *buffered* path, no MDL, no physical-memory
mapping, no `MmMapIoSpace`, no `ZwMapViewOfSection`, no `\Device\PhysicalMemory`, no
`MmGetPhysicalAddress`, no MSR/port/PCI/SMBus write in either x64 family. The `ssdevfactory`
`memcpy`/`memset` compiler intrinsics (`FUN_140006080` / `FUN_140006340`) are used only for
fixed-size `memset`s of locals and for the descriptor copies in §5.2–5.3, always with a
`min(caller_length, fixed_cap)` bound.

### 5.2 `ssdevfactory` `0x220003` / `0x220013` — `METHOD_NEITHER` fixed-content store

Both handlers obtain their object from the request parameters they themselves fill:

```
140001c29  lea  r8,[rbp-0x11]            ; &WDF_REQUEST_PARAMETERS
140001c4f  movw r15w,[rbp-0x11]          ; Size = 0x28  (sizeof(WDF_REQUEST_PARAMETERS), x64)
140001c54  mov  rax,[WdfFunctions+0x850] ; WdfRequestGetParameters
140001c5b  call guard_dispatch_icall
140001c64  mov  rax,[rbp-0x9]            ; block pointer  (base + 8)
```

`0x220003`, selector 0 (`0x140001efe`–`0x140001f4d`), writes into that block at fixed offsets:

```
movw $0x3,0x2c(%rax)      movq $0x140007338,0x48(%rax)
movb $0x0,0x2e(%rax)      movq $0x14000733c,0x78(%rax)
movl $0x1810040,0x40(%rax)  movl $0x3,0x44(%rax)
movq $0x1000,0x50(%rax)     movw $0x3,0x5c(%rax)
movb $0x1,0x5e(%rax)        movl $0x1820020,0x70(%rax)
movl $0x3,0x74(%rax)        movq $0x1000,0x80(%rax)
```

`0x220013` (`0x140001e8c`) is shorter and unconditional:

```
movl $0x3,(%rax)     ; dword 3 at block+0x00
movl %ebx,0x2(%rax)  ; word 0 at block+0x02
```

Selectors `0xB`/`0x28` (`FUN_140002244`), `0x1B` (`FUN_140001fa8`) and `9` (`FUN_140002138`)
then read/write further through the block's own fields — `+0x24` length (u32) and `+0x28`
buffer pointer — copying fixed driver templates (`&DAT_1400073b0`, `&DAT_1400074d0`,
`&DAT_140007398`, …) with a per-selector cap of `0x12`/`0x18`/`0x1A`/`0x1B`/`0x2E`/`0x3B`/`0x3C`,
and
`0x1B` (`FUN_140001fa8`) rejecting `*(param_2+0x24) > 0x20E` and then copying that many bytes
**from** the caller pointer `*(param_2+0x28)` into the device-context buffer created as
`WdfMemoryCreate(&cfg, PagedPool, 'PSS2' /*0x32325350*/, 0x20E, …)` in `FUN_140002b60`
(`0x140002b60` region, `0x32325350` at the `WdfMemoryCreate` call). That destination is exactly
0x20E bytes and the length is checked first, so the 0x1B path is a bounded **read** of caller
memory, not a write.

Why this is a caller-controlled object and not a driver context:

* the caller must supply the leading `u16 0x88` (`FUN_140002244`: `if (*param_2 != 0x88) return
  STATUS_INVALID_PARAMETER;`), the selector at `+0x02`, and the magic dword `0x13370000`/
  `0x13370001` at `+0x18` (`FUN_1400050f0` compares against both constants), the variant byte at
  `+0x83`, the length at `+0x24` and the buffer pointer at `+0x28`;
* the driver **never writes** `+0x00`, `+0x18`, `+0x24`, `+0x28` or `+0x83` in the
  `0x220003`/`0x220013` handlers; it only consumes them (the selector-0 branch fills
  `+0x2C…+0x80` and drops two `.data` pointers at `+0x48` and `+0x78`);
* there is **no `ProbeForWrite`/`ProbeForRead`** in any build and no
  `WdfRequestRetrieveUnsafeUserInputBuffer` use. For a `METHOD_NEITHER` IOCTL the I/O manager
  does not probe `Type3InputBuffer`; the handler is responsible, and it does not.

Net primitive, `ssdevfactory` x64: a caller who can open the interface (Everyone) can make the
driver store a **fixed ~0x5C-byte template (including two `ssdevfactory` `.data` pointers)** at a
caller-chosen 64-bit address (`0x220003` selector 0), or store `dword 3`/`word 0` at a
caller-chosen address (`0x220013`), or store a fixed template of ≤0x3C bytes at a pointer
supplied one level deeper (`+0x28`). The **value is not caller-chosen** (two bytes are, via the
flags at `+0x83`/`+0x41`), the **length is caller-chosen but clamped**, the **target is
caller-chosen**. That is a constrained write: **W2**, not W1. It also yields an arbitrary kernel
**read** (selector `0x1B` copies ≤0x20E bytes from the caller pointer into a HID report), which
is a KASLR-capable leak but is not itself a write.

### 5.3 The `0x2A0008`/`0x2A0010` report path

`FUN_140001ba0` `0x140001d8d`–`0x140001e87`: `WdfRequestRetrieveInputBuffer(Request,4,&in,NULL)`,
requires `in[0]==7`, uses `in[1]`/`in[2]` as LED index/branch, then
`WdfIoQueueRetrieveNextRequest(ctx+8, &pending)` and `WdfRequestGetParameters(pending,&p)`; the
copy is `FUN_140006080(dst = the buffer pointed to by block+0x28, src = input,
len = min(0x20, block+0x24))`
(`0x140001d3d`–`0x140001d5e`). `0x2A0010` is the same with `0x41`. Every bound comes from the
block's `+0x24`, clamped to `0x20`/`0x41` in the instruction stream — no overflow of the
destination.

### 5.4 `xusb21`

The report-descriptor copies (`FUN_00016278`, `FUN_00017c24`, `FUN_000163d0`, `FUN_00017b44`,
`FUN_000178d0`) write fixed XUSB templates into the descriptor object's `+0x28` buffer with the
same `min(length, fixed)` discipline, and every field is preceded by a length test. The object
is attached to the request (not to a user `Type3InputBuffer`) and, with no device interface and
hardware-only enumeration, no user-reachable path to it was found. No other write sink exists:
`ExAllocatePoolWithTag(0, 600, 'XUSB')` is a fixed size; the `0x8000xxxx` bus packets write a
fixed 12-byte block after `0xb < length`.

---

## 6. Hardware-only and other paths

### 6.1 `ssdevfactory` MB-lighting / SMBus notification

`IoRegisterPlugPlayNotification` is imported and used (`0x140002b25` inside
`FUN_1400023e8`; callback `FUN_140003370@0x140003370`; interface setup
`FUN_140003438@0x140003438` builds a `'SSMB'` 0x200-byte pool buffer and an IO target for the
SMBus-controller interface). The resulting object is used to emit the manufacturer's fixed
lighting packets; **no IOCTL field reaches the SMBus address/register/data** — the lighting
queue's `0x220003` handler writes only the constants shown in §5.2 plus the caller's variant
byte, and the other lighting codes (`0x2A0440/444/448`) carry fixed-size local structures. So the
SMBus/MB-lighting side is at most a **HW-ONLY** path (device/hardware access), with no
user-controlled transaction, and no chain from it into a memory write.

### 6.2 `ssdevfactory` i386 builds — fixed PCI config access

`ssdevfactory_3F76D97A` and `_A7F7DC6A` import `READ_PORT_ULONG`/`WRITE_PORT_ULONG`, used in
exactly one 70-byte routine (`FUN_00401120` in `3F76D97A`):

```
WRITE_PORT_ULONG(0xCF8, ((0 | 0xFFFF8000) << 5 | 0x1F) << 3 | 0) << 8 | 0x2C & ~3);
READ_PORT_ULONG(0xCFC);
```

i.e. a fixed PCI-config **address** write plus a read at bus 0 / device 0x1F / function 0 /
register 0x2C — a chipset-subsystem-ID probe with constants only. `HW-ONLY`, no user input, no
memory effect. (This call is absent from the three x64 builds.)

### 6.3 `xusb21`

No HW-ONLY surface at all: the bus driver talks to the controller through WDF USB pipes and
`PoSetSystemState`, holds no MMIO window, and performs no port/PCI/MSR access.

---

## 7. Build comparison (material differences only)

| Difference | 2017 (`A7F7DC6A`/`BB05D258`, 1.1.4.1) | 2020 (`3F76D97A`/`49E69A7F`, 1.2.0.0) | 2025 (`63D7C6F1`, 1.3.3.0) |
|---|---|---|---|
| Architecture | x86 + x64 | x86 + x64 | x64 only |
| SDDL / interface | same `Everyone-RWX` literal in all five builds; 3 creation sites in `63D7C6F1` | same literal | same literal, 3 sites (third child class) |
| `0x220003` block pointer | `WDF_REQUEST_PARAMETERS+8` (`local_60[1]`) | `+8` (`0x140001c65`) | `+8` (`0x140001c64`) |
| Descriptor templates | 2017 constant set (`&DAT_140006278`/`...27C`) | same family | 2025 constant set (`&DAT_140007338`/`...33C`), larger `0x2A04xx` block |
| `0x220003` write size | `+0x2C…+0x80` | same | `+0x2C…+0x88` |
| Port I/O | fixed PCI probe (`0xCF8/0xCFC`) | fixed PCI probe | none |
| Bugchecks | `KeBugCheckEx` imported (not on these paths) | none | none |
| Signer | SteelSeries | SteelSeries | Microsoft WHCP |

`xusb21` 9.18.1015.0 vs 9.18.1034.0: the later pair adds BCrypt/SHA-1 (`ksecdd`) to `0AABCEB6`
and `9D614C5D`, a slightly different descriptor constant block, and `Interlocked*`/`KeTickCount`
in the x86 pair. The dispatch, the descriptor protocol and the length checks are identical; no
build changes the memory-write picture.

---

## 8. Verdict

**Overall: `MW2 — reach=R1 setup=composition write=W2 load=signed` for the three x64
`ssdevfactory` builds.** The family exposes a `METHOD_NEITHER` IOCTL pair (`0x220003`,
`0x220013`) on an `Everyone`-RWX device interface, with no probe and no output-length check, that
stores fixed driver templates (and `dword 3`/`word 0`) at a caller-supplied 64-bit address. It is
not MW1: the stored value is a fixed template, not attacker-chosen, and the setup is
`composition`, not `none`. It is not MW4: the target is a full caller-chosen address and the
primitive is repeatable, not a fixed-offset corruption.

The two i386 `ssdevfactory` builds carry the same static primitive but are **BLOCKED** on
architecture (not loadable on x64); their only extra code, the fixed `0xCF8/0xCFC` PCI probe, is
`HW-ONLY`. The two x64 `xusb21` builds are **NO-MEMORY-WRITE (W0)**: no SDDL, no interface, no
symlink, no MMIO/port/MSR, all descriptor copies length-clamped, and the whole surface is
hardware-gated behind an Xbox-360-class controller. The two i386 `xusb21` builds are
**BLOCKED** on architecture.

Per-file: `MW2` for `63D7C6F1`, `49E69A7F`, `BB05D258`; `BLOCKED` for `3F76D97A`, `A7F7DC6A`,
`9D614C5D`, `785DEFAE`; `NO-MEMORY-WRITE` for `0AABCEB6`, `B7A7A906`.

---

## 9. Limitations and unresolved paths

1. **The one load-bearing uncertainty.** The `ssdevfactory` block pointer is loaded from
   `WDF_REQUEST_PARAMETERS + 8` (`0x140001c64` in `63D7C6F1`, `0x140001c65` in `49E69A7F`). Per
   the KMDF header
   (`wdfrequest.h`, 1.9 → 1.33, identical) offset `+8` of `Parameters.DeviceIoControl` is
   **`OutputBufferLength`**, while `Type3InputBuffer` is `+0x20`; the `Size` field the driver
   writes (`0x28` x64 / `0x18` x86) matches `sizeof(WDF_REQUEST_PARAMETERS)` exactly, and
   `+0x850` was confirmed as `pfnWdfRequestGetParameters` against the local `Wdf01000.pdb`
   (`offset = 2128`). Read literally, the field is a length and the branch would fault on first
   use. Against that: the block is demonstrably caller-initialised (§5.2), the driver's own
   service must drive these codes, and the sibling Microsoft `xusb21` code uses the same block
   shape with a real buffer pointer. One 5-minute KD run (break at `0x140001c64`, print `RAX`,
   call `0x220003` as a standard user with a user buffer and then with a kernel address) settles
   it. If the field is a length, the branch is a bugcheck and the family drops to **MW4 (W3,
   crash-first)**; if it is the caller's `Type3InputBuffer` — the reading adopted here — the
   verdict stands at MW2/W2.
2. **No dynamic confirmation, no REA.** Static only, as required; the four REA sessions were at
   capacity, so no independent evidence IDs exist for this report. Ghidra decompiler artefacts
   were cross-checked against `llvm-objdump` for every address cited; the stack-variable names in
   the decompiler output are unreliable in these functions (the `psStack_*` names do not reflect
   the real frame), which is why the report cites instruction addresses rather than variable
   names.
3. **`xusb21` coverage.** The driver is a large C++ KMDF bus driver (~80 KB image, 300+ functions)
   and only the dispatch, descriptor and bus-packet paths were enumerated. The USB pipe
   read/write wrappers (`wdfusbpipewrapper.cpp`) were reviewed for length handling but not
   exhaustively fuzzed statically. Since there is no user-openable interface and no mapping/port
   API, a missed path cannot reach a kernel memory write from R1/R2 without hardware; the residual
   risk is a hardware-gated pool bug, which would be MW3.
4. **No exploit code or PoC was produced**, consistent with the project rules. The `0x220003`
   descriptor layout and the exact write offsets are described only to the extent needed to
   identify the primitive.
5. **Not modified:** `audits/STATUS.md` and all other reports. This is the single report for these
   nine files.
