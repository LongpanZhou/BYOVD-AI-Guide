# Appendix: nvlddmkm.sys - UVM IOCTL fan-out and `NvAdminDevice` table

> **Supplements** [`nvlddmkm.focused.md`](nvlddmkm.focused.md). That report closed the device/mapping
> plane at `NO-MEMORY-WRITE (scoped)` but left two explicit gaps: *(1)* the `0x4a6e`
> `IRP_MJ_DEVICE_CONTROL` fan-out from `0x14161c960` was unread (UVM IOCTL handlers 0%), and
> *(2)* the `NvAdminDevice` per-major-function table was not followed. **This appendix closes both
> gaps** and does not re-verdict the mapping plane, the DxgkDdi escape/render surface, or the
> second `\Device\PhysicalMemory` literal.
>
> It does **not** supersede the baseline [`nvlddmkm.md`](nvlddmkm.md); the driver remains
> unaudited outside the planes listed in section 9.

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\nvlddmkm.sys` |
| SHA-256 | `71C743AF98CBB9F7924C7366062CBC65D938CDD5007D7FF22225498CF94E2E5C` - recomputed this pass (`Get-FileHash`), matches triage/baseline |
| Size / build | 71,847,544 bytes ; NVIDIA 32.0.15.6094 (560.94) ; PE32+ ; ImageBase `0x140000000` ; TimeDateStamp 2024-08-14 ; signed (Security dir RVA `0x4480200`) |
| Analysis date | 2026-10-25 |
| Method | Static-only, offline. `llvm-objdump` 20.1.5 (msys64) targeted disassembly + custom Python PE / `.pdata` / import-table parsers + raw rip-relative and `call rel32` xref scans. **No REA session. No Ghidra import.** Nothing loaded, executed, installed, or written to the registry. No web. |
| Reach tier | **R1** - all three relevant device objects grant `Everyone` read+write; no setup step beyond the already-loaded display miniport |
| Setup required | `none` |
| Write quality | **W0** (no kernel memory write established in the reviewed fan-out) |
| Loadability | Signed / WHQL / HVCI-compatible; already running as the WDDM miniport |
| Verdict | **NO-MEMORY-WRITE (scoped)** - no caller-controlled kernel write, kernel VA destination, or caller-chosen PA reaches a write in the two tables |

## 0 Method and coverage disclosure

The 71.8 MB image still defeats whole-image decompilation, so this pass used the same offline method
as the focused report and **did not** open an REA session or import the binary:

- `.pdata` yields **70,485** `RUNTIME_FUNCTION` records, used as the function-boundary table.
- Tables were decoded from file bytes, not guessed: `llvm-objdump` of the switch bodies gave the
  jump-table base addresses, then the byte-index and dword-offset arrays were read directly from
  `.text`. Every entry of both major-function tables (`0x1c` entries each) and both IOCTL switches
  is accounted for.
- Call targets were resolved two ways: `call rel32` (`E8`) scans for inter-function xrefs, and
  `ff 15 disp32` scans against specific IAT slots for API call sites.

**Coverage, stated honestly:**

| Item | Coverage |
|---|---|
| `DeviceType 0x4a6e` dispatch chain | **100%** of the path from `0x14161c960` to both IOCTL switches |
| UVM IOCTL codes enumerated | **26 of 26** (15 direct-I/O + 11 buffered) |
| `NvAdminDevice` (`0x90de`) codes | **9 of 9** |
| Major-function tables (`0x141009990`, `0x141009a70`) | **100%** (all 28 entries each, init sites read) |
| Functions inspected | **35** total - 13 read through their full `.pdata` extent, 22 through entry block + first sink |
| Share of image functions | 35 / 70,485 ~ **0.05%** |

Everything below the first length check or first kernel sink of each handler was followed; **not**
every GPU/RM routine behind those sinks was decompiled. section 9 lists what is still open.

---

## 1 The `0x4a6e` fan-out, resolved

The focused report stopped at `0x14161c960` and could not find the control-code switch. The missing
step is that `0x14161c960` is not the IOCTL handler - it is the **per-process state gate**; the
handler is chosen by the device's I/O flags one call deeper.

```
MajorFunction[0..0x1b] = 0x14161d190          (DriverEntry, stores from 0x1445af95c)
  \- switch (DeviceObject->DeviceType, +0x48)
       |- 0x4a6e --> 0x14161c960               (only if g_140fd206d != 0; else 0xC0000002)
       |- 0x90de --> g_driverData[0x3a160 + major*8]   = table 0x141009a70
       |- 0xa033 --> reject
       |- 0xa0de --> 0x141590b20
       \- other  --> g_driverData[0x3a080 + major*8]   = table 0x141009990
```

`0x14161c960` (`.pdata` `0x14161c960`-`0x14161cc7b`) then:

1. re-validates `DeviceType == 0x4a6e` (`0x14161c9a4`);
2. resolves the calling process's UVM state with **`0x140cab2e0`** (`0x14161c9cb`), which walks the
   global list at `0x140fd2038` and returns `0xC0000225` (`STATUS_NOT_FOUND`) on a miss - this is
   the identity gate the focused report left undecoded;
3. acquires the UVM global resource, then calls
   **`0x1400705d0(DeviceObject, Irp, CurrentStackLocation)`** at `0x14161cbae`.

`0x1400705d0` is the actual flag split (`0x1400705da`):

| `DEVICE_OBJECT->Flags & 0x10` | Path | Table |
|---|---|---|
| **set** - `DO_DIRECT_IO` | `0x140070d80` (via `0x140070685`) | 15 codes, `0x22E0xx`/`0x22F0xx` |
| **clear** - buffered | `0x140070220` (tail-jump at `0x1400705f4`) | 11 codes, `0x22E0xx`/`0x22F0xx`/`0x22FFFC` |

`0x140070d80` dispatches on `IO_STACK_LOCATION->MajorFunction` through a jump table
(byte index `0x140071530`, dword offsets `0x14007150c`). `IRP_MJ_DEVICE_CONTROL` (`0x0e`) lands at
**`0x140070ef8`**, which is the code switch. `0x140070220` does the same inline for the buffered
device. A third helper, `0x1400707d0`, classifies a code as "fast-path eligible" and is consulted
only on the state-lookup retry path; it neither authorises nor blocks an IOCTL.

Both switches enforce, **before** looking at the code:

```
mov edx, [stack+0x08]      ; OutputBufferLength
cmp edx, [stack+0x10]      ; InputBufferLength
jne  STATUS_INVALID_PARAMETER   (0x140070f04 / 0xc000000d)
```

so input length must equal output length for every code in both tables.

---

## 2 Device objects and effective DACL

Re-read from the create sites and the SDDL buffers themselves, not from the earlier summary.

| Device | Creator | Type | Flags applied | Default SDDL buffer | Effective DACL |
|---|---|---|---|---|---|
| `\Device\UVMLiteProcess%lld` | `0x140069ae0` | `0x4a6e` | `\|= 0x10` **DO_DIRECT_IO**, `&= ~0x80` (`0x140069c0d`, `0x140069c16`) | `0x140d10150` | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)` |
| `\Device\UVMLiteController0x%x` | `0x14006fa20` | `0x4a6e` | `\|= 0x4` **DO_BUFFERED_IO**, `&= ~0x80` (`0x14006fb8e`, `0x14006fb99`) | `0x140d10150` (same pointer) | same SDDL |
| `\Device\NvAdminDevice` | `0x14161cf00` | `0x90de` | `\|= 0x2004` **DO_BUFFERED_IO \| DO_POWER_PAGABLE** (`0x14161d064`); `Characteristics = 0x100` **FILE_DEVICE_SECURE_OPEN**; `IoInitializeRemoveLockEx('NVMG')` | `0x141666160` | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)(A;;GRGWGX;;;AC)` |

Consequences, which are the point of the exercise:

- `WD` = `Everyone`. `GRGW` = `FILE_GENERIC_READ | FILE_GENERIC_WRITE`, i.e. `FILE_READ_DATA` and
  `FILE_WRITE_DATA` in the device namespace. **Any local user can open all three devices read+write.**
- `AC` = `ALL APPLICATION PACKAGES`, so `\Device\NvAdminDevice` is additionally openable from an
  AppContainer.
- `\Device\NvAdminDevice` has `FILE_DEVICE_SECURE_OPEN`; the two UVM devices do **not**, so their
  protected DACL applies to the device-object open only (no rename/relative-path inheritance).
- Symbolic links exist for all three: `\DosDevices\Global\UVMLiteProcess%lld`,
  `\DosDevices\Global\UVMLiteController`, `\DosDevices\NvAdminDevice`.
- **The flag difference is the finding**: `UVMLiteController` is the same `DeviceType 0x4a6e` as
  `UVMLiteProcess` but is **buffered**, so it reaches `0x140070220` and the 11-code table - a code
  set the focused report never reached. `UVMLiteProcess` reaches only the 15-code table.

`IoValidateDeviceIoControlAccess` is **not imported at all** in this build (verified against the
import directory: zero IAT slots), so per-IOCTL `RequiredAccess` is never re-checked. Every code in
both tables is `FILE_ANY_ACCESS` anyway (`(code >> 14) & 3 == 3` for all 26), so even a read-only
handle could issue them.

---

## 3 UVM IOCTL table A - `UVMLiteProcess` (DO_DIRECT_IO, `0x140070ef8`)

All codes: **METHOD_BUFFERED**, **FILE_ANY_ACCESS**, `InputBufferLength == OutputBufferLength`
enforced by the caller-supplied size check shown in section 1. `sb` = `IRP->AssociatedIrp.SystemBuffer`
(`IRP+0x18`), i.e. the kernel copy of the user's input - every store below lands in that copy, not
in a caller-supplied address.

| Code | Size | Handler | Kernel action |
|---|---:|---|---|
| `0x22E004` | `0x18` | `0x140070f49` | zero `sb+0x10`; return 0x18 |
| `0x22E008` | `0x18` | `0x140070f74` | `0x14006a9f0(state, sb[0], sb[8], 0)` |
| `0x22E00C` | `0x30` | `0x140070f91` | reject if `[sb[0], sb[8])` lies wholly inside the runtime reservation `[0x140fad1f8, +0x140fad200)`; then `0x14007bc40(state, sb+0x18)` handle lookup and `0x14006a530(state, sb[0], sb[8], handle, sb[0x10])` |
| `0x22E010` | `0x18` | `0x14007108e` | `0x14006a9f0(...)`; status -> `sb+0x10` |
| `0x22E014` | `0x30` | `0x1400710b3` | `0x14006b810(state, sb[0], sb[8], sb[0x10])` |
| `0x22E018` | `0x10` | `0x1400710d1` | `0x14006ba70(state, sb[0])`; result -> `sb+0x8` |
| `0x22E01C` | `0x110` | `0x140071129` | array of <= `0x20` u64 from `sb[0..0x100]`, each must be `0` or `1`; `0x14006bb30` per entry |
| `0x22E054` | `0x30` | `0x1400711d8` | `0x14007bc40(state, sb)`; `0x14006b060(handle, sb[0x10], sb[0x18], sb[0x20])` |
| `0x22E058` | `0x18` | `0x14007126d` | `0x14006b450(state, sb[0], sb[8])` |
| `0x22E064` | `0x20` | `0x14007131e` | `0x140079b20(state, sb, sb[0x14], sb[0x18])` |
| `0x22E068` | `0x14` | `0x14007135c` | `0x140079cd0(state, sb)` |
| `0x22E094` | `0x28` | `0x1400712a7` | `0x140079a70(state, sb)` |
| `0x22E098` | `0x14` | `0x1400712e8` | `0x140079c00(state, sb)` |
| **`0x22F004`** | `0x20` | `0x140071372` | **`0x14006a770(state, sb[0], sb[8], &sb[0x10])`** - pin user pages, return kernel VA |
| `0x22F008` | `0x10` | `0x1400713ac` | `0x14006add0(state, sb[0])` |

Everything not listed in `0x22E004..0x22E098` and not `0x22F004/08` falls to `0x1400713e5`
(`STATUS_INVALID_DEVICE_REQUEST`).

### 3.1 The only real mapping path - `0x14006a770` (`0x22F004`)

This is the one place where a caller-supplied address is turned into a mapping, and it is
**`MmProbeAndLockPages` + `MmMapLockedPagesSpecifyCache` on the caller's own pages**
(`0x14006a8c6`, `0x14006a8f4`):

```
0x14006a7a3  require VA != 0, length != 0, VA page-aligned
0x14006a7b5  length must equal the low-32 of itself (size == (ULONG)size)
0x14006a7f6  reject if the range overlaps an existing entry in state+0x7e0
0x14006a8a6  IoAllocateMdl(VA, length, SecondaryBuffer=FALSE, ChargeQuota=FALSE, NULL)
0x14006a8c6  MmProbeAndLockPages(mdl, UserMode, IoModifyAccess)
0x14006a8f4  MmMapLockedPagesSpecifyCache(mdl, UserMode, MdlCache, NULL, FALSE, 0x10|flag)
0x14006a919  *out = [descriptor+8]        ; kernel VA written back into sb+0x10
```

It writes a **kernel VA of the caller's own locked pages** back to the caller. That is an info-leak
(low-value: the VA of a mapping the caller already owns), **not** a write primitive - the MDL's
`AccessMode` is user and the pages are the caller's. No second handler in either table accepts that
VA as a destination.

### 3.2 The VA-range path - `0x22E00C`/`0x22E054` -> `0x14006a530` / `0x14006b060`

`0x14006a530(state, va, size, handle, flags)` walks the range in 2 MB chunks and calls
`0x1400747b0(state[0x730], va, chunk, 2)`, then `0x140075410` / `0x1400751e0` / `0x1400753a0` and a
`IoCallDriver`-style dispatch through `0x140cc5a98` with a local 0x18-byte descriptor. `state+0x730`
is the UVM VA-space object built at device-creation time by `0x140073f90` (`0x140069c78`), so `va`
is a **UVM/GPU virtual address in the process's own address space**, not a CPU kernel VA. The
per-chunk PTE-style updates at `0x140075410`/`0x1400751e0` are the closest thing to a write sink in
this table; they are indexed by the caller's VA and bounded by the handler's `size` and the
`0x1400747b0` range check, which was **not** fully reviewed (section 9 item 3).

---

## 4 UVM IOCTL table B - `UVMLiteController` (buffered, `0x140070220`)

Reached only because `0x14006fa20` sets `DO_BUFFERED_IO` (`0x14006fb8e`). Same METHOD_BUFFERED /
FILE_ANY_ACCESS / in==out rules; `sb` is again the kernel copy.

| Code | Size | Handler | Kernel action |
|---|---:|---|---|
| **`0x22E028`** | `0x8` | `0x14007040f` -> `0x14006beb0(state, sb[0])` | **PID lookup -> physical-memory mapping** (below) |
| `0x22E030` | `0x388` | `0x14006c0c0(state, sb, sb[0x380])` | per-UID counter adjust, `0..9` index, `0x1f` on range error |
| `0x22E034` | `0x28` | `0x14006c190` | lookup + counter read into `sb+0x20` |
| `0x22E038` | `0x28` | `0x140078e30` | **self-test only** (see below) |
| `0x22E03C` | `0x8` | `0x140079520(state, sb[0])` | PID lookup, list read |
| `0x22E040` | `0x38` | `0x140079470(state, sb[0], &sb[0x18], &sb[0x20], &sb[0x28])` | list lookup, three out values |
| `0x22E044` | `0x10` | `0x140079180` / `0x140079050` | per-PID op, selected by `sb[8] == 0` |
| `0x22E050` | `0x208` | `0x14006ee00(state, sb, sb+0x200)` | not traced past entry (section 9) |
| `0x22E09C` | `0x8` | inline | clear `sb[0]` |
| **`0x22F000`** | `0x104` | `0x1400704ed` -> `0x140069ae0(sb)` | **creates `\Device\UVMLiteProcess%lld`** for the calling PID; instance id -> `sb[0x100]` |
| `0x22FFFC` | `0x8` | inline | zero `sb[0]` |

### 4.1 `0x22E028` - the `\Device\PhysicalMemory` chain, with the gate now visible

This is the chain the focused report flagged as "descriptor contents were not traced to a user
input". It **is** user-triggerable - but the physical address is not:

```
0x22E028  sb[0] = u32 PID
  \- 0x14006beb0(state, pid)
       |- 0x14006a500(pid): RtlLookupElementGenericTable(0x1410e53c0, &pid)   ; UVM process table
       |- 0x14006c3a0(PsGetCurrentProcessId(), ...) twice
       |- RtlEqualSid(object->ownerSid, callerTokenSid)      (0x14006bf95)
       |     fail -> 0x1b ; success -> continue
       |- 0x140070cc0(..., 0x238)  -> zeroed object
       \- 0x14006c870(object[0x7a0], &newObj[0x10])
             loop 0x20 descriptors, stride 0x38:
               offset = descriptor[0]        (u32, driver-owned table)
               size   = descriptor[0x10]
               ZwOpenSection("\Device\PhysicalMemory", GENERIC_READ, OBJ_KERNEL_HANDLE)
               ZwMapViewOfSection(..., offset, &size, ViewShare=1, Protect = 2 /*PAGE_READONLY*/)
               verify returned size == requested, else unmap+close
```

So: **the user's u32 selects a PID (an object), not a physical address.** Offset, length and
protection come from the driver's own descriptor table at `object+0x7a0`; the section is opened
`GENERIC_READ` only; the view is requested `PAGE_READONLY`; and the whole path is behind a token-SID
equality check. A cross-user or cross-integrity caller fails `RtlEqualSid`.

### 4.2 `0x22E038` - confirmed self-test

`0x140078e30` ignores its three caller dwords. It allocates a fresh `0x1000` page
(`0x140c56e40`), zeroes it, takes `MmGetPhysicalAddress` of that page (`0x140c572e0`), then calls
`0x14006c750(pa, 0x1000, protect=2)` at `0x140078ed0` and again with `protect=4` at `0x140078f59`.
That is the same self-test the focused report described, now tied to a concrete IOCTL: it proves
`map_physical_range` works against a page the driver just allocated. **No attacker-chosen PA.**

---

## 5 `NvAdminDevice` (`0x90de`) table

The per-major-function table the focused report did not follow is at **`0x141009a70`**, populated in
`DriverEntry` at `0x1445af89f`-`0x1445af8b4`:

| major | target | note |
|---:|---|---|
| `0x00` CREATE | `0x14161e240` | |
| `0x02` CLOSE | `0x14161e240` | |
| `0x0e` **DEVICE_CONTROL** | **`0x14161e320`** | the IOCTL handler |
| `0x01,0x03-0x0d,0x0f-0x1a` | `0x14161e9f0` | stub: completes with `STATUS_INVALID_DEVICE_REQUEST` |
| `0x1b` PNP | `0x14161ea30` | not in scope |

For contrast, the *default* table used by every other device type is `0x141009990`: CREATE/CLOSE ->
`0x14161d290`, **DEVICE_CONTROL -> `0x14161d400`**, SET_SECURITY -> `0x140caa5b0`, PNP -> `0x14161d7d0`,
everything else -> `0x14161d660`. `0x14161d400` is **not** in the assigned scope and was not audited.

`0x14161e320` (`0x14161e320`-`0x14161e9e1`) asserts `MajorFunction == 0x0e`, `DeviceType == 0x90de`
and `Method == 0` (buffered), then switches on the control code:

| Code | Sizes | Handler | Kernel action | User-reachable? |
|---|---:|---|---|---|
| `0x8DE0004` | out >= `0x88` | `0x140c7ca30` | enumerate PIDs from list `0x140fd2038` into `sb+8 + 4*i`, count at `sb+4`; bounded by `((outlen-0x88)>>2)+0x20`; writes stay <= `outlen` | **yes** |
| `0x8DE0008` | in == out | `0x140c7cb00` | parse 0x58-byte struct from `sb`; magic `[sb+8]==0x4c`, `[sb+0x2c]==0x1000151`; resolve UVM object by handle | **yes** |
| `0x8DE000C` | in >= 8 | `0x140c7d200` | UVM object op on `sb[0]` | **yes** |
| `0x8DE0010` | in >= `0x3c`, out >= in | `0x140c7cec0` | `[sb+8] <= inlen-0xc` check; UVM object op | **yes** |
| `0x8DE0014` | in >= `0x58`, out >= in | `0x140c7d440` | `[sb+0x20] <= inlen-0x28`; object + SID checks; builds a 0x30 local descriptor and calls `0x1415164b0` | **yes** |
| `0x8DE0040` | out >= 4 | `0x14161e985` | `*(u32*)sb = 0x10000` | **yes** |
| `0x8DE0100` | in >= `0x38` | `0x1415bc4a0` | object op | **no** - gated |
| `0x8DE0104` | in >= `0x20` | `0x1415bc7d0` | object op | **no** - gated |
| `0x8DE0108` | in >= 8 | `0x1415bc400` | object op | **no** - gated |

The three `0x8DE01xx` codes share an identical gate at `0x14161e70f` / `0x14161e822` /
`0x14161e933`:

```
pass =  (g_14100a138 != 0  ||  perObjectFlag != 0)
        && (byte[request+0x40] == 0)
```

`g_14100a138` lives in `.data` BSS (zero at load, set at runtime) and `perObjectFlag` comes from
`0x141661820`. The `request+0x40` byte is the value the sibling handlers pass as an access mode to
`0x1416620f0`, i.e. the requestor-mode field on the standard IRP layout. On that reading these three
are **kernel-caller paths** and are not reachable from a user handle. I flag the offset
interpretation as an inference in section 9 item 5 rather than as an instruction-level certainty.

`0x8DE0004` is the only *read* that returns kernel-derived values (a PID list). It writes into
`sb` only, within `OutputBufferLength`. It is an info-leak of PIDs, **not** a memory write.

---

## 6 Access-control audit (effective)

| Gate | Where | Can the requester satisfy it? |
|---|---|---|
| Device open | SDDL at create (section 2) | **Yes** - `Everyone` `GRGW`; `NvAdminDevice` also `AC` |
| Per-IOCTL access mask | none (`IoValidateDeviceIoControlAccess` not imported; all codes `FILE_ANY_ACCESS`) | **Yes**, trivially |
| `0x4a6e` process state | `0x140cab2e0` walks `0x140fd2038`, must contain the caller's PID | **Yes** - the state is created for the calling process by `0x22F000` -> `0x140069ae0`, keyed on `PsGetCurrentProcessId()`; a process creates its own entry |
| Buffered-device SID gate | `RtlEqualSid` at `0x14006bf95`, object-vs-token | **Yes** for one's own objects; **no** cross-user. Prevents using another user's PID |
| `NvAdmin` `0x8DE01xx` gate | global + per-object flag + requestor byte | **No** (kernel-caller path) |
| `SeSinglePrivilegeCheck` / `SeAccessCheck` on these paths | none found | n/a |
| IRQL | `KeGetCurrentIrql() < 2` asserted at `0x140c7d7b1` on the `0x8DE0014` path; handlers otherwise passive | normal user dispatch |

The DACL is therefore genuinely the *only* object-level gate, and it is permissive. The
driver-internal gates are identity checks that the caller's own process passes by construction.

---

## 7 Memory-write trace - what actually reaches a write

| Candidate sink | Caller-controlled input | Reaches a write? | Constraint |
|---|---|---|---|
| `sb[..]` stores in both UVM tables | all of `sb` | **Yes, into the kernel SystemBuffer only** | buffer is `max(in,out)` bytes; every handler stores within validated sizes; the copy-back to user is done by the I/O manager |
| `0x14006a770` pin+map (`0x22F004`) | user VA + length | **maps caller's own pages; returns kernel VA** | `MmProbeAndLockPages(UserMode, IoModifyAccess)`; no destination control |
| `0x14006a530` VA-range walk (`0x22E00C`) | UVM VA, size, flags, handle | PTE-style updates at caller VA | handle lookup + reservation-range reject + `0x1400747b0` bounds |
| `0x14006c870` physical map (`0x22E028`) | u32 PID only | `ZwMapViewOfSection` **read-only** | offset/size/protect from driver descriptor table; `GENERIC_READ` open; `PAGE_READONLY` |
| `0x140078e30` self-test (`0x22E038`) | none (args unused) | maps its own page R/O then R/W | self-test only |
| `0x140c7ca30` PID enumerate (`0x8DE0004`) | outlen | writes `sb` | bound `((outlen-0x88)>>2)+0x20`, <= `outlen` |
| `0x1415bc400/4a0/7d0` (`0x8DE01xx`) | `sb` | object op | not user-reachable per section 5 |

Import-level negatives for the reviewed set (call-site scans against the IAT):

- `ProbeForWrite` (`0x140cc51c8`) - 11 sites, **none** in the two IOCTL handler ranges
  (`0x1400702xx`-`0x1400714ff`, `0x14161e3xx`-`0x14161e9e1`, `0x140c7caxx`-`0x140c7d9xx`).
- `ProbeForRead` (`0x140cc5530`) - 13 sites, none in those ranges.
- `MmProbeAndLockPages` - the only UVM-cluster call is `0x14006a8c6` (the caller's own pages).
- `MmMapIoSpace`/`MmMapIoSpaceEx` - 6 sites, all outside these handlers.
- `MmGetPhysicalAddress` - 13 sites, all outside these handlers.
- No `MmCopyMemory`, no `\Device\PhysicalMemory` writer beyond the read-only `0x14006c870`.

**No caller-controlled kernel destination, length, or physical address reaches a write in the
reviewed fan-out.** The strongest thing the tables hand back is a kernel VA for the caller's own
pinned pages.

---

## 8 Most dangerous exposed capability (as established)

1. **World-writable, world-readable UVM control surface with a second, unreviewed code set.**
   `\Device\UVMLiteController0x%x` is `Everyone GRGW`, `DeviceType 0x4a6e`, but **buffered** - it
   reaches 11 codes including `0x22F000` (create a per-process UVM device) and `0x22E028` (PID ->
   `\Device\PhysicalMemory` mapping). The focused report only reached the 15-code direct set.
2. **`0x22F004` leaks a kernel VA** for the caller's pinned pages back into `sb+0x10`. Low value on
   its own (the mapping is the caller's), but it is a genuine kernel-address disclosure from an
   unprivileged handle and would assist any *future* write primitive in this driver. It is not a
   write and does not upgrade the verdict.
3. **`\Device\NvAdminDevice` grants `Everyone` and `ALL APPLICATION PACKAGES` `GRGWGX`**, and six of
   its nine codes are user-reachable; the three privileged-looking codes are gated to kernel callers.
4. **Nothing in the reviewed set writes kernel memory at a caller-chosen address, length, or PA.**

---

## 9 Verdict

**NO-MEMORY-WRITE - reach=R1 setup=none write=W0 load=signed (scoped).**

The `0x4a6e` fan-out and the `NvAdminDevice` table are now resolved: 26 UVM codes and 9 NVAdmin
codes enumerated with methods, access masks, size checks and kernel actions. Every code is
`METHOD_BUFFERED`, `FILE_ANY_ACCESS`, and guarded by `InputBufferLength == OutputBufferLength` plus a
per-code size check. The one live `\Device\PhysicalMemory` path is reachable from an unprivileged
IOCTL but consumes driver-owned descriptors, opens the section read-only and requests a
`PAGE_READONLY` view; the one pin-and-map path maps the caller's own pages.

This closes gaps 1 and 2 of `nvlddmkm.focused.md` section 8 and **confirms**, rather than upgrades, its
scoped `NO-MEMORY-WRITE`. It is **not** a clearance of `nvlddmkm.sys`.

## 10 Limitations and unresolved paths

1. **GPU/RM internals are not decompiled.** `0x1400747b0`, `0x1400751b0`, `0x140075410`,
   `0x1400751e0`, `0x1400753a0` and `0x1415164b0` were classified by call shape, not read line by
   line. If the UVM/GPU VA space can alias host system addresses, the `0x22E00C`/`0x22E054` PTE
   updates would be the place to look. **This is the largest remaining gap.**
2. **`0x22E050` (`0x14006ee00`, 0x342 bytes)** and `0x14006c190` were not traced past entry.
3. **`0x1400747b0`'s range check is unreviewed**, so the bound on the caller-supplied UVM VA in
   `0x22E00C` is asserted, not proven.
4. **`NvAdminDevice` `0x8DE0008/000C/0010/0014`** call into `0x140cab1d0`/`0x140cab400`/`0x140c86*`
   object machinery that was read only to the first length check.
5. **The `request+0x40` requestor-mode reading in section 5 is an inference** from the driver's own use of
   that byte as an access-mode argument; it is consistent across three handlers but was not
   cross-checked against a Windows symbol file. If it is wrong, the three `0x8DE01xx` codes would
   need a fresh trace - they are the only NvAdmin codes with a plausible kernel-write shape.
6. **The `0x14161d400` default-device `IRP_MJ_DEVICE_CONTROL` handler is out of scope** and
   unread; it serves every non-`0x4a6e`/`0x90de` device object (`nvkflt`, `NvLinkControl`,
   `nvpcfilt`).
7. `IRP_MJ_READ`/`WRITE`/`QUERY_INFORMATION` branches of `0x140070d80` (`0x140070e76`,
   `0x140071401`) and the whole `0x140070220` non-IOCTL surface were not audited.
8. Indirect dispatch through stored function pointers is still not covered by the call-site census.
9. No dynamic confirmation was attempted; nothing was loaded, opened, or executed on the host.
