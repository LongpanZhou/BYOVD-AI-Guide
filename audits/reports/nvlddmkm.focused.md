# Audit: nvlddmkm.sys — focused mapping / devices plane

> **Supplements** [`nvlddmkm.md`](nvlddmkm.md), the 0%-coverage baseline. That report issued no
> verdict because Ghidra auto-analysis of the 71.8 MB image never finished. This pass bypasses
> that blocker with offline disassembly and covers **only** the flagged plane: the
> `UVMLiteProcess` / `UVMLiteController` device creation, the two `\Device\PhysicalMemory`
> references, the physical/mapping toolbox, and the effective DACL of the user-openable devices.
> It is **not** a full-driver pass and does **not** supersede the baseline's "no sink cleared"
> status for the DxgkDdi escape/render surface.

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\nvlddmkm.sys` |
| SHA-256 | `71C743AF98CBB9F7924C7366062CBC65D938CDD5007D7FF22225498CF94E2E5C` — recomputed this pass, matches the baseline/triage row |
| Size / build | 71,847,544 bytes (0x4484C38) · NVIDIA 32.0.15.6094 (560.94) · PE32+ · ImageBase `0x140000000` · SizeOfImage `0x45da000` · TimeDateStamp 2024-08-14 · signed (Security dir RVA `0x4480200`, 0x4c78) |
| Analysis date | 2026-10-25 |
| Method | Static-only, offline. `llvm-objdump` 18.x (msys64) disassembly of all executable sections, custom Python PE/`.pdata`/IAT parsers, address-driven xref sweep. **No REA session opened. No Ghidra import.** Nothing loaded, executed, installed, or written to the registry. No web. |
| Reach tier | **R1** for the device objects (explicit DACLs grant `Everyone` generic read+write); no R1 write primitive established |
| Setup required | `none` — devices are created by `DriverEntry` / on-demand UVM runtime; the driver is already loaded as the WDDM miniport on this host |
| Write quality | **W0** (no kernel memory write established) |
| Loadability | Signed / WHQL / HVCI-compatible; already running |
| Verdict | **NO-MEMORY-WRITE** — *scoped to the reviewed mapping/devices plane only; not a full-driver clearance* |
| Coverage | 63,466 / 70,475 `.pdata` functions fully disassembled (**90.0%**); 7,009 PAGE_DD functions scanned only for target references; **~30 functions read in detail (0.04%)**, but 100% of the device-creation sites for the flagged devices and 100% of `\Device\PhysicalMemory` consumers. **UVM IOCTL handlers: followed up in `nvlddmkm.ioctl.appendix.md`.** |

### Method disclosure

- The 71.8 MB image defeats Ghidra auto-analysis (3 timeouts in the baseline). This pass therefore
  never imported it. Instead: parse the PE headers, extract all 70,475 `RUNTIME_FUNCTION` entries
  from `.pdata` as a function boundary table, build the IAT name map from the import directory,
  then disassemble the 11 executable sections with `llvm-objdump -d --no-show-raw-insn` and index
  every instruction by VA.
- Xrefs were found two ways: (a) rip-relative operands printed by `objdump` (`# 0x…`), and
  (b) a raw scan of every section for pointer-sized little-endian immediates plus 32-bit
  `.text` immediates. String-driven triage across the whole image, then upward call-chain walking.
- Every mapping-API import was enumerated by its IAT slot, so the call-site census in §5 is
  complete for **direct** calls in the disassembled set; it does not cover indirect dispatch
  through function pointers stored in tables.
- No decompiler was used; all statements are instruction-level readings with addresses.

---

## 1 Internals relevant to this plane

- `DriverEntry` body at `0x1445af000` (PE entry `0x1445b02f0` → `0x1445af0b0`). It sets
  `DriverObject->DriverUnload = 0x14161ebe0` at `0x1445afa2f` and fills
  `MajorFunction[1..0x1b]` (offsets `0x78`–`0x138`) with a **single common handler**
  `0x14161d190` (`0x1445af95c`–`0x1445afa12`). `IRP_MJ_CREATE` (`0x70`) is not written in the
  blocks recovered; its writer was not located.
- The common handler `0x14161d190` is a **device-type switch** on `DEVICE_OBJECT+0x48`:

  | DeviceType | Route |
  |---|---|
  | `0x4a6e` | `0x14161c960` (both UVM device families) — gated by byte `0x140fd206d`, else `STATUS_INVALID_DEVICE_REQUEST` (`0xc0000002`) |
  | `0x90de` | `0x14161d222` → per-major-function table at `0x140fcf910 + 0x3a080 + major*8` |
  | `0xa033` | `0x14161d273` (reject) |
  | `0xa0de` | `0x141590b20` |
  | other | `0x140fcf910 + 0x3a080 + major*8` indirect jump |

- `0x140fd206d` is set to 1 by `DriverEntry` at `0x1445af656`, only after the UVM module init
  `0x1400709f0` (called at `0x1445af644`) returns success, so the `0x4a6e` route is dead until
  UVM initialises.

## 2 Device objects, names, and effective DACL

### 2.1 `\Device\UVMLiteProcess%lld` — per-process UVM device

- Creator: `0x140069ae0`. Formats three names from `PsGetCurrentProcessId()`:
  `\Device\UVMLiteProcess%lld` (`0x140bc6fd0`), `\DosDevices\Global\UVMLiteProcess%lld`
  (`0x140bc6f88`), and the user-visible `\\.\UVMLiteProcess%lld` (`0x140bc7010`).
- Calls the **dynamically resolved** `IoCreateDeviceSecure` through the wrapper at `0x1413d4630`
  (the string `IoCreateDeviceSecure` lives at `0x140d1008c`; the resolver caches a function
  pointer). Arguments at `0x140069bcb`:
  `DriverObject = [0x1410e5320]`, `DeviceExtensionSize = 0x870`, `DeviceType = 0x4a6e`,
  `DeviceCharacteristics = 0`, `Exclusive = FALSE`, `DeviceClassGuid = NULL`,
  `DefaultSDDLString = 0x140d101c8`.
- `0x140d101c8` is a `UNICODE_STRING` (Length `0x72`, MaxLength `0x74`) whose buffer is
  **`0x140d10150`**:

  ```
  D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)
  ```

  `P` = protected DACL. **SYSTEM generic-all; Administrators read/write/execute; Everyone
  generic-read + generic-write; Restricted Code read.**
- Then `IoCreateSymbolicLink(0x140cc52d0)` for `\DosDevices\Global\…`.
- Device flags (`DEVICE_OBJECT+0x30`): `|= 0x10` (**DO_DIRECT_IO**), `&= ~0x80`
  (`0x140069c0d`, `0x140069c16`). So this is a direct-I/O device, not buffered.
- Extension (`0x870` bytes, zero-filled at `0x140069c3a`): `+0x4` = creating PID
  (`0x140069c3f`), `+0x8` = creating thread id, `+0x10` = monotonic instance id,
  `+0x20` = `PDEVICE_OBJECT`, `+0x730` = sub-object from `0x140073f90`. The record
  `{object, pid}` (size `0x10`) is inserted into the generic table at `0x1410e53c0`
  (`RtlInsertElementGenericTable`, `0x140069cb9`).
- Teardown mirror: `0x14006a085` — `IoDeleteSymbolicLink` for `\DosDevices\Global\…`,
  `IoDeleteDevice` (`0x140cc52e0`), then `RtlInitUnicodeString`/lookup.

### 2.2 `\Device\UVMLiteController0x%x`

- Creator: `0x14006fa20`. Formats `\Device\UVMLiteController0x%x` (`0x140bc7190`) using a global
  counter, retrying on `0x40000000` / `0xC0000035` (name collision) with the counter incremented
  (`0x14006fb01`–`0x14006fb0d`).
- **Same SDDL pointer** `0x140d101c8` → `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)`,
  same `DeviceType 0x4a6e`, extension `0x28`. Symlink name
  `\DosDevices\Global\UVMLiteController` (`0x140d00fc0`, stored as an absolute pointer at
  `0x140e9c970`, i.e. a statically initialised `UNICODE_STRING` buffer).
- Same `0x1413d4630` wrapper; `IoCreateSymbolicLink` at `0x14006fb31`.

### 2.3 `\Device\NvAdminDevice` (user-openable, outside the UVM pair but inside item 4)

- Creator `0x14161cf00`, called from `DriverEntry` at `0x1445afaf9`.
  Names `\Device\NvAdminDevice` (`0x1416660f0`) and `\DosDevices\NvAdminDevice` (`0x141666120`).
- `IoCreateDeviceSecure` at `0x14161cfbd` with `DeviceType = 0x90de`,
  `DeviceCharacteristics = 0x100` (**FILE_DEVICE_SECURE_OPEN**), extension `0x20`,
  `DeviceClassGuid = {A73C93F1-9727-4D1D-ACE1-0E333BA4E7DB}` (built at `0x14161cf28`–`0x14161cf44`),
  SDDL **`0x141666160`**:

  ```
  D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)(A;;GRGWGX;;;AC)
  ```

  SYSTEM all; Administrators, **Everyone**, Restricted Code and **All Application Packages**
  all get read+write+execute.
- `IoInitializeRemoveLockEx` ('NVMG'), flags `|= 0x2004` (**DO_BUFFERED_IO | DO_POWER_PAGABLE**),
  `&= ~0x80` (`0x14161d039`–`0x14161d072`).

### 2.4 Other names seen, not traced

`\Device\NvLinkControl` (`0x140bc82f0` + `\DosDevices\NvLinkControl`), `\Device\nvkflt`
(`0x140bba740`), `\Device\nvpcfilt`, `\Device\NTPNP_PCI`, `\Device\DxgKrnl`. Not part of the
flagged plane; no verdict offered for them.

## 3 Dispatch

- **Located**: the device-type switch `0x14161d190` (§1) and the `0x4a6e` entry `0x14161c960`.
  `0x14161c960` re-validates `DeviceType == 0x4a6e` (`0x14161c9a4`), takes the current stack
  location from `IRP+0xb8` (`0x14161c972`), calls `0x140cab2e0` (`0x14161c9cb`) and on failure
  returns `0xC0000225` (`STATUS_NOT_FOUND`) after walking a process/registration list at
  `0x140fd2038` (`0x14161ca07`–`0x14161ca7a`, comparing a PID-like field at `-0x27d0(rbx)`
  against `0`).
- **Not located within cap**: the `IRP_MJ_DEVICE_CONTROL` fan-out for the `0x4a6e` family
  (`IoControlCode` read/dispatch inside `0x14161c960` or a callee) and the UVM IOCTL table
  (codes, methods, input/output sizes, per-code validation). **Therefore no IOCTL in this driver
  was reviewed for memory-write behavior.**
- Verified-negative: `IoValidateDeviceIoControlAccess` appears as a string at `0x140d100bc` but
  has **no code reference** in any disassembled section, so the per-IOCTL access check API is not
  used in this build's UVM/NVAdmin path (as far as this scan shows).

## 4 Access-control audit (effective, not just the SDDL list)

For a device object, `GENERIC_WRITE` maps to `FILE_WRITE_DATA`, so an `IRP_MJ_DEVICE_CONTROL`
whose `RequiredAccess` includes `FILE_WRITE_ACCESS` is satisfiable by **any** principal holding
`GRGW`. Consequences:

| Device | Everyone | Verdict on DACL |
|---|---|---|
| `\Device\UVMLiteProcess%lld` | `GRGW` | **open handle obtainable by any local user**; `SECURE_OPEN` not set, so the protected DACL applies to opens by name |
| `\Device\UVMLiteController0x%x` | `GRGW` | same |
| `\Device\NvAdminDevice` | `GRGWGX` | **open handle obtainable by any local user *and* any app package**; `FILE_DEVICE_SECURE_OPEN` is set, so the DACL is enforced on name opens |

- The DACL is the only *object-level* gate. The identity gate is inside the dispatcher: the UVM
  path keys on the creating PID stored at extension `+0x4` and a process list at `0x140fd2038`,
  and returns `STATUS_NOT_FOUND` for non-matching callers (`0x14161c9d0`–`0x14161c9ee`). The
  exact comparison (and whether a *different* process can satisfy it) was **not** resolved; §3.
- `SeTokenIsAdmin` is imported (`0x140cc54e8`) and called at `0x1415b76b3`, `0x1415b76f8`
  (function `0x1415b7640`) and `0x141667f9e` — none of these is on the reviewed device-creation
  or `\Device\PhysicalMemory` path, so no admin gate is documented for the three devices above.
- Note on the exposure itself: a world-read/write device object is a **reach** finding (R1), not
  a memory-write finding. It matters here because it removes the DACL as a defence for whatever
  the unreviewed IOCTL table does.

## 5 Memory-write trace

### 5.1 `\Device\PhysicalMemory` occurrence #1 — `0x140bc70a0` (**live**)

The literal sits in the UVM string cluster between the `memory-manager.c` and `counters.c`
`__FILE__` strings. Two consumers:

- **`0x14006c750` — `map_physical_range(offset, size, protect, state)`**
  1. `RtlInitUnicodeString(&name, L"\\Device\\PhysicalMemory")` (`0x14006c770`).
  2. `OBJECT_ATTRIBUTES { Length=0x30, RootDirectory=NULL, ObjectName=&name,
     Attributes=0x240 }` — `OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE` (`0x14006c787`–`0x14006c7ba`).
  3. `ZwOpenSection(&state->handle, 0x80000000 /* GENERIC_READ */, &oa)` (`0x14006c7c3`).
  4. `ZwMapViewOfSection(state->handle, NtCurrentProcess, &state->base, 0, 0,
     &offset, &view_size, ViewShare=1, 0, protect)` (`0x14006c80e`). The **section offset is the
     caller's first argument** (spilled at `0x14006c757` and consumed as the `SectionOffset`
     value at `0x14006c7fc`); the requested view size is the caller's second argument
     (`0x14006c76c`, `0x14006c7d3`).
  5. Rejects the mapping if the returned view size differs from the request (`0x14006c81a`),
     otherwise unmaps and closes on error (`0x14006c82c`, `0x14006c849`).
  - **The physical offset is caller-supplied.** This is a genuine physical-memory mapping
    primitive at the helper level.
  - The section handle is opened **read-only** (`GENERIC_READ`), so a `PAGE_READWRITE` view
    (`protect = 4`) is subject to the section object's granted access and cannot legitimately
    succeed on that handle; only the read-only view (`protect = 2`) is consistent with the open.
- **`0x14006c870`** — loops over an array of descriptors and repeats the same open/map per entry
  (`0x14006c8f2`, `0x14006c9ff`), with `protect` from the descriptor.
- Reviewed callers of `0x14006c750`:
  - `0x140078e7f` — `map(pa = f(0, p), size = 0x1000, protect = 2 /*PAGE_READONLY*/)`.
  - `0x140078f07` — `map(pa = f(0, p), size = 0x1000, protect = 4 /*PAGE_READWRITE*/)`.
  In both, `p` is a freshly allocated, zero-filled `0x1000` buffer
  (`ExAllocatePool…`-style call at `0x140078e97`, `memset` at `0x140078eaf`,
  `pa = 0x140c572e0(0, p)` at `0x140078eb9`). The shape is a **self-test of the mapping
  mechanism against its own page**, not an attacker-chosen range.
  - `0x14006c870` is called from `0x14006c056` inside a UVM path that allocates a `0x238`
    structure and performs `RtlEqualSid` token comparisons plus `IoGetCurrentProcess` lookups
    (`0x14006bf8f`, `0x14006bfb6`, `0x14006bfc1`). Descriptor contents were not traced to a user
    input.
- Upward: `0x14006beb0` ← `0x140070426` (function `0x140070220`). Not traced further inside the
  cap; **no path from a device IOCTL to either consumer was established.**

### 5.2 `\Device\PhysicalMemory` occurrence #2 — `0x141664910` (**dead**)

Sits in a PAGE_K string blob next to `Validation`, `Trigger bugcheck to collect full kernel dump
for %s error`, `To disable the bugcheck, run "?? nvlddmkm!g_GlobalData.driverDebugBreakMode=0"`.
**No reference exists**: zero rip-relative operands in all 11 executable sections (including a
full 35 MB PAGE_DD pass), zero pointer-sized immediates anywhere in the image, zero 32-bit
immediates in `.text`. Treated as a validation/debug literal that is not wired to code in this
build.

### 5.3 Mapping-toolbox census (complete for direct IAT calls)

| Import (IAT) | Sites | Notes |
|---|---:|---|
| `MmMapIoSpace` `0x140cc55d0` | 6 | tail-call thunk `0x1400db9be`; calls `0x141531ce5`, `0x141534f88`, `0x14154c20b`, `0x1415c0a28`, `0x1415c0a99` |
| `MmMapIoSpaceEx` `0x140cc5870` | 1 | `0x14164f775` |
| `ZwOpenSection` `0x140cc5358` | 6 | `0x14006c7c3`, `0x14006c8f2`, `0x14006c9ff`, `0x1400dbb4f`, `0x14154c0e7`, `0x141590a19` |
| `ZwMapViewOfSection` `0x140cc5360` | 10 | `0x14006c80e`, `0x14006c939`, `0x14006ca45`, `0x1400797f2`, `0x1400798f5`, `0x1400db6a2`, `0x1400dbbff`, `0x1400dbe74`, `0x14154c155`, `0x141590aa2` |
| `MmMapLockedPagesSpecifyCache` `0x140cc52a0` | 9 | UVM `0x140068d3d`, `0x140069980`, `0x14006a8f4`; `0x140079899`; `0x140c50fbd`; `0x140c574d1`; `0x140c5e1d1`; `0x1416361c5`; `0x14166327b` |
| `MmProbeAndLockPages` `0x140cc5330` | 6 | `0x14006a8c6`, `0x14007983f`, `0x1400d948e`, `0x1400d9b00`, `0x1400db73d`, `0x140c5e18d` |
| `MmGetPhysicalAddress` `0x140cc5188` | 11 | thunk `0x140c57401`; 10 calls in PAGE_K/PAGE (`0x1415aa2f7` … `0x141669244`) |

- `0x14154c20b` is a clean generic helper: `MmMapIoSpace(PhysicalAddress = arg1,
  NumberOfBytes = arg2, CacheType = arg3)` (`0x14154c201`–`0x14154c20b`), with its cache type
  taken from a stack field (`[rbp+0x6f]`) and its PA/length from the function arguments. Its
  callers are RM/PCI initialisation code, not a reviewed device IOCTL.
- `0x14154bfa0` and `0x1415909a0` are the open-section + map-view (+ `MmMapIoSpace`) pair used by
  the same RM/PCI area; `0x140079720` is a lock-and-map helper (probe/lock + map-locked-pages).
- None of the 49 sites was traced to a user-controlled physical address, length, cache type, or
  kernel-VA destination. No `METHOD_NEITHER` raw-pointer copy was found in the reviewed functions.
- Nothing in the reviewed set writes through a user-supplied kernel pointer.

## 6 Most dangerous exposed capability (as established)

1. **World-open device objects.** `\Device\UVMLiteProcess%lld`, `\Device\UVMLiteController0x%x`
   and `\Device\NvAdminDevice` all grant `Everyone` generic read+write (the UVM pair) or
   read+write+execute (`NvAdminDevice`, plus All Application Packages). Any local user can obtain
   a handle and issue write-access IOCTLs; the only remaining gate is driver-internal identity
   checking, which this pass did not fully decode.
2. **A real, parameterised physical-mapping helper** exists (`0x14006c750`: `\Device\PhysicalMemory`
   + `ZwMapViewOfSection`, offset = caller argument). Its two reviewed callers use it as a
   self-test over a locally allocated page, and the section handle is read-only.
3. No caller-controlled destination, length, or PA was found reaching any write.

## 7 Verdict

**NO-MEMORY-WRITE — reach=R1 setup=none write=W0 load=signed (scoped).**

Within the reviewed plane there is no established kernel memory write: no caller-controlled
physical address, length, cache attribute, or kernel VA reaches `MmMapIoSpace`,
`ZwMapViewOfSection`, `MmMapLockedPagesSpecifyCache`, or a raw copy; the one live
`\Device\PhysicalMemory` path is a fixed-pattern self-test over a read-only section handle; the
second `\Device\PhysicalMemory` literal is unreachable.

This is **not** a clearance of `nvlddmkm.sys` and must not be read as an upgrade of the baseline:
the device objects are world-writable and their `IRP_MJ_DEVICE_CONTROL` fan-out was not reviewed,
so a write primitive behind those IOCTLs would be neither found nor excluded by this pass.

## 8 Limitations and unresolved paths

1. **UVM IOCTL table unreviewed (0%).** `0x14161c960` is the `DeviceType 0x4a6e` entry point, but
   the control-code fan-out and its validation were not decoded. This is the single largest gap
   and the only place a user-reachable PA/VA primitive could plausibly hide.
2. **`NvAdminDevice` IOCTL table unreviewed.** `0x90de` routes through the per-major-function
   table at `0x140fcf910 + 0x3a080`; the table entries were not followed.
3. **PAGE_DD (7,009 functions, 10% of functions) not reviewed** — only string-grepped for the two
   `\Device\PhysicalMemory` addresses and for `140bc70*` operands (zero hits).
4. **Indirect dispatch not covered.** The mapping census counts direct IAT calls only; a handler
   reached through a stored function pointer in `.data` would not appear.
5. **`\Device\UVMLiteController` / `\Device\NvLinkControl` / `nvkflt` / `nvpcfilt` IOCTL
   surfaces** were not enumerated.
6. **Identity gate not decoded.** Whether a non-owner process can pass `0x14161c960`'s process
   check (and what the check actually compares) remains open; this decides whether the
   world-writable UVM DACL is really reachable in practice.
7. No dynamic confirmation was attempted; nothing was loaded or opened on the host.
