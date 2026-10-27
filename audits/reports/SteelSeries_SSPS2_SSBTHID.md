# Audit: SteelSeries `ssps2` (7 builds) and `ssbthid` (5 builds)

Current-scope re-audit (memory-write only; `R2` admin inclusive; `HW-ONLY` split out). The two
historical baselines (`steelseries_hid.static.md`, `steelseries_hid_miniport.static.md`) were read
for orientation only; **no verdict is inherited**. Every build below was re-opened and re-traced.

| Field | Value |
|---|---|
| File(s) | `ssps2_26BF2283.sys`, `ssps2_5290DB46.sys`, `ssps2_60304E52.sys`, `ssps2_7CD82A2C.sys`, `ssps2_9B8E59A1.sys`, `ssps2_ABA47E0C.sys`, `ssps2_D262D152.sys`, `ssbthid_02919F79.sys`, `ssbthid_1665FB0C.sys`, `ssbthid_6FCAFD2E.sys`, `ssbthid_CFC3146E.sys`, `ssbthid_D6386EAF.sys` |
| SHA-256(s) | `26BF22835B060C31172FF145AAD02DCD9265B473DE1FFD09622E3CF7C9FAD476`, `5290DB4643096EF93BB97290854A936A022DC65EE69EF6C7CEB387D0B2633E7B`, `60304E5221CFF8B7E56320597232BCD0D1A06E8AEF71C0C090C85BD6D6C25978`, `7CD82A2CA7CFB722611D0FE033B78823570FA83F74ACD85035CEDFE6FACD9540`, `9B8E59A14470983419391094072D7DD5E22663153ADF2D606FAD0CA4DBD24919`, `ABA47E0C8017290544DE6E7BA14D050418D4572212BC52BEDE4B5A55D4ACF02D`, `D262D15200C648836B9308ADA5EF6A334AA7B15257D7BCE1AB8BBB0BA79CC176`, `02919F79588F01160B47930FECF07EF1F550E9DBA2D54BDA203D7DCB6FAC90FD`, `1665FB0C716C6DD9AF958585AFAF6BA93FA7F5A5591DC5F0BBB9F1585CB28E57`, `6FCAFD2E1AC61DC9B4DDCAF2F1D480B5F89A31D39513C7AE7B48286AF431C025`, `CFC3146ECA6DC715951571A841D887A17DFA61A415F6727C951D927770FDF8BF`, `D6386EAF8FF62025CBE691D5E4DB2F9CB5F313CDE639E995CC589BDF3180B4DD` |
| Analysis date | 2026-10-25 |
| Method | Static-only: local Ghidra 12.1.4 headless (full decompile of all 12 images) + `llvm-objdump`/PE parsing. No load, install, service, registry or execution. **REA was not used** - four REA audits were already active, so the mandated offline path was taken. |
| Reach tier | **R3** (hardware / devnode). The child-device interface DACL is `Everyone` RWX, so once the child exists the surface is R1-open. |
| Setup required | **hardware** (PS/2 keyboard controller for `ssps2`; a paired Bluetooth HID device for `ssbthid`) plus the SteelSeries package installed. |
| Write quality | **W0** |
| Verdict | **NO-MEMORY-WRITE** (7 x64 builds); **BLOCKED** (5 i386 builds - not loadable on x64). `ssps2` also carries `HW-ONLY` port-I/O / PCI-config paths. No MW1-MW4. |

---

## 1 Files, hashes, loadability

All hashes were recomputed on the exact files and match the existing SHA-256 prefixes. None of the
12 hashes appears in `indexes/dedupe/known_bad_hashes.txt`. All 12 carry an Authenticode security
directory (size 0x2658-0x4378).

| # | File | Machine | FileVersion | SHA-256 (verified) |
|---:|---|---|---|---|
| 1 | `ssps2_26BF2283.sys` | i386 (0x14C) | 2.0.2.2 | `26BF22835B060C31172FF145AAD02DCD9265B473DE1FFD09622E3CF7C9FAD476` |
| 2 | `ssps2_5290DB46.sys` | x64 (0x8664) | 2.0.2.2 | `5290DB4643096EF93BB97290854A936A022DC65EE69EF6C7CEB387D0B2633E7B` |
| 3 | `ssps2_60304E52.sys` | x64 | 2.2.0.0 | `60304E5221CFF8B7E56320597232BCD0D1A06E8AEF71C0C090C85BD6D6C25978` |
| 4 | `ssps2_7CD82A2C.sys` | i386 | 2.2.0.0 | `7CD82A2CA7CFB722611D0FE033B78823570FA83F74ACD85035CEDFE6FACD9540` |
| 5 | `ssps2_9B8E59A1.sys` | x64 | 2.0.2.2 | `9B8E59A14470983419391094072D7DD5E22663153ADF2D606FAD0CA4DBD24919` |
| 6 | `ssps2_ABA47E0C.sys` | x64 | 2.4.0.0 | `ABA47E0C8017290544DE6E7BA14D050418D4572212BC52BEDE4B5A55D4ACF02D` |
| 7 | `ssps2_D262D152.sys` | i386 | 2.0.2.2 | `D262D15200C648836B9308ADA5EF6A334AA7B15257D7BCE1AB8BBB0BA79CC176` |
| 8 | `ssbthid_02919F79.sys` | i386 | 1.1.0.0 | `02919F79588F01160B47930FECF07EF1F550E9DBA2D54BDA203D7DCB6FAC90FD` |
| 9 | `ssbthid_1665FB0C.sys` | i386 | 1.0.0.0 (Product 3.7.0) | `1665FB0C716C6DD9AF958585AFAF6BA93FA7F5A5591DC5F0BBB9F1585CB28E57` |
| 10 | `ssbthid_6FCAFD2E.sys` | x64 | 1.1.0.0 | `6FCAFD2E1AC61DC9B4DDCAF2F1D480B5F89A31D39513C7AE7B48286AF431C025` |
| 11 | `ssbthid_CFC3146E.sys` | x64 | 1.2.2.0 | `CFC3146ECA6DC715951571A841D887A17DFA61A415F6727C951D927770FDF8BF` |
| 12 | `ssbthid_D6386EAF.sys` | x64 | 1.0.0.0 (Product 3.7.0) | `D6386EAF8FF62025CBE691D5E4DB2F9CB5F313CDE639E995CC589BDF3180B4DD` |

**Architecture is a material finding.** Five of the twelve images are **i386** (`machine 0x14C`):
`ssps2_26BF2283`, `ssps2_7CD82A2C`, `ssps2_D262D152`, `ssbthid_02919F79`, `ssbthid_1665FB0C`.
They cannot load on the x64 target and are therefore **BLOCKED** as loadable primitives (their
static surface is still recorded below for reference). The earlier family report audited only one
build per family and did not surface this.

### Build-to-build comparison (material differences only)

- `ssps2_5290DB46` === `ssps2_9B8E59A1`: the two full decompile dumps are **identical line-for-line**
  (2,730 lines); the diff is only the path/MD5/SHA-256 header. Same code, different signature blob.
- `ssps2_26BF2283` === `ssps2_D262D152`: likewise identical (2,730 lines, metadata-only diff).
- `ssps2` IOCTL set and handler layout are the same in **all seven** builds. The only material
  differences are architecture and the presence of a manual `KeBugCheckEx(0xF7,...)` failure path:
  present in `26BF2283`/`D262D152` and `5290DB46`/`9B8E59A1`, absent (plain `0xC00000BB` return) in
  `7CD82A2C`, `60304E52` and `ABA47E0C`. The same split exists in `ssbthid`
  (`1665FB0C`/`D6386EAF` bugcheck; `02919F79`, `6FCAFD2E`, `CFC3146E` do not).
- `ssbthid_CFC3146E` (1.2.2.0) is the superset build: 7 `0x2A00xx` handlers, descriptor clamp
  `0xDF`, `0x2000`-byte key-map copies, 106 functions.
- `ssbthid_6FCAFD2E` (1.1.0.0), `ssbthid_02919F79` (1.1.0.0, i386) and `ssbthid_1665FB0C` (1.0.0.0,
  i386): 7 `0x2A00xx` handlers, `0xDF` descriptor clamp.
- `ssbthid_D6386EAF` (1.0.0.0 / Engine 3.7.0): descriptor clamp **`0x121`**, only five
  `0x2A00xx` handlers (`0x2A0018`/`0x2A001C` return `0xC000000D`), `0x800`-byte key-map copies,
  77 functions. It is the outlier; the other four use the `0xDF` clamp and seven handlers.

---

## 2 Driver model and device surfaces

Both families are KMDF drivers (`WdfVersionBind` / `WdfLdrQueryInterface` from `WDFLDR.SYS`; every
service is an indirect call through the per-image WDF function table). Neither imports
`IoCreateDevice`, `IoCreateSymbolicLink`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`,
`MmCopyMemory`, `MmGetPhysicalAddress`, `ZwMapViewOfSection`, `ZwOpenSection`, `HalGetBusData`, or
any `Nt*`/`Zw*` memory API. The only `HAL` imports are `KeStallExecutionProcessor` and, on the i386
`ssps2` images, the `READ_PORT_*`/`WRITE_PORT_*` helpers (the x64 images use inline `IN`/`OUT`).

### 2.1 `ssps2` - PS/2 keyboard forwarder

- `DriverEntry` (`entry` 0x140003AF0 in `ABA47E0C`) -> `WdfDriverCreate`; the FDO is created in
  `EvtDeviceAdd = FUN_140009000`.
- `EvtDeviceAdd` creates the unnamed PnP FDO, two request queues on it, and then calls
  `FUN_14000238C` to create the named child device:

  | Item | Value (`ssps2_ABA47E0C`) |
  |---|---|
  | Init | `WdfPdoInitAllocate`-class init (`+0x690`) |
  | **SDDL** | `UNICODE_STRING` @ `0x1400056F0` (`Length=0x7E`, `Max=0x80`, `Buffer=0x140005700`) |
  | SDDL text | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)` |
  | Assign call | `0x140002536` `lea r8,[0x1400056f0]` -> `call [WdfFunctions+0x220]` (`WdfDeviceInitAssignSDDLString`) |
  | Device type | `0x409` |
  | Name | `SteelSeries PS/2 Keyboard Forwarding device` (built by a `%02d`-style helper) |
  | Interface | `WdfDeviceCreateDeviceInterface` (GUID @ `0x140005110`) |
  | Child publish | `WdfChildListAddOrUpdateChildDescriptionAsPresent` |
  | Child IOCTL callback | `FUN_14000A070` (queue cfg `+0x28` = `EvtIoDeviceControl`) |

- Parent queues: queue 1 `EvtIoInternalDeviceControl = FUN_1400096F0`; queue 2
  `EvtIoDeviceControl = FUN_140009590`. The child queue's only handler forwards to the parent
  queue 2 via `WdfRequestForwardToIoQueue(Request, *(childCtx+8), ...)`.

### 2.2 `ssbthid` - Bluetooth HID filter

- `EvtDeviceAdd` (`FUN_1400023A8` in `CFC3146E`) creates the unnamed parent filter FDO, allocates a
  `0x6A0`-byte non-paged block (tag `'BtD'`), builds three queues for that device type, and creates
  a child device via `FUN_1400014C4`.
- Child device (`FUN_1400014C4`): same pattern - init `+0x690`, **SDDL** @ `0x1400084E8`
  (`Length=0x7E`, `Buffer=0x140008500`) assigned at `0x140001660`, device type `0x409`, name
  `SteelSeries Bluetooth HID device` (built by a `%02d`-style helper), device interface GUID @
  `0x140008200`, published through the child list, `EvtIoDeviceControl = FUN_140001A00`.
- Parent queues: queue 1 has `EvtIoDeviceControl = FUN_140002BE0` and
  `EvtIoInternalDeviceControl = FUN_140002E60`; queue 2 has `EvtIoDeviceControl = FUN_140002D70`
  and is the forward target of the child queue. The 1.2.2.0 image repeats this **three times**, one
  set per device type (GUIDs @ `0x1400081B8`, `0x1400081C8`, `0x1400081A8`), with the additional
  handler sets `FUN_140004320`/`FUN_1400044B0`/`FUN_1400045A0` and
  `FUN_1400053A0`/`FUN_140005530`/`FUN_1400055F0`; all six parent handlers have the same shape and
  the same fixed-offset sinks.

**Every one of the 12 images applies the SDDL.** Xref/`lea` sites:

| File | SDDL string VA | Assign site(s) |
|---|---|---|
| `ssps2_26BF2283` / `ssps2_D262D152` | `0x403638` (USTR `0x403630`) | `0x401DF8` |
| `ssps2_7CD82A2C` | `0x404668` (USTR `0x404660`) | `0x40219C` |
| `ssps2_5290DB46` / `ssps2_9B8E59A1` | `0x1400046A0` (USTR `0x140004690`) | `0x14000218D` |
| `ssps2_60304E52` | `0x1400046D0` (USTR `0x1400046C0`) | `0x14000251A` |
| `ssps2_ABA47E0C` | `0x140005700` (USTR `0x1400056F0`) | `0x140002536` |
| `ssbthid_02919F79` | `0x4053B0` (USTR `0x4053A4`) | `0x401548`, `0x407051` |
| `ssbthid_1665FB0C` | `0x405358` (USTR `0x40534C`) | `0x4033D4`, `0x40702B` |
| `ssbthid_6FCAFD2E` | `0x140006420` (USTR `0x140006408`) | `0x140001670`, `0x14000905F` |
| `ssbthid_CFC3146E` | `0x140008500` (USTR `0x1400084E8`) | `0x140001660`, `0x14000C05F` |
| `ssbthid_D6386EAF` | `0x1400063C0` (USTR `0x1400063A8`) | `0x140003E23`, `0x14000B040` |

## 3 Effective DACL and open gate

All 12 images use the **`GRGWGX` variant** (variant B of the historical report), not the narrower
`GRGW` variant:

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)
```

- `D:P` - DACL is **protected**; no inherited ACE can tighten it.
- `;;;SY` full access; `;;;BA` and `;;;WD` (Everyone) and `;;;RC` (restricted code) each get
  `GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE`.
- Everyone therefore has `FILE_READ_DATA|FILE_WRITE_DATA|FILE_EXECUTE` on the device object, and
  the device-interface symlink created from it inherits that descriptor.
- `GENERIC_WRITE` is what matters: `IRP_MJ_DEVICE_CONTROL` with `FILE_ANY_ACCESS` (the only access
  mask these drivers use) passes the `IoCheckFunctionAccess` test for any opener.

**Open gate:** the parent FDO is an unnamed PnP device with **no** SDDL override and no user-visible
symlink, so users cannot open it. The user-reachable gate is the **child device interface**:
`WdfDeviceCreateDeviceInterface` publishes a symlink whose security descriptor is the device
object's `GRGWGX` one. Any local user who can enumerate the interface (`CM_Get_DeviceInterfaceList`)
can open it read/write. This is an **unprivileged (R1-equivalent) gate once the child exists**; the
child only exists when the corresponding hardware stack enumerates (`hardware` setup).

No `SeSinglePrivilegeCheck`, `SeAccessCheck`, `FILE_WRITE_ACCESS` requirement, or caller-identity
handshake exists anywhere in either family.

---

## 4 Dispatch and IOCTL tables

### 4.1 `ssps2` - every narrowly-decoded code

All `FILE_ANY_ACCESS`. Parent queues: **internal** = `EvtIoInternalDeviceControl`; **devctl** =
`EvtIoDeviceControl`; **child** = child `EvtIoDeviceControl`.

| Code | CTL_CODE | Method | Handler / queue | Reach | Kernel action |
|---|---|---|---|---|---|
| `0xB2548` | dev `0xB`, fn `0x152` | BUFFERED | child `FUN_14000A070` -> `WdfRequestForwardToIoQueue` -> parent **devctl** `FUN_140009590` | **user** (child interface) | requires input >= `0x46`; retrieves `0x46` bytes; writes 2 u16 from input to `ctx+0x68`/`ctx+0x6A`; resets/reports to the HID target |
| `0xB0203` | dev `0xB`, fn `0x80` | **NEITHER** | parent **internal** `FUN_1400096F0` | kernel only (kbdclass) | retrieves `0x10`-byte input; copies 16 bytes to `ctx+8..0x17`; writes a kernel pointer + callback pointer **into the input buffer** |
| `0xB0403` | dev `0xB`, fn `0x100` | **NEITHER** | parent **internal** | kernel only | returns `0xC0000002` |
| `0xB2544` | dev `0xB`, fn `0x151` | BUFFERED | parent **internal** | kernel only | HID/keyboard relay: `input[0]` selects sub-op; fixed context writes; sub-op `0xD0` writes the PS/2 controller via `FUN_140001478(input[2],input[3])`; sub-ops `0x0B`/`0x0C` consume `0x40`/`0x20C` bytes |
| `0xB3FC3` | dev `0xB`, fn `0x3F0` | **NEITHER** | parent **internal** | kernel only | retrieves `0x30`-byte input; writes the device-context pointer and two callback pointers into that input buffer, and copies three values out of it |

**The `0xB2548` path is the only user-reachable code.** Its sink is two `u16` stores at **fixed**
offsets in the driver's own context (`+0x68`, `+0x6A`), followed by fixed-shape HID/PS/2 relay
calls. There is no destination, value, or length taken from the caller beyond those two words, and
the length is a compile-time `0x46`.

### 4.2 `ssbthid` - every narrowly-decoded code

| Code | CTL_CODE | Method | Queue / handler | Reach | Kernel action |
|---|---|---|---|---|---|
| `0x2A0000` | dev `0x2A`, fn `0x0` | BUFFERED | devctl `FUN_140002D70` -> `FUN_1400031DC` | **user** (child) | output min 8; stores one u64 from `ctx+0x48` into the output buffer; completes `Information=8` |
| `0x2A0004` | fn `0x1` | BUFFERED | -> `FUN_140003494` | **user** | input 4; 2-byte stores to `ctx+0x32` / `ctx+0x34` |
| `0x2A0008` | fn `0x2` | BUFFERED | -> `FUN_140003614` | **user** | input **min 0**; reads ~`0x1FE` bytes from `input+4` (pool over-read) and converts `0x100` bytes into `ctx+0x36/0x136/0x236/0x336` |
| `0x2A000C` | fn `0x3` | BUFFERED | dispatcher only | **user** | `0xC000000D` |
| `0x2A0010` | fn `0x4` | BUFFERED | -> `FUN_1400036F4` | **user** | input **min 0**; reads `0x101` dwords (~`0x204` bytes, pool over-read) into `ctx+0x43E`/`0x53E` (1.2.2.0), or `0x800`/`0x2000` bytes into `ctx+0x803A`/`0xA03A` (1.0.0.0) |
| `0x2A0014` | fn `0x5` | BUFFERED | -> `FUN_140003540` | **user** | input 4; 2-byte stores to `ctx+0x436..0x43C` |
| `0x2A0018` | fn `0x6` | BUFFERED | -> `FUN_140003398` | **user** | input 8 = event `HANDLE`; `ObReferenceObjectByHandle(..., ExEventObjectType, UserMode, ...)`, stores the object pointer in `ctx+8`, `KeSetEvent` |
| `0x2A001C` | fn `0x7` | BUFFERED | -> `FUN_140003290` | **user** | output >= 8 checked; returns 4 bytes from `ctx+0x18` |
| `0x410210` | dev `0x41`, fn `0x84` | BUFFERED | parent devctl `FUN_140002BE0` | HID-stack device, **not** the child interface | clamps `OutputBufferLength` to `0xDF` (or `0x121` in 1.0.0.0), writes length+descriptor from a `.rdata` constant into `*(WDFFILEOBJECT+0x18)`, completes with `Information=len` |
| `0x410003` | dev `0x41`, fn `0x0` | **NEITHER** | parent internal `FUN_140002E60` | kernel only | `WdfRequestFormatRequestUsingCurrentType` + `WdfRequestSend` down the stack with a completion routine that only updates counters/events |

`0x410210`'s destination is a **driver/kernel-owned** per-file object field
(`[WDFFILEOBJECT+0x18]`), never the request's input/output buffer; the copy source is a fixed
`.rdata` blob and the length is capped at the descriptor size. The exact KMDF field could not be
typed without symbols, but under either plausible interpretation (driver per-file context or
`FILE_OBJECT`-derived context) it is not caller-supplied - see section 11.

---

## 5 Access-control audit

- No access checks of any kind: no `SeSinglePrivilegeCheck`, no `SeAccessCheck`, no
  `FILE_WRITE_ACCESS` access mask (every code is `FILE_ANY_ACCESS`), no caller-identity test, no
  handshake token.
- The only gate is the `GRGWGX` DACL above.
- The parent FDOs have no name/symlink and no SDDL override, so the effective user surface is the
  child interface. The `ssps2` child accepts exactly one code (`0xB2548`); the `ssbthid` child
  accepts exactly eight (`0x2A0000`-`0x2A001C`). Everything else returns
  `0xC000000D`.
- No code path is reachable through `IRP_MJ_READ` or `IRP_MJ_WRITE`: no `EvtIoRead`/`EvtIoWrite`
  callback is installed on any queue (only `+0x28` and `+0x30` slots are populated).

---

## 6 Memory-write trace

The question for each sink: *does a caller-controlled field reach a kernel write, and is the
destination caller-chosen?*

### 6.1 `ssps2`

| Sink | Caller-controlled input | Destination | Verdict |
|---|---|---|---|
| `FUN_140009590` (`0xB2548`) | `input[0..3]` (2 u16), length fixed `0x46` | `ctx+0x68`, `ctx+0x6A` - **fixed offsets in the driver's device context** | fixed-offset, fixed-size, 4 bytes. Not a memory-write primitive. |
| `FUN_1400096F0` / `0xB0203` | `0x10`-byte connect block | `ctx+8..0x17` (fixed) **and** `*input = ctxPointer`, `input[1] = callback` | Writes 16 bytes **into the caller's input buffer**. METHOD_NEITHER, no probe - but the handler is `EvtIoInternalDeviceControl`, which user mode cannot issue. Kernel caller only (kbdclass). |
| `FUN_1400096F0` / `0xB3FC3` | `0x30`-byte block | `ctx+0x18..0x40` (fixed) **and** `*input = ctx`, `input[1..2] = callbacks` | Same: internal-only, fixed layout, caller's kernel buffer. |
| `FUN_1400096F0` / `0xB2544` | `input[0]` opcode + up to `0x20C` bytes | fixed report/context buffers; sub-op `0xD0` -> PS/2 ports | Internal-only. The port write is `HW-ONLY`. |
| `FUN_1400022C8` / `FUN_1400028C8` | `short` from `ctx+0x68/0x6A` | 6-byte report in a `WdfMemoryGetBuffer` block, then HID IOCTL | Fixed 6-byte buffer, no index arithmetic. |

No caller-chosen address appears anywhere: every store target is `ctx + constant`, a stack local, or
a buffer just retrieved from WDF with a matching minimum length. There is no pool-size arithmetic
driven by an input field, no array index from caller data, and no `Mm*`/physical-memory API.

### 6.2 `ssbthid`

| Sink | Caller-controlled input | Destination | Verdict |
|---|---|---|---|
| `0x2A0000` | none | `out[0..7]` | Output copy, min 8 checked. |
| `0x2A0004` | 4 bytes; 2 used | `ctx+0x32/0x34` | Fixed. |
| `0x2A0008` | selector + 0x200-byte span | `ctx+0x36 + n*0x100` (selector 1-4) | Fixed 4-way selector, fixed 0x100 bytes. The **read** from the input buffer is over-long (pool over-read). |
| `0x2A0010` | selector + 0x204/0x800/0x2000-byte span | `ctx+0x43E/0x53E` or `ctx+0x803A/0xA03A` | Fixed 4-way/2-way selector, fixed size. Over-long read again. |
| `0x2A0014` | 4 bytes | `ctx+0x436..0x43C` | Fixed. |
| `0x2A0018` | event `HANDLE` | object pointer in `ctx+8`; `KeSetEvent` | Handle reference, no memory write. |
| `0x2A001C` | none | `out[0..3]` | Output >= 8 checked. |
| `0x410210` | `OutputBufferLength` only | `[WDFFILEOBJECT+0x18]` (driver/kernel-owned) + `0xDF` header | Length clamped to descriptor size; destination not caller-supplied. |

The variable-length copies (`FUN_140002340`, `FUN_1400036F4`, `FUN_140005BF4`, `FUN_140004D00`,
`FUN_140006EC0`) all have **compile-time** lengths (`0x100`, `0x101` dwords, `0x200`, `0x800`,
`0x2000`, `0xDF`, `0x121`, `0x1002`, `0xFFE`) or a length clamped to a constant. No length field is
read out of the input buffer and used as a copy size.

### 6.3 Explicitly absent

Checked in all 12 images (imports + full decompile):

- No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `MmGetPhysicalAddress`,
  `ZwMapViewOfSection`, `ZwOpenSection`, `\Device\PhysicalMemory`, MDL mapping, or DMA programming.
- No `IoCreateDevice`/`IoCreateSymbolicLink` control device with a second DACL.
- No write-what-where, no caller-supplied kernel pointer dereference, no integer-overflow-then-copy.
- No `ProbeForWrite`/`ProbeForRead` is imported - **not** a finding here, because the only
  METHOD_NEITHER writes are on internal-only queues (kernel callers), and every user-reachable code
  is METHOD_BUFFERED (the I/O manager owns and validates the buffer).

---

## 7 Hardware-only paths (`HW-ONLY`)

`ssps2` (all seven builds, including the x64 ones, which use inline `IN`/`OUT` rather than the HAL
imports) contains:

- PS/2 controller port I/O: status `IN 0x64`, command `OUT 0x64`, data `IN/OUT 0x60`, plus a set of
  fixed keyboard-controller commands in the `0x60`-`0x74` range (e.g. 0xA7/0xAD/0xA8/0xAE/0x62/
  0x60/0x74/0x47 handshakes and 0x68/0x6C/0x70 writes). Caller-influenced values exist only on the
  **internal** `0xB2544` sub-op `0xD0` (`FUN_140001478`), which user mode cannot reach.
- A **fixed** PCI configuration read: `OUT 0xCF8` / `IN 0xCFC` with BDF `(0, 0x1F, 0, 0x2C)`
  (`FUN_1400016C4`), used for a subsystem-ID check. Read-only; no config write.

Both are `HW-ONLY`. Neither chains into a kernel memory write: the driver never maps a BAR, never
uses the config data to compute a kernel address, and imports no mapping primitive. `ssbthid` has
no hardware-register path at all (its 12 imports are HID/report plumbing plus
`RtlCompareMemory`, `memcpy`, `memset`, and event/object APIs).

---

## 8 Out-of-scope observations (recorded, not counted)

1. **Kernel pool over-read in `ssbthid`** - `0x2A0008` and `0x2A0010` call
   `WdfRequestRetrieveInputBuffer(Request, 0, ...)` (minimum length **0**) and then read a fixed
   span of ~`0x1FE`-`0x200` bytes (up to `0x204`, `0x800` or `0x2000` bytes in the larger
   variants) from it. A short METHOD_BUFFERED input produces a pool over-read. The decoded bytes
   are written only into the device's key-map context and are never returned to the caller, so this
   is not a usable info-leak and is **not** a memory write. It is a real robustness bug worth a
   separate read-only report.
2. **`ssps2` `0xB2548` accepts a 0x46-byte block from Everyone** but uses only 4 bytes; the rest is
   ignored. No overflow.
3. **`ssbthid` `0x2A0018` takes a user event `HANDLE`** and signals it from kernel context. A
   handle-scope/object-reference quirk, not a memory write.
4. **A `0xF7` bugcheck path** exists in `ssps2_26BF2283`/`D262D152`, `ssps2_5290DB46`/`9B8E59A1`,
   `ssbthid_1665FB0C` and `ssbthid_D6386EAF` when the PS/2 or report handshake fails; the other six
   builds return `0xC00000BB`. DoS-only.

---

## 9 Per-file verdict table

`W0` = no memory write. `HW-ONLY` = port I/O / PCI config only. `BLOCKED` = i386, not loadable on
the x64 target (static surface recorded for reference).

| File | Arch | SDDL applied | User-reachable IOCTLs | Kernel memory write | Verdict |
|---|---|---|---|---|---|
| `ssps2_26BF2283.sys` | i386 | B (`0x401DF8`) | `0xB2548` | none; PS/2 port I/O + fixed PCI read = HW-ONLY | **BLOCKED** (i386); static **NO-MEMORY-WRITE (HW-ONLY)** |
| `ssps2_5290DB46.sys` | x64 | B (`0x14000218D`) | `0xB2548` | none; PS/2 port I/O + fixed PCI read = HW-ONLY | **NO-MEMORY-WRITE (HW-ONLY)** |
| `ssps2_60304E52.sys` | x64 | B (`0x14000251A`) | `0xB2548` | none; PS/2 port I/O + fixed PCI read = HW-ONLY | **NO-MEMORY-WRITE (HW-ONLY)** |
| `ssps2_7CD82A2C.sys` | i386 | B (`0x40219C`) | `0xB2548` | none; PS/2 port I/O + fixed PCI read = HW-ONLY | **BLOCKED** (i386); static **NO-MEMORY-WRITE (HW-ONLY)** |
| `ssps2_9B8E59A1.sys` | x64 | B (`0x14000218D`) | `0xB2548` | none; identical to `5290DB46` | **NO-MEMORY-WRITE (HW-ONLY)** |
| `ssps2_ABA47E0C.sys` | x64 | B (`0x140002536`) | `0xB2548` | none; PS/2 port I/O + fixed PCI read = HW-ONLY | **NO-MEMORY-WRITE (HW-ONLY)** |
| `ssps2_D262D152.sys` | i386 | B (`0x401DF8`) | `0xB2548` | none; identical to `26BF2283` | **BLOCKED** (i386); static **NO-MEMORY-WRITE (HW-ONLY)** |
| `ssbthid_02919F79.sys` | i386 | B (`0x401548`, `0x407051`) | `0x2A0000`-`0x2A001C` | none (fixed context writes; over-read only) | **BLOCKED** (i386); static **NO-MEMORY-WRITE** |
| `ssbthid_1665FB0C.sys` | i386 | B (`0x4033D4`, `0x40702B`) | `0x2A0000`-`0x2A001C` | none (fixed context writes; over-read only) | **BLOCKED** (i386); static **NO-MEMORY-WRITE** |
| `ssbthid_6FCAFD2E.sys` | x64 | B (`0x140001670`, `0x14000905F`) | `0x2A0000`-`0x2A001C` | none (fixed context writes; over-read only) | **NO-MEMORY-WRITE** |
| `ssbthid_CFC3146E.sys` | x64 | B (`0x140001660`, `0x14000C05F`) | `0x2A0000`-`0x2A001C` | none (fixed context writes; over-read only) | **NO-MEMORY-WRITE** |
| `ssbthid_D6386EAF.sys` | x64 | B (`0x140003E23`, `0x14000B040`) | `0x2A0000`/`4`/`8`/`10`/`14` | none (fixed context writes; over-read only) | **NO-MEMORY-WRITE** |

## 10 Overall verdict

**NO-MEMORY-WRITE - `reach=R3 setup=hardware write=W0`, with `HW-ONLY` on the `ssps2` port-I/O /
PCI-config paths and `BLOCKED` on the five i386 images.**

- No MW1, MW2, MW3 or MW4 primitive exists in any of the 12 builds.
- The `GRGWGX` Everyone DACL is **live and effective** in all 12, but the exposed child interfaces
  only reach fixed-offset context writes.
- `ssps2`'s only user-reachable code (`0xB2548`) writes 4 caller-influenced bytes at fixed context
  offsets. Its NEITHER paths (`0xB0203`, `0xB3FC3`) write into caller buffers but are
  `IRP_MJ_INTERNAL_DEVICE_CONTROL`-only.
- `ssbthid`'s user-reachable codes write fixed-size, fixed-offset key-map/state blocks; they
  contain a pool over-**read**, not a write.
- The `0x410210` descriptor copy is bounded (`0xDF`/`0x121`) into a driver-owned per-file object.

## 11 Limitations

- Static only; **no dynamic verification**. `WdfDeviceInitAssignSDDLString` was identified by the
  `+0x220` WDF-table slot and the SDDL `UNICODE_STRING` argument (empirically confirmed in
  `ssps2_ABA47E0C` by disassembly); the i386 calls are the same 3-argument pattern through the
  corresponding import slot. No runtime DACL was observed (by design).
- `WDFFILEOBJECT+0x18` in the `0x410210` path could not be typed without KMDF symbols. It is
  reached by a one-argument WDF request getter (`WdfRequestGetFileObject`) and is **not** derived
  from `Type3InputBuffer`/`SystemBuffer`/`UserBuffer`; the write is capped at the descriptor
  length. Both plausible interpretations are driver/kernel-owned.
- The 1.1.0.0/1.2.2.0 `ssbthid` builds repeat the device/queue set two to three times (one per
  BT device type). Every instance was reviewed and has identical sink shapes.
- The over-reads in section 8 were not rated; they are read-only and out of the memory-write scope.
- REA cross-check was **not** used (capacity: four audits active). All findings rest on local
  Ghidra 12.1.4 headless decompilation and `llvm-objdump`; per-build dumps are retained under
  `%TEMP%\opencode\ssps2_bthid\dump\`.
