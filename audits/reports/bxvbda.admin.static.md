# Audit: `bxvbda.sys` — QLogic B06BDRV VBD (current scope)

**This report supersedes the old `audits/reports/b06bdrv.md` verdict (`WRITE-HIGH`) and the conditional
`WRITE-CRITICAL` in `audits/reports/b06bdrv_detailed.md`. The old `WRITE-*` labels are retired and are
not inherited.**

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\bxvbda.sys` |
| SHA-256 | `FEB2771428706126FEA1CC9A50EBE3CF4F8E8FB6FCB3CA19996497CA44FDAC45` (verified with `Get-FileHash`; matches the old baseline) |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local Ghidra 12.1.4 headless (two read-only imports; full selector and key-helper decompilation) plus GNU objdump disassembly, PE/import/string parsing, a local KMDF framework-template check, and inspection of the installed `netbvbda.inf`. REA was **not** used: the shared REA session was held by another audit (`silabser.sys`); this is disclosed. No load, execution, service creation, or registry write. |
| Reach tier | **R3 effective (hardware)**. The device/interface DACL itself resolves to **R2** (SYSTEM + Administrators), **not R1**. |
| Setup required | **hardware** — Broadcom/QLogic BCM5706/5708/5709/5716 Gigabit Ethernet NIC function bound to `b06bdrv` (INF `netbvbda.inf`, PCI `VEN_14E4`); a service-only start or a bare root devnode without a memory BAR does not open the dispatcher gate. |
| Write quality | **W1** (`0x8000203C`, caller-chosen kernel VA); **W2** (`0x80002024`, BAR-relative OOB); W3 residuals (`0x80002098`, `0x8000208C`) |
| Verdict | **MW2 — reach=R3 setup=hardware write=W1 load=signed** |
| Signature | **Valid**; `CN=Microsoft Windows, O=Microsoft Corporation`; issuer `Microsoft Windows Production PCA 2011` |
| Known-bad | No — hash is not in `indexes/dedupe/known_bad_hashes.txt` |
| HW-only | No overall; the direct BAR window is HW-only MMIO, but `0x80002024` chains past the mapping into kernel VA. |

## Bottom line

The binary contains a genuine **W1 arbitrary kernel memory write**: IOCTL `0x8000203C` takes a full
64-bit destination VA and a caller-supplied data array from the METHOD_BUFFERED input and stores it
with only count, input-length, and 4-byte-alignment checks (`0x140004EF3`–`0x140004F68`). It also
contains the originally reported **W2 BAR-relative OOB write** `0x80002024` (`0x140004D29`–`0x140004DBC`),
an arbitrary kernel **read** `0x80002038` (`0x140004F7E`), the matching BAR-relative OOB **read**
`0x80002020` (`0x140004855`), and an adapter-pointer **leak** `0x80002050` (`0x140005671`).

The gate is not free: the dispatcher returns `STATUS_INVALID_DEVICE_STATE` unless
`EvtDevicePrepareHardware` has succeeded and set the device-context state to `1`/`2`/`4`
(`0x1400017FB`–`0x140001836`; `0x140002BA9`). PrepareHardware requires a **CmResourceTypeMemory**
BAR (`0x140002B20`–`0x140002B43`) and successful `WdfFdoQueryForInterface` binding
(`FUN_140003360`, first query at `0x1400033B4`; call from `0x140002B89`); without a BCM57xx
function this fails at `0x140002C16`. Therefore the effective reach is R3/hardware
and the maximum is **MW2**, not MW1. Even if a different INF variant were to widen the DACL to R1,
the hardware gate would still cap this at MW2; the old `WRITE-HIGH` label is superseded either way.

## 1. Internals and loadability

| Property | Value |
|---|---|
| Format | PE32+ x86-64, native kernel driver |
| Image base | `0x140000000` |
| Entry point | `0x140034318` (WDF loader stub → `WdfVersionBind` at `0x1400343B3` → DriverEntry at `0x1400343F8`) |
| DriverEntry | `0x140001000` |
| Size / version | 533,816 bytes; QLogic Corporation **7.12.31.105**; “QLogic Gigabit Ethernet VBD”; original name `bxvbda.sys` |
| Service / binding | `b06bdrv`; installed INF `netbvbda.inf` binds it to Broadcom/QLogic BCM5706/5708/5709/5716 Gigabit Ethernet (`PCI\VEN_14E4`, `DEV_164A/16AA/164C/16AC/1639/163A/163B/163C`); QLogic “B06BDRV” client roles DIAG/NDIS/iSCSI/WSD per the old baseline |
| WDF | KMDF; WDF version word `0x02080000` at `0x140081640`; WDFLDR imports `WdfVersionBind`/`WdfVersionBindClass` |
| Security | Valid Microsoft Windows signature; not blocklisted; load=`signed` |

Sections: `.text` at `0x140001000`–`0x14003680E`; `.rdata` at `0x140037000`; `.data` at
`0x14003A000`; `INIT` at `0x140085000`; `.reloc` at `0x140088000`. The control-flow guard/CFG
stubs and `__security_check_cookie` are present.

There are **no** `WRMSR`/`RDMSR`, port-I/O, PCI-config, SMBus/EC, or `MmMapLockedPages*` imports.
The only `MmMapIoSpaceEx` callers are the BAR mapper (`0x14001E1F8`) and an internal one-page
mapper (`0x14001AD4C`); there is no `MmCopyMemory`, no MDL mapping into user mode, and no
`ZwMapViewOfSection` on a caller-controlled section.

## 2. Entry, device, interface, and effective DACL

### 2.1 DriverEntry and EvtDeviceAdd

`DriverEntry` (`0x140001000`) creates the WDF driver with `WdfDriverCreate` (table index 116 /
offset `0x3A0` at `0x1400010E1`) and stores `EvtDriverDeviceAdd = 0x140001228` in the driver
configuration (`0x1400010AA`–`0x1400010B1`). `EvtDeviceAdd` (`0x140001228`) then:

| Operation | Call site | Table index |
|---|---|---|
| `WdfDeviceInitSetDeviceType(FILE_DEVICE_UNKNOWN=0x8000)` | `0x140001272` | `0x210` (66) |
| `WdfDeviceInitSetExclusive(TRUE)` | `0x140001294` | `0x1F0` (62) |
| `WdfDeviceInitSetPnpPowerEventCallbacks` (PrepareHardware `0x140002A84`, Release `0x140002C8C`, D0Entry `0x140002758`, D0Exit `0x1400027D0`) | `0x140001335` | `0x1B8` (55) |
| `WdfDeviceInitSetPowerPolicyEventCallbacks` | `0x14000137D` | `0x1C0` (56) |
| `WdfFdoInitSetEventCallbacks` | `0x1400013D6` | `0x400` (128) |
| `WdfDeviceInitAssignWdmIrpPreprocessCallback(IRP_MJ_POWER=0x16, 0x1400019E4)` | `0x140001404` | `0x248` (73) |
| `WdfFdoInitSetDefaultChildListConfig` | `0x140001459` | `0x410` (130) |
| `WdfDeviceInitSetIoType(3)` | `0x140001476` | `0x1E8` (61) |
| `WdfDeviceCreate` (context 0x9380; type GUID `0x14003A018`) | `0x1400014D8` | `0x258` (75) |
| `WdfDeviceSetSpecialFileSupport(1..3, TRUE)` | `0x1400014FF`, `0x14000151F`, `0x14000153F` | `0x188` (49) |
| `WdfIoQueueCreate` (default parallel queue; `EvtIoDeviceControl = 0x1400017A8`) | `0x140001596` | `0x4C0` (152) |
| `WdfDeviceCreateDeviceInterface(GUID at 0x1400372E0, NULL)` | `0x14000164D` | `0x268` (77) |

The interface GUID bytes at `0x1400372E0` are
`2E 58 55 02 A5 76 62 4D 9D CB E0 86 68 61 76 6B`, i.e.
**`{0255582E-76A5-4D62-9DCB-E0866861766B}`**. The `{2AF67184-48D3-4E8E-A3FF-969EFF740ED2}`
string at `0x140034E20` is **not** the interface GUID; it is a service-registry path fragment
(`\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\{2AF67184-...}_Class\`) assembled by
`0x140002058`.

There is no `WdfDeviceInitAssignName` call (index 67 / `0x218`), no `\DosDevices\` string, and no
symbolic-link creation for this FDO. The only `\Device\` text in the image is `\Device\PhysicalMemory` at
`0x1400367E0`, used by the init-time firmware-table read (section 5.8); it is not this driver's FDO
name. The parent FDO's device interface is the only in-binary user path to this IOCTL dispatcher;
the child PDOs are separate client devices.

### 2.2 Effective DACL — resolved statically

The driver calls **neither** `WdfDeviceInitAssignSDDLString` (index 68 / `0x220`) **nor**
`WdfDeviceInitSetFileObjectConfig` (index 71 / `0x238`). A byte scan of `.text` for
`call qword ptr [rax+0x220]` / `[rax+0x238]` finds no such call; the WDF calls in `EvtDeviceAdd`
use `ff 90 <disp32>` with a table offset below `0x1000`, and the two security-relevant offsets are
absent (a register-variant scan of `ff 90`–`ff 97` for those offsets also finds none). The image
also contains no `D:P`, `D:(`, `SDDL`, or `\DosDevices\` text (ASCII or
UTF-16LE). There is therefore **no driver-supplied security descriptor and no file-create callback**.

The effective device security descriptor is the KMDF default. The installed KMDF 1.31
(`C:\Windows\System32\drivers\Wdf01000.sys`, file version `1.31.19041.1`) contains the device-object
default SDDL template at VA `0x1C009D450` (table entry at `0x1C0097A78`):

```text
D:P(A;;GA;;;SY)(A;;GA;;;BA)
```

That grants `GENERIC_ALL` only to **LocalSystem** and **Built-in Administrators**. It contains no
`WD` (Everyone), `AU` (Authenticated Users), `BU` (Users), or `IU` (Interactive) ACE. A local
administrator can open the interface and send every IOCTL; an unprivileged user cannot under this
default. The driver is exclusive (`WdfDeviceInitSetExclusive(TRUE)`), so only one handle at a time,
but that is not a privilege gate.

**INF check.** The installed INF `C:\Windows\INF\netbvbda.inf` confirms the binding: `class = system`
(class GUID `{4D36E97D-E325-11CE-BFC1-08002BE10318}`), `addservice = b06bdrv`, and hardware IDs
`PCI\VEN_14E4&DEV_164A`, `16AA`, `164C`, `16AC`, `1639`, `163A`, `163B`, and `163C` (Broadcom/QLogic
BCM5706/5708/5709/5716 Gigabit Ethernet). Its `[params]` and `[*.hw]` sections contain **no**
`Security` value; `[params]` only sets `create_pdo_flag` and `l2_rx_desc_cnt0`. The INF therefore
does **not** widen the device DACL. (The old report's “10 Gigabit Ethernet” description is
corrected to the BCM57xx Gigabit family stated by the INF and the file version resource.)

**Reach conclusion:** the binary plus the installed INF resolve to **R2** (local administrator) for
the DACL and **R3 effective** because of the hardware gate. The old report's “unprivileged open
succeeds” statement was a convention, not evidence, and is **withdrawn**. The corpus itself contains
no INF, but the installed INF is present and has no security override; an unrelated INF variant
with a permissive `HKR,,Security` value remains a theoretical limitation, not a proven R1.

All dispatched IOCTL values are `0x800020xx`: low two bits are `0` → **METHOD_BUFFERED**, and bits
14–15 are `0` → **FILE_ANY_ACCESS**. The I/O manager performs no handle-access check for these
codes; the open DACL is the only gate.

## 3. Dispatch and IOCTL table

There is one default parallel queue and one device-control handler, `EvtIoDeviceControl =
0x1400017A8`. It obtains the device with `WdfIoQueueGetDevice` (index 157 / `0x4E8`, call
`0x1400017D1`), obtains the typed context with `WdfObjectGetTypedContextWorker` (index 202 /
`0x650`, call `0x1400017F5`), and checks:

```text
if (ctx[0x10] != 0)                  return 0xC0000010;   // 0x1400017FF-0x140001802
if ((ctx[0x14]-1) & ~3) != 0          return 0xC000000E;   // 0x140001804-0x140001814
if (ctx[0x14] == 3)                   return 0xC000000E;
FUN_14000479C(ctx+0x10, request, outLen, inLen, code, &info);
```

There is **no identity, token, privilege, or requestor check** on this path. The dispatcher
`FUN_14000479C` (`0x14000479C`) contains 38 case values. Every code is `BUF/ANY`.

| Code | In (min) | Out (min) | Kernel action | Write |
|---|---:|---:|---|---|
| `0x80002000` | 4 | — | Child-list/device state via `FUN_140002634` → `FUN_1400025E4` (`0x140002634`, `0x1400025E4`); bit mask `&0xFFFFFFE1==0` | W0 |
| `0x80002004` | 4 | — | WDF child/queue state via `FUN_1400046B8` (`0x1400046B8`); bit mask `&0xFFFFFFE3==0` | W0 |
| `0x80002008` | — | 4 | State read under spinlock via `FUN_14000D5A8` (`0x14000D5A8`) | W0 |
| `0x8000200C` | — | — | Registry `create_pdo_flag` + device reconfiguration via `FUN_140007034` (`0x140007034`) | W0 |
| `0x80002010` | 0xC | 4 | Bounded register read via `FUN_140006F78`; `offset+count < 0x21` | W0 |
| `0x80002014` | 0x10 | — | Bounded register writes via `FUN_14002FACC`; `start+count < 0x21`, `count*4 ≤ inLen-0xC` | W0 (MMIO) |
| `0x80002018` | 0xC | 4 | BAR read: direct `<0x8000`, else indirect `FUN_1400326E8` (`0x1400049C2`) | W0 |
| `0x8000201C` | 0x10 | — | BAR write: direct `<0x8000`, else indirect `FUN_140032854` (`0x140004915`); split at `0x8000` | W0 (MMIO) |
| `0x80002020` | 0xC | 4·count | BAR read **without** split or upper bound (`0x140004855`; read at `0x1400048F5`) | W0 / OOB read |
| **`0x80002024`** | **0x10** | **—** | **BAR write without split or upper bound** (`0x140004D29`; store at `0x140004DA7`) | **W2** |
| `0x80002028` | 0xC | 4·count | BAR read via indirect window `FUN_1400326E8` for all offsets (`0x14000520E`) | W0 |
| `0x8000202C` | 0x10 | — | BAR write via indirect window `FUN_140032854` for all offsets (`0x14000517C`) | W0 (MMIO) |
| `0x80002030` | 0xC | 4·count | NVRAM read via `FUN_140030AA8`; `offset+len ≤ adapter+0x10C4` (`0x1400050BC`) | W0 |
| `0x80002034` | 0x10 | — | NVRAM write via `FUN_140030BE0`; same bound (`0x140005034`) | W0 |
| **`0x80002038`** | **0xC** | **4·count** | **Arbitrary kernel read from caller 64-bit source** (`0x140004F7E`) | W0 / leak |
| **`0x8000203C`** | **0x10** | **—** | **Arbitrary kernel write to caller 64-bit destination** (`0x140004EF3`) | **W1** |
| `0x80002040` | — | 0x64 | Fixed getter `FUN_14000619C` (`0x14000619C`) | W0 |
| `0x80002044` | — | 0x80 | Fixed getter `FUN_140006C64` (`0x140006C64`) | W0 |
| `0x80002048` | — | 0x150 | Fixed getter `FUN_140006068` (`0x140006068`) | W0 |
| `0x8000204C` | — | 0x3C | Fixed getter `FUN_140006624` (`0x140006624`) | W0 |
| **`0x80002050`** | **—** | **8** | **Returns adapter kernel pointer** (`0x140005671`; store at `0x1400056A9`) | W0 / leak |
| `0x80002054` | — | 0x1E | Fixed getter `FUN_14000650C` (`0x14000650C`) | W0 |
| `0x80002058` | — | — | Sets `ctx+0x41=1` if `ctx+0x28==0` (`0x140005602`) | W0 |
| `0x8000205C` | — | — | Clears `ctx+0x41` if `ctx+0x91E8==0` (`0x140005618`) | W0 |
| `0x80002060` | 4 | 4 | Device operation `FUN_140005C00` (`0x140005C00`) | W0 |
| `0x80002064` | 4 | 0x34 | Device read `FUN_140005DAC` (`0x140005DAC`) | W0 |
| `0x80002068` | 0x38 | 4 | Device operation `FUN_140007194` (`0x140007194`) | W0 |
| `0x8000206C` | 4 | — | Token-gated EEPROM write `FUN_1400072F0` (`0x1400072F0`); token at `adapter+0x499C` | W0 |
| `0x80002070` | — | 0x18 | Fixed version/capability block (`0x14000538D`) | W0 |
| `0x80002074` | — | 0x60 | Fixed register block (`0x1400056B1`) | W0 |
| `0x80002078` | 4 | 0x50 | Indexed block, `index<4` (`0x140005745`) | W0 |
| `0x8000207C` | 4/8 | 0x140 | Table read `FUN_140005EA8` (`0x140005EA8`); selector-bounded | W0 |
| `0x80002080` | 4/8 | 0x140 | Table read `FUN_140005EA8` | W0 |
| `0x80002084` | — | 0x31B | Snapshot `FUN_140006B08` (`0x140006B08`); fixed layout, driver-state counts | W0 / W3 residual |
| `0x80002088` | — | 0xE45 | Snapshot `FUN_140006708` (`0x140006708`); fixed layout | W0 |
| `0x8000208C` | — | 0xD19 | Port-list snapshot `FUN_140006DDC` (`0x140006DDC`); 0x150/entry, no entry-count cap | W3 residual |
| `0x80002090` | — | 0xD5 | Snapshot `FUN_1400068F8` (`0x1400068F8`); bounded `memset(0,outLen)` | W0 |
| `0x80002094` | — | 0x44 | Fixed getter `FUN_14000681C` (`0x14000681C`) | W0 |
| **`0x80002098`** | **4** | **—** | **Conditional byte write** `adapter+0x16BE8+idx*0x1E8+0x1E6` (`0x1400057A7`; gate `0x1400057D8`) | **W3 residual** |

All codes: `METHOD_BUFFERED`, `FILE_ANY_ACCESS`. The table’s “In/Out” values are the minimum sizes
requested by the dispatcher; the `count` fields are additionally bounded by the retrieved buffer
length as noted in section 5.

## 4. Access-control audit

- **No identity/privilege check on the IOCTL path.** The import list contains no `Se*` identity API,
  no `PsGetCurrentProcess`/`PsGetCurrentThread`, and no requestor query; `PsCreateSystemThread` is
  not an identity check. The only WDF request calls on the IOCTL path are retrieve-input/output
  (`0x868`/`0x870`) and complete (`0x848`). The dispatcher and wrapper decompiles contain no
  `SeAccessCheck`, `SeSinglePrivilegeCheck`, `SeTokenIsAdmin`, or `PreviousMode` test.
- **No file-create callback** (`WdfDeviceInitSetFileObjectConfig` absent); WDF’s default create
  succeeds. No caller identity is recorded in the device context.
- **All 38 codes are FILE_ANY_ACCESS**, so once a handle is open no further access right is checked.
- **The open DACL is the only access-control gate**: KMDF default
  `D:P(A;;GA;;;SY)(A;;GA;;;BA)`, i.e. R2. The device is exclusive, so one opener at a time.
- **The dispatcher state gate** (`ctx+0x10 == 0`, `ctx+0x14 ∈ {1,2,4}`) is a device-lifecycle gate,
  not an identity gate. It is satisfied on the successful `EvtDevicePrepareHardware` path at
  `0x140002BA9`.

## 5. Memory-write trace

### 5.1 `0x8000203C` — arbitrary caller-address write (W1)

**Case:** compare at `0x140004DF8`, branch to `0x140004EF3`. Input is retrieved with
`WdfRequestRetrieveInputBuffer(req, 0x10, ...)` at `0x140004F14`.

```text
in     = input buffer (kernel copy of user bytes)          // 0x140004F22
dest   = *(u64 *)(in + 0x00)                               // 0x140004F32  MOV RDX,[RAX]
count  = *(u32 *)(in + 0x08)                               // 0x140004F2A
data   = (u32 *)(in + 0x0C)                                // 0x140004F2E

if (count == 0) fail                                        // 0x140004F35-0x140004F38
if (count * 4 > inLen - 0xC) fail                           // 0x140004F3D-0x140004F4B
if ((dest & 3) != 0) fail                                   // 0x140004F4D-0x140004F50

for (i = 0; i < count; i++)                                 // 0x140004F57-0x140004F68
    *(u32 *)(dest) = data[i];                               // 0x140004F5E  MOV [RDX],EAX
    dest += 4;                                              // 0x140004F60
```

- **Target:** fully caller-chosen 64-bit virtual address, 4-byte aligned. There is no range,
  canonicality, probe, `ProbeForWrite`, `MmIsAddressValid`, or `PreviousMode` check.
- **Value:** fully caller-chosen 32 bits per iteration.
- **Size:** `count` dwords, bounded only by the input buffer length (`inLen-0xC`); repeatable.
- **Context:** the store executes in the caller’s process context. A kernel VA writes kernel memory;
  a user VA is not probed and may fault under SMAP. An invalid/noncanonical target faults →
  `PAGE_FAULT_IN_NONPAGED_AREA`/bugcheck.
- **Quality:** **W1** (arbitrary target + value; constrained only by 4-byte alignment and valid
  mapping). This is the strongest primitive in the binary.

The same handler’s `0x80002038` read is the natural leak companion:

### 5.2 `0x80002038` — arbitrary kernel read (leak/target supply)

Compare `0x140004DEE`, branch `0x140004F7E`. `source = *(u64 *)(in+0x00)` at `0x140004FE6`;
`count = *(u32 *)(in+0x08)` at `0x140004FE3`. Guards: `count != 0`, `outLen >= count*4`,
`source & 3 == 0` (`0x140004FE9`–`0x14000500A`). Loop copies `count` dwords from `source` into the
output buffer (`0x14000501C`–`0x14000502D`). **No source range check.** This is an arbitrary kernel
read (W0 for write, but a KASLR/target leak). It can read `adapter+0x38` (the BAR base) and
`adapter+0x499C` (the `0x6C` token) once the adapter pointer is known.

### 5.3 `0x80002050` — adapter kernel-pointer leak

Compare `0x14000532F`, branch `0x140005671`. Output is 8 bytes; `*(u64 *)out = adapter`
(`0x1400056A9`). The adapter is the `ExAllocatePoolWithTag(0x200, 0x21E90, 'brcm')` object created by
`FUN_14000DB50` (`0x14000DB50`), with the usable object at `pool+0x10`. This discloses a kernel heap
address and is the anchor for `0x38` reads of the BAR pointer and token.

### 5.4 `0x80002024` — BAR-relative OOB write (W2)

**Case:** compare at `0x1400047DF`, branch to `0x140004D29`. Input is retrieved with
`WdfRequestRetrieveInputBuffer(req, 0x10, ...)` at `0x140004D4A`.

```text
offset = *(u32 *)(in + 0x00)                               // 0x140004D68  MOV R8D,[RAX]
count  = *(u32 *)(in + 0x08)                               // 0x140004D60
data   = (u32 *)(in + 0x0C)                                // 0x140004D64  LEA R10,[RAX+0xC]

if (count == 0) fail                                        // 0x140004D6B-0x140004D6E
if (count * 4 > inLen - 0xC) fail                           // 0x140004D74-0x140004D84
if ((offset & 3) != 0) fail                                 // 0x140004D8A-0x140004D8E

base = *(u64 *)(adapter + 0x38);                            // 0x140004D9D  BAR mapping VA
for (i = 0; i < count; i++) {
    *(u32 *)(base + (u32)(offset + 4*i)) = data[i];         // 0x140004DA7  MOV [RCX+RAX],EDX
    offset += 4;                                            // 0x140004DAE  (32-bit wrap)
}
```

- **Base:** `adapter+0x38` is the kernel VA returned by `MmMapIoSpaceEx` in `FUN_14001E1F8`
  (`0x14001E1F8`), stored by `FUN_140022E14` (`0x140022E14`). The mapping length is
  `min(*(core+0x91C0), 0x400000)` (`0x14001E1F8`); the write path never reads that length.
- **Target:** `BAR_base + zext32(offset)` with any 4-aligned 32-bit offset, i.e. a **4 GiB window**
  above the BAR VA. The first `min(BAR length, 4 MiB)` bytes are device MMIO (HW-only); offsets
  beyond the mapping are **kernel VA OOB** and write attacker dwords into whatever is mapped there.
- **Value:** fully caller-chosen 32 bits per iteration.
- **Size:** `count` dwords, bounded by input length.
- **Quality:** **W2** — target is relative to an undisclosed BAR base, not an absolute 64-bit
  address; the window is 4 GiB and can hit unmapped memory (bugcheck) or adjacent kernel mappings.
  The 0x38/0x50 leaks can disclose the BAR base and make the relative target computable, but the
  4 GiB window/alignment constraint remains.

**The missing-split proof:** the sibling `0x8000201C` at `0x140004915` explicitly checks
`offset < 0x8000` (`CMP EDI,0x8000` at `0x140004984`, `JC` at `0x14000498A`), writes directly at
`0x1400049A3` for the low window, and calls `FUN_140032854` (`0x140004994`) for the indirect
register window. `0x80002024` has **no such compare, no window split, and no upper bound** —
the direct BAR store at `0x140004DA7` is unconditional.

### 5.5 `0x80002020` — matching BAR-relative OOB read

Compare `0x14000484A`, branch `0x140004855`. `offset = *(u32 *)(in+0)`, `count = *(u32 *)(in+8)`;
guards count != 0, `outLen >= count*4`, `offset & 3 == 0`; loop reads
`*(u32 *)(BAR_base + zext32(offset))` at `0x1400048F5` for every offset, with **no 0x8000 split and
no upper bound**. This is an OOB kernel read relative to the BAR VA and a leak/target supplier for
`0x24`/`0x3C`.

### 5.6 `0x80002098` — conditional adapter-relative byte write (W3 residual)

Compare `0x14000579C`, body `0x1400057A7`. Input 4 bytes: `idx = byte[0]`, `val = byte[1]`.
Target is `adapter + 0x16BE8 + idx*0x1E8 + 0x1E6` (`0x140005807`–`0x14000581D`); the byte store is
`0x14000582F`, then `FUN_140016E2C` (`0x140016E2C`). Guards at `0x1400057D8`–`0x1400057FD`:

```text
adapter+0x1940 != 1
*(char *)(*(u64 *)(adapter+0x18310) + 0x40) != 0
*(int *)(adapter+0x182F0) != 0
```

The adapter allocation is `0x21E90` bytes (`FUN_14000DB50`), usable adapter-relative size
`0x21E80`; index `0..92` is in bounds, index `93..255` writes up to ~0x13566 bytes past the
allocation. Init/state paths set `adapter+0x1940 = 1` at `0x14000D8FF` and `0x14000DEE2`, but the
field is a state machine later written with `0`, `2`, `3`, `4`, `5`, and `6` at many sites (e.g.
`0x14000CB47`, `0x14000D0A0`, `0x14001AFBC`, `0x14001BB0F`, `0x14001BD35`). Therefore “gate closed
by init 1” is too strong: the byte write is **state-dependent**, not unconditionally dead.

- **Target:** adapter-relative, index chosen by a byte (`0..255`), not an absolute caller address.
- **Value:** one attacker byte.
- **Quality:** **W3** residual (narrow/relative, state-gated, heap-grooming-dependent); it does not
  change the overall W1/MW2 finding. It is reported as a residual, not as the primary primitive.

### 5.7 `0x8000208C` and `0x80002084` — fixed-layout snapshot residuals

`0x8000208C` calls `FUN_140006DDC` (`0x140006DDC`) with a 0xD19-byte output buffer. The helper walks
the adapter port list and writes `0x150` bytes per entry (`param_2[uVar8*0x150 + ...]`) with **no
entry-count cap**; the fixed tail starts at `0xA88`. Seven entries fit before the tail; an eighth
collides with it, and a ninth or later writes past 0xD19. The port list is driver/hardware state,
not caller input.
`0x80002084` (`FUN_140006B08`, `0x140006B08`) similarly writes a fixed layout with counts read from
adapter state (`+0x160D2`, `+0xE044`), then zero-fills out to the actual output length; no
caller-chosen target. These are **W3 design-margin residuals** only; they are not the arbitrary
write.

### 5.8 Non-findings checked

- **`\Device\PhysicalMemory` mapping (`FUN_140033FC4`, `0x140033FC4`)** opens the section
  (`ZwOpenSection` at `0x140034018`), maps **fixed** physical offset `0x80000`, **fixed** view size
  `0x80000` (`0x140034072`; section offset at `[rbp+0x7F]`, view size at `[rbp+0x77]`), scans for
  iBFT/SMBIOS, copies the table with `memcpy_s` into a pool buffer, and unmaps (`0x1400340DD`). The
  view is **read**, never written. It is called once from DriverEntry (`0x1400011DE`) and is not
  reachable from any IOCTL. **No physical-memory write primitive.**
- **Second `MmMapIoSpaceEx` caller `FUN_14001AD4C` (`0x14001AD4C`)** maps one 0x1000 page at an
  index-derived offset. Its only reference is a callback-table store at `0x140013403` (table slot
  `+0x280`), not a dispatched IOCTL; no user path was found. It remains an internal/residual
  callback, not an exposed primitive.
- **`0x8000206C`** requires a 32-bit token equal to `adapter+0x499C` and writes a fixed 0xE0-byte
  block to device offset `0x420` via `FUN_140030BE0`; it is not a kernel memory write. The token can
  be read with `0x38` after the `0x50` leak, but the result is device NVRAM/EEPROM, not kernel
  memory.
- **`0x80002030`/`0x80002034`** are NVRAM reads/writes bounded by `adapter+0x10C4`; device space.
- **No MSR, port I/O, PCI config, SMBus/EC, or fixed-window-only primitive** was found. Direct BAR
  writes (0x18/0x1C/0x28/0x2C and the in-window part of 0x24) are `HW-ONLY`; 0x24 is the one that
  chains past the mapping into kernel VA.

## 6. Most dangerous exposed capability

1. **`0x8000203C` + `0x80002038` + `0x80002050`** — arbitrary kernel read/write with an adapter
   pointer leak. A local administrator who can open the interface and whose BCM57xx
   function has started can write attacker dwords to any 4-byte-aligned 64-bit kernel VA, and read
   arbitrary kernel memory to find targets. This is **W1**, but hardware-gated → **MW2**.
2. **`0x80002024`** — arbitrary-value dword writes at any 4-aligned 32-bit offset from the mapped
   BAR kernel VA, with no upper bound. This is **W2**; alone it would rate **MW3** under
   `R3 + hardware + W2`, but the W1 `0x3C` raises the driver to MW2.
3. **`0x80002098`** — state-dependent adapter-relative byte write; up to ~0x13566 bytes (≈77 KiB)
   past a 0x21E90 NonPagedPoolNx allocation for index ≥93. **W3** residual; heap-grooming/state
   dependent.
4. **`0x8000208C`** — hardware/port-count-dependent fixed-layout output overflow; **W3** residual.

## 7. Verdict and reclassification

**Verdict: `MW2 — reach=R3 setup=hardware write=W1 load=signed`.**

- The **W1** `0x8000203C` is a true arbitrary kernel memory write, but it is not usable with
  `Setup: none`. The dispatcher is closed until `EvtDevicePrepareHardware` finds a memory BAR and
  `FUN_140003360` succeeds in binding the device interfaces. That requires a BCM57xx Gigabit
  Ethernet function (or a faithful hardware/composition staging), not a plain service or bare
  devnode.
- The **W2** `0x80002024` is a real kernel OOB write but its target is BAR-relative within a 4 GiB
  window, not an absolute caller-chosen address. It would be MW3 on its own.
- The overall maximum is therefore **MW2**, not MW1. The old `WRITE-HIGH` label is superseded, and
  the old detailed report’s conditional `WRITE-CRITICAL` is reclassified to **W1/MW2**.
- **Why not BLOCKED:** the image is validly signed by Microsoft Windows and is not in the
  known-bad list; it is loadable on x64.
- **Why not NO-MEMORY-WRITE:** `0x3C` and `0x24` are actual kernel write paths, not mere IOCTL
  presence or device MMIO.

### What changed from the old reports

| Old statement | Current finding |
|---|---|
| `WRITE-HIGH`; `0x80002024` is the main primitive | `0x80002024` is confirmed but is W2/MW3 alone. The first report missed `0x8000203C`, which is W1/MW2. |
| Reach R1 (“unprivileged open succeeds”, default DACL convention) | No driver SDDL; KMDF default is SYSTEM + Administrators GA (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`). The installed `netbvbda.inf` has no `Security` value. DACL is **R2**; R1 is **not established**. |
| Conditional `WRITE-CRITICAL` if unprivileged | Even under R1, the hardware gate caps the verdict at **MW2**. |
| `FUN_1400019E4` was called the file-create callback in the first report | It is the `IRP_MJ_POWER` preprocess callback (`WdfDeviceInitAssignWdmIrpPreprocessCallback`, major `0x16`, `0x140001404`); there is **no** file-create callback. |
| Separate `{2AF67184-...}` GUID string near the interface | It is a service-registry path fragment (`0x140034E20`), not the interface GUID. The interface GUID is `{0255582E-76A5-4D62-9DCB-E0866861766B}` at `0x1400372E0`. |
| “QLogic 10 Gigabit Ethernet” hardware description | Installed `netbvbda.inf` binds `b06bdrv` to Broadcom/QLogic **BCM5706/5708/5709/5716 Gigabit Ethernet** (`PCI\VEN_14E4`, `DEV_164A/16AA/164C/16AC/1639/163A/163B/163C`). |
| `0x80002098` gate simply closed by init `1` | The `+0x1940` field is a state machine later set to `0`, `2`–`6`; the byte write is **state-dependent**, not unconditionally dead. Still W3 residual. |

## 8. Limitations and unresolved paths

1. **INF evidence.** The corpus has no INF; the installed `C:\Windows\INF\netbvbda.inf` was
   inspected. It binds `b06bdrv` to the BCM57xx family and contains no `Security` value, so the
   KMDF SYSTEM+Administrators default applies. A different INF variant with a permissive
   `HKR,,Security` value remains a theoretical limitation; the deployed INF does not widen the
   DACL, so R1 is not established.
2. **No hardware/VM confirmation.** The PrepareHardware gate was resolved statically from
   `0x140002A84` (memory-resource descriptor, `FUN_140003360` binding) and the dispatcher state
   check. No BCM57xx NIC was used for this static pass, so no runtime open or IOCTL was attempted. Under
   `SEVERITY.md`'s “device not present” modifier, an environment that cannot stage the adapter would
   be capped at MW3; the MW2 verdict records the hardware-gated W1 primitive under the project's
   stageable-hardware convention.
3. **WDF table names** are resolved against the local KMDF headers (`wdffuncenum.h`, 1.25); the
   call shapes and offsets are consistent, but the framework version field `0x02080000` was not
   independently mapped to a specific KMDF release.
4. **`0x80002098` and `0x8000208C`** are state/hardware-dependent residuals. Their exact runtime
   gates were not dynamically confirmed; they are not rated above W3.
5. **`FUN_14001AD4C`** (one-page `MmMapIoSpaceEx`) is only referenced as a callback-table slot at
   `0x140013403`; no user-reachable caller was found. It is an internal path, not an exposed
   primitive.
6. **`0x8000207C`/`0x80002080`** request 8 input bytes but the decompiled check appears to require
   an input length of 4; this path is read-only and was not resolved further. It is not a write.
7. **Helper coverage.** The 38 dispatcher cases and the critical write/leak paths were line-read;
   the fixed getter/snapshot helpers (`0x40`–`0x94`) were decompiled/sampled and show fixed or
   output-length-bounded fills, but not every instruction in every helper was audited. No
   caller-chosen kernel address was found outside `0x24`/`0x3C`.
8. **No PoC or exploit code** was produced. No driver was loaded, no service was created, and no
   registry value was written.

## 9. Evidence and address index

| Claim | Address / evidence |
|---|---|
| SHA-256, signature | `Get-FileHash` and `Get-AuthenticodeSignature` on the exact file; digest `FEB277...DAC45`; status Valid, Microsoft Windows |
| Entry / DriverEntry | `0x140034318`; `0x140001000`; `WdfVersionBind` `0x1400343B3`; DriverEntry call `0x1400343F8` |
| EvtDeviceAdd | `0x140001228`; stored at `0x1400010AA`–`0x1400010B1` |
| WdfDeviceCreate / interface | `0x1400014D8` (index 75); `0x14000164D` (index 77); GUID `0x1400372E0` |
| No SDDL / no file-object config | No `call [rax+0x220]` (index 68) or `[rax+0x238]` (index 71) in `.text`; no `D:P`/`D:(`/`SDDL` strings |
| KMDF default SDDL | `Wdf01000.sys` 1.31 VA `0x1C009D450` (file offset `0x9C250`), table `0x1C0097A78`: `D:P(A;;GA;;;SY)(A;;GA;;;BA)` |
| INF / binding | `C:\Windows\INF\netbvbda.inf`: `class = system`, class GUID `{4D36E97D-E325-11CE-BFC1-08002BE10318}`, `addservice = b06bdrv`, `PCI\VEN_14E4` `DEV_164A/16AA/164C/16AC/1639/163A/163B/163C`; **no** `Security` value in `[params]`/`[*.hw]`; `[params]` sets `create_pdo_flag` and `l2_rx_desc_cnt0` |
| Queue / dispatch handler | `0x140001596` (index 152); `EvtIoDeviceControl = 0x1400017A8` |
| Dispatcher gate | `0x1400017FB`–`0x140001836`; `[ctx+0x10]==0`, `[ctx+0x14]∈{1,2,4}`, `!=3`; errors `0xC0000010`/`0xC000000E` |
| Dispatcher | `0x14000479C`; 38 cases `0x80002000`–`0x80002098`; all `BUF/ANY` |
| 0x8000203C | compare `0x140004DF8`; body `0x140004EF3`; dest `0x140004F32`; guards `0x140004F35`–`0x140004F50`; store `0x140004F5E`; increment `0x140004F60` |
| 0x80002024 | compare `0x1400047DF`; body `0x140004D29`; BAR base `0x140004D9D`; store `0x140004DA7`; offset add `0x140004DAE` |
| 0x8000201C split | `0x140004915`; `CMP EDI,0x8000` `0x140004984`; `JC` `0x14000498A`; direct store `0x1400049A3`; indirect `0x140004994` |
| 0x80002020 OOB read | compare `0x14000484A`; body `0x140004855`; read `0x1400048F5`; no split |
| 0x80002038 arbitrary read | compare `0x140004DEE`; body `0x140004F7E`; source `0x140004FE6`; guards `0x140004FE9`–`0x14000500A`; read `0x14000501C` |
| 0x80002050 adapter leak | compare `0x14000532F`; body `0x140005671`; store `0x1400056A9` |
| Adapter allocation | `FUN_14000DB50` `0x14000DB50`; `ExAllocatePoolWithTag(0x200,0x21E90,'brcm')`; adapter = `pool+0x10` |
| BAR mapping | `FUN_14001E1F8` `0x14001E1F8`: `MmMapIoSpaceEx((core+0x91B8)&~0xF, min(core+0x91C0,0x400000), 0x204)`; stored at `adapter+0x38` by `FUN_140022E14` `0x140022E14` |
| PrepareHardware state | `0x140002A84`; memory resource `0x140002B20`–`0x140002B43`; `FUN_140003360` call `0x140002B89`; state `+0x14=1` at `0x140002BA9`; failure `0x140002C16` |
| D0Entry / D0Exit | `0x140002758` / `0x1400027D0`; no `+0x10`/`+0x14` writes |
| 0x80002098 | compare `0x14000579C`; body `0x1400057A7`; gate `0x1400057D8`–`0x1400057FD`; target `0x140005807`–`0x14000581D`; store `0x14000582F` |
| 0x8000208C | `0x1400058CB`; `FUN_140006DDC` `0x140006DDC`; `0x150`/entry, no count cap; tail at `0xA88` |
| PhysicalMemory read | `FUN_140033FC4` `0x140033FC4`; `\Device\PhysicalMemory` string `0x1400367E0`; `ZwOpenSection` `0x140034018`; `ZwMapViewOfSection` `0x140034072` (offset `0x80000`, size `0x80000`); unmap `0x1400340DD`; DriverEntry call `0x1400011DE` |
| Secondary page mapper | `FUN_14001AD4C` `0x14001AD4C`; callback store `0x140013403` (table `+0x280`) |
| WDF indices | Local KMDF `wdffuncenum.h` 1.25: `0x220`=68 `WdfDeviceInitAssignSDDLString`; `0x238`=71 `WdfDeviceInitSetFileObjectConfig`; `0x268`=77 `WdfDeviceCreateDeviceInterface`; `0x868`=269 `WdfRequestRetrieveInputBuffer`; `0x870`=270 `WdfRequestRetrieveOutputBuffer`; `0x650`=202 `WdfObjectGetTypedContextWorker`; `0x4E8`=157 `WdfIoQueueGetDevice`; `0x848`=265 `WdfRequestCompleteWithInformation` |
| Absent hardware primitives | Import/string sweep: no `WRMSR`/`RDMSR`, no `READ_PORT`/`WRITE_PORT`, no PCI-config helper, no SMBus/EC, no `MmCopyMemory`, no `MmMapLockedPages*` |

*End of report.*
