# Audit: Blackmagic capture driver group (Desktop Video 15.3.1)

| Field | Value |
|---|---|
| File(s) | `BlackmagicIO_64878EBE.sys`, `BlackmagicUsbIO_B48DF15C.sys`, `BMDNetwork_0DE46D82.sys`, `deckaud_D525B6F1.sys`, `deckavs_B89FCDA2.sys`, `decklink_458738A0.sys`, `deckser_65A92D8F.sys`, `multibridge_4F49016B.sys` (8 primary); 7 `*_legacy_*` variants compared only |
| SHA-256(s) | see section 10 (all 15 verified against `indexes/drivers_manifest.csv`) |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local Ghidra 12.1.4 headless (`C:\tools\ghidra_12.1.4_PUBLIC`), full auto-analysis + decompile-all for all 8 images, plus PE section/import/data-directory inspection. No load, service, registry, execution, or web. |
| Reach tier | **R3** (devnode/hardware). Device DACL is the I/O-manager default (no explicit SDDL, no access check) → admin-openable (**R2**) once the card is present; unprivileged open not established. |
| Setup required | **hardware** (DeckLink PCIe/USB device must be present; these are function drivers for the card's child devices) |
| Write quality | **W3** (fixed-target kernel page) for 3 files; **W0** for 5 files. No W1/W2/W3P established. |
| Verdict | **MW4 — fixed-target W3 only; no arbitrary kernel write, no caller-controlled physical address, no W2/W1.** Functionally `HW-ONLY` for the MMIO/DMA surface. |

> Provenance: all eight primary images and all legacy variants come from
> `Blackmagic_Desktop_Video_Windows_15.3.1.zip` (collected1/agentS4, `drv_DesktopVideoDrivers` and
> `drv_DesktopVideoDriversLegacy`). Primaries are `Valid`, signer
> `CN=Microsoft Windows Hardware Compatibility Publisher` (WHQL/attestation); legacy variants are
> `NotSigned`. None of the eight hashes is in `indexes/dedupe/known_bad_hashes.txt`.

---

## 1. Group internals (why one report)

The eight images are one product stack, not eight unrelated drivers:

| Image | Type | Role |
|---|---|---|
| `BlackmagicIO` | KMDF (static `WdfVersionBind` → `FxDriverEntryWorker`), ~2,625 functions | Main PCIe function/bus driver; IOKit-derived C++ object model (`IOPCIDevice`, `IOMemoryDescriptor`, `IOUserClient`), enumerates `DeckLink\AVStream`, `DeckLink\Audio`, `DeckLink\RS422` children |
| `decklink` | WDM, 969 functions | Legacy/full PCIe function driver with the same C++ runtime and the same 0x222xxx ABI |
| `BlackmagicUsbIO` | WDM USB function driver, 724 functions | USB DeckLink transport; same C++ runtime and ABI |
| `multibridge` | WDM USB function driver, 89 functions | Older USB product; reduced ABI |
| `deckser` | WDM serial-port function driver | `\Device\DeckLinkSerialN` + `\DosDevices\DeckLinkSerialN`, `FILE_DEVICE_SERIAL_PORT` (0x1b), standard serial IOCTLs |
| `deckavs` | AVStream/KS minidriver | `KsInitializeDriver`; capture pins/properties |
| `deckaud` | PortCls audio miniport | `PcInitializeAdapterDriver`; no device IOCTL surface |
| `BMDNetwork` | NDIS 6.80 miniport | NIC/DMA path; no device object |

`BlackmagicIO`, `BlackmagicUsbIO`, `decklink` and `multibridge` share a common private ABI
(`0x222000`–`0x2228xx`), which is why the same handlers appear in several images.

## 2. Entry / device / interface / effective DACL

| Image | Entry → DriverEntry | Device creation | Name / interface |
|---|---|---|---|
| `BlackmagicIO` | `0x140062400` → `FxDriverEntryWorker` | `IoCreateDevice` in `FUN_140008020` (type 0x22, **exclusive=1**, no name); KMDF FDO via framework | unnamed; interfaces/child services `DeckLink\AVStream`, `DeckLink\Audio`, `DeckLink\RS422` |
| `BlackmagicUsbIO` | `0x140031000` → `FUN_14001f784` | `FUN_14001dc50` → `IoCreateDevice(...,0x1c8,NULL,0x22,0,0,...)` | 3 interfaces (`DAT_140024c58/c48/c38`) + `\DeckLink` reference string |
| `BMDNetwork` | `0x14000e1b0` | none (NDIS miniport) | n/a |
| `deckaud` | `0x140008010` → `0x140008000` | `PcInitializeAdapterDriver` | KS/audio filter device |
| `deckavs` | `0x140013000` → `0x140002eb0` | `KsInitializeDriver` | AVStream filter device |
| `decklink` | `0x14025b000` → `0x140040bf0` | `FUN_140042ae0` → `IoCreateDevice(...,0x2898,NULL,0x22,0,0,...)` | 3 interfaces (`DAT_140052a38/a48/a58`) |
| `deckser` | `0x14000a180` → `0x14000a000` | `FUN_14000269c` → `IoCreateDevice(...,0x468,"\Device\DeckLinkSerial<N>",0x1b)`; `FUN_140002c8c` → `IoCreateSymbolicLink` | named device + `\DosDevices\DeckLinkSerialN` |
| `multibridge` | `0x140014000` → `0x140001000` | `FUN_140001274` → `IoCreateDevice(...,0x138,NULL,0x22,0,0,...)` | interface `DAT_140007170` |

**Effective DACL / open gate.** None of the eight images contains an explicit security
descriptor: no `IoCreateDeviceSecure`, no `WdfDeviceInitAssignSDDLString`, no `D:P(...)` literal,
and no `SeAccessCheck` / `SeSinglePrivilegeCheck` / `SeExports` import (verified by import scan and
string scan on all eight). The device objects therefore inherit the I/O manager's default device
security descriptor in the loading (PnP/SYSTEM) context — SYSTEM + Administrators full control.

Consequences:

* The gate is **local administrator (R2)**, not a driver-internal check. No image performs any
  caller-identity, privilege, or `FILE_WRITE_ACCESS` test in `IRP_MJ_CREATE` or in the IOCTL path.
* `deckser` is the only image with a directly openable `\DosDevices` link; the others are reached
  through device interfaces (SetupDi), which does not change the DACL.
* `BlackmagicUsbIO`'s create path allows a single client at a time (`FUN_14001d230`: rejects when
  `*FsContext != 0`), and `decklink` tracks an open flag at `FsContext2+0x10e`. These are
  exclusivity gates, not security gates.
* I did not dynamically confirm the resulting DACL; R1 is not claimed.

## 3. Dispatch and IOCTL surface (summary)

Full per-code decompilation is retained in `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\bmd\dumps\`
(`*_dec.txt`, `*_disp.txt`, `*_entry.txt`). Counts below are distinct `code == 0x...` comparisons
inside the dispatch function.

| Image | Dispatch | Major functions set | Codes | Method / sizes observed | Kernel action |
|---|---|---|---|---|---|
| `decklink` | DC `0x14003a7c0` | CREATE `0x14003a730`, CLOSE `0x14003a6d0`, READ/WRITE `0x14003f400` (**both complete STATUS_SUCCESS, no transfer**), DC `0x14003a7c0`, INTERNAL_DC `0x14003e010`, PNP `0x140042d90`, POWER `0x140044400` | ≈191 in `0x222000`–`0x222898` | Mostly `METHOD_BUFFERED`; `Type3InputBuffer` (`METHOD_NEITHER`) for a small set (`0x222403`, `0x22240f`, `0x22242b`, `0x222443`, `0x2224xx` frame descriptors) | settings blobs, ring-buffer push/pull, MMIO register read/write, DMA/stream control, one 4 KB page map (`0x222403`) |
| `BlackmagicIO` | UserClient method table `0x14005cf10` (vtable at file offset `0x763b8`) | KMDF queue → `0x14005cf10`; framework-bound EvtIo* | ≈53 in `0x222000`–`0x2220dc` | Buffered input/output retrieved with fixed per-code sizes (4/8/0x18/0x48/0x58/0x88/0xd0) | open/close, settings get/set, audio read/write, LUT, `performDMATransfer`, notifications, 4 KB page map (`0x2220bc`) |
| `BlackmagicUsbIO` | DC wrapper `0x14001de30` → per-open handler `0x14000ff80` | CREATE `0x14001d230`, DC `0x14001de30` | ≈152 in `0x222000`–`0x222898` | Buffered, plus `METHOD_NEITHER` `Type3InputBuffer` set (`0x222403`, `0x22240f`, `0x22241c`, `0x222443`, …) | USB control/bulk transfers, settings, stream, 4 KB page map (`0x222403`) |
| `multibridge` | DC `0x140001340` | CREATE `0x140001300`, CLOSE `0x1400012d0`, DC `0x140001340`, POWER `0x1400021d0`, PNP `0x1400020a0` | ≈79 in `0x222000`–`0x2225c5` | Buffered; length checks `3 < out`, `3 < in`; MDL (`METHOD_*_DIRECT`) for `0x222482` | USB transfers, settings, version/caps, stream via IRP MDL |
| `deckser` | DC `0x140001470` | CREATE `0x140002160`, CLOSE `0x140002030`, READ `0x140003b10`, WRITE `0x140004790`, DC `0x140001470`, INTERNAL_DC `0x1400013a0`, PNP/POWER | ≈37 serial codes `0x1b0004`–`0x1b009c` | Buffered, standard serial sizes | baud/line control/handflow/chars/queue size, FIFO data |
| `BMDNetwork` | NDIS miniport callbacks | n/a | OIDs only (network stack) | n/a | DMA scatter-gather, MMIO via `NdisMMapIoSpace` |
| `deckavs` | KS property/pin handlers | AVStream | KS property sets | ks.sys-validated | capture pin property I/O only |
| `deckaud` | PortCls miniport | n/a | none | n/a | audio streaming only |

Notable individual codes examined in detail:

* `decklink 0x222403` — `METHOD_NEITHER`; `Type3InputBuffer` is `ProbeForWrite`-ed for 8 bytes,
  then `FUN_14003f4e8` returns a **user VA of a 4 KB non-paged-pool page** and stores it through the
  caller's pointer. This is the only mapping-returning IOCTL on the image.
* `BlackmagicIO 0x2220bc` — 8-byte buffered output; `FUN_14005cde0` performs the same 4 KB page map
  for the calling user client.
* `BlackmagicUsbIO 0x222403` — same as `decklink` but the page is per-client (`FUN_14000fdb8`).
* `decklink 0x222154/0x22214c/0x222150` — push into a bounded circular buffer
  (`FUN_140044c88` stops at the ring limit pointers at `+0x10`/`+0x20`); caller length cannot
  overrun it.
* `deckser 0x1b004c` — `SET_QUEUE_SIZE`: rejects 0 and values `> 0xfffffff0`, then reallocates the
  RX/TX FIFOs (`FUN_140003a70`). Not a memory-write primitive.
* `BlackmagicIO 0x2220a0/0x2220a4` — 0x48-byte settings blobs; the setters use fixed struct copies.

## 4. Access-control audit

* No `SeSinglePrivilegeCheck`, `SeAccessCheck`, `IoCreateDeviceSecure`, SDDL string, or
  `FILE_WRITE_ACCESS`/`DesiredAccess` test anywhere in the eight images.
* No `ProbeForWrite`-less raw user pointer is dereferenced: the `Type3InputBuffer` uses in
  `decklink`/`BlackmagicUsbIO` are preceded by `ProbeForRead`/`ProbeForWrite` over the full strided
  range (e.g. `decklink 0x14003a7c0` at `0x22242b`: `ProbeForWrite(Type3, InputBufferLength, 1)`;
  `0x22243x` frame descriptor: `ProbeForRead(base, 1, 1)` then the last byte of the strided span).
* All remaining IOCTLs are `METHOD_BUFFERED`; lengths come from `IO_STACK_LOCATION+0x8/+0x10` and
  are compared to fixed constants before use.
* The gate is therefore the default device DACL (R2). No image is `BLOCKED`: all primary hashes are
  absent from the known-bad list, and the primaries carry a Microsoft WHQL/attestation signature.

## 5. Memory-write trace

### 5.1 `MmMapIoSpace` — 3 call sites, all device-resource driven, none user-controlled

| Site | Image | Argument source | Verdict |
|---|---|---|---|
| `FUN_140061e68` (`0x140061de4`) | `BlackmagicIO` | Enumerates a `CM_RESOURCE_LIST`-style descriptor array (`param_3`, from the framework start path, callers `0x14005f6c0`); type `0x03` entries are `MmMapIoSpace(*(u64*)(d+4), *(u32*)(d+0xc), 0)` | **HW-ONLY** fixed MMIO |
| `FUN_14004344c` (`0x14004344c`) | `decklink` | Called from `IRP_MJ_PNP`/`IRP_MN_START_DEVICE` (`0x140042d90` → `0x14004344c`); same descriptor array; special-cases a `0x100000` length, otherwise uses the descriptor length | **HW-ONLY** fixed MMIO |
| `FUN_14004344c` (second call) | `decklink` | Same descriptor, second BAR (`dev+0x120`) | **HW-ONLY** fixed MMIO |

No path passes a user-supplied physical address, length, cache type, or BAR index into
`MmMapIoSpace`. The mapping is performed once at start-device, stored in the device extension, and
is not re-programmable from an IOCTL. Register accesses through the mapping use fixed offsets in
helper routines; I found no `base + user_offset` index computation.

`MmMapIoSpace` is the only physical-mapping API in the group. There is **no** `MmCopyMemory`,
`ZwMapViewOfSection`, `\Device\PhysicalMemory`, or `MmGetPhysicalAddress`-to-write chain.
`BMDNetwork`'s single `MmGetPhysicalAddress` (`FUN_140004ef0`) converts an
`NdisGetDataBuffer` result for a TX scatter-gather list — NDIS-internal, not user-reachable.

### 5.2 `MmMapLockedPagesSpecifyCache` — MDLs, not caller physical addresses

All sites fall into three classes:

1. **IRP MDL for stream data** (normal): `multibridge` `FUN_140004a5c`/`FUN_140006318` map the
   `IRP->MdlAddress` with `AccessMode=KernelMode`, then copy device data into it; `decklink`
   `0x222689`/`0x222482` and `BlackmagicUsbIO 0x222689` do the same. Sizes are the IRP MDL byte
   count. No target control.
2. **Driver-owned buffer, kernel mapping** (`BlackmagicIO FUN_140004c80`, `FUN_140004d90`):
   `MmBuildMdlForNonPagedPool` + kernel map, for internal `IOMemoryDescriptor` copies; offset and
   length are bounds-checked against the descriptor length (`+0x20`).
3. **Driver-owned 4 KB page mapped into UserMode** (the only write-relevant class):
   * `decklink FUN_14003f4e8`: `IoAllocateMdl(dev+0x260, 0x1000, ...)` +
     `MmBuildMdlForNonPagedPool` + `MmMapLockedPagesSpecifyCache(Mdl, 1 /*UserMode*/, MmCached, …)`,
     cached at `FsContext2+0x978`; page allocated in `FUN_140046a70` as
     `ExAllocatePoolWithTag(0, 0x1000, 'Deck')`.
   * `BlackmagicIO FUN_14005cde0`: `IoAllocateMdl` over the user client's 0x50-byte buffer
     (`client+0x58`, `IOBufferMemoryDescriptor`), rounded to 0x1000, mapped `UserMode`.
   * `BlackmagicUsbIO FUN_14000fdb8`: identical pattern for the per-client buffer at `client+0x20`.

   In all three the returned *user* VA is handed back to the opener (IOCTL `0x222403` on
   `decklink`/`BlackmagicUsbIO`, `0x2220bc` on `BlackmagicIO`). The user may then write the page.
   The target is fixed (the driver's own allocation), the size is fixed (4 KB), and the content is
   the driver's DMA/command block (initialised with command byte `0xbd`). There is no way to make
   the call map a different page.

### 5.3 No kernel-VA write from caller data

No IOCTL in the eight images takes a kernel destination pointer. All output goes through
`SystemBuffer`, `MdlAddress`, or `Type3InputBuffer` after a probe. The only `FsContext`-derived
pointers used as stores are the driver's own per-open contexts.

### 5.4 Unresolved (recorded, not rated)

`BlackmagicIO`'s `UserClientClass::performDMATransfer` (`0x140015840`) and
`writeAudioSamples` (`0x140017050`) accept a 64-bit address + 32-bit length, build an
`IOMemoryDescriptor` via `0x140014f10` → `FUN_140004e10` → `FUN_140004c28`, and prepare it with
`MmProbeAndLockPages` (`FUN_140004cf0`). The MDL access mode is taken from a stored per-client flag
(`client+0x50`). I could not resolve that flag statically (the C++ vtable is built at runtime, and
the two vtables at file offsets `0x6d9f8`/`0x763b8` are populated by constructor code), so I cannot
prove whether the address is treated as user or kernel. If it is treated as kernel, the path would
be a W2 candidate (lock/DMA an arbitrary kernel VA). **Not established; not rated.** This is the
single residual worth a dynamic check.

## 6. Per-file results

| File | SHA-256 (prefix) | Role | Reach | Setup | Write quality | Verdict |
|---|---|---|---|---|---|---|
| `BlackmagicIO_64878EBE.sys` | `64878ebe…` | KMDF PCIe function/bus driver | R3 (R2 DACL) | hardware | **W3** (fixed 4 KB pool page → user, `0x2220bc`) + W0 otherwise | **MW4** (fixed-target, by design; no W2/W1) |
| `BlackmagicUsbIO_B48DF15C.sys` | `b48df15c…` | WDM USB function driver | R3 (R2 DACL) | hardware | **W3** (fixed 4 KB pool page → user, `0x222403`) + W0 otherwise | **MW4** (fixed-target, by design; no W2/W1) |
| `decklink_458738A0.sys` | `458738a0…` | WDM PCIe function driver | R3 (R2 DACL) | hardware | **W3** (device-wide 4 KB command page → user, `0x222403`) + W0 otherwise | **MW4** (fixed-target, by design; no W2/W1) |
| `multibridge_4F49016B.sys` | `4f49016b…` | WDM USB function driver | R3 (R2 DACL) | hardware | W0 (IRP-MDL transfers only) | **NO-MEMORY-WRITE** |
| `deckser_65A92D8F.sys` | `65a92d8f…` | serial-port function driver | R3 (R2 DACL) | hardware | W0 (serial registers/FIFO) | **NO-MEMORY-WRITE (HW-ONLY)** |
| `deckavs_B89FCDA2.sys` | `b89fcda2…` | AVStream capture minidriver | R3 | hardware | W0 | **NO-MEMORY-WRITE** |
| `deckaud_D525B6F1.sys` | `d525b6f1…` | PortCls audio miniport | R3 | hardware | W0 | **NO-MEMORY-WRITE** |
| `BMDNetwork_0DE46D82.sys` | `0de46d82…` | NDIS 6.80 miniport | R3 | hardware | W0 (DMA PA lookup only) | **NO-MEMORY-WRITE (HW-ONLY)** |

**Overall verdict: MW4 — fixed-target W3 only.** Three of eight images let an opener write a fixed
4 KB driver-owned page (MDL mapped read/write into the calling process); that is the lowest write
tier, by design, with no target or size control. Five of eight have no memory-write sink at all.
No image exposes `W3P`, `W2`, or `W1`: there is **no caller-controlled physical address, offset,
length, or value reaching a kernel mapping or store**, and no arbitrary kernel-VA write. If
by-design shared pages are excluded from the scale, the group is **NO-MEMORY-WRITE (HW-ONLY)**.

## 7. Legacy variants — dedupe result

All seven `*_legacy_*` images were compared by PE section hash, import table, and string set. For
every pair **every section is byte-identical** (`.text`, `.rdata`, `.data`, `.pdata`, `INIT`,
`.rsrc`, `.reloc`, plus paged sections where present). The only differences are:

* No Authenticode certificate table (`Security` data directory = 0, `NotSigned` in the collection
  manifest); the primary has a 10,456-byte table.
* Consequently a different PE checksum and file size, and the loss of the embedded Microsoft CA
  chain strings present in the signed primaries.

They are therefore **the same code, unsigned variants** — no material difference in the
memory-write surface. They are not separately rated; under HVCI/Secure Boot they are `BLOCKED`
(derived image, no signature), and any primitive they would carry is identical to the primary.

| Legacy file | SHA-256 (prefix) | Sections vs primary | Signature |
|---|---|---|---|
| `BlackmagicIO_legacy_96843A91.sys` | `96843a91…` | all identical | none |
| `BlackmagicUsbIO_legacy_598A6C3C.sys` | `598a6c3c…` | all identical | none |
| `deckaud_legacy_64B2CFAE.sys` | `64b2cfae…` | all identical | none |
| `deckavs_legacy_51CBC2F8.sys` | `51cbc2f8…` | all identical | none |
| `decklink_legacy_7EF358D7.sys` | `7ef358d7…` | all identical | none |
| `deckser_legacy_16F3AD97.sys` | `16f3ad97…` | all identical | none |
| `multibridge_legacy_93572ECE.sys` | `93572ece…` | all identical | none |

## 8. Most dangerous exposed capability

For an administrator with a DeckLink card installed: open the function device (default DACL),
issue `0x222403` (`decklink`/`BlackmagicUsbIO`) or `0x2220bc` (`BlackmagicIO`) to obtain a
read/write user mapping of the driver's 4 KB command/DMA page, then write that page.
That is a fixed-target kernel write with no way to redirect it. Everything else the IOCTL surface
offers is either a device register/settings operation (HW-ONLY) or a stream transfer into the
caller's own buffer.

## 9. Verdict and severity

`MW4 — reach=R3 setup=hardware write=W3 load=signed`

* Ceiling is `MW4` because three images have a real but fixed-target kernel-VA write.
* There is no `MW2`/`MW1` path: no arbitrary destination, no arbitrary value at an arbitrary
  address, no caller-controlled PA/length into `MmMapIoSpace`, no `\Device\PhysicalMemory` view.
* `MW3`/`W3P` does not apply: no user-writable physical mapping was found.
* Practical impact of the MW4 residual is nil beyond the driver's own DMA/command page; it is a
  designed shared-memory mechanism, not a corruption primitive.
* The group is **not** `BLOCKED`: primaries are WHQL/attestation-signed and absent from the
  known-bad list.

## 10. Hashes (verified)

| File | SHA-256 |
|---|---|
| `BlackmagicIO_64878EBE.sys` | `64878EBE6F4E0E8EC2B6690F5A5E14F6BA3C53C3C7DC122D7B50B8597E3B335E` |
| `BlackmagicUsbIO_B48DF15C.sys` | `B48DF15CC141F8C602EEFF7E3970EF55DDD74570AD9692D549A272F27DD7E716` |
| `BMDNetwork_0DE46D82.sys` | `0DE46D8290CEFBCAE012A06ACE5EB25E4010D628C6E0B3849AC25B3B261B5982` |
| `deckaud_D525B6F1.sys` | `D525B6F19557D07E5DB1ECB3F1024C26698C01C9348985DE9D87970652D32D33` |
| `deckavs_B89FCDA2.sys` | `B89FCDA2F8F705A5CADBE5FE01B5CAFBF96D11289083E6ECE48095867D596D98` |
| `decklink_458738A0.sys` | `458738A0E0F377A0881EF31963F76DC3FEA66CACEAD26BD87A6B1F85B027AFF3` |
| `deckser_65A92D8F.sys` | `65A92D8FBC11CA1AB54A39ADD0FEBEA8222CF7EEE2D598DF46AB878D7E0B248D` |
| `multibridge_4F49016B.sys` | `4F49016BA5BA91FB45BF8CF63F3215EEF3CAD82A45F165A42A836FD993A3AFF2` |
| `BlackmagicIO_legacy_96843A91.sys` | `96843A91EB49BB7CF74FCB6EE35978E70783531167C1FDBDEC3614D10F4863FC` |
| `BlackmagicUsbIO_legacy_598A6C3C.sys` | `598A6C3C5A4498EFDC442796BBC6B8A815425DD5666C673779A4A005DB9A660A` |
| `deckaud_legacy_64B2CFAE.sys` | `64B2CFAEE6D3C09447BBF1E652ABB2154ACA4EA6FF895D9C5EB053ADDE7B779E` |
| `deckavs_legacy_51CBC2F8.sys` | `51CBC2F8E6A4F1BBCE7FBBFC831E2B30BB0AF71C03CF4A635826D2A9597B7ABC` |
| `decklink_legacy_7EF358D7.sys` | `7EF358D7693733C17376B61F9F8A66D01FEB3B0330AF7D7229D2A7A702707D2D` |
| `deckser_legacy_16F3AD97.sys` | `16F3AD97F77591A9DC58E8E77146618A6A481296FA231FAB1BAD8DF8D0877002` |
| `multibridge_legacy_93572ECE.sys` | `93572ECE270C2A5BA3B8611F0049A9EB5699016B6FC192351488FDCD88109808` |

## 11. Limitations

1. **REA** was reachable (its provider is Ghidra 12.1.4) but the shared bridge had three other
   audits active; I used local Ghidra 12.1.4 headless only. No foreign-binary contamination and no
   provider gap; all evidence is from the local images above.
2. **KMDF binding.** `BlackmagicIO` imports only `WdfVersionBind`/`WdfVersionUnbind`; the framework
   callbacks are reached through `FxDriverEntryWorker` and a runtime function table, so the
   EvtDriverDeviceAdd/EvtIoDeviceControl binding could not be named symbolically. The UserClient
   method table and its 53 IOCTL comparisons were resolved directly.
3. **C++ vtable resolution.** `BlackmagicIO`'s IOKit-derived classes build their vtables at runtime;
   two absolute-pointer tables at file offsets `0x6d9f8`/`0x763b8` were used to anchor the user
   client methods. The per-client access-mode flag at `client+0x50` (used by
   `IOMemoryDescriptor::withAddress` at `0x140004e10`/`FUN_140004c28`) is unresolved — see section 5.4.
4. **DMA command page semantics.** Whether the fixed 4 KB page's contents can program the device's
   DMA engine to an arbitrary bus address is a hardware-behaviour question; the DMA programming
   path runs through indirect framework calls. This is the only route by which the MW4 residual
   could rise to W3P/MW3; it was not established statically.
5. **DACL** was reasoned from the absence of an explicit descriptor and the loader context, not
   from a live `!devobj`/`GetSecurityInfo` read (static-only rule). R1 is not claimed.
6. `BMDNetwork`'s NDIS OID handlers were reviewed at import/callback level only; NDIS OIDs are
   not a user-mode IOCTL surface.
