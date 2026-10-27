# Audit: SteelSeries `msihid` and `sssmbus` families (12 builds)

**Scope re-audit - kernel memory-write only.** This report supersedes the `msihid`/`sssmbus`
sections of `steelseries_hid.static.md` for the exact builds listed below. It does **not** modify
that historical report or `audits/STATUS.md`.

| Field | Value |
|---|---|
| File(s) | `drivers\msihid_3CBA25FA.sys`, `msihid_60473311.sys`, `msihid_929EF572.sys`, `msihid_A25F3CEC.sys`, `msihid_A9D1B251.sys`, `msihid_C81DE3C9.sys`, `msihid_FBA136DD.sys`, `drivers\sssmbus_1091D873.sys`, `sssmbus_1F2F26E5.sys`, `sssmbus_57D26E85.sys`, `sssmbus_7B4435F8.sys`, `sssmbus_CD4B9402.sys` |
| SHA-256(s) | See per-file table, section 7 (all 12 verified; file names match the first 8 hex digits) |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local Ghidra 12.1.4 headless decompilation (`DumpAll.java`, all functions), `llvm-objdump` 18 (msys64) disassembly, and direct PE/UNICODE_STRING/SDDL parsing. **REA cross-check was not used because four REA audits are already active (capacity limit).** No driver was loaded, executed, installed, or registered. No web access. |
| Reach tier | `R1` for the `msihid` control device (Everyone `GRGW`). `sssmbus` is also Everyone-openable (`GRGWGX`) but exposes **no user-mode dispatch path**; its only IOCTL handler is `EvtIoInternalDeviceControl` (kernel callers only). |
| Setup required | `service` for `msihid` (control device is created unconditionally in `DriverEntry`; the HID child path additionally needs the devnode/hardware). `devnode` for `sssmbus` (PnP FDO on the SMBus controller node). |
| Write quality | `W0` - no kernel memory write in any of the 12 builds |
| Verdict | **NO-MEMORY-WRITE** (both families). No MW1-MW4. `sssmbus` carries a `HW-ONLY` SMBus/port-I/O capability that is **not reachable from user mode** in these images. Five i386 images are additionally `BLOCKED` for x64 load. |

---

## 1. Short answer

No build in either family contains a kernel memory-write primitive reachable with local-admin
(or unprivileged) access.

* **`msihid`** creates a real control device `\Device\steelseries_msihid` with an explicit,
  protected SDDL that grants **Everyone `GENERIC_READ|GENERIC_WRITE`**. All 16 control IOCTLs are
  `METHOD_BUFFERED`, `FILE_ANY_ACCESS`, fixed-size, and write only into the WDF request's system
  buffer or into the driver's own device context. No caller-chosen kernel destination, no
  caller-controlled copy length, no `METHOD_NEITHER` on the user-reachable queue, and no
  memory-mapping API. One secondary issue exists: `0xC0DE0030` sets the completion Information to
  the caller's output length while initialising only `0x50` bytes, which can disclose
  uninitialized system-buffer/pool bytes (info leak, out of scope; see section 5.1).
* **`sssmbus`** has an SDDL-protected FDO `\SSSMbus` with an interface GUID and an Everyone
  `GRGWGX` DACL, but its only queue callback is registered at
  `WDF_IO_QUEUE_CONFIG.EvtIoInternalDeviceControl` (+0x30), **not** `EvtIoDeviceControl` (+0x28).
  The single IOCTL `0x222800` therefore cannot be issued with `DeviceIoControl`; it is a
  kernel-internal SMBus transaction interface. The transaction itself is `HW-ONLY` (SMBus byte
  writes via the ACPI SMBus interface and port I/O; PCI config via `0xCF8/0xCFC`), with no
  `MmMapIoSpace`, no MDL, and no kernel-memory destination.

The material correction to the historical report is the `sssmbus` reachability: it described
`0x222800` as an unprivileged arbitrary-SMBus-write path and as `FILE_WRITE_ACCESS`. Both are
wrong for these builds - the access field is `FILE_ANY_ACCESS` and the handler is internal-only.

---

## 2. Inventory and build relationships

Section-hash comparison (SHA-256 of each PE section) shows two exact code duplicates:

| Group | Files | Relationship |
|---|---|---|
| x64 `msihid` 2.6.3.0 | `3CBA25FA` | Newest; MS WHCP-signed; adds `0xC0DE003C` and HID codes `0xB000F/0xB002B/0xB0195/0xB0263` |
| x64 `msihid` 2.5.0.0 | `60473311` (2020-09) | SteelSeries-signed; 15 IOCTLs (no `0xC0DE003C`) |
| x64 `msihid` 2020-07 | `929EF572` = `A25F3CEC` | Identical `.text`/`.rdata`/`.data`; different signature blob only |
| i386 `msihid` 2.5.0.0 | `A9D1B251` | 32-bit; same design; not loadable on x64 |
| i386 `msihid` 2020-07 | `C81DE3C9` = `FBA136DD` | Identical code; 32-bit |
| x64 `sssmbus` 1.2.2.0 | `1091D873` | Newest; MS WHCP-signed |
| x64 `sssmbus` 2019 | `57D26E85` | Same device/SDDL/IOCTL; older KMDF layout |
| x64 `sssmbus` 2017 | `7B4435F8` | Same device/SDDL/IOCTL; uses global KMDF table |
| i386 `sssmbus` 2017/2019 | `1F2F26E5`, `CD4B9402` | 32-bit; port I/O; not loadable on x64 |

All 12 images have a **valid Authenticode signature** (`Get-AuthenticodeSignature` = `Valid`).
None of the 12 SHA-256 values is in `indexes\dedupe\known_bad_hashes.txt`. `3CBA25FA` and
`1091D873` are signed by *Microsoft Windows Hardware Compatibility Publisher*; the older builds are
signed by *SteelSeries ApS*.

---

## 3. `msihid` - SteelSeries MSI HID driver

### 3.1 Entry, device, interface

All x64 builds follow the same `DriverEntry` -> `WdfControlDeviceInitAllocate` -> named control
device + DOS symlink -> `WdfIoQueueCreate` pattern, then an `EvtDeviceAdd` path for the PnP HID FDO.

`msihid_3CBA25FA.sys` (`DriverEntry` `0x14000A000`):

```
14000A150  LEA R8,[0x140007278]          ; UNICODE_STRING: SDDL "D:P(A;;GA;;;SY)..."
14000A15A  MOV R9,[RCX+0xC8]             ; WdfControlDeviceInitAllocate
14000A16B  CALL guard_dispatch_icall
14000A1BF  ... +0x218                    ; WdfDeviceInitAssignName("\Device\steelseries_msihid")
14000A1F1  ... +0x258                    ; WdfDeviceCreate
14000A220  ... +0x280                    ; WdfDeviceCreateSymbolicLink("\DosDevices\steelseries_msihid")
14000A265  MOV [RBP-0x78],0x14000A380    ; queue config +0x28 = EvtIoDeviceControl
14000A290  ... +0x4C0                    ; WdfIoQueueCreate
```

The same call sites exist at `0x140009150`/`0x140009380` (`60473311`) and
`0x14000A13E`/`0x14000A330` (`929EF572`, `A25F3CEC`). The i386 builds build the same two names
from wide-string literals (`0x00407A24`/`0x00407A5A` in `A9D1B251`).

The SDDL `UNICODE_STRING` is live in every build: it is passed as the second argument to the
`+0xC8` control-device-init allocator, and the returned init is the object that is named and
created.

There is **no** `WdfDeviceCreateDeviceInterface` call for the control device; reach is by
`\DosDevices\steelseries_msihid` (i.e. `\\.\steelseries_msihid`). The PnP HID FDO created later is
unnamed and has no symlink/interface; user access to it is only through `hidclass`.

`msihid_3CBA25FA` imports only:
`DbgPrintEx, ExEventObjectType, KeQueryPerformanceCounter, KeSetEvent, ObfDereferenceObject,
ObReferenceObjectByHandle, RtlCopyUnicodeString, sqrt, WdfVersionBind,
WdfVersionBindClass, WdfVersionUnbind, WdfVersionUnbindClass, WdfLdrQueryInterface`.
There is no `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`,
`MmGetPhysicalAddress`, `KeStackAttachProcess`, or `ProbeForWrite`. The older x64 builds add only
`memset`/`RtlGetVersion`/`KeBugCheckEx`.

### 3.2 Effective DACL and open gate

Variant A, identical in all seven builds:

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)
```

| SID | Rights |
|---|---|
| `SY` (LocalSystem) | `GA` (all) |
| `BA` (Builtin Administrators) | `GRGWGX` (generic read/write/execute) |
| `WD` (Everyone) | **`GRGW` (generic read + generic write)** |
| `RC` (Restricted Code) | `GR` (generic read) |

`P` = protected DACL; no inherited ACE can tighten it. There is no `SeAccessCheck`,
`SeSinglePrivilegeCheck`, caller-identity test, or auth handshake anywhere in the control path.
**Any local user can open the control device for read/write** (`R1`). The `GRGW` grant does not
include execute, but every IOCTL in the table is `FILE_ANY_ACCESS`, so write access is sufficient.

### 3.3 Dispatch and IOCTL table (control device)

`EvtIoDeviceControl = FUN_14000A380` (config offset +0x28, verified against the WDK
`WDF_IO_QUEUE_CONFIG` layout for KMDF 1.11-1.33: `EvtIoDeviceControl` at +0x28,
`EvtIoInternalDeviceControl` at +0x30, struct size `0x60`). Dispatch signature is
`(Queue, Request, OutputBufferLength, InputBufferLength, IoControlCode)`; all codes are
`METHOD_BUFFERED`, `FILE_ANY_ACCESS`, device `0xC0DE`:

| IOCTL | Fn | Method | Access | Size gate | Kernel action |
|---|---|---|---|---|---|
| `0xC0DE0000` | 0x000 | BUFFERED | ANY | none | `DAT_1400083C0 = 0` (macro-engine disable) |
| `0xC0DE0004` | 0x001 | BUFFERED | ANY | none | `DAT_1400083C0 = 1` |
| `0xC0DE0008` | 0x002 | BUFFERED | ANY | in >= `0x814` | VID/PID lookup; require `*(u32*)(in+0x10) < 0x101`; copy exactly `0x814` into a `WDFMEMORY`; send to child HID target (`FUN_1400014B8`, `0x140003F38`) |
| `0xC0DE000C` | 0x003 | BUFFERED | ANY | in >= `0x10` | per-device descriptor; fixed-offset writes in context (`FUN_1400017CC`) |
| `0xC0DE0010` | 0x004 | BUFFERED | ANY | in >= 4 | VID/PID match -> reset child (`FUN_140001668`, `FUN_140004100`) |
| `0xC0DE0014` | 0x005 | BUFFERED | ANY | in >= `0x38` | 10-dword (40-byte) fixed copy into `dev+0x168+0x38` (`FUN_140001CB8` -> `FUN_14000529C`) |
| `0xC0DE0018` | 0x006 | BUFFERED | ANY | in >= `0x38` | per-device config, fixed offsets (`FUN_140001FC8`) |
| `0xC0DE001C` | 0x007 | BUFFERED | ANY | in >= `0x14` | per-device config (`FUN_14000215C`) |
| `0xC0DE0020` | 0x008 | BUFFERED | ANY | in >= `0x18` | per-device config (`FUN_140001ED0`) |
| `0xC0DE0024` | 0x009 | BUFFERED | ANY | in >= `0x18` | per-device config (`FUN_140001E4C`) |
| `0xC0DE0028` | 0x00A | BUFFERED | ANY | in >= `0x18` | VID/PID + byte into context (`FUN_140001F54`) |
| `0xC0DE002C` | 0x00B | BUFFERED | ANY | in >= 8 | `ObReferenceObjectByHandle(ExEventObjectType)`; stores referenced event in a global (`FUN_140001C58`) |
| `0xC0DE0030` | 0x00C | BUFFERED | ANY | out >= `0x50`, in >= `0x50` | zero `0x50` bytes of the input buffer, write <=10 status records, `WdfRequestSetInformation(OutputBufferLength)` (`FUN_140001BB4`, `0x140001C42`); see section 5.1 |
| `0xC0DE0034` | 0x00D | BUFFERED | ANY | none | enumerate child devices (`FUN_140001AC0`) |
| `0xC0DE0038` | 0x00E | BUFFERED | ANY | in >= `0x814` | select last child, copy exactly `0x814` into a `WDFMEMORY` (`FUN_140001960`) |
| `0xC0DE003C` | 0x00F | BUFFERED | ANY | in >= `0x10` | per-device config at `dev+0x168+0x2C8` (`FUN_1400022F0`) - **2.6.3.0 only** |

`0xC0DE003C` is present only in `3CBA25FA`. The 2.5.0.0/2020 builds expose 15 codes; the missing
code is not a security difference.

### 3.4 HID-side IOCTLs (internal only)

`FUN_140002660` is stored at queue-config **+0x30** in the child FDO's queue
(`0x14000A7F2` in `3CBA25FA`; the queue is created at `0x14000A838`). That is
`EvtIoInternalDeviceControl`, not `EvtIoDeviceControl`. These codes are produced by the HID class
stack (`hidclass`) and are **not reachable through the named control device**.

| IOCTL | Fn | Method | Handler | Action |
|---|---|---|---|---|
| `0xB0003` | 0x000 | NEITHER | `FUN_14000564C` | copy fixed 9 bytes from `0x1400071E8` into output memory |
| `0xB0007` | 0x001 | NEITHER | `FUN_1400056F0` | copy fixed `0xA7` bytes from `0x140007140` into output memory |
| `0xB000B` | 0x002 | NEITHER | `FUN_140005794` | complete/flag only |
| `0xB000F` | 0x003 | NEITHER | `FUN_140003198` | build and send an IOCTL to the HID target |
| `0xB0027` | 0x009 | NEITHER | `FUN_1400030C0` | require `0x20` input; write `0x20`-byte attribute block into it |
| `0xB002B` | 0x00A | NEITHER | `FUN_140003198` | as `0xB000F` |
| `0xB0191` | 0x064 | IN_DIRECT | - | no-op success |
| `0xB0192` | 0x064 | OUT_DIRECT | - | no-op success |
| `0xB0195` | 0x065 | IN_DIRECT | `FUN_140003198` | as `0xB000F` |
| `0xB01A2` | 0x068 | OUT_DIRECT | `FUN_140005794` | complete/flag only |
| `0xB0263` | 0x098 | NEITHER | `FUN_140003198` | as `0xB000F` |

`0xB000F/0xB002B/0xB0195/0xB0263` are new in `3CBA25FA`; the 2020 builds expose
`0xB0003/7/B/27/191/192/1A2`.

The output copies are done with `WdfRequestRetrieveOutputMemory` + `WdfMemoryCopyFromBuffer`
(+0x860/+0x628 in `FUN_14000564C`), so KMDF validates the memory-object size. The size is a
compile-time constant (9 / `0xA7` / `0x20`). There is no `ProbeForWrite`/`ProbeForRead` import and
no raw user pointer dereference. For a future build that exposed these codes on
`EvtIoDeviceControl`, the fixed-size copies should be re-checked dynamically, but in these builds
the buffers are kernel-owned.

### 3.5 Access control and memory-write trace

* No `SeAccessCheck`, no privilege check, no service/pid allow-list in any handler.
* The control-device path is `METHOD_BUFFERED` end to end. `WdfRequestRetrieveInputBuffer` is
  called with a fixed minimum (4, 8, `0x10`, `0x14`, `0x18`, `0x38`, `0x50`, `0x814`). No handler
  uses a caller-supplied length as a copy count. No handler uses a caller-supplied value as a
  destination pointer.
* `FUN_14000468C` copies at most 10 x 8 bytes from a driver global ring (count capped at 10) into
  a `0x50`-byte buffer.
* `FUN_1400048D0`/`FUN_140003F38` allocate a `WDFMEMORY` of exactly `0x814` and copy `0x814`
  bytes from the already-length-checked input into it.
* In the 2020 x64 builds, `FUN_140002590` `memset`s a WDF-memory allocation with the same length
  value returned by its allocator (`local_res8[0]`), and a second fixed `0x88` object.
* The macro engine (`FUN_1400037C0`) opens with `if (DAT_1400083C0 != 0)` - i.e. only after
  `0xC0DE0004` - parses the `0x814` block uploaded by `0xC0DE0008`, and writes only to fixed
  context offsets (`+0x38/+0x47/+0x4C/+0x70/+0x94/...`) or fixed 4-byte key-state arrays. Macro
  entry counts/indices can drive **out-of-bounds reads** of the WDF memory, not writes.
* The HID input-report parser `FUN_1400027C0` switches on the report length (6/8/9/`0x10`/
  `0x20`/`0x28`/`0xC`) and reads only within the supplied length (except the vendor usage
  `0x472/0x475` branch, which reads 8 bytes without a length test - again a read).

**Result: no kernel memory write.** Caller-controlled data reaches (a) the WDF request's
system buffer via fixed-size copy-back, (b) driver context fields at fixed offsets, and (c) HID
report buffers owned by the driver. There is no write-what-where, no OOB write, and no
kernel destination chosen by the caller.

### 3.6 Build comparison (material differences only)

| Build | Difference | Memory-write impact |
|---|---|---|
| `3CBA25FA` (2.6.3.0) | adds `0xC0DE003C`; adds four HID codes; `0xC0DE0030` zeroes the input buffer before filling status | none; same fixed-size model; the `0x30` info-leak pattern is present in all x64 builds |
| `60473311` (2.5.0.0) | handler addresses differ; 15 control codes | none |
| `929EF572` = `A25F3CEC` | identical code, different signature | none |
| `A9D1B251`, `C81DE3C9` = `FBA136DD` | i386 | not loadable on x64 -> `BLOCKED`; same W0 design |

---

## 4. `sssmbus` - SteelSeries SMBus interface

### 4.1 Entry, device, interface

`DriverEntry` `0x140002AAC` -> `FxDriverEntryWorker` -> client entry `0x1400017F8` ->
`EvtDriverDeviceAdd = FUN_1400018A0`. The FDO is created in `FUN_1400018A0`:

| Item | Value | Evidence (`sssmbus_1091D873`) |
|---|---|---|
| Device type | `0x22` (`FILE_DEVICE_UNKNOWN`) | `+0x210` call, `0x140001957` |
| SDDL | variant B | `LEA R8,[0x140004238]` at `0x1400019F1`; call `+0x220` at `0x140001A0B` |
| SDDL string | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)` | `UNICODE_STRING` at `0x140004238`, `Length=0x7E`, buffer `0x140004250` |
| Device | unnamed PnP FDO | `WdfDeviceCreate` `+0x258`, `0x140001A7B` |
| Symlink | `\SSSMbus` (8 chars, `Length=0x10`) | string at `0x140003200`; `WdfDeviceCreateSymbolicLink` `+0x280`, `0x140001BE3` |
| Interface | `{8AFF2D8C-E4EF-4907-B9F4-12D54B104B4C}` | `+0x268`, `0x140001BB6`; GUID at `0x1400040F0` |
| Queue | `WdfIoQueueCreate` `+0x4C0` | `0x140001C48`; `EvtIoInternalDeviceControl` stored at `0x140001C21` (config +0x30) |

The same SDDL/name/interface/queue pattern is present in `57D26E85` (device add `0x140001904`,
SDDL call `0x140001A41`, callback store `0x140001C5C`) and `7B4435F8` (device add `0x1400018D8`,
SDDL call `0x1400019FD`, callback store `0x140001BF0`). All three x64 builds use the same
interface GUID.

Imports (`1091D873`): `_vsnwprintf, DbgPrintEx, IoRegisterPlugPlayNotification,
IoUnregisterPlugPlayNotification, KeDelayExecutionThread, RtlCopyUnicodeString,
WdfVersionBind, WdfVersionBindClass, WdfVersionUnbind, WdfVersionUnbindClass,
WdfLdrQueryInterface`. No memory-mapping imports.

### 4.2 Effective DACL and open gate

Variant B:

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)
```

`WD` (Everyone) receives `GRGWGX`. The DACL is protected. The device is reachable as
`\GLOBALROOT\SSSMbus` and through the interface GUID above; a standard user can open it.

**However, opening it does not expose the IOCTL.** The only queue callback is
`EvtIoInternalDeviceControl`. A user-mode `DeviceIoControl` produces `IRP_MJ_DEVICE_CONTROL`;
KMDF looks up `EvtIoDeviceControl` (+0x28), which is `NULL`, and completes the request with
`STATUS_INVALID_DEVICE_REQUEST` (there is no `EvtIoDefault` and no read/write callback either).
Only a kernel caller can send `IRP_MJ_INTERNAL_DEVICE_CONTROL` to this device.

Queue-layout verification (WDK `wdfio.h`, KMDF 1.11-1.33): `Size=0x60`, `DispatchType` +0x04,
`PowerManaged` +0x08, `DefaultQueue` +0x0D, `EvtIoDefault` +0x10, `EvtIoRead` +0x18,
`EvtIoWrite` +0x20, `EvtIoDeviceControl` +0x28, `EvtIoInternalDeviceControl` +0x30,
`Settings.Parallel.NumberOfPresentedRequests` +0x50. The driver writes `0x60` to +0x00,
`-1` to +0x50, and `FUN_140001EB0` to +0x30. As a control, the `msihid` control device stores its
handler at +0x28 in the same structure and is therefore `EvtIoDeviceControl`.

### 4.3 IOCTL table (internal-only)

| IOCTL | Fn | Method | Access | Size gate | Kernel action |
|---|---|---|---|---|---|
| `0x222800` | 0xA00 | BUFFERED | **ANY** (`0x222800 & 0xC000 == 0`) | `WdfRequestRetrieveInputBuffer(Request, min(InputBufferLength, 0x189), ...)` | `FUN_140002000` parses the input and performs SMBus byte transactions |

`0x222800` is `CTL_CODE(0x22, 0xA00, METHOD_BUFFERED, FILE_ANY_ACCESS)`. The historical report's
`FILE_WRITE_ACCESS` label is incorrect.

### 4.4 `0x222800` path and the SMBus primitive

`FUN_140001EB0` (`0x140001EB0`) gets the queue's device context and calls
`FUN_140002000` (`0x140002000`) with the retrieved input buffer. The parser:

1. Tests `(*in & ctx->mask) == 0`; returns success if the mask has no overlap.
2. Byte at `in+4` selects an opcode 0-7:
   * `0`: `addr = in[5]`, `reg = in[6]`, `val = in[7]` -> one SMBus byte write.
   * `1`: writes `ctx->capability_mask = *(u32*)(in+5) | 1` (caller can widen its own mask).
   * `2`: `ctx->default_addr = in[5]`.
   * `3`: block write, count `in[5]`, register/data bytes at `in+6/7` and `in+2`.
   * `4`: dword at `in+5` split into registers `0x80/0x81/0x82`, data `0x88/0x89/0x8A`.
   * `5`: reset sequence (`0x9F=0`, `0x80=0xFF`, `0x81=0xFF`, `0x8A=0xFF`).
   * `6`: commands `0x9F`, `0xF4`.
   * `7`: loop `count = *(u32*)(in+5)`, 4-byte entries at `in+9+4i`, writing registers
     `0x80/0x81/0x82`, data `0x88/0x89/0x8A`.
3. Each write calls `FUN_1400012E0` -> `FUN_140001314(iface, addr, 0, reg, 2, &val)`.
   `iface` is the driver's static interface block at `0x140005000`, populated in
   `FUN_1400018A0`/`FUN_140001D70`; `[iface+0x10] = FUN_140001420` performs the actual
   transaction and `[iface+0x20]` is a spin lock. The address, register and data all come from the
   IOCTL buffer.

`FUN_140001420` (`0x140001420`) drives the SMBus controller with `in`/`out` instructions at
`*iface` (the I/O-port base from the PnP resource list), with the protocol byte selecting
quick/byte/block transfers. `FUN_1400011A0`/`FUN_1400011E0`/`FUN_140001214` additionally perform
PCI configuration reads/writes through `0xCF8/0xCFC` (used to locate/fix up the controller), and
`FUN_1400013E0` clears a PCI status bit. These are `HW-ONLY` operations.

**This is not a kernel memory write.** It cannot target kernel VA, cannot be redirected to a
pointer, and does not use `MmMapIoSpace`/MDLs. It is an SMBus transaction to a caller-chosen 7-bit
address and register.

### 4.5 Length and output validation

* The retrieve call uses `min(InputBufferLength, 0x189)` as the **minimum required size**, so a
  short input (e.g. 1 byte) is accepted; the parser then reads `in+1` ... `in+0xB` and, for opcode 7,
  up to `in+9+4*count` without re-checking the length. That is a kernel **out-of-bounds read** of
  the system buffer (the values go to hardware, not back to the user).
* Opcode 7's count is an unvalidated 32-bit value; a large count makes the driver loop issuing
  SMBus writes and reading past the buffer (DoS/potential crash), still not a memory write.
* The handler never uses an output buffer and never calls `WdfRequestSetInformation`; completion is
  status-only. There is no output-length or user-pointer path, and no `METHOD_NEITHER`.

### 4.6 Build comparison (material differences only)

| Build | Difference | Memory-write impact |
|---|---|---|
| `1091D873` (1.2.2.0) | 2025 MS-signed; SDDL/interface/queue as above; `min(len,0x189)` gate; port I/O inline | none |
| `57D26E85` (2019) | same device/SDDL/IOCTL, older KMDF call layout, explicit `memset` | none |
| `7B4435F8` (2017) | same device/SDDL/IOCTL, global KMDF table | none |
| `1F2F26E5`, `CD4B9402` | i386; port I/O + `memset`; same SMBus opcode model | `BLOCKED` (i386); static W0 |

The i386 builds are not loadable on the x64 target and cannot be treated as a live primitive.

---

## 5. Secondary findings (not memory writes)

### 5.1 `msihid` `0xC0DE0030` - uninitialized system-buffer disclosure

`FUN_140001BB4` (all x64 builds) checks `OutputBufferLength >= 0x50`, retrieves the **input**
buffer with a minimum of `0x50`, zeroes `0x50` bytes, writes up to `0x50` bytes of status records,
then calls `WdfRequestSetInformation(Request, OutputBufferLength)` (`0x140001C42`) before the
dispatcher completes the request with success.

For a `METHOD_BUFFERED` request, the I/O manager allocates one system buffer of
`max(InputBufferLength, OutputBufferLength)`. If a caller supplies `InputBufferLength = 0x50` and
`OutputBufferLength > 0x50`, the tail of the system buffer was never initialised by the driver and
is copied back to the caller. This is a static, plausible **kernel pool information disclosure**
(and a KASLR-leak candidate), but it is not a memory write and does not change the `W0` verdict.
It was not dynamically confirmed.

### 5.2 `sssmbus` short-buffer OOB read

As in section 4.5: the `min(len,0x189)` minimum and the unvalidated opcode-7 count produce an OOB read of
the system buffer. Values read are used to program the SMBus controller; they are not returned to
the caller. DoS/OOB-read only.

### 5.3 Device-name / reachability note

`sssmbus` publishes `\SSSMbus` in the object-manager root and the interface GUID, so a user can
obtain a handle. The handle is inert for `IRP_MJ_DEVICE_CONTROL`/READ/WRITE. This is easy to
misread as an unprivileged SMBus primitive; the queue callback offset is the deciding evidence.

---

## 6. HW-ONLY vs kernel memory write

| Capability | Where | Reachable from user mode? | Classification |
|---|---|---|---|
| SMBus byte/block write to caller-chosen address/register/data | `sssmbus` `0x222800` -> `FUN_140002000` -> `FUN_140001420` | **No** - `EvtIoInternalDeviceControl` only | `HW-ONLY` (kernel-internal) |
| SMBus controller port I/O (`in`/`out` at I/O BAR) | `sssmbus` `0x140001420` | No (internal helper) | `HW-ONLY` |
| PCI config read/write via `0xCF8/0xCFC` | `sssmbus` `0x1400011A0/11E0/1214` | No (internal helper) | `HW-ONLY` |
| MSR access | none | - | - |
| MMIO mapping / `MmMapIoSpace` | none in either family | - | - |
| MDL / physical-memory mapping | none in either family | - | - |
| Kernel memory write | none | - | - |

No chain from the SMBus/port-I/O capability into a kernel memory write was found: the driver never
uses a caller value as a kernel pointer, never maps physical memory, and never writes through a
pointer derived from hardware data.

---

## 7. Per-file verdicts

All SHA-256 values were recomputed from the exact files in `drivers\`. `Arch` is the PE machine
(`0x8664` = x64, `0x14c` = i386).

| # | File | Arch | Version | SHA-256 | Surface / DACL | W | Verdict |
|---:|---|---|---|---|---|---|---|
| 1 | `msihid_3CBA25FA.sys` | x64 | 2.6.3.0 | `3CBA25FA5E4EACFBC538C40090EF96C851FCCDE3D907454C0E4DB6A37EF7F1C0` | `\Device\steelseries_msihid` + DOS link; Everyone `GRGW` (A) | W0 | **NO-MEMORY-WRITE** |
| 2 | `msihid_60473311.sys` | x64 | 2.5.0.0 | `604733110C104AF46097D05462677C3C2A26FAB8EE78F2DF1B9C99D345C79D8C` | same; Everyone `GRGW` (A) | W0 | **NO-MEMORY-WRITE** |
| 3 | `msihid_929EF572.sys` | x64 | 2020-07 | `929EF5728E6A089B310D93584AD95EF6A8BA3B5FA4D613BF8600F2534881FF73` | same; Everyone `GRGW` (A) | W0 | **NO-MEMORY-WRITE** |
| 4 | `msihid_A25F3CEC.sys` | x64 | 2020-07 | `A25F3CEC3AD7FD137473F3749749FE587B9B43030D931C24935896A30473B9A4` | same; identical code to #3 | W0 | **NO-MEMORY-WRITE** |
| 5 | `msihid_A9D1B251.sys` | i386 | 2.5.0.0 | `A9D1B2515418A372EB4776602D68E177F91FBA1398F60C5DE201475F56411AD3` | same design; Everyone `GRGW` (A) | W0 | **BLOCKED** (i386) / static W0 |
| 6 | `msihid_C81DE3C9.sys` | i386 | 2020-07 | `C81DE3C99A341E3121702C9C13B9271286CF69AA4B3E3DD6D8AAA02CB68BAA58` | same design; Everyone `GRGW` (A) | W0 | **BLOCKED** (i386) / static W0 |
| 7 | `msihid_FBA136DD.sys` | i386 | 2020-07 | `FBA136DD13B6B45BC6796329AF2AF3D032C14D1ED677118B6CCCDF68500CD44D` | identical code to #6 | W0 | **BLOCKED** (i386) / static W0 |
| 8 | `sssmbus_1091D873.sys` | x64 | 1.2.2.0 | `1091D87375DDA66C0318802ECE412FE5469B07BD405AB95FD7D32093A028268C` | `\SSSMbus` + interface `{8AFF2D8C-...}`; Everyone `GRGWGX` (B); IOCTL internal-only | W0 | **NO-MEMORY-WRITE** (HW-ONLY) |
| 9 | `sssmbus_57D26E85.sys` | x64 | 2019 | `57D26E85EF5F9669186552200AAA241421BED8FABB00F8BA874CE43D7EB78EBF` | same; Everyone `GRGWGX` (B); internal-only | W0 | **NO-MEMORY-WRITE** (HW-ONLY) |
| 10 | `sssmbus_7B4435F8.sys` | x64 | 1.0.0.0 / 3.9.10.0 | `7B4435F84457DDE533B4E485BD3CBB23F86584A0B2E1D7A9536E3507E2C5AE9E` | same; Everyone `GRGWGX` (B); internal-only | W0 | **NO-MEMORY-WRITE** (HW-ONLY) |
| 11 | `sssmbus_1F2F26E5.sys` | i386 | 1.0.0.0 / 3.9.10.0 | `1F2F26E54DE67683F312878039B7BC1B58C04465EEC946F61973D24268CFAA08` | same design; Everyone `GRGWGX` (B) | W0 | **BLOCKED** (i386) / static W0 |
| 12 | `sssmbus_CD4B9402.sys` | i386 | 2019 | `CD4B9402DA340624448E597D9FA97046D8A10BB6CA6F2D3A43122C9B23966ED6` | same design; Everyone `GRGWGX` (B) | W0 | **BLOCKED** (i386) / static W0 |

---

## 8. Overall verdict

**NO-MEMORY-WRITE - reach=R1 (msihid control device) / setup=service; sssmbus R1-open but no
user IOCTL / setup=devnode; write=W0; load=signed.**

* `msihid`: no kernel memory write in any of the seven builds. The Everyone-RW control device is
  real, but every reachable IOCTL is a fixed-size buffered operation on WDF-owned buffers/context.
  The only noteworthy defect is the `0xC0DE0030` uninitialized-pool disclosure (section 5.1), which is an
  information leak, not a write.
* `sssmbus`: no kernel memory write. The arbitrary SMBus address/register/data write exists as a
  `HW-ONLY` hardware primitive, but it is registered on `EvtIoInternalDeviceControl` and is not
  reachable from user mode in these images. The historical "unprivileged arbitrary SMBus write"
  verdict is withdrawn for this corpus.
* Five i386 images are `BLOCKED` for the x64 target; their static design is also W0.
* No `MW1`-`MW4` finding. No `BLOCKED` status from signing or blocklist: all 12 Authenticode
  signatures are valid and none of the hashes is known-bad.

---

## 9. Limitations and unresolved paths

1. **Static only.** Nothing was loaded, installed, or executed. The KMDF queue-callback classification
   is based on the documented `WDF_IO_QUEUE_CONFIG` layout (verified against the installed WDK
   headers 1.11-1.33) and on the observed store offsets; a dynamic breakpoint on
   `WdfIoQueueCreate` would make it conclusive.
2. **REA not used.** Four REA sessions were already active; per the scope rules, this audit used
   local Ghidra/objdump only. There are no REA evidence IDs to retain.
3. **No INF/CAT in the corpus.** Install/binding conditions for `sssmbus` (which ACPI SMBus node
   the INF targets) and the exact `msihid` HID hardware ID were not verified. The device-creation
   code paths and DACLs are independent of the INF, but the "device present" condition is not
   proven for this host.
4. **`hidclass` forwarding of vendor `0xB0xxx` codes** was not dynamically tested. These codes are
   on `EvtIoInternalDeviceControl`; even if `hidclass` forwards a vendor code, the handlers use
   fixed-size WDF memory copies and do not accept a kernel destination. This is the one path that
   would benefit from a dynamic check in a snapshot VM.
5. **The `0xC0DE0030` info leak** is a static inference from `WdfRequestSetInformation` semantics;
   it was not confirmed by observing returned bytes.
6. **Signing/catalog membership** was checked only with `Get-AuthenticodeSignature` (all `Valid`);
   catalog member hashes were not independently recomputed.

---

## 10. Historical-report deltas

| Historical claim (`steelseries_hid.static.md`) | This audit |
|---|---|
| `msihid` NO-WRITE | Confirmed: **NO-MEMORY-WRITE (W0)** for all 7 builds; added the `0xC0DE0030` info-leak note and the `+0x28` vs `+0x30` queue distinction |
| `sssmbus` "arbitrary SMBus address/register/data write to unprivileged users" | **Withdrawn for reachability.** The handler is `EvtIoInternalDeviceControl` (config +0x30), not `EvtIoDeviceControl` (+0x28); user-mode `DeviceIoControl` does not reach `0x222800` |
| `0x222800` = `FILE_WRITE_ACCESS` | Incorrect: `0x222800 & 0xC000 == 0` -> `FILE_ANY_ACCESS` |
| "no `ProbeForWrite` (not needed: every code is BUFFERED)" | The control-device codes are buffered, but several HID-side codes are `METHOD_NEITHER`; they are internal-only and use WDF memory objects rather than raw user pointers |
| Only the newest build of each family was examined | All 7 `msihid` and 5 `sssmbus` builds were examined; the material build differences are listed in section 3.6 and section 4.6 |

---

*End of report.*
