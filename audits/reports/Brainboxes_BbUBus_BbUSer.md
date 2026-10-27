# Audit: Brainboxes BbUBus / BbUSer family (8 files)

| Field | Value |
|---|---|
| File(s) | `drivers\BbUBus51_4D52F9D9.sys`<br>`drivers\BbUBus51AMD64_06AD927A.sys`<br>`drivers\BbUBusV251_1385F866.sys`<br>`drivers\BbUBusV251AMD64_8DF6C013.sys`<br>`drivers\BbUSer51_0286D48F.sys`<br>`drivers\BbUSer51AMD64_D4AE57AA.sys`<br>`drivers\BbUSerV251_11783D97.sys`<br>`drivers\BbUSerV251AMD64_475E1B75.sys` |
| SHA-256(s) | `4D52F9D901535C21434FC3AE1D5C35717FB72C86C0B351D85BFEA4064C44BAC8` (BbUBus51)<br>`06AD927AC9E69E8AC7F86E1E322FDE2AEEB3848D09714D34758AA803423EC660` (BbUBus51AMD64)<br>`1385F8666686F4265F14D72F0B35C6DA621E1B6BD205E3AEA68CAC519E390D0E` (BbUBusV251)<br>`8DF6C01336F9E4B9CEF8C5723CE8FD3A40DD56CADB0AA6499D417993709671D3` (BbUBusV251AMD64)<br>`0286D48F849DB6017A5D6054BA4FE24E38360AF27E5602BCE75EE7C7C7F39423` (BbUSer51)<br>`D4AE57AADD1D238B84F938E63DAE578E3A2557E456533EA57376F78FFDFDB759` (BbUSer51AMD64)<br>`11783D9767F5F265216854D86588C4A6D6B5B2F8D92CA3B496CEEFDB17CCFD83` (BbUSerV251)<br>`475E1B7596945F2C953B110C222A9CD5C8DCE4EA1F14C1829C87E2528481EC52` (BbUSerV251AMD64) |
| Analysis date | 2026-10-25 |
| Method | Static-only: local Ghidra 12.1.4 headless (private project), PE import/string inspection, Authenticode/version-resource read. REA was used for an initial cross-check; the shared bridge later switched to a foreign target and those results were discarded. No driver was loaded, executed, installed, or registered. |
| Reach tier | **R3 - hardware** (device exists only after a Brainboxes USB/ExpressCard device enumerates); R2 local administrator for the DACL gate once it exists |
| Setup required | **hardware** |
| Write quality | **W0** |
| Verdict | **NO-MEMORY-WRITE (HW-ONLY)** - no confirmed MW1-MW4; the flagged `MmMapIoSpace` is a fixed PnP-assigned device window, not a user-writable physical mapping and not a kernel-VA write. Residual child-parser path noted in section 11. |
| HW-only | **yes** |

> Scope note: this is the canonical aggregate report for the eight Brainboxes images. It supersedes the four
> partial AMD64 per-file reports (`BbUBus51AMD64_06AD927A.admin.static.md`,
> `BbUBusV251AMD64_8DF6C013.admin.static.md`, `BbUSer51AMD64_D4AE57AA.admin.static.md`,
> `BbUSerV251AMD64_475E1B75.admin.static.md`), which stopped at the unresolved vtable/callback hop and did not
> enumerate the serial IOCTL set. The x86 four had no report. Re-audit reason: unresolved path now resolved,
> plus four new files.

## 1 Identity and inventory

All eight are Brainboxes Limited, FileVersion **5.1.132.0**, ProductName "Brainboxes Boost.Software
Products". Authenticode status is **Valid** for every file, signer `CN=Brainboxes Ltd, O=Brainboxes Ltd,
L=Liverpool, C=GB`. None of the eight SHA-256 values is in `indexes\dedupe\known_bad_hashes.txt`.

| File | Arch | Size | Internal driver name | Family role | SHA-256 verified |
|---|---|---:|---|---|---|
| `BbUBus51_4D52F9D9.sys` | i386 | 187,592 | `BbUBus51` | bus / USB transport + child enumerator | yes |
| `BbUBus51AMD64_06AD927A.sys` | AMD64 | 238,280 | `BbUBus51` | bus / USB transport + child enumerator | yes |
| `BbUBusV251_1385F866.sys` | i386 | 185,544 | `BbUBus51` | bus variant (cancel-safe queue) | yes |
| `BbUBusV251AMD64_8DF6C013.sys` | AMD64 | 225,496 | `BbUBus51` | bus variant (cancel-safe queue) | yes |
| `BbUSer51_0286D48F.sys` | i386 | 190,680 | `BbUSer51` | virtual COM-port function driver | yes |
| `BbUSer51AMD64_D4AE57AA.sys` | AMD64 | 244,952 | `BbUSer51` | virtual COM-port function driver | yes |
| `BbUSerV251_11783D97.sys` | i386 | 188,632 | `BbUSer51` | COM-port variant (cancel-safe queue) | yes |
| `BbUSerV251AMD64_475E1B75.sys` | AMD64 | 229,080 | `BbUSer51` | COM-port variant (cancel-safe queue) | yes |

"V251" is a build variant of the same internal `BbUBus51`/`BbUSer51` driver, not a different device
stack. The material code delta is the `IoCsq*` cancel-safe queue and a few OS-version helpers (section 8).

Address convention: x64 addresses are linked VAs at image base `0x140000000`; x86 addresses are
image-relative Ghidra addresses (32-bit images were imported with base 0).

## 2 Internals

- Both families are WDM, C++-style drivers with a shared `CSsFunctionalDevice` / `CSsPhysicalDevice`
  framework, a `CSsControlQueue` IRP queue, and a PnP resource parser. BbUBus also carries the USB
  transport (`CFTDI1Port`, `CUSBTransport`, `USBD_*`) and child-device enumeration; BbUSer carries the
  virtual COM-port class (`CBbUVCPDriver`, `CVCP`) and the `IOCTL_SERIAL_*` / `IOCTL_BBSERIAL_*` surface.
- Dangerous imports across the eight are limited to `MmMapIoSpace`, `MmUnmapIoSpace`, `IoCreateDevice`,
  `IoCreateSymbolicLink`, `IoRegisterDeviceInterface`, `IoBuildDeviceIoControlRequest`,
  `ExAllocatePoolWithTag`, `ObReferenceObjectByHandle`, and (x86 only) `MmIsAddressValid`,
  `memcpy`, `memset`.
- **Not present in any of the eight:** `IoCreateDeviceSecure`, `WdfDeviceCreate`,
  `MmMapLockedPagesSpecifyCache`, `MmGetPhysicalAddress`, `MmCopyMemory`, `ZwMapViewOfSection`,
  `KeStackAttachProcess`, `ProbeForRead`, `ProbeForWrite`, `SeAccessCheck`,
  `SeSinglePrivilegeCheck`, `IoValidateDeviceIoControlAccess`, `RtlSetDaclSecurityDescriptor`, or an
  SDDL string. A raw byte scan for `D:P(`, `D:(A;`, `SDDL`, and the security API names over ASCII and
  UTF-16 returns nothing in all eight.
- `MmGetSystemRoutineAddress` is used only for the WMI/ETW/`PsGetVersion` helper set, not for
  `MmMapIoSpace` (verified `FUN_00039006` in `BbUSer51`). There is therefore no hidden second mapping
  entry point beyond the single import call site in each image.

## 3 Entry / device / interface / effective DACL

- **Device creation.** Both families use the shared `CSsPhysicalDevice` helper, which calls
  `IoCreateDevice(DriverObject, 0x40, &deviceName, deviceType, 0, exclusive, &deviceObject)` with a
  **NULL security descriptor**. Verified at `FUN_14001b898` (`0x14001b8e3`) in
  `BbUBusV251AMD64`; the x86 equivalent calls `IoCreateDevice` at `0x23b4b` in `BbUSer51`.
  The device name and symbolic link are built from registry values read by the same helper
  (`DeviceName` at registry-info `+0x118`, `SymbolicLinkName` at `+0x150`; BbUBus
  `FUN_14001c730` / BbUSer `FUN_140021040`). They are not hard-coded and are not user-supplied at
  open time.
- **BbUSer COM port.** `CBbUVCPDriver::m_DoStartDevice` reads `PortName` from the device parameter key,
  writes the `SERIALCOMM` mapping, creates the named device plus `\DosDevices\` symlink, and registers
  the standard COM-port interface **GUID_DEVINTERFACE_COMPORT
  `{86E0D1E0-8089-11D0-9CE4-08003E301F73}`** (GUID bytes at RVA `0x261fc` / VA `0x361fc` in
  `BbUSer51`; the `IoRegisterDeviceInterface` call is in `FUN_00014a80` / its x64 analogue).
- **Effective DACL.** No image supplies an SDDL or any security descriptor, and no image calls a
  security API. The effective DACL is the I/O-manager default for a driver-created named device
  object: full control for `SYSTEM` and `BUILTIN\Administrators`, with the exact inherited ACE list
  applied by the object manager and not readable from the static image. Reach is therefore
  **R2/local administrator** once the hardware-created devnode exists; ordinary-user reach was not
  established and is not needed for any finding.
- **Bus devices.** BbUBus creates an FDO and child `CSsPhysicalDevice` objects from a registry list
  (`FUN_140013dec` in `BbUBusV251AMD64`), passing registry-supplied names/type/exclusive flags. No
  child is user-named and none sets a custom DACL.

## 4 Dispatch and IOCTL table

### 4.1 BbUBus - no bus IOCTL store; named opens enter a child-specific handler

`DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]` is set in `FUN_140012468` to
`FUN_140012820`, which forwards through `FUN_140011c44` to the functional-device handler
`FUN_140014ae0` (`BbUBusV251AMD64`). On the callback path that handler:

1. rejects any code whose method bits are non-zero - `if ((IoControlCode & 3) != 0) return
   0xC00000BB` - so only `METHOD_BUFFERED` reaches the callback; and
2. rejects the request if both callback slots `this+0x2158` and `this+0x2160` are NULL.

Both slots are zeroed in the `CBbUBus` constructor `FUN_140012b70` and are never assigned on the bus
path. The only `+0x2160` callback store observed in the family is in the BbUSer 64-bit
`m_DoStartDevice`; the bus has no equivalent store. Consequently, a bus IOCTL on an unnamed open (or
one that falls through the name lookup) reaches the callback path with both slots NULL and returns
`STATUS_INVALID_DEVICE_REQUEST` (`0xC00000BB`); a named mismatch returns `STATUS_ACCESS_DENIED`
(`0xC0000022`). A named open that matches a child enters a child-specific handler (`FUN_140016fa8`),
which reads the IRP system buffer with a minimum-length check and calls the child object; it is not a
bus-side unrestricted store and does not change the W0 result. The bus's own control operations are
`IRP_MJ_INTERNAL_DEVICE_CONTROL` (`IOCTL_CREATE_BBISERIAL`, internal USB `IOCTL_INTERNAL_USB_*`),
which user mode cannot issue through `NtDeviceIoControlFile`.

**BbUBus IOCTL table: no unrestricted handler of its own; named opens enter a child-specific
handler.** The name-keyed child branch `FUN_140016fa8` handles these buffered codes:

| Code | In / Out | Action |
|---|---|---|
| `0x80002000` | in >= 4, out 4 | query child value (`FUN_140016cec`); write result to system buffer |
| `0x80002004` | in == query value | open/close child registry or handle (`FUN_1400173dc`, `FUN_14000e9f4`, `ZwClose`) |
| `0x80002008` | in >= 8 | parse child name/settings (`FUN_140018144`) and invoke bus callback |
| `0x8000200C` | in >= 8 | parse child settings and invoke bus callback |
| `0x80002010` | in > 3 | open/set child value, then query and copy to system buffer |
| `0x80002014` | in == query value | open/set child value, query, copy to system buffer |
| `0x80002000`-`0x80002014`, step 4 | `(code + 0x7ffe2000) <= 0x14`, method bits 0 | generic callback at bus `+0xa8` with system buffer and lengths |

All of these use `Irp->AssociatedIrp.SystemBuffer` and check lengths before touching it. The
serialization parser (`FUN_140018144`) writes parsed values into child-object fields, not into a
caller-supplied address. No `METHOD_NEITHER` path exists anywhere in the bus. The user-mode
reachability of this name-keyed branch was not established (the branch is entered only when the file
object name matches a child; a normal `\\.\COMx` open goes to the child PDO, not the bus FDO), so it
is recorded for completeness rather than as a confirmed R2 surface.

### 4.2 BbUSer - standard serial IOCTL surface

`IRP_MJ_DEVICE_CONTROL` is `FUN_140016300` (x64) / the x86 analogue, which reaches the
framework handler `FUN_14001aab0` (x64) via `FUN_140015724`. The handler reads
`CurrentStackLocation` (`IRP+0xb8` on x64), takes:

- `IoControlCode` = `+0x18` (x64) / `+0xc` (x86),
- `InputBufferLength` = `+0x8`, `OutputBufferLength` = `+0x10` (x64; `+0x8`/`+0x4` on x86),
- `Irp->AssociatedIrp.SystemBuffer` = `IRP+0x18` (x64) / `IRP+0xc` (x86),

and applies the same gate: **`(IoControlCode & 3) != 0` -> `0xC00000BB`.** It then calls the VCP
callback installed at `functionalDevice+0x2160` by `m_DoStartDevice`
(`0x140004ac0` stores `thunk_FUN_1400028b8`). The x86 equivalent is `FUN_00026ece`
(`if (... && (uVar1 & 3) == 0)`), with `SystemBuffer` from `IRP+0xc`.

Consequences: every accepted code is **METHOD_BUFFERED** and **FILE_ANY_ACCESS**; input and output
are the same kernel system buffer; no raw user VA is ever passed to a handler. The per-code handlers
in `FUN_1400029a0` (x64) / `FUN_000129a0` (x86) check the relevant input/output length before
touching the buffer.

| Code | Name | Method / access | In | Out | Kernel action |
|---|---|---|---:|---:|---|
| `0x1B0004` | `IOCTL_SERIAL_SET_BAUD_RATE` | BUFFERED / ANY | 4 | 0 | store baud in VCP state |
| `0x1B0008` | `IOCTL_SERIAL_SET_QUEUE_SIZE` | BUFFERED / ANY | 8 | 0 | store InSize; OutSize ignored; recompute flow-control threshold |
| `0x1B000C` | `IOCTL_SERIAL_SET_LINE_CONTROL` | BUFFERED / ANY | 3 | 0 | store 3-byte line config |
| `0x1B0010` | `IOCTL_SERIAL_SET_BREAK_ON` | BUFFERED / ANY | 0 | 0 | USB/port break on |
| `0x1B0014` | `IOCTL_SERIAL_SET_BREAK_OFF` | BUFFERED / ANY | 0 | 0 | USB/port break off |
| `0x1B0018` | `IOCTL_SERIAL_IMMEDIATE_CHAR` | BUFFERED / ANY | 1 | 0 | transmit one byte |
| `0x1B001C` | `IOCTL_SERIAL_SET_TIMEOUTS` | BUFFERED / ANY | 0x14 | 0/0x14 | store timeouts; optional echo to system buffer |
| `0x1B0020` | `IOCTL_SERIAL_GET_TIMEOUTS` | BUFFERED / ANY | 0 | 0x14 | copy timeouts to output |
| `0x1B0024` | `IOCTL_SERIAL_SET_DTR` | BUFFERED / ANY | 0 | 0 | modem control |
| `0x1B0028` | `IOCTL_SERIAL_CLR_DTR` | BUFFERED / ANY | 0 | 0 | modem control |
| `0x1B002C` | `IOCTL_SERIAL_RESET_DEVICE` | BUFFERED / ANY | 0 | 0 | port reset |
| `0x1B0030` | `IOCTL_SERIAL_SET_RTS` | BUFFERED / ANY | 0 | 0 | modem control |
| `0x1B0034` | `IOCTL_SERIAL_CLR_RTS` | BUFFERED / ANY | 0 | 0 | modem control |
| `0x1B0038` | `IOCTL_SERIAL_SET_XOFF` | BUFFERED / ANY | 0 | 0 | flow control |
| `0x1B003C` | `IOCTL_SERIAL_SET_XON` | BUFFERED / ANY | 0 | 0 | flow control |
| `0x1B0040` | `IOCTL_SERIAL_GET_WAIT_MASK` | BUFFERED / ANY | 0 | 4 | copy mask |
| `0x1B0044` | `IOCTL_SERIAL_SET_WAIT_MASK` | BUFFERED / ANY | 4 | 0 | store mask |
| `0x1B0048` | `IOCTL_SERIAL_WAIT_ON_MASK` | BUFFERED / ANY | 0 | 4 | queue/pend wait IRP |
| `0x1B004C` | `IOCTL_SERIAL_PURGE` | BUFFERED / ANY | 4 | 0 | purge queues |
| `0x1B0050` | `IOCTL_SERIAL_GET_BAUD_RATE` | BUFFERED / ANY | 0 | 4 | copy baud |
| `0x1B0054` | `IOCTL_SERIAL_GET_LINE_CONTROL` | BUFFERED / ANY | 0 | 3 | copy line config |
| `0x1B0058` | `IOCTL_SERIAL_GET_CHARS` | BUFFERED / ANY | 0 | 6 | copy 6 chars |
| `0x1B005C` | `IOCTL_SERIAL_SET_CHARS` | BUFFERED / ANY | 6 | 0 | store 6 chars |
| `0x1B0060` | `IOCTL_SERIAL_GET_HANDFLOW` | BUFFERED / ANY | 0 | 0x10 | copy handflow |
| `0x1B0064` | `IOCTL_SERIAL_SET_HANDFLOW` | BUFFERED / ANY | 0x10 | 0 | validate/store handflow |
| `0x1B0068` | `IOCTL_SERIAL_GET_MODEMSTATUS` | BUFFERED / ANY | 0 | 4 | copy modem status |
| `0x1B006C` | `IOCTL_SERIAL_GET_COMMSTATUS` | BUFFERED / ANY | 0 | 0x14 | copy comm status |
| `0x1B0070` | `IOCTL_SERIAL_XOFF_COUNTER` | BUFFERED / ANY | 0xC | 0 | queue timed XOFF transmit |
| `0x1B0074` | `IOCTL_SERIAL_GET_PROPERTIES` | BUFFERED / ANY | 0 | 0x40 | copy properties |
| `0x1B0078` | `IOCTL_SERIAL_GET_DTRRTS` | BUFFERED / ANY | 0 | 1 | copy DTR/RTS bits |
| `0x1B007C` | `IOCTL_SERIAL_LSRMST_INSERT` | BUFFERED / ANY | 1 | 0 | store insert char |
| `0x1B0080` | `IOCTL_SERIAL_CONFIG_SIZE` | BUFFERED / ANY | 0 | 4 | returns 0 |
| `0x1B0084` | `IOCTL_SERIAL_GET_COMMCONFIG` | BUFFERED / ANY | 0 | 0 | **unsupported** `0xC00000BB` |
| `0x1B0088` | `IOCTL_SERIAL_SET_COMMCONFIG` | BUFFERED / ANY | 0 | 0 | **unsupported** `0xC00000BB` |
| `0x1B008C` | `IOCTL_SERIAL_GET_STATS` | BUFFERED / ANY | 0 | 0x18 | copy stats |
| `0x1B0090` | `IOCTL_SERIAL_CLEAR_STATS` | BUFFERED / ANY | 0 | 0 | clear stats |
| `0x1B0094` | `IOCTL_SERIAL_GET_MODEM_CONTROL` | BUFFERED / ANY | 0 | 4 | copy modem control |
| `0x1B0098` | `IOCTL_SERIAL_SET_MODEM_CONTROL` | BUFFERED / ANY | 4 | 0 | store modem control |
| `0x1B009C` | `IOCTL_SERIAL_SET_FIFO_CONTROL` | BUFFERED / ANY | 1 | 0 | store FIFO control |
| `0x1B2000` | `IOCTL_BBSERIAL_GET_DUPLEX_MODE` | BUFFERED / ANY | 0 | 8 | copy duplex mode/flag |
| `0x1B2004` | `IOCTL_BBSERIAL_SET_DUPLEX_MODE` | BUFFERED / ANY | 8 | 0 | validate mode 1-4; hardware setting |
| `0x1B2008` | `IOCTL_BBSERIAL_SET_LOOPBACK_MODE` | BUFFERED / ANY | 0 | 0 | hardware loopback on |
| `0x1B200C` | `IOCTL_BBSERIAL_CLEAR_LOOPBACK_MODE` | BUFFERED / ANY | 0 | 0 | hardware loopback off |
| `0x1B2018` | `IOCTL_BBSERIAL_READ_EEPROM` | BUFFERED / ANY | 8 | `count` | `count` from in[1]; requires `OutputBufferLength == count`; writes to system buffer |
| `0x1B201C` | `IOCTL_BBSERIAL_WRITE_EEPROM` | BUFFERED / ANY | `count+8` | 0 | requires `InputBufferLength == count+8`; reads data from system buffer |

Every handler above checks its input/output length first; the two EEPROM handlers additionally
require an exact length match before calling the `ISerial` transport. There is no output-length
under-check and no raw user pointer.

## 5 Access-control audit

- No `SeAccessCheck`, `SeSinglePrivilegeCheck`, token/owner query, or per-IOCTL access mask exists in
  any of the eight. All serial codes are `FILE_ANY_ACCESS`, so the device DACL is the only gate.
- The image supplies no security descriptor; the effective DACL is the I/O-manager default for a
  named driver device (SYSTEM/Administrators full). That is an **R2 admin** gate once the hardware
  devnode exists. It is not an unprivileged open surface in the image.
- The bus has no non-forwarding user IOCTL handler (section 4.1); a forwarded child is a serial PDO with
  the same W0 surface, so its DACL does not change the write result.
- The serial device name/symlink and the bus child names are registry-controlled (INF/service
  parameters), not attacker-controlled at open time.

## 6 Memory-write trace - the flagged `MmMapIoSpace`

Each image contains **exactly one** `MmMapIoSpace` call site (verified by symbol reference and by
the absence of a second `COMPUTED_CALL`):

| File | `MmMapIoSpace` call | Containing function | Source of PA / length |
|---|---|---|---|
| `BbUBus51_4D52F9D9.sys` | `0x22841` | `FUN_000226d6` | PnP translated memory resources |
| `BbUBus51AMD64_06AD927A.sys` | `0x2724d` | `FUN_00026d38` | PnP translated memory resources |
| `BbUBusV251_1385F866.sys` | `0x411ebd` | `FUN_00411d3e` | PnP translated memory resources |
| `BbUBusV251AMD64_8DF6C013.sys` | `0x140016070` | `FUN_140015e98` | PnP translated memory resources |
| `BbUSer51_0286D48F.sys` | `0x2757d` | `FUN_00027412` | PnP translated memory resources |
| `BbUSer51AMD64_D4AE57AA.sys` | `0x2a59d` | `FUN_0002a088` | PnP translated memory resources |
| `BbUSerV251_11783D97.sys` | `0x41677d` | `FUN_004165fe` | PnP translated memory resources |
| `BbUSerV251AMD64_475E1B75.sys` | `0x14001c040` | `FUN_14001be68` | PnP translated memory resources |

The parser is a standard PnP start routine. It receives the **IO_STACK_LOCATION** (not a user
buffer): the translated list is at `+0x10` (x64) / `+0x8` (x86), the raw list at `+0x8` / `+0x4`.
It iterates `CmResourceTypeMemory` (type `1`) and calls:

```
MmMapIoSpace(translated.PhysicalAddress, translated.Length, MmNonCached)
```

with the address and length taken from the resource descriptor. The driver logs the PA to the
debugger (`"call MmMapIoSpace with parameter 0x%X"`), stores the returned VA plus length in a
private list (`this+0x22f0` x64 / `this+0x12a0` x86), and unmaps it on failure/remove
(`MmUnmapIoSpace`). The single caller is the **`IRP_MN_START_DEVICE` (minor 0)** branch:

- `BbUBusV251AMD64`: `FUN_140014f50` case 0 -> `FUN_140015e98` (`0x140016070`)
- `BbUBus51AMD64`: `FUN_000276e4` (StartDevice strings) -> `FUN_00026d38`
- `BbUBus51`: `FUN_00022e46` case 0 -> `FUN_000226d6`
- `BbUBusV251`: `FUN_004110b0` case 0 -> `FUN_00411d3e`
- `BbUSerV251AMD64`: `FUN_14001af20` (PnP start) -> `FUN_14001be68`
- `BbUSer51`: `FUN_00027b82` (PnP start) -> `FUN_00027412`
- `BbUSer51AMD64`: PnP start caller -> `FUN_0002a088`
- `BbUSerV251`: `FUN_00415970` case 0 -> `FUN_004165fe`

No IOCTL, WMI call, or file-open path can supply this address or length. The list is built by PnP
from the device's BAR/INF; an administrator who creates a root-enumerated devnode with crafted
`LogConfig` resources could influence the PA, but that is devnode setup, not a runtime primitive, and
the resulting mapping is still kernel-private and never exposed to user mode (so it does not become
`W3P`). There is no
second mapping routine, no `MmMapLockedPagesSpecifyCache`, no `MmGetPhysicalAddress`, no
`ZwMapViewOfSection` on `\Device\PhysicalMemory`, no `MmCopyMemory`, and no `KeStackAttachProcess` in
any image. The mapped window is exactly the device's PnP-assigned BAR/window:

- on a USB-only Brainboxes adapter the translated memory list is normally empty, so the loop maps
  nothing;
- on an ExpressCard/CardBus variant it maps the assigned BAR, which is fixed-window **device MMIO**
  used for hardware registers.

**Classification.** This is fixed-window/device MMIO, i.e. **HW-ONLY**. It is not `W3P`/MW3: the
requester cannot choose the physical address, cannot ask the driver to map a different PA, and the
mapped kernel VA is never returned or exposed by an IOCTL. It is not `W2`/`W1`: no caller-controlled
value reaches a kernel store, and no kernel-VA destination is derived from the mapping.

## 7 Other write paths

- **Serial read/write.** `CVCP::m_Read` / `m_Write` operate on a driver-owned `CSsControlBuffer`
  (pool-backed: `FUN_00020c54`/`FUN_00020c9a` allocate via `ExAllocatePoolWithTag`; the buffer is
  never pointed at a user VA). The IRP handler copies between that pool buffer and the request
  buffer. The queue has an explicit overflow check
  (`"CVCP::m_Read - OUT - Buffer is overflow, can't read"`) and the handlers check length before
  copying. No caller-chosen kernel destination is used by the buffer object.
- **EEPROM custom IOCTLs.** `IOCTL_BBSERIAL_READ_EEPROM` writes `count` bytes into the output
  system buffer only after `OutputBufferLength == count`; `IOCTL_BBSERIAL_WRITE_EEPROM` reads
  `count` bytes only after `InputBufferLength == count + 8`. Both then call the `ISerial` transport
  (`+0xf0`/`+0xf8` on x64, `+0x78`/`+0x7c` on x86). The pointer is the IRP system buffer, not a
  caller-chosen kernel address.
- **`IOCTL_SERIAL_SET_QUEUE_SIZE`.** Stores `InSize` and a derived threshold in the VCP object; no
  allocation and no copy from the input buffer beyond the 8-byte structure.
- **Registry writes** (`SERIALCOMM`, device parameters) are configuration, not memory writes.
- **Internal IRPs.** `IoBuildDeviceIoControlRequest` sends driver-owned buffers to the USB stack;
  the bus's `IOCTL_CREATE_BBISERIAL` is kernel-originated (`IRP_MJ_INTERNAL_DEVICE_CONTROL`).
- **32-bit `memcpy`/`memset`.** Imported in the 32-bit images. In `BbUSer51` the imports are not
  called through the import thunk (the compiler inlined the copies); the driver's copies there are
  structure/IRP-buffer copies with driver-field lengths. `BbUBus51`'s USB/child-enumeration copies
  were not traced line by line, but the bus has no user IOCTL surface, so no user-controlled
  destination is reachable through it. No caller-controlled kernel destination was found.
- No write-what-where, no caller-controlled fixed-address store, no MDL user mapping, and no
  physical-memory write primitive were found.

## 8 32-bit vs 64-bit and 51 vs V251 - material differences

| Axis | Difference | Primitive effect |
|---|---|---|
| x86 vs AMD64 | Same mapping function shape and same single call site; only the IO_STACK_LOCATION offsets differ (`+0x8`/`+0x10`/`+0x18` and `SystemBuffer+0x18` on x64; `+0x4`/`+0x8`/`+0xc` and `SystemBuffer+0xc` on x86). x86 builds import `memcpy`/`memset` (BbUSer51 also imports `MmIsAddressValid`); x64 inlines the copies and does not import `MmIsAddressValid`. | None |
| 51 vs V251 | V251 adds `IoCsqInitializeEx`/`IoCsqInsertIrpEx`/`IoCsqRemoveNextIrp`/`IoCsqRemoveIrp` (cancel-safe queue); 51 uses `IoWMIWriteEvent` and a manual cancel spin lock. Other OS-helper imports (`RtlGetVersion`, `MmQuerySystemSize`, `RtlDeleteRegistryValue`) vary by build but do not affect the primitive. | None; same mapping and IOCTL validation |
| BbUBus vs BbUSer | Bus has no non-NULL device-control callback of its own, so no bus IOCTL store; named opens may forward to a serial child. Serial has the standard COM-port table. | Bus: none; serial: W0 |
| All eight | Same `CSsPhysicalDevice`/`CSsFunctionalDevice` framework, same NULL-SD `IoCreateDevice`, same `(code & 3) == 0` gate on the paths that exist. | None |

No build has a caller-controlled physical address, an exposed mapped VA, a `METHOD_NEITHER` path, or
a kernel-VA write.

## 9 Most dangerous exposed capability

The most exposed capability is the **admin-open serial IOCTL interface** of the four BbUSer images
once a Brainboxes device enumerates: 45 buffered serial/EEPROM codes, all `FILE_ANY_ACCESS`. Every
one is length-checked, the dispatcher rejects non-buffered methods, and the data copies terminate in
the IRP system buffer or driver state. The bus images expose no unrestricted IOCTL store of their own
(a named open may reach a child-specific handler). The `MmMapIoSpace` window is the least exposed
part: it is created only from the PnP resource list at start and is not addressable by any IOCTL.

## 10 Verdict

**Overall: NO-MEMORY-WRITE (HW-ONLY) - reach=R3 setup=hardware write=W0 load=signed.** No confirmed
MW1, MW2, MW3, or MW4 finding. The flagged `MmMapIoSpace` is a fixed PnP-assigned device MMIO window,
not a user-writable physical mapping, and there is no confirmed true kernel-VA write primitive in any
of the eight images; the bus's name-keyed child parser remains an unresolved residual (section 11).

| File | Arch | SHA-256 (prefix) | `MmMapIoSpace` | User IOCTL surface | Gate | Write | Verdict |
|---|---|---|---|---|---|---|---|
| `BbUBus51_4D52F9D9.sys` | i386 | `4D52F9D9...` | `0x22841` fixed PnP resources | none of its own (child-specific handler) | default DACL + hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| `BbUBus51AMD64_06AD927A.sys` | AMD64 | `06AD927A...` | `0x2724d` fixed PnP resources | none of its own (child-specific handler) | default DACL + hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| `BbUBusV251_1385F866.sys` | i386 | `1385F866...` | `0x411ebd` fixed PnP resources | none of its own (child-specific handler) | default DACL + hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| `BbUBusV251AMD64_8DF6C013.sys` | AMD64 | `8DF6C013...` | `0x140016070` fixed PnP resources | none of its own (child-specific handler) | default DACL + hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| `BbUSer51_0286D48F.sys` | i386 | `0286D48F...` | `0x2757d` fixed PnP resources | serial + BBSERIAL, buffered | default DACL + hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| `BbUSer51AMD64_D4AE57AA.sys` | AMD64 | `D4AE57AA...` | `0x2a59d` fixed PnP resources | serial + BBSERIAL, buffered | default DACL + hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| `BbUSerV251_11783D97.sys` | i386 | `11783D97...` | `0x41677d` fixed PnP resources | serial + BBSERIAL, buffered | default DACL + hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |
| `BbUSerV251AMD64_475E1B75.sys` | AMD64 | `475E1B75...` | `0x14001c040` fixed PnP resources | serial + BBSERIAL, buffered | default DACL + hardware | W0 | **NO-MEMORY-WRITE (HW-ONLY)** |

**Per-file verdicts are identical; the overall verdict is the same for the family.**

## 11 Limitations

1. **Static only.** No driver was loaded, no service/devnode was created, no IOCTL was issued, and no
   registry key was written. The device DACL, the actual PnP resource list, and the presence/absence
   of a hardware filter were not observed live.
2. **Effective DACL is inferred.** The images contain no SDDL or security-descriptor bytes and no
   security API. The `SYSTEM`/`Administrators` default is the documented `IoCreateDevice(NULL)`
   behaviour, applied by the object manager; it was not read from a live device object. A deployment
   that applies a different SD could change reach, but not the W0 result.
3. **Queue internals and child parser.** The `CSsControlQueue` ring-buffer arithmetic, the IRP
   read/write copy between the pool buffer and the request buffer, the USB transport's EEPROM
   control-transfer implementation, and the bus's name-keyed child serialization parser
   (`FUN_140016fa8` / `FUN_140018144` / `FUN_140018350`) were reviewed at the dispatcher/bounds-check
   level, not modelled line by line. No caller-controlled kernel address was found; the child parser
   writes parsed values into child-object fields, but the destination field bounds were not fully
   modelled. This is the main residual path. The queue contains its own overflow check and the EEPROM
   handlers require exact length matches.
4. **REA contention / foreign target.** The shared REA bridge was used for the first cross-check, then
   returned a foreign binary (`mccfwld_05370B16.sys`, SHA-256
   `05370b16e9ebf30ad0fef6fe7249c039388026c9d96c63d63b78f076098a603b`) mid-session. Results obtained
   after that switch were discarded. All load-bearing claims were re-verified with **local Ghidra
   12.1.4 headless** on `BbUBusV251AMD64`, `BbUBus51AMD64`, `BbUSerV251AMD64`, `BbUSer51`,
   `BbUSer51AMD64`, and with PE/import/string scans on all eight; the remaining x86 V251 and
   BbUBus51 mapping call sites were cross-checked before the switch and match the same function
   shape.
5. **Superseded reports.** The four existing AMD64 per-file reports are partial and are superseded by
   this aggregate; they did not resolve the vtable/callback hop and therefore did not enumerate the
   serial IOCTL set. No other file was modified.
