# Audit: silabser.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\silabser.sys` |
| SHA-256 | `9393781cf3fd66c9ea21380ec8ec1affa6d84eb27c7eaeb14064bd90d32f27b2` |
| Analysis date | 2026-10-23 |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4, x86:LE:64) |
| REA document | `target-9393781cf3fd.sys` |
| Image base | `0x140000000` |

> Static-only. No driver was loaded, no device was opened, and no IOCTL was executed. All addresses are linked virtual addresses (image base `0x140000000`). A shared REA session was switched to another target once during the audit; the target was re-opened, and every result retained below was re-checked against `target-9393781cf3fd.sys` (SHA-256 above).

---

## 1. Internals

`silabser.sys` is a 64-bit PE (KMDF minidriver), 105,880 bytes, 242 analyzed procedures and 282 defined strings (Evidence `ev_c3709c7f2c6d147870d95eb1588006e85987c1987999d1170a22139dedfadf95`).

**Segments** (from `binary_overview`):

| Section | Range |
|---|---|
| Headers | `0x140000000`-`0x140000400` |
| `.text` | `0x140001000`-`0x14000c000` |
| `.rdata` | `0x14000c000`-`0x14000d000` |
| `.data` | `0x14000d000`-`0x14000dff4` |
| `.pdata` | `0x14000e000`-`0x14000ea00` |
| `.gfids` | `0x14000f000`-`0x14000f200` |
| `PAGESRP0` | `0x140010000`-`0x140013200` |
| `PAGE` | `0x140014000`-`0x140014200` |
| `PAGESER` | `0x140015000`-`0x140015400` |
| `INIT` | `0x140016000`-`0x140016800` |
| `.rsrc` | `0x140017000`-`0x140017600` |
| `.reloc` | `0x140018000`-`0x140018200` |

**PE entry point.** `e_lfanew = 0x108`; optional-header `AddressOfEntryPoint = 0x1184`, i.e. VA `0x140001184` (Ghidra symbol `entry`). The entry stub at `0x140001184` calls `__security_init_cookie` (`0x14001625c`) and jumps to `FxDriverEntryWorker` at `0x140001060`.

**KMDF bootstrap.** `FxDriverEntryWorker` (`0x140001060`):

- initializes a WDF bind structure and calls `WdfVersionBind` through `0x14000a1fe` at `0x1400010da`;
- calls `FxStubBindClasses` (`0x140001228`) and `FxStubInitTypes` (`0x1400012b0`);
- calls the driver's real `DriverEntry` at `0x140016000` (`0x140001104`).

`DriverEntry` (`0x140016000`, INIT section):

- `RtlGetVersion` via `0x14000c0b8` at `0x1400160c8` (sets OS-version globals `0x14000d120`/`0x14000d124`);
- `WdfDriverCreate` through `0x14000d4e0` at `0x1400160b3`, with a `WDF_DRIVER_CONFIG` at `[rsp+0x70]` (size `0x20`) whose `EvtDriverDeviceAdd` is `0x1400107c8`;
- registry-config helper `0x140016130` reads driver parameters.

**Imports.** Only NTOSKRNL/HAL and the WDF loader are imported: `MmQuerySystemSize`, `RtlInitUnicodeString`, `RtlWriteRegistryValue`, `RtlDeleteRegistryValue`, `RtlIsNtDdiVersionAvailable`, `IoGetConfigurationInformation`, `KeAcquireSpinLockRaiseToDpc`, `ExFreePoolWithTag`, `IoAllocateErrorLogEntry`, `IoWriteErrorLogEntry`, `KeBugCheckEx`, `ExAllocatePoolWithTag`, `KeDelayExecutionThread`, `RtlCopyUnicodeString`, `RtlAnsiCharToUnicodeChar`, `ExAllocatePoolWithQuotaTag`, `RtlGetVersion`, `IofCompleteRequest`, `KeReleaseSpinLock`, `RtlAssert`, `KeQueryPerformanceCounter`, plus `WdfVersionBind/BindClass/Unbind/UnbindClass` from `WDFLDR.SYS`. All other WDF services are called through the runtime-populated table at `0x14000d2xx`-`0x14000dbxx`.

Notably absent: **no** `SeSinglePrivilegeCheck`, `SeAccessCheck`, `ObOpenObjectByPointer`, `ZwOpenKey`, `PsGetCurrentProcess*`, or any other security/identity import.

**Embedded source paths.** `..\src\cp210xusb.c`, `..\src\ioctl.c`, `..\src\utils.c`, `..\src\write.c` (strings at `0x14000a680`, `0x14000b0c0`, `0x14000b8b0`, `0x14000bf10`), and KMDF class-bind section names (`.kmdfclassbind$a`, `.kmdfclassbind$c`, `.kmdfclassbind$d`, `.kmdftypeinit$a`, `.kmdftypeinit$c`).

**Device/wire names.** `\Device\Silabser` (UTF-16 at `0x140012610`), `\DosDevices\` (UTF-16 at `0x140012d90`), `SERIALCOMM` (UTF-16 at `0x140012df0`), `GUID_DEVINTERFACE_COMPORT` (string at `0x140012e50`), `SILABUSBSERIALBRIDGE` (string at `0x140012940`).

---

## 2. Device & entry chain

### 2.1 Init -> device creation

`EvtDriverDeviceAdd` is `FUN_1400107c8` (body `0x1400107c8`-`0x140011220`; bound at `0x140016064` in `DriverEntry`).

Device-name construction:

- format string `L"%ws%u"` at `0x140012640`, prefix `L"\Device\Silabser"` at `0x140012610`;
- `0x140010841`-`0x14001085d` builds `\Device\Silabser<N>` using the incrementing global `DAT_14000d12c` (`0x140010834` reads it, `0x140010857` increments it);
- `WdfDeviceInitAssignName` via `0x14000d358` at `0x14001087b`.

The device-init sequence then sets, in order:

| Init action | Call site | Argument / evidence |
|---|---|---|
| SDDL assignment | `0x14001089c`, slot `0x14000d360` | `R8 = 0x14000c240` (UNICODE_STRING -> SDDL at `0x14000c250`) |
| Boolean TRUE init flag (consistent with exclusive-open) | `0x1400108b9`, slot `0x14000d330` | `R8B = 1` |
| Device type `0x1b` (27 = FILE_DEVICE_SERIAL_PORT) | `0x1400108cf`, slot `0x14000d350` | `R8D = 0x1b` |
| PnP/power callbacks | `0x140010912` / `0x140010968` | slots `0x14000d380` / `0x14000d2f8` |
| File-object config | `0x140010ac3`, slot `0x14000d378` | `WDF_FILEOBJECT_CONFIG` at `[rbp+0xf8]`: size `0x28`, EvtFileCreate `0x140010088`, EvtFileClose `0x140015000`, EvtFileCleanup `0x1400052d8` |
| `WdfDeviceCreate` | `0x140010c07`, slot `0x14000d398` | device init + object attributes |

After creation, power-idle settings are applied (`0x140010ca7`, slot `0x14000d3d8`) using four DWORDs of value 2 read from `0x14000c1a0` and two `0xFFFFFFFF` timeouts.

### 2.2 Two device interfaces and a DOS device name

1. **Custom interface** - `WdfDeviceCreateDeviceInterface` through `0x14000d3a8` at `0x1400111b5`, GUID pointer `0x14000c180`:
   - bytes `20 92 a3 a2 f4 39 88 4b ae cb 3d 86 a3 5d c7 48`
   - GUID `{A2A39220-39F4-4B88-AECB-3D86A35DC748}` (the "SILABUSBSERIALBRIDGE" interface named in the log string at `0x140012940`).
2. **COM-port interface** - in `SerialCreateExternalNaming` (`FUN_140010538`, body `0x140010538`-`0x1400107c5`), `WdfDeviceCreateDeviceInterface` through `0x14000d3a8` at `0x14001073a`, GUID pointer `0x14000c190`:
   - bytes `e0 d1 e0 86 89 80 d0 11 9c e4 08 00 3e 30 1f 73`
   - GUID `{86E0D1E0-8089-11D0-9CE4-08003E301F73}` (GUID_DEVINTERFACE_COMPORT).
3. **DOS name** - `0x140010680`-`0x1400106a1` builds `\DosDevices\<DosName>`; `WdfDeviceCreateSymbolicLink` through `0x14000d3c0` at `0x1400106c0`; `RtlWriteRegistryValue` writes `SERIALCOMM\DeviceMap` at `0x140010708`; `IoGetConfigurationInformation()->SerialCount` is incremented at `0x1400111e7`-`0x1400111ed`.

Both interfaces are created even if external naming is skipped by configuration; the custom interface is registered unconditionally in the device-add path.

### 2.3 Queue configuration -> dispatch

A `WDF_IO_QUEUE_CONFIG` (size `0x58`) is built at `[rbp-0x2c8]` and passed to the queue-create slot `0x14000d600` at `0x14001113f`. Callback pointers are installed at:

| Role | Function | Store site |
|---|---|---|
| EvtIoRead | `0x140006a38` | `0x1400110e9` |
| EvtIoWrite | `0x140008980` | `0x1400110f4` |
| **EvtIoDeviceControl** | **`0x140003424`** | **`0x1400110ff`** |
| EvtIoInternalDeviceControl | `0x1400049cc` | `0x14001110a` |
| EvtIoStop / Resume / Canceled | `0x140007c20` / `0x140007ce0` / `0x140007cb8` | `0x140011115`-`0x140011132` |

`FUN_140003424` is the IOCTL switch audited in section 3.

### 2.4 File-create path

`EvtFileCreate = FUN_140010088` (`0x140010088`):

- resolves the device extension (`0x14000d790`) and calls `FUN_140004fdc`;
- completes the create request through `0x14000d978`.

`FUN_140004fdc` allocates the read buffer (`0x400` / `0x2000` / `0x10000` depending on `MmQuerySystemSize`), calls the WDF device-open helper `0x14000d400`, initializes hardware, and returns status. It performs **no** caller-identity, privilege, or access-mask check. The only early rejection is the device-removed flag at `[DE+0xf8]` (`0x140004ff3`).

---

## 3. IOCTL table

### 3.1 Dispatch entry

`EvtIoDeviceControl` = `FUN_140003424` (body `0x140003424`-`0x1400049cb`, 5,544 bytes; pseudo-code Evidence `ev_c1e8885a09280187491ae48c042f3aaeca5e452a2ceb6dd2864f39d74e8ff98f`, assembly Evidence `ev_d271f834c861c4a05f0e2c89b9854807f4e366b91bb3125c014868e616e1af51`). The IOCTL code arrives as the 5th argument (`param_5` / `ECX` in the switch).

Prologue behavior:

- resolves device context `DE` and request context (`0x14000344c`-`0x14000346c`);
- calls the log-name helper `FUN_140004c24` (`0x1400034a0`);
- rejects if `DE->f8` or `DE->fc` is set (`STATUS_INVALID_DEVICE_STATE`, `0xC0000010`);
- calls `FUN_1400077d8` (XOFF-counter/purge continuation gate; no security check);
- initializes the request context and enters the switch.

**No requestor-mode, privilege, access-mask, or process-identity check exists anywhere on this path.**

### 3.2 Control-code encoding (all codes)

Every compared code is either device type `0x1b` (`FILE_DEVICE_SERIAL_PORT`) or `0x22` (`FILE_DEVICE_UNKNOWN`). For **all 49** codes:

- bits 31-30 = `00` -> **METHOD_BUFFERED**;
- bits 15-14 = `00` -> **FILE_ANY_ACCESS**;
- buffers are obtained only through the WDF retrieve helpers `0x14000d9a8` (input) and `0x14000d9b0` (output).

So no IOCTL uses METHOD_NEITHER, METHOD_IN_DIRECT, or METHOD_OUT_DIRECT, and no IOCTL requires a specific access right beyond a valid handle.

### 3.3 Standard serial codes (37)

`Fn = (code >> 2) & 0xFFF`. "In -> Out" is the size requested at the dispatch layer; "-" means the branch delegates to a helper that performs the transfer.

| Code | Fn | In -> Out | Observed action at `FUN_140003424` |
|---|---|---|---|
| `0x1B0004` | 1 | 4 -> - | Reads a 4-byte baud rate into `DE+0x334`; calls `FUN_1400019f0` to program the divisor. |
| `0x1B0008` | 2 | 8 -> - | Reads 8-byte queue sizes; may allocate a pool buffer if requested size exceeds `DE+0x2e0`. |
| `0x1B000C` | 3 | 3 -> - | Reads 3-byte line control; validates data bits/parity/stop bits; stores at `DE+0x38c`; calls `FUN_140001ab8`. |
| `0x1B0010` | 4 | - -> - | Delegates to `FUN_140004fcc` -> `FUN_140001a34` (modem/line helper). |
| `0x1B0014` | 5 | - -> - | Delegates to `FUN_140004fbc` -> `FUN_140001480`. |
| `0x1B0018` | 6 | 1 -> - | Reads one immediate character; calls `FUN_1400019ac`. |
| `0x1B001C` | 7 | 20 -> - | Reads five `ULONG` serial timeouts; rejects the all-`0xFFFFFFFF` case; stores at `DE+0x344`. |
| `0x1B0020` | 8 | - -> 20 | Returns the five stored timeouts. |
| `0x1B0024` | 9 | - -> - | Rejects if handshake mode is `2`; `FUN_140004f94` -> `FUN_140001b20(..., 0x101)`. |
| `0x1B0028` | 10 | - -> - | Rejects if handshake mode is `2`; `FUN_140004f6c` -> `FUN_140001b20(..., 0x100)`. |
| `0x1B002C` | 11 | - -> - | `FUN_140001968` (device reset helper). |
| `0x1B0030` | 12 | - -> - | Rejects if handshake bits are not `0x80`; `FUN_140004fa8` -> `FUN_140001b20(..., 0x202)`. |
| `0x1B0034` | 13 | - -> - | Same handshake gate; `FUN_140004f80` -> `FUN_140001b20(..., 0x200)`. |
| `0x1B0038` | 14 | - -> - | `FUN_140001ba4` (XOFF helper). |
| `0x1B003C` | 15 | - -> - | `FUN_140001be8` (XON helper). |
| `0x1B0040` | 16 | - -> 4 | Reads 4-byte modem status from `DE+0x238` under spinlock `DE+0x228`. |
| `0x1B0044` | 17 | 4 -> - | Reads 4-byte flow-control value; rejects values with bits outside `0x1FFF`; queues via `DE+0x1c8`. |
| `0x1B0048` | 18 | - -> 4 | Retrieves 4-byte output buffer and queues via `DE+0x1c8`. |
| `0x1B004C` | 19 | 4 -> - | Reads 4-byte mask; accepts `0` or values with bits outside `0xFFFFFFF0` clear; queues via `DE+0x1f8`. |
| `0x1B0050` | 20 | - -> 4 | Returns the stored 4-byte baud rate (`DE+0x334`). |
| `0x1B0054` | 21 | - -> 3 | Zero-fills and returns the 3-byte line control (`DE+0x38c`). |
| `0x1B0058` | 22 | 6 -> - | Reads 6-byte `SERIAL_CHARS`; stores at `DE+0x358`; calls `FUN_140001b60`. |
| `0x1B005C` | 23 | 6 -> - | Reads 6-byte handshake/flow-control; stores `DE+0x358`/`DE+0x35c` and `DE+0x42c`/`DE+0x434`; calls `FUN_140001b60`. |
| `0x1B0060` | 24 | - -> 16 | Returns the 16-byte wait mask from `DE+0x360`. |
| `0x1B0064` | 25 | 16 -> - | Reads 16-byte wait mask; validates masks/event counts; stores at `DE+0x360`; calls `FUN_140001a74`. |
| `0x1B0068` | 26 | - -> 4 | Returns comm-status byte (`DE+0x269`) directly if `DE+0x105` is set, otherwise queues a pending read via `FUN_14000162c`. |
| `0x1B006C` | 27 | - -> 20 | Returns 20-byte XOFF-counter structure; uses `KeQueryPerformanceCounter` for elapsed-time logic and `FUN_140002a2c`. |
| `0x1B0070` | 28 | 12 -> - | Reads 12-byte handflow; validates second dword > 0; queues via `DE+0x198`. |
| `0x1B0074` | 29 | - -> 0x40 | Returns up to `0x40` bytes of properties from `DE+0x114`, clamped to `DE+0x160`. |
| `0x1B0078` | 30 | 1 -> - | Reads 1-byte LSR/MST-insert setting; validates against existing chars; stores `DE+0x398`; calls `FUN_140001518`. |
| `0x1B007C` | 31 | - -> 4 | Returns 4-byte DTR/RTS state; may queue via `FUN_14000162c`. |
| `0x1B0080` | 32 | - -> 4 | Zero-fills 4 bytes and returns 0 (configuration-size stub). |
| `0x1B008C` | 35 | - -> 0x18 | Returns 24 bytes of statistics from `DE+0x374`, `DE+0x480`. |
| `0x1B0090` | 36 | - -> - | Clears statistics fields at `DE+0x374`/`DE+0x480`. |
| `0x1B0094` | 37 | - -> 4 | Returns modem-control bits (`DE+0x269 & 3`); may queue via `FUN_14000162c`. |
| `0x1B0098` | 38 | 4 -> - | Reads 4-byte modem control; calls `FUN_140001b20` with `0x200` or `0x202`. |
| `0x1B009C` | 39 | 4 -> - | Reads 4-byte FIFO-control value; no further action at this layer. |

`0x1B0084` and `0x1B0088` are **not** compared and fall to the default invalid-parameter path.

> Label caveat: the driver's own log-label helper `FUN_140004c24` (`0x140004c24`, assembly Evidence `ev_857707f12023e6c3c046f1308b29237b5065cc910d337bd85d90465450ca8a17`) maps several codes to names that do not match the observed dispatch semantics (for example `0x1B0060` is labelled `GET_HANDFLOW` but copies the 16-byte wait mask, and `0x1B0058` is labelled `GET_CHARS` but consumes 6 input bytes). The "observed action" column above is derived from the dispatch code, not from that label table.

### 3.4 Vendor / bridge codes (12)

These are the security-relevant additions. The driver's label helper maps them consistently with the handlers.

| Code | Fn | In -> Out | Action |
|---|---|---|---|
| `0x222008` | `0x802` | - -> 18 | `CP210x_GET_DEVICE_DESCRIPTOR_IOCTL`: copies 18 bytes from `DE+0xd2` (cached device descriptor). |
| `0x22200C` | `0x803` | - -> >=9 | `CP210x_GET_CONFIG_DESCRIPTOR_IOCTL`: requests 9-byte minimum output, returns `min(outLen, DE->f0)` bytes from `DE+0xe8`. |
| `0x222024` | `0x809` | 8+payload -> - | `CP210x_SEND_USB_CONTROL_IOCTL`: parses an 8-byte control header (request type/direction/recipient, `bRequest`, `wValue`, `wIndex`, `wLength`) and sends an OUT control transfer using `input+8` as data; checks `wLength <= inputLen-8`. |
| `0x222028` | `0x80A` | 8 -> 9 (min) | `CP210x_GET_USB_CONTROL_IOCTL`: parses the same 8-byte header and sends an IN control transfer into `output+8` with length `wLength`; **no check that `wLength` fits the output buffer** (see section 5). |
| `0x222080` | `0x820` | - -> 1 | `CP210x_GET_PART_NUM_IOCTL`: returns byte `DE+0xa0`. |
| `0x222084` | `0x821` | - -> `DE->b0` | `CP210x_GET_PRODUCT_STRING_IOCTL`: copies `min(outLen, DE->b0)` bytes from `DE+0xa8`. |
| `0x222088` | `0x822` | - -> `DE->d0` | String getter (no log name; consumes `DE+0xc8`/`DE+0xd0`). |
| `0x22208C` | `0x823` | - -> `DE->c0` | `CP210x_GET_SERIAL_STRING_IOCTL`: copies `min(outLen, DE->c0)` bytes from `DE+0xb8`. |
| `0x222090` | `0x824` | - -> 1 or 2 | `CP210x_READ_LATCH_IOCTL`: `FUN_14000188c` issues a vendor control IN (`bRequest 0xFF`) to read the GPIO latch; requires 2 bytes for part `8`. |
| `0x222094` | `0x825` | 2 -> - | `CP210x_WRITE_LATCH_IOCTL`: `FUN_140002188` issues a vendor control OUT (`bRequest 0xFF`, `wValue 0x37E1`) with 1-4 bytes of attacker data. |
| `0x222098` | `0x826` | - -> 1 | `CP210x_WAS_DEVICE_REMOVED_IOCTL`: returns `DE->fb != 0`. |
| `0x22209C` | `0x827` | - -> 1 | `CP210x_CHECK_TT_BUFFER_ERROR_IOCTL`: returns `DE->f5 != 0` and clears the flag. |

---

## 4. Access-control audit

### 4.1 The device DACL is explicitly permissive

At `0x14001089c` the driver passes a `UNICODE_STRING` at `0x14000c240` to the WDF device-init SDDL service (`0x14000d360`):

- `Length = 0x007E` (126 bytes), `MaximumLength = 0x0080`, `Buffer = 0x14000C250`;
- the SDDL text at `0x14000c250` is exactly:

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)
```

Evidence: `ev_b14f0f7dd708f955c1bb4ca2d475eda558c9ca8ea8c787472ff72a5eb0455808`; GUID/interface evidence `ev_3facb1f822c2de844cb52366ba75e61ccae58c9f33d5876588876a99134d44d6`.

Decoded:

| ACE | SID | Rights |
|---|---|---|
| `A;;GA;;;SY` | Local System | GENERIC_ALL |
| `A;;GRGWGX;;;BA` | Built-in Administrators | GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE |
| `A;;GRGWGX;;;WD` | **Everyone** | GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE |
| `A;;GRGWGX;;;RC` | Restricted Code | GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE |

`D:P` means the DACL is protected (no inherited ACEs). The `WD` (Everyone) ACE with `GR`/`GW` is the decisive point: **any local user can open the device for read/write**, and therefore obtain a handle suitable for `DeviceIoControl`.

### 4.2 No additional gate in the driver

- **No privilege check.** `SeSinglePrivilegeCheck` is not imported; no privilege name or `Se*` security API appears in the import table.
- **No requestor-mode / process check.** `EvtIoDeviceControl` (`0x140003424`) and the file-create path (`0x140010088` -> `0x140004fdc`) never call `WdfRequestGetRequestorMode`, `WdfRequestGetRequestorProcess`, or any equivalent; no such import exists.
- **No per-IOCTL access mask.** All 49 control codes are `FILE_ANY_ACCESS`; the handlers never inspect `RequestorMode` or the file object's granted access.
- **One open handle at a time (inferred).** Immediately after the SDDL assignment, a BOOLEAN `TRUE` is passed through WDF init slot `0x14000d330` at `0x1400108b9`; this is consistent with `WdfDeviceInitSetExclusive(TRUE)`. Even if so, this only serializes access; it does not restrict *who* may open, and it enables a trivial denial-of-service by holding the single handle.
- **Reachability.** The device is discoverable through `{A2A39220-39F4-4B88-AECB-3D86A35DC748}` and `GUID_DEVINTERFACE_COMPORT`, and normally through `\DosDevices\COM<N>` / `SERIALCOMM`. Enumeration + `CreateFile` is enough; no administrator-only interface exists.

### 4.3 Conclusion

The driver implements no caller-identity gate of its own, and its explicit DACL grants Everyone read/write. **Any unprivileged local process that can open the COM device (or the custom interface) reaches the complete IOCTL switch, including all vendor control-transfer IOCTLs.** The only effective boundary is the open DACL, which is permissive by construction.

---

## 5. Most dangerous exposed capability

### 5.1 `0x222028` `CP210x_GET_USB_CONTROL_IOCTL` - unchecked USB transfer length -> kernel pool out-of-bounds write

This is the strongest finding. The handler at `0x140004524`:

1. `WdfRequestRetrieveInputBuffer(Request, 8, &in, &inLen)` at `0x140004541` - 8-byte control header.
2. `WdfRequestRetrieveOutputBuffer(Request, 9, &out, &outLen)` at `0x140004572` - the driver asks for only **9 bytes**.
3. Parses the header at `0x1400045a6` (`FUN_14000331c`): byte 0 selects standard/vendor, IN/OUT, recipient; byte 1 is `bRequest`; `+2` is `wValue`; `+4` is `wIndex`; `+6` is `wLength`.
4. Loads `wLength = *(uint16_t *)(in + 6)` at `0x1400045ab`/`0x14000465c`.
5. Calls `FUN_140002c64(DE, Request, ..., wLength, out + 8)` at `0x1400046dc` (`ADD RBX,8` at `0x1400045b1`, stack argument at `0x1400046d8`).

There is **no comparison between `wLength` and `outLen`**. The sibling SEND case (`0x222024`) does have such a check - `inputLen - 8` vs. `wLength` at `0x140004661`-`0x140004679` - but the GET case omits it.

The call then enters:

- `FUN_140002c64` (`0x140002c64`) -> `FUN_140002db0` (`0x140002db0`) with `wLength` and `out+8`;
- `FUN_140002db0` at `0x1400024e1`-`0x14000250c` calls `FUN_1400024b0(DE, completion, DE, wLength, out+8, &memory)`;
- `FUN_1400024b0` at `0x14000250c` calls WDF memory-create-preallocated (`0x14000d748`) with **`Buffer = out+8` and `BufferSize = wLength`** (pseudo-code Evidence `ev_5693c3f51df11abb982dea2fc3230c4cdfa7ba1dcf9299c2e956e508b0045daf`);
- the resulting `WDFMEMORY` is attached to a USB target request and formatted as a control IN transfer of `wLength` bytes (Evidence `ev_4064972b7922767421099090bb0b0eb3f86d932d8e82f09b5044772b9722447b`).

Because the IOCTL is `METHOD_BUFFERED`, the input and output buffers are the same system buffer. With a 9-byte output buffer, `out+8` points at the **last byte** of the allocation, while the USB stack is told the buffer is `wLength` bytes long. A standard `GET_DESCRIPTOR(DEVICE)` request returns 18 bytes and writes 17 bytes past the allocation.

Concrete static trigger (no malicious device required):

```
DeviceIoControl(hCom, 0x222028,
    input:  80 06 00 01 00 00 12 00    // IN, standard, device; GET_DESCRIPTOR; wValue=0x0100; wLength=18
    inputLength: 8,
    output: 9-byte buffer,
    outputLength: 9)
```

`byte0 = 0x80` -> IN + standard + device recipient; `bRequest = 0x06`; `wValue = 0x0100`; `wIndex = 0`; `wLength = 0x0012`. The CP210x returns its 18-byte device descriptor; the driver's USB request writes 18 bytes starting one byte before the end of the 9-byte system buffer.

**Impact:** kernel non-paged pool out-of-bounds write of up to 65,535 bytes (attacker-controlled length and largely attacker-controlled contents from the device response), reachable by any local user because of the `WD` ACE. This is a local privilege-escalation primitive. The static defect is definite; the exact overflow size depends on the length actually returned by the attached USB device, but 18 bytes is guaranteed by the standard device-descriptor response.

### 5.2 Secondary: `0x222024` `CP210x_SEND_USB_CONTROL_IOCTL`

The SEND path performs an attacker-controlled USB control transfer OUT with `bRequest`, `wValue`, `wIndex`, and up to `inputLen-8` bytes of payload. The length is bounded against the input buffer (`0x140004661`-`0x140004679`), so it is not a kernel memory-safety bug, but it lets an unprivileged user issue arbitrary vendor/standard OUT requests to the CP210x (e.g. EEPROM/vendor commands, device reconfiguration) and, together with `0x222094` (`WRITE_LATCH`, `wValue 0x37E1`), toggle the bridge's GPIO pins. This is a device-integrity/physical-effect capability, subordinate to 5.1.

### 5.3 Not the headline

The remaining vendor IOCTLs are bounded copies of cached descriptors/strings or single-byte status reads (`0x222008`, `0x22200C`, `0x222080`-`0x22209C`), and the 37 standard serial codes operate on the serial device extension with explicit buffer sizes. No comparable unchecked copy was found in those branches.

---

## 6. VERDICT

**VULNERABLE (static) - high-severity local privilege-escalation exposure.**

- The driver explicitly assigns `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)` to the device (`0x14001089c`, SDDL at `0x14000c250`), granting **Everyone** read/write. There is no `SeSinglePrivilegeCheck`, requestor-mode check, or per-IOCTL access mask anywhere in the driver.
- IOCTL `0x222028` (`CP210x_GET_USB_CONTROL_IOCTL`, handler `0x140004524`) trusts a user-supplied `wLength` and wraps `output+8` as a `wLength`-byte buffer (`0x1400045b1`, `0x1400046dc` -> `0x1400024b0` -> `0x14000250c`), although the output buffer is only guaranteed to be 9 bytes. A standard `GET_DESCRIPTOR(DEVICE)` request overflows the kernel system buffer.
- Consequence: an unprivileged local user with the device present can cause a kernel pool out-of-bounds write, with up to 65,535 bytes of transfer length, without any administrator privilege.
- Secondary exposure: arbitrary vendor USB control transfers (`0x222024`) and GPIO latch writes (`0x222094`) are also available to unprivileged users.
- Static confidence in the missing bound check and the permissive DACL is high. Dynamic confirmation (actual pool layout, exploitability) was not performed and is outside this static-only audit.

*End of report.*
