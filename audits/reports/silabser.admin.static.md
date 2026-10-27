# Audit: silabser.sys (current scope, static)

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\silabser.sys` |
| SHA-256 | `9393781cf3fd66c9ea21380ec8ec1affa6d84eb27c7eaeb14064bd90d32f27b2` |
| Analysis date | 2026-10-25 |
| Method | Static-only via local REA/Ghidra 12.1.4 headless, with local `objdump` disassembly and direct PE import-table parsing as cross-checks. SHA-256 verified before analysis. No driver load, service creation, device open, IOCTL execution, or registry write. |
| Reach tier | **R1** - unprivileged / authenticated user. The driver-set device SDDL grants Everyone `GRGWGX`; there is no privilege, requestor-mode, process, or per-IOCTL access check. |
| Setup required | **hardware** - a CP210x-family USB device (or a USB stack that enumerates one) must be present and started. A service-only load creates no device object; the PnP start path creates the USB target and aborts without it. |
| Write quality | **W2** - real kernel nonpaged-pool OOB write; target is the pool adjacent to the system buffer, value is device-controlled, size is caller-influenced and device-limited. |
| Verdict | **MW2 - reach=R1 setup=hardware write=W2 load=signed** |
| HW-only | no |
| Supersedes | This report supersedes the verdict in `audits/reports/silabser.md` (old `WRITE-CRITICAL`, pre-2026-10-24 scope). The old file is retained as a historical baseline; it is not modified by this audit. `audits/reports/silabser.dynamic.md` is a Phase A dynamic baseline, not a current-scope verdict. |

> Static-only. No driver was loaded and no IOCTL was sent. Addresses are linked virtual addresses at image base `0x140000000`. The REA sessions used Ghidra 12.1.4; function dossiers retain the evidence IDs listed in section 9.

---

## 1. Internals

`silabser.sys` is a 64-bit PE32+ KMDF minidriver (105,880 bytes; file version 6.7.5.1893; "Silicon Labs CP210x USB to UART Bridge Driver (64-bit)"). PE entry RVA `0x1184` -> VA `0x140001184`; image base `0x140000000`.

- `DriverEntry` is at `0x140016000` (INIT section). It calls `WdfDriverCreate` through slot `0x14000d4e0` at `0x1400160b3`, storing `EvtDriverDeviceAdd = 0x1400107c8` at `0x140016080`. It creates **no** device object and no control device.
- The import table is minimal: 20 NTOSKRNL imports, 1 HAL import (`KeQueryPerformanceCounter`), and 4 WDFLDR imports (`WdfVersionBind`, `WdfVersionBindClass`, `WdfVersionUnbind`, `WdfVersionUnbindClass`). All other WDF services are called through the runtime-populated table at `0x14000d2xx`-`0x14000dcxx`.
- There is **no** `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `MmProbeAndLockPages`, `MmAllocateContiguousMemory`, `SeSinglePrivilegeCheck`, `SeAccessCheck`, or `ObOpenObjectByPointer` import. This rules out a physical-memory/MDL path and a driver-level privilege gate in this image.
- Embedded source paths: `..\src\cp210xusb.c`, `..\src\ioctl.c`, `..\src\utils.c`, `..\src\write.c`.
- Device/wire strings: `\Device\Silabser`, `\DosDevices\`, `SERIALCOMM`, `GUID_DEVINTERFACE_COMPORT`, `SILABUSBSERIALBRIDGE`.

---

## 2. Entry, device, interface, and effective DACL

### 2.1 Load-only state

`DriverEntry` (`0x140016000`) only calls `WdfDriverCreate` (`0x1400160b3`). A service-only load therefore creates no device object, no symbolic link, and no device interface. The driver is a PnP function driver; its device is created only when `EvtDriverDeviceAdd = 0x1400107c8` is invoked on a devnode.

### 2.2 Device creation and SDDL

`EvtDriverDeviceAdd` (`0x1400107c8`-`0x140011220`):

| Action | Address | Detail |
|---|---|---|
| Build device name `\Device\Silabser<N>` | `0x14001085d` | `FUN_140005774` with `L"%ws%u"` at `0x140012640`, prefix `\Device\Silabser` at `0x140012610`, counter `0x14000d12c`. |
| `WdfDeviceInitAssignName` | `0x14001087b` | slot `0x14000d358` |
| `WdfDeviceInitAssignSDDLString` | `0x14001089c` | slot `0x14000d360`, `UNICODE_STRING` at `0x14000c240` |
| `WdfDeviceInitSetExclusive(TRUE)` | `0x1400108b9` | slot `0x14000d330`, `R8B = 1` |
| Device type `0x1b` (`FILE_DEVICE_SERIAL_PORT`) | `0x1400108cf` | slot `0x14000d350` |
| `WdfDeviceCreate` | `0x140010c07` | slot `0x14000d398` |
| Custom interface `{A2A39220-39F4-4B88-AECB-3D86A35DC748}` | `0x1400111b5` | GUID bytes at `0x14000c180` |
| COMPORT interface `{86E0D1E0-8089-11D0-9CE4-08003E301F73}` | `0x14001073a` | GUID bytes at `0x14000c190` |
| DOS symbolic link | `0x1400106c0` | `WdfDeviceCreateSymbolicLink` |
| `SERIALCOMM\DeviceMap` write | `0x140010708` | `RtlWriteRegistryValue` |

The SDDL object at `0x14000c240` is a `UNICODE_STRING` with `Length = 0x007E`, `MaximumLength = 0x0080`, and `Buffer = 0x14000c250`. The 126 bytes at `0x14000c250` decode exactly to:

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)
```

Decoded:

| ACE | SID | Rights |
|---|---|---|
| `A;;GA;;;SY` | Local System | `GENERIC_ALL` |
| `A;;GRGWGX;;;BA` | Built-in Administrators | `GENERIC_READ` + `GENERIC_WRITE` + `GENERIC_EXECUTE` |
| `A;;GRGWGX;;;WD` | **Everyone** | `GENERIC_READ` + `GENERIC_WRITE` + `GENERIC_EXECUTE` |
| `A;;GRGWGX;;;RC` | Restricted Code | `GENERIC_READ` + `GENERIC_WRITE` + `GENERIC_EXECUTE` |

`D:P` is a protected DACL with no inherited ACEs. The `WD` ACE is decisive: any local user can open the device for read/write, and all 49 IOCTLs are `FILE_ANY_ACCESS`. The `WdfDeviceInitSetExclusive(TRUE)` call only serializes opens; it does not restrict who may open. The SDDL is the effective driver-applied DACL: the call at `0x14001089c` is on the success path after name assignment, and a failure there aborts creation rather than falling back to a default descriptor. No later security change exists in the image.

**Reach: R1.** The hardware requirement is a separate Setup field (section 5.4 and section 7), not a privilege tier: once the CP210x device exists, any unprivileged opener reaches the full IOCTL switch.

**Limitation:** the matching INF is not in the corpus. An INF-level `Security` override was not assessed; the descriptor above is the one the driver applies to its FDO.

---

## 3. Dispatch and IOCTL table

### 3.1 Dispatch entry

`EvtIoDeviceControl` is `FUN_140003424` (`0x140003424`-`0x1400049CB`, 5,544 bytes), bound into the default queue configuration at `0x1400110ff`; the queue is created at `0x14001113f`. The callback's prologue resolves the device extension and request context and rejects the device-removed state (`DE+0xf8`/`DE+0xfc`). It performs **no** requestor-mode, process, privilege, or access-mask check. The only gate is `FUN_1400077d8` (XOFF/purge continuation), which is not a security check.

### 3.2 Encoding

Every compared code is `0x1Bxxxx` (`FILE_DEVICE_SERIAL_PORT`) or `0x22xxxx` (`FILE_DEVICE_UNKNOWN`). For all 49 codes:

- bits 31-30 = `00` -> **METHOD_BUFFERED**;
- bits 15-14 = `00` -> **FILE_ANY_ACCESS**;
- buffers are obtained only through `WdfRequestRetrieveInputBuffer` (slot `0x14000d9a8`) and `WdfRequestRetrieveOutputBuffer` (slot `0x14000d9b0`). No `METHOD_NEITHER`, `METHOD_IN_DIRECT`, or `METHOD_OUT_DIRECT` code exists.

### 3.3 Standard serial codes (37)

`Fn = (code >> 2) & 0xFFF`. "In -> Out" are the minimum sizes passed to the retrieve helpers. "-" means the branch delegates or uses no buffer.

| Code | Fn | In -> Out | Observed kernel action |
|---|---|---|---|
| `0x1B0004` | 1 | 4 -> - | Reads baud rate; stores `DE+0x334`; `FUN_1400019f0`. |
| `0x1B0008` | 2 | 8 -> - | Queue-size change; may allocate a new read buffer (section 5.2). |
| `0x1B000C` | 3 | 3 -> - | Validates/stores line control at `DE+0x38c`; `FUN_140001ab8`. |
| `0x1B0010` | 4 | - -> - | `FUN_140004fcc` -> `FUN_140001a34`. |
| `0x1B0014` | 5 | - -> - | `FUN_140004fbc` -> `FUN_140001480`. |
| `0x1B0018` | 6 | 1 -> - | Immediate character; `FUN_1400019ac`. |
| `0x1B001C` | 7 | 20 -> - | Reads five timeouts; rejects all-`0xFFFFFFFF`; stores `DE+0x344`. |
| `0x1B0020` | 8 | - -> 20 | Returns the five stored timeouts. |
| `0x1B0024` | 9 | - -> - | Rejects handshake mode 2; `FUN_140004f94` -> `FUN_140001b20(...,0x101)`. |
| `0x1B0028` | 10 | - -> - | Rejects handshake mode 2; `FUN_140004f6c` -> `FUN_140001b20(...,0x100)`. |
| `0x1B002C` | 11 | - -> - | `FUN_140001968` device reset. |
| `0x1B0030` | 12 | - -> - | Handshake gate; `FUN_140004fa8` -> `FUN_140001b20(...,0x202)`. |
| `0x1B0034` | 13 | - -> - | Handshake gate; `FUN_140004f80` -> `FUN_140001b20(...,0x200)`. |
| `0x1B0038` | 14 | - -> - | `FUN_140001ba4` XOFF. |
| `0x1B003C` | 15 | - -> - | `FUN_140001be8` XON. |
| `0x1B0040` | 16 | - -> 4 | Modem status from `DE+0x238` under spinlock `DE+0x228`. |
| `0x1B0044` | 17 | 4 -> - | Validates bits outside `0x1FFF`; queues on `DE+0x1c8`. |
| `0x1B0048` | 18 | - -> 4 | Retrieves 4-byte output; queues on `DE+0x1c8`. |
| `0x1B004C` | 19 | 4 -> - | Validates mask; queues on `DE+0x1f8`. |
| `0x1B0050` | 20 | - -> 4 | Returns baud rate `DE+0x334`. |
| `0x1B0054` | 21 | - -> 3 | Zero-fills the output buffer and returns line control. |
| `0x1B0058` | 22 | 6 -> - | `SERIAL_CHARS`; stores `DE+0x358`; `FUN_140001b60`. |
| `0x1B005C` | 23 | 6 -> - | Handshake/flow control; stores `DE+0x358`/`0x35c` and `0x42c`/`0x434`. |
| `0x1B0060` | 24 | - -> 16 | Returns the 16-byte wait mask from `DE+0x360`. |
| `0x1B0064` | 25 | 16 -> - | Validates wait mask/event counts; stores `DE+0x360`; `FUN_140001a74`. |
| `0x1B0068` | 26 | - -> 4 | Comm status; returns one byte directly or queues a pending read. |
| `0x1B006C` | 27 | - -> 20 | XOFF counters; uses `KeQueryPerformanceCounter`. |
| `0x1B0070` | 28 | 12 -> - | Handflow; validates second dword > 0; queues on `DE+0x198`. |
| `0x1B0074` | 29 | - -> 0x40 | Properties copy from `DE+0x114`, clamped to `DE+0x160`. |
| `0x1B0078` | 30 | - -> 4 | **Output** 4 bytes; writes one byte from `DE+0x269` (modem status). |
| `0x1B007C` | 31 | 1 -> - | **Input** 1 byte; stores `DE+0x398`; `FUN_140001518`. |
| `0x1B0080` | 32 | - -> 4 | Zero-fills 4 bytes; returns 0. |
| `0x1B008C` | 35 | - -> 0x18 | Returns 24 bytes of statistics. |
| `0x1B0090` | 36 | - -> - | Clears statistics. |
| `0x1B0094` | 37 | - -> 4 | Returns modem-control bits (one byte used). |
| `0x1B0098` | 38 | 4 -> - | Modem control; `FUN_140001b20(...,0x200/0x202)`. |
| `0x1B009C` | 39 | 4 -> - | Reads 4-byte FIFO-control value; no further action. |

`0x1B0084` and `0x1B0088` are not compared and take the invalid-parameter default. The old baseline's rows for `0x1B0078` and `0x1B007C` were swapped; the current rows above reflect the dispatch code (`0x1B0078` retrieves the **output** buffer and writes one byte; `0x1B007C` retrieves a **one-byte input**). This correction does not affect the write verdict.

### 3.4 Vendor / bridge codes (12)

| Code | Fn | In -> Out | Observed kernel action |
|---|---|---|---|
| `0x222008` | `0x802` | - -> 18 | `CP210x_GET_DEVICE_DESCRIPTOR`: copies 18 bytes from `DE+0xd2`. |
| `0x22200C` | `0x803` | - -> >=9 | `CP210x_GET_CONFIG_DESCRIPTOR`: copies `min(outLen, DE+0xf0)` bytes from `DE+0xe8`. |
| `0x222024` | `0x809` | 8+payload -> - | `CP210x_SEND_USB_CONTROL`: OUT control transfer from `input+8`; checks `wLength <= inputLen-8`. |
| `0x222028` | `0x80A` | 8 -> >=9 | `CP210x_GET_USB_CONTROL`: IN control transfer into `output+8` with **unchecked `wLength`** (section 5.1). |
| `0x222080` | `0x820` | - -> 1 | `CP210x_GET_PART_NUM`: byte `DE+0xa0`. |
| `0x222084` | `0x821` | - -> `DE+0xb0` | `CP210x_GET_PRODUCT_STRING`: `min(outLen, DE+0xb0)` from `DE+0xa8`. |
| `0x222088` | `0x822` | - -> `DE+0xd0` | String getter from `DE+0xc8`. |
| `0x22208C` | `0x823` | - -> `DE+0xc0` | `CP210x_GET_SERIAL_STRING`: `min(outLen, DE+0xc0)` from `DE+0xb8`. |
| `0x222090` | `0x824` | - -> 1 | `CP210x_READ_LATCH`: vendor IN (`bRequest 0xFF`); requires 2 bytes for part 8. |
| `0x222094` | `0x825` | 2+ -> - | `CP210x_WRITE_LATCH`: vendor OUT (`bRequest 0xFF`, `wValue 0x37E1`); requires 4 bytes for part 8. |
| `0x222098` | `0x826` | - -> 1 | `CP210x_WAS_DEVICE_REMOVED`: `DE+0xfb`. |
| `0x22209C` | `0x827` | - -> 1 | `CP210x_CHECK_TT_BUFFER_ERROR`: `DE+0xf5`, then clears it. |

---

## 4. Access-control audit

- **No privilege check.** No `SeSinglePrivilegeCheck`, `SeAccessCheck`, or `Se*` security import exists. The dispatch (`0x140003424`) and file-create path (`0x140010088` -> `0x140004fdc`) contain no privilege test.
- **No requestor-mode/process check.** No `WdfRequestGetRequestorMode`, `WdfRequestGetRequestorProcess`, or equivalent call appears on the create or IOCTL paths.
- **No per-IOCTL access mask.** All 49 codes are `FILE_ANY_ACCESS`; the handlers never inspect the file object's granted access.
- **Effective DACL.** The explicit SDDL at `0x14000c250`, applied at `0x14001089c`, grants `WD` (Everyone) `GRGWGX`. Any local user who can open the COM port or the custom interface reaches the full switch.
- **Exclusive open.** `WdfDeviceInitSetExclusive(TRUE)` at `0x1400108b9` serializes access to one handle at a time. It is a DoS/serialization property, not a security gate.
- **Reach.** R1. The only effective boundary is the permissive DACL. An administrator is not required.

---

## 5. Memory-write trace

### 5.1 `0x222028` `CP210x_GET_USB_CONTROL` - unchecked control-IN length into `output+8`

**Dispatch edge.** The binary-search switch reaches the `0x222028` case at `0x140004453` (`JZ 0x140004524`) and the body is `0x140004524`-`0x1400046E1`.

1. **Input header.** `WdfRequestRetrieveInputBuffer(Request, 8, &in, &inLen)` at `0x140004538`/`0x140004541`. The input pointer is saved at `0x14000455C` (`R12`).
2. **Output buffer.** `WdfRequestRetrieveOutputBuffer(Request, 9, &out, &outLen)` at `0x140004564`/`0x140004572`. The output pointer is loaded at `0x14000458A`; `outLen` is loaded at `0x140004582` and stored into the request context at `0x140004592`.
3. **Header parse.** `FUN_14000331c` at `0x1400045A6` decodes byte 0 of the input as `bmRequestType`: bit 7 = direction (IN/OUT), bits 6-5 = request type, bits 0-4 = recipient. The helper's type test is `(byte0 & 0x60) == 0x40`, i.e. it distinguishes only **vendor** (`0x40`) from everything else; `FUN_140002db0` reconstructs the type from that single bit, so a class request (`0x20`) is re-emitted as standard (`0x00`). This type-confusion quirk is separate from the memory-write path; the `0x222028` overflow is reachable with a plain standard request. Byte 1 is `bRequest`; bytes 2-3 are `wValue`; bytes 4-5 are `wIndex`; bytes 6-7 are `wLength`.
4. **`wLength`.** Loaded as a 16-bit value at `0x1400045AB` (low byte) and `0x1400045B5` (high byte); combined at `0x1400045D0`-`0x1400045D5`.
5. **Destination.** `ADD RBX, 8` at `0x1400045B1` makes the transfer buffer `out+8`; the buffer argument is stored at `0x1400045CB`, and `wLength` is stored as the 9th argument at `0x1400045E6`.
6. **No bound check.** The GET path jumps from `0x14000460F` to the common block at `0x1400046CE` and then the call at `0x1400046DC`, without comparing `wLength` with `outLen`. The sibling SEND path (`0x222024`) does have the check at `0x140004661`-`0x140004679` (`RCX = inLen - 8; CMP RCX, wLength; JNC ok; else STATUS_INVALID_BUFFER_SIZE 0xC0000232`). The omission is specific to the GET path.
7. **Call.** `FUN_140002c64(DE, Request, ..., wLength, out+8)` at `0x1400046DC`.

**Downstream.**

- `FUN_140002c64` (`0x140002C64`) routes to `FUN_140002db0` (`0x140002DB0`).
- `FUN_140002db0` reconstructs `bmRequestType` at `0x140002DD0`-`0x140002E37`. Its expected-length guard at `0x140002E44`-`0x140002E76` is taken only when the direction is OUT (`param_5 == 0`); for an IN request the direction is 1 and the guard is skipped. The function loads `wLength` at `0x140002E90`, the buffer at `0x140002EAB`, and calls `FUN_1400024b0` at `0x140002EB3`.
- `FUN_1400024b0` (`0x1400024B0`) creates a WDF memory object. For a non-null buffer and non-zero `wLength`, it calls `WdfMemoryCreatePreallocated` through slot `0x14000d748` at **`0x14000250C`**, with `Buffer = out+8` and `BufferSize = wLength` (`MOVZX R9D, R9W` at `0x140002503`). It sets the completion routine at `0x1400025E3`.
- Back in `FUN_140002db0`, `WdfUsbTargetDeviceFormatRequestForControlTransfer` is called through slot `0x14000dbb0` at `0x140002F64`, with the setup packet, the request, and the preallocated memory. `WdfRequestSend` follows at `0x140002F90` (slot `0x14000d928`).
- With bit 7 of `bmRequestType` set (IN), the USB stack therefore performs a control-IN transfer of `wLength` bytes into the buffer beginning at `out+8`. The driver does not force the direction; the user's header does. With bit 7 clear (OUT), the same unchecked length makes the USB stack read `wLength` bytes from `out+8`, an OOB read to the device (out of scope for this memory-write verdict; see section 5.2).

**Why the buffer is 9 bytes.** The IOCTL is `METHOD_BUFFERED`, so the I/O manager's system buffer is `max(InputBufferLength, OutputBufferLength)`. A caller can pass `InputBufferLength = 8` and `OutputBufferLength = 9`; the system buffer is then 9 bytes, and `out+8` is its last valid byte. `WdfRequestRetrieveOutputBuffer(Request, 9, ...)` accepts this (the minimum is met) and reports `outLen = 9`. The driver never compares `wLength` with that 9.

**Overflow bound.**

- Bytes written = `min(wLength, bytes returned by the device)`.
- Valid tail = 1 byte (`out+8`). Overflow = bytes written - 1.
- `wLength` is 16-bit, maximum `0xFFFF`, so the static maximum is **65,534 bytes past the 9-byte requested buffer** (subject to pool-block rounding, which may absorb the first few bytes).
- With a stock CP210x and a standard `GET_DESCRIPTOR(DEVICE)` request (`wLength = 0x12`), the device returns 18 bytes and the overflow is **17 bytes**; a 2-byte `GET_STATUS` request gives a 1-byte overflow.
- The values written are the device's response bytes, not caller bytes; a hostile or emulated USB device can return up to `wLength` bytes and therefore control both the length (up to the 16-bit limit) and the contents of the overflow.
- No probe is required (`METHOD_BUFFERED`), no `ProbeForWrite` is missing, and no other length check exists on this path.

**Classification.** Real kernel nonpaged-pool OOB write; constrained target (pool adjacent to the system buffer), device-controlled value, caller-influenced size. **W2.**

### 5.2 Other IOCTLs checked for memory writes

| Path | Addresses | Result |
|---|---|---|
| `0x222024` SEND control | `0x140004614`-`0x1400046DC` | OUT transfer from `input+8`; `wLength <= inLen-8` checked at `0x140004661`-`0x140004679`. No kernel memory write. |
| `0x22200C` config descriptor | `0x1400046E6`-`0x140004743` | Retrieval 9; `min(outLen, DE+0xf0)` at `0x140004713`-`0x140004721`; copy from `DE+0xe8` via `0x140004743` -> `0x140003FFA`. Bounded. |
| `0x222084`/`0x222088`/`0x22208C` strings | `0x14000446B`, `0x140004748`, `0x14000491F` | Retrieval minimum equals the cached length; the copy call is at `0x1400044D3`, `0x1400047AC`, `0x14000497F` respectively. Bounded. |
| `0x222008` device descriptor | `0x1400043D7`-`0x14000441B` | Retrieval 18 at `0x1400043F6`; copy 18 at `0x14000440A`-`0x14000441B`. Bounded. |
| `0x1B0074` properties | `0x140003FB1`-`0x140003FFA` | Retrieval `0x40`; `memset(out, 0, outLen)`; copy `min(outLen, DE+0x160)` from `DE+0x114` (`0x140003FD9`-`0x140003FFA`). Writes stay inside the output buffer; any over-read is from the device extension, not a write. |
| `0x1B0008` queue-size change | `0x1400036E3`-`0x14000375F`; `FUN_1400070B0` | `ctx+0x70` is set to the **input system-buffer pointer** at `0x140003714` (assembly `MOV RAX,[RBP-0x18]`), not to a user value. The completion reads the requested size from that buffer at `0x140007101` and installs the newly allocated pool buffer. No caller-chosen destination. |
| `0x222090` READ_LATCH dispatch | `0x1400048C7`; `0x14000188C` | Retrieval 1; the handler checks `outLen != 0` and, for part 8, `outLen >= 2`. Bounded. |
| `0x222094` WRITE_LATCH dispatch | `0x140004882`-`0x1400048C2` | Retrieval 2; `FUN_140002188` checks `inLen >= 2` (part 5) or `>= 4` (part 8). Bounded. |
| `0x1B0054` line control | `0x140003CD4`-`0x140003D01` | Retrieval 3; `memset(out, 0, outputLen)` at `0x140003CEC`; writes 3 bytes. The memset length is the output buffer length. Bounded. |
| `EvtIoRead` / `EvtIoWrite` | `0x140006A38` / `0x140008980` | Each retrieves the caller's buffer with the request length and queues it; no kernel copy and no fixed-size destination. |
| `EvtIoInternalDeviceControl` | `0x1400049CC` | Handles `0x1B0004`, `0x1B0008`, `0x1B000C`, `0x1B0010` with fixed 4-/0x2C-byte buffers. Kernel-originated IRPs only. |

**No caller-chosen destination, no physical/MDL path.** The import table contains no `Mm*` mapping API and no `\Device\PhysicalMemory` access. The only pointer-like user-controlled field found was the `0x1B0008` context field, and assembly confirms it holds the kernel input-buffer pointer, not a user pointer. No write-what-where was found.

**Direction-agnostic note.** The missing `wLength` check is not limited to the IN direction. With bit 7 of `bmRequestType` clear, the driver formats an OUT control transfer over the same `out+8`/`wLength` memory description, so the USB stack reads `wLength` bytes starting at the one-byte tail and sends them to the device. That is a kernel OOB read / info-leak path, not a memory write; it is recorded here for completeness and does not change the W2 verdict.

### 5.3 What the old report got right, and what is corrected

- Confirmed: the missing `wLength`/`outLen` check on `0x222028`, the `WdfMemoryCreatePreallocated(out+8, wLength)` data flow, the permissive `WD` SDDL, the absence of a driver privilege check, and the `METHOD_BUFFERED` nature of all codes.
- Corrected: the old table swapped `0x1B0078` and `0x1B007C` (see section 3.3). The old maximum-overflow wording "65,535 bytes" describes the transfer length; the overflow past the one-byte tail is at most 65,534 bytes (17 with a stock device descriptor).
- Corrected: the old dynamic baseline attributed the hardware-free failure to the `EvtDriverDeviceAdd` naming tail. Static analysis shows a further, hardware-dependent gate in `EvtDevicePrepareHardware` (`0x140011318` -> `0x1400113F8`), which creates the USB target and takes the error path (`0x140011400` -> `0x1400115EA`) without a USB PDO. The dynamic `CM_PROB_FAILED_START` is consistent with that gate (the AddDevice naming tail could also fail on a root stand-in), but in either case the surface requires a real USB device; the exact failing statement was not proven from user mode (see section 5.4).

### 5.4 Setup: load-only vs CP210x hardware

The vulnerable IOCTL is not reachable from a service-only load:

1. `DriverEntry` (`0x140016000`) creates no device object.
2. `EvtDriverDeviceAdd` (`0x1400107c8`) creates the FDO only on a PnP devnode.
3. `EvtDevicePrepareHardware` (`0x140011318`) calls `WdfUsbTargetDeviceCreate` through slot `0x14000db50` at `0x1400113F8`, storing the USB target at `DE+0x70` (`0x1400113DE`/`0x1400113EF`). On failure it jumps to `0x1400115EA`, aborting the start.
4. `CreateFile` runs `EvtFileCreate` (`0x140010088`) -> `FUN_140004fdc` -> `FUN_1400017C8` at `0x1400051C3`. `FUN_1400017C8` issues a synchronous control transfer (`FUN_140002C64` with a null request at `0x1400017FA` -> `FUN_140003124`), which loads `DE+0x70` at `0x140003266` and calls `WdfUsbTargetDeviceSendControlTransferSynchronously` at `0x140003293`. Without a live USB target this open fails, so no handle reaches the IOCTL queue.
5. The `0x222028` transfer itself sends through `DE+0x70` (`0x140002F4B`/`0x140002F64`).

Therefore the setup is `hardware`: a CP210x-family device enumerated by the USB stack (or a USB emulation that presents one) is required. The old dynamic baseline's hardware-free VM correctly found no openable surface; it did not test the primitive.

---

## 6. Most dangerous exposed capability

`0x222028` (`CP210x_GET_USB_CONTROL`) is the only kernel memory-write primitive in this image:

- a local user opens the COM port (Everyone `GRGWGX`), sends an 8-byte control header and a 9-byte output buffer;
- `wLength` from the header is trusted as the transfer length;
- `WdfMemoryCreatePreallocated` wraps the last byte of the 9-byte system buffer as a `wLength`-byte buffer;
- the USB stack writes the device's control-IN response past the allocation.

Impact: nonpaged-pool corruption. With a stock CP210x device descriptor the overflow is 17 bytes; with a hostile/emulated device returning the full requested length it can reach 65,534 bytes and the contents are device-controlled. The target is the pool adjacent to the caller's system buffer, not an arbitrary kernel address, so this is a constrained write (W2), not an arbitrary write.

Secondary capabilities: `0x222024` (arbitrary vendor/standard OUT control transfers) and `0x222094` (GPIO latch writes) are device-integrity/physical-effect operations, not kernel memory writes. `0x222090`/`0x222094` are length-checked.

---

## 7. Verdict

**MW2 - reach=R1 setup=hardware write=W2 load=signed.**

- **MW2, not MW1:** the write target is the pool adjacent to the caller's 9-byte system buffer, not an arbitrary address; the value is the device's response, not caller bytes; and the primitive requires a CP210x-family USB device. `SEVERITY.md` names `silabser`/CP210x as the canonical hardware-gated **MW2** example.
- **MW2, not MW3:** it is a real kernel nonpaged-pool write (not a physical-address mapping), with a caller-influenced size up to 65,534 bytes.
- **MW2, not MW4:** it is not a fixed/narrow value write and is not crash-first; a 17-byte overflow is available with an ordinary device descriptor and can be shaped by the request/device response.
- **Not BLOCKED:** the image is signed by Microsoft Windows Hardware Compatibility Publisher (WHQL); `Get-AuthenticodeSignature` reports `Valid`; the SHA-256 is not in `indexes/dedupe/known_bad_hashes.txt`. No HVCI-incompatible construct was observed (KMDF, no dynamic code, no mapping API).
- **Device-not-present modifier:** if the CP210x is absent, the device does not start and the practical cap is **MW3** per `SEVERITY.md` ("a device not present caps at MW3"). The static primitive remains MW2 with the device present.
- **Reach rationale:** R1 is the DACL-based tier (Everyone `GRGWGX`, no privilege/requestor/access-mask gate). The hardware requirement is recorded in `Setup required`, not used to raise the reach tier. This resolves the matrix as `R1 + W2 = MW2`, matching the explicit `silabser` example.

**Supersedes:** the old `audits/reports/silabser.md` `WRITE-CRITICAL` verdict and its unqualified "any unprivileged user can trigger" phrasing. The defect is real and the SDDL is permissive, but under the current scope it is a hardware-gated constrained pool overflow (MW2), not an unconditional MW1. The old `silabser.dynamic.md` Phase A run remains historical evidence for the load chain and the hardware gate; its Phase B was never executed.

---

## 8. Limitations

- Static-only: no driver load, service, devnode, device open, or IOCTL execution. The exact number of bytes the USB stack writes depends on the attached device's response and was not measured.
- The 17-byte figure assumes a standard 18-byte device descriptor; a different descriptor or vendor request changes the count. The 65,534-byte figure assumes a device that returns the full `wLength`; a stock device short-packets earlier.
- The system buffer is 9 bytes only when the caller passes `InputBufferLength = 8` and `OutputBufferLength = 9`. A larger input or output buffer moves the tail and reduces or eliminates the overflow for a given `wLength`; it does not remove the missing check.
- Pool-block rounding may absorb the first few bytes of the overflow; the reported bound is relative to the requested 9-byte buffer, not the allocator's rounded block.
- The matching INF is not in the corpus; the effective DACL is the driver-applied SDDL at `0x14001089c`. An INF-level security override was not assessed.
- WDF slot names are inferred from call signatures and surrounding data flow (the image imports only `WdfVersionBind*`); the cited addresses and assembly data flow are exact. The identity of `WdfMemoryCreatePreallocated` at `0x14000250c` is supported by its `(attributes, buffer, size, &memory)` signature and the subsequent control-transfer format.
- The old dynamic baseline is hardware-free and Phase A only; it neither confirms nor refutes the OOB. No dynamic confirmation was performed for this report.
- The `0x1B0008` queue-size path was re-checked and is not a caller-chosen destination; `ctx+0x70` is the input system-buffer pointer (`0x140003714`), and the completion reads the size from it (`0x140007101`). No unresolved caller-chosen write remains.

---

## 9. Evidence and method notes

- REA/Ghidra 12.1.4, image base `0x140000000`, document `target-9393781cf3fd.sys`.
- Binary overview: `ev_c3709c7f2c6d147870d95eb1588006e85987c1987999d1170a22139dedfadf95`.
- `FUN_140003424` (dispatch): `ev_f099b0823d12215c5b71ff375b1d639b0acd4cf57a9b2bdefd56547f1c3e27f1`.
- `FUN_1400024b0` (`WdfMemoryCreatePreallocated`): `ev_4ea7da82a2c9897b0d63c3f0f5f30e4e8c96be508e5073b2897c3a198676c1c9`.
- `FUN_140002db0` (control-transfer setup): `ev_a7f319f42bbc0b20e51897d4a8dc96273dba27e54fff794589806705fbb9d766`.
- `FUN_1400107c8` (device add/SDDL): `ev_9ddd03a8a87356a305681849e850e3c2a15302eec81902cc36497656602156be`.
- `FUN_140011318` (prepare hardware/USB target): `ev_6c074b2d0c613b303c6b2f8360da9a8c2d308008e5c306cec6c8d98d0b98e657`.
- `FUN_140004fdc` (file-create init): `ev_1a9a189018126e8a71403dc7376b60e3eeeb6b3900ce3caf6e9c4b3e558d70f4`.
- `FUN_1400070b0` (`0x1B0008` completion): `ev_26a14d911f5ed5dd9be9f9d932e1b4da0e7abadb89fb16809994336b52cfc061`.
- SDDL bytes at `0x14000c250`: `ev_4e7215b13b9e087764dd52ff0d2e47a5d48cf91c4bc10e2625ee6fe1187e15f7`; interface/GUID bytes at `0x14000c180`: `ev_330e2105b203b865f4223971d7111a1c394314d31da7ddc1ac1c9a294ea5c3f6`.
- Cross-check: local `objdump -d` (AT&T) confirmed the `0x222028` case body, the `MOV R8D, 9` output minimum at `0x140004564`, the `ADD RBX, 8` at `0x1400045B1`, the missing comparison, the `0x14000250C` preallocated-memory call, and the assembly-level `0x1B0008` pointer store at `0x140003714`. Direct PE import parsing confirmed the 20/1/4 import set and the absence of mapping/security APIs.

*End of report.*
