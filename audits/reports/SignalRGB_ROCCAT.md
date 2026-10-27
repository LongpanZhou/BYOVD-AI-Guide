# Audit: SignalRGB `ftdibus` (x2) and ROCCAT `ScpVBus` (x2) - current-scope re-audit

| Field | Value |
|---|---|
| File(s) | `drivers\ftdibus_8C494A63.sys` (x64), `drivers\ftdibus_731AA4E6.sys` (x86), `drivers\ScpVBus_B1B85035.sys` (x64), `drivers\ScpVBus_A12F3C7C.sys` (x86) |
| SHA-256(s) | `8C494A63B270D8605AB9A4AD7D5AE074F7D466D64ADBA36F5E559210ECB35617`<br>`731AA4E6CA473419AB392589C52D92514B82E2ECAF29945F59F77912BDF3F27C`<br>`B1B85035D7E5195A812F057542666C387AFF5A324BA7A3A719B028C895A69833`<br>`A12F3C7C62D852FEB0E7DFB48E4D4A9C88BD0132C3089B5D7079E01B37E5CC15` |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local Ghidra 12.1.4 headless (PE load, auto-analysis, decompiler) + `llvm-objdump` 21 disassembly + direct PE header/resource parsing. **REA was not used**: the shared bridge is at capacity (4 audits active), per the task constraint. No load, execute, install, service, or registry operation; no web. |
| Reach tier | **R1** - `\Device\Ftdiport_Com_N` is opened through a `\DosDevices` symlink whose DACL grants `WD` (Everyone) `GRGW`, and the vulnerable vendor IOCTLs are `FILE_ANY_ACCESS`. ScpVBus is **R3/composition** (admin-only FDO must first plug a child PDO). |
| Setup required | **hardware** for the FTDI primitive (an FTDI FT232H / FT-X class device must be enumerated). **composition** for ScpVBus (root-enumerated bus + admin plug). |
| Write quality | **W2** - caller-controlled length and device-controlled content into a kernel pool buffer at a fixed offset; target is not an arbitrary VA. |
| Verdict | **MW2 - reach=R1 setup=hardware write=W2 load=signed** (FTDI x64). Overall for the four files: **MW2**, carried entirely by `ftdibus_8C494A63.sys`; the other three are `NO-MEMORY-WRITE` or `BLOCKED (i386)`. |
| HW-only | no (the FTDI write lands in kernel pool memory, not in MSR/port/MMIO space) |

**Headline:** the historical "NO-WRITE" verdict for this family is **wrong for the x64 FTDI build**. Four `0x2221E4`-`0x2221F0` vendor-EEPROM IOCTLs take the transfer length straight out of the user's input buffer and hand it to `URB_FUNCTION_VENDOR_DEVICE` with `TransferBuffer = SystemBuffer + N`, where the system buffer is only `max(InputBufferLength, OutputBufferLength)` bytes. Two of the four are IN transfers, so the USB core writes that many device-returned bytes into the under-sized pool block. ScpVBus remains a genuine no-write: its Everyone-RWX DACL is real but only guards fixed-size HID/URB operations.

---

## 0. Verification and per-file results

All four hashes were recomputed with `Get-FileHash -Algorithm SHA256` and match the values above. PE machine field was read directly (not from Ghidra) to settle architecture:

| File | Machine | PE | Arch | Version | Size |
|---|---|---|---|---|---|
| `ftdibus_8C494A63.sys` | `0x8664` | PE32+ | **AMD64** | 2.12.28 | 129,448 |
| `ftdibus_731AA4E6.sys` | `0x014C` | PE32 | **i386** | 2.12.28 | 105,200 |
| `ScpVBus_B1B85035.sys` | `0x8664` | PE32+ | **AMD64** | 1.7.1.2 | 44,080 |
| `ScpVBus_A12F3C7C.sys` | `0x014C` | PE32 | **i386** | 1.7.1.2 | 28,368 |

**Both "older build" pairings in the historical baselines are wrong.** `ftdibus_731AA4E6.sys` is not an older 2.12.28 link of `8C494A63` - it is the **32-bit build of the same version**. `ScpVBus_A12F3C7C.sys` is likewise the **32-bit build of 1.7.1.2**, not simply an older ScpVBus. Neither i386 image can load on this x64 host.

| File | Effective device DACL | Open gate | User-reachable IOCTL surface | Memory write | Per-file verdict |
|---|---|---|---|---|---|
| `ftdibus_8C494A63.sys` (x64) | COM PDO: `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)` - live | `WD` GRGW via `\DosDevices\Ftdiport_Com_N`; port must be "ready" | `0x222000`-`0x2221F0`, all METHOD_BUFFERED / FILE_ANY_ACCESS | **W2**: `0x2221E4` / `0x2221EC` unvalidated `TransferBufferLength` -> pool OOB write (IN URB); `0x22209C` 1-byte NUL off-by-one | **MW2** |
| `ftdibus_731AA4E6.sys` (x86) | Same SDDL present and pushed to `WdmlibIoCreateDeviceSecure@36` (`0x4049FA`) | n/a - cannot load on x64 | Same switch **minus** `0x2221E4`-`0x2221F0` (no such immediates in the image) | No equivalent path found | **BLOCKED** (i386 image) |
| `ScpVBus_B1B85035.sys` (x64) | FDO: plain `IoCreateDevice`, no SDDL -> SYSTEM/Administrators. Child PDO: `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)` - live | FDO admin-only; child PDO world-RWX, created only by `0x2AA004` | `0x2AA004/8/C`, `0x2AE010`, `0x2AE404/8/C/10` (all BUFFERED, exact length checks) | **W0** - fixed-size descriptor/report writes into kernel-supplied URB buffers | **NO-MEMORY-WRITE** |
| `ScpVBus_A12F3C7C.sys` (x86) | Same SDDL present and pushed to `WdmlibIoCreateDeviceSecure@36` (`0x405ED7`, UNICODE_STRING at `0x403180`) | n/a - cannot load on x64 | Same model as x64 | **W0** | **BLOCKED** (i386 image) |

---

## 1. Family A - FTDI `ftdibus` 2.12.28

### 1.1 Internals

WDM USB function driver (325 functions modelled). `ftdibus` binds the FTDI USB device, creates an unnamed FDO, and enumerates one named COM-port PDO per interface. A second driver (`ftser2k`, not in this scope) normally attaches to the PDO to present `\\.\COMx`.

`DriverEntry` = `FUN_140005900` (`8C494A63`):

| DriverObject offset | MajorFunction | Routine |
|---|---|---|
| `+0x68` | `IRP_MJ_DRIVER_UNLOAD` | `FUN_1400068DC` |
| `+0x70` | `IRP_MJ_CREATE` | `FUN_14000B424` |
| `+0x80` | `IRP_MJ_CLOSE` | `FUN_14000B068` |
| `+0x88` | `IRP_MJ_READ` | `LAB_140010204` |
| `+0x90` | `IRP_MJ_WRITE` | `FUN_14001020C` |
| `+0xE0` | **`IRP_MJ_DEVICE_CONTROL`** | **`FUN_1400076B0`** |
| `+0xE8` | `IRP_MJ_INTERNAL_DEVICE_CONTROL` | `FUN_14000A320` |
| `+0x120` | `IRP_MJ_POWER` | `LAB_14000D760` |
| `+0x128` | `IRP_MJ_SYSTEM_CONTROL` | `FUN_140014050` |
| `+0x148` | `IRP_MJ_SHUTDOWN` | `LAB_14000C620` |
| `DriverExtension+0x08` | `AddDevice` | `FUN_140006248` |

### 1.2 Device / interface / effective DACL

**FDO** - `FUN_140006248` (`0x140006248`):

```c
IoCreateDevice(DriverObject, 0x11F0, NULL, 0x22 /*FILE_DEVICE_UNKNOWN*/, 0x80, 0, &dev);
```

Name `NULL`, no `IoCreateDeviceSecure`, no security descriptor => **default DACL (SYSTEM + Administrators)**. It is also unreachable by name, so only `AddDevice`/PnP holds a pointer to it.

**COM-port PDO** - `FUN_1400052F0` (`0x1400052F0`), name built from `\Device\Ftdiport_Com_0` plus a digit (`0x140014D90`), symlink `\DosDevices\Ftdiport_Com_<n>` (`0x140014DC0`):

```c
local_118 = 0x80;                    // DeviceCharacteristics
local_110 = 0;                       // Exclusive = FALSE
local_108 = &DAT_140016470;          // &UNICODE_STRING(SDDL)
local_100 = &DAT_1400163D0;          // &class GUID
WdmlibIoCreateDeviceSecure(DriverObject, 0x1C8, NULL, 0x2A, 0x80, ...);
```

`DAT_140016470` is `{Length=0x72, MaximumLength=0x74, Buffer=0x140016480}` (57 UTF-16 characters); the string at `0x140016480` decodes to exactly:

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)
```

| SID | Access |
|---|---|
| `SY` | `GA` (GENERIC_ALL) |
| `BA` | `GRGWGX` (read/write/execute) |
| `WD` **Everyone** | `GRGW` (read/write) |
| `RC` | `GR` (read) |

The descriptor is **actually used** - it is the SDDL argument of the live `IoCreateDeviceSecure` call for every COM-port PDO, and the historical claim that it is "deliberate COM-port exposure" is correct as to intent. The x86 build carries the identical string at `0x4122C8` and pushes its UNICODE_STRING (`0x4122C0`) at `0x4049FA` in the same creation pattern.

Note: the PDO is created with `Characteristics = 0x80`, **not** `0x100` (`FILE_DEVICE_SECURE_OPEN`). The DACL is therefore enforced on opens that resolve through the device object (the `\DosDevices` symlink), which is the normal user path; it is not additionally hardened against a privileged opener holding a raw PDO pointer.

### 1.3 Dispatch and IOCTL table (`FUN_1400076B0`)

`lVar11 = *(IRP+0xB8)` = `IrpSp`; `IoControlCode = *(u32*)(IrpSp+0x18)`, `InputBufferLength = *(u32*)(IrpSp+0x10)`, `OutputBufferLength = *(u32*)(IrpSp+0x08)`, `SystemBuffer = *(IRP+0x18)` - the standard aligned x64 `IO_STACK_LOCATION`. **Every code in the range is `METHOD_BUFFERED` and `FILE_ANY_ACCESS`** (`code & 3 == 0`; `(code >> 14) & 3 == 0`), so there are no raw user pointers and no `METHOD_NEITHER` paths in this driver.

Ready gate (`0x1400076E0`): if the file object has no FsContext **and** `FUN_14000AF68` says the port is not ready **and** the code is not `0x2221D8`/`0x2221DC`, the driver returns `0xC0000056` (`STATUS_DEVICE_NOT_READY`). `CREATE` deliberately sets `FileObject->FsContext = 0` (`0x14000B424`), so the effective gate is `FUN_14000AF68` - i.e. the port must have been opened successfully against a present, configured device.

| Code | Method / Access | Length check | Kernel action |
|---|---|---|---|
| `0x222000` | BUF / ANY | `outLen >= devDescLen` (`ctx[0x13]+2` u16) | `memcpy(SystemBuffer, descriptor, len)` - bounded by device descriptor |
| `0x222004` | BUF / ANY | - | reset / re-enumerate (`FUN_1400091D0`, `FUN_140009214`, `FUN_140013054`) |
| `0x222008` | BUF / ANY | - | status, no data |
| `0x22200C` | BUF / ANY | `outLen > 0xF` | 16-byte status struct |
| `0x222010` | BUF / ANY | `inLen >= 0x10` | config flags from input dword -> `ctx+0xBC4`, registry persist |
| `0x222028` | BUF / ANY | `inLen >= 0x10` | copy 16 bytes -> `ctx+0x1088` |
| `0x222040` | BUF / ANY | - | purge (`FUN_14000755C`) |
| `0x222080` | BUF / ANY | `outLen > 1` | vendor request `0x90`, 2-byte value (read) |
| `0x222084` | BUF / ANY | `inLen >= 4` | vendor request `0x91` |
| `0x222088` | BUF / ANY | `inLen >= 4` | vendor request `0x92` |
| `0x22208C` | BUF / ANY | `inLen >= 0xC` / `>= 0x10` | store event handle; `ObReferenceObjectByHandle(..., ExEventObjectType, ...)` |
| `0x222090` | BUF / ANY | `outLen > 3` | line status dword |
| `0x222094` | BUF / ANY | `outLen >= 0xC` | counters (clamped to `0x10000`) |
| `0x222098` | BUF / ANY | `inLen == 2` | vendor control |
| `0x22209C` | BUF / ANY | `outLen > 0xF` | **unbounded `strcpy(SystemBuffer, ctx+0xAF1)`** (serial) - see section 1.5b |
| `0x2220A0` | BUF / ANY | `strlen(ctx+0xB02) <= outLen` | `strcpy` product string (checked) |
| `0x2220A4` | BUF / ANY | `outLen > 3` | status dword |
| `0x222104` | BUF / ANY | `inLen >= 4` | vendor request |
| `0x22210C` | BUF / ANY | non-NULL | vendor request (byte) |
| `0x222110` / `0x222114` | BUF / ANY | - | vendor request (`0x4000` / `0`) |
| `0x22211C` | BUF / ANY | `inLen == 8` or `0x14` | timer config |
| `0x222120` | BUF / ANY | `outLen >= 0x14` | read timer config |
| `0x222124` / `0x222128` / `0x222130` / `0x222134` | BUF / ANY | - | vendor helpers |
| `0x222144` | BUF / ANY | `inLen >= 4` | store dword -> `ctx+0x158` |
| `0x222148` | BUF / ANY | `outLen > 3` | read event state (pending-capable) |
| `0x22214C` | BUF / ANY | non-NULL | control flags |
| `0x22215C` | BUF / ANY | non-NULL | vendor (byte) |
| `0x222164` | BUF / ANY | non-NULL | vendor (u16) |
| `0x222168` | BUF / ANY | `outLen > 3` | status dword |
| `0x22216C` | BUF / ANY | `outLen > 3` | RX counter (clamped) |
| `0x222170` / `0x222174` / `0x222178` / `0x22217C` | BUF / ANY | chip-gated | H/X-series vendor helpers (`inLen != 0`, `> 1`) |
| `0x222180` | BUF / ANY | `inLen > 7` | baud divisor, both values range-checked against `ctx[0x11F]`/`ctx[0x120]` |
| `0x222184` | BUF / ANY | `inLen > 3` | set event mask |
| `0x222188` | BUF / ANY | `outLen >= 4` | read mask/pending |
| `0x22218C` | BUF / ANY | `outLen >= 0x10` | 16-byte status |
| `0x222190` | BUF / ANY | `inLen >= 0x1C` | 28-byte config -> `ctx+0xB64` |
| `0x222194` | BUF / ANY | `outLen >= 0x1C` | read 28-byte config |
| `0x222198` | BUF / ANY | `outLen >= 0x60` / `>= 0x68` | device-info struct (chip-table) |
| `0x22219C` / `0x2221A0` | BUF / ANY | - | reset / purge |
| `0x2221A4` | BUF / ANY | `inLen >= 4` | store dword -> `ctx+0x182` |
| `0x2221A8` | BUF / ANY | chip-gated | re-initialise |
| `0x2221AC` | BUF / ANY | `inLen >= 4` | store dword -> `ctx+0xC0C` |
| `0x2221BC` | BUF / ANY | `outLen > 3` | constant `0x21228` |
| `0x2221C0` / `0x2221C4` / `0x2221C8` | BUF / ANY | `outLen >= 4` / `>= 2` / `>= 4` | read context dwords |
| `0x2221CC` | BUF / ANY | `outLen != 0` | vendor request `0x93` |
| `0x2221D0` | BUF / ANY | `inLen > 1` | vendor request `0x94` |
| `0x2221D4` | BUF / ANY | `outLen > 1` | vendor request `0x95` |
| `0x2221D8` | BUF / ANY | `outLen > 3` | RX bytes available (allowed even when not ready) |
| `0x2221DC` | BUF / ANY | - | `FUN_1400110FC` open/setup (allowed even when not ready) |
| `0x2221E0` | BUF / ANY | - | `FUN_140010C74` teardown |
| **`0x2221E4`** | BUF / ANY | **none** (only `SystemBuffer != NULL`) | **vendor IN request `0x20`, `TransferBufferLength = *(u16*)(SystemBuffer+2)`, `TransferBuffer = SystemBuffer+4`** -> `FUN_140012D38` -> `FUN_1400094B8(..., flags=3)` |
| **`0x2221E8`** | BUF / ANY | **none** | vendor OUT request `0x21`, length `*(u16*)(SystemBuffer+2)`, buffer `SystemBuffer+4` -> OOB **read** fed to the device |
| **`0x2221EC`** | BUF / ANY | **none** | **vendor IN request `0x22`, `TransferBufferLength = *(u16*)(SystemBuffer+4)`, `TransferBuffer = SystemBuffer+0x18`** -> `FUN_140012D18` |
| **`0x2221F0`** | BUF / ANY | **none** | vendor OUT request `0x23`, length `*(u16*)(SystemBuffer+4)`, buffer `SystemBuffer+0x18` -> OOB **read** |
| default | - | - | `0xC0000010` (`STATUS_INVALID_DEVICE_REQUEST`) |

Chip-type gate for the `0x2221xx` H/X-series group (`0x14000904E`-`0x1400090A1`): the high byte of the chip id must be one of `0x1400`, `0x1500`, `0x1600`, `0x1700`, `0x1800`, `0x1900`, `0x2100`, `0x2700` (FT232H / FT-X class). Other chips fall to `0xC0000001`.

### 1.4 Access-control audit

* The only gate is the device DACL. `IRP_MJ_CREATE` (`FUN_14000B424`) performs **no** caller-identity, privilege, or `FILE_WRITE_ACCESS` check; it sets `FileObject->FsContext = 0`, increments the open counter, brings the port up, and allocates the 256 KB RX ring plus four 256 KB endpoint buffers.
* All vendor IOCTLs are `FILE_ANY_ACCESS`; both the `GR` and `GW` halves of the `WD` ACE are sufficient for `0x2221E4`.
* `SeSinglePrivilegeCheck` / `SeAccessCheck` are not imported and not dynamically resolved. The embedded Wdmlib init does resolve `IoValidateDeviceIoControlAccess` (`0x14001BA2B` -> `MmGetSystemRoutineAddress` -> global `0x1400182A8`), but that global is **written once and never read** - the DEVICE_CONTROL dispatch never calls it, so it is linked-but-dead library code, not an access gate.
* Consequence: any local user can open `\\.\Ftdiport_Com_<n>` and issue the full vendor surface. No administrator gate exists on this path.

### 1.5 Memory-write trace

#### (a) Primary - unvalidated URB transfer length (W2)

`FUN_1400094B8` (`0x1400094B8`) is the single vendor-request builder:

```c
urb = ExAllocatePoolWithTag(pool, 0x298, 'Ftdi');
urb->Hdr        = 0x170088;   // Length 0x88, Function 0x17 = URB_FUNCTION_VENDOR_DEVICE
urb->TransferFlags        = param_6;      // 3 = USBD_TRANSFER_DIRECTION_IN | SHORT_TRANSFER_OK
urb->TransferBufferLength = param_5;      // caller u16, NOT validated
urb->TransferBuffer       = param_4;      // caller pointer, NOT validated
urb->Request  = 0x20/0x21/0x22/0x23;
irp = IoBuildDeviceIoControlRequest(0x220003 /*IOCTL_INTERNAL_USB_SUBMIT_URB*/,
                                    lowerDevice, 0,0,0,0, ...);
// URB pointer is stored in the slot the callee reads as Parameters.Others.Argument1:
//   mov rax,[irp+0xB8] ; mov [rax-0x40], rdi   (0x1400095B7 / 0x1400095BE)
IofCallDriver(lowerDevice, irp);
```

Ground truth, `8C494A63`:

```
14000952a  mov  [rdi+0x24], eax        ; TransferBufferLength = *(u16*)[rsp+0xb0]  (param_5)
140009534  mov  [rdi+0x20], eax        ; TransferFlags        = param_6
14000953f  mov  [rdi+0x28], rbx        ; TransferBuffer       = param_4 (r9)
1400095b7  mov  rax, [rax+0xb8]
1400095be  mov  [rax-0x40], rdi        ; URB pointer into Parameters.Others.Argument1
```

Call sites (both are IN transfers, `param_6 = 3`, and **neither inspects `InputBufferLength` or `OutputBufferLength`**):

```
; IOCTL 0x2221E4
1400090af  test rdi, rdi               ; only check: SystemBuffer != NULL
1400090b2  je   0x1400091b1
1400090b8  movzx r9d, word ptr [rdi+2] ; length  = user input bytes [2..3]   (0..0xFFFF)
1400090bd  lea  r8, [rdi+4]            ; buffer  = SystemBuffer + 4
1400090c1  mov  dl, byte ptr [rdi]     ; Request = user input byte [0]
1400090c6  call 0x140012d38            ; -> FUN_1400094B8(..., 3, ...)  IN

; IOCTL 0x2221EC
140008f63  test rdi, rdi               ; only check: SystemBuffer != NULL
140008f6c  movzx r9d, word ptr [rdi+4] ; length  = user input bytes [4..5]
140008f71  lea  r8, [rdi+6]            ; buffer  = SystemBuffer + 0x18
140008f75  movzx edx, word ptr [rdi]
140008f7b  call 0x140012d18            ; -> FUN_1400094B8(..., 3, ...)  IN
```

Because the IOCTL is METHOD_BUFFERED, `SystemBuffer` is a pool allocation of `max(InputBufferLength, OutputBufferLength)` bytes. A caller can therefore supply four input bytes (making the block four bytes), put an arbitrary 16-bit length in bytes `[2..3]`, and the driver will ask the USB core for that many bytes with `TransferBuffer` pointing **four bytes past** a four-byte pool block. On completion of the IN transfer the host controller writes the device's response into that address range - a kernel pool out-of-bounds write whose **length is caller-controlled** (up to `0xFFFF`) and whose **content is device-controlled**. `0x2221EC` is the same primitive with an offset of `0x18`.

`0x2221E8` / `0x2221F0` are the mirror OUT transfers (`TransferFlags = 0`): the USB core reads `length` bytes from `SystemBuffer+4` / `+0x18` and sends them to the device - a kernel pool OOB **read** (info leak to the device), not a write.

Constraints:

* Requires a live FTDI FT232H / FT-X device (the chip-id gate at ~`0x140009080`-`0x1400090A1` accepts `0x1400`-`0x1900`, `0x2100`, `0x2700`), i.e. the COM-port PDO must exist and be "ready".
* Requires the device to answer vendor request `0x20`/`0x22` with more bytes than the system buffer holds. A stock chip returns at most its EEPROM/user-area content; a reflashed or emulated FTDI device can return up to the requested `wLength`. Either way the transfer is short-transfer-tolerant (`USBD_SHORT_TRANSFER_OK`), so a partial response still lands in the undersized block.
* Target is the I/O manager's pool block, not an arbitrary kernel VA, and the write offset is fixed (`+4` or `+0x18`). That is a constrained pool overflow -> **W2**, not W1.
* No `MmMapIoSpace`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, or MDL-mapped user write exists anywhere in the image.

#### (b) Secondary - unbounded `strcpy` into the system buffer (`0x22209C`)

`FUN_1400113C8` is a plain NUL-terminated `strcpy`. `0x22209C` calls it with `dest = SystemBuffer`, `src = ctx+0xAF1`, guarded only by `OutputBufferLength > 0xF`. The serial field at `ctx+0xAF1` is produced by `FUN_1400039A4(..., max = 0x10)`, whose converter (`FUN_140003920`) copies at most 16 characters and always NUL-terminates - so the field can hold a 16-character serial plus terminator (17 bytes). With `OutputBufferLength == 0x10` that is a **one-byte NUL write past a 16-byte pool block**: a narrow off-by-one (W3), not the primary primitive, and its practical effect is confined to allocator padding. Recorded for completeness; not counted toward the verdict.

#### (c) MDL path - not a user-controlled write

`FUN_140002848` (RX completion) takes the pending read URB, and if the MDL is not already mapped calls `MmMapLockedPagesSpecifyCache(mdl, 0 /*KernelMode*/, 1 /*MmCached*/, NULL, FALSE, DAT_140018264 | 0x10)`, then copies from the driver's 256 KB RX ring into the mapped buffer with

```c
uVar6 = urb->TransferBufferLength;
if (available < urb->TransferBufferLength) { urb->TransferBufferLength = available; uVar6 = available; }
```

Both the destination length and the source are clamped to the driver's own ring state. This is the ordinary serial RX path, not a caller-controlled write.

### 1.6 FTDI verdict

**MW2 - reach=R1 setup=hardware write=W2 load=signed.** A real kernel pool out-of-bounds write with caller-controlled length and device-controlled data, behind the world-writable COM-port DACL and the `0x2221E4` / `0x2221EC` vendor IOCTLs. Hardware-gated: an FT232H / FT-X device (or an emulated equivalent) must be enumerated and the port opened. Under a strict reading of the SEVERITY matrix (which maps "R3 hardware + W2" to MW3) this would be MW3; MW2 is retained because the access path is unprivileged (`R1`), the hardware is commodity/stageable, and this matches the project's `silabser` (CP210x, W2 pool OOB) precedent.

---

## 2. Family B - ROCCAT / Nefarius `ScpVBus` 1.7.1.2

### 2.1 Internals

Root-enumerated virtual bus driver. `DriverEntry` = `FUN_14000D000`:

| DriverObject offset | MajorFunction | Routine |
|---|---|---|
| `+0x68` | `IRP_MJ_DRIVER_UNLOAD` | `FUN_140009158` |
| `+0x70` / `+0x80` | `IRP_MJ_CREATE` / `IRP_MJ_CLOSE` | `FUN_14000909C` (shared) |
| `+0xE0` | **`IRP_MJ_DEVICE_CONTROL`** | **`FUN_140001D18`** |
| `+0xE8` | **`IRP_MJ_INTERNAL_DEVICE_CONTROL`** | **`FUN_1400015D0`** |
| `+0x100` | `IRP_MJ_PNP` | `FUN_140009000` |
| `+0x120` | `IRP_MJ_POWER` | `FUN_14000234C` |
| `+0x128` | `IRP_MJ_SYSTEM_CONTROL` | `LAB_14000913C` |
| `+0x148` | `IRP_MJ_SHUTDOWN` | `FUN_14000A3F8` |
| `DriverExtension+0x08` | `AddDevice` | `FUN_140009B24` |

This is the key correction to the historical report: `0x220003/0x220007/0x220013` are on **`IRP_MJ_INTERNAL_DEVICE_CONTROL`**, not `IRP_MJ_DEVICE_CONTROL`. They are the bus driver's **URB submission** interface (`IOCTL_INTERNAL_USB_SUBMIT_URB = 0x220003`) used by the USB stack that binds above the emulated controller. A user-mode `DeviceIoControl` call can never reach `FUN_1400015D0`.

### 2.2 Device / interface / effective DACL

**FDO** - `FUN_140009B24` (`0x140009B24`):

```c
IoCreateDevice(DriverObject, 200, NULL, 0x2A /*BUS_EXTENDER*/, 0x100, /*Exclusive*/ 1, &dev);
IoRegisterDeviceInterface(PhysicalDeviceObject, &GUID_DEVINTERFACE_SCPVBUS, ...);
```

No SDDL => **default DACL (SYSTEM + Administrators)**. The FDO is also exclusive (`Exclusive = TRUE`), so even an administrator cannot open it twice. Unprivileged users cannot open it at all.

**Child PDO** - `FUN_14000A25C` (`0x14000A25C`), reached from `0x2AA004`:

```
14000a2e9  mov  edx, 0xb8              ; DeviceExtensionSize
14000a2d4  mov  r9d, 0x2a              ; DeviceType
14000a2e1  xor  r8d, r8d               ; DeviceName = NULL  (FILE_AUTOGENERATED_DEVICE_NAME)
14000a2f2  lea  rax, [0x1400042a0]     ; &UNICODE_STRING(SDDL)
14000a303  mov  dword ptr [rsp+0x20], 0x180   ; Characteristics
14000a2fe  mov  byte ptr [rsp+0x28], 0        ; Exclusive = FALSE
14000a30b  call 0x14000a708            ; WdmlibIoCreateDeviceSecure
```

`0x1400042A0` = `{Length=0x7E, MaximumLength=0x80, Buffer=0x1400042B0}`; the string at `0x1400042B0` decodes to:

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)
```

| SID | Access |
|---|---|
| `SY` | `GA` |
| `BA` | `GRGWGX` |
| `WD` **Everyone** | `GRGWGX` (read/write/execute) |
| `RC` | `GRGWGX` |

So the **Everyone/WD DACL is real and live**, but only on PDOs that are created on demand when an administrator (or the SCP service) sends `0x2AA004` to the FDO. A fresh boot has no world-openable ScpVBus device. `Characteristics = 0x180` = `FILE_DEVICE_SECURE_OPEN | FILE_AUTOGENERATED_DEVICE_NAME`, so the DACL follows the auto-generated `\Device\000000xx` name and its interface.

The x86 build is identical in this respect: `0x405ED7` calls `WdmlibIoCreateDeviceSecure@36` with the UNICODE_STRING at `0x403180` (`Buffer = 0x403188`) holding the same SDDL.

### 2.3 Dispatch and IOCTL tables

#### (a) `IRP_MJ_DEVICE_CONTROL` - `FUN_140001D18` (user reachable)

`piVar6 = *(IRP+0x18)` = `SystemBuffer`; the ioctl code is read from `IrpSp+0x18`, input length from `IrpSp+0x10`, output length from `IrpSp+0x08`. Every case is `METHOD_BUFFERED` with exact equality checks on the lengths and on the embedded `Size` field.

| Code | Access | Check | Action |
|---|---|---|---|
| `0x2AA004` | WRITE | `inLen == 0x10 && *(u32*)buf == 0x10` | `FUN_14000A25C` - create a child PDO (SDDL above), fixed 0x6C hardware-ID string |
| `0x2AA008` | WRITE | `inLen == 0x10 && Size == 0x10` | `FUN_14000A5C4` - unplug by serial (PID-relevant) |
| `0x2AA00C` | WRITE | `inLen == 0x10 && Size == 0x10` | `FUN_140009D08` - eject |
| `0x2AE010` | RW | `inLen == 0x1C && Size == 0x1C` | `FUN_140001FA8` - submit 20-byte input report; **PID-gated** (`ctx+0xB0 == PsGetCurrentProcessId()`, else `0xC0000022`) and serial-matched |
| `0x2AE404` | RW | out/in length 4 | is-plugged |
| `0x2AE408` | RW | `outLen == 1` | creating PID |
| `0x2AE40C` | RW | length 4 | empty slots |
| `0x2AE410` | RW | `outLen == 4` | version (`0x1712`) |

`0x2AE010` writes the 20-byte report into a pending read URB's transfer buffer (see section 2.4); it never writes to a user-supplied address.

#### (b) `IRP_MJ_INTERNAL_DEVICE_CONTROL` - `FUN_1400015D0` (kernel only)

| Code | Method | Access | Action |
|---|---|---|---|
| `0x220003` | NEITHER | ANY | **URB submission** (`IOCTL_INTERNAL_USB_SUBMIT_URB`). `URB = *(PURB*)(IrpSp+0x08)` (`Parameters.Others.Argument1`). Branches on `URB->Function` bits: descriptors, select-config, class/vendor requests, bulk/interrupt IN completion |
| `0x220007` | BUFFERED | ANY | no-op success |
| `0x220013` | NEITHER | ANY | `*(u32*)URB = 3` (status/version) |

The historical report's "destination provenance is ambiguous / `[stack+8]` may be OutputBufferLength" is now resolved: `[IrpSp+8]` is `Parameters.Others.Argument1`, which is exactly where `IOCTL_INTERNAL_USB_SUBMIT_URB` carries the `PURB`. The `{u16 size; u16 type; ...; u32 len@0x24; void *buf@0x28}` structure is a **`_URB`** (`TransferBufferLength` @`0x24`, `TransferBuffer` @`0x28`), supplied by the kernel USB stack, not by user mode.

### 2.4 Memory-write trace

* **Descriptor writes** (`0x220003`, type 0/1/8/9/10): fixed Xbox 360 HID descriptor templates written into `URB->TransferBuffer`. The `0x58` branch checks `URB->TransferBufferLength >= descriptor length` (`cmp [urb+0x24], ecx; jb error`) before `memcpy`; the `0x130` branch is bounded by the URB header length. No caller-chosen address and no caller-chosen length.
* **`0x220013`**: writes a fixed dword `3` to the URB pointer. Fixed value, kernel-supplied URB.
* **Report completion** (`FUN_140001FA8`): copies 20 bytes into `URB->TransferBuffer` after setting `URB->TransferBufferLength = 0x14`. The URB belongs to the kernel USB client (xusb21/hidusb, which uses a 0x14-byte input-report buffer). Residual: a kernel client that submitted a shorter interrupt-IN buffer would receive a 20-byte overwrite - not user-reachable and not controllable from `0x2AE010`.
* **`0x2AA004`**: `ExAllocatePoolWithTag(0, 0x6C)` then a fixed literal hardware-ID copy (`_snwprintf`-built `USB\VID_045E&PID_028E...`); no caller length, no caller pointer.
* No `MmMapIoSpace`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `MmMapLockedPages*`, or `ProbeForWrite` in the image.
* The FDO is admin-only, so the bus-management IOCTLs cannot be used by a standard user without a pre-existing child PDO. A child PDO *is* world-RWX, and sending `0x2AA004` to a child re-enters `FUN_14000A25C` with the child extension, whose `+0x48` fast-mutex/`+0x30` list were never initialised as such => likely `ExAcquireFastMutex` on garbage / list corruption. That is a **DoS**, explicitly out of scope, and not a controlled write.

### 2.5 ScpVBus verdict

**NO-MEMORY-WRITE (W0)** for `ScpVBus_B1B85035.sys`. The Everyone-RWX DACL is genuine but protects only fixed-size HID descriptor/report operations and a URB interface that is unreachable from user mode. The `0x220003` write that the historical report left open is a kernel-only URB submission whose destination and length both come from the kernel USB stack. `ScpVBus_A12F3C7C.sys` is the same design but **BLOCKED (i386 image)** on this host.

---

## 3. Build comparison - material differences only

| Pair | Material difference |
|---|---|
| `ftdibus_8C494A63` vs `731AA4E6` | **Architecture** (AMD64 vs i386), same 2.12.28 version. The x64 build adds the H/X-series EEPROM IOCTLs `0x2221E4`-`0x2221F0`; the x86 switch stops at `0x2221E0` and contains no immediate for `0x2221E4/8/C/F0` (byte-pattern scan: not found), so it has **no equivalent unvalidated-URB path**. The x86 build still carries the same SDDL and the `0x22209C` `strcpy`, and is not loadable on x64. |
| `ScpVBus_B1B85035` vs `A12F3C7C` | **Architecture** (AMD64 vs i386), same 1.7.1.2 version, same SDDL, same device model and same `0x220003` URB handler. No behavioural difference found beyond pointer width; the x86 image is not loadable on x64. |

The historical baselines treated each pair as two same-architecture builds and did not record the architecture split; that is the main factual error inherited from them, alongside the FTDI "every case length-checks" claim.

---

## 4. Limitations and unresolved paths

1. **REA not used** (bridge at capacity). Evidence is Ghidra 12.1.4 headless decompilation plus `llvm-objdump` ground truth; project and scripts retained under `%TEMP%\opencode\sig_audit` (`proj\SigAudit`, `out\*.txt`).
2. **No dynamic confirmation.** The FTDI OOB write is established statically from the URB construction and the METHOD_BUFFERED allocation rule; the exact number of bytes the USB core writes depends on the device's response to vendor request `0x20`/`0x22`, which was not measured (no hardware, no VM run).
3. **Vendor request semantics** (`0x20`-`0x23`) were not resolvable from the image alone and no external lookup was permitted; the primitive does not depend on their meaning, only on the device returning more bytes than the system buffer holds.
4. `0x22209C` off-by-one: whether the 16-character serial always reaches the full 17 bytes depends on the device's string descriptor; worst case is a 1-byte NUL past a 16-byte pool block.
5. ScpVBus child-PDO creation from a child PDO (uninitialised fast-mutex/list) is a probable bugcheck, rated DoS only. Not tested.
6. `WdmlibIoCreateDeviceSecure` resolves `IoCreateDeviceSecure` via `MmGetSystemRoutineAddress` with an embedded SDDL fallback; both paths apply the same descriptor on any supported OS, so the effective DACL conclusion is not version-sensitive.

---

## 5. Overall verdict

**MW2 - reach=R1 setup=hardware write=W2 load=signed.**

| Build | Verdict |
|---|---|
| `ftdibus_8C494A63.sys` (x64) | **MW2** - unvalidated `URB_FUNCTION_VENDOR_DEVICE` transfer length (`0x2221E4`, `0x2221EC`) drives a kernel pool OOB write behind a live Everyone-RW COM-port DACL; hardware-gated to FT232H / FT-X |
| `ftdibus_731AA4E6.sys` (x86) | **BLOCKED** (i386; same version, no `0x2221E4`+ path) |
| `ScpVBus_B1B85035.sys` (x64) | **NO-MEMORY-WRITE** (W0); Everyone-RWX child-PDO DACL is live but only fixed-size HID/URB operations are exposed |
| `ScpVBus_A12F3C7C.sys` (x86) | **BLOCKED** (i386; same design, W0) |

The FTDI primitive is a true kernel memory write, not `HW-ONLY`: the destination is a kernel pool block and the source is device DMA, with caller-controlled length. It supersedes the historical `NO-WRITE` verdict for `ftdibus`.
