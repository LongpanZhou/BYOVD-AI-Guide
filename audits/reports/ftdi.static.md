# FTDI `ftdibus` / `ftser2k` — static audit

**Binaries**
* `drivers\SignalRGB\ftdibus_8C494A63.sys` — 129,448 bytes, x64, image base `0x140000000`, version 2.12.28
  SHA-256 `8C494A63B270D8605AB9A4AD7D5AE074F7D466D64ADBA36F5E559210ECB35617`
* `drivers\SignalRGB\ftser2k_2D07F148.sys` — 89,792 bytes, x64, image base `0x140000000`, version 2.12.28
  SHA-256 `2D07F14812AF8D0796A2056808C092A71275DF3138378AEB2C22A396BEC67051`

**Framework:** WDM. `ftdibus` embeds a copy of `WdmlibIoCreateDeviceSecure` (`0x14001BA5C`) plus the SDDL→security-descriptor converter (`SepSddlLookupAccessMaskInTable` and friends) and resolves `IoCreateDeviceSecure` dynamically via `MmGetSystemRoutineAddress` (`RtlInitUnicodeString(..., L"IoCreateDeviceSecure")` at `0x14001xxxx`). The older 2.12.28 build `ftdibus_731AA4E6.sys` imports `IoCreateDeviceSecure` statically; the difference is link-time only.

## Verdict

**NO-WRITE (kernel memory).** The permissive SDDL is live, but it is applied to the **COM-port PDO** (`\Device\Ftdiport_Com_N`), which is exactly the device the FTDI INF intends to expose to users. The IOCTL surface is the stock FTDI vendor/serial interface: every case either validates `InputBufferLength`/`OutputBufferLength` before touching the buffer, writes into the device extension at fixed offsets, or issues a USB control/bulk transfer. No IOCTL supplies a kernel pointer, a physical address, or a copy length. The devices only exist when a real FTDI USB device is enumerated.

## 1. Device surface

### 1a. `ftdibus` FDO (USB function device)

`FUN_140006248` creates the FDO for the USB device:

```c
iVar2 = IoCreateDevice(param_1, 0x11F0, 0, 0x22, 0x80, 0, &local_res18);
```

* Name `NULL`, device type `0x22`, characteristics `0x80`.
* No `IoCreateDeviceSecure`, no `WdfDeviceInitAssignSDDLString`, no security descriptor → **default device DACL (SYSTEM + Administrators)**.
* Device interface registered with `IoRegisterDeviceInterface` (`\Device\USBFDO-…`).
* Unprivileged users cannot open this FDO.

### 1b. `ftdibus` COM-port PDO

`FUN_1400052F0` builds the name `\Device\Ftdiport_Com_<n>` (from the literal `0x140014D90` plus a digit) and creates it securely:

```c
local_108 = &DAT_140016470;          // &UNICODE_STRING(SDDL)
local_100 = &DAT_1400163D0;          // &GUID (device class)
local_110 = 0;                       // Exclusive = FALSE
local_118 = 0x80;                    // characteristics
uVar8 = WdmlibIoCreateDeviceSecure(DriverObject, 0x1C8, 0, 0x2A);
```

The SDDL `UNICODE_STRING` at `0x140016470` is `Length=0x72`, `MaximumLength=0x74`, `Buffer=0x140016480`, and decodes to:

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)
```

Effective DACL on `\Device\Ftdiport_Com_N`:

| SID | Access |
|---|---|
| `SY` | `GA` GENERIC_ALL |
| `BA` | `GRGWGX` read/write/execute |
| `WD` **Everyone** | `GRGW` **read + write** |
| `RC` | `GR` read |

A `\DosDevices\Ftdiport_Com_<n>` symbolic link is created for the port. This is deliberate COM-port exposure, not a driver bug.

### 1c. `ftser2k` VCP device

`FUN_14000CF8C`:

```c
iVar4 = IoCreateDevice(param_1, 0xDD8, &local_90 /* "\Device\VCP"+n */, 0x1B);
...
uVar6 = IoCreateSymbolicLink(param_1 + 0xB8, puVar2);
```

No `IoCreateDeviceSecure`, no SDDL literal in the image → **default DACL (admin-only)**. The VCP ports are not reachable by an unprivileged user through this driver.

## 2. IOCTL table

### 2a. `ftdibus` (device `0x22`, `FUN_1400076B0`, `0x1400076B0`)

Large vendor switch, `0x222000`–`0x2221F0`, all `METHOD_BUFFERED`; access is `FILE_ANY_ACCESS` for `0x222000` and `FILE_WRITE_ACCESS` for the `0x2228xx` variants (only `0x222000`–`0x2221F0` are dispatched here). The handler first rejects the request with `0xC0000056` when the port is not ready, except for `0x2221D8`/`0x2221DC` (ready/status queries). Representative cases:

| Code | Function | Behaviour |
|---|---|---|
| `0x222000` | 0x800 | copy the device descriptor block (`uVar12` bytes) into the output buffer; checks `outLen >= uVar12` |
| `0x222004` | 0x801 | reset/reenumerate (`FUN_1400091D0`, `FUN_140009214`, `FUN_140013054`) |
| `0x222008` | 0x802 | no-op status if the lower device is present |
| `0x22200C` | 0x803 | 0x10-byte status struct (`*puVar4`, `puVar4[1..3]`), checks `outLen > 0xF` |
| `0x222010` | 0x804 | set config flags from `*puVar4`, persist `ConfigData` via registry, `FUN_1400141CC` |
| `0x222028` | 0x805 | copy 16 bytes from the input into `ctx+0x1088`/`ctx+0x1090` |
| `0x222040` | 0x806 | purge (`FUN_14000755C`) |
| `0x222080`/`84`/`88` | 0x820/0x821/0x822 | vendor commands 0x90/0x91/0x92 via `FUN_1400094B8` |
| `0x22208C` | 0x823 | store an event `HANDLE` from the input, `ObReferenceObjectByHandle` |
| `0x222090`–`0x2220A4` | 0x824–0x829 | line status / modem status / counters |
| `0x222104`–`0x222128` | 0x841–0x84A | EEPROM/vendor commands |
| `0x222168` | 0x85A | 4-byte status write |
| `0x2221BC`–`0x2221F0` | 0x86F–0x87C | EEPROM read/write, latency timer, USB descriptors; vendor commands 0x90–0x95 |

Every case begins with a length check on `*(u32*)(stack+8)` (output) or `*(u32*)(stack+0x10)` (input), e.g. `if (3 < uVar2)`, `if (uVar17 < 0x10) goto STATUS_INVALID_PARAMETER`.

### 2b. `ftser2k`

Standard serial-port dispatch (`IRP_MJ_CREATE/READ/WRITE/DEVICE_CONTROL/…`) with the usual `0x1Bxxxx` serial IOCTLs (`IOCTL_SERIAL_*`); no custom vendor IOCTL range was found. The device DACL is admin-only, so this is out of reach for the unprivileged case regardless.

## 3. Write sinks

* **Device-context only.** `0x222028` copies 16 bytes to `ctx+0x1088`; `0x222010` writes `ctx+0xBC4` (`ConfigData`) and calls the registry helper; `0x22208C` stores a referenced event object pointer at `ctx+0xBE0`. Offsets are compile-time constants.
* **USB transfers.** Vendor commands (`0x90`–`0x95`) are assembled into a URB/control-transfer buffer and sent to the FTDI chip via `FUN_1400094B8`; the payload is the user buffer, the destination is the device.
* **MDL mapping (serial read completion).** `FUN_140002848` (`0x140002848`):
  ```c
  puVar7 = MmMapLockedPagesSpecifyCache(lVar3, 0, 1, 0, 0, DAT_140018264 | 0x10);
  ...
  uVar6 = *(uint *)(lVar2 + 0x24);
  if (uVar4 < uVar6) { *(uint *)(lVar2 + 0x24) = uVar4; uVar6 = uVar4; }
  ```
  The mapped MDL belongs to the pending read IRP and the length is clamped to the remaining request length. This is the normal serial RX path, not a user-controlled write.
* **`IRP_MJ_SET_INFORMATION`-style allocation.** `0x14000C361` allocates `(ctx->0x1000 + n)*8 + 0x10` and copies `n*8` bytes from the IRP's system buffer — the allocation is derived from the same `n`, so no overflow.
* No `MmMapIoSpace`, no `MmCopyMemory`, no `ZwMapViewOfSection`, no user-supplied kernel pointer.

## 4. Validation gaps

* `0x22208C` accepts a user `HANDLE` and calls `ObReferenceObjectByHandle(..., ExEventObjectType, ...)`; the object type is checked by the kernel. A handle to a non-event is rejected.
* `0x222028` copies 16 bytes but only requires `outLen >= 0x10`; exactly 16 bytes are copied.
* The `0x222000` descriptor copy uses the *device's* descriptor length (`uVar12` from `ctx`), and checks `outLen >= uVar12` — no overflow.
* `ftser2k`'s default DACL is the real mitigation; no permissive SDDL was found in the image (raw scan for `D:P(` returned nothing).

## 5. Setup required

**hardware.** Both drivers create their COM/VCP devices only when an FTDI USB device is enumerated (VID/PID match). Without a physical FTDI adapter there is no `\Device\Ftdiport_Com_N` and no `\Device\VCP` instance. `ftser2k` additionally requires the port to be paired with an `ftdibus` port.

## 6. Next dynamic test

1. With an FTDI adapter attached, open `\\.\Ftdiport_Com_1` as a standard user with `GENERIC_READ|GENERIC_WRITE`; confirm success (the SDDL is applied).
2. Fuzz `0x222000`–`0x2221F0` with random in/out lengths under Driver Verifier (special pool + I/O verification); the expected result is `STATUS_INVALID_PARAMETER`/`STATUS_BUFFER_TOO_SMALL`, never a pool corruption.
3. Try `0x22208C` with a non-event handle and with a null handle; expect `STATUS_INVALID_HANDLE`/`STATUS_OBJECT_TYPE_MISMATCH`, and confirm no reference leak.
4. Confirm `ftser2k` `\Device\VCP` denies a standard-user open (default DACL).

**Bottom line:** the FTDI pair is a stock vendor driver with a deliberately world-RW COM port and a large but length-checked vendor IOCTL surface. No kernel memory-write primitive; exploitation would require a physical FTDI device and a logic bug not visible in this build.
