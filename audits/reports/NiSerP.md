# Audit: NiSerP.sys

> **File:** `C:\Users\<scrubbed>\Desktop\driver_candidates\NiSerP.sys`
> **SHA-256:** `582da85fb3c60dc64f5ddc48568649f5f3c8bd90fe5743d8cecbdbf165572ad7` (matches triage_index.csv)
> **Analysis date:** 2026-10-23
> **Method:** Static-only via REA/Ghidra 12.1.4, plus read-only PE scans of the file on disk. Nothing executed. No network, no external lookups.
> **Threat model:** unprivileged local user holding a handle to the COM device the driver publishes.
> **Verdict: LOW (DACL-conditional).** Verified primitive: any caller holding a device handle can repeatedly delete and recreate a COM port's device link and its `SERIALCOMM` value, performed in kernel context with fixed data. This is a local denial of service on the port. The one pointer dereference that could have escalated it (section 7.2) is resolved statically: the pointer is set to a valid in-object address by the constructor, and the only write through it is a caller-supplied DWORD into the same object. The DACL is the verdict condition (section 7.1, section 9). The context link and alias writers are accepted scope limits (section 7.2, section 11).

## 1 Internals

| Property | Observed value | Source |
|---|---|---|
| Format | PE32+, x86-64, 397,704 bytes; `.text` 0x140001000-0x140047E00, `PAGE`, `INIT`, `.rsrc`, `.reloc` | `list_segments` |
| Version resource | `NISERIALDRIVER 19.0.0f0`, built `2019/03/20 05:42:14` | strings `0x14005E384`, `0x14005E3CC` |
| Vendor / PDB | National Instruments; RSDS `niserialDriver.pdb` referenced, not loaded | overview limitations |
| Framework | C++ class graph (APAL/"niapal"). Objects wired through vtables and multiple inheritance (MI) | constructors `FUN_14003D5B0`, `FUN_140031130` |
| Device type | `0x1B` = `FILE_DEVICE_SERIAL_PORT` (both creation sites) | `FUN_14002A450`, `FUN_140041730` |
| Imports | 99 (NTOSKRNL 96, USBD 2, HAL 1) | `list_names` |
| Relevant imports present | `IoCreateDevice`, `IoCreateSymbolicLink`, `IoDeleteSymbolicLink`, `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `RtlWriteRegistryValue`, `RtlDeleteRegistryValue`, `ZwOpenKey`, `ZwCreateFile`, `ObReferenceObjectByHandle`, `IoConnectInterrupt`, `PsCreateSystemThread` | `list_names` |
| Relevant imports absent | `IoCreateDeviceSecure`, any `Se*`, `ZwSetSecurityObject`, SDDL strings | import list, `search_strings` |

## 2 Entry, driver object and dispatch (verified)

```
entry (DriverEntry) -> FUN_140030E80  driver object ctor
   |- FUN_1400415A0   MajorFunction table, DriverUnload (+0x68 = FUN_140042760), AddDevice (DriverExtension+0x08 = FUN_140041FF0)
   \- DAT_140054260 = driver manager (vtable PTR_LAB_14004CD80)
```

| IRP | Offset | Handler | Status |
|---|---|---|---|
| CREATE | +0x70 | `FUN_140042200` | verified: forwards to device-extension slot `+0xB8` |
| CLOSE | +0x80 | `FUN_140042300` | not decompiled |
| READ / WRITE | +0x88 / +0x90 | `FUN_1400424C0` | not decompiled |
| QUERY_INFORMATION | +0x98 | `FUN_140042640` | not decompiled |
| SET_INFORMATION | +0xA0 | `FUN_1400426A0` | not decompiled |
| FLUSH_BUFFERS | +0xB8 | `FUN_1400425E0` | not decompiled |
| **DEVICE_CONTROL** | **+0xE0** | **`FUN_140042360`** | **verified: IOCTL router (section 3)** |
| INTERNAL_DEVICE_CONTROL | +0xE8 | `FUN_140042360` | same router |
| CLEANUP | +0x100 | `FUN_140042460` | not decompiled |
| POWER | +0x120 | `FUN_140042700` | not decompiled |
| SYSTEM_CONTROL | +0x128 | `FUN_140042360` | same router |
| PNP | +0x148 | `FUN_140042260` | verified: forwards to device-extension slot `+0xA0` |

Not decompiled: CLOSE, READ/WRITE, QUERY, SET, FLUSH, CLEANUP, POWER, PnP's target (`0x14003E6F4`), and `DriverUnload`. These are not IOCTL paths. Their effect on the IOCTL verdict is covered by section 5.

## 3 IOCTL path (verified)

```
DEVICE_CONTROL -> FUN_140042360 router
   method = code & 3:  NEITHER(3) -> complete 0xC00000BB (not forwarded)
                       BUFFERED(0) -> device-extension vtable +0xB0 (SystemBuffer, lengths)
                       DIRECT(1,2) -> only with MdlAddress; passes MDL.StartVa + ByteOffset
 -> +0xB0 thunk (this -= vbase+0x68) -> FUN_140035E00 wrapper:
      IoAcquireRemoveLockEx; MajorFunction!=0x0E -> forward down; state!=1 -> 0xC00000A3
      -> device-extension +0x40 thunk -> FUN_140035060 forwarder
      -> FUN_140035060 forwarder: `rcx = this-0x100` (the vbase subobject -> primary object P), then `[vptr(P)+0x58]` = `0x1400350C0`  ->  FUN_1400350C0 case switch, `this = P` (verified; section 7.2)
 switch gate: *(param_1+0x89)==0, *(param_1+0x18)!=0, *(*(param_1+0x18)+0x95)!=0 (else 0xCBE5 / 1 / 0xCBE4)
```

No layer checks `FILE_READ_DATA` / `FILE_WRITE_DATA`, and no layer checks caller identity. The only checks are remove lock, port state, the gate above, and per-handler buffer lengths.

## 4 IOCTL case table (complete: 50 codes)

All codes are `METHOD_BUFFERED`. Access is `FILE_ANY_ACCESS` except `0x1B4000` (`FILE_READ_ACCESS`). Behavior column: **verified** = body decompiled; "delegate" = forwards to an unresolved helper after the same state check.

### 4.1 Standard serial group `0x1B00xx` (31 codes)

| Code | Handler | Input -> output / effect | Risk |
|---|---|---|---|
| 0x1B0004 | `FUN_1400375D0` | input >=4 -> one DWORD -> `FUN_1400119E0` (hardware); on success stores port+0x8C | safe |
| 0x1B0008 | `FUN_140037CC0` | input >=8 -> reads one DWORD -> state check -> `FUN_1400173B0` | safe |
| 0x1B000C | `FUN_140037780` | input >=3; stop bits 0-2, parity 0-4, data bits 5-8 validated -> `FUN_140011950`; stores port+0x90..0x98 | safe |
| 0x1B0010 | `FUN_140039780` | state check (busy -> 0x10029) -> delegate `FUN_140015FC0`; no caller data | safe (delegate) |
| 0x1B0014 | `FUN_1400397E0` | same pattern -> delegate `FUN_1400160F0` | safe (delegate) |
| 0x1B0018 | `FUN_140037540` | input >=1 -> reads one byte -> state check -> `FUN_14001AF60`; info 1 | safe |
| 0x1B001C | `FUN_140037BC0` | input >=20; five DWORDs -> port+0xC4..0xD4 (SET_TIMEOUTS-shaped); rejects all -1 | safe |
| 0x1B0020 | `FUN_140037C50` | output >=20; returns the five DWORDs; info 20 | safe |
| 0x1B0024 | `FUN_140039480` | sets port+0xA5 = 1; optional `FUN_140013D10` (DTR set) | safe |
| 0x1B0028 | `FUN_140039510` | clears port+0xA5; `FUN_140013DF0` (DTR clear) | safe |
| 0x1B002C | `LAB_14000BA20` | `xor eax,eax; ret` (no-op success) | safe |
| 0x1B0030 | `FUN_1400395A0` | sets port+0xA7 = 1; `FUN_140014160` (RTS set) | safe |
| 0x1B0034 | `FUN_140039630` | clears port+0xA7; `FUN_140014240` (RTS clear) | safe |
| 0x1B0038 | `FUN_1400396C0` | state check -> delegate `FUN_140015CD0` | safe (delegate) |
| 0x1B003C | `FUN_140039720` | state check -> delegate `FUN_140015B40` | safe (delegate) |
| 0x1B0040 | `FUN_140038ED0` | output >=4; reads DWORD through `*(port+0xE0)` (self-pointer to `port+0xD8`, section 7.2) | safe (section 7.2) |
| 0x1B0044 | `FUN_140038C60` | input >=4; mask validated and translated -> `FUN_1400125C0`; writes the caller's DWORD through `*(port+0xE0)` into `port+0xD8` (assembly-verified, section 7.2) | safe (section 7.2) |
| 0x1B0048 | `FUN_140038F10` | output >=4; fixed-size 0x188 wait object (`FUN_14003E780`, size not caller-controlled) -> `FUN_14003C450` -> `FUN_1400126A0`; pends | safe (pends; no caller length) |
| 0x1B004C | `FUN_140039130` | input >=4; mask nibble 0-F validated; flags 2/8/1 -> notifications `FUN_1400178E0`/`FUN_140017990`/`FUN_14001ACD0`; bad mask -> 0xCB25 | safe (verified during review) |
| 0x1B0050 | `FUN_140037740` | output >=4; one DWORD from port+0x8C | safe |
| 0x1B0054 | `FUN_1400379C0` | output >=3; three bytes from port state (enum-mapped) | safe |
| 0x1B0058 | `FUN_140039400` | output >=6; six bytes from port state | safe |
| 0x1B005C | `FUN_140039240` | input >=6; bytes and fixed-width fields -> port state; `FUN_140011AB0` with two bytes | safe |
| 0x1B0060 | `FUN_140038AD0` | output >=16; four DWORDs of port state, bit-packed flags; info 16 | safe |
| 0x1B0064 | `FUN_140037E60` | input >=16; reserved bits rejected (0xCB25); flow-control flags via checked helpers; DWORDs -> port+0xB0/B4 on success | safe |
| 0x1B0068 | `FUN_140039840` | output >=4; state query via vtable +0x160 | safe |
| 0x1B006C | `FUN_140039970` | output >=20; state queries (`FUN_140011E30`, `FUN_140016220`, `FUN_140011C70`, `FUN_14001A810`); info 20 | safe |
| 0x1B0074 | `FUN_140039AD0` | output >=64; fills a fixed 64-byte properties block from queries | safe |
| 0x1B0078 | `FUN_140039910` | output >=4; one DWORD of port flags | safe |
| 0x1B0080 | `FUN_140039DF0` | output >=4; writes 0 | safe |
| 0x1B0094 | `FUN_14003A190` | input >=4; enum 0x80-0x83 only -> vtable +0x1D0 query | safe |
| default | `FUN_14003AF30` | returns 0xCB25 (invalid), no request change | safe |

### 4.2 NI-specific group `0x1B3Exx`-`0x1B4000` (19 codes)

| Code | Handler | Input -> output / effect | Risk |
|---|---|---|---|
| 0x1B3ED8 | inline | no-op | safe |
| 0x1B3EDC | inline | if `req+0x30 != 0`, writes byte 1 at `*(req+0x28)`; no call | safe |
| 0x1B3EF8 | `FUN_14003A410` | output >=4; writes 0/1 from vtable +0x1F0 query | safe |
| 0x1B3EFC | `FUN_14003A360` | input >=4; 0/1 -> vtable +0x1E8 set; other values error | safe |
| 0x1B3F48 | `FUN_14003AE30` | output >=4; writes 0/1 from vtable +0x1C0 | safe |
| **0x1B3F4C** | **`FUN_14003AED0`** | **see section 5.2: deletes the port's `SERIALCOMM\<name>` value, deletes and recreates `\DosDevices` link, rewrites `SERIALCOMM`. Trigger only; names from configuration** | **verified LOW** |
| 0x1B3F70 | `FUN_14003A8D0` | state==2; 1-byte output from `FUN_140011C10` | safe |
| 0x1B3F74 | `FUN_14003AA80` | state==2; vtable +0x1D8 query; if 2 -> vendor action +0xC0 with request record | safe (vendor action, no caller length) |
| 0x1B3F78 | `FUN_14003A980` | state==2; vendor action +0xB8 | safe (vendor action) |
| 0x1B3F98 | `FUN_14003AB80` | state==2; 1-byte output from `FUN_140011C10` | safe |
| 0x1B3F9C | `FUN_14003AD30` | state==2; vendor action +0xD0 | safe (vendor action) |
| 0x1B3FA0 | `FUN_14003AC30` | state==2; vendor action +0xC8 | safe (vendor action) |
| 0x1B3FC0 | `FUN_14003A690` | state==2; 4-byte output (enum 5-7 -> 0-2) | safe |
| 0x1B3FC4 | `FUN_14003A4E0` | state==2; input enum 0-2 -> vtable +0x1D0 | safe |
| 0x1B3FC8 | `FUN_14003A770` | state==2; output >=8; 8 bytes from vtable +0x1D8/+0x1E0 | safe |
| 0x1B3FE8 | `FUN_14003A0A0` | state==1; output >=4; enum 1-4 -> 0-3 | safe |
| 0x1B3FEC | `FUN_140039EE0` | state==1; input enum 0-3 -> vtable +0x1D0 | safe |
| 0x1B3FF4, 0x1B4000 | `FUN_140039E30` | selector 0 or 1 -> vendor actions +0xF0 / +0xE8; `0x1B4000` requires FILE_READ_ACCESS | safe (vendor action, enum selector) |

**Counts:** 50 control codes, all listed above, plus the default. Four (`0x1B0010`, `0x1B0014`, `0x1B0038`, `0x1B003C`) delegate after their state check to helpers that receive only device-held objects (`ctx+0x38`/`ctx+0x70`), not caller data. Those helpers were not traced past the call. Every handler that reads the request checks its buffer length first. No handler copies a caller-sized buffer into pool or kernel memory.

## 5 Device creation, symbolic links, registry (verified)

### 5.1 Creation sites

- **Site A** `FUN_14002A450`: `IoCreateDevice(drv, 8, NULL, 0x1B, 0x180, TRUE)` (unnamed, exclusive; `FILE_DEVICE_SECURE_OPEN | FILE_AUTOGENERATED_DEVICE_NAME`).
- **Site B** `FUN_140041730`: `IoCreateDevice(drv, 8, name, 0x1B, 0x100, FALSE)` (named from configuration; `Exclusive` masked to FALSE). Called from the enumerator `FUN_1400312D0`.

Both set `FILE_DEVICE_SECURE_OPEN`. The binary sets no DACL on either.

### 5.2 Symbolic link and `SERIALCOMM` (verified end to end)

`0x1B3F4C` -> `FUN_14003AED0`:
1. `FUN_140037440`: builds the port name from the stored configuration (`FUN_14000F730`, `FUN_14000F7F0`, `RtlInitAnsiString`/`RtlAnsiStringToUnicodeString`) and calls `RtlDeleteRegistryValue(4, L"SERIALCOMM", name)`.
2. `IoDeleteSymbolicLink(ctx+0xE8)`, `RtlFreeUnicodeString`.
3. `FUN_1400369B0`: `IoCreateSymbolicLink(ctx+0xE8, devname)`, with the device name from `FUN_140030050`, which converts the stored configuration name (ANSI -> Unicode).
4. `FUN_140036E80`: reads `PortName` through `FUN_14002F1E0`, then `RtlWriteRegistryValue(4, L"SERIALCOMM", ...)`.

The request buffer is never read by this handler. The caller only triggers the republish. The effect is a denial of service on the port (its link disappears between steps 2 and 3) and a registry rewrite performed in kernel context with fixed data.

### 5.3 Enumerator

Manager vtable `PTR_LAB_14004CD80`: slot `+0x20` = `FUN_140031130` (port factory), slot `+0x30` = `FUN_1400312D0` (enumerator). The enumerator reads `DeviceObjectNamePrefix` from the installation key, appends the counter `DAT_1400542C0`, and creates the device through `FUN_140041730`.

## 6 OPEN, PnP and the mapping chain

- **OPEN** (`FUN_14003F960`, device-extension slot `+0xB8`, verified): remove lock; requires state 1; `FUN_140025E60` matches the request's FileName against the registered port list (`RtlEqualUnicodeString`), default = first entry; then slot `+0x08`. A caller chooses among ports the enumerator registered, and cannot create one.
- **PnP** (device-extension slot `+0xA0` -> `0x14003E6F4`): reached only from the kernel PnP manager (minor code from `SL+1`). No user request reaches it.
- **Mapping chain (verified callers):** `FUN_1400303E0` (`MmMapIoSpace`) <- `FUN_140004100`, `FUN_140042990`, `FUN_140042B00`. `FUN_140042B00` <- `FUN_140004100` (<- `FUN_140004500` <- `FUN_140004990`) and `FUN_140028A40`; `FUN_140042990` <- `FUN_14002AAA0`; `FUN_14002AAA0` and `FUN_140028A40` <- `FUN_1400294B0`.

**Reachability from the IOCTL switch: not reached.** `FUN_1400294B0` and `FUN_140004990` have no direct callers. Their addresses sit in vtable slots at `.rdata` `0x14004BE88`-`0x14004C160` (92 slots, the entry `FUN_1400294B0` at `+0x1F0`), `0x14004C2B8`-`0x14004C538`, `0x14004C5A8`-`0x14004C818`, and `0x1400490A8`-`0x1400490F8` (`FUN_140004990` at `+0x38`). The constructor call sites for those tables are `FUN_140028D76`, `FUN_1400290DE`, `FUN_14002C582`, `FUN_14002DEDC`, `FUN_14003D9A8`, `FUN_14002CA75`, `FUN_14002CB5C`, `FUN_14002D379`. None of the 50 IOCTL handlers calls into those objects with a slot that holds these entries. The state-object calls used by the handlers take no arguments (`FUN_1400294B0` takes five), so the slot `+0x1F0` coincidence does not match. The PnP START path reaches resource setup only through the kernel-side device extension, not from IOCTL.

## 7 Access control, open items

### 7.1 Access control

- No driver-set security descriptor (no `IoCreateDeviceSecure`, `ZwSetSecurityObject`, SDDL, or `Se*` import).
- Both creation sites set `FILE_DEVICE_SECURE_OPEN`. The effective DACL is whatever the OS applies to the device. **The verdict below assumes the worst case, that standard users can open the device.** A tighter DACL lowers the rating and does not change the primitive.
- No IOCTL checks caller identity, token, or privilege.

### 7.2 `+0xE0` pointer: resolved statically (not a NULL dereference)

The port object `P` is the object constructed by `FUN_140031AF0` (called from `FUN_140031880` and `FUN_14003D5B0`).

Assembly, verified:

- **Construction** `FUN_140031AF0` 0x140031D0A-0x140031D29: `LEA RAX,[RDI+0xD8]; MOV [RAX],R15D` (sets `P+0xD8 = 0`); `MOV [RAX+8],RAX` (sets `P+0xE0 = &P+0xD8`). This runs unconditionally, after the `param_5` branch.
- **0x1B0044 write** `FUN_140038C60` 0x140038E3D-0x140038E5C: `LEA RCX,[RDI+0xD8]`; `MOV RCX,[RCX+8]` (loads `P+0xE0`); `MOV [RCX],EAX` writes the caller's mask DWORD into `P+0xD8`. The handler checks `P+0xD8 != &local` before the write, and that check is always true, since `P+0xD8` is a heap address.
- **0x1B0040 read** `FUN_140038ED0` reads through the same pointer (decompiled in the earlier session).

So the pointer is never NULL after construction, and its target is always `P+0xD8` unless something overwrites `P+0xE0`. The request controls only the 4-byte value written, not the address.

**Correction.** An earlier draft of this section said no non-zero store to `+0xE0` exists. That was wrong. The disp32 scan could not see the constructor's store, because it is `[RAX+8]`, a disp8 access through a shifted base. The corrected statement is the one above.

**The handler's `this` is `P` (verified).** The switch `FUN_1400350C0` calls each case handler with the first argument `param_1 + 8 + *(int*)(*(param_1+8))` (decompiled). `*(param_1+8)` is the vptr `DAT_14004CEE8`, whose first dword is `-8`, so the argument is `P`. The switch gate reads `P+0x89` (zeroed by the constructor at 0x140031C9A), and `P+0x18` (the context, also constructor-initialised). The chain that reaches the switch with `this = P`: the router's `+0xB0` thunk calls the wrapper `FUN_140035E00` with `W`. `W` is the vbase subobject `P+0x100`: `[W-0xF8]` is the vptr `DAT_14004CEE8` with vbase displacement `0xF8`, and the wrapper's remove lock sits at `W+0x1E8+0xF8 = P+0x3E0`, the address the constructor initialises (0x140031B3A-0x140031BEC). The forwarder `FUN_140035060` subtracts `0x100`, giving `P`, and calls slot `+0x58` of the primary vtable `0x14004D008`, which is `FUN_1400350C0`.

**Other writers to `P+0xE0`, checked:**

- A disp32 scan of the whole `.text` section (REX prefixes `40`-`4F`, MOV, MOV-immediate, LEA, and 16-byte SSE stores covering `+0xE0`) found 21 stores and 10 LEAs with displacement `0xE0`, in 11 and 5 procedures. These are constructors that zero or initialise their own `+0xE0`, or belong to other objects.
- The wait path, `FUN_140038F10` (0x1B0048) and its callees `FUN_14003C450`, `FUN_1400126A0`, `FUN_14003AF50`, never write `P+0xE0`. They use `+0xD8` of a different object (the queue's pending-waiter slot).
- **Not covered:** disp8 writes through other aliases of `P`. An exhaustive check would need a full cross-reference pass over every procedure. If such a writer stored a request-controlled pointer into `P+0xE0`, the request could write a DWORD to an arbitrary kernel address, and the rating would become HIGH. No such writer was observed.

## 8 Dangerous capability chain

1. Caller opens the COM device (or `\DosDevices\COMn`). OPEN selects a registered port (section 6).
2. Caller sends `IOCTL 0x1B3F4C`. Router (section 3) -> wrapper -> forwarder -> switch -> `FUN_14003AED0`.
3. `FUN_140037440` deletes `SERIALCOMM\<name>`; the link is deleted and recreated; `SERIALCOMM` is rewritten (section 5.2). Data is from configuration.
4. Effect: the COM device disappears from the namespace and from `SERIALCOMM` for the duration, repeatably, with no privilege.

Not reached: physical-memory mapping (section 6), pool allocation sized by the caller (every allocation is fixed-size), caller-chosen write targets (the only pointer write is section 7.2).

## 9 VERDICT

**LOW (DACL-conditional).**

- **Verified primitive:** any caller holding a device handle can repeatedly delete and recreate a COM port's device link (`0x1B3F4C`, section 5.2) and rewrite its `SERIALCOMM` value. Both use fixed or configured data. Effect: local denial of service on the port.
- **Wait-mask IOCTLs (`0x1B0040`/`0x1B0044`):** the caller writes a DWORD into the port's own object through `P+0xE0`, which is a constructor-set self-pointer (section 7.2). No crash path, and no caller control over the address.
- **What would raise this to HIGH:** a writer that stores a request-controlled pointer into `P+0xE0` (section 7.2, "Not covered"). None was observed.
- **DACL:** determines who can trigger the finding. The worst case (standard users can open the device) is assumed, so LOW is the ceiling for this primitive. A restrictive DACL would lower the rating. Nothing in the DACL can raise it.

## 10 Recommendations

1. Initialise and validate `P+0xE0` defensively: keep the constructor's self-pointer, and add a NULL and range check in `0x1B0040` and `0x1B0044` before the dereference. This is hygiene, not a fix for a live crash.
2. Restrict the device DACL to SYSTEM and Administrators, or set it explicitly with `IoCreateDeviceSecure`.
3. Require privilege, or a server-side check, before `0x1B3F4C` deletes and recreates the link and rewrites `SERIALCOMM`.
4. To close the section 7.2 residual, run a full cross-reference pass on `P+0xE0` that covers disp8 aliases. That is the only item this verdict leaves to tooling rather than to reading.

## 11 Limitations

- **Accepted scope (2026-10-23).** The reviewer accepted LOW as DACL-conditional. Three items are stated scope limits, not verified here: (1) the context link (whether `P+0x18` holds the factory-built object) and the vendor targets of its five candidate classes (section 7.2); (2) alias writers to `P+0xE0` not exhaustively enumerated (section 7.2); (3) the effective DACL, which needs a VM query (section 7.1, section 9).
- Static analysis of one binary. Procedures are Ghidra-recovered (`FUN_xxxxxxxx`).
- **Dispatcher name and `this`: resolved (section 3, section 7.2).** `FUN_1400350C0` is the case switch. An intermediate reading of the wrong vtable (`DAT_14004CEE8`, which points through a thunk at `0x14003B0D0` to `FUN_140035860`) is retracted.
- **Vendor virtual targets: open, scope narrowed.** The handlers call the context object `*(P+0x18)` through its vtable (slots `+0x160`, `+0x1C0`-`+0x1F0`, `+0xB8`-`+0xF0`). The context is built by the factory `FUN_14000F960`, which selects one of five classes from a registry configuration type:
  - type 1: `FUN_140008EE0` (0x158 bytes), vtable `0x1400496F8`
  - type 2: `FUN_14000CC30` (0x160 bytes), vtable `0x1400499D0`
  - type 3: `FUN_14000D6D0` (0x160 bytes), vtable `0x140049D48`
  - type 4: `FUN_14001CBE0` (0x5A8 bytes), vtable `0x14004ADA8`, 63 slots ending at `+0x1F0`; the only candidate whose vtable spans every handler slot
  - type 9: `FUN_140022060` (0x178 bytes), vtable `0x14004B0C8`

  Checked: `FUN_14000FD70` does not store the factory result at `P+0x18`. It passes `param_1+0x18` into the factory as a parent slot, then links the returned object into a list node stored at `param_1+0x28`/`+0x30` under a lock at `param_1+0x38`. Whether `FUN_14000FD70`'s `param_1` is the port `P` is not verified, so the link from `P+0x18` to the factory object is still open. Also not verified: the per-class resolution of each handler slot. Byte scans cannot find the context: 447 64-bit stores to `[reg+0x18]` occur in 397 procedures. Handlers were verified for what they pass to these targets (validated enums, checked-length request records, or fixed values), not for what each target does.
- **Off-by-encoding writes:** the `+0xE0` scan covers disp32 forms and the constructor's disp8 form, but not every disp8 alias (section 7.2).
- The DACL and any runtime value cannot be read statically. A VM run would confirm section 7.2 but is not required for this verdict.
- Two earlier address errors in drafts were corrected in place. Evidence IDs are REA session artifacts recorded 2026-10-23.
