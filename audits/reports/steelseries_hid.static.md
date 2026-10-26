# SteelSeries HID / SMBus family — static audit

Six families under `drivers\SteelSeries\`. Newest build of each was audited; older variants were only opened where the family's device model differed (noted inline). All are x64 KMDF drivers bound through `WdfVersionBind`/`WdfVersionLdr`; every WDF service is an indirect call through a per-driver function table, which is why the original triage could not see the SDDL call.

**Shared result: the `;;;WD` SDDL literal is *not* dead in any of the six — every family passes it to a WDF device-creation API.** The original `SDDL-UNPROVEN` tag was wrong for all six. Five families expose no kernel-memory write primitive; `sssmbus` exposes a genuine **arbitrary SMBus address/register/data write** to unprivileged users (hardware, not memory).

| Family | Build audited | SHA-256 | Verdict |
|---|---|---|---|
| `sshid` | 2.11.5.0 `sshid_ADD52989.sys` | `ADD529899D3062F7BF556BAC9D6620D197FBB77151697BEEE3359EC90EC631A5` | **NO-WRITE** |
| `msihid` | 2.6.3.0 `msihid_3CBA25FA.sys` | `3CBA25FA5E4EACFBC538C40090EF96C851FCCDE3D907454C0E4DB6A37EF7F1C0` | **NO-WRITE** |
| `sssmbus` | 1.2.2.0 `sssmbus_1091D873.sys` | `1091D87375DDA66C0318802ECE412FE5469B07BD405AB95FD7D32093A028268C` | **NO-WRITE** (memory) / **SMBus write primitive** |
| `ssps2` | 2.4.0.0 `ssps2_ABA47E0C.sys` | `ABA47E0C8017290544DE6E7BA14D050418D4572212BC52BEDE4B5A55D4ACF02D` | **NO-WRITE** |
| `ssbthid` | 1.2.2.0 `ssbthid_CFC3146E.sys` | `CFC3146ECA6DC715951571A841D887A17DFA61A415F6727C951D927770FDF8BF` | **NO-WRITE** |
| `ssdevfactory` | 1.3.3.0 `ssdevfactory_63D7C6F1.sys` | `63D7C6F16CB3BB4C71848627D7D0C418E1AC53915418C55ABD05850C9F993B0E` | **NEEDS-DYNAMIC** (one METHOD_NEITHER branch; see §6) |

Both SDDL variants in this family:

```
A) D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)      ; sshid, msihid
B) D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC) ; sssmbus, ssps2, ssbthid, ssdevfactory
```

A grants Everyone `GENERIC_READ|GENERIC_WRITE`; B grants Everyone `GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE`. In both cases the DACL is protected (`P`), so no inherited ACE can tighten it.

---

## 1. `sshid` — SteelSeries Engine HID proxy

**Device surface (control device, created in `DriverEntry` `0x14000D000`).**

| Item | Value |
|---|---|
| Allocation | `WdfControlDeviceInitAllocate` (`+0xC8`) |
| SDDL | `UNICODE_STRING` @ `0x140009578` → buffer `0x140009500`, string A |
| Device name | `\Device\SSengine` (built on stack from literal `0x14000DC10`) |
| Symlink | `\DosDevices\SSengine` (from `0x14000DC40`) |
| IOCTL callback | `FUN_14000D360` (`WDF_IO_QUEUE_CONFIG` +0x28; queue `+0x4C0`) |

Call site (the literal is live):

```
14000D128  4C 8D 05 49 C4 FF FF   LEA R8,[0x140009578]      ; &SDDL_UNICODE_STRING
14000D12F  48 8B D0               MOV RDX,RAX               ; WDFDRIVER
14000D132  4C 8B 89 C8 00 00 00   MOV R9,[RCX+0xC8]         ; WdfControlDeviceInitAllocate
14000D140  49 8B C1               MOV RAX,R9
             ...                   CALL guard_dispatch_icall
```

The `UNICODE_STRING` at `0x140009578` is valid: `Length=0x72`, `MaximumLength=0x74`, `Buffer=0x140009500`; the text is exactly string A. The device is created unconditionally at load, then `WdfDeviceInitAssignName` and `WdfDeviceCreateSymbolicLink` expose it as `\\\\.\\SSengine`.

**IOCTL table** (all `METHOD_BUFFERED`, `FILE_ANY_ACCESS`, device `0xC0DE`; handler `0x14000D360`):

| Codes | Function | Action |
|---|---|---|
| `0xC0DE0000` / `0xC0DE0004` | 0x000 / 0x001 | set global flag `DAT_14000B7C0` = 0 / 1 |
| `0xC0DE0008` | 0x002 | requires input ≥ 0x814 and retrieves exactly 0x814; checks `*(u32*)(in+16) < 0x101`; walks child devices and copies the 0x814 block into a `WdfMemory` (`FUN_140004438`) |
| `0xC0DE000C` | 0x003 | input ≥ 0x10; per-device descriptor block |
| `0xC0DE0010` | 0x004 | input 4 bytes = VID/PID pair; matches a child device, resets it (`FUN_140004600`) |
| `0xC0DE0014` | 0x005 | input 0x38; `FUN_140005AF8` copies 10 dwords into `ctx+0x168` |
| `0xC0DE0018` | 0x006 | input 0x38; child-device config |
| `0xC0DE001C` | 0x007 | input 0x38; child-device config |
| `0xC0DE0020` | 0x008 | input 0x38; child-device config |
| `0xC0DE0024` | 0x009 | child-device config |
| `0xC0DE0028` | 0x00A | input 0x18; VID/PID → `FUN_140005BB8` writes 8 bytes into `ctx+0x3A0` |
| `0xC0DE002C` | 0x00B | input 8: event `HANDLE`; `ObReferenceObjectByHandle(ExEventObjectType)` |
| `0xC0DE0030` | 0x00C | output ≥ 0x50; fills a status struct, `WdfRequestSetInformation(outLen)` |
| `0xC0DE0034` | 0x00D | no buffer; enumerates children |
| `0xC0DE0038` | 0x00E | input 0x814; bulk report descriptor |
| `0xC0DE003C` | 0x00F | input 0x38 |
| `0xC0DE0040` | 0x010 | input 0x38 |
| `0xC0DE0044` | 0x011 | input 0xB0 |

**Write sinks.**

* `FUN_140005AF8` (`0x140005AF8`): fixed 40-byte copy into the per-device context:
  ```c
  *(u8 *)(param_2 + 0x2c) = *(u8 *)(param_1 + 8);
  for (i = 0; i < 10; i++) *puVar3++ = *(u32 *)(param_1 + ...);
  ```
  `param_1` is the probed input buffer, `param_2` the context. No length comes from the user.
* `FUN_140004438` / `FUN_140004FC0`: `WdfMemoryCreate(..., 0x814)` + `WdfMemoryCopyFromBuffer(mem, 0, user, 0x814)`; the 0x814 size is a compile-time constant and the input length was already required to be exactly 0x814.
* HID report path: `WdfIoTargetSendIoctlSynchronously` to the child HID target; buffers are the driver's `WdfMemory`, not user pointers.
* No `MmMapIoSpace`, no `MmCopyMemory`, no user-supplied kernel pointer, no `ProbeForWrite` (not needed: every code is BUFFERED).

**Validation gaps.** `0xC0DE0028` passes minimum 0x18 to `WdfRequestRetrieveInputBuffer` but then reads only 8 bytes; harmless. `0xC0DE0030` writes a fixed 0x50-byte struct into a buffer that was only checked for ≥0x50. `0xC0DE002C` stores a referenced event object in a global (`DAT_14000B4F0`) and replaces it on every call (old reference dropped) — a handle-lifetime quirk, not a write primitive.

**Setup required:** none for the device (created in `DriverEntry`); composition (SteelSeries Engine service installed) to load the driver.

**Next dynamic test:** open `\\\\.\\SSengine` as a standard user with `GENERIC_WRITE`, issue `0xC0DE0030` (out 0x50) and `0xC0DE0000`; then fuzz `0xC0DE0008`/`0x38` with lengths around 0x814 under Driver Verifier + special pool.

---

## 2. `msihid` — SteelSeries MSI HID proxy

**Device surface.** Identical control-device pattern to `sshid`, from `DriverEntry` `0x14000A000`:

```
14000A150  4C 8D 05 21 D1 FF FF   LEA R8,[0x140007278]      ; &SDDL_UNICODE_STRING
14000A157  48 8B D0               MOV RDX,RAX
14000A15A  4C 8B 89 C8 00 00 00   MOV R9,[RCX+0xC8]         ; WdfControlDeviceInitAllocate
```

SDDL `UNICODE_STRING` @ `0x140007278` → `0x140007200`, string A. Device `\Device\steelseries_msihid`, symlink `\DosDevices\steelseries_msihid`. IOCTL callback `FUN_14000A380`.

**IOCTL table.**

* Control device (BUFFERED, ANY, device `0xC0DE`), handler `0x14000A380`:
  `0xC0DE0000`, `0004`, `0008`, `000C`, `0010`, `0014`, `0018`, `001C`, `0020`, `0024`, `0028`, `002C`, `0030`, `0034`, `0038`, `003C` — same semantics as `sshid` minus `0x40`/`0x44`.
* HID-side (device `0x0B`), handler `FUN_140002660`: `0xB0003`, `0xB0007`, `0xB000B`, `0xB000F`, `0xB0027`, `0xB002B`, `0xB0191`, `0xB0192`, `0xB0195`, `0xB01A2`, `0xB0263`.
  Examples: `0xB0003` → `FUN_14000564C` copies 9 bytes from `&DAT_1400071E8` into the request's output memory; `0xB0007` → `FUN_1400056F0` copies 0xA7 bytes from `&DAT_140007140`.

**Write sinks.** Same fixed-offset context model (`FUN_140005AF8` etc.); fixed 9/0xA7-byte descriptor copies into WDF output memory; no user-controlled destination or length. `0xB01A2`/`0xB000B` → `FUN_140005794` calls `WdfRequestGetFileObject`-style helper with `*param_1` (a context field), not a user pointer.

**Validation gaps.** Same as `sshid`; the HID IOCTLs are forwarded to the HID stack, which performs its own buffer validation.

**Setup required:** none for the control device; composition to load.

**Next dynamic test:** same as `sshid`; additionally send the `0xB0xxx` set to `\\\\.\\steelseries_msihid` and confirm they are rejected/forwarded rather than handled locally.

---

## 3. `sssmbus` — SteelSeries SMBus interface *(the interesting one)*

**Device surface (PnP FDO, not a control device).** `DriverEntry` `0x140002AAC` → client entry `0x1400017F8` (`WdfDriverCreate`, `EvtDriverDeviceAdd = FUN_1400018A0`). The FDO is created in `FUN_1400018A0`:

| Item | Value | Evidence |
|---|---|---|
| SDDL | `UNICODE_STRING` @ `0x140004238` → `0x140004250`, string B | `WdfDeviceInitAssignSDDLString` (`+0x220`) |
| Device name | unnamed FDO (PnP name from the PDO) | `WdfDeviceCreate` (`+0x258`) |
| Interface | GUID @ `0x1400040F0` | `WdfDeviceCreateDeviceInterface` (`+0x268`) |
| Symlink | `\SSSMbus` (8 chars, len 0x10) | `WdfDeviceCreateSymbolicLink` (`+0x280`) |
| IOCTL queue | `WdfIoQueueCreate` (`+0x4C0`), `EvtIoDeviceControl = FUN_140001EB0` |

Call sites:

```
1400019F1  4C 8D 05 40 28 00 00   LEA R8,[0x140004238]      ; &SDDL_UNICODE_STRING
1400019F8  48 8B 54 24 48         MOV RDX,[RSP+0x48]        ; WDFDEVICE_INIT
140001A04  48 8B 80 20 02 00 00   MOV RAX,[RAX+0x220]       ; WdfDeviceInitAssignSDDLString
140001A0B  FF 15 5F 26 00 00      CALL guard_dispatch_icall
...
140001BCB  4C 8D 44 24 60         LEA R8,[RSP+0x60]         ; &UNICODE_STRING("\SSSMbus")
140001BDC  48 8B 80 80 02 00 00   MOV RAX,[RAX+0x280]       ; WdfDeviceCreateSymbolicLink
140001BE3  FF 15 87 24 00 00      CALL guard_dispatch_icall
```

`0x140004238` decodes as `Length=0x7E`, `MaximumLength=0x80`, `Buffer=0x140004250` = string B. So the FDO is Everyone-RWX and is reachable through its device interface, and through `\GLOBALROOT\SSSMbus` (note: the link is in the object-manager root, not `\DosDevices`, so `\\\\.\\SSSMbus` does not resolve).

**IOCTL table.** Exactly one code, `0x222800` = `CTL_CODE(0x22, 0xA00, METHOD_BUFFERED, FILE_WRITE_ACCESS)`, handler `FUN_140001EB0`.

```
FUN_140001EB0: WdfRequestRetrieveInputBuffer(Request, min(len,0x189), &buf, &len)
               if (IoControlCode == 0x222800) FUN_140002000(ctx, buf)
```

**Write sink — arbitrary SMBus transaction.** `FUN_140002000` (`0x140002000`) parses the input buffer:

| Offset | Meaning |
|---|---|
| `+0x00` dword | capability bit checked against `ctx+0x5C` (`if ((*in & ctx->mask) == 0) return 0`) |
| `+0x04` byte | opcode 0..7 |
| `+0x05..` | opcode parameters (address, register, data) |

Opcodes:

* `0x00`: `addr = in[5]`, `reg = in[6]`, `val = in[7]` → `FUN_1400012E0(&addr, reg, val)`
* `0x01`: `ctx+0x5C = *(u32*)(in+5) | 1` — **the caller sets its own capability mask**
* `0x02`: `ctx+0x58 = in[5]` — default SMBus address
* `0x03`: block write: count `in[5]`, `regs 0x80/0x81/0x82` = bitmask, `0x88/0x89` = data, `0x8A` = dword
* `0x04`: dword at `in+5` split across `0x80/0x81/0x82`, then `0x88/0x89/0x8A`
* `0x05`: reset sequence `0x9F=0`, `0x80=0xFF`, `0x81=0xFF`, `0x8A=0xFF`
* `0x06`: command `0x9F`, `0xF4`
* `0x07`: loop `in[5]` times over 4-byte entries: `reg=in[9+4i]`, data `in[10+4i]`, `in[11+4i]`, dword `in[0xC+4i]`

The actual transfer:

```c
void FUN_1400012E0(u8 *slot, u8 reg, u8 val) {
  u8 v = val;
  FUN_140001314(*(u64 *)(slot + 8), *slot, 0, reg, 2, &v);
}

int FUN_140001314(iface, addr, 0, reg, 2, &val) {
  KeAcquire...;
  do { r = (*(code **)(iface + 0x10))(iface, addr, 0, reg, 2, &val); } while (r == 6);
  ...
}
```

`iface` is the SMBus-controller interface obtained via `IoRegisterPlugPlayNotification` (GUID `0x140004100`) in `FUN_1400024D0`; it is trusted kernel data. **The address, register and data all come from the IOCTL buffer.** This is a hardware write primitive to any SMBus target address/register, gated only by the (self-granted) capability mask and by the DACL.

**Validation gaps.**

* No range check on the SMBus address/register; `addr` is a raw byte.
* The capability mask is caller-writable via opcode 1; opcode 1 itself only requires one overlapping bit, and the initial mask is `0xFFFFFFFF` in the device-add initializer, so opcode 1 is reachable.
* Input buffer length is `min(len, 0x189)`; opcode 7's loop count `in[5]` is not re-checked against the buffer length (`FUN_140002000` reads `in[5 + i*4 + 0xB]` up to the count) — a **kernel out-of-bounds read** of the system buffer, not a write.

**Setup required:** devnode/composition — the driver must be installed and bound to the SMBus controller (SteelSeries Engine installation). No extra hardware.

**Next dynamic test:** as a standard user, open the interface (`CM_Get_DeviceInterfaceList` for GUID `0x1400040F0`, or `\\?\GLOBALROOT\SSSMbus`) and send `0x222800` with opcode 1 (mask) then opcode 0 targeting a known SMBus device (e.g. the DIMM SPD at 0x50, read-only) to confirm the transaction is issued; then a write to an unused address and watch for a bus error rather than a crash. Also send opcode 7 with `count=0xFF` on a short buffer to confirm the OOB read (Verifier + special pool).

---

## 4. `ssps2` — PS/2 keyboard forwarding

**Device surface.** `FUN_14000238C` (`0x14000238C`) allocates a `WDFDEVICE_INIT` (`+0x690` = `WdfDeviceInitAllocate`), applies the SDDL, names the device `SteelSeries PS/2 Keyboard Forwarding device`, creates it (`+0x258`), registers a device interface (`+0x268`) and publishes it as a child (`+0x428` = `WdfChildListAddOrUpdateChildDescriptionAsPresent`).

SDDL call site (`WdfDeviceInitAssignSDDLString`, `+0x220`):

```c
uVar1 = (**(code **)(DAT_140007348 + 0x220))(DAT_140007350, local_328, &DAT_1400056f0);
```

`0x1400056F0` is the `UNICODE_STRING` (`Length=0x72`, buffer `0x140005700`, string B).

**IOCTL table.** Exactly one: `0xB2548` = `CTL_CODE(0x0B, 0x952, METHOD_BUFFERED, FILE_ANY_ACCESS)`, handler `FUN_14000A070`. It does nothing but forward the request to an internal queue:

```c
if (param_5 == 0xB2548) {
  local_18[0] = 0x100000008;
  iVar1 = (*(...+0xC58))(globals, Request, *(ctx+8), local_18);  // WdfRequestForwardToIoQueue
}
```

**Write sinks.** None. No MMIO, no SMBus, no user pointer; the only copy is the fixed 0xB25xx forward.

**Validation gaps.** The forward target queue is `*(ctx+8)`; if it is not accepting, the request is completed with `0xC000000D`. No memory write.

**Setup required:** hardware/devnode — a PS/2 keyboard must be present for the child device to be created; the driver itself must be installed.

**Next dynamic test:** open the device interface as a standard user and send `0xB2548`; expect a forward or `STATUS_INVALID_DEVICE_REQUEST`, no crash.

---

## 5. `ssbthid` — Bluetooth HID filter

**Device surface.** `FUN_1400014C4` (`0x1400014C4`) creates a child device (`WdfDeviceInitAllocate` `+0x690`, SDDL `+0x220`, `WdfDeviceCreate` `+0x258`, interface `+0x268`, child-list `+0x428`) named `SteelSeries Bluetooth HID Filter`. The SDDL is applied at two sites (lines 574 and 5214 of the decompile), both with `&DAT_1400084e8` (`Length=0x72`, buffer `0x140008500`, string B).

**IOCTL table.** `0x2A0000`, `0x2A0004`, `0x2A0008`, `0x2A000C`, `0x2A0010`, `0x2A0014`, `0x2A0018`, `0x2A001C` — device `0x2A`, functions 0..7, BUFFERED, ANY. Handler `FUN_140001A00` forwards every one of them to the HID queue with `WdfRequestForwardToIoQueue` (`+0xC58`).

**Write sinks.** None; no user-controlled destination or length. `FUN_140001AF8` is a `_vsnwprintf` helper into a `UNICODE_STRING` whose length is validated (`MaximumLength/2`), used for device naming.

**Validation gaps.** None material.

**Setup required:** hardware (a supported Bluetooth HID device) plus installation.

**Next dynamic test:** open the interface and send `0x2A0000..0x2A001C`; expect forwards only.

---

## 6. `ssdevfactory` — virtual keyboard factory

**Device surface.** `FUN_1400023E8` (`0x1400023E8`) creates `SteelSeries Keyboard` child devices; `FUN_140003xxx` creates further children. `WdfDeviceInitAllocate` (`+0x690`), SDDL `+0x220` at **three** sites (lines 1283, 2128, 2473) with `&DAT_140007640` (`Length=0x72`, buffer `0x140007650`, string B), `WdfDeviceCreate` (`+0x258`), interface (`+0x268`), three queues (`+0x4C0`), child publication (`+0x428`). IOCTL callback `FUN_140001BA0`.

**IOCTL table.**

| IOCTL | Function | Method | Access | Handler |
|---|---|---|---|---|
| `0x220003` | 0x800 | **NEITHER** | ANY | `FUN_140001BA0` |
| `0x220013` | 0x804 | **NEITHER** | ANY | `FUN_140001BA0` |
| `0x2A0008` | 0x802 | BUFFERED | ANY | `FUN_140001BA0` |
| `0x2A0010` | 0x804 | BUFFERED | ANY | `FUN_140001BA0` |

**Write sinks.**

* `0x220003`: writes a fixed HID report-descriptor template at offsets `+0x2C .. +0x88` (constants `0x5DFF`, `0x81`, `0xFFFF`, `0x1810040`, `0x1000`, `0x1820020`, …) and a **kernel pointer** (`&DAT_140007338`) at `+0x48` and `&DAT_14000733C` at `+0x78`.
* `0x220013`: writes `dword 3` to the same pointer.
* `0x2A0008`: retrieves 4 bytes of input, requires `in[0] == 7`, then copies `min(0x20, destLen)` bytes into the destination request's buffer and calls `WdfRequestSetInformation`.
* `0x2A0010`: retrieves 0x41 bytes and copies `min(0x41, destLen)`.

**Validation gap (the only one in the family).** The `0x220003` branch writes ~0x88 bytes to a pointer obtained from the WDF request parameters (`WdfRequestGetParameters`, table `+0x850`) without checking an output length. Static provenance of that pointer is ambiguous because Ghidra aliases the KMDF parameters struct (`psStack_60` at `[rbp+0x60]` vs. the `WDF_REQUEST_PARAMETERS` at `[rbp-0x39]`); the branch also stores a kernel `.data` pointer into the buffer, which is either context initialisation (if the buffer is the driver context) or a KASLR leak (if it is user memory). No `ProbeForWrite`/`ProbeForRead` is imported.

**Verdict: NEEDS-DYNAMIC** — specifically to establish whether the `0x220003` destination is the driver's context or the caller's `METHOD_NEITHER` buffer. If the latter, it is a **fixed-content write to an attacker-chosen address** (limited primitive; the attacker cannot choose the bytes), plus a kernel-pointer disclosure.

**Setup required:** composition (the factory is driven by the SteelSeries service); child devices are created on demand.

**Next dynamic test:** under KD, break on the `0x220003` path (`0x140001EFE`–`0x140001F4D`) and log the value of `RAX` (the destination) and the caller's `Type3InputBuffer`/`UserBuffer`; call it as a standard user with a user buffer and again with a kernel address to see whether the write is blocked or crashes the box.

---

## Cross-family summary

* **SDDL is live in all six.** `sshid`/`msihid` use `WdfControlDeviceInitAllocate(+0xC8)` at `DriverEntry` → named control devices `\Device\SSengine` / `\Device\steelseries_msihid` with `\DosDevices\…` symlinks. `sssmbus`/`ssps2`/`ssbthid`/`ssdevfactory` use `WdfDeviceInitAssignSDDLString(+0x220)` on a `WdfDeviceInitAllocate` or PnP init.
* **Control device vs filter:** these are *not* pure HID filters. `sshid`/`msihid` create real control devices; `sssmbus` creates a PnP FDO with a root-object symlink; the other three create child devices with device interfaces. All are openable by Everyone through their name/interface, subject to the usual `CreateFile` access check.
* **Memory writes:** none of the six has an arbitrary kernel write. The only SMBus/hardware primitive that matters is `sssmbus`'s `0x222800`, which allows an unprivileged caller to direct a write to an arbitrary SMBus address/register/data. That is a **hardware** write primitive (motherboard/DIMM/EC), not a kernel memory write.
* **Most useful next step:** `sssmbus` `0x222800` is the highest-value target for a dynamic test on this family — it is a clean, self-contained arbitrary-SMBus-write path behind an Everyone-RWX DACL.
