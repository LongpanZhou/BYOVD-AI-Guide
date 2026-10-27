# Audit: vpnva64-6.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\vpnva64-6.sys` |
| SHA-256 | `506ab485fe0da85c6df6d0b7abbad412aca6a8eb3f575dfc2c81662107054792` |
| Analysis date | 2026-10-23 |
| Method | **Static-only audit via REA/Ghidra** - no execution, no network, no external sources |

**Limitations.** All findings derive from static disassembly/decompilation of the shipped binary. Function names are REA-generated (`FUN_xxxxxxxx`); NDIS/NTOSKRNL calls identified via import thunks. Nothing was run; no signature check was performed beyond recording the hash.

## 1. Internals

- 64-bit PE, image base `0x140000000`. Sections: `.text` `0x140001000-0x140008600`, `.rdata` `0x140009000-0x140009e00`, `.data` `0x14000a000-0x14000a200`, `PAGE` `0x14000c000-0x14000d200`, `INIT` `0x14000e000-0x14000ea00`, `.rsrc`, `.reloc`. 137 procedures, ~90 strings.
- This is an **NDIS 6.20 miniport driver**: `OID_GEN_DRIVER_VERSION` (`0x10110`) returns `0x614`; characteristics header dword at +4 = `0x1021406` (Major 6, Minor 20).
- Key NDIS.SYS imports: `NdisMRegisterMiniportDriver` (thunk `0x140009080`), `NdisRegisterDeviceEx`, `NdisMSetMiniportAttributes`, `NdisAllocationNetBufferAndNetBufferList`/`NdisAllocateMdl`, `NdisMIndicateReceiveNetBufferLists`, `NdisMIndicateStatusEx`, `NdisAllocate/CancelTimerObject`, `NdisMResetComplete`, `NdisMPauseComplete`, `NdisOpenConfigurationEx`, `NdisRead/WriteConfiguration`, `NdisDeregisterDeviceEx`. NTOSKRNL.EXE imports: `MmMapLockedPagesSpecifyCache` (thunk `0x140009100`), `MmGetSystemRoutineAddress`, `IofCompleteRequest`, `KeBugCheckEx`, `KeAcquireSpinLockRaiseToDpc`, `ExInterlockedInsertTailList`/`RemoveHeadList`, `IoWMIRegistrationControl`.
- WPP tracing helpers (`FUN_140001000`, `FUN_140001028`, `FUN_140001140`, ...) with trace state at `DAT_14000a0f8`.
- Version resources (.rsrc): "Cisco Systems, Inc.", "AnyConnect Virtual Miniport Adapter for Windows", "Cisco Secure Client", FileVersion "4, 10, 05040", "(c) Copyright 2004-2021 Cisco Systems, Inc."; build stamp "Dec 14 2021" / "14:47:55" (`0x14000e260/0x14000e270`); PDB ref `vpnva64-6.pdb` GUID `2c656697-b9fc-4954-89d3-c8ad6bcfc876`.
- Adapter context: single global `DAT_14000a120`, allocated in init (`NdisAllocateMemoryWithTagPriority`, size `FUN_140007f9c()+0x278`, tag `0x61765343`). Layout highlights: spin locks ctx `+0x10/+0x58/+0x70/+0xB8/+0x150`; parked-IRP slots ctx `+0x48/+0x50/+0x68`; timer objects ctx `+0xD0/+0x170/+0x178/+0x180/+0x188`; free-frame list ctx `+0x120`; MAC bytes ctx `+0x84..0x8F`; packet filter ctx `+0x1A8`; lookahead ctx `+0x1AC`; multicast list ctx `+0x1B4` (cap `0xC0`).

## 2. Device & entry chain

- PE entry `0x14000e000` = `DriverEntry` (no KMDF wrapper). Builds the miniport characteristics struct on the stack and calls `NdisMRegisterMiniportDriver` at `0x14000e172`; driver handle stored to `DAT_14000a1c0` / `DAT_14000a130`.
- Handler table (struct base = stack `-0xB8`):

| Slot | Address | Role |
|---|---|---|
| +0x10 | `0x1400046e0` | CheckForHang (returns 0) |
| +0x18 | `0x14000cc80` | MiniportInitializeEx |
| +0x20 | `0x14000c3c0` | HaltEx (frees 5 timer objects, `KeFlushQueuedDpcs`, cleanup `FUN_140003320`, `FUN_140005190`, `NdisFreeMemory`) |
| +0x28 | `0x14000c560` | Unload (`NdisMDeregisterMiniportDriver` + `FUN_14000c620`) |
| +0x30 | `0x14000c090` | PauseEx (ctx+0x80 \|= 0x10, cancels timers, returns `0x103`) |
| +0x38 | `0x14000c000` | Restart (ctx+0x80 &= ~0x30) |
| +0x40 | `0x140002fe0` | OidRequest |
| +0x48 | `0x140007720` | SendNetBufferLists |
| +0x50 | `0x1400059b0` | ReturnNetBufferLists (frees MDLs, returns frames to free list, `NdisSetEvent(ctx+0xD8)`) |
| +0x58 | `0x140007360` | no-op |
| +0x60 | `0x1400031d0` | no-op |
| +0x68 | `0x140003270` | CancelSend |
| +0x70 | `0x14000c250` | DevicePnPEventNotify (events 2/5) |
| +0x78 | `0x1400017a0` | ShutdownEx (flag \|= 0x200) |
| +0x80 | `0x140003160` | no-op |

- `MiniportInitializeEx` (`0x14000cc80`) allocates the context, applies attributes (two `NdisMSetMiniportAttributes` calls), assigns MAC bytes ctx+0x84..0x8F, publishes `DAT_14000a120`, then calls `FUN_140004854(ctx, DriverHandle)`.
- `FUN_140004854` registers a **control device exactly once** (refcount `DAT_14000a148` under spin lock `DAT_14000a14c`): `\Device\VPNVA` (`0x1400084e0`) / `\DosDevices\VPNVA` (`0x140008500`) via `NdisRegisterDeviceEx` (~`0x140004a3d`). `NDIS_DEVICE_OBJECT_ATTRIBUTES` observed: header dword `0x380185` (Type 0x85, Rev 1, Size 0x38), `MajorFunctionCount = 16`, 16-entry dispatch table with indices **0 (MJ_CREATE), 2 (MJ_CLOSE), 0xE (MJ_DEVICE_CONTROL), 0x12 (MJ_CLEANUP) all = `FUN_140003fc0`**. On success, device-object `Flags |= 0x10` (**DO_DIRECT_IO**) at `0x140004a50`; device object -> `DAT_14000a138`, ctx -> `DAT_14000a140`.
- **Bug:** the stack dword just past the `MajorFunctionCount` field in the attributes copy (at `[RSP+0x44]`) is **never initialized** - residual stack data is passed to `NdisRegisterDeviceEx` (the slot where a security-descriptor / other Attributes field would live).
- Every IRP hits the single handler `FUN_140003fc0` (Irp SPA at `Irp+0xB8`; `IoControlCode` at SL+0x18, out/in lengths at SL+0x08/0x10, `SystemBuffer` at `Irp+0x18`, MDL at `Irp+0x08`, `IoStatus` at `Irp+0x30/0x38`), which completes in-line, forwards to `FUN_140003a70`, or pends the IRP.

## 3. IOCTL / OID table

### 3.1 Control-device IOCTLs (DeviceType `0x22`, all access field values = 0 -> `FILE_ANY_ACCESS`)

Layer 1 - `FUN_140003fc0`:

| Code | Buffering | Validation / kernel action |
|---|---|---|
| `0x222004` | METHOD_BUFFERED | In-len >= 8 else `0xC0000023`; two ints each must be in `[8, 0x100]` else `0xC000000D`. Stored to ctx+0x30 / ctx+0x34 (frame count / size). |
| `0x22200A` | METHOD_IN_DIRECT | **Maps caller MDL into system VA** via `MmMapLockedPagesSpecifyCache`; only check is `MdlFlags & 5`; requires ctx+0x30/0x34 != 0. `FUN_140007fa8` writes RX descriptor at ctx+0x38 (`[0]=count`, `+0x10`=mapped VA, stride `count*0x800`, `[0xA]=2`, `[0xB]=ctx+0x34`), then `FUN_140004b04`; **IRP parked** at ctx+0x48 with cancel routine `FUN_1400038c0` (`XCHG` at `0x140003be5`). |
| `0x22200C` | METHOD_BUFFERED | Disconnect cleanup `FUN_140003320`. |
| `0x22201C` | METHOD_BUFFERED | Out >= 0x18 else fail; copies 24 bytes `{ctx+0x1A8, ctx+0x190, ctx+0xF0}`, `Information = 0x18`. |
| `0x222030` | METHOD_BUFFERED | In-len must be 8 or 4 (else `0xC0000024`); **stores arbitrary 8-byte value at ctx+0x28**; calls `FUN_140001de0(value, (ctx+0x20!=1)+0x4001000b)` -> "Connect"/"Disconnect" status indications (strings `0x1400084c0/0x1400084d0`). |
| `0x222010`,`0x222018`,`0x222080`,`0x222084` | - | Forwarded to layer 2 (`LAB_140004623`). |
| default | - | `0xC0000010` STATUS_INVALID_DEVICE_REQUEST. |

Layer 2 - `FUN_140003a70`:

| Code | Buffering | Action |
|---|---|---|
| `0x222010` / `0x222018` | BUFFERED | Log + state change `FUN_140001cd0(0)` / `(0xF)` + `FUN_1400073d0`. |
| `0x222023` | NEITHER (code&3=3) | **Parks IRP** at ctx+0x50; cancel routine `FUN_1400037b0` installed. |
| `0x222027` / `0x22202B` | NEITHER | `NdisSetTimerObject` on ctx+0xD0 (receive pump) / ctx+0x170. |
| `0x22202F` | NEITHER | **Parks IRP** at ctx+0x68 - **no cancel routine found for this slot**. |
| `0x222080` / `0x222084` | BUFFERED | `FUN_140001de0(0x4001000b / 0x4001000c)` connect/disconnect. |

Timers: ctx+0xD0 `FUN_140005280` **receive pump** (builds NBLs via `FUN_140007e7c` + `NdisAllocateMdl`, then `NdisMIndicateReceiveNetBufferLists(ctx+8, list, 0, count)` flag `0x401`); ctx+0x170 `FUN_140007060`->`FUN_1400065b0(1)`; ctx+0x178 `FUN_140006ea0`->`FUN_1400073d0`; ctx+0x180 `FUN_140006f50` free-list walker; ctx+0x188 `FUN_1400018e0` reset/pause completion (<=0x15 retries -> `NdisMResetComplete`/`NdisMPauseComplete`).

Send path (`FUN_140007720` -> `FUN_140005dd0` -> `FUN_140006190`): maps send NBL MDLs with `MmMapLockedPagesSpecifyCache`; drops frames per packet-filter bits (ctx+0x1A8 bits 1/2/4/8) and multicast list ctx+0x1B4 vs target MAC (ctx+0x8A/0x90); per-frame size check of `*(NB+0x18)` against `param_4+0x40` and cap `0x61C`; copy via `FUN_140008100` (memcpy); drop path `FUN_1400036c0`.

### 3.2 OID plane (`MiniportOidRequest` = `0x140002fe0`)

Dispatch on `RequestType` @ req+4: 0/2 -> QUERY `FUN_1400022c0`; 1 -> SET `FUN_140001ff0`; 0xC -> `FUN_140002f20` (always `0xC00000BB`). Fields: Oid @+0x20, InformationBuffer @+0x28, Length @+0x30, BytesWritten/Read @+0x34, BytesNeeded @+0x38.

QUERY (`FUN_1400022c0`) - supported:

| OIDs | Source |
|---|---|
| `0x10101` | Supported-OID list copied from `DAT_14000a010` (up to 0xE8 bytes) |
| `0x10102/03/04/05/06` | Header/statistic ctx fields (framesize*count values) |
| `0x10107` | **Link-speed qword read from ctx+0x28 - the value planted via IOCTL `0x222030`** |
| `0x10108/09`, `0x1010A/0B/11` | Frame-size / MTU(+0xE) fields |
| `0x1010C`, `0x1010D` | Vendor id from MAC ctx+0x84; description `"Cisco AnyConnect VPN Virtual Miniport Adapter for Windows x64"` @`0x140009218` |
| `0x1010E`, `0x1010F`, `0x10113`(=8), `0x10114`, `0x10115`, `0x10116`(=0x20001) | ctx+0x1A8 / +0x1AC / +0x20 / +0x34 / constants |
| `0x1010101/02/04` | MAC ctx+0x84 / ctx+0x8A (6 B); `0x20` |
| `0x20101..05`, `0x2021C`, `0x10201..03`, `0x1020201..05`, `0x1020101..03` | Statistics via `FUN_140002c90`: **BytesNeeded=8 but only 4-byte writes with partial `Information=4` even when the full 8 requested** (weak length enforcement) |
| `0x20106` | 0x98-byte statistics struct (header dwords `0x00980180`, `0x3F87FF`) |
| `0x10209`, `0xFD010107` | 12-byte (hdr 0xC0180) / 0x34-byte wakeup-capability struct; `0xFD010102` -> empty success |
| `0x10117`, `0xFC0102xx`, `0xFEFD..` family | -> `0xC00000BB` STATUS_NOT_SUPPORTED |

SET (`FUN_140001ff0`) - supported:

| OIDs | Behavior / risk |
|---|---|
| `0x1010E` / `0x1010F` | Packet filter / lookahead: len must == 4 else `0xC0010014` (BytesNeeded=4); **4-byte value stored unvalidated** into ctx and used to gate the TX filter path |
| `0x1010103` | Multicast list: len multiple of 6, <= 0xC0 else `0xC0010009` (BytesNeeded=0xC0); memcpy -> ctx+0x1B4, count -> +0x1B0 |
| `0xFD010101` | Wakeup add: silent success |
| `0x10118` / `0x10119` | Silent success, no content verification |
| `0x1021A` | **Permissive accept** - claims success with `BytesWritten = InputBufferLength` for an effectively unimplemented OID |
| `0xFD010102..0xFD01010C`, `0xFD0101..` `bits` sweep | -> `0xC00000BB` |
| default | `BytesWritten=0`, `BytesNeeded=0`, status `0xC0010017` |

## 4. Access-control audit

- **No driver-enforced access control of any kind.** Sweep of strings, imports, and all decompiled code found:
  - No SDDL/security-descriptor string, no `IoCreateDeviceSecure`.
  - No `SeSinglePrivilegeCheck` / `SeAccessCheck` / privilege validation.
  - No exclusive flag; device created through `NdisRegisterDeviceEx` with **no SecurityDescriptor** - worse, the attributes field that would carry it is the *uninitialized* stack dword `[RSP+0x44]` noted in section 2.
- All 14 IOCTLs carry access bits = 0 (`FILE_ANY_ACCESS`): the driver never even requires `FILE_READ/WRITE_DATA` on the handle.
- Net effect: exposure is gated **only** by the object manager's default security for `\Device\VPNVA` (normally admins/service account). This is an OS default, not a driver control, and it is weaker than an explicit SDDL.

## 5. Most dangerous exposed capability

1. **User-mode packet injection into NDIS (`0x22200A` + `0x222027` + `0x222004`).** A caller can hand its own MDL to the driver; the driver maps those user pages into system VA (`MmMapLockedPagesSpecifyCache`, only `MdlFlags & 5` checked), targets the parked-IRP ctx+0x48 queue, and the timer at ctx+0xD0 (`FUN_140005280`) then drains those user-owned bytes into `NdisMIndicateReceiveNetBufferLists`. Arbitrary frames from user memory reach the OS network stack through an admin-details-free direct pipeline; the data is validated at *per-frame send* time, not at *inject* time. Cancel path `FUN_1400038c0` -> `FUN_140003320` tears down, but the parked IRP + stale mapping lifetimes are the usual race window.
2. **Attacker-controlled link-speed / device state:** `0x222030` writes an arbitrary 8-byte value to ctx+0x28 (returned by OID `0x10107` as an NDIS-reported field), and SET `0x1010E`/`0x1010F` store unvalidated 4-byte filter/lookahead values that directly drive the TX accept/drop logic in `FUN_140005dd0`/`FUN_140006190`. SET `0x1021A` acknowledges anything with `BytesWritten = InputLen`. Stats OIDs (`FUN_140002c90`) hand out partial 4-byte replies when the buffer is merely >= 4 bytes instead of enforcing the declared size.
3. **Parked-IRP handling:** three parking slots (ctx+0x48/0x50/0x68) with cancel routines (`FUN_1400038c0`, `FUN_1400037b0`) - slot ctx+0x68 (`0x22202F`) has **no cancel routine**, so IRPs parked there can outlive their ticket-holders and transition the device into a hung request state.

## 6. VERDICT

- **Legitimate VPN virtual-adapter miniport** (Cisco AnyConnect / Secure Client "VPNVA") - not malware. All dangerous primitives (packet in/out, filter/multicast control, reset/pause machinery) are functionally required for the adapter's purpose.
- However, the attack surface is maximally exposed by policy choices: `\Device\VPNVA` is created with **no access-control hardening at all** (default security, `FILE_ANY_ACCESS` on every IOCTL, no privilege check), and input validation is minimal across the IOCTL plane (`0x22200A`, `0x222030`, `0x222023/0x22202F` parked queues) and the OID SET/STATS paths.
- Recommended hardening: explicit SDDL / privilege check on device creation, per-frame and per-IRP length checks in OID/stat handlers, cancel routine for the ctx+0x68 queue, initialization of the attributes dword at `[RSP+0x44]`, and strict MDL lifetime control for `0x22200A` (MDL user-buffer mapping).
- Risk as shipped: **moderate for the intended admin-managed use; high if `\Device\VPNVA` is openable by any process** - this depends on the OS default descriptor, not on the driver, so treat the device as effectively unattributed-input-capable.

---

*Evidence (REA session): overview `ev_d3e0128fd2bd25f8de8db5c99f1b76852c1ab4f10feab034b391a78e60419a0a`; procedures `ev_22930d43f30e14d4f63dc2959f451c867d83623e9632e3e2861e14a1005a0ff3`; strings `ev_5d6022bc84d5594e8f933068230d1142b14af312ffcb825864010811da15d6b0`. All addresses are file-VA relative to image base `0x140000000`.*
