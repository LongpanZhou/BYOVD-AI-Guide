# Audit: Scuf `Scufdriver5` / `Scufdriver6` and Silicon Labs `SiUSBXp32` / `SiUSBXp64`

| Field | Value |
|---|---|
| File(s) | `drivers/Scufdriver5_7CE234CA.sys` (50,864 B, x64); `drivers/Scufdriver6_B32A09F9.sys` (30,896 B, x64); `drivers/SiUSBXp32_589FEA41.sys` (14,592 B, i386); `drivers/SiUSBXp64_A1F4B952.sys` (19,456 B, x64) |
| SHA-256(s) | `7CE234CA6779190E2DA2C025D0857F3954E36CF55991FC29599803E7A3CA0281`; `B32A09F95A3D28F41F0BEAC79AA79E6D307D9261183FF26AEAD85A6C9F37B328`; `589FEA41EF48ACD9F0FC54AB25A430E5627D17E8EC3C950F3C5CB71C348E9B8D`; `A1F4B952099EBA4BA4E659782F85B45C4BBB411BF5B7C02D5BE0CC3DBF27AFF3` (all `Get-FileHash -Algorithm SHA256`; match `indexes/drivers_manifest.csv`) |
| Analysis date | 2026-10-25 |
| Method | **Static only.** Local Ghidra 12.1.4 headless decompile (`DumpDecomp.java`, four dumps, 96/66/64/41 functions) plus `llvm-objdump` PE headers, import tables and targeted disassembly. No driver load, install, service creation, registry write or execution. **REA was not used**: four REA audits were already active, so no REA session was opened and no REA evidence IDs exist for this report. This is a Ghidra/objdump-only audit. |
| Reach tier | SiUSBXp32/64: **R1** device interface (`FILE_ANY_ACCESS` codes; default Everyone-read device DACL), with an **R2** load gate because the images are unsigned. Scuf5/6: **R1/R2** control-device symlink (write-access codes need a write ACE); device existence is **R3** (hardware for Scuf5, devnode for Scuf6). |
| Setup required | **hardware** (Scufdriver5; SiUSBXp32/64 — USB device must enumerate), **devnode** (Scufdriver6 — `StartDevice` creates the control device, so a matching root devnode is sufficient) |
| Write quality | **W2** (SiUSBXp32/64, static) / **W0** (Scufdriver5, Scufdriver6) |
| Verdict | **BLOCKED** — the only memory-write primitive in this batch is the unsigned SiUSBXp pair (**static MW2**, hardware-gated). **NO-MEMORY-WRITE** — Scufdriver5 and Scufdriver6. |

> Static analysis only. No driver was loaded, installed, started or executed; no IOCTL was issued. This report describes gates and a primitive; it contains no exploit code or PoC.

## Overall verdict

The two Scuf drivers expose named control devices whose symlink path is not protected by `FILE_DEVICE_SECURE_OPEN`, but they contain **no kernel memory-write primitive**: their only caller-data stores are fixed-offset, fixed-length, in-bounds configuration fields, and their one pointer-based `METHOD_NEITHER` handler sits on an unnamed, unregistered PDO that user mode cannot open.

**Triage confirmation:** none of the four import tables or decompiled dumps references `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, or `KeStackAttachProcess`. The supplied "no memory-mapping API" triage is correct; the SiUSBXp finding is a plain `METHOD_BUFFERED` pool OOB, not a mapping primitive.

The two SiUSBXp builds contain a real, static **pool out-of-bounds write** in IOCTL `0x222028`: a 16-bit caller-controlled length is placed into a USB control-IN URB whose transfer buffer is the `METHOD_BUFFERED` system buffer `+ 8`, with no check against `InputBufferLength` or `OutputBufferLength`. The same code has a matching unchecked **OOB read** in `0x222024` (OUT direction). The primitive is hardware-gated (a USBXpress device or a malicious device with matching IDs must return the oversized IN data) and the images are unsigned, so the batch verdict is **BLOCKED (static MW2)** even though the write is real.

## Per-file results

| File | SHA-256 (prefix) | Device / interface | Effective DACL / open gate | IOCTL surface | Write | Verdict |
|---|---|---|---|---|---|---|
| `Scufdriver5_7CE234CA.sys` | `7CE234CA…` | `\Device\ScufOneCtl%d` + `\DosDevices\ScufOneCtl%d`, created only after the Scuf USB descriptor exchange; unnamed FDO and unnamed type-3 PDO | No SDDL / no `IoCreateDeviceSecure`; I/O-manager default device DACL (SYSTEM/Administrators full, Everyone read). Device characteristics **0** at `0x140003138` — **no `FILE_DEVICE_SECURE_OPEN`**; symlink published, so the link path is not device-DACL-gated (link DACL is an OS property, not in the image). No `SeAccessCheck`/`SeSinglePrivilegeCheck`. | `0x22E848` (BUFFERED, RW, OBL exactly `0x40`, 0x40-byte board-name read); IRP_MJ_READ (4-byte state); IRP_MJ_WRITE (0x14/0xC fixed config stores); internal `0x220003` on the unreachable PDO | Fixed in-bounds config store only | **NO-MEMORY-WRITE** (W0) |
| `Scufdriver6_B32A09F9.sys` | `B32A09F9…` | `\Device\ScufAudCtl%d` + `\DosDevices\ScufAudCtl%d`, created from PnP `StartDevice` | Same: no SDDL, default device DACL, characteristics **0** at `0x140001D94` — no `FILE_DEVICE_SECURE_OPEN`; no privilege check | `0x22E84C`, `0x22E850` (BUFFERED, RW, no buffer use; set `Ext+0x1D8` and queue `ShowDevice`); IRP_MJ_READ/WRITE complete with no copy | None | **NO-MEMORY-WRITE** (W0) |
| `SiUSBXp32_589FEA41.sys` | `589FEA41…` | Unnamed FDO; interface `{3C5E1462-5695-4E18-876B-F3F3D08AAF18}` via SiLib `GenericRegisterInterface` | No SDDL / no `IoCreateDeviceSecure`; default device DACL. Characteristics `0x80` (auto-name, **no SECURE_OPEN**) at `0x11DF1`. All codes `FILE_ANY_ACCESS`; read handle suffices. No privilege check. **Unsigned** (no PE security directory; no `.cat` in corpus). | Nine codes (`0x222008/0C/14/18/24/28/80/84/88`) plus `IRP_MJ_QUERY_INFORMATION` | **OOB pool write** `0x222028` (W2); matching OOB read `0x222024`; 4-byte slack overwrite at `0x222084` | **BLOCKED** (static MW2) |
| `SiUSBXp64_A1F4B952.sys` | `A1F4B952…` | Same interface GUID, unnamed FDO | Same; characteristics `0x80` at `0x13830`; **unsigned** | Same nine codes | **OOB pool write** `0x222028` (W2); matching OOB read `0x222024`; 4-byte slack overwrite at `0x222084` | **BLOCKED** (static MW2) |

## 1 Internals and entry

### 1.1 Scufdriver5 (x64, Corsair, 1.0.100, signed WHCP)

- `entry` `0x14000C000` → `FUN_1400019BC` (DriverEntry). It fills all 28 major functions with `FUN_140001D20`, then sets:
  - `IRP_MJ_CREATE` (`+0x70`), `IRP_MJ_CLEANUP` (`+0x100`), `IRP_MJ_READ` (`+0x80`), `IRP_MJ_WRITE` (`+0x88`), `IRP_MJ_QUERY_INFORMATION` (`+0x90`) → `FUN_140001920`;
  - `IRP_MJ_DEVICE_CONTROL` (`+0xE0`) and `IRP_MJ_INTERNAL_DEVICE_CONTROL` (`+0xE8`) → `FUN_1400018F0`;
  - `IRP_MJ_PNP` (`+0x148`) → `FUN_140001960`, `IRP_MJ_POWER` (`+0x120`) → `FUN_140001990`, `IRP_MJ_SYSTEM_CONTROL` (`+0x128`) → `FUN_140001ED0`;
  - `DriverExtension->AddDevice` → `FUN_140001640`; `DriverUnload` → `FUN_140001F20`.
- `AddDevice` `FUN_140001640` creates an **unnamed** FDO (`IoCreateDevice`, extension `0x28E`, type `0x22`, characteristics 0) and attaches it to the USB PDO. That FDO is not user-openable.
- The named control device is created by `FUN_140003068`, called from the driver's system worker `FUN_140001000` on the `"CreatePDOs"` work item (`0x14000118C`). That work item is queued only after `"GetMac"` (`0x14000116E`), which follows `"SetTargetConfiguration"` and `"GetDescriptorData"`. `"GetDescriptorData"` is queued at PnP `StartDevice` (`0x140005B89`, `FUN_140005AD0`) and aborts the chain if the descriptor read `FUN_14000237C` fails (`0x1400010DA` → return `0xC0000001`). A real Scuf USB device (or an emulated one) is therefore required before `\Device\ScufOneCtl0` exists.

### 1.2 Scufdriver6 (x64, Corsair, 1.0.96, signed WHCP)

- `entry` `0x140007000` → `FUN_140001750` (DriverEntry). It sets `IRP_MJ_CREATE`/`CLEANUP`/`READ`/`WRITE`/`QUERY_INFORMATION` → `FUN_1400016D0`, `IRP_MJ_DEVICE_CONTROL`/`IRP_MJ_INTERNAL_DEVICE_CONTROL` → `FUN_1400016B0`, `IRP_MJ_PNP` → `FUN_140001710`, `IRP_MJ_POWER` → `FUN_140001730`, `IRP_MJ_SYSTEM_CONTROL` → `FUN_140001A80`, `AddDevice` → `FUN_140001410`, `DriverUnload` → `FUN_140001AD0`.
- `AddDevice` `FUN_140001410` creates an unnamed FDO and attaches to the PDO.
- PnP `StartDevice` (`FUN_140002758`, minor 0) calls `FUN_1400028B4`, which starts the worker and **immediately queues `"CreatePDOs"`** at `0x14000296D`. The worker calls `FUN_140001CC4` (`0x1400010BC`), which creates the named `\Device\ScufAudCtl%d`. Unlike Scuf5, no USB descriptor exchange is required; a matching root-enumerated devnode whose `StartDevice` is forwarded successfully is enough. `Setup: devnode` is therefore the appropriate field.

### 1.3 SiUSBXp32 / SiUSBXp64 (Silicon Laboratories USBXpress 3.3, unsigned)

- `entry` `0x19064` (x64) / `0x12E05` (x86) → DriverEntry `FUN_00015008` / `FUN_00012A06`.
- `AddDevice` `FUN_000137E8` (x64) / `0x11DB2` (x86) calls `IoCreateDevice(DriverObject, ext, NULL, 0x22, 0x80, 0, &dev)` — unnamed, auto-name characteristic, **no `SECURE_OPEN`** — attaches to the USB PDO, copies `\DosDevices\USBINT` into the extension (never published; `IoCreateSymbolicLink` is not imported), and registers device interface `{3C5E1462-5695-4E18-876B-F3F3D08AAF18}` through SiLib (`GenericRegisterInterface` at `0x13B3B` x64 / `0x11FD7` x86).
- The user-visible path is therefore the PnP **device interface**, not a `\DosDevices` name. It exists only while the USBXpress device is enumerated and started.

## 2 Device DACL / open gate

| Binary | SDDL present? | Creation call | Characteristics | Effective gate |
|---|---|---|---|---|
| Scufdriver5 | **None** (no `D:P(`, no `IoCreateDeviceSecure`, no `RtlSetDaclSecurityDescriptor`, no `ZwSetSecurityObject`) | `IoCreateDevice(DriverObject, 0x28E, &name, 0x22, 0, TRUE, &dev)` at `0x140003138`; symlink at `0x140003202` | `0` — no `FILE_DEVICE_SECURE_OPEN`; `Exclusive=TRUE` | I/O-manager default device DACL: SYSTEM + Administrators full, Everyone read. Because `SECURE_OPEN` is clear, the symlink path is not checked against the device DACL; the link's default DACL is an OS property not in the image. Write-access code `0x22E848` needs a write ACE, so **R2 is certain; R1 is possible if the link DACL is permissive**. |
| Scufdriver6 | **None** | `IoCreateDevice(DriverObject, 0x1E0, &name, 0x22, 0, TRUE, &dev)` at `0x140001D94`; symlink at `0x140001E5E` | `0`; `Exclusive=TRUE` | Same as Scuf5. |
| SiUSBXp32 | **None** | `IoCreateDevice(..., NULL, 0x22, 0x80, 0, ...)` at `0x11DF1` | `0x80` auto-name; **no `SECURE_OPEN`**; no symlink | Default device DACL (Everyone read). All codes are `FILE_ANY_ACCESS`, so a read-only interface handle is sufficient. **R1** once the (unsigned) driver is loaded. |
| SiUSBXp64 | **None** | `IoCreateDevice(..., NULL, 0x22, 0x80, 0, ...)` at `0x13848` | `0x80`; no `SECURE_OPEN`; no symlink | Same. |

No image contains `SeAccessCheck`, `SeSinglePrivilegeCheck`, `RtlSetDaclSecurityDescriptor`, `IoCreateDeviceSecure`, or an SDDL literal. The default DACL is the documented I/O-manager default; it was **not** read from a live device object (static-only limit).

## 3 Dispatch and IOCTL surface

### 3.1 Scufdriver5 — `\Device\ScufOneCtlN` (extension type 2)

`IRP_MJ_DEVICE_CONTROL` reaches `FUN_1400018F0`; the type-2 branch tail-jumps to `FUN_140004A80`.

| Code / path | Method | Access | Input | Output | Kernel action |
|---|---|---|---|---|---|
| `0x22E848` (`0x140004AF8`) | BUFFERED | RW | none | exactly `0x40` | Copies at most `0x20` UTF-16 words (0x40 bytes) from a static board-name table into `SystemBuffer`, null-terminates within the 0x40 bytes. In-bounds. |
| `IRP_MJ_READ` (`0x140004C44`) | — | — | — | length 4 | Writes the 4-byte controller state to `SystemBuffer`. In-bounds. |
| `IRP_MJ_WRITE` (`0x140004C5D`) | — | — | length `0x14` | — | `movups` 20 caller bytes to **FDO extension +0x262**; length `0xC` writes 12 bytes to **+0x276**. FDO extension is `0x28E`; both end at `0x282` — in-bounds. These are calibration/override fields used by the gamepad report builder, not pointers. |
| internal `0x220003` (type-3 PDO only) | NEITHER | ANY | driver-built URB/struct | — | `FUN_1400033BC` writes through `*(PVOID *)(input+0x28)` and related fields. The type-3 device is created **unnamed** at `0x140002F80` with no symlink/interface; the only such IRPs seen are built by the driver itself (`0x140002095`, Type3InputBuffer = kernel buffer). **Not user-reachable.** |
| `0xB000F` (unnamed FDO type 0) | NEITHER | ANY | user buffer interpreted as `{PVOID, ULONG}` | — | `FUN_140003238` hex-logs up to 0x40 bytes from the pointer; a kernel **read**, no store. The type-0 FDO is unnamed/not openable. Not a write. |

`0x22E848` output-length check is `== 0x40` (`0x140004B08`), and the copy loop is capped at 0x20 words (`0x140004B31`–`0x140004B5E`). No overflow.

### 3.2 Scufdriver6 — `\Device\ScufAudCtlN` (extension type 2)

`IRP_MJ_DEVICE_CONTROL` → `FUN_1400016B0`; type 2 → `FUN_140002144` (`0x22E84C` check at `0x1400021A1`).

| Code | Method | Access | Input | Output | Kernel action |
|---|---|---|---|---|---|
| `0x22E84C` | BUFFERED | RW | none used | none | `Ext+0x1D8 = 1`; queues `ShowDevice` (`0x140003D30`). |
| `0x22E850` | BUFFERED | RW | none used | none | `Ext+0x1D8 = 0`; queues `ShowDevice`. |
| IRP_MJ_READ / WRITE | — | — | — | — | `FUN_1400020CC` only acquires/releases the remove lock and completes; **no buffer copy**. |

`ShowDevice` may create the type-1 unnamed child device (`FUN_140001AE0`) and invalidate relations; it does not consume caller data.

### 3.3 SiUSBXp32 / SiUSBXp64 — interface `{3C5E1462-…}`

DeviceControl `FUN_00013008` (x64) / `FUN_000117CE` (x86). The dispatch compares `IoControlCode`; `InputBufferLength` is at stack `+0x10`, `OutputBufferLength` at `+0x8`, `SystemBuffer` at `IRP+0x18`.

| Code | Method | Access | In | Out | Kernel action |
|---|---|---|---|---|---|
| `0x222008` | BUFFERED | ANY | 0 | ≥ `0x12` | Copy `0x12` bytes of extension data to `SystemBuffer`. |
| `0x22200C` | BUFFERED | ANY | 0 | ≥ 9 | Copy 9 bytes. |
| `0x222014` | BUFFERED | ANY | 0 | ≥ `0x30` (x64) / ≥ `0x24` (x86) | Copy `0x30` / `0x24` bytes. x86 build uses `0x24`. |
| `0x222018` | BUFFERED | ANY | 0 | ≥ ext `USHORT` | `memset(SystemBuffer, 0, OBL)` then copy ext-size bytes; OBL check present. |
| `0x222024` | BUFFERED | ANY | ≥ 8 to control header | > 0 | Builds vendor/class **OUT** URB (TransferFlags `0`, `0x135B5` x64), `TransferBuffer = SystemBuffer+8`, `TransferBufferLength = *(USHORT *)(input+6)`; **no length check** → OOB **read** of pool to the device. |
| `0x222028` | BUFFERED | ANY | ≥ 8 to control header | > 0 | Builds vendor/class **IN** URB (TransferFlags `3` = IN + SHORT_TRANSFER_OK, `0x134FA` x64), `TransferBuffer = SystemBuffer+8`, `TransferBufferLength = *(USHORT *)(input+6)`; **no length check** → OOB **write** (section 4). |
| `0x222080` | BUFFERED | ANY | 0 | > 0 | Ring-buffer copy to `SystemBuffer`, capped by OBL (`FUN_00011008` / `FUN_0001119E`). Safe. |
| `0x222084` | BUFFERED | ANY | 0 | > 0 | Writes a 4-byte status to `SystemBuffer`; only `OBL != 0` is checked. OBL 1–3 writes 4 bytes; the pool block's 8/16-byte granularity contains it, so this is **pool slack, not a usable overflow**. Note only. |
| `0x222088` | BUFFERED | ANY | > 0 | 0 | Reads one input byte; optionally zeroes a fixed `0x1000` kernel buffer; no user length. |
| `IRP_MJ_QUERY_INFORMATION` | — | — | — | ≤ `0x1000` | `FUN_00014834` allocates `0x80`, builds an internal `0x220003` URB with `TransferBuffer = SystemBuffer`, `TransferBufferLength = OBL`; bounded by OBL. |

All nine codes are `FILE_ANY_ACCESS` (`(code >> 14) & 3 == 0`), so no write right is needed on the handle.

## 4 Memory-write trace — SiUSBXp `0x222028`

### 4.1 Exact data flow

x64 build, `FUN_00013008`, branch at `0x13476`:

1. `uVar15 = OutputBufferLength`; the only gate is `OutputBufferLength != 0` (`0x13476`). `InputBufferLength` is **not** checked.
2. `puVar5 = IRP->SystemBuffer` (`IRP+0x18`).
3. Header is read from the system buffer:
   - byte `+1` = request, word `+2` = value, word `+4` = index;
   - **word `+6` = transfer length** (`0x134B8`), zero-extended to 32 bits;
   - **`TransferBuffer = SystemBuffer + 8`** (`0x134CA`);
   - `TransferFlags = 3` (`0x134FA`) = `USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK`;
   - URB function `0x17` (vendor interface) or `0xB` (GET_DESCRIPTOR), selected by bit `0x40` of input byte 0.
4. `FUN_000141A8` wraps the structure in `IOCTL_INTERNAL_USB_SUBMIT_URB` (`0x220003`) and sends it to the lower USB PDO. No length validation is added.

x86 build, `FUN_000117CE`, branch at `0x11C08`: identical — length from `*(USHORT *)(input+6)` (`0x11C17`), buffer `SystemBuffer+8` (`0x11C45`), `TransferFlags = 3` (`0x11C64`), submit at `0x11C6B`.

### 4.2 Why it is an out-of-bounds write

For `METHOD_BUFFERED`, the I/O manager allocates one system buffer of size `max(InputBufferLength, OutputBufferLength)` and copies the input into it. With `InputBufferLength = 8` (header only) and `OutputBufferLength = 1`, the buffer is 8 bytes; `SystemBuffer + 8` is the first byte past the requested size, and the IN URB is told to write up to the 16-bit length there. The USB stack builds the transfer from the URB's `TransferBuffer`/`TransferBufferLength`; it has no knowledge of the original allocation size. A device that returns the full control-IN data stage therefore writes up to **65,535 bytes starting at `SystemBuffer+8`**; once the response exceeds the allocator's rounding slack, the write corrupts the adjacent non-paged-pool block. The length is fully caller-controlled; the bytes are device-controlled (arbitrary for a malicious device with matching VID/PID).

The `0x222028` branch also returns `InputBufferLength` as `IoStatus.Information`, which does not affect the transfer.

### 4.3 The matching read

`0x222024` is the same URB builder with `TransferFlags = 0` (OUT): the USB stack **reads** `TransferBufferLength` bytes from `SystemBuffer+8` and sends them to the device. With the same unchecked length this is an OOB pool **read** to a device the attacker controls — a kernel-memory disclosure that can supply pool/KASLR information, but not a write. It is recorded as a modifier, not a write verdict.

### 4.4 What is not a primitive

- `0x222084`: 4-byte store with only `OBL != 0`; OBL 1–3 writes 3 bytes into the allocator's rounding slack. No adjacency control and no reliable cross-block write; handled as a robustness bug, not MW.
- `0x222018`, `0x222080`, `0x222008/0C/14`: output lengths are checked or fixed; copies stay within `SystemBuffer`.
- Scuf5 `IRP_MJ_WRITE`: 20/12 bytes to fixed FDO-extension offsets, in-bounds; configuration/calibration, no address or size control (same treatment as the fixed `DevExt+0x20` store in the Corsair VBus report → W0).
- Scuf5 internal `0x220003`: pointer-based `METHOD_NEITHER` write, but only on the unnamed type-3 PDO; not user-openable.

## 5 Access-control audit

| Gate | Scuf5 | Scuf6 | SiUSBXp32/64 |
|---|---|---|---|
| Device SDDL | none | none | none |
| `IoCreateDeviceSecure` | absent | absent | absent |
| `FILE_DEVICE_SECURE_OPEN` | **clear** (characteristics 0) | **clear** | clear (0x80 is auto-name) |
| Symlink / interface | `\DosDevices\ScufOneCtlN` | `\DosDevices\ScufAudCtlN` | interface GUID `{3C5E1462-…}` |
| Open gate | default device DACL + link DACL; write codes need write ACE | same | default device DACL; all codes ANY, read handle suffices |
| In-driver privilege check | none | none | none |
| Reach | R2 certain; R1 if link permits | R2 certain; R1 if link permits | R1 once loaded (unsigned → R2 load gate) |

The exact symbolic-link/interface DACL is not present in the images and was not read live; the table records the device-object default and the `SECURE_OPEN` behaviour. This is the main static uncertainty for reach, not for the write analysis.

## 6 Most dangerous exposed capability

**SiUSBXp32/64, IOCTL `0x222028`:** a caller-controlled 16-bit transfer length and a fixed `SystemBuffer+8` destination produce a non-paged-pool OOB write of up to 64 KB of device-controlled bytes. It is reachable through the device interface with a read-only handle (`FILE_ANY_ACCESS`), but needs the USBXpress hardware (or a malicious device with matching IDs) and the unsigned driver must be loadable (test signing / valid catalog). Static write quality **W2**, static severity **MW2** by the `silabser`/CP210x hardware-gated-W2 precedent; the strict R3+W2 matrix row would read MW3, but the open gate is R1 and the hardware is attacker-suppliable, so MW2 is the closer match. Status **BLOCKED** because the images are unsigned.

Scuf5's most dangerous capability is the fixed 20-byte control-device write into the FDO extension (in-bounds configuration); Scuf6's is a flag toggle. Neither is a memory-write primitive.

## 7 Verdicts

| File | Reach / setup | Write | Load | Verdict |
|---|---|---|---|---|
| `Scufdriver5_7CE234CA.sys` | R2 (R1 possible via link) / hardware | W0 | signed WHCP (valid, timestamped) | **NO-MEMORY-WRITE** — `MW0`; fixed in-bounds config store only; internal pointer path unreachable |
| `Scufdriver6_B32A09F9.sys` | R2 (R1 possible via link) / devnode | W0 | signed WHCP | **NO-MEMORY-WRITE** — flag toggles only |
| `SiUSBXp32_589FEA41.sys` | R1 interface / hardware | W2 | **unsigned** (no embedded signature; catalog unknown) | **BLOCKED** — static **MW2** (`0x222028` pool OOB write; `0x222024` OOB read) |
| `SiUSBXp64_A1F4B952.sys` | R1 interface / hardware | W2 | **unsigned** | **BLOCKED** — static **MW2** (same) |

**Overall: BLOCKED** — the batch's only memory-write primitive is the unsigned, hardware-gated SiUSBXp `0x222028` pool OOB write (static MW2). The two Scuf drivers are **NO-MEMORY-WRITE**.

## 8 Limitations and unresolved paths

1. **Static only.** No driver loaded, no device staged, no IOCTL issued. The `0x222028` overflow is inferred from the URB `TransferFlags = IN`, the unchecked 16-bit length, and standard `METHOD_BUFFERED` allocation size; it was not observed dynamically. The USB stack's handling of an oversized `TransferBufferLength` is standard but not executed here.
2. **REA not used.** Four REA audits were already active; no REA session was opened and no REA evidence IDs exist. All addresses are Ghidra 12.1.4 / `llvm-objdump` addresses. Dumps: `%TEMP%\opencode\scuf_si\scuf5_dump.txt`, `scuf6_dump.txt`, `si32_dump.txt`, `si64_dump.txt`.
3. **Effective link/interface DACL not read live.** The device objects use the I/O-manager default (SYSTEM/Administrators full, Everyone read). Scuf5/6 clear `FILE_DEVICE_SECURE_OPEN`, so the symlink path is not device-DACL-gated; the link's default DACL is an OS property. SiUSBXp has no symlink and all codes are `FILE_ANY_ACCESS`; a read handle is sufficient if the interface DACL grants Everyone read.
4. **SiUSBXp signing.** The PE has no embedded signature (security directory 0) and no `.cat` is in the corpus. A valid catalog would remove the BLOCKED load gate; without it, HVCI/DSE blocks the driver unless test signing is enabled. This is the difference between "static MW2, blocked" and "MW2 on a test-signed host".
5. **Scuf5 hardware precondition.** `\Device\ScufOneCtl0` appears only after the descriptor/MAC chain succeeds (`FUN_14000237C` returns `0xC0000001` on failure). A root devnode alone is not enough for Scuf5; Scuf6 creates its control device directly from `StartDevice` and is devnode-reachable.
6. **Scuf5 latent path.** The type-3 PDO `0x220003` handler trusts pointer fields inside its input structure. It is not user-reachable today (unnamed, no interface, no symlink) and is recorded only as a latent design risk; if a future build publishes that PDO, the path would need a full `METHOD_NEITHER` probe/validation review.
7. **No exploit code or PoC.** The report stops at the primitive description.
