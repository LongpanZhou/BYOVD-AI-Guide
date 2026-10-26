# Audit: TeamGroup `nvme_*.sys` family — current-scope re-audit

| Field | Value |
|---|---|
| File(s) | `drivers\nvme_35B2D3D4.sys`, `drivers\nvme_45635E0B.sys`, `drivers\nvme_77C8809A.sys`, `drivers\nvme_A9B48787.sys`, `drivers\nvme_E4AB6E36.sys`, `drivers\nvme_FFD83A43.sys` |
| SHA-256(s) | `35B2D3D40F30C9315DAB336B115FE4777B6C8C1CD947B67430728148E257A0A7` (35B2D3D4)<br>`45635E0BC7C8913555625BE68C0ABDA7254F1442C283930F3907424358986027` (45635E0B)<br>`77C8809A972B18B9A749001F93DFA970119C965A73E4DDFFFB0E43BB88CED78E` (77C8809A)<br>`A9B4878717E52EA70892BDF9AF58EA7A8408DCFFEBDA095D83E39D8580565A8B` (A9B48787)<br>`E4AB6E3610A6BC6BD2CB287D5556C681ED0DFA63C9DFB6A73D7DB922DD7CF5BB` (E4AB6E36)<br>`FFD83A43F8CFB54C57ED2000DE562F709A73F2600AE5EB8CD0A472F8F6CF5CF9` (FFD83A43) |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local Ghidra 12.1.4 headless (import + full decompile of every function) and `llvm-objdump` PE/import/disassembly cross-check. **No REA session was opened: the shared REA bridge was at its four-audit capacity, so no REA evidence IDs exist for this report.** |
| Reach tier | `R2` local administrator (storage-device handle) / `R3` hardware (matching NVMe controller) |
| Setup required | `hardware` (NVMe PCI controller + PnP devnode; the miniport loads only when the controller enumerates) |
| Write quality | `W2` (constrained target and value) |
| Verdict | **MW2** — x64 builds `45635E0B`, `A9B48787`, `E4AB6E36`; **BLOCKED** — i386 builds `35B2D3D4`, `77C8809A`, `FFD83A43` |

Supersedes `audits\reports\teamgroup_nvme.static.md` (old scope, one build dumped, `NO-WRITE` by policy).
Reason for re-audit: scope change (admin in scope), all six files verified, i386/x64 split discovered, and the
SRB pass-through surface was never traced.

## 0. Per-file table

| Build | Arch | SHA-256 verified | Entry | Signed | Pass-through write path | Verdict |
|---|---|---|---|---|---|---|
| `nvme_45635E0B.sys` | x64 (PE32+) | yes | `0x140012898` | Realtek, Valid | present (traced) | **MW2** |
| `nvme_A9B48787.sys` | x64 (PE32+) | yes | `0x140012d20` | Realtek, Valid | present (same code shape) | **MW2** |
| `nvme_E4AB6E36.sys` | x64 (PE32+) | yes | `0x140010000` | Realtek, Valid | present (same code shape) | **MW2** |
| `nvme_35B2D3D4.sys` | i386 (PE32) | yes | `0x0040d000` | Realtek, Valid | present but not loadable on x64 | **BLOCKED** (arch) |
| `nvme_77C8809A.sys` | i386 (PE32) | yes | `0x00410ada` | Realtek, Valid | present but not loadable on x64 | **BLOCKED** (arch) |
| `nvme_FFD83A43.sys` | i386 (PE32) | yes | `0x004104ea` | Realtek, Valid | present but not loadable on x64 | **BLOCKED** (arch) |

The historical report's claim that all six are one interchangeable family is wrong in one material respect: **three
are i386 images** (image base `0x00400000`, `coff-i386`) and cannot load on x64. The three x64 images are the
loadable members. All six are the same product: `Standard NVMe Storport Miniport Driver`, FileVersion
`6.3.9600.17038`, PE timestamp 2014-12-08, Microsoft copyright strings, Realtek-authenticode-signed.

## 1. Internals

- StorPort NVMe miniport. `DriverEntry` (`0x14000dd78` in 45635E0B) fills a `HW_INITIALIZATION_DATA` of size
  `0xd0` and calls `StorPortInitialize` once. `DeviceExtensionSize = 0x12f8`, `SrbExtensionSize = 0x11c8`.
- Imports are the StorPort set (`StorPortInitialize`, `StorPortGetDeviceBase`, `StorPortGetScatterGatherList`,
  `StorPortGetPhysicalAddress`, `StorPortNotification`, `StorPortRegistryRead`, `StorPortExtendedFunction`, …),
  plus `MmGetPhysicalAddress`. No `IoCreateDevice`, `IoCreateSymbolicLink`, `IoRegisterDeviceInterface`,
  `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`.
- Registry inputs read at init: `Namespaces`, `MaxTXSize`, `AdQEntries`, `IoQEntries`, `IntCoalescingTime`,
  `IntCoalescingEntries`, and the debug flag `dump=1`.
- The i386 builds add `StorPortReadRegisterUlong`, `StorPortWriteRegisterUlong`, `StorPortMoveMemory`,
  `ScsiPortMoveMemory`, `RtlUnwind`, `KeBugCheckEx`; the x64 builds do not import the register-access pair.

## 2. Entry / device / interface / effective DACL

| Item | Result |
|---|---|
| Device object created by this driver | **None** — no create API imported, no `\Device\` or `\DosDevices\` string in any of the six images |
| Symbolic link / device interface | **None** |
| IRP_MJ_CREATE / DEVICE_CONTROL handler registered | **None** — the driver owns no device object and therefore no DACL |
| Effective DACL | Not supplied by this driver. The only reachable objects are the storage stack's disk/adapter devices (`\\.\PhysicalDriveN`, `\\.\ScsiN`), whose DACL is owned by disk/storport and requires write access for the pass-through IOCTLs |
| Open gate | Local administrator (write access to the physical drive or SCSI adapter). No driver-side `SeAccessCheck` / `SeSinglePrivilegeCheck` exists |
| Setup | `hardware` + PnP `devnode`; no software-only load path (miniport bound by the storage INF) |

This is the same conclusion as the historical report on the "control device" question, but the pass-through
consequence was not drawn there.

## 3. Dispatch and IOCTL table

`HwStartIo` is `0x14001135c`; it switches on the SRB function byte (`Srb+0x02`; `Srb+0x14` for
`SRB_FUNCTION_STORAGE_REQUEST_BLOCK = 0x28`). All user reach comes through the port driver, not through a
driver-owned IOCTL dispatch.

| SRB function | Handler (45635E0B) | Meaning / kernel action |
|---|---|---|
| `0x00` EXECUTE_SCSI | build `0x14000e5e4` / submit `0x140004080` | Normal SCSI CDB path; PRPs built from the port-supplied SG list; buffer and length are the port driver's MDL/length |
| `0x02` IO_CONTROL | `0x1400114e4` | `IOCTL_SCSI_MINIPORT` pass-through; parses `SRB_IO_CONTROL` at the start of the IOCTL buffer; checks `DataTransferLength >= buffer->Length(+0x18) + 0x1c`; signature must be `NvmeMini` or `SCSIDISK` |
| `0x10` RESET_BUS / `0x12`-`0x13` / `0x20` RESET_LUN | `0x1400109b0`, `0x14001126c` | Reset paths; no caller data |
| `0x17` WMI / `0x24` POWER | `0x140011c98` / in-line | WMI and power; no caller data |
| `0x01`, `0x05`, `0x11`, `0x14` | — | Not handled (status 6) |

Miniport control codes inside `SRB_IO_CONTROL.ControlCode` (`+0x10`), all reached with
`IOCTL_SCSI_MINIPORT` (`0x0004D008`, METHOD_BUFFERED, `FILE_READ_ACCESS|FILE_WRITE_ACCESS` ⇒ administrator):

| Signature | ControlCode | Handler | Checks | Kernel action |
|---|---|---|---|---|
| `NvmeMini` | `0xE0002000` | build `0x140010b74` / submit `0x1400114e4` | `DataTransferLength >= 0x98`; `buffer+0x94 >= 0x98`; per-opcode only `buffer+0x8c` / `buffer+0x94` (caller-owned fields) | Copies the 0x40-byte NVMe command template from `buffer+0x34`, builds PRPs from `buffer+0x98`, submits to the device |
| `NvmeMini` | `0xE0002004` | `0x14001126c` | — | Controller reset (`StorPortPause` + reset); DoS only |
| `NvmeMini` | `0xE0002008` | `0x14001010c` | — | Aborts a pending namespace reset; status only |
| `NvmeMini` | `0xE000200C` | `0x1400101b4` | — | Namespace/format state transition; status only |
| `SCSIDISK` | `0x1B0500` | `0x140010eb0` | `DataTransferLength > 0x33` | Fixed 0x28-byte identity reply |
| `SCSIDISK` | `0x1B0501` | `0x140010eb0` | `DataTransferLength > 0x22b` | `memset(buffer+0x1c, 0, 0x210)` — inside the checked buffer |
| `SCSIDISK` | `0x1B0502` / `0x1B0503` | `0x140010eb0` | `DataTransferLength > 0x48` / `> 0x3a` | Allocates a driver 0x1000 pool buffer, DMAs identity data there, copies a fixed 0x40/0x2e reply |
| `SCSIDISK` | `0x1B0504` / `0x1B0505` | `0x140010eb0` | — | Status only |

Opcode dispatch inside the `NvmeMini` template (`buffer+0x34` = NVMe command dword 0):

| Opcode | Handler (45635E0B) | Length source used for PRPs | Check that constrains it |
|---|---|---|---|
| `0x02` | `0x1400100a0` | `(buffer+0x5e & 0xfff) * 4 + 4` (≤ 0x4000) | `buffer+0x94 >= length + 0x98` |
| `0x06` | `0x1400102d4` | fixed `0x1000` | `buffer+0x94 >= 0x1098` |
| `0x09` | `0x14000fba8` | `((buffer+0x64 & 0xff) + 1) * 0x10` (≤ 0x1000) | `buffer+0x8c >= length` |
| `0x11` | `0x14001002c` | `buffer+0x5c * 4 + 4` | `buffer+0x8c >= length` |
| `0x81` / `0x82` | `0x140010334` | `buffer+0x60` (any 32-bit value) | `buffer+0x94 >= length + 0x98` (0x82) / `buffer+0x8c >= length` (0x81) |
| `0x80` | `0x14000fc0c` → `0x14000f11c` | declared `buffer+0x38` | `<= MaxTXSize` at `adapter+0x338` |

**Every "check" in the right-hand column compares the length against another field inside the same caller
buffer.** Nothing compares the declared span with `Srb->DataTransferLength`, and the only port-level check is
`DataTransferLength >= 0x98` (the size of the header). The same pattern is present in all three x64 builds
(verified independently in `A9B48787` at `0x140010c60`/`0x140010bec`/`0x140010ef4` and in `E4AB6E36` at
`0x14000ac90`/`0x14000ac28`/`0x14000aee8`).

## 4. Access-control audit

- No driver-side access check of any kind; the driver never sees an IRP, only SRBs.
- The gate is the storage device's security descriptor: opening `\\.\PhysicalDriveN` or `\\.\ScsiN` with write
  access is an administrator operation on a default Windows install. `IOCTL_SCSI_MINIPORT` additionally carries
  `FILE_READ_ACCESS|FILE_WRITE_ACCESS`.
- Therefore the surface is **R2**. It is not reachable unprivileged, and it is not reachable at all without the
  matching NVMe controller (the miniport never loads).
- No `SeSinglePrivilegeCheck`, no `SeAccessCheck`, no caller-identity check, no `FILE_WRITE_ACCESS` test inside the
  miniport — once the handle is open, everything in §3 is available.

## 5. Memory-write trace

**What exists**

- **PRP builder `0x140003798`** (identical role in `A9B48787` `0x140004358`, `E4AB6E36` `0x1400042c8`):
  translates `buffer+0x98` and each following 4 KiB page with `0x140002acc`, and stores the resulting physical
  addresses into the SRB extension at `+0x30` (PRP1), `+0x38` (PRP2) and `+0x898` (PRP list), incrementing the
  count at `+0x1098`. The list write is `*puVar5 = pa` in a loop with **no test against `0x1098`/the
  `0x11c8`-byte extension**.
- **VA→PA `0x140002acc`**: `StorPortGetPhysicalAddress(ext, NULL, va, &len)` normally, `MmGetPhysicalAddress(va)`
  when the `dump=1` adapter flag is set. The `Srb = NULL` form is the same one the driver uses for its own
  internal 0x1000 buffers (`0x140002910`), i.e. it is a generic kernel-VA translation, not an SG-list lookup.
- **Submit path**: the 0x40-byte command at `extension+0x18` carries the caller's command dwords with the
  driver-computed PRP1/PRP2 patched in; `0x140004080` allocates a queue slot and copies the extra PRP entries
  into the slot's PRP list (`memcpy(slot_prp, extension+0x898, (count-1)*8)` in `E4AB6E36` `0x140004bb0`).
  The device then reads/writes exactly those pages.

**What is missing**

`Srb->DataTransferLength` is checked only for `>= 0x98`. The caller can therefore present a 0x98-byte IOCTL
buffer whose header declares a much larger payload (and a matching `+0x8c`/`+0x94` value), and the PRP list
will cover pages past the end of the IOCTL buffer. Because the buffer is the port driver's kernel system buffer
(the driver `strncmp`s it directly at build time), the extra pages are kernel pool, and the NVMe command DMAs
into them.

**Effect and limits**

- Data-in opcodes (`0x02`, `0x06`, `0x09`) cause the device to write disk/log/identify content into pool pages
  that follow the IOCTL buffer. Opcode `0x02` allows up to 16 KiB per request; `0x81`/`0x82` take an arbitrary
  32-bit length.
- The PRP list itself is written into the SRB extension without a 256-entry bound, so a long VA walk also
  overwrites `extension+0x1098` onward and, through the submit copy, can overrun the queue slot's PRP list.
- The write is **not** arbitrary: the base is the IOCTL buffer (pool placement is groomable, not chosen), the
  value is device/disk content (controllable only by choosing the LBA of a read), and the walk aborts with
  status `0xF` if any page in the span is unmapped. This is why the rating is `W2`, not `W1`.

**What does not exist**

- No `MmMapIoSpace`, no `MmMapLockedPagesSpecifyCache`, no `MmCopyMemory`, no `ZwMapViewOfSection`, no
  `\Device\PhysicalMemory`, no MDL mapped writable to user mode, no `METHOD_NEITHER` raw-pointer path.
- MMIO register writes exist only in the i386 builds (`StorPortWriteRegisterUlong` to BAR offsets taken from
  `StorPortGetDeviceBase`); those are `HW-ONLY` and are not counted.

## 6. Most dangerous exposed capability

An administrator who can open the TeamGroup NVMe disk/adapter can send `IOCTL_SCSI_MINIPORT` with a
`SRB_IO_CONTROL` of signature `NvmeMini`, control code `0xE0002000`, and an NVMe read-style command whose
declared length exceeds the supplied buffer. The miniport builds a PRP list from `buffer+0x98` outwards using
only the caller's own length fields, and the controller DMAs up to 16 KiB (opcode `0x02`) of attacker-chosen
disk content into the adjacent kernel pool, or an unbounded PRP list for opcode `0x81`/`0x82`.

## 7. Verdict

**MW2 — reach=R2 setup=hardware write=W2 load=signed** for the three x64 builds.

- `MW2` because the write is real and admin-reachable, but the target is constrained to the pool pages that
  follow the port driver's IOCTL buffer, the value is device/disk content, and the controller must be present.
- If the matching NVMe controller is **not** installed, the miniport never loads and the practical ceiling is
  `MW3` (not reachable), not `MW2`.
- The three i386 builds are **BLOCKED** (not loadable on x64) even though the same static path exists in them.
- The i386 MMIO register access (`StorPortWriteRegisterUlong`) is `HW-ONLY` and does not add a memory write.

The historical `NO-WRITE` verdict is withdrawn: it rested on the hardware/devnode disqualifier and on tracing
only one build's import table. The driver still creates no device and offers no DACL of its own; the write
capability sits behind the storage stack's pass-through surface, which the old report never examined.

## 8. Limitations

- Static only. Nothing was loaded, installed, or executed; no service or registry changes were made; no dynamic
  confirmation of the pool placement, of the actual IOCTL system-buffer size, or of `StorPortGetPhysicalAddress`
  behaviour with `Srb = NULL` was performed.
- The INF is not in the corpus, so the exact hardware-ID match (and therefore whether the driver binds to
  non-TeamGroup NVMe controllers) is unknown. The binary describes itself as a generic
  "Standard NVMe Storport Miniport Driver".
- The semantic name of the length field at `buffer+0x5e`/`+0x5c`/`+0x60` was not established; only its role as
  the PRP span is proven by the code. The finding does not depend on the name.
- `nvme_45635E0B.sys` was decompiled in full and disassembled at the cited sites; `A9B48787` and `E4AB6E36` were
  decompiled in full and their equivalent handlers matched by structure and by the same immediate constants.
  `35B2D3D4`, `77C8809A`, `FFD83A43` were checked at import/string/constant level only (i386, not loadable).
- REA was not used (four-audit capacity limit); no REA evidence IDs are cited. All addresses are file/image
  virtual addresses from the Ghidra project and `llvm-objdump`.
