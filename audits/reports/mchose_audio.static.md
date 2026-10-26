# MCHOSE / OUYU USB audio drivers — static audit (14 families, grouped)

Folder: `_collected2\drivers\MCHOSE\` — **16 `.sys` files, 14 families**. The product names are "USB Gaming Headset" (MCHOSE and BLK), and "USB Advanced Audio Device" (OUYU). Vendors: C-Media Electronics and maicong Inc.

Method: static only. Ghidra 12.1.4 headless, `AuditCls.java` (imports, device-creation and sink call sites, decompile of each sink-holding function, capped at 300 lines per function). Nothing loaded or installed. **Each family's newest build was dumped.** Other builds were not dumped, but are listed in §2.

## 1. Verdict

**All 14 families: NO-WRITE.** The surface is a PortCls USB audio adapter that the PnP manager loads for an attached USB headset. It needs hardware and a devnode, so policy disqualifies it.

## 2. Build table (newest dumped per family)

| Family | Dumped build | Date | Version | Vendor (version resource) | Other build(s), not dumped |
|---|---|---|---|---|---|
| BLK2025GHS | `F5CF8A1E` | 2024-10-23 | 10.0.2410.2300 | C-Media | `E328A8AA` (same date and version) |
| MCHOSE_F9 | `86F422DE` | 2025-03-20 | 10.0.2021.0831 | C-Media | — |
| MCHOSE_G9 | `E066BCBD` | 2025-03-03 | 10.0.2411.1300 | C-Media | — |
| MCHOSE_G9_II | `125CBC32` | 2025-03-05 | 10.0.2502.2700 | C-Media | — |
| MCHOSE_G9_PRO | `25A02326` | 2024-11-13 | 10.0.2411.1300 | maicong | — |
| MCHOSE_K20 | `C31ADA13` | 2025-03-14 | 10.0.2021.0831 | C-Media | — |
| MCHOSE_K20_PRO | `0A34F98C` | 2025-10-15 | 10.0.2510.1500 | C-Media | — |
| MCHOSE_K20_TURBO | `BEC117EA` | 2026-04-13 | 10.0.2604.1301 | C-Media | — |
| MCHOSE_S9_PRO | `A4F4639E` | 2024-11-13 | 10.0.2411.1300 | maicong | — |
| MCHOSE_V9 | `DD75AEB4` | 2024-12-12 | 10.0.2412.1200 | C-Media | — |
| MCHOSE_V9_PRO | `7B451A5E` | 2024-12-12 | 10.0.2412.1200 | C-Media | — |
| MCHOSE_V9_TURBO | `6D340ECD` | 2025-12-17 | 10.0.2503.2001 | maicong | — |
| MCHOSE_V9_TURBO_600D | `EF5F2159` | 2025-12-29 | 10.0.2503.2003 | maicong | — |
| OUYU002X1WGHS | `56F0EDDB` | 2024-09-20 | 10.0.2409.2000 | C-Media | `A7108D76` (same date and version) |

## 3. Shared import set (identical across all 14 dumped builds)

`IoAllocateMdl`, `IoRegisterDeviceInterface`, `MmMapLockedPagesSpecifyCache`, `PcInitializeAdapterDriver`, `USBD_CreateConfigurationRequestEx`, `USBD_ParseConfigurationDescriptorEx`, `USBD_ParseDescriptors`, `ZwCreateFile`.

The import-set hash matches across all 14. The sink holders have the same shape in every build. Only the call-site counts vary (for example, `USBD_ParseConfigurationDescriptorEx` has 25 to 36 call sites). `OUYU002X1WGHS` has one extra holder, a debug-log helper that formats `USBD failed` (`0x14013b910`). Nothing else differs.

**No `IoCreateDevice`, no `IoCreateSymbolicLink`.** The driver creates no named device. The user reaches it only through the KS audio interface that PnP creates for the attached headset.

## 4. Callbacks and sinks (representative: `MCHOSE_V9_DD75AEB4`, function addresses are for this build)

| Role | Address | Notes |
|---|---|---|
| `entry` | `0x140351200` | Calls `PcInitializeAdapterDriver` |
| PortCls adapter init | `FUN_140351000` @ `0x140351000` | Contains the `PcInitializeAdapterDriver` call |
| Device-interface registration | `FUN_1402e6350` @ `0x1402e6350` | `IoRegisterDeviceInterface`, 2 call sites. This is the KS audio interface on the PDO. |
| Audio buffer MDL | `FUN_1402f94f0` @ `0x1402f94f0` | `IoAllocateMdl`, then `MmBuildMdlForNonPagedPool`, then `MmMapLockedPagesSpecifyCache(mdl, 1 /*KernelMode*/, 1 /*MmCached*/, 0)` |
| USB descriptor parsing | `0x1402f6310`, `0x1402f8cd8`, and others | `USBD_ParseConfigurationDescriptorEx`, `USBD_CreateConfigurationRequestEx`. Input is device-supplied descriptors. |
| USB descriptor walk | `0x14031ed04`, `0x14032a318` | `USBD_ParseDescriptors`, 2 call sites |
| File open | `FUN_14034cef4` @ `0x14034cef4` | `ZwCreateFile`, 1 call site (2 in `MCHOSE_K20_TURBO`). Target not traced. |

**The MDL path maps driver-owned memory, not user memory.** In `FUN_1402f94f0` the buffer is `ExAllocatePoolWithTag(0x200, size, 0x64425355)`, so the source is non-paged pool allocated by the driver. The mapping is `KernelMode` (argument `1`). No user buffer is passed to `MmProbeAndLockPages`. This path is therefore not an attacker-chosen kernel address or user-to-kernel mapping. The buffer size is computed from format and rate fields of the stream's state (for example `*(int *)(lVar15 + 0x30)` in the same function). Where those fields come from was not traced, and the arithmetic was not checked for overflow.

## 5. Precondition table

| Item | Result |
|---|---|
| Control device | None created by the driver |
| Named device / symlink | None |
| User-reachable path | KS audio interface, created by PnP for an attached USB audio device |
| Setup cost | **hardware** (USB headset; vendor per version resource, C-Media or maicong) + **devnode** (PortCls adapter via PnP). VIDs not checked. |
| INF in corpus | **None** for any MCHOSE build. The setup model is taken from the binary's PnP calls (`PcInitializeAdapterDriver`, `IoRegisterDeviceInterface`), not from an INF. |
| DACL | Not applicable (no openable name) |

Both disqualifiers hold, so no further setup analysis is needed for the verdict.

## 6. Corrections to `master_drivers.csv`

- **`NO-DEVICE` is accurate for "no named control device", but misleading.** These are PortCls adapters that register a KS audio device interface. The correct label is `PNP-INTERFACE (hardware)`.

## 7. Corruption, not write

- None assessed beyond the sink check. The USB descriptor parser consumes device-supplied data, which is hardware input, not user input. The stream-size arithmetic in `FUN_1402f94f0` was not checked for overflow (§4).

## 8. Next dynamic test (described, not run)

None planned. Disqualified by hardware and devnode. If the policy changed, the first step would be to check whether the KS audio stream-size arithmetic in `FUN_1402f94f0` can underflow or overflow from a stream-descriptor value, because that is the one user-influenced size in the path.

## 9. NO-WRITE reason (one line)

A PortCls USB audio adapter with no control device: it is reachable only through the KS audio interface that PnP creates for an attached USB headset, which is hardware plus a devnode.
